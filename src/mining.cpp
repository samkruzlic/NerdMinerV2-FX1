#include <Arduino.h>
#include <ArduinoJson.h>
#include <WiFi.h>
#include <esp_task_wdt.h>
#include <esp_timer.h>
#include <esp_chip_info.h>
#include <nvs_flash.h>
#include <nvs.h>
//#include "ShaTests/nerdSHA256.h"
#include "ShaTests/nerdSHA256plus.h"
#include "stratum.h"
#include "mining.h"
#include "utils.h"
#include "monitor.h"
#include "timeconst.h"
#include "drivers/displays/display.h"
#include "drivers/storage/storage.h"
#include <mutex>
#include <atomic>
#include <list>
#include <map>
#include "mbedtls/sha256.h"
#include "i2c_master.h"
#include "crypto/ReferenceSha256.h"
#include "crypto/MiningRangePolicy.h"
#include "crypto/ShaResourcePolicy.h"
#include "crypto/ClassicKernelPolicy.h"

//10 Jobs per second
#define NONCE_PER_JOB_SW 4096
#define NONCE_PER_JOB_HW 16*1024

//#define I2C_SLAVE

//#define SHA256_VALIDATE
//#define RANDOM_NONCE
#define RANDOM_NONCE_MASK 0xFFFFC000

#ifdef HARDWARE_SHA265
#include <sha/sha_dma.h>
#include <hal/sha_hal.h>
#include <hal/sha_ll.h>

#if defined(CONFIG_IDF_TARGET_ESP32)

// Writing SHA_TEXT while the classic ESP32 SHA engine is busy is outside the
// documented peripheral contract. Keep the experiment available for explicit
// development builds, but never enable it in a normal release build.
#ifndef NERDMINER_EXPERIMENTAL_SHA_TEXT_OVERLAP
#define NERDMINER_EXPERIMENTAL_SHA_TEXT_OVERLAP 0
#endif
#include <sha/sha_parallel_engine.h>
#endif

#endif

nvs_handle_t stat_handle;

uint32_t templates = 0;
uint32_t hashes = 0;
uint32_t Mhashes = 0;
uint64_t totalKHashes = 0;
uint32_t elapsedKHs = 0;
uint64_t upTime = 0;

volatile uint32_t shares; // increase if blockhash has 32 bits of zeroes
volatile uint32_t valids; // increased if blockhash <= target

// Track best diff
double best_diff = 0.0;

// Variables to hold data from custom textboxes
//Track mining stats in non volatile memory
extern TSettings Settings;

IPAddress serverIP(1, 1, 1, 1); //Temporally save poolIPaddres

//Global work data 
static WiFiClient client;
static miner_data mMiner; //Global miner data (Create a miner class TODO)
mining_subscribe mWorker;
mining_job mJob;
monitor_data mMonitor;
static bool volatile isMinerSuscribed = false;
unsigned long mLastTXtoPool = millis();

static void addCompletedHashes(uint32_t count);
static uint64_t completedHashesSnapshot();

int saveIntervals[7] = {5 * 60, 15 * 60, 30 * 60, 1 * 3600, 3 * 3600, 6 * 3600, 12 * 3600};
int saveIntervalsSize = sizeof(saveIntervals)/sizeof(saveIntervals[0]);
int currentIntervalIndex = 0;

bool checkPoolConnection(void) {
  
  if (client.connected()) {
    return true;
  }
  
  isMinerSuscribed = false;

  Serial.println("Client not connected, trying to connect..."); 
  
  //Resolve first time pool DNS and save IP
  if(serverIP == IPAddress(1,1,1,1)) {
    WiFi.hostByName(Settings.PoolAddress.c_str(), serverIP);
    Serial.printf("Resolved DNS and save ip (first time) got: %s\n", serverIP.toString());
  }

  //Try connecting pool IP
  if (!client.connect(serverIP, Settings.PoolPort)) {
    Serial.println("Imposible to connect to : " + Settings.PoolAddress);
    WiFi.hostByName(Settings.PoolAddress.c_str(), serverIP);
    Serial.printf("Resolved DNS got: %s\n", serverIP.toString());
    return false;
  }

  return true;
}

//Implements a socketKeepAlive function and 
//checks if pool is not sending any data to reconnect again.
//Even connection could be alive, pool could stop sending new job NOTIFY
unsigned long mStart0Hashrate = 0;
bool checkPoolInactivity(unsigned int keepAliveTime, unsigned long inactivityTime){ 

    const uint64_t currentKHashes = completedHashesSnapshot() / 1000ULL;
    const uint64_t elapsedHashesK = currentKHashes - totalKHashes;

    uint32_t time_now = millis();

    // If no shares sent to pool
    // send something to pool to hold socket oppened
    if (time_now < mLastTXtoPool) //32bit wrap
      mLastTXtoPool = time_now;
    if ( time_now > mLastTXtoPool + keepAliveTime)
    {
      mLastTXtoPool = time_now;
      Serial.println("  Sending  : KeepAlive suggest_difficulty");
      //if (client.print("{}\n") == 0) {
      tx_suggest_difficulty(client, DEFAULT_DIFFICULTY);
      /*if(tx_suggest_difficulty(client, DEFAULT_DIFFICULTY)){
        Serial.println("  Sending keepAlive to pool -> Detected client disconnected");
        return true;
      }*/
    }

    if(elapsedHashesK == 0){
      //Check if hashrate is 0 during inactivityTIme
      if(mStart0Hashrate == 0) mStart0Hashrate  = time_now; 
      if((time_now-mStart0Hashrate) > inactivityTime) { mStart0Hashrate=0; return true;}
      return false;
    }

  mStart0Hashrate = 0;
  return false;
}

struct JobRequest
{
  uint32_t generation;
  uint32_t nonce_start;
  uint32_t nonce_count;
  double difficulty;
  uint8_t sha_buffer[128];
  uint32_t midstate[8];
  uint32_t bake[17];
  uint8_t raw_header[80];
  uint8_t network_target[32];
};

struct JobResult
{
  uint32_t generation;
  uint32_t nonce;
  uint32_t nonce_count;
  double difficulty;
  uint8_t hash[32];
  uint8_t raw_header[80];
  bool has_candidate = false;
  double required_difficulty = 0;
  bool timed_kernel = false;  // classic ESP32: the candidate came from the timed kernel
};

static std::mutex s_job_mutex;
std::list<std::shared_ptr<JobRequest>> s_job_request_list_sw;
#ifdef HARDWARE_SHA265
std::list<std::shared_ptr<JobRequest>> s_job_request_list_hw;
#endif
std::list<std::shared_ptr<JobResult>> s_job_result_list;
static std::atomic<uint32_t> s_working_generation(0);
static std::atomic<uint32_t> s_validation_errors(0);
static portMUX_TYPE s_hash_counter_mux = portMUX_INITIALIZER_UNLOCKED;

static void addCompletedHashes(uint32_t count)
{
  portENTER_CRITICAL(&s_hash_counter_mux);
  mining_validation::accumulateCompleted(Mhashes, hashes, count);
  portEXIT_CRITICAL(&s_hash_counter_mux);
}

static uint64_t completedHashesSnapshot()
{
  portENTER_CRITICAL(&s_hash_counter_mux);
  const uint64_t result = static_cast<uint64_t>(Mhashes) * 1000000ULL + hashes;
  portEXIT_CRITICAL(&s_hash_counter_mux);
  return result;
}

static void JobPush(std::list<std::shared_ptr<JobRequest>> &job_list,
                    uint32_t generation, uint32_t nonce_start,
                    uint32_t nonce_count, double difficulty,
                    const uint8_t* sha_buffer, const uint8_t* raw_header,
                    const uint32_t* midstate, const uint32_t* bake)
{
  std::shared_ptr<JobRequest> job = std::make_shared<JobRequest>();
  job->generation = generation;
  job->nonce_start = nonce_start;
  job->nonce_count = nonce_count;
  job->difficulty = difficulty;
  memcpy(job->sha_buffer, sha_buffer, sizeof(job->sha_buffer));
  memcpy(job->midstate, midstate, sizeof(job->midstate));
  memcpy(job->bake, bake, sizeof(job->bake));
  memcpy(job->raw_header, raw_header, sizeof(job->raw_header));
  memcpy(job->network_target, mMiner.bytearray_target, sizeof(job->network_target));
  job_list.push_back(job);
}

// Bounded backpressure, never discard a candidate or completed-work count.
// Called outside the SHA engine lock and outside s_job_mutex.
static void finishWorkerRange(std::list<std::shared_ptr<JobRequest>> &requests,
                              std::shared_ptr<JobRequest> &job,
                              std::shared_ptr<JobResult> &result)
{
  while (result) {
    {
      std::lock_guard<std::mutex> lock(s_job_mutex);
      if (s_job_result_list.size() < 16) {
        s_job_result_list.push_back(result);
        if (job && mining_validation::resumeCompletedPrefix(*job, result->nonce_count,
                s_working_generation.load(std::memory_order_acquire)))
          requests.push_front(job);
        result.reset();
      }
    }
    if (result) {
      esp_task_wdt_reset();
      vTaskDelay(1);
    }
  }
}

// Unusually easy jobs cannot use the fixed 16-zero-bit fast filter.
static void runReferenceRange(const JobRequest *job, JobResult *result)
{
  uint8_t header[80], hash[32];
  memcpy(header, job->raw_header, sizeof(header));
  result->nonce_count = job->nonce_count;
  for (uint32_t offset = 0; offset < job->nonce_count; ++offset) {
    const uint32_t nonce = job->nonce_start + offset;
    memcpy(header + 76, &nonce, sizeof(nonce));
    mining_validation::referenceSha256d(header, sizeof(header), hash);
    const double difficulty = diff_from_target(hash);
    if (mining_validation::candidateEligible(
            mining_validation::hashMeetsTarget(hash, job->network_target),
            difficulty, job->difficulty)) {
      result->has_candidate = true;
      result->nonce = nonce;
      result->difficulty = difficulty;
      result->nonce_count = offset + 1;
      memcpy(result->hash, hash, sizeof(hash));
      memcpy(result->raw_header, header, sizeof(header));
      break;
    }
    if ((offset & 0xffU) == 0) {
      esp_task_wdt_reset();
      if (s_working_generation.load(std::memory_order_acquire) != job->generation) {
        result->nonce_count = offset + 1;
        break;
      }
    }
  }
}

struct Submition
{
  double diff;
  bool is32bit;
  bool isValid;
};

static void MiningJobStop(uint32_t &job_pool, std::map<uint32_t, std::shared_ptr<Submition>> & submition_map)
{
  {
    std::lock_guard<std::mutex> lock(s_job_mutex);
    s_working_generation.fetch_add(1, std::memory_order_release);
    for (const auto &result : s_job_result_list)
      addCompletedHashes(result->nonce_count);
    s_job_result_list.clear();
    s_job_request_list_sw.clear();
    #ifdef HARDWARE_SHA265
    s_job_request_list_hw.clear();
    #endif
  }
  job_pool = 0xFFFFFFFF;
  submition_map.clear();
}

#if defined(HARDWARE_SHA265) && defined(CONFIG_IDF_TARGET_ESP32)
static void classicCandidateRejected(const JobResult *result);
#endif

#ifdef RANDOM_NONCE
uint64_t s_random_state = 1;
static uint32_t RandomGet()
{
    s_random_state += 0x9E3779B97F4A7C15ull;
    uint64_t z = s_random_state;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
    return z ^ (z >> 31);
}

#endif

void runStratumWorker(void *name) {

// TEST: https://bitcoin.stackexchange.com/questions/22929/full-example-data-for-scrypt-stratum-client

  Serial.println("");
  Serial.printf("\n[WORKER] Started. Running %s on core %d\n", (char *)name, xPortGetCoreID());

  #ifdef DEBUG_MEMORY
  Serial.printf("### [Total Heap / Free heap / Min free heap]: %d / %d / %d \n", ESP.getHeapSize(), ESP.getFreeHeap(), ESP.getMinFreeHeap());
  #endif

  std::map<uint32_t, std::shared_ptr<Submition>> s_submition_map;

#ifdef I2C_SLAVE
  std::vector<uint8_t> i2c_slave_vector;

  //scan for i2c slaves
  if (i2c_master_start() == 0)
    i2c_slave_vector = i2c_master_scan(0x0, 0x80);
  Serial.printf("Found %d slave workers\n", i2c_slave_vector.size());
  if (!i2c_slave_vector.empty())
  {
    Serial.print("  Workers: ");
    for (size_t n = 0; n < i2c_slave_vector.size(); ++n)
      Serial.printf("0x%02X,", (uint32_t)i2c_slave_vector[n]);
    Serial.println("");
  }
#endif

  // connect to pool  
  double currentPoolDifficulty = DEFAULT_DIFFICULTY;
  double activeJobDifficulty = DEFAULT_DIFFICULTY;
  uint32_t nonce_pool = 0;
  uint32_t job_pool = 0xFFFFFFFF;
  uint32_t last_job_time = millis();
  // These buffers belong to the active job, not one coordinator iteration.
  uint32_t hw_midstate[8] = {};
  uint32_t diget_mid[8] = {};
  uint32_t bake[17] = {};
  #if defined(CONFIG_IDF_TARGET_ESP32)
  alignas(uint32_t) uint8_t sha_buffer_swap[128] = {};
  #endif

  while(true) {
      
    if(WiFi.status() != WL_CONNECTED){
      // WiFi is disconnected, so reconnect now
      mMonitor.NerdStatus = NM_Connecting;
      MiningJobStop(job_pool, s_submition_map);
      WiFi.reconnect();
      vTaskDelay(5000 / portTICK_PERIOD_MS);
      continue;
    } 

    if(!checkPoolConnection()){
      //If server is not reachable add random delay for connection retries
      //Generate value between 1 and 60 secs
      MiningJobStop(job_pool, s_submition_map);
      vTaskDelay(((1 + rand() % 60) * 1000) / portTICK_PERIOD_MS);
      continue;
    }

    if(!isMinerSuscribed)
    {
      //Stop miner current jobs
      mWorker = init_mining_subscribe();

      // STEP 1: Pool server connection (SUBSCRIBE)
      if(!tx_mining_subscribe(client, mWorker)) { 
        client.stop();
        MiningJobStop(job_pool, s_submition_map);
        continue; 
      }
      
      strcpy(mWorker.wName, Settings.BtcWallet);
      strcpy(mWorker.wPass, Settings.PoolPassword);
      // STEP 2: Pool authorize work (Block Info)
      tx_mining_auth(client, mWorker.wName, mWorker.wPass); //Don't verifies authoritzation, TODO
      //tx_mining_auth2(client, mWorker.wName, mWorker.wPass); //Don't verifies authoritzation, TODO

      // STEP 3: Suggest pool difficulty
      tx_suggest_difficulty(client, currentPoolDifficulty);

      isMinerSuscribed=true;
      uint32_t time_now = millis();
      mLastTXtoPool = time_now;
      last_job_time = time_now;
    }

    //Check if pool is down for almost 5minutes and then restart connection with pool (1min=600000ms)
    if(checkPoolInactivity(KEEPALIVE_TIME_ms, POOLINACTIVITY_TIME_ms)){
      //Restart connection
      Serial.println("  Detected more than 2 min without data form stratum server. Closing socket and reopening...");
      client.stop();
      isMinerSuscribed=false;
      MiningJobStop(job_pool, s_submition_map);
      continue; 
    }

    {
      uint32_t time_now = millis();
      if (time_now < last_job_time) //32bit wrap
        last_job_time = time_now;
      if (time_now >= last_job_time + 10*60*1000)  //10minutes without job
      {
        client.stop();
        isMinerSuscribed=false;
        MiningJobStop(job_pool, s_submition_map);
        continue;
      }
    }

    //Read pending messages from pool
    while(client.connected() && client.available())
    {
      String line = client.readStringUntil('\n');
      //Serial.println("  Received message from pool");      
      stratum_method result = parse_mining_method(line);
      switch (result)
      {
          case MINING_NOTIFY:         if(parse_mining_notify(line, mJob))
                                      {
                                          uint32_t generation;
                                          {
                                            std::lock_guard<std::mutex> lock(s_job_mutex);
                                            generation = s_working_generation.fetch_add(1, std::memory_order_acq_rel) + 1;
                                            s_job_request_list_sw.clear();
                                            #ifdef HARDWARE_SHA265
                                            s_job_request_list_hw.clear();
                                            #endif
                                          }
                                          //Increse templates readed
                                          templates++;
                                          job_pool++;

                                          last_job_time = millis();
                                          mLastTXtoPool = last_job_time;

                                          //Prepare data for new jobs
                                          activeJobDifficulty = currentPoolDifficulty;
                                          mMiner=calculateMiningData(mWorker, mJob);

                                          memset(mMiner.bytearray_blockheader+80, 0, 128-80);
                                          mMiner.bytearray_blockheader[80] = 0x80;
                                          mMiner.bytearray_blockheader[126] = 0x02;
                                          mMiner.bytearray_blockheader[127] = 0x80;

                                          nerd_mids(diget_mid, mMiner.bytearray_blockheader);
                                          nerd_sha256_bake(diget_mid, mMiner.bytearray_blockheader+64, bake);

                                          #ifdef HARDWARE_SHA265
                                          #if defined(CONFIG_IDF_TARGET_ESP32S2) || defined(CONFIG_IDF_TARGET_ESP32S3) || defined(CONFIG_IDF_TARGET_ESP32C3)
                                            esp_sha_acquire_hardware();
                                            sha_hal_hash_block(SHA2_256,  mMiner.bytearray_blockheader, 64/4, true);
                                            sha_hal_read_digest(SHA2_256, hw_midstate);
                                            esp_sha_release_hardware();
                                          #endif
                                          #endif

                                          #if defined(CONFIG_IDF_TARGET_ESP32)
                                          for (int i = 0; i < 32; ++i)
                                            ((uint32_t*)sha_buffer_swap)[i] = __builtin_bswap32(((const uint32_t*)(mMiner.bytearray_blockheader))[i]);
                                          #endif

                                          #ifdef RANDOM_NONCE
                                          nonce_pool = RandomGet() & RANDOM_NONCE_MASK;
                                          #else
                                            #ifdef I2C_SLAVE
                                            if (!i2c_slave_vector.empty())
                                              nonce_pool = 0x10000000;
                                            else
                                            #endif
                                              nonce_pool = 0xDA54E700;  //nonce 0x00000000 is not possible, start from some random nonce
                                          #endif
                                          

                                          {
                                            std::lock_guard<std::mutex> lock(s_job_mutex);
                                            for (int i = 0; i < 4; ++ i)
                                            {
                                              #if 1
                                              JobPush(s_job_request_list_sw, generation, nonce_pool,
                                                  NONCE_PER_JOB_SW, activeJobDifficulty,
                                                  mMiner.bytearray_blockheader,
                                                  mMiner.bytearray_blockheader, diget_mid, bake);
                                              #ifdef RANDOM_NONCE
                                              nonce_pool = RandomGet() & RANDOM_NONCE_MASK;
                                              #else
                                              nonce_pool += NONCE_PER_JOB_SW;
                                              #endif
                                              #endif
                                              #ifdef HARDWARE_SHA265
                                                #if defined(CONFIG_IDF_TARGET_ESP32)
                                                  JobPush(s_job_request_list_hw, generation, nonce_pool,
                                                      NONCE_PER_JOB_HW, activeJobDifficulty,
                                                      sha_buffer_swap, mMiner.bytearray_blockheader,
                                                      hw_midstate, bake);
                                                #else
                                                  JobPush(s_job_request_list_hw, generation, nonce_pool,
                                                      NONCE_PER_JOB_HW, activeJobDifficulty,
                                                      mMiner.bytearray_blockheader,
                                                      mMiner.bytearray_blockheader, hw_midstate, bake);
                                                #endif
                                              #ifdef RANDOM_NONCE
                                              nonce_pool = RandomGet() & RANDOM_NONCE_MASK;
                                              #else
                                              nonce_pool += NONCE_PER_JOB_HW;
                                              #endif
                                              #endif
                                            }
                                          }
                                          #ifdef I2C_SLAVE
                                          //Nonce for nonce_pool starts from 0x10000000
                                          //For i2c slave we give nonces from 0x20000000, that is 0x10000000 nonces per slave
                                          i2c_feed_slaves(i2c_slave_vector, job_pool & 0xFF, 0x20, activeJobDifficulty, mMiner.bytearray_blockheader);
                                          #endif
                                      } else
                                      {
                                        Serial.println("Parsing error, need restart");
                                        client.stop();
                                        isMinerSuscribed=false;
                                        MiningJobStop(job_pool, s_submition_map);
                                      }
                                      break;
          case MINING_SET_DIFFICULTY: parse_mining_set_difficulty(line, currentPoolDifficulty);
                                      break;
          case STRATUM_SUCCESS:       {
                                        unsigned long id = parse_extract_id(line);
                                        auto itt = s_submition_map.find(id);
                                        if (itt != s_submition_map.end())
                                        {
                                          if (itt->second->diff > best_diff)
                                            best_diff = itt->second->diff;
                                          if (itt->second->is32bit)
                                            shares++;
                                          if (itt->second->isValid)
                                          {
                                            Serial.println("CONGRATULATIONS! Valid block found");
                                            valids++;
                                          }
                                          s_submition_map.erase(itt);
                                        }
                                      }
                                      break;
          case STRATUM_PARSE_ERROR:   {
                                        unsigned long id = parse_extract_id(line);
                                        auto itt = s_submition_map.find(id);
                                        if (itt != s_submition_map.end())
                                        {
                                          Serial.printf("Refuse submition %d\n", id);
                                          s_submition_map.erase(itt);
                                        }
                                      }
                                      break;
          default:                    Serial.println("  Parsed JSON: unknown"); break;

      }
    }

    std::list<std::shared_ptr<JobResult>> job_result_list;
    #ifdef I2C_SLAVE
    if (i2c_slave_vector.empty() || job_pool == 0xFFFFFFFF)
    {
      vTaskDelay(50 / portTICK_PERIOD_MS); //Small delay
    } else
    {
      uint32_t time_start = millis();
      i2c_hit_slaves(i2c_slave_vector);
      vTaskDelay(5 / portTICK_PERIOD_MS);
      uint32_t nonces_done = 0;
      std::vector<uint32_t> nonce_vector = i2c_harvest_slaves(i2c_slave_vector, job_pool & 0xFF, nonces_done);
      addCompletedHashes(nonces_done);
      for (size_t n = 0; n < nonce_vector.size(); ++n)
      {
        std::shared_ptr<JobResult> result = std::make_shared<JobResult>();
        ((uint32_t*)(mMiner.bytearray_blockheader+64+12))[0] = nonce_vector[n];
        if (nerd_sha256d_baked(diget_mid, mMiner.bytearray_blockheader+64, bake, result->hash))
        {
          result->generation = s_working_generation.load(std::memory_order_acquire);
          result->nonce = nonce_vector[n];
          result->has_candidate = true;
          result->nonce_count = 0;
          result->difficulty = diff_from_target(result->hash);
          result->required_difficulty = activeJobDifficulty;
          memcpy(result->raw_header, mMiner.bytearray_blockheader,
                 sizeof(result->raw_header));
          memcpy(result->raw_header + 76, &result->nonce, sizeof(result->nonce));
          job_result_list.push_back(result);
        }
      }
      uint32_t time_end = millis();
      //if (nonces_done > 16384)
        //Serial.printf("Harvest slaves in %dms hashes=%d\n", time_end - time_start, nonces_done);
      if (time_end > time_start)
      {
        uint32_t elapsed = time_end - time_start;
        if (elapsed < 50)
          vTaskDelay((50 - elapsed) / portTICK_PERIOD_MS);
      } else
        vTaskDelay(40 / portTICK_PERIOD_MS);
    }
    #else
    vTaskDelay(50 / portTICK_PERIOD_MS); //Small delay
    #endif

    
    {
      std::lock_guard<std::mutex> lock(s_job_mutex);
      job_result_list.splice(job_result_list.end(), s_job_result_list);
    }
    if (job_pool != 0xFFFFFFFF)
    {
      std::lock_guard<std::mutex> lock(s_job_mutex);

#if 1
      while (s_job_request_list_sw.size() < 4)
      {
        JobPush(s_job_request_list_sw,
            s_working_generation.load(std::memory_order_acquire), nonce_pool,
            NONCE_PER_JOB_SW, activeJobDifficulty, mMiner.bytearray_blockheader,
            mMiner.bytearray_blockheader, diget_mid, bake);
        #ifdef RANDOM_NONCE
        nonce_pool = RandomGet() & RANDOM_NONCE_MASK;
        #else
        nonce_pool += NONCE_PER_JOB_SW;
        #endif
      }
#endif

      #ifdef HARDWARE_SHA265
      while (s_job_request_list_hw.size() < 4)
      {
        #if defined(CONFIG_IDF_TARGET_ESP32)
          JobPush(s_job_request_list_hw,
              s_working_generation.load(std::memory_order_acquire), nonce_pool,
              NONCE_PER_JOB_HW, activeJobDifficulty, sha_buffer_swap,
              mMiner.bytearray_blockheader, hw_midstate, bake);
        #else
          JobPush(s_job_request_list_hw,
              s_working_generation.load(std::memory_order_acquire), nonce_pool,
              NONCE_PER_JOB_HW, activeJobDifficulty, mMiner.bytearray_blockheader,
              mMiner.bytearray_blockheader, hw_midstate, bake);
        #endif
        #ifdef RANDOM_NONCE
        nonce_pool = RandomGet() & RANDOM_NONCE_MASK;
        #else
        nonce_pool += NONCE_PER_JOB_HW;
        #endif
      }
      #endif
    }

    while (!job_result_list.empty())
    {
      std::shared_ptr<JobResult> res = job_result_list.front();
      job_result_list.pop_front();

      addCompletedHashes(res->nonce_count);
      if (res->has_candidate)
      {
        if (!client.connected())
          continue;

        bool meets_network_target = false;
        const mining_validation::CandidateValidationResult validation =
            mining_validation::validateCandidate(
                res->generation,
                s_working_generation.load(std::memory_order_acquire),
                res->raw_header, res->hash, mMiner.bytearray_target,
                &meets_network_target);
        if (validation == mining_validation::CandidateValidationResult::StaleGeneration)
          continue;
        if (validation == mining_validation::CandidateValidationResult::HashMismatch)
        {
          s_validation_errors.fetch_add(1, std::memory_order_relaxed);
          Serial.printf("CRITICAL: candidate SHA-256d validation failed (generation=%u nonce=%08x errors=%u)\n",
                        res->generation, res->nonce,
                        s_validation_errors.load(std::memory_order_relaxed));
          uint8_t reference[32];
          mining_validation::referenceSha256d(res->raw_header, 80, reference);
          Serial.print("SHA diagnostic optimized=");
          for (unsigned i=0; i<32; ++i) Serial.printf("%02x", res->hash[i]);
          Serial.print(" reference=");
          for (unsigned i=0; i<32; ++i) Serial.printf("%02x", reference[i]);
          Serial.println();
#if defined(HARDWARE_SHA265) && defined(CONFIG_IDF_TARGET_ESP32)
          classicCandidateRejected(res.get());
#endif
          Serial.print("SHA diagnostic header=");
          for (unsigned i=0; i<80; ++i) Serial.printf("%02x%s", res->raw_header[i], (i&3U)==3U ? " " : "");
          Serial.println();
          continue;
        }
        if (!mining_validation::candidateEligible(meets_network_target,
                res->difficulty, res->required_difficulty))
          continue;

        unsigned long sumbit_id = 0;
        if (!tx_mining_submit(client, mWorker, mJob, res->nonce, sumbit_id)) {
          Serial.printf("CRITICAL: candidate transmit failed (generation=%u nonce=%08x)\n",
                        res->generation, res->nonce);
          client.stop();
          isMinerSuscribed = false;
          MiningJobStop(job_pool, s_submition_map);
          continue;
        }
        Serial.print("   - Current diff share: "); Serial.println(res->difficulty,12);
        Serial.print("   - Current pool diff : "); Serial.println(currentPoolDifficulty,12);
        Serial.print("   - TX SHARE: ");
        for (size_t i = 0; i < 32; i++)
            Serial.printf("%02x", res->hash[i]);
        Serial.println("");
        mLastTXtoPool = millis();

        std::shared_ptr<Submition> submition = std::make_shared<Submition>();
        submition->diff = res->difficulty;
        submition->is32bit = (res->hash[29] == 0 && res->hash[28] == 0);
        submition->isValid = meets_network_target;

        s_submition_map.insert(std::make_pair(sumbit_id, submition));
        if (s_submition_map.size() > 32)
          s_submition_map.erase(s_submition_map.begin());
      }
    }
  }
}

//////////////////THREAD CALLS///////////////////

void minerWorkerSw(void * task_id)
{
  unsigned int miner_id = (uint32_t)task_id;
  Serial.printf("[MINER] %d Started minerWorkerSw Task!\n", miner_id);

  std::shared_ptr<JobRequest> job;
  std::shared_ptr<JobResult> result;
  uint8_t hash[32];
  uint32_t wdt_counter = 0;
  while (1)
  {
    finishWorkerRange(s_job_request_list_sw, job, result);
    {
      std::lock_guard<std::mutex> lock(s_job_mutex);
      if (!s_job_request_list_sw.empty())
      {
        job = s_job_request_list_sw.front();
        s_job_request_list_sw.pop_front();
      } else
        job.reset();
    }
    if (job)
    {
      result = std::make_shared<JobResult>();
      result->difficulty = job->difficulty;
      result->required_difficulty = job->difficulty;
      result->nonce = 0xFFFFFFFF;
      result->generation = job->generation;
      result->nonce_count = job->nonce_count;
      if (mining_validation::requiresFullDigest(job->difficulty, job->network_target))
        runReferenceRange(job.get(), result.get());
      else for (uint32_t n = 0; n < job->nonce_count; ++n)
      {
        ((uint32_t*)(job->sha_buffer+64+12))[0] = job->nonce_start+n;
        if (nerd_sha256d_baked(job->midstate, job->sha_buffer+64, job->bake, hash))
        {
          double diff_hash = diff_from_target(hash);
          if (diff_hash >= job->difficulty ||
              mining_validation::hashMeetsTarget(hash, job->network_target))
          {
            result->difficulty = diff_hash;
            result->nonce = job->nonce_start+n;
            result->has_candidate = true;
            memcpy(result->hash, hash, 32);
            memcpy(result->raw_header, job->raw_header, sizeof(result->raw_header));
            memcpy(result->raw_header + 76, &result->nonce, sizeof(result->nonce));
            result->nonce_count = n + 1;
            break;
          }
        }

        if ((uint16_t)(n & 0xFF) == 0 &&
            s_working_generation.load(std::memory_order_acquire) != job->generation)
        {
          result->nonce_count = n+1;
          break;
        }
      }
    } else
      vTaskDelay(2 / portTICK_PERIOD_MS);

    wdt_counter++;
    if (wdt_counter >= 8)
    {
      wdt_counter = 0;
      esp_task_wdt_reset();
    }
  }
}

#ifdef HARDWARE_SHA265

#if defined(CONFIG_IDF_TARGET_ESP32S2) || defined(CONFIG_IDF_TARGET_ESP32S3) || defined(CONFIG_IDF_TARGET_ESP32C3)

static inline void nerd_sha_ll_fill_text_block_sha256(const void *input_text, uint32_t nonce)
{
    uint32_t *data_words = (uint32_t *)input_text;
    uint32_t *reg_addr_buf = (uint32_t *)(SHA_TEXT_BASE);

    REG_WRITE(&reg_addr_buf[0], data_words[0]);
    REG_WRITE(&reg_addr_buf[1], data_words[1]);
    REG_WRITE(&reg_addr_buf[2], data_words[2]);
#if 0
    REG_WRITE(&reg_addr_buf[3], nonce);
    //REG_WRITE(&reg_addr_buf[3], data_words[3]);    
    REG_WRITE(&reg_addr_buf[4], data_words[4]);
    REG_WRITE(&reg_addr_buf[5], data_words[5]);
    REG_WRITE(&reg_addr_buf[6], data_words[6]);
    REG_WRITE(&reg_addr_buf[7], data_words[7]);
    REG_WRITE(&reg_addr_buf[8], data_words[8]);
    REG_WRITE(&reg_addr_buf[9], data_words[9]);
    REG_WRITE(&reg_addr_buf[10], data_words[10]);
    REG_WRITE(&reg_addr_buf[11], data_words[11]);
    REG_WRITE(&reg_addr_buf[12], data_words[12]);
    REG_WRITE(&reg_addr_buf[13], data_words[13]);
    REG_WRITE(&reg_addr_buf[14], data_words[14]);
    REG_WRITE(&reg_addr_buf[15], data_words[15]);
#else
    REG_WRITE(&reg_addr_buf[3], nonce);
    REG_WRITE(&reg_addr_buf[4], 0x00000080);
    REG_WRITE(&reg_addr_buf[5], 0x00000000);
    REG_WRITE(&reg_addr_buf[6], 0x00000000);
    REG_WRITE(&reg_addr_buf[7], 0x00000000);
    REG_WRITE(&reg_addr_buf[8], 0x00000000);
    REG_WRITE(&reg_addr_buf[9], 0x00000000);
    REG_WRITE(&reg_addr_buf[10], 0x00000000);
    REG_WRITE(&reg_addr_buf[11], 0x00000000);
    REG_WRITE(&reg_addr_buf[12], 0x00000000);
    REG_WRITE(&reg_addr_buf[13], 0x00000000);
    REG_WRITE(&reg_addr_buf[14], 0x00000000);
    REG_WRITE(&reg_addr_buf[15], 0x80020000);
#endif
}

static inline void nerd_sha_ll_fill_text_block_sha256_inter()
{
  uint32_t *reg_addr_buf = (uint32_t *)(SHA_TEXT_BASE);

  DPORT_INTERRUPT_DISABLE();
  REG_WRITE(&reg_addr_buf[0], DPORT_SEQUENCE_REG_READ(SHA_H_BASE + 0 * 4));
  REG_WRITE(&reg_addr_buf[1], DPORT_SEQUENCE_REG_READ(SHA_H_BASE + 1 * 4));
  REG_WRITE(&reg_addr_buf[2], DPORT_SEQUENCE_REG_READ(SHA_H_BASE + 2 * 4));
  REG_WRITE(&reg_addr_buf[3], DPORT_SEQUENCE_REG_READ(SHA_H_BASE + 3 * 4));
  REG_WRITE(&reg_addr_buf[4], DPORT_SEQUENCE_REG_READ(SHA_H_BASE + 4 * 4));
  REG_WRITE(&reg_addr_buf[5], DPORT_SEQUENCE_REG_READ(SHA_H_BASE + 5 * 4));
  REG_WRITE(&reg_addr_buf[6], DPORT_SEQUENCE_REG_READ(SHA_H_BASE + 6 * 4));
  REG_WRITE(&reg_addr_buf[7], DPORT_SEQUENCE_REG_READ(SHA_H_BASE + 7 * 4));
  DPORT_INTERRUPT_RESTORE();

  REG_WRITE(&reg_addr_buf[8], 0x00000080);
  REG_WRITE(&reg_addr_buf[9], 0x00000000);
  REG_WRITE(&reg_addr_buf[10], 0x00000000);
  REG_WRITE(&reg_addr_buf[11], 0x00000000);
  REG_WRITE(&reg_addr_buf[12], 0x00000000);
  REG_WRITE(&reg_addr_buf[13], 0x00000000);
  REG_WRITE(&reg_addr_buf[14], 0x00000000);
  REG_WRITE(&reg_addr_buf[15], 0x00010000);
}

static inline void nerd_sha_ll_read_digest(void* ptr)
{
  DPORT_INTERRUPT_DISABLE();
  ((uint32_t*)ptr)[0] = DPORT_SEQUENCE_REG_READ(SHA_H_BASE + 0 * 4);
  ((uint32_t*)ptr)[1] = DPORT_SEQUENCE_REG_READ(SHA_H_BASE + 1 * 4);
  ((uint32_t*)ptr)[2] = DPORT_SEQUENCE_REG_READ(SHA_H_BASE + 2 * 4);
  ((uint32_t*)ptr)[3] = DPORT_SEQUENCE_REG_READ(SHA_H_BASE + 3 * 4);
  ((uint32_t*)ptr)[4] = DPORT_SEQUENCE_REG_READ(SHA_H_BASE + 4 * 4);
  ((uint32_t*)ptr)[5] = DPORT_SEQUENCE_REG_READ(SHA_H_BASE + 5 * 4);
  ((uint32_t*)ptr)[6] = DPORT_SEQUENCE_REG_READ(SHA_H_BASE + 6 * 4);  
  ((uint32_t*)ptr)[7] = DPORT_SEQUENCE_REG_READ(SHA_H_BASE + 7 * 4);
  DPORT_INTERRUPT_RESTORE();
}


static inline bool nerd_sha_ll_read_digest_if(void* ptr)
{
  DPORT_INTERRUPT_DISABLE();
  uint32_t last = DPORT_SEQUENCE_REG_READ(SHA_H_BASE + 7 * 4);
  #if 1
  if ( (uint16_t)(last >> 16) != 0)
  {
    DPORT_INTERRUPT_RESTORE();
    return false;
  }
  #endif

  ((uint32_t*)ptr)[7] = last;
  ((uint32_t*)ptr)[0] = DPORT_SEQUENCE_REG_READ(SHA_H_BASE + 0 * 4);
  ((uint32_t*)ptr)[1] = DPORT_SEQUENCE_REG_READ(SHA_H_BASE + 1 * 4);
  ((uint32_t*)ptr)[2] = DPORT_SEQUENCE_REG_READ(SHA_H_BASE + 2 * 4);
  ((uint32_t*)ptr)[3] = DPORT_SEQUENCE_REG_READ(SHA_H_BASE + 3 * 4);
  ((uint32_t*)ptr)[4] = DPORT_SEQUENCE_REG_READ(SHA_H_BASE + 4 * 4);
  ((uint32_t*)ptr)[5] = DPORT_SEQUENCE_REG_READ(SHA_H_BASE + 5 * 4);
  ((uint32_t*)ptr)[6] = DPORT_SEQUENCE_REG_READ(SHA_H_BASE + 6 * 4);  
  DPORT_INTERRUPT_RESTORE();
  return true;
}

static inline void nerd_sha_ll_write_digest(void *digest_state)
{
    uint32_t *digest_state_words = (uint32_t *)digest_state;
    uint32_t *reg_addr_buf = (uint32_t *)(SHA_H_BASE);

    REG_WRITE(&reg_addr_buf[0], digest_state_words[0]);
    REG_WRITE(&reg_addr_buf[1], digest_state_words[1]);
    REG_WRITE(&reg_addr_buf[2], digest_state_words[2]);
    REG_WRITE(&reg_addr_buf[3], digest_state_words[3]);
    REG_WRITE(&reg_addr_buf[4], digest_state_words[4]);
    REG_WRITE(&reg_addr_buf[5], digest_state_words[5]);
    REG_WRITE(&reg_addr_buf[6], digest_state_words[6]);
    REG_WRITE(&reg_addr_buf[7], digest_state_words[7]);
}

static inline void nerd_sha_hal_wait_idle()
{
    while (REG_READ(SHA_BUSY_REG))
    {}
}

//#define VALIDATION
void minerWorkerHw(void * task_id)
{
  unsigned int miner_id = (uint32_t)task_id;
  Serial.printf("[MINER] %d Started minerWorkerHw Task!\n", miner_id);

  std::shared_ptr<JobRequest> job;
  std::shared_ptr<JobResult> result;
  uint8_t interResult[64];
  uint8_t hash[32];
  uint8_t digest_mid[32];
  uint8_t sha_buffer[64];
  uint32_t wdt_counter = 0;

#ifdef VALIDATION
  uint8_t doubleHash[32];
  uint32_t diget_mid[8];
  uint32_t bake[17];
#endif

  while (1)
  {
    finishWorkerRange(s_job_request_list_hw, job, result);
    {
      std::lock_guard<std::mutex> lock(s_job_mutex);
      if (!s_job_request_list_hw.empty())
      {
        job = s_job_request_list_hw.front();
        s_job_request_list_hw.pop_front();
      } else
        job.reset();
    }
    if (job)
    {
      result = std::make_shared<JobResult>();
      result->generation = job->generation;
      result->nonce = 0xFFFFFFFF;
      result->nonce_count = job->nonce_count;
      result->difficulty = job->difficulty;
      result->required_difficulty = job->difficulty;
      memcpy(digest_mid, job->midstate, sizeof(digest_mid));
      memcpy(sha_buffer, job->sha_buffer+64, sizeof(sha_buffer));
#ifdef VALIDATION
      nerd_mids(diget_mid, job->sha_buffer);
      nerd_sha256_bake(diget_mid, job->sha_buffer+64, bake);
#endif

      esp_sha_acquire_hardware();
      REG_WRITE(SHA_MODE_REG, SHA2_256);
      for (uint32_t offset = 0; offset < job->nonce_count; ++offset)
      {
        const uint32_t n = job->nonce_start + offset;
        //nerd_sha_hal_wait_idle();
        nerd_sha_ll_write_digest(digest_mid);
        //nerd_sha_hal_wait_idle();
        nerd_sha_ll_fill_text_block_sha256(sha_buffer, n);
        //sha_ll_continue_block(SHA2_256);
        REG_WRITE(SHA_CONTINUE_REG, 1);
        
        sha_ll_load(SHA2_256);
        nerd_sha_hal_wait_idle();
        nerd_sha_ll_fill_text_block_sha256_inter();
        //sha_ll_start_block(SHA2_256);
        REG_WRITE(SHA_START_REG, 1);
        sha_ll_load(SHA2_256);
        nerd_sha_hal_wait_idle();
        if (nerd_sha_ll_read_digest_if(hash))
        {
          //Serial.printf("Hw 16bit Share, nonce=0x%X\n", n);
#ifdef VALIDATION
          //Validation
          ((uint32_t*)(job->sha_buffer+64+12))[0] = n;
          nerd_sha256d_baked(diget_mid, job->sha_buffer+64, bake, doubleHash);
          for (int i = 0; i < 32; ++i)
          {
            if (hash[i] != doubleHash[i])
            {
              Serial.println("***HW sha256 esp32s3 bug detected***");
              break;
            }
          }
#endif
          //~5 per second
          double diff_hash = diff_from_target(hash);
            if (diff_hash >= job->difficulty ||
                mining_validation::hashMeetsTarget(hash, job->network_target))
          {
              result->difficulty = diff_hash;
              result->nonce = n;
              result->has_candidate = true;
              memcpy(result->hash, hash, sizeof(hash));
              memcpy(result->raw_header, job->raw_header, sizeof(result->raw_header));
              memcpy(result->raw_header + 76, &result->nonce, sizeof(result->nonce));
              result->nonce_count = offset + 1;
              break;
          }
        }
        if (
             (uint8_t)(n & 0xFF) == 0 &&
             s_working_generation.load(std::memory_order_acquire) != job->generation)
        {
          result->nonce_count = n-job->nonce_start+1;
          break;
        }
      }
      esp_sha_release_hardware();
    } else
      vTaskDelay(2 / portTICK_PERIOD_MS);

    wdt_counter++;
    if (wdt_counter >= 8)
    {
      wdt_counter = 0;
      esp_task_wdt_reset();
    }
  }
}

#endif  //#if defined(CONFIG_IDF_TARGET_ESP32S2) || defined(CONFIG_IDF_TARGET_ESP32S3) || defined(CONFIG_IDF_TARGET_ESP32C3)

#if defined(CONFIG_IDF_TARGET_ESP32)

static inline __attribute__((always_inline))
bool nerd_sha_ll_read_digest_swap_from_word(void* ptr, bool force_read, uint32_t fin)
{
  // Most nonces need only the final word for the exact 16-bit early filter.
  // DPORT_REG_READ is the framework's SMP-safe path for a single register.
  const bool passes_early_filter = (uint32_t)(fin & 0xFFFF) == 0;
  if (!passes_early_filter && !force_read)
    return false;

  // Samples and filter hits are rare; use the faster sequential-read helper
  // for the remaining digest words while interrupts are locally disabled.
  DPORT_INTERRUPT_DISABLE();
  ((uint32_t*)ptr)[7] = __builtin_bswap32(fin);
  ((uint32_t*)ptr)[0] = __builtin_bswap32(DPORT_SEQUENCE_REG_READ(SHA_TEXT_BASE + 0 * 4));
  ((uint32_t*)ptr)[1] = __builtin_bswap32(DPORT_SEQUENCE_REG_READ(SHA_TEXT_BASE + 1 * 4));
  ((uint32_t*)ptr)[2] = __builtin_bswap32(DPORT_SEQUENCE_REG_READ(SHA_TEXT_BASE + 2 * 4));
  ((uint32_t*)ptr)[3] = __builtin_bswap32(DPORT_SEQUENCE_REG_READ(SHA_TEXT_BASE + 3 * 4));
  ((uint32_t*)ptr)[4] = __builtin_bswap32(DPORT_SEQUENCE_REG_READ(SHA_TEXT_BASE + 4 * 4));
  ((uint32_t*)ptr)[5] = __builtin_bswap32(DPORT_SEQUENCE_REG_READ(SHA_TEXT_BASE + 5 * 4));
  ((uint32_t*)ptr)[6] = __builtin_bswap32(DPORT_SEQUENCE_REG_READ(SHA_TEXT_BASE + 6 * 4));
  DPORT_INTERRUPT_RESTORE();
  return passes_early_filter;
}

static inline void nerd_sha_ll_read_digest(void* ptr)
{
  DPORT_INTERRUPT_DISABLE();
  ((uint32_t*)ptr)[0] = DPORT_SEQUENCE_REG_READ(SHA_TEXT_BASE + 0 * 4);
  ((uint32_t*)ptr)[1] = DPORT_SEQUENCE_REG_READ(SHA_TEXT_BASE + 1 * 4);
  ((uint32_t*)ptr)[2] = DPORT_SEQUENCE_REG_READ(SHA_TEXT_BASE + 2 * 4);
  ((uint32_t*)ptr)[3] = DPORT_SEQUENCE_REG_READ(SHA_TEXT_BASE + 3 * 4);
  ((uint32_t*)ptr)[4] = DPORT_SEQUENCE_REG_READ(SHA_TEXT_BASE + 4 * 4);
  ((uint32_t*)ptr)[5] = DPORT_SEQUENCE_REG_READ(SHA_TEXT_BASE + 5 * 4);
  ((uint32_t*)ptr)[6] = DPORT_SEQUENCE_REG_READ(SHA_TEXT_BASE + 6 * 4);
  ((uint32_t*)ptr)[7] = DPORT_SEQUENCE_REG_READ(SHA_TEXT_BASE + 7 * 4);
  DPORT_INTERRUPT_RESTORE();
}

#include "crypto/ClassicEsp32ShaAccess.h"

static inline __attribute__((always_inline)) void nerd_sha_hal_wait_idle()
{
    classic_sha::waitIdle();
}

static inline __attribute__((always_inline)) uint32_t *nerd_sha_text_words()
{
    uint32_t *words = reinterpret_cast<uint32_t *>(SHA_TEXT_BASE);

    // Keep SHA_TEXT_BASE in one address register.  Without this compiler
    // barrier GCC rematerializes many individual absolute MMIO addresses in
    // the per-nonce fills.  The stores retain the same semantics used by the
    // ESP-IDF low-level helper that this code specializes.
    __asm__ __volatile__("" : "+r"(words));
    return words;
}

static inline void nerd_sha_ll_fill_text_block_sha256(
    const void *input_text, uint32_t *reg_addr_buf = nerd_sha_text_words())
{
    const uint32_t *data_words = static_cast<const uint32_t *>(input_text);

    reg_addr_buf[0]  = data_words[0];
    reg_addr_buf[1]  = data_words[1];
    reg_addr_buf[2]  = data_words[2];
    reg_addr_buf[3]  = data_words[3];
    reg_addr_buf[4]  = data_words[4];
    reg_addr_buf[5]  = data_words[5];
    reg_addr_buf[6]  = data_words[6];
    reg_addr_buf[7]  = data_words[7];
    reg_addr_buf[8]  = data_words[8];
    reg_addr_buf[9]  = data_words[9];
    reg_addr_buf[10] = data_words[10];
    reg_addr_buf[11] = data_words[11];
    reg_addr_buf[12] = data_words[12];
    reg_addr_buf[13] = data_words[13];
    reg_addr_buf[14] = data_words[14];
    reg_addr_buf[15] = data_words[15];
}

#if NERDMINER_EXPERIMENTAL_SHA_TEXT_OVERLAP
static inline void nerd_sha_ll_fill_text_block_sha256_lower_half(const void *input_text)
{
    const uint32_t *data_words = (const uint32_t *)input_text;
    uint32_t *reg_addr_buf = (uint32_t *)(SHA_TEXT_BASE);

    reg_addr_buf[0] = data_words[0];
    reg_addr_buf[1] = data_words[1];
    reg_addr_buf[2] = data_words[2];
    reg_addr_buf[3] = data_words[3];
    reg_addr_buf[4] = data_words[4];
    reg_addr_buf[5] = data_words[5];
    reg_addr_buf[6] = data_words[6];
    reg_addr_buf[7] = data_words[7];
}

static inline void nerd_sha_ll_fill_text_block_sha256_upper_half(const void *input_text)
{
    const uint32_t *data_words = (const uint32_t *)input_text;
    uint32_t *reg_addr_buf = (uint32_t *)(SHA_TEXT_BASE);

    reg_addr_buf[8]  = data_words[8];
    reg_addr_buf[9]  = data_words[9];
    reg_addr_buf[10] = data_words[10];
    reg_addr_buf[11] = data_words[11];
    reg_addr_buf[12] = data_words[12];
    reg_addr_buf[13] = data_words[13];
    reg_addr_buf[14] = data_words[14];
    reg_addr_buf[15] = data_words[15];
}
#endif

static inline __attribute__((always_inline))
void nerd_sha_ll_fill_text_block_sha256_upper(
    const void *input_text, uint32_t nonce_be,
    uint32_t *reg_addr_buf = nerd_sha_text_words())
{
    const uint32_t *data_words = static_cast<const uint32_t *>(input_text);

    reg_addr_buf[0]  = data_words[0];
    reg_addr_buf[1]  = data_words[1];
    reg_addr_buf[2]  = data_words[2];
    reg_addr_buf[3]  = nonce_be;
#if 1
    reg_addr_buf[4]  = 0x80000000;
    reg_addr_buf[5]  = 0x00000000;
    reg_addr_buf[6]  = 0x00000000;
    reg_addr_buf[7]  = 0x00000000;
    reg_addr_buf[8]  = 0x00000000;
    reg_addr_buf[9]  = 0x00000000;
    reg_addr_buf[10] = 0x00000000;
    reg_addr_buf[11] = 0x00000000;
    reg_addr_buf[12] = 0x00000000;
    reg_addr_buf[13] = 0x00000000;
    reg_addr_buf[14] = 0x00000000;
    reg_addr_buf[15] = 0x00000280;
#else
    reg_addr_buf[4]  = data_words[4];
    reg_addr_buf[5]  = data_words[5];
    reg_addr_buf[6]  = data_words[6];
    reg_addr_buf[7]  = data_words[7];
    reg_addr_buf[8]  = data_words[8];
    reg_addr_buf[9]  = data_words[9];
    reg_addr_buf[10] = data_words[10];
    reg_addr_buf[11] = data_words[11];
    reg_addr_buf[12] = data_words[12];
    reg_addr_buf[13] = data_words[13];
    reg_addr_buf[14] = data_words[14];
    reg_addr_buf[15] = data_words[15];
#endif
}

static inline __attribute__((always_inline)) void nerd_sha_ll_fill_text_block_sha256_double(
    uint32_t *reg_addr_buf = nerd_sha_text_words())
{

#if 0
    //No change
    reg_addr_buf[0]  = data_words[0];
    reg_addr_buf[1]  = data_words[1];
    reg_addr_buf[2]  = data_words[2];
    reg_addr_buf[3]  = data_words[3];
    reg_addr_buf[4]  = data_words[4];
    reg_addr_buf[5]  = data_words[5];
    reg_addr_buf[6]  = data_words[6];
    reg_addr_buf[7]  = data_words[7];
#endif
    reg_addr_buf[8]  = 0x80000000;
    reg_addr_buf[9]  = 0x00000000;
    reg_addr_buf[10] = 0x00000000;
    reg_addr_buf[11] = 0x00000000;
    reg_addr_buf[12] = 0x00000000;
    reg_addr_buf[13] = 0x00000000;
    reg_addr_buf[14] = 0x00000000;
    reg_addr_buf[15] = 0x00000100;
}

// Set by classicShaSelfTest() when the two-store block-3 padding fails a known
// answer on this chip; the kernel then writes all of words 8..15.
volatile uint32_t s_classic_full_padding = 0;

// Timed kernel ("kernel A") or today's polled kernel, with the runtime net's
// counters. Selected by classicShaSelfTest(); switches to polled for good on
// any known-answer or sample mismatch.
classic_kernel::FallbackState s_classic_kernel;
// Locked groups started, for the runtime net's rotating sample offset.
uint32_t s_classic_sample_group = 0;
static_assert(classic_kernel::kGroupNonces == 1024, "sample schedule assumes 1,024-nonce groups");

// Runtime net (c): a candidate that fails the pre-submit reference re-check
// and came from the timed kernel proves that kernel wrong. The range was
// already handed on, so only the kernel is switched (one-way, one line).
static void __attribute__((noinline)) classicCandidateRejected(const JobResult *result)
{
  if (s_classic_kernel.invalidCandidate(result->timed_kernel))
    Serial.printf("CRITICAL: [SHA] timed kernel produced an invalid candidate nonce=%08x; "
                  "using the polled kernel until reboot\n", result->nonce);
}

namespace {

// SHA_TEXT is shared across all three classic ESP32 engines. Reserve them
// together before amortizing its critical section; other SDK users then take
// their documented software fallback instead of starting another algorithm.
static bool tryReserveClassicSha()
{
  if (!esp_sha_try_lock_engine(SHA2_256)) return false;
  if (!esp_sha_try_lock_engine(SHA1)) {
    esp_sha_unlock_engine(SHA2_256);
    return false;
  }
  if (!esp_sha_try_lock_engine(SHA2_512)) {
    esp_sha_unlock_engine(SHA1);
    esp_sha_unlock_engine(SHA2_256);
    return false;
  }
  return true;
}

static void releaseClassicSha()
{
  esp_sha_unlock_engine(SHA2_512);
  esp_sha_unlock_engine(SHA1);
  esp_sha_unlock_engine(SHA2_256);
}

// The classic ESP32 SHA engine cannot restore an arbitrary midstate. The
// experimental path below depends on undocumented SHA_TEXT latching and is
// compiled only for explicit development builds.
#if NERDMINER_EXPERIMENTAL_SHA_TEXT_OVERLAP
constexpr uint32_t kHardwarePipelineVerifyInterval = 4096;
static std::atomic<bool> s_hardware_pipeline_enabled(true);
static std::atomic<uint32_t> s_hardware_pipeline_errors(0);
#endif

static void recordHardwareCandidate(JobResult *result, const JobRequest *job,
                                    uint32_t nonce, const uint8_t hash[32])
{
  const double diff_hash = diff_from_target((void *)hash);
  if (diff_hash >= job->difficulty ||
      mining_validation::hashMeetsTarget(hash, job->network_target))
  {
    result->difficulty = diff_hash;
    result->nonce = nonce;
    result->has_candidate = true;
    memcpy(result->hash, hash, sizeof(result->hash));
    memcpy(result->raw_header, job->raw_header, sizeof(result->raw_header));
    memcpy(result->raw_header + 76, &nonce, sizeof(nonce));
  }
}

#if NERDMINER_EXPERIMENTAL_SHA_TEXT_OVERLAP
__attribute__((noinline))
static bool validateHardwareHash(const JobRequest *job, uint32_t nonce,
                                 const uint8_t hardware_hash[32])
{
  uint8_t header[80];
  uint8_t reference_hash[32];
  memcpy(header, job->raw_header, sizeof(header));
  memcpy(header + 76, &nonce, sizeof(nonce));
  mining_validation::referenceSha256d(header, sizeof(header), reference_hash);
  return memcmp(reference_hash, hardware_hash, sizeof(reference_hash)) == 0;
}
#endif

static inline __attribute__((always_inline))
void nerd_sha_control_write(uint32_t *words, uint32_t control_register)
{
    // Derive the offset from the framework register definitions. DPORT writes
    // do not require the read workaround; retain its volatile store/barrier.
    DPORT_REG_WRITE(reinterpret_cast<uintptr_t>(words) +
                    (control_register - SHA_TEXT_BASE), 1);
}

#ifdef NERDMINER_SHA_DIAGNOSTICS
static bool s_diag_force_digest = true;
static uint32_t s_diag_checked = 0;
static uint32_t s_diag_errors = 0;
static uint32_t s_diag_hits = 0;
static void diagRecordNonce(uint32_t nonce, const uint8_t hash[32],
                            uint32_t final_word, bool passes_filter);
static bool diagFlushBurst(const JobRequest *job);
#endif
#ifdef W390_KERNEL_SOAK
// Development-only: the W390 kernel soak forces the kernel per call (0 polled,
// 1 timed, -1 the runtime selection); it never touches s_classic_kernel.
static int32_t s_soak_kernel = -1;
static inline bool soakKernelForced() { return s_soak_kernel >= 0; }
#else
static inline bool soakKernelForced() { return false; }
#endif

static constexpr uint32_t CLASSIC_SHA_GROUP_NONCES = 1024;

// Runtime net of the timed kernel: re-hash one sampled nonce in software and
// compare its final word. Called only after the group's stall and shared-memory
// lock are released. On a mismatch the timed kernel stays off until reboot.
static bool __attribute__((noinline))
checkTimedSample(const JobRequest *job, uint32_t nonce, uint32_t final_word)
{
  const uint32_t reference = classic_kernel::referenceFinalWord(job->raw_header, nonce);
  if (s_classic_kernel.recordSample(reference == final_word))
    return true;
  if (!soakKernelForced())  // the soak reports its own mismatches
    Serial.printf("CRITICAL: [SHA] timed kernel sample mismatch nonce=%08x kernel=%08x reference=%08x; "
                "using the polled kernel until reboot\n", nonce, final_word, reference);
  return false;
}

// Each group of up to CLASSIC_SHA_GROUP_NONCES nonces runs with SHA_TEXT locked
// and the other CPU stalled. The job generation is written only by the stratum
// task, which is pinned to the other CPU, so it cannot change while the stall
// holds: it is checked once per group, after the stall starts, instead of every
// 256 nonces. The inner loop carries no bookkeeping beyond the early filter.
//
// Two kernels share this group frame; the choice is read once per group:
//  - polled (today's): every input written while the engine is idle, BUSY
//    polled after a MEMW for every block.
//  - timed ("kernel A", eligible 240 MHz rev-3 chips that pass the boot
//    known-answer test): fixed cycle waits from ccount instead of BUSY, and the
//    next block's words written while the engine is busy, at the points the
//    bench measured as latched (classic_kernel::k*WaitCycles).
static void IRAM_ATTR __attribute__((noinline, optimize("O2")))
runClassicHardwareSequential(const JobRequest *job,
                                         JobResult *result,
                                         uint8_t sha_buffer[128],
                                         uint8_t hash[32])
{
  const uint32_t first = job->nonce_start;
  const uint32_t count = job->nonce_count;
  uint32_t *const words = nerd_sha_text_words();
  const bool full_padding = s_classic_full_padding != 0;
  uint32_t done = 0;
  result->nonce_count = count;
  while (done < count)
  {
    const uint32_t group = count - done < CLASSIC_SHA_GROUP_NONCES ?
                           count - done : CLASSIC_SHA_GROUP_NONCES;
    uint32_t nonce = first + done;
    const uint32_t group_end = nonce + group;  // modulo 2^32, compared with !=
    bool passes_filter = false;
#ifdef W390_KERNEL_SOAK
    const bool timed = soakKernelForced() ? s_soak_kernel == 1 :
                       s_classic_kernel.activeWord().load(std::memory_order_acquire) ==
                       static_cast<uint32_t>(classic_kernel::Kernel::Timed);
#else
    const bool timed = s_classic_kernel.activeWord().load(std::memory_order_acquire) ==
                       static_cast<uint32_t>(classic_kernel::Kernel::Timed);
#endif
    bool sampled = false;
    uint32_t sample_nonce = 0, sample_word = 0;
    // Runtime net (a): one group in 4 is sampled, at a rotating offset; a
    // target beyond the group's last nonce means no sample in this group.
    const uint32_t sample_target =
        nonce + classic_kernel::sampleOffset(s_classic_sample_group++);

    // SHA_TEXT is shared by SHA-1/256/384/512, not only SHA-256 users. Other
    // SHA algorithms cannot start while this critical section is held. Local
    // interrupts are masked by the SDK lock: never yield or perform network,
    // queue or reference-validation work while holding it.
    const int64_t groupBegan = esp_timer_get_time();
    esp_sha_lock_memory_block();
    sha_hal_wait_idle();
    DPORT_STALL_OTHER_CPU_START();
    if (s_working_generation.load(std::memory_order_acquire) != job->generation) {
      DPORT_STALL_OTHER_CPU_END();
      esp_sha_unlock_memory_block();
      result->nonce_count = done;
      return;
    }
    if (timed)
    {
      using classic_kernel::kCommandWaitCycles;
      using classic_kernel::kLoadWaitCycles;
      using classic_kernel::kPaddingWaitCycles;
      using classic_kernel::kLatchWaitCycles;
      using classic_sha::rawStore;
      using classic_sha::waitCyclesSince;
      constexpr uint32_t START = SHA_256_START_REG - SHA_TEXT_BASE;
      constexpr uint32_t CONTINUE = SHA_256_CONTINUE_REG - SHA_TEXT_BASE;
      constexpr uint32_t LOAD = SHA_256_LOAD_REG - SHA_TEXT_BASE;
      const uint32_t *const block1 = reinterpret_cast<const uint32_t *>(sha_buffer);
      const uint32_t *const block2 = reinterpret_cast<const uint32_t *>(sha_buffer + 64);
      const uint32_t t0 = block2[0], t1 = block2[1], t2 = block2[2];

      // Block-1 words 8..15 of each nonce are written during the previous
      // nonce's block-3 compression; the first nonce of a group needs them now.
      rawStore<32>(words, block1[8]);  rawStore<36>(words, block1[9]);
      rawStore<40>(words, block1[10]); rawStore<44>(words, block1[11]);
      rawStore<48>(words, block1[12]); rawStore<52>(words, block1[13]);
      rawStore<56>(words, block1[14]); rawStore<60>(words, block1[15]);
      uint32_t final_word = 0;
      do
      {
        rawStore<0>(words, block1[0]);   rawStore<4>(words, block1[1]);
        rawStore<8>(words, block1[2]);   rawStore<12>(words, block1[3]);
        rawStore<16>(words, block1[4]);  rawStore<20>(words, block1[5]);
        rawStore<24>(words, block1[6]);  rawStore<28>(words, block1[7]);
        rawStore<START>(words, 1);
        uint32_t t = classic_sha::cycleCount();

        // Block 2 goes in once block 1 is latched (kLatchWaitCycles).
        const uint32_t nonce_be = classic_sha::byteSwap(nonce);
#ifdef W390_SOAK_BREAK_LATCH
        // DELIBERATELY BROKEN soak build: no latch wait at all (the 531806c bug).
#else
        waitCyclesSince(t, kLatchWaitCycles);
#endif
        rawStore<0>(words, t0);          rawStore<4>(words, t1);
        rawStore<8>(words, t2);          rawStore<12>(words, nonce_be);
        rawStore<16>(words, 0x80000000); rawStore<20>(words, 0);
        rawStore<24>(words, 0);          rawStore<28>(words, 0);
        rawStore<32>(words, 0);          rawStore<36>(words, 0);
        rawStore<40>(words, 0);          rawStore<44>(words, 0);
        rawStore<48>(words, 0);          rawStore<52>(words, 0);
        rawStore<56>(words, 0);          rawStore<60>(words, 0x00000280);
        // Free while block 1 compresses: keep the previous nonce's final word
        // if it is the runtime net's sample (the last nonce is checked below).
        if (nonce - 1U == sample_target) {
          sampled = true;
          sample_nonce = nonce - 1U;
          sample_word = final_word;
        }
        waitCyclesSince(t, kCommandWaitCycles);
        rawStore<CONTINUE>(words, 1);
        t = classic_sha::cycleCount();

        // Block-3 padding while block 2 compresses. LOAD replaces words 0..7
        // only; words 9..14 are still the zeros of block 2 (see the polled
        // kernel), unless the boot test selected the full padding.
        waitCyclesSince(t, kPaddingWaitCycles);
        rawStore<32>(words, 0x80000000);
        if (full_padding) {
          rawStore<36>(words, 0); rawStore<40>(words, 0); rawStore<44>(words, 0);
          rawStore<48>(words, 0); rawStore<52>(words, 0); rawStore<56>(words, 0);
        }
        rawStore<60>(words, 0x00000100);
        waitCyclesSince(t, kCommandWaitCycles);
        rawStore<LOAD>(words, 1);
        t = classic_sha::cycleCount();
        waitCyclesSince(t, kLoadWaitCycles);
        rawStore<START>(words, 1);
        t = classic_sha::cycleCount();

        // The next nonce's block-1 words 8..15 go in once block 3 is latched.
#ifdef W390_SOAK_BREAK_LATCH
        // DELIBERATELY BROKEN soak build: no latch wait at all (the 531806c bug).
#else
        waitCyclesSince(t, kLatchWaitCycles);
#endif
        rawStore<32>(words, block1[8]);  rawStore<36>(words, block1[9]);
        rawStore<40>(words, block1[10]); rawStore<44>(words, block1[11]);
        rawStore<48>(words, block1[12]); rawStore<52>(words, block1[13]);
        rawStore<56>(words, block1[14]); rawStore<60>(words, block1[15]);
        waitCyclesSince(t, kCommandWaitCycles);
        rawStore<LOAD>(words, 1);
        t = classic_sha::cycleCount();
        waitCyclesSince(t, kLoadWaitCycles);
        final_word = classic_sha::rawLoad<28>(words);
        passes_filter = nerd_sha_ll_read_digest_swap_from_word(hash,
#ifdef NERDMINER_SHA_DIAGNOSTICS
          s_diag_force_digest,
#else
          false,
#endif
          final_word);
#ifdef NERDMINER_SHA_DIAGNOSTICS
        diagRecordNonce(nonce, hash, final_word, passes_filter);
#endif
        ++nonce;
      } while (!passes_filter && nonce != group_end);
      if (nonce - 1U == sample_target) {
        sampled = true;
        sample_nonce = nonce - 1U;
        sample_word = final_word;
      }
    }
    else
    {
    do
    {
      nerd_sha_ll_fill_text_block_sha256(sha_buffer, words);
      nerd_sha_control_write(words, SHA_256_START_REG);

      // This CPU-only conversion is safe to overlap with the first compression;
      // SHA_TEXT is not touched until the engine is confirmed idle.
      const uint32_t nonce_be = classic_sha::byteSwap(nonce);

      classic_sha::waitIdleOtherCpuStalled();
      nerd_sha_ll_fill_text_block_sha256_upper(sha_buffer + 64, nonce_be, words);
      nerd_sha_control_write(words, SHA_256_CONTINUE_REG);

      classic_sha::waitIdleOtherCpuStalled();
      nerd_sha_control_write(words, SHA_256_LOAD_REG);
      classic_sha::waitIdleOtherCpuStalled();
      // LOAD replaces words 0..7 only; words 9..14 are still the zeros of the
      // second block (measured on the classic ESP32 engine, not documented), so
      // the 32-byte message padding needs just words 8 and 15. The boot-time
      // known-answer test selects the full padding if a chip disagrees.
      if (full_padding) {
        nerd_sha_ll_fill_text_block_sha256_double(words);
      } else {
        words[8]  = 0x80000000;
        words[15] = 0x00000100;
      }
      nerd_sha_control_write(words, SHA_256_START_REG);

      classic_sha::waitIdleOtherCpuStalled();
      nerd_sha_control_write(words, SHA_256_LOAD_REG);
      classic_sha::waitIdleOtherCpuStalled();
      const uint32_t final_word = _DPORT_REG_READ(SHA_TEXT_BASE + 7 * sizeof(uint32_t));
      passes_filter = nerd_sha_ll_read_digest_swap_from_word(hash,
#ifdef NERDMINER_SHA_DIAGNOSTICS
        s_diag_force_digest,
#else
        false,
#endif
        final_word);
#ifdef NERDMINER_SHA_DIAGNOSTICS
      diagRecordNonce(nonce, hash, final_word, passes_filter);
#endif
      ++nonce;
    } while (!passes_filter && nonce != group_end);
    }
    DPORT_STALL_OTHER_CPU_END();
    esp_sha_unlock_memory_block();
    const uint32_t group_began_done = done;
    done = nonce - first;

    if (secureTransportCpuActive()) {
      // Idle peripheral, no shared-memory lock and no interrupt masking:
      // lend a bounded CPU window to TLS without a slow software nonce range.
      // TLS computation needs a bounded share of the other CPU. Record I/O
      // without this window failed a physical watchdog test. No SHA/DPORT
      // lock is held here and these cycles are never counted as hashes.
      const uint32_t windowUs = static_cast<uint32_t>(
          (esp_timer_get_time() - groupBegan) / 2);
      const uint32_t maximumUs = 1500U;
      const bool handshake = secureTransportHandshakeActive();
      const int64_t windowBegan = esp_timer_get_time();
      delayMicroseconds(windowUs < maximumUs ? windowUs : maximumUs);
      const uint32_t measuredWindowUs = static_cast<uint32_t>(esp_timer_get_time() - windowBegan);
      shaCpuWindowMicroseconds().fetch_add(measuredWindowUs, std::memory_order_relaxed);
      if (handshake) shaHandshakeWindowMicroseconds().fetch_add(measuredWindowUs, std::memory_order_relaxed);
    }
#if defined(NERDMINER_SHA_DIAGNOSTICS) && !defined(W390_KERNEL_SOAK)
    if (!diagFlushBurst(job)) {
      result->nonce_count = done;
      return;
    }
#endif
    // Outside the stall and lock. A mismatch makes every result of this group
    // suspect: hash the same group again with the polled kernel (unless the
    // soak forces the kernel; it compares the group itself).
    if (sampled && !checkTimedSample(job, sample_nonce, sample_word) && !soakKernelForced()) {
      done = group_began_done;
      continue;
    }
    if (passes_filter) {
      recordHardwareCandidate(result, job, nonce - 1U, hash);
      if (result->has_candidate) {
        result->nonce_count = done;
        result->timed_kernel = timed;
        return;
      }
    }
  }
}

// Known-answer test of the production kernel on public Bitcoin block headers.
// Each range starts three nonces before the block's own nonce (none of those
// passes the 16-bit filter), so the kernel must stop exactly on the real nonce
// with the reference SHA-256d.
static const char *const kClassicKnownHeaders[] = {
  "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd"
  "7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c",
  "010000006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000982051fd"
  "1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e857233e0e61bc6649ffff001d01e36299",
  "0100000050120119172a610421a6c3011dd330d9df07b63616c2cc1f1cd00200000000006657a925"
  "2aacd5c0b2940996ecff952228c3067cc38d4885efb5a4ac4247e9f337221b4d4c86041b0f2b5710"};
static constexpr unsigned kClassicKnownHeaderCount =
    sizeof(kClassicKnownHeaders) / sizeof(kClassicKnownHeaders[0]);

struct ClassicKnownAnswerRun {
  classic_kernel::KnownAnswer outcome;
  uint32_t nonce;           // the block's own nonce
  bool kernel_hit;          // the kernel stopped on a filter hit
  uint32_t kernel_word;     // its final word (H7), when it did
  uint32_t reference_word;  // the reference H7 for the block's own nonce
  uint32_t hit_nonce;       // where the kernel stopped, when it hit
  uint32_t completed;       // nonces it reported done
};

static ClassicKnownAnswerRun __attribute__((noinline)) classicKnownAnswer(const char *hex)
{
  JobRequest job{};
  job.generation = s_working_generation.load(std::memory_order_acquire);
  job.difficulty = 0.0;  // every filter hit is a candidate
  for (unsigned i = 0; i < 80; ++i) {
    const char pair[3] = {hex[i * 2], hex[i * 2 + 1], 0};
    job.raw_header[i] = static_cast<uint8_t>(strtoul(pair, nullptr, 16));
  }
  alignas(4) uint8_t buffer[128] = {};
  uint8_t hash[32], reference[32];
  memcpy(buffer, job.raw_header, 80);
  buffer[80] = 0x80; buffer[126] = 0x02; buffer[127] = 0x80;
  for (unsigned i = 0; i < 32; ++i)
    reinterpret_cast<uint32_t *>(buffer)[i] = __builtin_bswap32(reinterpret_cast<uint32_t *>(buffer)[i]);
  uint32_t known;
  memcpy(&known, job.raw_header + 76, sizeof(known));
  job.nonce_start = known - classic_kernel::kKnownAnswerLead;
  job.nonce_count = 8;
  JobResult result{};
  runClassicHardwareSequential(&job, &result, buffer, hash);
  mining_validation::referenceSha256d(job.raw_header, 80, reference);
  ClassicKnownAnswerRun run{};
  run.nonce = known;
  run.kernel_hit = result.has_candidate;
  run.kernel_word = __builtin_bswap32(reinterpret_cast<const uint32_t *>(result.hash)[7]);
  run.reference_word = __builtin_bswap32(reinterpret_cast<const uint32_t *>(reference)[7]);
  run.hit_nonce = result.nonce;
  run.completed = result.nonce_count;
  run.outcome = classic_kernel::classifyKnownAnswer(
      result.has_candidate, result.nonce, result.nonce_count, known,
      memcmp(result.hash, reference, sizeof(reference)) == 0,
      s_working_generation.load(std::memory_order_acquire) != job.generation);
  return run;
}

static bool classicKnownAnswers()
{
  for (const char *hex : kClassicKnownHeaders)
    if (classicKnownAnswer(hex).outcome != classic_kernel::KnownAnswer::Pass)
      return false;
  return true;
}

// Runtime net (b): once per new job, one public header through the timed
// kernel, with the shared engines already reserved by the caller.
// The decision (due, cancelled, failed) is classic_kernel::FallbackState::checkJob.
static void __attribute__((noinline)) classicTimedJobCheck(uint32_t generation)
{
  s_classic_kernel.checkJob(generation, kClassicKnownHeaderCount, [](unsigned header) {
    const ClassicKnownAnswerRun run = classicKnownAnswer(kClassicKnownHeaders[header]);
    if (run.outcome == classic_kernel::KnownAnswer::Fail)
      Serial.printf("CRITICAL: [SHA] timed kernel known-answer mismatch nonce=%08x kernel=%s%08x reference=%08x; "
                    "using the polled kernel until reboot\n", run.nonce,
                    run.kernel_hit ? "" : "no-hit/", run.kernel_word, run.reference_word);
    return run.outcome;
  });
}

#if NERDMINER_EXPERIMENTAL_SHA_TEXT_OVERLAP
// Returns false if the ESP32 peripheral did not preserve byte-exact SHA-256d
// semantics while text-register writes were overlapped with compression.
// The caller then discards all results from this attempt and recomputes the
// complete range with runClassicHardwareSequential().
static bool IRAM_ATTR __attribute__((noinline))
runClassicHardwarePipelined(const JobRequest *job,
                            JobResult *result,
                            uint8_t sha_buffer[128],
                            uint8_t hash[32])
{
  result->nonce_count = job->nonce_count;
  nerd_sha_ll_fill_text_block_sha256(sha_buffer);

  for (uint32_t offset = 0; offset < job->nonce_count; ++offset)
  {
    const uint32_t nonce = job->nonce_start + offset;

    // The first compression consumes the already prepared first block while
    // the CPU prepares the second block in the shared text window.
    sha_ll_start_block(SHA2_256);
    nerd_sha_ll_fill_text_block_sha256_upper(
        sha_buffer + 64, __builtin_bswap32(nonce));
    nerd_sha_hal_wait_idle();

    // CONTINUE latches the second block.  Its upper half can then be replaced
    // with the fixed padding for the second SHA while compression is active.
    sha_ll_continue_block(SHA2_256);
    nerd_sha_ll_fill_text_block_sha256_double();
    nerd_sha_hal_wait_idle();
    sha_ll_load(SHA2_256);
    nerd_sha_hal_wait_idle();

    // LOAD placed the first digest in words 0..7; words 8..15 already contain
    // the 32-byte-message padding.  Prepare half of the next first block while
    // the double-hash compression runs.
    sha_ll_start_block(SHA2_256);
    nerd_sha_ll_fill_text_block_sha256_upper_half(sha_buffer);
    nerd_sha_hal_wait_idle();
    sha_ll_load(SHA2_256);
    nerd_sha_hal_wait_idle();

    const bool sample = (offset & (kHardwarePipelineVerifyInterval - 1U)) == 0;
    const bool passes_early_filter = nerd_sha_ll_read_digest_swap_from_word(
        hash, sample, DPORT_REG_READ(SHA_TEXT_BASE + 7 * 4));

    // Complete preparation of the next first block only after copying any
    // digest that is needed for a sample or candidate.
    nerd_sha_ll_fill_text_block_sha256_lower_half(sha_buffer);

    if (sample || passes_early_filter)
    {
      if (!validateHardwareHash(job, nonce, hash))
        return false;
    }

    if (passes_early_filter)
      recordHardwareCandidate(result, job, nonce, hash);

    if ((offset & 0xFFU) == 0 &&
        s_working_generation.load(std::memory_order_acquire) != job->generation)
    {
      result->nonce_count = offset + 1;
      break;
    }
  }
  return true;
}
#endif

}  // namespace

#ifdef NERDMINER_SHA_DIAGNOSTICS
#include "crypto/ClassicShaDiagnostics.h"
#endif
#ifdef W390_KERNEL_SOAK
#include "crypto/W390KernelSoak.h"
#endif

// TLS may own the SHA-256 engine across network waits. Never wait on that
// engine: complete a bounded prefix with the proven software engine. The
// existing handoff resumes its exact suffix, so brief TLS work does not commit
// the miner to a whole slow 16,384-nonce software range.
static void runSoftwareFallback(const JobRequest *job, JobResult *result)
{
  const int64_t began = esp_timer_get_time();
  alignas(uint32_t) uint8_t padded[128] = {};
  uint32_t midstate[8], bake[17];
  uint8_t hash[32];
  memcpy(padded, job->raw_header, 80);
  padded[80] = 0x80;
  padded[126] = 0x02;
  padded[127] = 0x80;
  nerd_mids(midstate, padded);
  nerd_sha256_bake(midstate, padded + 64, bake);
  const uint32_t prefix = job->nonce_count < 64U ? job->nonce_count : 64U;
  result->nonce_count = prefix;
  for (uint32_t offset = 0; offset < prefix; ++offset) {
    const uint32_t nonce = job->nonce_start + offset;
    memcpy(padded + 76, &nonce, sizeof(nonce));
    if (nerd_sha256d_baked(midstate, padded + 64, bake, hash)) {
      recordHardwareCandidate(result, job, nonce, hash);
      if (result->has_candidate) {
        result->nonce_count = offset + 1;
        break;
      }
    }
    if ((offset & 0xffU) == 0 &&
        s_working_generation.load(std::memory_order_acquire) != job->generation) {
      result->nonce_count = offset + 1;
      break;
    }
  }
  shaFallbackMicroseconds().fetch_add(
      static_cast<uint32_t>(esp_timer_get_time() - began), std::memory_order_relaxed);
  shaFallbackNonces().fetch_add(result->nonce_count, std::memory_order_relaxed);
}

void classicShaSelfTest()
{
  if (!tryReserveClassicSha()) {
    s_classic_full_padding = 1;
    Serial.println("[SHA] classic self-test skipped (engine busy); using full padding, polled kernel");
    return;
  }
  // The padding choice is made on the polled kernel; the timed kernel then
  // has to pass the same known answers with it before it is used.
  bool ok = classicKnownAnswers();
  if (!ok) {
    s_classic_full_padding = 1;
    ok = classicKnownAnswers();
    Serial.printf("CRITICAL: [SHA] two-store padding failed known answers; full padding %s\n",
                  ok ? "passes, using it" : "ALSO FAILS");
  } else {
    Serial.println("[SHA] classic self-test passed (3 known blocks, two-store padding)");
  }
  esp_chip_info_t chip;
  esp_chip_info(&chip);
  const uint32_t cpuMhz = getCpuFrequencyMhz();
  if (!classic_kernel::timedKernelEligible(cpuMhz, chip.revision)) {
    Serial.printf("[SHA] timed kernel not eligible (cpu=%u MHz, chip rev %u); polled kernel\n",
                  cpuMhz, chip.revision);
  } else if (s_classic_kernel.enableIfKnownAnswersPass(true, kClassicKnownHeaderCount, [](unsigned header) {
               const ClassicKnownAnswerRun run = classicKnownAnswer(kClassicKnownHeaders[header]);
               if (run.outcome != classic_kernel::KnownAnswer::Pass)
                 Serial.printf("[SHA] timed known answer failed: block nonce=%08x hit=%d at %08x completed=%u kernel H7=%08x reference H7=%08x\n",
                               run.nonce, run.kernel_hit, run.hit_nonce, run.completed, run.kernel_word, run.reference_word);
               return run.outcome;
             })) {
    Serial.println("[SHA] timed kernel passed 3 known blocks; using it");
  } else {
    Serial.println("CRITICAL: [SHA] timed kernel failed known answers; polled kernel until reboot");
  }
  releaseClassicSha();
}

void minerWorkerHw(void * task_id)
{
  unsigned int miner_id = (uint32_t)task_id;
  Serial.printf("[MINER] %d Started minerWorkerHwEsp32D Task!\n", miner_id);

  std::shared_ptr<JobRequest> job;
  std::shared_ptr<JobResult> result;
  uint8_t hash[32];
  uint8_t sha_buffer[128];

  while (1)
  {
    finishWorkerRange(s_job_request_list_hw, job, result);
    {
      std::lock_guard<std::mutex> lock(s_job_mutex);
      if (!s_job_request_list_hw.empty())
      {
        job = s_job_request_list_hw.front();
        s_job_request_list_hw.pop_front();
      } else
        job.reset();
    }
    if (job)
    {
      result = std::make_shared<JobResult>();
      result->generation = job->generation;
      result->nonce = 0xFFFFFFFF;
      result->difficulty = job->difficulty;
      result->required_difficulty = job->difficulty;
      memcpy(sha_buffer, job->sha_buffer, 80);

      if (mining_validation::requiresFullDigest(job->difficulty, job->network_target)) {
        runReferenceRange(job.get(), result.get());
      } else if (secureTransportActive() || !tryReserveClassicSha()) {
        runSoftwareFallback(job.get(), result.get());
      } else {
      classicTimedJobCheck(job->generation);  // once per new job, while timed
#if NERDMINER_EXPERIMENTAL_SHA_TEXT_OVERLAP
      if (s_hardware_pipeline_enabled.load(std::memory_order_acquire))
      {
        if (!runClassicHardwarePipelined(job.get(), result.get(), sha_buffer, hash))
        {
          const uint32_t errors =
              s_hardware_pipeline_errors.fetch_add(1, std::memory_order_relaxed) + 1;
          s_hardware_pipeline_enabled.store(false, std::memory_order_release);
          Serial.printf("CRITICAL: ESP32 SHA pipeline validation failed; disabling pipeline (errors=%u)\n",
                        errors);

          result->nonce = 0xFFFFFFFF;
          result->has_candidate = false;
          result->difficulty = job->difficulty;
          memset(result->hash, 0, sizeof(result->hash));
          memset(result->raw_header, 0, sizeof(result->raw_header));
          runClassicHardwareSequential(job.get(), result.get(), sha_buffer, hash);
        }
      }
      else
        runClassicHardwareSequential(job.get(), result.get(), sha_buffer, hash);
#else
      runClassicHardwareSequential(job.get(), result.get(), sha_buffer, hash);
#endif
      releaseClassicSha();
      }
    } else
      vTaskDelay(2 / portTICK_PERIOD_MS);

    esp_task_wdt_reset();
  }
}

#endif  //CONFIG_IDF_TARGET_ESP32

#endif  //HARDWARE_SHA265


#define DELAY 100
#define REDRAW_EVERY 10

void restoreStat() {
  if(!Settings.saveStats) return;
  esp_err_t ret = nvs_flash_init();
  if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
    Serial.printf("[MONITOR] NVS partition is full or has invalid version, erasing...\n");
    nvs_flash_init();
  }

  ret = nvs_open("state", NVS_READWRITE, &stat_handle);

  size_t required_size = sizeof(double);
  nvs_get_blob(stat_handle, "best_diff", &best_diff, &required_size);
  nvs_get_u32(stat_handle, "Mhashes", &Mhashes);
  uint32_t nv_shares = 0, nv_valids = 0;
  nvs_get_u32(stat_handle, "shares", &nv_shares);
  nvs_get_u32(stat_handle, "valids", &nv_valids);
  shares = nv_shares;
  valids = nv_valids;
  nvs_get_u32(stat_handle, "templates", &templates);
  nvs_get_u64(stat_handle, "upTime", &upTime);

  uint32_t crc = crc32_reset();
  crc = crc32_add(crc, &best_diff, sizeof(best_diff));
  crc = crc32_add(crc, &Mhashes, sizeof(Mhashes));
  crc = crc32_add(crc, &nv_shares, sizeof(nv_shares));
  crc = crc32_add(crc, &nv_valids, sizeof(nv_valids));
  crc = crc32_add(crc, &templates, sizeof(templates));
  crc = crc32_add(crc, &upTime, sizeof(upTime));
  crc = crc32_finish(crc);

  uint32_t nv_crc = 0;
  if (nvs_get_u32(stat_handle, "crc32", &nv_crc) != ESP_OK || nv_crc != crc)
  {
    best_diff = 0.0;
    Mhashes = 0;
    shares = 0;
    valids = 0;
    templates = 0;
    upTime = 0;
  }
}

void saveStat() {
  if(!Settings.saveStats) return;
  Serial.printf("[MONITOR] Saving stats\n");
  portENTER_CRITICAL(&s_hash_counter_mux);
  const uint32_t savedMhashes = Mhashes;
  portEXIT_CRITICAL(&s_hash_counter_mux);
  nvs_set_blob(stat_handle, "best_diff", &best_diff, sizeof(best_diff));
  nvs_set_u32(stat_handle, "Mhashes", savedMhashes);
  nvs_set_u32(stat_handle, "shares", shares);
  nvs_set_u32(stat_handle, "valids", valids);
  nvs_set_u32(stat_handle, "templates", templates);
  nvs_set_u64(stat_handle, "upTime", upTime);

  uint32_t crc = crc32_reset();
  crc = crc32_add(crc, &best_diff, sizeof(best_diff));
  crc = crc32_add(crc, &savedMhashes, sizeof(savedMhashes));
  uint32_t nv_shares = shares;
  uint32_t nv_valids = valids;
  crc = crc32_add(crc, &nv_shares, sizeof(nv_shares));
  crc = crc32_add(crc, &nv_valids, sizeof(nv_valids));
  crc = crc32_add(crc, &templates, sizeof(templates));
  crc = crc32_add(crc, &upTime, sizeof(upTime));
  crc = crc32_finish(crc);
  nvs_set_u32(stat_handle, "crc32", crc);
}

void resetStat() {
    Serial.printf("[MONITOR] Resetting NVS stats\n");
    portENTER_CRITICAL(&s_hash_counter_mux);
    hashes = Mhashes = 0;
    portEXIT_CRITICAL(&s_hash_counter_mux);
    templates = elapsedKHs = shares = valids = 0;
    totalKHashes = upTime = 0;
    best_diff = 0.0;
    saveStat();
}

void runMonitor(void *name)
{

  Serial.println("[MONITOR] started");
  restoreStat();

  unsigned long mLastCheck = 0;

  resetToFirstScreen();

  unsigned long frame = 0;

  uint32_t seconds_elapsed = 0;

  totalKHashes = completedHashesSnapshot() / 1000ULL;
  uint32_t last_update_millis = millis();
  uint32_t uptime_frac = 0;

  while (1)
  {
    uint32_t now_millis = millis();
    if (now_millis < last_update_millis)
      now_millis = last_update_millis;
    
    uint32_t mElapsed = now_millis - mLastCheck;
    if (mElapsed >= 1000)
    { 
      mLastCheck = now_millis;
      last_update_millis = now_millis;
      const uint64_t currentHashes = completedHashesSnapshot();
      const uint64_t currentKHashes = currentHashes / 1000ULL;
      elapsedKHs = static_cast<uint32_t>(currentKHashes - totalKHashes);
      totalKHashes = currentKHashes;
      // Allocation-free telemetry is independent of rendering and UI smoothing.
#if defined(HARDWARE_SHA265) && defined(CONFIG_IDF_TARGET_ESP32)
      Serial.printf("[Work] t=%u completed=%llu generation=%u kernel=%s samples=%u mismatches=%u\n",
        now_millis, static_cast<unsigned long long>(currentHashes),
        s_working_generation.load(std::memory_order_acquire),
        classic_kernel::kernelName(s_classic_kernel.active()),
        s_classic_kernel.samples(), s_classic_kernel.mismatches());
#else
      Serial.printf("[Work] t=%u completed=%llu generation=%u\n", now_millis,
        static_cast<unsigned long long>(currentHashes),
        s_working_generation.load(std::memory_order_acquire));
#endif

      uptime_frac += mElapsed;
      while (uptime_frac >= 1000)
      {
        uptime_frac -= 1000;
        upTime ++;
      }

      drawCurrentScreen(mElapsed);

      // Monitor state when hashrate is 0.0
      if (elapsedKHs == 0)
      {
        Serial.printf(">>> [i] Miner: newJob>%s / inRun>%s) - Client: connected>%s / subscribed>%s / wificonnected>%s\n",
            "true",//(1) ? "true" : "false",
            isMinerSuscribed ? "true" : "false",
            client.connected() ? "true" : "false", isMinerSuscribed ? "true" : "false", WiFi.status() == WL_CONNECTED ? "true" : "false");
      }

      #ifdef DEBUG_MEMORY
      Serial.printf("### [Total Heap / Free heap / Min free heap]: %d / %d / %d \n", ESP.getHeapSize(), ESP.getFreeHeap(), ESP.getMinFreeHeap());
      Serial.printf("### Max stack usage: %d\n", uxTaskGetStackHighWaterMark(NULL));
      #endif

      seconds_elapsed++;

      if(seconds_elapsed % (saveIntervals[currentIntervalIndex]) == 0){
        saveStat();
        seconds_elapsed = 0;
        if(currentIntervalIndex < saveIntervalsSize - 1)
          currentIntervalIndex++;
      }    
    }
    animateCurrentScreen(frame);
    doLedStuff(frame);

    vTaskDelay(DELAY / portTICK_PERIOD_MS);
    frame++;
  }
}
