#include <Arduino.h>
#include <ArduinoJson.h>
#include <WiFi.h>
#include <esp_task_wdt.h>
#include <esp_timer.h>
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
#include "crypto/BatchedSha.h"
#include "crypto/BatchedShaSelfTest.h"

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
// FX1's original S2/S3/C3 loop, unchanged apart from moving it out of
// minerWorkerHw. On the S3 and C3 it is the last fallback of the batched kernel.
static void runSha2EngineOriginalRange(const JobRequest *job, JobResult *result)
{
  uint8_t hash[32];
  uint8_t digest_mid[32];
  uint8_t sha_buffer[64];
#ifdef VALIDATION
  uint8_t doubleHash[32];
  uint32_t diget_mid[8];
  uint32_t bake[17];
#endif
      memcpy(digest_mid, job->midstate, sizeof(digest_mid));
      memcpy(sha_buffer, job->sha_buffer+64, sizeof(sha_buffer));
#ifdef VALIDATION
      nerd_mids(diget_mid, job->sha_buffer);
      nerd_sha256_bake(diget_mid, job->sha_buffer+64, bake);
#endif

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
          uint8_t header_tail[64];
          memcpy(header_tail, job->sha_buffer+64, sizeof(header_tail));
          ((uint32_t*)(header_tail+12))[0] = n;
          nerd_sha256d_baked(diget_mid, header_tail, bake, doubleHash);
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
}

#if defined(CONFIG_IDF_TARGET_ESP32S3) || defined(CONFIG_IDF_TARGET_ESP32C3)
#define NERDMINER_BATCHED_SHA 1
// ---------------------------------------------------------------------------
// ESP32-S3 / ESP32-C3: batched SHA-256d (src/crypto/BatchedSha.h).
//
// Relies on SHA behaviour measured on both chips (nerdminer s3bench/c3bench, W390):
// SHA_H is writable and is the state CONTINUE resumes from; SHA_TEXT and SHA_H
// are latched when START/CONTINUE is written, so SHA_TEXT may be rewritten while
// BUSY; the engine never modifies SHA_TEXT; SHA_H reads 0 while BUSY. A peripheral
// access costs ~13-15 CPU cycles on the S3 (~6-9 on the C3) against ~64-100 for a
// block, so the kernel minimises accesses and keeps SHA_TEXT writes off the
// critical path. A boot known-answer test through this production code selects
// G32 -> F32 -> the original loop.
//
// Test coverage: the host tests (tools/run_batched_sha_tests.sh) do NOT compile the
// BSHA_* macros or BatchedShaEngine below. They run BatchedSha.h against a hand-written
// model of the peripheral, so a fault in this register code passes the whole host
// suite; for example dropping the volatile/"memory" from the accesses, or reading
// SHA_H[0..6] before the BUSY wait. Such faults are caught only on the chip: by the
// boot known-answer test, and by the *_SHA_DIAG builds. A boot-test failure is not
// an error the user sees: the board falls back to a slower kernel (F32 or the
// original loop) until reboot and logs it once on serial ("[SHA] ... FAIL"). A fault
// the boot test misses (e.g. one that hits one nonce in a thousand) loses hashes;
// a wrong candidate hash is still rejected by runMiner's reference SHA-256d check
// before submission.
#ifndef NERDMINER_BATCHED_SHA_FORCE_KERNEL
#define NERDMINER_BATCHED_SHA_FORCE_KERNEL 0  // 0: self-test picks; 1: start at F32; 2: original loop
#endif

static_assert(SHA_START_REG - DR_REG_SHA_BASE == 0x10 && SHA_CONTINUE_REG - DR_REG_SHA_BASE == 0x14 &&
              SHA_BUSY_REG - DR_REG_SHA_BASE == 0x18 && SHA_H_BASE - DR_REG_SHA_BASE == 0x40 &&
              SHA_TEXT_BASE - DR_REG_SHA_BASE == 0x80, "ESP32-S3/C3 SHA register map");

#if defined(CONFIG_IDF_TARGET_ESP32S3)
// Xtensa: plain stores and loads (no MEMW per access); MEMW only around START/CONTINUE.
#define BSHA_ST(off, v) __asm__ __volatile__("s32i %0, %1, %2" :: "r"((uint32_t)(v)), "r"(base), "i"(off) : "memory")
#define BSHA_LD(off) ({ uint32_t _w; __asm__ __volatile__("l32i %0, %1, %2" : "=r"(_w) : "r"(base), "i"(off) : "memory"); _w; })
#define BSHA_MEMW() __asm__ __volatile__("memw" ::: "memory")
#else
// RISC-V (C3): plain volatile accesses, as IDF's own C3 SHA HAL uses; in-order core,
// a BUSY read right after a command never missed it (0/1000 on silicon).
#define BSHA_ST(off, v) (((volatile uint32_t *)DR_REG_SHA_BASE)[(off) / 4] = (uint32_t)(v))
#define BSHA_LD(off) (((volatile uint32_t *)DR_REG_SHA_BASE)[(off) / 4])
#define BSHA_MEMW() __asm__ __volatile__("" ::: "memory")
#endif
#define BSHA_H(k) (0x40 + 4 * (k))
#define BSHA_T(k) (0x80 + 4 * (k))

template <bool kPollWord7, int kBroken>  // kBroken: development-only faults, 0 in every release build
struct BatchedShaEngine {
  static constexpr uint32_t base = DR_REG_SHA_BASE;
  static inline __attribute__((always_inline)) void command(uint32_t off) {
    BSHA_MEMW();
    if (off == 0x10) BSHA_ST(0x10, 1); else BSHA_ST(0x14, 1);
    BSHA_MEMW();  // later loads must not pass the command
  }
  static inline __attribute__((always_inline)) uint32_t waitWord7() {
    uint32_t w = 0;
    if (kPollWord7) {  // SHA_H reads 0 while BUSY; a genuine 0 falls through to BUSY
      for (int k = 8; k; --k) { w = BSHA_LD(BSHA_H(7)); if (w) return w; }
    }
    while (BSHA_LD(0x18)) {}
    return BSHA_LD(BSHA_H(7));
  }
  static inline __attribute__((always_inline)) void begin() {
    REG_WRITE(SHA_MODE_REG, SHA2_256);
    BSHA_ST(BSHA_T(9), 0); BSHA_ST(BSHA_T(10), 0); BSHA_ST(BSHA_T(11), 0);
    BSHA_ST(BSHA_T(12), 0); BSHA_ST(BSHA_T(13), 0); BSHA_ST(BSHA_T(14), 0);
  }
  static inline __attribute__((always_inline)) void loadBlock2(const uint32_t t[3], uint32_t nonce) {
    BSHA_ST(BSHA_T(0), t[0]); BSHA_ST(BSHA_T(1), t[1]); BSHA_ST(BSHA_T(2), t[2]);
    BSHA_ST(BSHA_T(3), nonce); BSHA_ST(BSHA_T(4), 0x80); BSHA_ST(BSHA_T(5), 0);
    BSHA_ST(BSHA_T(6), 0); BSHA_ST(BSHA_T(7), 0); BSHA_ST(BSHA_T(8), 0);
    BSHA_ST(BSHA_T(15), 0x80020000);
  }
  static inline __attribute__((always_inline)) void setNonce(uint32_t nonce) {
    if (kBroken == 2 && (nonce & 1023U) == 517U) return;  // stale nonce, rare: the boot test cannot see it
    BSHA_ST(BSHA_T(3), nonce);
  }
  static inline __attribute__((always_inline)) void setState(const uint32_t m[8]) {
    BSHA_ST(BSHA_H(0), m[0]); BSHA_ST(BSHA_H(1), m[1]); BSHA_ST(BSHA_H(2), m[2]);
    if (kBroken != 1) BSHA_ST(BSHA_H(3), m[3]);
    BSHA_ST(BSHA_H(4), m[4]); BSHA_ST(BSHA_H(5), m[5]); BSHA_ST(BSHA_H(6), m[6]); BSHA_ST(BSHA_H(7), m[7]);
  }
  static inline __attribute__((always_inline)) void resume() { command(0x14); }
  static inline __attribute__((always_inline)) void start() { command(0x10); }
  static inline __attribute__((always_inline)) void readHead(uint32_t o[8]) {
    o[0] = BSHA_LD(BSHA_H(0)); o[1] = BSHA_LD(BSHA_H(1)); o[2] = BSHA_LD(BSHA_H(2)); o[3] = BSHA_LD(BSHA_H(3));
    o[4] = BSHA_LD(BSHA_H(4)); o[5] = BSHA_LD(BSHA_H(5)); o[6] = BSHA_LD(BSHA_H(6));
  }
  static inline __attribute__((always_inline)) void readState(uint32_t o[8]) { o[7] = waitWord7(); readHead(o); }
  static inline __attribute__((always_inline)) void loadDigest(const uint32_t d[8]) {
    BSHA_ST(BSHA_T(0), d[0]); BSHA_ST(BSHA_T(1), d[1]); BSHA_ST(BSHA_T(2), d[2]); BSHA_ST(BSHA_T(3), d[3]);
    BSHA_ST(BSHA_T(4), d[4]); BSHA_ST(BSHA_T(5), d[5]); BSHA_ST(BSHA_T(6), d[6]); BSHA_ST(BSHA_T(7), d[7]);
  }
  static inline __attribute__((always_inline)) void loadFinalPadding() {
    BSHA_ST(BSHA_T(8), 0x80); BSHA_ST(BSHA_T(15), 0x00010000);
  }
  static inline __attribute__((always_inline)) uint32_t finalWord() { return waitWord7(); }
};

// Development only: 1 = midstate word 3 never written (the boot test must reject G32),
// 2 = stale nonce once per 1,024 (passes the boot test; the diagnostics build must fail).
#ifndef NERDMINER_BATCHED_SHA_BREAK_G32
#define NERDMINER_BATCHED_SHA_BREAK_G32 0
#endif
using BatchedShaEngineG32 = BatchedShaEngine<true, NERDMINER_BATCHED_SHA_BREAK_G32>;
using BatchedShaEngineF32 = BatchedShaEngine<false, 0>;

enum BatchedShaKernel : uint8_t { BATCHED_SHA_G32 = 0, BATCHED_SHA_F32 = 1, BATCHED_SHA_ORIGINAL = 2 };
static const char *const kBatchedShaKernelNames[] = {
    "G32 (batched x32, SHA_H[7] polling)", "F32 (batched x32, BUSY polling)", "FX1 original loop"};
static BatchedShaKernel s_batched_sha_kernel = BATCHED_SHA_ORIGINAL;

// Same candidate rule, generation rule and nonce_count as runSha2EngineOriginalRange.
template <class Engine, class OnFinal>
static inline __attribute__((always_inline)) uint32_t
runBatchedRange(const JobRequest *job, JobResult *result, OnFinal &onFinal)
{
  uint32_t tail[3];
  memcpy(tail, job->sha_buffer + 64, sizeof(tail));
  auto onFilterPass = [job, result](uint32_t nonce, const uint32_t *words) -> bool {
    uint8_t hash[32];
    memcpy(hash, words, sizeof(hash));
    const double diff_hash = diff_from_target(hash);
    if (diff_hash >= job->difficulty ||
        mining_validation::hashMeetsTarget(hash, job->network_target)) {
      result->difficulty = diff_hash;
      result->nonce = nonce;
      result->has_candidate = true;
      memcpy(result->hash, hash, sizeof(hash));
      memcpy(result->raw_header, job->raw_header, sizeof(result->raw_header));
      memcpy(result->raw_header + 76, &result->nonce, sizeof(result->nonce));
      return true;
    }
    return false;
  };
  auto stale = [job]() {
    return s_working_generation.load(std::memory_order_acquire) != job->generation;
  };
  return batched_sha::hashRange<Engine>(job->midstate, tail, job->nonce_start, job->nonce_count,
                                   onFilterPass, onFinal, stale);
}

// Plain functions: GCC drops IRAM_ATTR's section on template instantiations.
static uint32_t IRAM_ATTR __attribute__((noinline)) runBatchedG32Range(const JobRequest *job, JobResult *result)
{
  batched_sha::NoRecord noRecord;
  return runBatchedRange<BatchedShaEngineG32>(job, result, noRecord);
}
static uint32_t IRAM_ATTR __attribute__((noinline)) runBatchedF32Range(const JobRequest *job, JobResult *result)
{
  batched_sha::NoRecord noRecord;
  return runBatchedRange<BatchedShaEngineF32>(job, result, noRecord);
}

// Caller holds esp_sha_acquire_hardware(). result->nonce_count is preset to job->nonce_count.
static void runBatchedShaRange(BatchedShaKernel kernel, const JobRequest *job, JobResult *result)
{
  if (kernel == BATCHED_SHA_G32)
    result->nonce_count = runBatchedG32Range(job, result);
  else if (kernel == BATCHED_SHA_F32)
    result->nonce_count = runBatchedF32Range(job, result);
  else
    runSha2EngineOriginalRange(job, result);
}

// Production midstate, computed exactly as runStratumWorker does.
static void batchedHardwareMidstate(JobRequest &job)
{
  memset(job.sha_buffer + 80, 0, 48);
  job.sha_buffer[80] = 0x80; job.sha_buffer[126] = 0x02; job.sha_buffer[127] = 0x80;
  sha_hal_hash_block(SHA2_256, job.sha_buffer, 64/4, true);
  sha_hal_read_digest(SHA2_256, job.midstate);
}

static void scribbleShaText()  // what another SHA user may leave behind between jobs
{
  for (int k = 0; k < 16; ++k) REG_WRITE(SHA_TEXT_BASE + 4 * k, 0xA5A50000U ^ (k * 0x01010101U));
}

// Known-answer test through runBatchedShaRange, over the windows in
// src/crypto/BatchedShaSelfTest.h (genesis and block 125552). Each window checks that
// the real nonce is reported as the candidate with the right hash and pos + 1 nonces
// completed, at batch slot 0, 17, 28 and 31, slot 3 of a second batch, the last slot
// of a single partial batch and the last slot of a final partial batch after a full
// one; then that the resumed suffix (FX1's candidate hand-off) completes with no
// candidate. No window contains a nonce with low byte 0, so the kernel never reads
// the job generation here and a new stratum job during the test cannot fail it
// (checked at compile time in that header). Caller holds the SHA hardware.
static bool batchedKernelKnownAnswers(BatchedShaKernel kernel)
{
  using namespace batched_sha_self_test;
  static JobRequest job;
  static JobResult result;
  for (const Window &w : kWindows) {
    uint8_t want[32];
    memset(&job, 0, sizeof(job));
    for (int i = 0; i < 80; ++i) { char pair[3] = {kHeaders[w.block][2*i], kHeaders[w.block][2*i+1], 0}; job.raw_header[i] = strtoul(pair, nullptr, 16); }
    for (int i = 0; i < 32; ++i) { char pair[3] = {kHashes[w.block][2*i], kHashes[w.block][2*i+1], 0}; want[i] = strtoul(pair, nullptr, 16); }
    memcpy(job.sha_buffer, job.raw_header, 80);
    batchedHardwareMidstate(job);
    uint32_t nonce;
    memcpy(&nonce, job.raw_header + 76, sizeof(nonce));
    if (nonce != kNonces[w.block]) return false;
    job.generation = s_working_generation.load(std::memory_order_acquire);
    job.difficulty = 1.0;
    job.nonce_start = nonce - w.pos;
    job.nonce_count = w.count;
    memset(&result, 0, sizeof(result));
    result.nonce_count = job.nonce_count;
    scribbleShaText();
    runBatchedShaRange(kernel, &job, &result);
    if (!result.has_candidate || result.nonce != nonce || result.nonce_count != w.pos + 1 ||
        memcmp(result.hash, want, 32) != 0)
      return false;
    const bool resumed = mining_validation::resumeCompletedPrefix(job, result.nonce_count, job.generation);
    if (resumed != (w.pos + 1 < w.count)) return false;
    if (!resumed) continue;  // the candidate was the last nonce of the window
    memset(&result, 0, sizeof(result));
    result.nonce_count = job.nonce_count;
    scribbleShaText();
    runBatchedShaRange(kernel, &job, &result);
    if (result.has_candidate || result.nonce_count != w.count - w.pos - 1) return false;
  }
  return true;
}

static void selectBatchedShaKernel()
{
  esp_sha_acquire_hardware();
  const bool g32 = NERDMINER_BATCHED_SHA_FORCE_KERNEL == 0 && batchedKernelKnownAnswers(BATCHED_SHA_G32);
  const bool f32 = !g32 && NERDMINER_BATCHED_SHA_FORCE_KERNEL <= 1 && batchedKernelKnownAnswers(BATCHED_SHA_F32);
  esp_sha_release_hardware();
  s_batched_sha_kernel = g32 ? BATCHED_SHA_G32 : (f32 ? BATCHED_SHA_F32 : BATCHED_SHA_ORIGINAL);
  Serial.printf("[SHA] %s kernel self-test: G32 %s, F32 %s -> using %s\n", CONFIG_IDF_TARGET,
                NERDMINER_BATCHED_SHA_FORCE_KERNEL > 0 ? "skipped (forced)" : (g32 ? "pass" : "FAIL"),
                g32 ? "not needed" : (NERDMINER_BATCHED_SHA_FORCE_KERNEL > 1 ? "skipped (forced)" : (f32 ? "pass" : "FAIL")),
                kBatchedShaKernelNames[s_batched_sha_kernel]);
}

#ifdef NERDMINER_SHA_DIAGNOSTICS
#include "crypto/BatchedShaDiagnostics.h"
#endif
#endif  // CONFIG_IDF_TARGET_ESP32S3 || CONFIG_IDF_TARGET_ESP32C3

void minerWorkerHw(void * task_id)
{
  unsigned int miner_id = (uint32_t)task_id;
  Serial.printf("[MINER] %d Started minerWorkerHw Task!\n", miner_id);

  std::shared_ptr<JobRequest> job;
  std::shared_ptr<JobResult> result;
  uint32_t wdt_counter = 0;
#ifdef NERDMINER_BATCHED_SHA
  selectBatchedShaKernel();
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

      esp_sha_acquire_hardware();
#ifdef NERDMINER_BATCHED_SHA
      runBatchedShaRange(s_batched_sha_kernel, job.get(), result.get());
#else
      runSha2EngineOriginalRange(job.get(), result.get());
#endif
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
static bool diagCheckNonce(const JobRequest *job, uint32_t nonce,
                           const uint8_t hash[32], uint32_t final_word,
                           bool passes_filter);
#endif

static constexpr uint32_t CLASSIC_SHA_GROUP_NONCES = 1024;

static void IRAM_ATTR __attribute__((noinline, optimize("O2")))
runClassicHardwareSequential(const JobRequest *job,
                                         JobResult *result,
                                         uint8_t sha_buffer[128],
                                         uint8_t hash[32])
{
  result->nonce_count = job->nonce_count;
  uint32_t *const words = nerd_sha_text_words();
  bool memory_locked = false;
  int64_t groupBegan = 0;
  for (uint32_t offset = 0; offset < job->nonce_count; ++offset)
  {
    const uint32_t nonce = job->nonce_start + offset;
    // SHA_TEXT is shared by SHA-1/256/384/512, not only SHA-256 users.
    // Amortize the shared-memory critical section over a bounded group. Other SHA
    // algorithms cannot start while this critical section is held. Wait for all engines
    // on acquisition; subsequent nonces already end with SHA-256 confirmed idle.
    // Local interrupts are masked by the SDK lock: never yield or perform
    // network, queue or reference-validation work while holding this lock.
    if (!memory_locked) {
      groupBegan = esp_timer_get_time();
      esp_sha_lock_memory_block();
      sha_hal_wait_idle();
      DPORT_STALL_OTHER_CPU_START();
      memory_locked = true;
    }
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
    nerd_sha_ll_fill_text_block_sha256_double(words);
    nerd_sha_control_write(words, SHA_256_START_REG);

    classic_sha::waitIdleOtherCpuStalled();
    nerd_sha_control_write(words, SHA_256_LOAD_REG);
    classic_sha::waitIdleOtherCpuStalled();
    const uint32_t final_word = _DPORT_REG_READ(SHA_TEXT_BASE + 7 * sizeof(uint32_t));
    const bool passes_filter = nerd_sha_ll_read_digest_swap_from_word(hash,
#ifdef NERDMINER_SHA_DIAGNOSTICS
      s_diag_force_digest,
#else
      false,
#endif
      final_word);
    if (passes_filter || ((offset + 1U) & (CLASSIC_SHA_GROUP_NONCES - 1U)) == 0 || offset + 1U == job->nonce_count) {
      DPORT_STALL_OTHER_CPU_END();
      esp_sha_unlock_memory_block();
      memory_locked = false;
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
    }
#ifdef NERDMINER_SHA_DIAGNOSTICS
    if (!diagCheckNonce(job, nonce, hash, final_word, passes_filter)) {
      result->nonce_count = offset + 1;
      break;
    }
#endif
    if (passes_filter) {
      recordHardwareCandidate(result, job, nonce, hash);
      if (result->has_candidate) {
        result->nonce_count = offset + 1;
        break;
      }
    }

    if ((offset & 0xFFU) == 0 &&
        s_working_generation.load(std::memory_order_acquire) != job->generation)
    {
      result->nonce_count = offset + 1;
      break;
    }
  }
  if (memory_locked) {
    DPORT_STALL_OTHER_CPU_END();
    esp_sha_unlock_memory_block();
  }
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
      Serial.printf("[Work] t=%u completed=%llu generation=%u\n", now_millis,
        static_cast<unsigned long long>(currentHashes),
        s_working_generation.load(std::memory_order_acquire));

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
