// Development-only physical differential test of the production SHA kernel.
#pragma once
#include <mbedtls/sha512.h>
static void diagPrintDigest(const char *label, const uint8_t *h)
{ Serial.print(label); for (unsigned i=0; i<32; ++i) Serial.printf("%02x",h[i]); Serial.println(); }
namespace {
static std::atomic<bool> s_diag_other_stop(false);
static std::atomic<bool> s_diag_other_done(false);
static void diagOtherSha(void *)
{
  uint8_t input[128] = {}, digest[64];
  uint32_t count = 0;
  while (!s_diag_other_stop.load()) {
    memcpy(input, &count, sizeof(count));
    mbedtls_sha512_ret(input, sizeof(input), digest, count & 1U);
    ++count;
    if ((count & 15U) == 0) vTaskDelay(1);
  }
  s_diag_other_done.store(true);
  vTaskDelete(nullptr);
}
static uint32_t s_diag_burst_count = 0;
struct DiagSample { uint32_t nonce, word; bool hit; uint8_t hash[32]; };
static DiagSample s_diag_samples[CLASSIC_SHA_GROUP_NONCES];
static bool diagCompareNonce(const JobRequest *job, uint32_t nonce,
                           const uint8_t hash[32], uint32_t final_word, bool passes_filter)
{
  alignas(4) uint8_t header[80], reference[32];
  memcpy(header,job->raw_header,80); memcpy(header+76,&nonce,4);
  mining_validation::referenceSha256d(header,80,reference);
  uint32_t reference_word; memcpy(&reference_word,reference+28,4);
  bool wanted_filter=reference[30]==0 && reference[31]==0;
  bool matches=reference_word==__builtin_bswap32(final_word) && passes_filter==wanted_filter;
  if (s_diag_force_digest || passes_filter) matches=matches && memcmp(reference,hash,32)==0;
  ++s_diag_checked;
  if (passes_filter) ++s_diag_hits;
  if (!matches) {
    ++s_diag_errors;
    Serial.printf("SHA DIAG MISMATCH nonce=%08x final_word=%08x full=%u\n",nonce,final_word,s_diag_force_digest);
    if (s_diag_force_digest || passes_filter) diagPrintDigest("hardware=",hash);
    diagPrintDigest("reference=",reference);
    return false;
  }
  if ((s_diag_checked & 4095U)==0) esp_task_wdt_reset();
  return true;
}
static bool diagFlushBurst(const JobRequest *job)
{
  bool ok = true;
  for (uint32_t i=0; i<s_diag_burst_count && ok; ++i) {
    const DiagSample &sample = s_diag_samples[i];
    ok = diagCompareNonce(job, sample.nonce, sample.hash, sample.word, sample.hit);
  }
  s_diag_burst_count = 0;
  if ((s_diag_checked & 4095U)==0) vTaskDelay(1);
  return ok;
}
// Called inside the locked group (at most CLASSIC_SHA_GROUP_NONCES times);
// the comparison runs in diagFlushBurst() after the lock is released.
static void diagRecordNonce(uint32_t nonce, const uint8_t hash[32], uint32_t word, bool hit)
{
  DiagSample &sample = s_diag_samples[s_diag_burst_count++];
  sample.nonce = nonce; sample.word = word; sample.hit = hit;
  if (s_diag_force_digest || hit) memcpy(sample.hash, hash, 32);
}
}
void runClassicShaDiagnostics()
{
  Serial.println("SHA DIAG BEGIN: fixed production kernel; public Bitcoin headers only");
  const char *headers[]={
    "010000000000000000000000000000000000000000000000000000000000000000000000"
    "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c",
    "010000006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d619000000000"
    "0982051fd1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e857233e0e61bc6649ffff001d01e36299",
    "0100000050120119172a610421a6c3011dd330d9df07b63616c2cc1f1cd0020000000000"
    "6657a9252aacd5c0b2940996ecff952228c3067cc38d4885efb5a4ac4247e9f337221b4d4c86041b0f2b5710"};
  const uint32_t boundaries[]={0,1,0xff,0x100,0xffff,0x10000,0x7fffffff,0x80000000,0xfffffffe,0xffffffff};
  if (!tryReserveClassicSha()) { Serial.println("SHA DIAG engine unavailable"); return; }
  TaskHandle_t other = nullptr;
  if (xTaskCreatePinnedToCore(diagOtherSha, "ShaOther", 8192, nullptr, 2, &other, 0) != pdPASS) {
    releaseClassicSha();
    Serial.println("SHA DIAG concurrent task unavailable");
    return;
  }
  for (unsigned mode=0; mode<3 && !s_diag_errors; ++mode) {
  SecureTransportCpuWork cpuWork(mode != 0, mode == 2);
  Serial.printf("SHA DIAG access mode=%u (0=normal, 1=record I/O, 2=handshake CPU window)\n", mode);
  for (unsigned h=0; h<3 && !s_diag_errors; ++h) {
    JobRequest job{}; job.generation=s_working_generation.load(); job.difficulty=1e100;
    for (unsigned i=0; i<80; ++i) { char pair[3]={headers[h][i*2],headers[h][i*2+1],0};
      job.raw_header[i]=strtoul(pair,nullptr,16); }
    alignas(4) uint8_t buffer[128]={}, hash[32];
    memcpy(buffer,job.raw_header,80); buffer[80]=0x80; buffer[126]=2; buffer[127]=0x80;
    for (unsigned i=0;i<32;++i) reinterpret_cast<uint32_t *>(buffer)[i]=__builtin_bswap32(reinterpret_cast<uint32_t *>(buffer)[i]);
    s_diag_force_digest=true;
    for (unsigned b=0;b<11 && !s_diag_errors;++b) {
      uint32_t known; memcpy(&known,job.raw_header+76,4);
      job.nonce_start=b<10 ? boundaries[b] : known;
      job.nonce_count=1; JobResult result{};
      runClassicHardwareSequential(&job,&result,buffer,hash);
      diagFlushBurst(&job);
    }
    if (s_diag_errors) break;
    job.nonce_start=0xda54f700U; job.nonce_count=200000;
    JobResult result{}; runClassicHardwareSequential(&job,&result,buffer,hash);
    diagFlushBurst(&job);
    Serial.printf("SHA DIAG full header=%u checked=%u errors=%u\n",h,s_diag_checked,s_diag_errors);
    if (s_diag_errors) break;
    s_diag_force_digest=false; job.difficulty=0;
    uint32_t completed=0;
    while (completed<131072 && !s_diag_errors) {
      job.nonce_start=0xda54f700U+completed; job.nonce_count=131072-completed;
      JobResult candidate{}; runClassicHardwareSequential(&job,&candidate,buffer,hash);
      completed+=candidate.nonce_count;
      if (!diagFlushBurst(&job)) break;
      if (candidate.has_candidate) {
        bool block=false;
        auto verdict=mining_validation::validateCandidate(job.generation,job.generation,
          candidate.raw_header,candidate.hash,job.network_target,&block);
        if (verdict!=mining_validation::CandidateValidationResult::Valid) ++s_diag_errors;
      }
    }
    Serial.printf("SHA DIAG filter header=%u completed=%u checked=%u hits=%u errors=%u\n",
      h,completed,s_diag_checked,s_diag_hits,s_diag_errors);
  }
  }
  releaseClassicSha();
  s_diag_other_stop.store(true);
  while (!s_diag_other_done.load()) vTaskDelay(1);
  Serial.printf("SHA DIAG COMPLETE checked=%u hits=%u errors=%u\n",s_diag_checked,s_diag_hits,s_diag_errors);
}
