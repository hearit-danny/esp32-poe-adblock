#include "blocklist.h"

#include <Arduino.h>
#include <esp_heap_caps.h>
#include <esp_partition.h>
#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>
#include <string.h>

#include "fnv.h"

// The Bloom filter lives in RAM as four 32 KB blocks rather than one 128 KB
// block: on ESP32 without PSRAM the largest free DRAM block after lwIP and the
// EMAC driver is often below 128 KB, while four smaller blocks always fit.
static constexpr uint32_t BLOOM_CHUNK_BYTES = 32768;
static constexpr uint32_t BLOOM_CHUNK_SHIFT = 18;  // bits per chunk = 2^18
static constexpr uint32_t BLOOM_CHUNKS = BLK_MAX_BLOOM_BYTES / BLOOM_CHUNK_BYTES;
static constexpr uint32_t PAGE = 4096;

static const char *const SLOT_LABELS[2] = {"blk_a", "blk_b"};

static SemaphoreHandle_t g_lock;
static uint8_t *g_bloom[BLOOM_CHUNKS];
static const esp_partition_t *g_parts[2];

// Active list, guarded by g_lock.
static int g_active = -1;
static BlocklistHeader g_hdr;
static const uint8_t *g_keys;  // into the mapped slot
static esp_partition_mmap_handle_t g_map;
static bool g_mapped;

// Upload state, touched only from the AsyncTCP task.
static bool g_up_active;
static int g_up_slot;
static uint8_t *g_up_page;
static size_t g_up_fill;      // bytes in g_up_page
static uint32_t g_up_flash;   // flash offset of g_up_page
static uint32_t g_up_total;   // from the header, 0 until it is parsed
static uint32_t g_up_received;

static uint32_t g_crc_table[256];

static void crc_init() {
  for (uint32_t i = 0; i < 256; i++) {
    uint32_t c = i;
    for (int b = 0; b < 8; b++) c = (c & 1) ? 0xEDB88320UL ^ (c >> 1) : c >> 1;
    g_crc_table[i] = c;
  }
}

// Standard CRC-32, same as Python zlib.crc32(data, crc).
static uint32_t crc32_update(uint32_t crc, const uint8_t *p, size_t n) {
  crc = ~crc;
  while (n--) crc = g_crc_table[(crc ^ *p++) & 0xFF] ^ (crc >> 8);
  return ~crc;
}

static bool header_valid(const BlocklistHeader &h, uint32_t capacity) {
  if (h.magic != BLK_MAGIC || h.version != BLK_VERSION) return false;
  if (h.header_size != BLK_HEADER_SIZE || h.key_bytes != BLK_KEY_BYTES) return false;
  if (h.bloom_bits == 0 || h.bloom_bits % 8 || h.bloom_bits / 8 > BLK_MAX_BLOOM_BYTES) return false;
  if (h.bloom_k == 0 || h.bloom_k > BLK_MAX_K) return false;
  uint64_t expect = (uint64_t)BLK_HEADER_SIZE + h.bloom_bits / 8 + (uint64_t)h.entry_count * BLK_KEY_BYTES;
  return h.total_size == expect && h.total_size <= capacity;
}

// CRC over bloom + keys as stored in the partition.
static bool slot_crc_ok(const esp_partition_t *part, const BlocklistHeader &h, uint8_t *buf) {
  uint32_t crc = 0;
  for (uint32_t off = BLK_HEADER_SIZE; off < h.total_size; off += PAGE) {
    uint32_t n = min<uint32_t>(PAGE, h.total_size - off);
    if (esp_partition_read(part, off, buf, n) != ESP_OK) return false;
    crc = crc32_update(crc, buf, n);
  }
  return crc == h.payload_crc32;
}

static bool read_committed_header(int slot, BlocklistHeader &h) {
  if (!g_parts[slot]) return false;
  if (esp_partition_read(g_parts[slot], 0, &h, sizeof(h)) != ESP_OK) return false;
  return h.commit_seq != BLK_UNCOMMITTED && header_valid(h, g_parts[slot]->size);
}

static bool bloom_test(uint64_t h64) {
  uint64_t h1 = h64 & 0xFFFFFFFFULL;
  uint64_t h2 = (h64 >> 32) | 1;
  for (uint32_t i = 0; i < g_hdr.bloom_k; i++) {
    uint32_t bit = (uint32_t)((h1 + i * h2) % g_hdr.bloom_bits);
    const uint8_t *chunk = g_bloom[bit >> BLOOM_CHUNK_SHIFT];
    uint32_t local = bit & ((1UL << BLOOM_CHUNK_SHIFT) - 1);
    if (!(chunk[local >> 3] & (1 << (local & 7)))) return false;
  }
  return true;
}

static inline uint64_t key_at(uint32_t i) {
  const uint8_t *p = g_keys + (size_t)i * BLK_KEY_BYTES;
  return (uint64_t)p[0] | ((uint64_t)p[1] << 8) | ((uint64_t)p[2] << 16) | ((uint64_t)p[3] << 24) |
         ((uint64_t)p[4] << 32);
}

static bool keys_contain(uint64_t key) {
  uint32_t lo = 0, hi = g_hdr.entry_count;
  while (lo < hi) {
    uint32_t mid = lo + (hi - lo) / 2;
    uint64_t k = key_at(mid);
    if (k == key) return true;
    if (k < key) lo = mid + 1;
    else hi = mid;
  }
  return false;
}

static void unload_locked() {
  if (g_mapped) esp_partition_munmap(g_map);
  g_mapped = false;
  g_keys = nullptr;
  g_active = -1;
  memset(&g_hdr, 0, sizeof(g_hdr));
}

// Maps `slot`, copies its Bloom filter into RAM and makes it the active list.
static bool load_slot(int slot, const BlocklistHeader &h) {
  const void *ptr;
  esp_partition_mmap_handle_t map;
  if (esp_partition_mmap(g_parts[slot], 0, h.total_size, ESP_PARTITION_MMAP_DATA, &ptr, &map) != ESP_OK) {
    Serial.printf("[blocklist] mmap of %s failed\n", SLOT_LABELS[slot]);
    return false;
  }
  const uint8_t *base = (const uint8_t *)ptr;
  uint32_t bloom_bytes = h.bloom_bits / 8;

  xSemaphoreTake(g_lock, portMAX_DELAY);
  unload_locked();
  for (uint32_t c = 0; c < BLOOM_CHUNKS; c++) {
    uint32_t off = c * BLOOM_CHUNK_BYTES;
    uint32_t n = off < bloom_bytes ? min(BLOOM_CHUNK_BYTES, bloom_bytes - off) : 0;
    if (n) memcpy(g_bloom[c], base + BLK_HEADER_SIZE + off, n);
    memset(g_bloom[c] + n, 0, BLOOM_CHUNK_BYTES - n);
  }
  g_hdr = h;
  g_keys = base + BLK_HEADER_SIZE + bloom_bytes;
  g_map = map;
  g_mapped = true;
  g_active = slot;
  xSemaphoreGive(g_lock);
  return true;
}

bool blocklist_begin() {
  crc_init();
  g_lock = xSemaphoreCreateMutex();
  for (uint32_t c = 0; c < BLOOM_CHUNKS; c++) {
    g_bloom[c] = (uint8_t *)heap_caps_malloc(BLOOM_CHUNK_BYTES, MALLOC_CAP_8BIT);
    if (!g_bloom[c]) {
      Serial.printf("[blocklist] bloom alloc failed at chunk %u\n", (unsigned)c);
      return false;
    }
    memset(g_bloom[c], 0, BLOOM_CHUNK_BYTES);
  }
  for (int s = 0; s < 2; s++) {
    g_parts[s] = esp_partition_find_first(ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_ANY, SLOT_LABELS[s]);
    if (!g_parts[s]) Serial.printf("[blocklist] partition %s missing\n", SLOT_LABELS[s]);
  }

  uint8_t *buf = (uint8_t *)malloc(PAGE);
  if (!buf) return false;
  BlocklistHeader h[2];
  bool ok[2];
  for (int s = 0; s < 2; s++) {
    ok[s] = read_committed_header(s, h[s]) && slot_crc_ok(g_parts[s], h[s], buf);
    if (ok[s]) Serial.printf("[blocklist] %s: seq %u, %u entries\n", SLOT_LABELS[s], (unsigned)h[s].commit_seq, (unsigned)h[s].entry_count);
  }
  free(buf);

  int pick = -1;
  if (ok[0] && ok[1]) pick = h[1].commit_seq > h[0].commit_seq ? 1 : 0;
  else if (ok[0]) pick = 0;
  else if (ok[1]) pick = 1;
  if (pick < 0 || !load_slot(pick, h[pick])) {
    Serial.println("[blocklist] no valid blocklist in flash, forwarding every query");
  }
  return true;
}

bool blocklist_contains(const char *name, size_t len) {
  xSemaphoreTake(g_lock, portMAX_DELAY);
  bool hit = false;
  if (g_active >= 0) {
    const char *p = name;
    size_t rest = len;
    while (rest) {
      const char *dot = (const char *)memchr(p, '.', rest);
      if (!dot) break;  // single label left (a TLD): never listed
      uint64_t h64 = fnv1a64(p, rest);
      if (bloom_test(h64) && keys_contain(fold40(h64))) {
        hit = true;
        break;
      }
      rest -= (dot + 1) - p;
      p = dot + 1;
    }
  }
  xSemaphoreGive(g_lock);
  return hit;
}

BlocklistInfo blocklist_info() {
  BlocklistInfo info = {};
  xSemaphoreTake(g_lock, portMAX_DELAY);
  info.loaded = g_active >= 0;
  info.active_slot = g_active;
  info.entry_count = g_hdr.entry_count;
  info.bloom_bits = g_hdr.bloom_bits;
  info.bloom_k = g_hdr.bloom_k;
  info.build_time = g_hdr.build_time;
  info.commit_seq = g_hdr.commit_seq;
  info.slot_capacity = g_parts[0] ? g_parts[0]->size : 0;
  xSemaphoreGive(g_lock);
  return info;
}

bool blocklist_upload_active() { return g_up_active; }

void blocklist_upload_abort() {
  free(g_up_page);
  g_up_page = nullptr;
  g_up_active = false;
}

bool blocklist_upload_begin(const char *&err) {
  if (g_up_active) {
    err = "Upload Already Running";
    return false;
  }
  xSemaphoreTake(g_lock, portMAX_DELAY);
  int active = g_active;
  xSemaphoreGive(g_lock);
  g_up_slot = active == 0 ? 1 : 0;
  if (!g_parts[g_up_slot]) {
    err = "Blocklist Partition Missing";
    return false;
  }
  g_up_page = (uint8_t *)malloc(PAGE);
  if (!g_up_page) {
    err = "Out Of Memory";
    return false;
  }
  g_up_fill = 0;
  g_up_flash = 0;
  g_up_total = 0;
  g_up_received = 0;
  g_up_active = true;
  return true;
}

static bool flush_page(const char *&err) {
  const esp_partition_t *part = g_parts[g_up_slot];
  if (esp_partition_erase_range(part, g_up_flash, PAGE) != ESP_OK ||
      esp_partition_write(part, g_up_flash, g_up_page, g_up_fill) != ESP_OK) {
    err = "Flash Write Failed";
    return false;
  }
  g_up_flash += PAGE;
  g_up_fill = 0;
  return true;
}

bool blocklist_upload_write(const uint8_t *data, size_t len, const char *&err) {
  while (len) {
    size_t n = min(len, (size_t)(PAGE - g_up_fill));
    memcpy(g_up_page + g_up_fill, data, n);
    g_up_fill += n;
    g_up_received += n;
    data += n;
    len -= n;

    if (!g_up_total && g_up_flash == 0 && g_up_fill >= BLK_HEADER_SIZE) {
      BlocklistHeader *h = (BlocklistHeader *)g_up_page;
      h->commit_seq = BLK_UNCOMMITTED;  // only commit() may set it
      if (!header_valid(*h, g_parts[g_up_slot]->size)) {
        err = "Invalid Blocklist Header";
        return false;
      }
      g_up_total = h->total_size;
    }
    if (g_up_total && g_up_received > g_up_total) {
      err = "File Longer Than Header";
      return false;
    }
    if (g_up_fill == PAGE && !flush_page(err)) return false;
  }
  return true;
}

bool blocklist_upload_commit(const char *&err) {
  if (!g_up_total || g_up_received != g_up_total) {
    err = "File Length Mismatch";
    return false;
  }
  if (g_up_fill && !flush_page(err)) return false;

  const esp_partition_t *part = g_parts[g_up_slot];
  BlocklistHeader h;
  if (esp_partition_read(part, 0, &h, sizeof(h)) != ESP_OK || !slot_crc_ok(part, h, g_up_page)) {
    err = "Checksum Mismatch";
    return false;
  }

  xSemaphoreTake(g_lock, portMAX_DELAY);
  uint32_t seq = g_active >= 0 ? g_hdr.commit_seq + 1 : 1;
  xSemaphoreGive(g_lock);
  if (seq == BLK_UNCOMMITTED) seq = 1;
  if (esp_partition_write(part, offsetof(BlocklistHeader, commit_seq), &seq, sizeof(seq)) != ESP_OK) {
    err = "Flash Write Failed";
    return false;
  }
  h.commit_seq = seq;
  if (!load_slot(g_up_slot, h)) {
    err = "Reload Failed";
    return false;
  }
  Serial.printf("[blocklist] swapped to %s: seq %u, %u entries\n", SLOT_LABELS[g_up_slot], (unsigned)seq,
                (unsigned)h.entry_count);
  blocklist_upload_abort();  // frees the page buffer
  return true;
}
