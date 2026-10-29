#pragma once
// On-flash layout of blocklist.bin, shared with scripts/build_blocklist.py
// (it parses the BLK_* constants below with a regex; keep one per line).
//
//   [header, 64 bytes][bloom, bloom_bits / 8 bytes][keys, entry_count * 5 bytes]
//
// All integers little-endian. Keys are 40-bit domain_key40() values, sorted
// ascending, packed 5 bytes each (no padding). payload_crc32 is standard
// CRC-32 (zlib.crc32) over bloom + keys.
//
// commit_seq is 0xFFFFFFFF in the file. The firmware writes the whole file to
// the inactive slot, verifies the CRC by reading it back, then programs
// commit_seq (erased flash bits only go 1 -> 0, so no erase is needed). Boot
// and reload pick the committed slot with the highest commit_seq, which makes
// the swap atomic across a power cut.

#include <stdint.h>

constexpr uint32_t BLK_MAGIC = 0x4C424441UL;  // "ADBL"
constexpr uint32_t BLK_VERSION = 1UL;
constexpr uint32_t BLK_HEADER_SIZE = 64UL;
constexpr uint32_t BLK_KEY_BYTES = 5UL;
constexpr uint32_t BLK_MAX_BLOOM_BYTES = 131072UL;  // RAM buffer allocated at boot
constexpr uint32_t BLK_MAX_K = 16UL;
constexpr uint32_t BLK_UNCOMMITTED = 0xFFFFFFFFUL;

struct __attribute__((packed)) BlocklistHeader {
  uint32_t magic;
  uint16_t version;
  uint16_t header_size;
  uint32_t entry_count;
  uint32_t bloom_bits;
  uint8_t bloom_k;
  uint8_t key_bytes;
  uint16_t reserved0;
  uint32_t build_time;  // unix seconds, set by the builder
  uint32_t payload_crc32;
  uint32_t total_size;  // header + bloom + keys
  uint8_t reserved1[28];
  uint32_t commit_seq;  // must stay the last field
};

static_assert(sizeof(BlocklistHeader) == BLK_HEADER_SIZE, "header size");
