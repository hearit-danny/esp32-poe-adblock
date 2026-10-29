#pragma once
// Blocklist lookup: RAM Bloom pre-filter plus binary search over the sorted
// 40-bit keys, read in place from a memory-mapped flash partition.

#include <stddef.h>
#include <stdint.h>

#include "blocklist_format.h"

struct BlocklistInfo {
  bool loaded;
  int active_slot;  // 0 = blk_a, 1 = blk_b, -1 = none
  uint32_t entry_count;
  uint32_t bloom_bits;
  uint8_t bloom_k;
  uint32_t build_time;
  uint32_t commit_seq;
  uint32_t slot_capacity;  // bytes per slot partition
};

// Allocates the Bloom buffer and loads the newest committed slot. Returns
// false only if the Bloom buffer cannot be allocated; an empty or invalid
// flash leaves the list unloaded and every name allowed.
bool blocklist_begin();

// True if `name` (already normalised: lowercase, no trailing dot) or any of
// its parent suffixes with at least one dot is on the list.
bool blocklist_contains(const char *name, size_t len);

BlocklistInfo blocklist_info();

// Streaming upload into the inactive slot. Call begin once, write the file in
// order, then commit. Each returns false and fills `err` on failure; after a
// failure call abort. Commit verifies the CRC, flips commit_seq and reloads
// the Bloom filter without a reboot.
bool blocklist_upload_begin(const char *&err);
bool blocklist_upload_write(const uint8_t *data, size_t len, const char *&err);
bool blocklist_upload_commit(const char *&err);
void blocklist_upload_abort();
bool blocklist_upload_active();
