#pragma once
// Domain hashing shared by the firmware and scripts/build_blocklist.py.
//
// This file is the single definition of the algorithm. The Python builder
// parses the FNV_* constants and the HASH_VECTOR lines below with a regex, so
// keep them as plain `constexpr uint64_t NAME = 0x...ULL;` and
// `HASH_VECTOR("domain", 0x...ULL)` one per line.
//
// Algorithm, over the normalised name (ASCII lowercase, no trailing dot):
//   h64   = FNV-1a 64-bit over the name bytes
//   key40 = ((h64 >> 40) ^ h64) & 0xFFFFFFFFFF      (FNV xor-fold to 40 bits)
//   bloom = Kirsch-Mitzenmacher double hashing on h64:
//           h1 = h64 & 0xFFFFFFFF, h2 = (h64 >> 32) | 1
//           bit_i = (h1 + i * h2) % bloom_bits, i = 0 .. k-1

#include <stddef.h>
#include <stdint.h>

constexpr uint64_t FNV_OFFSET_BASIS = 0xCBF29CE484222325ULL;
constexpr uint64_t FNV_PRIME = 0x00000100000001B3ULL;
constexpr uint64_t KEY40_MASK = 0x000000FFFFFFFFFFULL;

constexpr uint64_t fnv1a64(const char *s, size_t len) {
  uint64_t h = FNV_OFFSET_BASIS;
  for (size_t i = 0; i < len; i++) {
    h ^= (uint8_t)s[i];
    h *= FNV_PRIME;
  }
  return h;
}

constexpr size_t const_strlen(const char *s) { return *s ? 1 + const_strlen(s + 1) : 0; }

constexpr uint64_t fold40(uint64_t h64) { return ((h64 >> 40) ^ h64) & KEY40_MASK; }

constexpr uint64_t domain_key40(const char *s) { return fold40(fnv1a64(s, const_strlen(s))); }

// Known-answer vectors. The compiler checks them below; build_blocklist.py
// checks the same lines with its own implementation before it writes a file,
// so a mismatch between the two fails one of the two builds.
#define HASH_VECTORS(HASH_VECTOR)                       \
  HASH_VECTOR("doubleclick.net", 0xCD12ABF9C9ULL)       \
  HASH_VECTOR("example.com", 0x634E707C80ULL)           \
  HASH_VECTOR("ads.example.com", 0x58975A366FULL)       \
  HASH_VECTOR("googleadservices.com", 0x60013ACAA4ULL)

#define HASH_VECTOR_ASSERT(name, expected) \
  static_assert(domain_key40(name) == (expected), "fnv.h vector mismatch: " name);
HASH_VECTORS(HASH_VECTOR_ASSERT)
#undef HASH_VECTOR_ASSERT
