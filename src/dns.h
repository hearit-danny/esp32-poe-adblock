#pragma once
// DNS server on UDP 53: answers blocked names locally and relays everything
// else to the upstream resolvers.

#include <stdint.h>

struct DnsStats {
  uint32_t queries;
  uint32_t blocked;
  uint32_t forwarded;
  uint32_t relayed;   // upstream answers passed back to clients
  uint32_t timeouts;  // queries that got no upstream answer within 2 s
  uint32_t dropped;   // malformed, or the in-flight table was full
  uint32_t inflight;
  uint32_t cache_hits;     // answered from the upstream answer cache
  uint32_t cache_entries;  // answers held now
  uint32_t cache_bytes;    // cache size, 0 when off
  const char *upstream;
  bool nxdomain;
};

void dns_begin();
// Expires in-flight queries and handles upstream fallback; call from loop().
void dns_loop();
DnsStats dns_stats();
// true: blocked names get NXDOMAIN. false: 0.0.0.0 / :: answers. Persisted.
void dns_set_nxdomain(bool on);
