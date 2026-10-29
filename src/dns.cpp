#include "dns.h"

#include <Arduino.h>
#include <AsyncUDP.h>
#include <Preferences.h>
#include <esp_heap_caps.h>
#include <freertos/FreeRTOS.h>
#include <freertos/queue.h>
#include <freertos/semphr.h>
#include <string.h>

#include "blocklist.h"
#include "fnv.h"

// Blocked answers: 0.0.0.0 / :: by default, NXDOMAIN with -DDNS_BLOCK_NXDOMAIN=1.
// The admin page can flip it at runtime; the choice is kept in NVS.
#ifndef DNS_BLOCK_NXDOMAIN
#define DNS_BLOCK_NXDOMAIN 0
#endif
// Short TTL so clients ask again soon after the blocklist changes.
#ifndef DNS_BLOCKED_TTL
#define DNS_BLOCKED_TTL 10
#endif
// Upstream answer cache: RAM for cached answers (0 turns it off) and the
// longest an answer is kept, whatever its TTL says.
#ifndef DNS_CACHE_BYTES
#define DNS_CACHE_BYTES 24576
#endif
#ifndef DNS_CACHE_MAX_TTL
#define DNS_CACHE_MAX_TTL 3600
#endif
static_assert(DNS_CACHE_BYTES <= 65535, "cache offsets are 16-bit");

static constexpr uint16_t DNS_PORT = 53;
static constexpr size_t HDR = 12;
static constexpr size_t MAX_QUERY = 512;
// EDNS UDP size advertised upstream. Keeps answers inside one Ethernet frame:
// AsyncUDP hands over only the first pbuf of a reassembled datagram and caps
// sends at 1460 bytes, so a bigger answer would reach the client cut short.
static constexpr uint16_t MAX_UDP_PAYLOAD = 1232;
static constexpr int SLOTS = 32;  // in-flight upstream queries
static constexpr uint32_t RETRY_MS = 1000;    // resend to the other upstream
static constexpr uint32_t TIMEOUT_MS = 2000;  // give up on the query
static constexpr uint8_t FAILS_TO_SWITCH = 3;
static constexpr uint32_t PRIMARY_RETRY_MS = 60000;
static constexpr int TX_QUEUE = 32;
static constexpr int CACHE_ENTRIES = 256;
static constexpr size_t CACHE_MIN_FREE_HEAP = 65536;  // left for TCP, uploads and OTA

static const IPAddress UPSTREAMS[2] = {IPAddress(1, 1, 1, 1), IPAddress(8, 8, 8, 8)};
static const char *const UPSTREAM_NAMES[2] = {"1.1.1.1", "8.8.8.8"};

struct Slot {
  bool used;
  bool retried;
  uint8_t upstream;  // index into UPSTREAMS of the last send
  uint16_t client_id;
  uint16_t up_id;
  uint16_t client_port;
  IPAddress client_ip;
  uint32_t sent_ms;
  uint16_t len;
  uint16_t qend;             // end of the question, 0 if it was not parsed
  uint8_t query[MAX_QUERY];  // kept for the resend and the answer check
};

// A packet waiting for the dns_tx task.
struct Outgoing {
  uint8_t *buf;  // malloc'd, freed by the sender
  uint16_t len;
  uint16_t port;
  uint32_t ip;  // IPv4, network order as IPAddress stores it
  bool upstream;
};

// A cached upstream answer in g_cache. len 0 marks a free entry.
struct CacheEntry {
  uint32_t key;  // cache_key() of the question and query flags
  uint32_t stored_ms;
  uint32_t ttl_ms;
  uint16_t off;
  uint16_t len;
  uint8_t flags;  // query_flags() of the query that fetched it
};

static AsyncUDP g_server;    // port 53, talks to clients
static AsyncUDP g_upstream;  // ephemeral port, talks to 1.1.1.1 / 8.8.8.8
static SemaphoreHandle_t g_lock;
static QueueHandle_t g_txq;
static Slot g_slots[SLOTS];
static uint8_t g_cur;  // upstream in use
static uint8_t g_fails[2];
static uint32_t g_switched_ms;
static bool g_nxdomain = DNS_BLOCK_NXDOMAIN;
static DnsStats g_stats;
// Answers are written into g_cache as a ring, overwriting the oldest bytes.
static uint8_t *g_cache;
static size_t g_cache_size;
static size_t g_cache_head;
static CacheEntry g_entries[CACHE_ENTRIES];

static inline uint16_t rd16(const uint8_t *p) { return (uint16_t)(p[0] << 8 | p[1]); }
static inline void wr16(uint8_t *p, uint16_t v) {
  p[0] = v >> 8;
  p[1] = v & 0xFF;
}

// Packets are never sent from the async_udp task. AsyncUDP's receive path
// blocks the lwIP thread (holding the TCP/IP core lock) until async_udp takes
// the packet off its 32-entry queue, while writeTo() needs that core lock: a
// send from async_udp with the queue full would deadlock the network stack.
// So handlers queue a buffer without waiting and this task does the writeTo.
// queue_owned() takes a malloc'd buffer; queue_send() queues a copy.
static void queue_owned(bool upstream, uint8_t *buf, size_t len, const IPAddress &ip, uint16_t port) {
  Outgoing o;
  o.buf = buf;
  o.len = len;
  o.port = port;
  o.ip = (uint32_t)ip;
  o.upstream = upstream;
  if (xQueueSend(g_txq, &o, 0) != pdPASS) {
    free(buf);
    g_stats.dropped++;
  }
}

static void queue_send(bool upstream, const uint8_t *data, size_t len, const IPAddress &ip, uint16_t port) {
  uint8_t *buf = (uint8_t *)malloc(len);
  if (!buf) {
    g_stats.dropped++;
    return;
  }
  memcpy(buf, data, len);
  queue_owned(upstream, buf, len, ip, port);
}

static void tx_task(void *) {
  Outgoing o;
  for (;;) {
    if (xQueueReceive(g_txq, &o, portMAX_DELAY) != pdPASS) continue;
    (o.upstream ? g_upstream : g_server).writeTo(o.buf, o.len, IPAddress(o.ip), o.port);
    free(o.buf);
  }
}

// Parses the single question into `name` (lowercase, dot separated, no
// trailing dot). Returns the offset just past QTYPE/QCLASS, or 0 if the
// question is not one we can check.
static size_t parse_question(const uint8_t *msg, size_t len, char *name, size_t &name_len, uint16_t &qtype) {
  size_t pos = HDR, out = 0;
  while (true) {
    if (pos >= len) return 0;
    uint8_t l = msg[pos++];
    if (l == 0) break;
    if (l & 0xC0) return 0;  // compression in a question: not expected
    if (pos + l > len || out + l + 1 > 253) return 0;
    if (out) name[out++] = '.';
    for (uint8_t i = 0; i < l; i++) {
      char c = (char)msg[pos++];
      name[out++] = (c >= 'A' && c <= 'Z') ? c + 32 : c;
    }
  }
  if (pos + 4 > len) return 0;
  qtype = rd16(msg + pos);
  name_len = out;
  name[out] = 0;
  return pos + 4;
}

static size_t skip_name(const uint8_t *m, size_t len, size_t pos) {
  while (pos < len) {
    uint8_t l = m[pos];
    if (l == 0) return pos + 1;
    if ((l & 0xC0) == 0xC0) return pos + 2 <= len ? pos + 2 : 0;
    if (l & 0xC0) return 0;
    pos += 1 + l;
  }
  return 0;
}

// Offset of the OPT record's TYPE field, or 0 if the message has none.
static size_t find_opt(const uint8_t *m, size_t len, size_t qend) {
  size_t pos = qend;
  unsigned rrs = rd16(m + 6) + rd16(m + 8) + rd16(m + 10);
  while (rrs--) {
    pos = skip_name(m, len, pos);
    if (!pos || pos + 10 > len) return 0;
    if (rd16(m + pos) == 41) return pos;
    pos += 10 + rd16(m + pos + 8);
  }
  return 0;
}

// Lowers the OPT record's UDP payload size to MAX_UDP_PAYLOAD.
static void clamp_edns(uint8_t *m, size_t len, size_t qend) {
  size_t opt = find_opt(m, len, qend);
  if (opt && rd16(m + opt + 2) > MAX_UDP_PAYLOAD) wr16(m + opt + 2, MAX_UDP_PAYLOAD);
}

// Query bits that change the answer: RD, CD, EDNS present, DO.
static uint8_t query_flags(const uint8_t *m, size_t len, size_t qend) {
  uint8_t f = (m[2] & 0x01) | ((m[3] & 0x10) ? 2 : 0);
  size_t opt = find_opt(m, len, qend);
  if (opt) f |= 4 | ((m[opt + 6] & 0x80) ? 8 : 0);
  return f;
}

// Question byte i, lowercased within the name (not in QTYPE/QCLASS).
static inline uint8_t folded(const uint8_t *m, size_t i, size_t qend) {
  uint8_t c = m[i];
  return (i < qend - 4 && c >= 'A' && c <= 'Z') ? c + 32 : c;
}

static uint32_t cache_key(const uint8_t *m, size_t qend, uint8_t flags) {
  uint64_t h = FNV_OFFSET_BASIS;
  for (size_t i = HDR; i < qend; i++) h = (h ^ folded(m, i, qend)) * FNV_PRIME;
  h = (h ^ flags) * FNV_PRIME;
  return (uint32_t)(h ^ (h >> 32));
}

static bool same_question(const uint8_t *a, const uint8_t *b, size_t qend) {
  for (size_t i = HDR; i < qend; i++)
    if (folded(a, i, qend) != folded(b, i, qend)) return false;
  return true;
}

// Walks the records after the question, skipping OPT. Returns the smallest
// TTL, or 0 if there is no record or one does not parse. A nonzero age_s is
// subtracted from every TTL.
static uint32_t walk_ttls(uint8_t *m, size_t len, size_t qend, uint32_t age_s) {
  size_t pos = qend;
  unsigned rrs = rd16(m + 6) + rd16(m + 8) + rd16(m + 10);
  uint32_t min = UINT32_MAX;
  while (rrs--) {
    pos = skip_name(m, len, pos);
    if (!pos || pos + 10 > len) return 0;
    if (rd16(m + pos) != 41) {
      uint8_t *t = m + pos + 4;
      uint32_t ttl = (uint32_t)t[0] << 24 | (uint32_t)t[1] << 16 | (uint32_t)t[2] << 8 | t[3];
      if (ttl < min) min = ttl;
      if (age_s) {
        ttl = ttl > age_s ? ttl - age_s : 0;
        t[0] = ttl >> 24;
        t[1] = ttl >> 16;
        t[2] = ttl >> 8;
        t[3] = ttl;
      }
    }
    pos += 10 + rd16(m + pos + 8);
    if (pos > len) return 0;
  }
  return min == UINT32_MAX ? 0 : min;
}

static bool live(const CacheEntry &e, uint32_t now) { return e.len && now - e.stored_ms < e.ttl_ms; }

// Keeps an upstream answer for the query in slot s. Only complete NOERROR
// and NXDOMAIN answers with a TTL are kept.
static void cache_put_locked(uint8_t *msg, size_t len, const Slot &s) {
  if (!g_cache || !s.qend || len > g_cache_size) return;
  uint8_t rcode = msg[3] & 0x0F;
  if ((msg[2] & 0x02) || (rcode != 0 && rcode != 3)) return;
  uint32_t ttl = walk_ttls(msg, len, s.qend, 0);
  if (!ttl) return;
  if (ttl > DNS_CACHE_MAX_TTL) ttl = DNS_CACHE_MAX_TTL;
  uint8_t flags = query_flags(s.query, s.len, s.qend);
  uint32_t key = cache_key(s.query, s.qend, flags);
  if (g_cache_head + len > g_cache_size) g_cache_head = 0;
  size_t start = g_cache_head, end = start + len;
  uint32_t now = millis();
  CacheEntry *slot = nullptr, *oldest = nullptr;
  for (CacheEntry &e : g_entries) {
    // Drop entries whose bytes this answer overwrites, and older copies.
    if (e.len && ((e.off < end && e.off + e.len > start) || (e.key == key && e.flags == flags))) e.len = 0;
    if (!live(e, now)) {
      if (!slot) slot = &e;
    } else if (!oldest || (int32_t)(e.stored_ms - oldest->stored_ms) < 0) {
      oldest = &e;
    }
  }
  if (!slot) slot = oldest;
  memcpy(g_cache + start, msg, len);
  slot->key = key;
  slot->stored_ms = now;
  slot->ttl_ms = ttl * 1000;
  slot->off = start;
  slot->len = len;
  slot->flags = flags;
  g_cache_head = end;
}

// Answers the query from the cache, with TTLs lowered by the time the answer
// has been held. Returns false on a miss.
static bool cache_answer(const uint8_t *q, size_t len, size_t qend, const IPAddress &ip, uint16_t port) {
  if (!g_cache || !qend) return false;
  uint8_t flags = query_flags(q, len, qend);
  uint32_t key = cache_key(q, qend, flags);
  size_t opt = find_opt(q, len, qend);
  size_t limit = opt && rd16(q + opt + 2) > 512 ? rd16(q + opt + 2) : 512;
  uint8_t *buf = nullptr;
  size_t n = 0;
  uint32_t age_s = 0;
  xSemaphoreTake(g_lock, portMAX_DELAY);
  uint32_t now = millis();
  for (CacheEntry &e : g_entries) {
    if (!e.len || e.key != key || e.flags != flags) continue;
    const uint8_t *r = g_cache + e.off;
    if (!live(e, now) || e.len > limit || e.len < qend || !same_question(r, q, qend)) break;
    buf = (uint8_t *)malloc(e.len);
    if (buf) {
      memcpy(buf, r, e.len);
      n = e.len;
      age_s = (now - e.stored_ms) / 1000;
      g_stats.cache_hits++;
    }
    break;
  }
  xSemaphoreGive(g_lock);
  if (!buf) return false;
  memcpy(buf, q, 2);                       // the client's id
  memcpy(buf + HDR, q + HDR, qend - HDR);  // and its spelling of the name
  if (age_s) walk_ttls(buf, n, qend, age_s);
  queue_owned(false, buf, n, ip, port);
  return true;
}

// Takes what RAM can spare after the Bloom filter, up to DNS_CACHE_BYTES.
static void cache_begin() {
  size_t free_heap = heap_caps_get_free_size(MALLOC_CAP_8BIT);
  size_t size = heap_caps_get_largest_free_block(MALLOC_CAP_8BIT);
  if (size > DNS_CACHE_BYTES) size = DNS_CACHE_BYTES;
  if (free_heap < CACHE_MIN_FREE_HEAP + size) size = free_heap > CACHE_MIN_FREE_HEAP ? free_heap - CACHE_MIN_FREE_HEAP : 0;
  if (size >= 4096) g_cache = (uint8_t *)heap_caps_malloc(size, MALLOC_CAP_8BIT);
  g_cache_size = g_cache ? size : 0;
  Serial.printf("[dns] answer cache %u bytes%s\n", (unsigned)g_cache_size, g_cache ? "" : " (off)");
}

static void send_blocked(const uint8_t *q, size_t qend, uint16_t qtype, const IPAddress &ip, uint16_t port) {
  uint8_t resp[MAX_QUERY + 28];
  memcpy(resp, q, qend);
  bool a = qtype == 1, aaaa = qtype == 28;
  bool answer = !g_nxdomain && (a || aaaa);
  // QR=1, keep opcode and RD, RA=1; rcode 3 (NXDOMAIN) or 0. Other types get
  // an empty NOERROR answer (NODATA).
  resp[2] = 0x80 | (q[2] & 0x79);
  resp[3] = 0x80 | (g_nxdomain ? 3 : 0);
  wr16(resp + 4, 1);
  wr16(resp + 6, answer ? 1 : 0);
  wr16(resp + 8, 0);
  wr16(resp + 10, 0);
  size_t n = qend;
  if (answer) {
    uint16_t rdlen = a ? 4 : 16;
    resp[n++] = 0xC0;  // name: pointer to the question
    resp[n++] = HDR;
    wr16(resp + n, qtype);
    n += 2;
    wr16(resp + n, 1);  // IN
    n += 2;
    uint32_t ttl = DNS_BLOCKED_TTL;
    resp[n++] = ttl >> 24;
    resp[n++] = ttl >> 16;
    resp[n++] = ttl >> 8;
    resp[n++] = ttl;
    wr16(resp + n, rdlen);
    n += 2;
    memset(resp + n, 0, rdlen);
    n += rdlen;
  }
  queue_send(false, resp, n, ip, port);
}

// SERVFAIL echoing the question when we parsed one; resolvers such as glibc
// ignore a reply whose question section does not match.
static void send_servfail(const uint8_t *q, size_t qend, const IPAddress &ip, uint16_t port) {
  uint8_t resp[MAX_QUERY];
  size_t n = qend ? qend : HDR;
  memcpy(resp, q, n);
  resp[2] = 0x80 | (q[2] & 0x79);
  resp[3] = 0x80 | 2;
  wr16(resp + 4, qend ? 1 : 0);
  memset(resp + 6, 0, 6);
  queue_send(false, resp, n, ip, port);
}

static void note_fail_locked(uint8_t u) {
  if (++g_fails[u] >= FAILS_TO_SWITCH && u == g_cur) {
    g_cur = 1 - u;
    g_fails[g_cur] = 0;
    g_switched_ms = millis();
    Serial.printf("[dns] upstream %s not answering, switching to %s\n", UPSTREAM_NAMES[u], UPSTREAM_NAMES[g_cur]);
  }
}

static void send_upstream_locked(Slot &s, uint8_t u) {
  s.upstream = u;
  queue_send(true, s.query, s.len, UPSTREAMS[u], DNS_PORT);
}

// Random 16-bit id not used by another in-flight query.
static uint16_t fresh_id_locked() {
  for (;;) {
    uint16_t id = (uint16_t)esp_random();
    bool clash = false;
    for (int i = 0; i < SLOTS && !clash; i++) clash = g_slots[i].used && g_slots[i].up_id == id;
    if (!clash) return id;
  }
}

static void forward(const uint8_t *q, size_t len, size_t qend, const IPAddress &ip, uint16_t port) {
  if (len > MAX_QUERY) {
    g_stats.dropped++;
    send_servfail(q, qend <= MAX_QUERY ? qend : 0, ip, port);
    return;
  }
  xSemaphoreTake(g_lock, portMAX_DELAY);
  int free_slot = -1;
  for (int i = 0; i < SLOTS; i++) {
    if (!g_slots[i].used) {
      free_slot = i;
      break;
    }
  }
  if (free_slot < 0) {
    xSemaphoreGive(g_lock);
    g_stats.dropped++;
    send_servfail(q, qend, ip, port);
    return;
  }
  Slot &s = g_slots[free_slot];
  s.used = true;
  s.retried = false;
  s.client_id = rd16(q);
  s.up_id = fresh_id_locked();
  s.client_ip = ip;
  s.client_port = port;
  s.sent_ms = millis();
  s.len = len;
  s.qend = qend;
  memcpy(s.query, q, len);
  wr16(s.query, s.up_id);
  if (qend) clamp_edns(s.query, len, qend);
  send_upstream_locked(s, g_cur);
  g_stats.forwarded++;
  xSemaphoreGive(g_lock);
}

static void on_client_packet(AsyncUDPPacket &p) {
  const uint8_t *q = p.data();
  size_t len = p.length();
  g_stats.queries++;
  if (len < HDR || (q[2] & 0x80)) {  // too short, or a response
    g_stats.dropped++;
    return;
  }
  char name[256];
  size_t name_len = 0;
  uint16_t qtype = 0;
  size_t qend = 0;
  bool standard = ((q[2] >> 3) & 0x0F) == 0 && rd16(q + 4) == 1;
  if (standard) qend = parse_question(q, len, name, name_len, qtype);
  if (qend && qend <= MAX_QUERY && name_len && blocklist_contains(name, name_len)) {
    g_stats.blocked++;
    send_blocked(q, qend, qtype, p.remoteIP(), p.remotePort());
    return;
  }
  if (qend && cache_answer(q, len, qend, p.remoteIP(), p.remotePort())) return;
  forward(q, len, qend, p.remoteIP(), p.remotePort());
}

static void on_upstream_packet(AsyncUDPPacket &p) {
  size_t len = p.length();
  if (len < HDR || p.remotePort() != DNS_PORT) return;
  IPAddress from = p.remoteIP();
  int u = from == UPSTREAMS[0] ? 0 : from == UPSTREAMS[1] ? 1 : -1;
  if (u < 0) return;

  uint8_t *msg = p.data();
  uint16_t id = rd16(msg);
  xSemaphoreTake(g_lock, portMAX_DELAY);
  // Match on the id and the question bytes, so a late answer to a retried
  // query cannot land on a newer query that drew the same id.
  for (int i = 0; i < SLOTS; i++) {
    Slot &s = g_slots[i];
    if (!s.used || s.up_id != id) continue;
    if (s.qend && (len < s.qend || memcmp(msg + HDR, s.query + HDR, s.qend - HDR) != 0)) break;
    g_fails[u] = 0;
    cache_put_locked(msg, len, s);
    wr16(msg, s.client_id);  // restore the client's id in place
    queue_send(false, msg, len, s.client_ip, s.client_port);
    s.used = false;
    g_stats.relayed++;
    break;
  }
  xSemaphoreGive(g_lock);
}

void dns_begin() {
  g_lock = xSemaphoreCreateMutex();
  g_txq = xQueueCreate(TX_QUEUE, sizeof(Outgoing));
  xTaskCreatePinnedToCore(tx_task, "dns_tx", 4096, nullptr, 3, nullptr, tskNO_AFFINITY);
  Preferences prefs;
  if (prefs.begin("adblock", true)) {
    g_nxdomain = prefs.getBool("nxdomain", DNS_BLOCK_NXDOMAIN);
    prefs.end();
  }
  cache_begin();
  if (!g_upstream.listen(0)) Serial.println("[dns] upstream socket failed");
  g_upstream.onPacket(on_upstream_packet);
  if (!g_server.listen(DNS_PORT)) Serial.println("[dns] listen on 53 failed");
  g_server.onPacket(on_client_packet);
  Serial.printf("[dns] listening on 53, upstream %s, fallback %s, blocked answer %s\n", UPSTREAM_NAMES[0],
                UPSTREAM_NAMES[1], g_nxdomain ? "NXDOMAIN" : "0.0.0.0");
}

void dns_loop() {
  uint32_t now = millis();
  xSemaphoreTake(g_lock, portMAX_DELAY);
  for (int i = 0; i < SLOTS; i++) {
    Slot &s = g_slots[i];
    if (!s.used) continue;
    uint32_t age = now - s.sent_ms;
    if (age >= TIMEOUT_MS) {
      note_fail_locked(s.upstream);
      s.used = false;
      g_stats.timeouts++;
    } else if (age >= RETRY_MS && !s.retried) {
      note_fail_locked(s.upstream);
      s.retried = true;
      send_upstream_locked(s, 1 - s.upstream);
    }
  }
  if (g_cur != 0 && now - g_switched_ms >= PRIMARY_RETRY_MS) {
    g_cur = 0;
    g_fails[0] = 0;
    Serial.printf("[dns] trying primary upstream %s again\n", UPSTREAM_NAMES[0]);
  }
  xSemaphoreGive(g_lock);
}

DnsStats dns_stats() {
  xSemaphoreTake(g_lock, portMAX_DELAY);
  DnsStats s = g_stats;
  uint32_t n = 0;
  for (int i = 0; i < SLOTS; i++) n += g_slots[i].used;
  s.inflight = n;
  uint32_t now = millis();
  n = 0;
  for (const CacheEntry &e : g_entries) n += live(e, now);
  s.cache_entries = n;
  s.cache_bytes = g_cache_size;
  s.upstream = UPSTREAM_NAMES[g_cur];
  s.nxdomain = g_nxdomain;
  xSemaphoreGive(g_lock);
  return s;
}

void dns_set_nxdomain(bool on) {
  g_nxdomain = on;
  Preferences prefs;
  if (prefs.begin("adblock", false)) {
    prefs.putBool("nxdomain", on);
    prefs.end();
  }
}
