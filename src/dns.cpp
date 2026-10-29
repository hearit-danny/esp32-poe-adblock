#include "dns.h"

#include <Arduino.h>
#include <AsyncUDP.h>
#include <Preferences.h>
#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>
#include <string.h>

#include "blocklist.h"

// Blocked answers: 0.0.0.0 / :: by default, NXDOMAIN with -DDNS_BLOCK_NXDOMAIN=1.
// The admin page can flip it at runtime; the choice is kept in NVS.
#ifndef DNS_BLOCK_NXDOMAIN
#define DNS_BLOCK_NXDOMAIN 0
#endif
// Short TTL so clients ask again soon after the blocklist changes.
#ifndef DNS_BLOCKED_TTL
#define DNS_BLOCKED_TTL 10
#endif

static constexpr uint16_t DNS_PORT = 53;
static constexpr size_t HDR = 12;
static constexpr size_t MAX_QUERY = 512;
static constexpr int SLOTS = 32;  // in-flight upstream queries; id low 5 bits = slot
static constexpr uint32_t RETRY_MS = 1000;    // resend to the other upstream
static constexpr uint32_t TIMEOUT_MS = 2000;  // give up on the query
static constexpr uint8_t FAILS_TO_SWITCH = 3;
static constexpr uint32_t PRIMARY_RETRY_MS = 60000;

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
  uint8_t query[MAX_QUERY];  // kept for the resend to the fallback
};

static AsyncUDP g_server;    // port 53, talks to clients
static AsyncUDP g_upstream;  // ephemeral port, talks to 1.1.1.1 / 8.8.8.8
static SemaphoreHandle_t g_lock;
static Slot g_slots[SLOTS];
static uint8_t g_cur;  // upstream in use
static uint8_t g_fails[2];
static uint32_t g_switched_ms;
static bool g_nxdomain = DNS_BLOCK_NXDOMAIN;
static DnsStats g_stats;

static inline uint16_t rd16(const uint8_t *p) { return (uint16_t)(p[0] << 8 | p[1]); }
static inline void wr16(uint8_t *p, uint16_t v) {
  p[0] = v >> 8;
  p[1] = v & 0xFF;
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
  g_server.writeTo(resp, n, ip, port);
}

static void send_servfail(const uint8_t *q, size_t len, const IPAddress &ip, uint16_t port) {
  uint8_t resp[HDR];
  memcpy(resp, q, HDR);
  resp[2] = 0x80 | (q[2] & 0x79);
  resp[3] = 0x80 | 2;
  memset(resp + 4, 0, 8);
  g_server.writeTo(resp, HDR, ip, port);
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
  wr16(s.query, s.up_id);
  g_upstream.writeTo(s.query, s.len, UPSTREAMS[u], DNS_PORT);
}

static void forward(const uint8_t *q, size_t len, const IPAddress &ip, uint16_t port) {
  if (len > MAX_QUERY) {
    g_stats.dropped++;
    send_servfail(q, len, ip, port);
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
    send_servfail(q, len, ip, port);
    return;
  }
  Slot &s = g_slots[free_slot];
  s.used = true;
  s.retried = false;
  s.client_id = rd16(q);
  s.up_id = (uint16_t)((esp_random() & 0xFFE0) | free_slot);
  s.client_ip = ip;
  s.client_port = port;
  s.sent_ms = millis();
  s.len = len;
  memcpy(s.query, q, len);
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
  forward(q, len, p.remoteIP(), p.remotePort());
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
  Slot &s = g_slots[id & (SLOTS - 1)];
  if (!s.used || s.up_id != id) {
    xSemaphoreGive(g_lock);
    return;  // late duplicate after a retry, or not ours
  }
  g_fails[u] = 0;
  wr16(msg, s.client_id);  // restore the client's id in place
  g_server.writeTo(msg, len, s.client_ip, s.client_port);
  s.used = false;
  g_stats.relayed++;
  xSemaphoreGive(g_lock);
}

void dns_begin() {
  g_lock = xSemaphoreCreateMutex();
  Preferences prefs;
  if (prefs.begin("adblock", true)) {
    g_nxdomain = prefs.getBool("nxdomain", DNS_BLOCK_NXDOMAIN);
    prefs.end();
  }
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
