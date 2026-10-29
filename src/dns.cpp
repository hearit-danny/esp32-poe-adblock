#include "dns.h"

#include <Arduino.h>
#include <AsyncUDP.h>
#include <Preferences.h>
#include <freertos/FreeRTOS.h>
#include <freertos/queue.h>
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

static inline uint16_t rd16(const uint8_t *p) { return (uint16_t)(p[0] << 8 | p[1]); }
static inline void wr16(uint8_t *p, uint16_t v) {
  p[0] = v >> 8;
  p[1] = v & 0xFF;
}

// Packets are never sent from the async_udp task. AsyncUDP's receive path
// blocks the lwIP thread (holding the TCP/IP core lock) until async_udp takes
// the packet off its 32-entry queue, while writeTo() needs that core lock: a
// send from async_udp with the queue full would deadlock the network stack.
// So handlers queue a copy without waiting and this task does the writeTo.
static void queue_send(bool upstream, const uint8_t *data, size_t len, const IPAddress &ip, uint16_t port) {
  Outgoing o;
  o.buf = (uint8_t *)malloc(len);
  if (!o.buf) {
    g_stats.dropped++;
    return;
  }
  memcpy(o.buf, data, len);
  o.len = len;
  o.port = port;
  o.ip = (uint32_t)ip;
  o.upstream = upstream;
  if (xQueueSend(g_txq, &o, 0) != pdPASS) {
    free(o.buf);
    g_stats.dropped++;
  }
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

// Lowers the OPT record's UDP payload size to MAX_UDP_PAYLOAD.
static void clamp_edns(uint8_t *m, size_t len, size_t qend) {
  size_t pos = qend;
  unsigned rrs = rd16(m + 6) + rd16(m + 8) + rd16(m + 10);
  while (rrs--) {
    pos = skip_name(m, len, pos);
    if (!pos || pos + 10 > len) return;
    if (rd16(m + pos) == 41 && rd16(m + pos + 2) > MAX_UDP_PAYLOAD) wr16(m + pos + 2, MAX_UDP_PAYLOAD);
    pos += 10 + rd16(m + pos + 8);
  }
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
