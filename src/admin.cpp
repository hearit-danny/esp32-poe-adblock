#include "admin.h"

#include <Arduino.h>
#include <ESPAsyncWebServer.h>
#include <ETH.h>
#include <Update.h>
#include <time.h>

#include "blocklist.h"
#include "dns.h"

// Set by scripts/admin_password.py from ADBLOCK_ADMIN_PASSWORD.
#ifndef ADMIN_PASSWORD
#error "ADMIN_PASSWORD is not defined; build through PlatformIO with ADBLOCK_ADMIN_PASSWORD set"
#endif
static constexpr const char *ADMIN_USER = "admin";
static constexpr const char *REALM = "adblocker";

static AsyncWebServer g_server(80);
static AsyncWebServerRequest *g_upload_owner;  // request that holds the blocklist upload
static uint32_t g_reboot_at;

// Per-request upload state in request->_tempObject (freed by the library).
struct UploadCtx {
  const char *err;
  bool done;
};

// HTTP basic auth. Upload bodies reach the chunk handlers before the request
// handler runs, so both check it.
static bool authorized(AsyncWebServerRequest *req) { return req->authenticate(ADMIN_USER, ADMIN_PASSWORD); }

static void ask_login(AsyncWebServerRequest *req) { req->requestAuthentication(REALM, false); }

static UploadCtx *upload_ctx(AsyncWebServerRequest *req) {
  if (!req->_tempObject) req->_tempObject = calloc(1, sizeof(UploadCtx));
  return (UploadCtx *)req->_tempObject;
}

static String fmt_uptime(uint32_t s) {
  char buf[32];
  snprintf(buf, sizeof(buf), "%ud %02u:%02u:%02u", (unsigned)(s / 86400), (unsigned)(s / 3600 % 24),
           (unsigned)(s / 60 % 60), (unsigned)(s % 60));
  return buf;
}

static String fmt_time(uint32_t t) {
  if (!t) return "-";
  time_t tt = t;
  struct tm tm;
  gmtime_r(&tt, &tm);
  char buf[32];
  strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M UTC", &tm);
  return buf;
}

static String stats_json() {
  DnsStats d = dns_stats();
  BlocklistInfo b = blocklist_info();
  String s;
  s.reserve(600);
  s += "{\"uptime_s\":" + String(millis() / 1000);
  s += ",\"ip\":\"" + ETH.localIP().toString() + "\"";
  s += ",\"link_mbps\":" + String(ETH.linkUp() ? ETH.linkSpeed() : 0);
  s += ",\"queries\":" + String(d.queries);
  s += ",\"blocked\":" + String(d.blocked);
  s += ",\"forwarded\":" + String(d.forwarded);
  s += ",\"relayed\":" + String(d.relayed);
  s += ",\"timeouts\":" + String(d.timeouts);
  s += ",\"dropped\":" + String(d.dropped);
  s += ",\"inflight\":" + String(d.inflight);
  s += ",\"upstream\":\"" + String(d.upstream) + "\"";
  s += ",\"block_mode\":\"" + String(d.nxdomain ? "nxdomain" : "zero") + "\"";
  s += ",\"blocklist_loaded\":" + String(b.loaded ? "true" : "false");
  s += ",\"entries\":" + String(b.entry_count);
  s += ",\"build_time\":" + String(b.build_time);
  s += ",\"bloom_bits\":" + String(b.bloom_bits);
  s += ",\"bloom_k\":" + String(b.bloom_k);
  s += ",\"slot\":" + String(b.active_slot);
  s += ",\"seq\":" + String(b.commit_seq);
  s += ",\"free_heap\":" + String(ESP.getFreeHeap());
  s += ",\"min_free_heap\":" + String(ESP.getMinFreeHeap());
  s += ",\"max_alloc\":" + String(ESP.getMaxAllocHeap());
  s += "}";
  return s;
}

static void row(String &h, const char *k, const String &v) { h += "<tr><th>" + String(k) + "</th><td>" + v + "</td></tr>"; }

static String status_page() {
  DnsStats d = dns_stats();
  BlocklistInfo b = blocklist_info();
  String h;
  h.reserve(3000);
  h += "<!doctype html><html><head><meta charset=utf-8><meta name=viewport content='width=device-width'>"
       "<title>AdBlocker</title><style>body{font:15px system-ui,sans-serif;margin:16px;max-width:640px}"
       "th{text-align:left;padding-right:16px;font-weight:500;color:#555}td{font-variant-numeric:tabular-nums}"
       "form{margin:16px 0}</style></head><body><h1>AdBlocker</h1><table>";
  row(h, "Uptime", fmt_uptime(millis() / 1000));
  row(h, "IP", ETH.localIP().toString() + (ETH.linkUp() ? " (" + String(ETH.linkSpeed()) + " Mbps)" : " (link down)"));
  row(h, "Queries", String(d.queries));
  String pct = d.queries ? String(100.0 * d.blocked / d.queries, 1) + "%" : "-";
  row(h, "Blocked", String(d.blocked) + " (" + pct + ")");
  row(h, "Forwarded", String(d.forwarded) + ", answered " + String(d.relayed) + ", timed out " + String(d.timeouts));
  row(h, "Dropped", String(d.dropped));
  row(h, "Upstream in use", String(d.upstream) + (String(d.upstream) == "1.1.1.1" ? "" : " (fallback)"));
  row(h, "Blocked answer", d.nxdomain ? "NXDOMAIN" : "0.0.0.0 / ::");
  if (b.loaded) {
    row(h, "Blocklist entries", String(b.entry_count));
    row(h, "Blocklist built", fmt_time(b.build_time));
    row(h, "Bloom filter", String(b.bloom_bits) + " bits, k=" + String(b.bloom_k));
    row(h, "Slot", String(b.active_slot == 0 ? "blk_a" : "blk_b") + ", seq " + String(b.commit_seq));
  } else {
    row(h, "Blocklist", "none loaded, forwarding everything");
  }
  row(h, "Free heap", String(ESP.getFreeHeap()) + " B (min " + String(ESP.getMinFreeHeap()) + ", largest block " +
                          String(ESP.getMaxAllocHeap()) + ")");
  row(h, "Firmware", String(__DATE__ " " __TIME__));
  h += "</table>"
       "<form method=post action=/upload enctype=multipart/form-data><b>Blocklist</b><br>"
       "<input type=file name=file accept=.bin> <button>Upload</button></form>"
       "<form method=post action=/mode><b>Blocked answer</b><br>"
       "<button name=nxdomain value=0>0.0.0.0</button> <button name=nxdomain value=1>NXDOMAIN</button></form>"
       "<form method=post action=/update enctype=multipart/form-data><b>Firmware</b><br>"
       "<input type=file name=firmware accept=.bin> <button>Update</button></form>"
       "<p><a href=/stats>/stats</a></p></body></html>";
  return h;
}

static void on_upload_chunk(AsyncWebServerRequest *req, const String &, size_t index, uint8_t *data, size_t len,
                            bool final) {
  UploadCtx *ctx = upload_ctx(req);
  if (!ctx || ctx->err) return;
  if (index == 0) {
    if (!authorized(req)) {
      ctx->err = "Login Required";
      return;
    }
    if (!blocklist_upload_begin(ctx->err)) return;
    g_upload_owner = req;
    req->onDisconnect([req]() {
      if (g_upload_owner == req) {
        blocklist_upload_abort();
        g_upload_owner = nullptr;
      }
    });
  }
  if (g_upload_owner != req) return;
  bool ok = blocklist_upload_write(data, len, ctx->err);
  if (ok && final) ok = ctx->done = blocklist_upload_commit(ctx->err);
  if (!ok || final) {
    if (!ok) blocklist_upload_abort();
    g_upload_owner = nullptr;
  }
}

static void on_upload_done(AsyncWebServerRequest *req) {
  if (!authorized(req)) return ask_login(req);
  UploadCtx *ctx = (UploadCtx *)req->_tempObject;
  if (ctx && ctx->done) {
    req->send(200, "text/plain", "Blocklist Updated\n" + String(blocklist_info().entry_count) + " entries loaded.\n");
  } else {
    req->send(400, "text/plain", String(ctx && ctx->err ? ctx->err : "No File Received") + "\n");
  }
}

static void on_update_chunk(AsyncWebServerRequest *req, const String &, size_t index, uint8_t *data, size_t len,
                            bool final) {
  UploadCtx *ctx = upload_ctx(req);
  if (!ctx || ctx->err) return;
  if (index == 0 && !authorized(req)) {
    ctx->err = "Login Required";
    return;
  }
  if (index == 0 && !Update.begin(UPDATE_SIZE_UNKNOWN, U_FLASH)) {
    ctx->err = "No Update Partition";
    return;
  }
  if (Update.write(data, len) != len) {
    Update.abort();
    ctx->err = "Firmware Write Failed";
    return;
  }
  if (final) {
    if (Update.end(true)) ctx->done = true;
    else ctx->err = "Firmware Image Rejected";
  }
}

static void on_update_done(AsyncWebServerRequest *req) {
  if (!authorized(req)) return ask_login(req);
  UploadCtx *ctx = (UploadCtx *)req->_tempObject;
  if (ctx && ctx->done) {
    req->send(200, "text/plain", "Firmware Updated\nRestarting now.\n");
    g_reboot_at = millis() + 1000;
  } else {
    req->send(400, "text/plain", String(ctx && ctx->err ? ctx->err : "No File Received") + "\n");
  }
}

void admin_begin() {
  // The status page asks for the login too, so the browser already holds the
  // credentials when its forms POST (otherwise a firmware upload is sent twice).
  // /stats stays open for read-only monitoring.
  g_server.on("/", HTTP_GET, [](AsyncWebServerRequest *req) {
    if (!authorized(req)) return ask_login(req);
    req->send(200, "text/html", status_page());
  });
  g_server.on("/stats", HTTP_GET, [](AsyncWebServerRequest *req) { req->send(200, "application/json", stats_json()); });
  g_server.on("/mode", HTTP_POST, [](AsyncWebServerRequest *req) {
    if (!authorized(req)) return ask_login(req);
    if (req->hasParam("nxdomain", true)) dns_set_nxdomain(req->getParam("nxdomain", true)->value() == "1");
    req->redirect("/");
  });
  g_server.on("/upload", HTTP_POST, on_upload_done, on_upload_chunk);
  g_server.on("/update", HTTP_POST, on_update_done, on_update_chunk);
  g_server.onNotFound([](AsyncWebServerRequest *req) { req->send(404, "text/plain", "Not Found\n"); });
  g_server.begin();
  Serial.println("[admin] http on port 80");
}

void admin_loop() {
  if (g_reboot_at && (int32_t)(millis() - g_reboot_at) >= 0) ESP.restart();
}
