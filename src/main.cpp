// DNS ad blocker for the M5Stack ESP32 Ethernet Unit with PoE (U138).
// Ethernet up via DHCP, then the blocklist, DNS on 53 and the admin UI on 80.

#include <Arduino.h>
#include <ETH.h>

#include "admin.h"
#include "blocklist.h"
#include "dns.h"

static void log_heap(const char *when) {
  Serial.printf("[heap] %s: free %u, min %u, largest block %u\n", when, (unsigned)ESP.getFreeHeap(),
                (unsigned)ESP.getMinFreeHeap(), (unsigned)ESP.getMaxAllocHeap());
}

// Link loss is logged and left to the driver: the GOT_IP event fires again
// when the cable or switch comes back, so there is no reboot path here.
static void on_net_event(arduino_event_id_t event) {
  switch (event) {
    case ARDUINO_EVENT_ETH_START:
      ETH.setHostname("adblocker");
      break;
    case ARDUINO_EVENT_ETH_CONNECTED:
      Serial.printf("[eth] link up, %u Mbps %s duplex\n", (unsigned)ETH.linkSpeed(), ETH.fullDuplex() ? "full" : "half");
      break;
    case ARDUINO_EVENT_ETH_GOT_IP:
      Serial.printf("[eth] ip %s, gateway %s, mac %s\n", ETH.localIP().toString().c_str(),
                    ETH.gatewayIP().toString().c_str(), ETH.macAddress().c_str());
      break;
    case ARDUINO_EVENT_ETH_LOST_IP:
      Serial.println("[eth] lost ip, waiting for DHCP");
      break;
    case ARDUINO_EVENT_ETH_DISCONNECTED:
      Serial.println("[eth] link down, waiting for link");
      break;
    case ARDUINO_EVENT_ETH_STOP:
      Serial.println("[eth] stopped");
      break;
    default:
      break;
  }
}

void setup() {
  Serial.begin(115200);
  Serial.printf("\n[boot] adblocker, firmware %s %s\n", __DATE__, __TIME__);
  log_heap("boot");

  Network.onEvent(on_net_event);
  if (!ETH.begin(ETH_PHY_IP101, ETH_PHY_ADDR_U138, ETH_PHY_MDC_U138, ETH_PHY_MDIO_U138, ETH_PHY_POWER_U138,
                 ETH_CLOCK_GPIO0_IN)) {
    Serial.println("[eth] ETH.begin failed");
  }
  log_heap("after ethernet");

  if (!blocklist_begin()) Serial.println("[blocklist] init failed, forwarding every query");
  BlocklistInfo b = blocklist_info();
  Serial.printf("[blocklist] %u entries, bloom %u bits, k=%u\n", (unsigned)b.entry_count, (unsigned)b.bloom_bits,
                (unsigned)b.bloom_k);

  dns_begin();
  admin_begin();
  log_heap("ready");
}

void loop() {
  dns_loop();
  admin_loop();
  delay(50);
}
