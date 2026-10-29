# AdBlocker

ESP32 PoE DNS ad blocker for the M5Stack ESP32 Ethernet Unit (U138) at 192.168.1.159.

It answers DNS on UDP 53. Names on the blocklist (and their subdomains) get `0.0.0.0` / `::`
with a 10 s TTL. Everything else is relayed to 1.1.1.1, with 8.8.8.8 as the fallback. The
status page, blocklist upload and firmware update are at http://192.168.1.159.

## Hardware

- ESP32-WROOM-32U, 4 MB flash, no PSRAM, IP101G PHY over RMII (MDC 23, MDIO 18, PHY
  address 1, 50 MHz clock into GPIO0), PoE powered. No USB port.
- The unit ships with ESP-AT firmware, which answers ping but listens on no TCP port.
- IP comes from DHCP. Reserve 192.168.1.159 for the unit's MAC on the router; the MAC is
  printed on the serial log at boot (`[eth] ip ..., mac ...`).

## Tools

Nothing new to install. PlatformIO is already at
`C:\Users\DannyHearit\.platformio\penv\Scripts\pio.exe`, with the pioarduino platform
(55.03.38-1, arduino-esp32 3.3.8) that Clawdmeter uses. The commands below call it as
`$HOME/.platformio/penv/Scripts/pio.exe`, which works in PowerShell and Git Bash. Run them
from the repo root.

## 0. Admin password (one time)

The status page, blocklist upload, block-mode switch and firmware update use HTTP basic auth
with user `admin`. The password is built into the firmware from the `ADBLOCK_ADMIN_PASSWORD`
environment variable, and the build stops if it is unset. Set it once for your user, then
open a new shell so it is picked up:

```bash
setx ADBLOCK_ADMIN_PASSWORD "choose-a-password"
```

`scripts/build_blocklist.py --upload` reads the same variable. To change the password,
change the variable and reflash. `/stats` (JSON counters) stays open without a login.

## 1. Build the firmware

```bash
$HOME/.platformio/penv/Scripts/pio.exe run -e m5stack-u138
```

## 2. First flash (serial, one time)

The U138 has no USB port. M5Stack's documented route is to remove the case and connect the
M5Stack ESP32 Downloader to the reserved program download interface on the board
(https://docs.m5stack.com/en/unit/poesp32). Once the downloader is plugged into the PC, find
its COM port:

```bash
$HOME/.platformio/penv/Scripts/pio.exe device list
```

COM4 and COM5 on this PC are Bluetooth serial links, not the downloader. Flash, replacing
`COMx` with the downloader's port:

```bash
$HOME/.platformio/penv/Scripts/pio.exe run -e m5stack-u138 -t upload --upload-port COMx
```

Watch the boot log (IP, link speed, blocklist entry count, Bloom size, free heap):

```bash
$HOME/.platformio/penv/Scripts/pio.exe device monitor -b 115200 -p COMx
```

## 3. Later firmware updates (over Ethernet)

After the first flash, new builds go over the network. Use the Firmware form on the status
page, or (curl asks for the admin password):

```bash
curl.exe -u admin -F "firmware=@.pio/build/m5stack-u138/firmware.bin" http://192.168.1.159/update
```

The unit restarts into the new image about a second after the upload.

## 4. Build and upload the blocklist

Downloads the StevenBlack hosts file, checks the hash against `src/fnv.h`, writes
`blocklist.bin` (gitignored) and prints entry count, Bloom parameters and size:

```bash
python -I scripts/build_blocklist.py
```

Build and push to the unit in one step:

```bash
python -I scripts/build_blocklist.py --upload http://192.168.1.159/upload
```

The unit writes the file to its inactive flash slot, verifies it and swaps to it without a
reboot. The status page shows the new entry count and build date. Re-run weekly or so to
pick up list changes. `--hosts FILE` builds from a local copy instead of downloading.

## 5. Point the network at it

On the router, set the DHCP DNS server to 192.168.1.159. Clients pick it up when their lease
renews; reconnect a client to pick it up now.

## 6. Test

```bash
nslookup doubleclick.net 192.168.1.159
```

Expected: `Address: 0.0.0.0` (plus `::` for the AAAA query).

```bash
nslookup example.com 192.168.1.159
```

Expected: real addresses from upstream. In both, `Server: UnKnown` is normal; nslookup asks
for the PTR record of 192.168.1.159 first and the public resolvers have none.

Run the `example.com` lookup twice: the second answer comes from the cache, so the
status page's Answer cache row shows one more hit and the TTL is a little lower.

## How it works

- **Hash.** FNV-1a 64-bit over the normalised name (lowercase, no trailing dot), xor-folded
  to 40 bits. `src/fnv.h` defines it once; the compiler checks the `HASH_VECTOR` lines with
  `static_assert`, and the Python builder checks the same lines with its own implementation,
  so the two cannot drift. `python -I scripts/build_blocklist.py --self-check` runs only
  that check.
- **File.** `blocklist.bin` = 64-byte header + 128 KB Bloom filter + sorted packed 40-bit
  keys (5 bytes each), CRC-32 over the payload. Layout in `src/blocklist_format.h`.
- **Lookup.** The full name and each parent suffix (`ads.example.com`, `example.com`) is
  tested against the Bloom filter in RAM; on a hit, binary search over the keys, read in
  place from the memory-mapped flash slot. The builder drops names already covered by a
  listed parent, since the suffix walk blocks those anyway.
- **Bloom numbers.** m = 1,048,576 bits. The builder picks k = round(m/n ln 2), capped at 16.
  On 2026-10-28 the hosts file had 76,147 names, 41,367 after pruning: k = 16, predicted
  false positive rate 5.3e-6 per name. A false positive costs one flash binary search, never
  a wrong answer. For reference, the original estimate of 140k names at k = 5 gives 2.7%, not
  1%.
- **Flash.** Two OTA app slots of 1.44 MB and two blocklist slots of 544 KB (about 85k
  entries each), in `partitions.csv`. An upload goes to the inactive slot with its
  `commit_seq` left erased; after a CRC read-back the firmware programs `commit_seq` and
  swaps. Boot picks the committed slot with the highest sequence, so a power cut mid-upload
  leaves the old list active.
- **Upstream.** Up to 32 queries in flight, each with a fresh random 16-bit transaction id;
  an answer must match the id, the upstream address and the question bytes. No answer in
  1 s: resend to the other upstream. No answer in 2 s: drop. Three failures in a row switch
  the upstream in use; the primary is retried after 60 s. The EDNS UDP size is capped at
  1232 so answers fit one Ethernet frame.
- **Answer cache.** Complete NOERROR and NXDOMAIN answers are kept for their smallest TTL,
  at most 1 hour (`-DDNS_CACHE_MAX_TTL`). A repeat question is answered from RAM with the
  client's id and spelling of the name, and every TTL lowered by the time held. Answers are
  keyed on the question plus the RD, CD, EDNS and DO bits, so an EDNS answer never goes to a
  client that sent none. The store is a 24 KB ring (`-DDNS_CACHE_BYTES`, 0 turns it off)
  with up to 256 answers, allocated after the Bloom filter and shrunk if that would leave
  under 64 KB of heap. Blocked names are checked first, so a list upload takes effect at
  once. The status page shows hits and answers held.
- **Sending.** All DNS packets go out from a `dns_tx` task, never from the AsyncUDP
  receive task, which would deadlock the lwIP core lock when the receive queue is full.
- **Block mode.** 0.0.0.0 / :: by default (`-DDNS_BLOCK_NXDOMAIN=0` in `platformio.ini`).
  The status page can switch to NXDOMAIN; that choice is stored in NVS.
- **Memory.** The Bloom filter is four 32 KB blocks allocated once at boot (a single 128 KB
  block often does not exist on a PSRAM-less ESP32). Uploads stream to flash in 4 KB pages.
  Free heap is on the serial log and the status page.

## Limits

- Basic auth over plain HTTP: the password crosses the LAN unencrypted on each admin request.
- The answer cache lives in RAM only, so a reboot or firmware update empties it.
- DNS listens on IPv4 UDP only. No TCP/53, so a client cannot retry a truncated answer
  over TCP here; it usually falls back to another resolver.
- Upstream queries leave from one fixed source port, so spoofing resistance rests on the
  16-bit id and question match. Fine on a home LAN.
