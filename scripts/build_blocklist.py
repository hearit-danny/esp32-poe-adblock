"""Build blocklist.bin for the ESP32 DNS ad blocker, and optionally upload it.

Run with the isolated interpreter (stdlib only):

    python -I scripts/build_blocklist.py
    python -I scripts/build_blocklist.py --upload http://192.168.1.159/upload

The hash algorithm and file layout are defined once, in src/fnv.h and
src/blocklist_format.h. This script reads its constants from those headers and
checks its own hash against the HASH_VECTOR lines in fnv.h before it writes
anything; the firmware checks the same lines with static_assert at compile
time, so the two implementations cannot drift apart silently.
"""

import argparse
import base64
import os
import math
import re
import struct
import sys
import time
import urllib.request
import uuid
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HOSTS_URL = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
DEFAULT_BLOOM_BITS = 1 << 20  # 128 KB, the firmware's RAM buffer

# Hostnames the hosts file maps for the local machine, not for blocking.
LOCAL_NAMES = {
    "localhost", "localhost.localdomain", "local", "broadcasthost", "ip6-localhost",
    "ip6-loopback", "ip6-localnet", "ip6-mcastprefix", "ip6-allnodes", "ip6-allrouters",
    "ip6-allhosts", "0.0.0.0",
}
DOMAIN_RE = re.compile(r"^[a-z0-9_-]+(\.[a-z0-9_-]+)+$")
IPV4_RE = re.compile(r"^\d+\.\d+\.\d+\.\d+$")


def read_constants():
    consts = {}
    for name in ("fnv.h", "blocklist_format.h"):
        text = (ROOT / "src" / name).read_text()
        for m in re.finditer(r"constexpr uint\d+_t (\w+) = (0x[0-9A-Fa-f]+|\d+)U?L*;", text):
            consts[m.group(1)] = int(m.group(2), 0)
    vectors = [(m.group(1), int(m.group(2), 16))
               for m in re.finditer(r'HASH_VECTOR\("([^"]+)", (0x[0-9A-Fa-f]+)ULL\)', (ROOT / "src" / "fnv.h").read_text())]
    return consts, vectors


C, VECTORS = read_constants()
MASK64 = (1 << 64) - 1


def slot_size() -> int:
    """Size of the blk_a partition in partitions.csv (blk_b is the same)."""
    for line in (ROOT / "partitions.csv").read_text().splitlines():
        cols = [c.strip() for c in line.split("#", 1)[0].split(",")]
        if cols[0] == "blk_a":
            return int(cols[4], 0)
    sys.exit("blk_a not found in partitions.csv")


def fnv1a64(name: str) -> int:
    h = C["FNV_OFFSET_BASIS"]
    for b in name.encode("ascii"):
        h ^= b
        h = (h * C["FNV_PRIME"]) & MASK64
    return h


def fold40(h64: int) -> int:
    return ((h64 >> 40) ^ h64) & C["KEY40_MASK"]


def bloom_bits_for(h64: int, k: int, m: int):
    h1 = h64 & 0xFFFFFFFF
    h2 = (h64 >> 32) | 1
    return [(h1 + i * h2) % m for i in range(k)]


def self_check():
    if not VECTORS:
        sys.exit("no HASH_VECTOR lines found in src/fnv.h")
    for name, expected in VECTORS:
        got = fold40(fnv1a64(name))
        if got != expected:
            sys.exit(f"hash mismatch for {name}: python 0x{got:010X}, fnv.h 0x{expected:010X}")
        print(f"  hash ok  {name:<24} 0x{got:010X}")


def normalise(name: str) -> str:
    return name.strip().lower().rstrip(".")


def parse_hosts(text: str):
    domains = set()
    for line in text.splitlines():
        line = line.split("#", 1)[0].split()
        if len(line) < 2 or line[0] not in ("0.0.0.0", "127.0.0.1"):
            continue
        for raw in line[1:]:
            d = normalise(raw)
            if d in LOCAL_NAMES or IPV4_RE.match(d) or not DOMAIN_RE.match(d):
                continue
            domains.add(d)
    return domains


def prune_covered(domains):
    """Drop names whose parent suffix is already listed. The firmware checks
    every parent suffix, so a listed apex already blocks its subdomains."""
    kept = []
    for d in domains:
        parts = d.split(".")
        if not any(".".join(parts[i:]) in domains for i in range(1, len(parts) - 1)):
            kept.append(d)
    return kept


def build(domains, bloom_bits, k):
    keys = {}
    collisions = 0
    for d in domains:
        key = fold40(fnv1a64(d))
        if key in keys:
            collisions += 1
        keys[key] = d
    bloom = bytearray(bloom_bits // 8)
    for d in domains:
        for bit in bloom_bits_for(fnv1a64(d), k, bloom_bits):
            bloom[bit >> 3] |= 1 << (bit & 7)
    sorted_keys = sorted(keys)
    packed = b"".join(key.to_bytes(C["BLK_KEY_BYTES"], "little") for key in sorted_keys)
    payload = bytes(bloom) + packed
    total = C["BLK_HEADER_SIZE"] + len(payload)
    header = struct.pack(
        "<IHHIIBBHIII28sI",
        C["BLK_MAGIC"], C["BLK_VERSION"], C["BLK_HEADER_SIZE"], len(sorted_keys), bloom_bits, k,
        C["BLK_KEY_BYTES"], 0, int(time.time()), zlib.crc32(payload), total, b"\0" * 28, C["BLK_UNCOMMITTED"],
    )
    assert len(header) == C["BLK_HEADER_SIZE"]
    return header + payload, len(sorted_keys), collisions


def lookup(blob: bytes, name: str) -> bool:
    """Same walk as blocklist_contains() in the firmware, over the built file."""
    count, m, k = struct.unpack_from("<IIB", blob, 8)
    hs = C["BLK_HEADER_SIZE"]
    bloom = blob[hs:hs + m // 8]
    keys = blob[hs + m // 8:]
    name = normalise(name)
    while "." in name:
        h64 = fnv1a64(name)
        if all(bloom[b >> 3] & (1 << (b & 7)) for b in bloom_bits_for(h64, k, m)):
            want, lo, hi = fold40(h64), 0, count
            while lo < hi:
                mid = (lo + hi) // 2
                got = int.from_bytes(keys[mid * 5:mid * 5 + 5], "little")
                if got == want:
                    return True
                lo, hi = (mid + 1, hi) if got < want else (lo, mid)
        name = name.split(".", 1)[1]
    return False


def upload(url: str, blob: bytes, password: str):
    boundary = uuid.uuid4().hex
    body = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"blocklist.bin\"\r\n"
            f"Content-Type: application/octet-stream\r\n\r\n").encode() + blob + f"\r\n--{boundary}--\r\n".encode()
    req = urllib.request.Request(url, data=body, method="POST",
                                 headers={"Content-Type": f"multipart/form-data; boundary={boundary}"})
    # Sent up front so the file goes over once, rather than after a 401.
    token = base64.b64encode(f"admin:{password}".encode()).decode()
    req.add_header("Authorization", f"Basic {token}")
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            print(f"upload: HTTP {resp.status}: {resp.read().decode(errors='replace').strip()}")
    except urllib.error.HTTPError as e:
        if e.code == 401:
            sys.exit("upload failed: HTTP 401, the admin password does not match the firmware's")
        sys.exit(f"upload failed: HTTP {e.code}: {e.read().decode(errors='replace').strip()}")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--hosts", type=Path, help="read this hosts file instead of downloading")
    ap.add_argument("--save-hosts", type=Path, help="also save the downloaded hosts file here")
    ap.add_argument("--out", type=Path, default=ROOT / "blocklist.bin")
    ap.add_argument("--bloom-bits", type=int, default=DEFAULT_BLOOM_BITS)
    ap.add_argument("--k", type=int, help="bloom hash count (default: optimal for the entry count)")
    ap.add_argument("--no-prune", action="store_true", help="keep subdomains of listed domains")
    ap.add_argument("--upload", metavar="URL", help="POST the file, e.g. http://192.168.1.159/upload")
    ap.add_argument("--password", default=os.environ.get("ADBLOCK_ADMIN_PASSWORD", ""),
                    help="admin password for --upload (default: $ADBLOCK_ADMIN_PASSWORD)")
    ap.add_argument("--self-check", action="store_true", help="only run the hash self-check")
    args = ap.parse_args()

    print("self-check against src/fnv.h:")
    self_check()
    if args.self_check:
        return
    if args.upload and not args.password:
        sys.exit("--upload needs the admin password: set ADBLOCK_ADMIN_PASSWORD or pass --password")
    if args.bloom_bits % 8 or args.bloom_bits // 8 > C["BLK_MAX_BLOOM_BYTES"]:
        sys.exit(f"--bloom-bits must be a multiple of 8 and at most {C['BLK_MAX_BLOOM_BYTES'] * 8}")

    if args.hosts:
        text = args.hosts.read_text(encoding="utf-8", errors="replace")
    else:
        print(f"downloading {HOSTS_URL}")
        with urllib.request.urlopen(HOSTS_URL, timeout=60) as resp:
            text = resp.read().decode("utf-8", errors="replace")
        if args.save_hosts:
            args.save_hosts.write_text(text, encoding="utf-8")

    parsed = parse_hosts(text)
    domains = sorted(parsed) if args.no_prune else sorted(prune_covered(parsed))
    n, m = len(domains), args.bloom_bits
    k = args.k or max(1, min(C["BLK_MAX_K"], round(m / n * math.log(2))))
    blob, entries, collisions = build(domains, m, k)
    fpr = (1 - math.exp(-k * n / m)) ** k

    print(f"domains parsed:      {len(parsed)}")
    print(f"entries written:     {entries}" + ("" if args.no_prune else f" ({len(parsed) - n} subdomains of listed names pruned)"))
    print(f"40-bit collisions:   {collisions}")
    print(f"bloom:               {m} bits ({m // 8192} KB), k={k}, {m / n:.2f} bits/entry")
    print(f"bloom false positive {fpr:.2e} per name checked (a hit costs one flash binary search)")
    slot = slot_size()
    print(f"file size:           {len(blob)} bytes, flash slot {slot} bytes ({len(blob) * 100 // slot}% used)")
    if len(blob) > slot:
        sys.exit("blocklist does not fit the blk_a/blk_b slot in partitions.csv")

    for name, want in (("doubleclick.net", True), ("ads.doubleclick.net", True), ("example.com", False)):
        got = lookup(blob, name)
        print(f"  lookup {'ok ' if got == want else 'BAD'} {name:<22} {'blocked' if got else 'allowed'}")
        if got != want:
            sys.exit("lookup check failed")

    args.out.write_bytes(blob)
    print(f"wrote {args.out}")
    if args.upload:
        upload(args.upload, blob, args.password)


if __name__ == "__main__":
    main()
