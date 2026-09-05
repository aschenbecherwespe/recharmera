#!/usr/bin/env python3
"""
Firmware analysis helpers for the GPCV flash dump.

Subcommands:
    entropy  <fw.bin>           Print a 4 KB-block entropy map (high=code/compressed, low=raw/padding)
    strings  <fw.bin> [regex]   Grep printable strings (default: print all >4 chars)
    magic    <fw.bin>           Find JPEG/WAV/GPZP/GP+/SPII signatures
    seg      <fw.bin> <off> [n] Hex+ascii dump of a region

Usage examples:
    python3 scripts/firmware_analysis.py entropy charmera.bin | tail -40
    python3 scripts/firmware_analysis.py strings charmera.bin 'upgrade|JH_|\\.bin'
    python3 scripts/firmware_analysis.py magic charmera.bin
    python3 scripts/firmware_analysis.py seg charmera.bin 0x21818 64
"""
import math, re, struct, sys

MAGICS = [
    (b"SPII", "SPII flash header"),
    (b"GP+", "GP+ resource FS"),
    (b"GPZP", "GPZP compressed image"),
    (b"\xff\xd8\xff", "JPEG"),
    (b"RIFF", "RIFF (WAV/AVI)"),
    (b"GPCV", "GPCV SDK string"),
]


def entropy(block):
    if not block:
        return 0.0
    c = {}
    for b in block:
        c[b] = c.get(b, 0) + 1
    n = len(block)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


def cmd_entropy(data):
    for i in range(0, len(data), 4096):
        blk = data[i:i + 4096]
        if len(blk) < 256:
            continue
        e = entropy(blk)
        bar = "#" * int(e / 8 * 40)
        flag = "  <-- LOW (raw/zero)" if e < 6 else ""
        print(f"{i:08x}  {e:5.2f} {bar}{flag}")


def cmd_strings(data, pat):
    rx = re.compile(pat.encode()) if pat else re.compile(rb"[ -~]{5,}")
    for m in re.finditer(rx, data):
        print(f"0x{m.start():08x}: {m.group().decode(errors='replace')!r}")


def cmd_magic(data):
    for sig, label in MAGICS:
        hits = []
        i = 0
        while True:
            i = data.find(sig, i)
            if i < 0:
                break
            hits.append(i)
            i += 1
            if len(hits) >= 40:
                break
        print(f"{label:24s} ({sig!r}): {[hex(h) for h in hits]}")


def cmd_seg(data, off, n):
    for i in range(off, off + n, 16):
        row = data[i:i + 16]
        asc = "".join(chr(c) if 32 <= c < 127 else "." for c in row)
        print(f"{i:08x}  {row.hex(' '):48s}  {asc}")


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)
    cmd = sys.argv[1]
    data = open(sys.argv[2], "rb").read()
    if cmd == "entropy":
        cmd_entropy(data)
    elif cmd == "strings":
        cmd_strings(data, sys.argv[3] if len(sys.argv) > 3 else None)
    elif cmd == "magic":
        cmd_magic(data)
    elif cmd == "seg":
        off = int(sys.argv[3], 0)
        n = int(sys.argv[4], 0) if len(sys.argv) > 4 else 64
        cmd_seg(data, off, n)
    else:
        print(f"unknown cmd: {cmd}")


if __name__ == "__main__":
    main()