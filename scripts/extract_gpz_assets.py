#!/usr/bin/env python3
"""
Extract the GP+ UI resource filesystem from a GPCV/Generplus flash dump.

The GP+ partition (typically at offset 0x120000 in a 2 MiB dump) contains:
  - Header (0x20 bytes): 'GP+' magic
  - Name table: sequence of  null-terminated filename + 4-byte LE file ID
  - Then asset data, sector-aligned (0x200), in the SAME ORDER as the name table.

Each asset is stored from its start offset to the next asset's start offset
(raw, sector-aligned => includes any trailing 0x00/0xFF padding).

Usage:
    uv run scripts/extract_gpz_assets.py <firmware.bin> [gp+_offset] [outdir]
Default:                   example.bin                    0x120000      assets/
"""
import os, re, struct, sys

MAGIC = b"GP+"
GPZP = b"GPZP"


def find_gp_plus(data: bytes, start: int = 0x100000) -> int:
    """Locate the GP+ filesystem (first 'GP+' at sector boundary with name table)."""
    idx = start
    while True:
        i = data.find(MAGIC, idx)
        if i < 0:
            return -1
        # heuristic: next bytes often 0x00 0x03 0x00 0x03 (version)
        if data[i + 4:i + 8] in (b"\x00\x03\x00\x03", b"\x00\x02\x00\x03", b"\x00\x01\x00\x01"):
            return i
        idx = i + 1


def parse_name_table(data: bytes, start: int) -> list:
    """Parse the filename+ID table beginning right after the GP+ header."""
    i = start + 0x20
    names = []
    while i < start + 0x700:
        m = re.match(rb"[A-Za-z][A-Za-z0-9_]{2,}", data[i:i + 64])
        if not m:
            i += 1
            continue
        name = m.group().decode()
        j = i + len(name)
        while j < len(data) and data[j] == 0:
            j += 1
        if j + 4 > len(data):
            break
        file_id = struct.unpack("<I", data[j:j + 4])[0]
        names.append((name, file_id))
        i = j + 4
    # dedupe, preserving order
    seen, out = set(), []
    for n, fid in names:
        if n not in seen:
            seen.add(n)
            out.append((n, fid))
    return out


def find_asset_blocks(data: bytes, start: int, end: int = 0x180000) -> list:
    """Ordered list of asset start offsets (GPZP / JPEG / WAV magic signatures)."""
    blocks = []
    for sig in (GPZP, b"\xff\xd8\xff\xc0", b"\xff\xd8\xff\xe0", b"RIFF"):
        idx = start
        while True:
            s = data.find(sig, idx)
            if s < 0 or s > end:
                break
            blocks.append(s)
            idx = s + len(sig)
    return sorted(set(blocks))


def ext_for_magic(head: bytes) -> str:
    if head[:4] == b"RIFF":
        return "wav"
    if head[:2] == b"\xff\xd8":
        return "jpg"
    if head[:4] == GPZP:
        return "gpzp"
    return "bin"


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    fw_path = sys.argv[1]
    start = int(sys.argv[2], 0) if len(sys.argv) > 2 else 0x120000
    outdir = sys.argv[3] if len(sys.argv) > 3 else "assets"

    data = open(fw_path, "rb").read()
    if len(data) < start:
        print("GP+ offset out of range")
        sys.exit(1)

    names = parse_name_table(data, start)
    blocks = find_asset_blocks(data, start)
    if len(names) != len(blocks) and len(names) != len(blocks) + 1:
        print(f"WARNING: {len(names)} names vs {len(blocks)} blocks")

    os.makedirs(outdir, exist_ok=True)
    bi = 0
    for name, _fid in names:
        # GPRSPAK is a container marker with no standalone data block in some images
        if name == "GPRSPAK" and bi >= len(blocks):
            continue
        if bi >= len(blocks):
            print(f"ran out of blocks at {name}")
            break
        addr = blocks[bi]
        bi += 1
        nxt = blocks[bi] if bi < len(blocks) else min(addr + 0x2000, len(data))
        blob = data[addr:nxt]
        ext = ext_for_magic(blob)
        low = name.lower()
        stem = name
        for suf in ("gpzp", "gpz", "jpg", "jpeg", "wav", "gprspak"):
            if low.endswith(suf):
                stem = name[: len(name) - len(suf)] + "." + ext
                break
        else:
            stem = name + "." + ext
        out_path = os.path.join(outdir, stem)
        with open(out_path, "wb") as f:
            f.write(blob)
        print(f"{stem:28s} {len(blob):8d}  @0x{addr:07x}")

    print(f"\nExtracted {bi} files to {outdir}/")


if __name__ == "__main__":
    main()
