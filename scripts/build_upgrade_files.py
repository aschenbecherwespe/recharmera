#!/usr/bin/env python3
"""
Build candidate SD-card upgrade files ("JH_5408*.bin") for the GPCV camera.

The camera's SD upgrade mechanism (see REVERSE_ENGINEERING_NOTES.md):
  * looks for C:\\JH_5408*.bin on the SD card root
  * check_fn (0x21818): if file[0x19] != "202505201029" -> "update available"
                        if file[0x19] == "202505201029" -> "already current" (file IGNORED)
  * flasher (0x21370):  parses an 8-hex-char byte-sum expected value from the
                        header, opens the file, sums all bytes, and aborts
                        (before writing) on mismatch.  On success it writes the
                        whole file 1:1 to SPI flash in 0x400-byte sectors.

So a working upgrade file is (current model):
  [0x19..0x25] 12-byte version  -> MUST DIFFER from the installed "202505201029"
  [0x26..0x2E]  8 hex chars    -> expected byte-sum (coverage still being tested)
  [0x2E..]      raw flash image content

Usage:
    python3 scripts/build_upgrade_files.py [base.bin]
Default: base.bin = charmera.bin; writes vC_whole.bin, vD_body.bin, vE_after26.bin
"""
import hashlib, sys

BASE = "charmera.bin"
VERSION_TOKEN = b"202505201029"          # the installed version constant
# A DIFFERENT version marker (must differ to trigger the upgrade attempt)
NEW_VERSION = b"100000000000"


def put_version(d: bytearray, ver: bytes) -> None:
    d[0x19:0x25] = ver


def whole_file_sum(d: bytearray) -> int:
    return sum(d) & 0xFFFFFFFF


def body_sum(d: bytearray) -> int:
    return sum(d[0x30:]) & 0xFFFFFFFF


def after_0x26_sum(d: bytearray) -> int:
    return sum(d[0x2E:]) & 0xFFFFFFFF


def write_checksum(d: bytearray, compute: callable, at: int = 0x26, iters: int = 30) -> None:
    """Write an 8-char uppercase hex byte-sum at `at`, iterating to a fixed point."""
    prev = None
    for _ in range(iters):
        s = compute(d)
        d[at:at + 8] = ("%08X" % s).encode()
        if prev == d[at:at + 8]:
            break
        prev = bytes(d[at:at + 8])


def save(variant: str, d: bytearray) -> None:
    fn = f"{variant}.bin"
    with open(fn, "wb") as f:
        f.write(bytes(d))
    print(f"{fn:22s} md5={hashlib.md5(bytes(d)).hexdigest()}"
          f"  @0x19={bytes(d[0x19:0x25])!r}  @0x26={bytes(d[0x26:0x2E])!r}")


def main():
    base = sys.argv[1] if len(sys.argv) > 1 else BASE
    data = bytearray(open(base, "rb").read())
    print(f"base: {base} ({len(data)} bytes)")

    # vC: version differs + whole-file byte-sum
    d = bytearray(data)
    put_version(d, NEW_VERSION)
    write_checksum(d, whole_file_sum)
    save("vC_whole", d)

    # vD: version differs + body-only (0x30..) byte-sum
    d = bytearray(data)
    put_version(d, NEW_VERSION)
    write_checksum(d, body_sum)
    save("vD_body", d)

    # vE: version differs + sum of bytes after the checksum field (0x2E..)
    d = bytearray(data)
    put_version(d, NEW_VERSION)
    write_checksum(d, after_0x26_sum)
    save("vE_after26", d)

    print("\nTo test: format SD card FAT32 (<=32GB), copy one of these to the root")
    print("as 'JH_5408.bin' exactly (root, not in a folder), boot the camera.")


if __name__ == "__main__":
    main()