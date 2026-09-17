#!/usr/bin/env python3
"""
Build a valid SD-card upgrade file for the GPCV/CHARMERA camera.

Wire format (confirmed on hardware; see REVERSE_ENGINEERING_NOTES.md section 3)
-----------------------------------------------------------------------------
The updater carries its metadata in the *SD filename*, not in the file:

    C:\\JH_5408*.bin              <- find-first pattern (card root, .bin suffix)
    JH_5408<VER12><X><CK8>.bin    <- fname[0:7] / [7:19] / [19] / [20:28] / [28:]

      fname[7:19]  VER12  12-char version, memcmp'd against the installed
                          "202505201029" (flash 0x218C4).  Must DIFFER to
                          trigger the upgrade; equal = file ignored.
      fname[19]    X      free separator char (never read by the updater)
      fname[20:28] CK8    8 ASCII hex chars = whole-file byte sum mod 2^32

IMAGE SIZE IS LOAD-BEARING
--------------------------
After the last data sector the flasher erases one extra sector at
`image_size + 0x10000` (instruction 0x217B4).  A NOR chip decodes an address
modulo its capacity, so an address past the end of the 2 MiB part does NOT
no-op - it destroys a sector near the *start* of the flash.  A full-size
2 MiB dump puts that erase at 0x210000 -> 0x210000 % 0x200000 = 0x010000,
which bricks the camera.  Hence images are truncated to

    MAX_IMAGE = 0x200000 - 2 * 0x10000 = 0x1E0000

(the trailing erase then lands at 0x1F0000, inside the chip).  Everything the
truncation drops is 0xFF in the stock dump, so nothing is lost.

Usage:
    uv run scripts/build_upgrade_files.py [dump.bin] [-d DIR] [--version VER12]
                                          [--clean] [--bump]
Verify with:
    uv run scripts/emu_updater.py --stage write <out.bin>   # write tail
    uv run scripts/emu_updater.py --stage both  <out.bin>   # both gates
"""
import argparse
import os
import sys
import struct

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from emu_updater import (                                            # noqa: E402
    MAX_IMAGE, CHIP_SIZE, SECTOR, byte_sum, canonical_name,
    NAME_PREFIX, NAME_SUFFIX,
)

BASE = "charmera.bin"
INSTALLED = b"202505201029"           # build stamp compiled into the firmware
DEFAULT_VERSION = b"202609101200"
SPII_LEN_OFF = 0x10                   # SPII header field 0x001B0000 (image length)
FW_VERSION_OFF = 0x218C4              # "202505201029" string inside the firmware

# Device-state regions wiped by --clean (REVERSE_ENGINEERING_NOTES.md §11):
#   0x170000-0x17EFFF  GPNV non-volatile settings (12 x 0x200-byte ring slots)
#   0x17F000-0x17FFFF  internal photo-store index ((u32 slot, u32 size) entries)
#   0x180000-0x185FFF  stored photos (960x720 GPEncoder JPEGs, one per slot)
# Everything past 0x186000 is already 0xFF in the stock dump.
GPNV_START = 0x170000
PHOTO_END = 0x186000


def fit_image(raw: bytes) -> tuple[bytes, str]:
    """Truncate to the largest size whose trailing sector erase stays in range."""
    if len(raw) <= MAX_IMAGE:
        return raw, f"already within the 0x{MAX_IMAGE:x} limit"
    dropped = raw[MAX_IMAGE:]
    if any(b != 0xFF for b in dropped):
        raise SystemExit(
            f"refusing to build: image is {len(raw)} bytes and bytes beyond "
            f"0x{MAX_IMAGE:x} are not 0xFF, so truncating would lose data")
    return raw[:MAX_IMAGE], (f"truncated from {len(raw)} to 0x{MAX_IMAGE:x} bytes "
                             f"(dropped {len(dropped)} trailing 0xFF bytes; the flasher "
                             f"erases that region anyway)")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("base", nargs="?", default=BASE, help=f"source flash image (default {BASE})")
    ap.add_argument("-d", "--dir", default=".", help="output directory")
    ap.add_argument("--version", default=DEFAULT_VERSION.decode(),
                    help=f"12-char version for the filename (must differ from "
                         f"{INSTALLED.decode()!r})")
    ap.add_argument("--bump", action="store_true",
                    help="also rewrite the version string inside the firmware image "
                         "to match --version, so the camera 'remembers' the update "
                         "and won't re-flash the same file on the next boot")
    ap.add_argument("--clean", action="store_true",
                    help=f"wipe device state (GPNV settings + photo store, "
                         f"0x{GPNV_START:x}-0x{PHOTO_END:x}) to 0xFF so the "
                         f"upgrade file carries firmware + assets only")
    args = ap.parse_args()

    version = args.version.encode()
    if len(version) != 12:
        ap.error(f"--version must be exactly 12 characters, got {len(version)}")
    if version == INSTALLED:
        print(f"warning: version {version.decode()!r} equals the installed build - "
              f"the camera would ignore the file", file=sys.stderr)

    raw = bytearray(open(args.base, "rb").read())

    cleaned = False
    if args.clean:
        if PHOTO_END > len(raw):
            raise SystemExit(f"refusing to clean: image too small for the "
                             f"0x{GPNV_START:x}-0x{PHOTO_END:x} region")
        raw[GPNV_START:PHOTO_END] = b"\xff" * (PHOTO_END - GPNV_START)
        cleaned = True
        print(f"  clean    : wiped 0x{GPNV_START:x}-0x{PHOTO_END-1:x} "
              f"(GPNV settings + photo index + stored photos) to 0xFF")

    if args.bump:
        if FW_VERSION_OFF + 12 > len(raw):
            raise SystemExit(f"refusing to bump: image too small for version at "
                             f"0x{FW_VERSION_OFF:x}")
        old = bytes(raw[FW_VERSION_OFF:FW_VERSION_OFF + 12])
        if old != INSTALLED:
            print(f"warning: version at 0x{FW_VERSION_OFF:x} is {old!r}, "
                  f"not the stock {INSTALLED!r} - overwriting anyway", file=sys.stderr)
        raw[FW_VERSION_OFF:FW_VERSION_OFF + 12] = version
        print(f"  bump     : firmware version at 0x{FW_VERSION_OFF:x} "
              f"{old!r} -> {version!r}")
    image, note = fit_image(raw)
    name = canonical_name(image, version).decode()
    out = os.path.join(args.dir, name)
    os.makedirs(args.dir, exist_ok=True)
    with open(out, "wb") as f:
        f.write(image)

    checksum = byte_sum(image)
    print(f"{out}")
    print(f"  image    : {len(image)} bytes (0x{len(image):x}) from {args.base} - {note}")
    if cleaned:
        print(f"  state    : device settings and stored photos BLANKED "
              f"(factory-fresh; firmware re-inits GPNV on boot)")
    print(f"  name     : {name}  ({len(name)} chars)")
    print(f"             {NAME_PREFIX.decode()}|{version.decode()}|"
          f"{name[19]}|{checksum:08X}|{NAME_SUFFIX.decode()}")
    print(f"  version  : {version.decode()} (differs from installed {INSTALLED.decode()}"
          f" -> update triggers)")
    print(f"  checksum : {checksum:08X} = sum(image) mod 2^32")
    print(f"  write tail: image + 0x{SECTOR:x} = 0x{len(image) + SECTOR:x} sector erase, "
          f"ends at 0x{len(image) + 2 * SECTOR:x} <= chip 0x{CHIP_SIZE:x} "
          f"{'OK' if len(image) + 2 * SECTOR <= CHIP_SIZE else 'OUT OF RANGE - DO NOT FLASH'}")
    if len(raw) > SPII_LEN_OFF + 4:
        declared = int.from_bytes(raw[SPII_LEN_OFF:SPII_LEN_OFF + 4], "little")
        print(f"  SPII len : header declares 0x{declared:x} (informational)")
    print(f"\nCopy '{name}' to the ROOT of a FAT32 SD card (do not rename it), then boot.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
