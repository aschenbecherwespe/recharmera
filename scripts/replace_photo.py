#!/usr/bin/env python3
"""
Replace the stored 960x720 JPEG in the internal SPI photo store.

The store is not a filesystem.  Its index lives at 0x17F000 and consists of
little-endian ``(u32 slot, u32 size)`` pairs followed by a zero terminator; the
JPEG data starts at 0x180000.  On ``charmera.bin`` slot ``0x00010000`` points at
the 24227-byte capture.  This tool rewrites that JPEG and updates its size, so
the replacement can be shorter than the original.  Only the 0x180000-0x185FFF
region is proven safe by both dumps; larger JPEGs are rejected rather than
encroaching on unverified slot geometry.

Usage:
    uv run scripts/replace_photo.py [base.bin] IMAGE [-o OUT.bin]
Then build + validate the SD upgrade file:
    uv run scripts/build_upgrade_files.py OUT.bin --bump
    uv run scripts/emu_updater.py --stage both <JH_5408*.bin>
"""
import argparse
import os
import struct
import sys

from PIL import Image

BASE = "charmera.bin"
DEFAULT_OUT = os.path.join("patched", "charmera_replaced.bin")

PHOTO_OFFSET = 0x180000
PHOTO_SAFE_SIZE = 0x6000
PHOTO_END = PHOTO_OFFSET + PHOTO_SAFE_SIZE
INDEX_OFFSET = 0x17F000
SLOT0 = 0x00010000
WIDTH, HEIGHT = 960, 720
DEFAULT_QUALITY = 92


def encode_jpeg(path: str, quality: int) -> bytes:
    with Image.open(path) as image:
        converted = image.convert("RGB")
        if converted.size != (WIDTH, HEIGHT):
            converted = converted.resize((WIDTH, HEIGHT), Image.Resampling.LANCZOS)
        converted.save(os.devnull, "JPEG", quality=quality, optimize=True)

        import io
        buffer = io.BytesIO()
        converted.save(buffer, "JPEG", quality=quality, optimize=True)
        return buffer.getvalue()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("base", nargs="?", default=BASE,
                    help=f"source flash image (default {BASE})")
    ap.add_argument("image", help="replacement image (any Pillow-supported format)")
    ap.add_argument("-o", "--out", default=DEFAULT_OUT,
                    help=f"output flash image (default {DEFAULT_OUT})")
    ap.add_argument("--quality", type=int, default=DEFAULT_QUALITY,
                    help=f"JPEG quality 1-95 (default {DEFAULT_QUALITY})")
    ap.parse_args()
    args = ap.parse_args()

    if not 1 <= args.quality <= 95:
        ap.error("--quality must be between 1 and 95")

    raw = bytearray(open(args.base, "rb").read())
    if len(raw) < PHOTO_END or INDEX_OFFSET + 16 > len(raw):
        raise SystemExit(f"refusing to patch: {args.base} is too small for the photo store")

    slot, size = struct.unpack_from("<II", raw, INDEX_OFFSET)
    if slot != SLOT0:
        raise SystemExit(
            f"refusing to patch: expected index slot {SLOT0:#010x} at "
            f"0x{INDEX_OFFSET:x}, found {slot:#010x}")
    jpeg = bytes(raw[PHOTO_OFFSET:PHOTO_OFFSET + size])
    if not jpeg.startswith(b"\xff\xd8\xff") or not jpeg.endswith(b"\xff\xd9"):
        raise SystemExit(
            f"refusing to patch: indexed size {size} at 0x{INDEX_OFFSET:x} does not "
            f"delimit a complete JPEG")

    replacement = encode_jpeg(args.image, args.quality)
    available = PHOTO_SAFE_SIZE
    if len(replacement) > available:
        raise SystemExit(
            f"replacement is {len(replacement)} bytes; the current reserved area is "
            f"{available} bytes - lower --quality or use a smaller source image")

    raw[PHOTO_OFFSET:PHOTO_END] = replacement
    raw[PHOTO_OFFSET + len(replacement):PHOTO_END] = b"\xff" * (
        available - len(replacement))
    struct.pack_into("<II", raw, INDEX_OFFSET, SLOT0, len(replacement))

    out_dir = os.path.dirname(args.out)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    with open(args.out, "wb") as output:
        output.write(raw)

    print(f"{args.out}")
    print(f"  photo    : 0x{PHOTO_OFFSET:x} {size} -> {len(replacement)} bytes "
          f"({WIDTH}x{HEIGHT}, quality {args.quality})")
    print(f"  index    : 0x{INDEX_OFFSET:x} size -> {len(replacement)}")
    print(f"  image    : {len(raw)} bytes (0x{len(raw):x}) from {args.base}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
