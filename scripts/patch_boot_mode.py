#!/usr/bin/env python3
"""
Patch the GPCV/CHARMERA firmware to boot into photo mode instead of the
"SELECT MODE" menu.

Boot mode chain (see REVERSE_ENGINEERING_NOTES.md sections 10.2 and 10.10)
-------------------------------------------------------------------------
The mode dispatcher is task slot 0x2d (file 0x25868).  It owns the message
queue whose handle lives at RAM 0x110d90 (= mode ctx 0x110d80 + 0x10), decodes
each received word's low 9 bits as a mode id, stores it at 0x110d1e and
switch-dispatches at 0x258e0:

    mode 0x100 -> 0x65b0  power-on / SD-update gate (logo)
    mode 0x108 -> 0x21370 SD firmware updater
    mode 0x10D -> 0x2526c "SELECT MODE" menu
    mode 0x101 -> 0x1c644 video record
    mode 0x102 -> 0x1d6fc still capture        <- what we want at power-on

At power-on the dispatcher seeds the queue with 0x100 (0x25874).  The power-on
handler 0x65b0 drains the event queue; on event 0x5025 it posts mode 0x108
(SD-update check, kept) and then leaves through 0x6578, which posts mode 0x10D
(select menu) to the same mode queue:

    0006578: ldr r0, [pc, #0x198]   ; pool=0x110d90   (mode queue handle)
    000657c: push {r3, lr}
    0006580: ldr r0, [r0]           ; queue handle
    0006584: ldr r1, [pc, #0x188]   ; <- literal 0x6714 = 0x10D  [SITE]
    0006588: bl #0x8f87c            ; msgQSend(queue, mode)

That literal is loaded only by 0x6584 and 0x6578 has exactly one caller
(0x668c, in 0x65b0), so rewriting it changes only the boot transition and
leaves every later "go back to the menu" post intact (photo/video still post
0x10D from 0x1d6fc / 0x1c644).

Usage:
    uv run scripts/patch_boot_mode.py [base.bin] [-o OUT.bin] [--mode 0x102]
Then build + validate the upgrade file:
    uv run scripts/build_upgrade_files.py OUT.bin
    uv run scripts/emu_updater.py --stage both <JH_5408*.bin>
"""
import argparse
import os
import struct
import sys

BASE = "charmera.bin"
DEFAULT_OUT = os.path.join("patched", "charmera_photo.bin")

POST_INSN = 0x6584          # ldr r1, [pc, #0x188]  (in 0x6578)
POST_INSN_WORD = 0xE59F1188
POST_LITERAL = 0x6714       # literal holdering the boot mode id
MENU_MODE = 0x10D           # "SELECT MODE" menu (stock boot target)
PHOTO_MODE = 0x102          # still capture


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("base", nargs="?", default=BASE, help=f"source flash image (default {BASE})")
    ap.add_argument("-o", "--out", default=DEFAULT_OUT, help=f"output image (default {DEFAULT_OUT})")
    ap.add_argument("--mode", default=hex(PHOTO_MODE),
                    help=f"mode id to boot into (default {hex(PHOTO_MODE)} = photo)")
    args = ap.parse_args()

    mode = int(args.mode, 0)
    if not 0 <= mode <= 0x1FF:
        ap.error(f"--mode must fit the dispatcher's 9-bit id field, got {mode:#x}")

    raw = bytearray(open(args.base, "rb").read())
    if POST_INSN + 4 > len(raw) or POST_LITERAL + 4 > len(raw):
        raise SystemExit(f"refusing to patch: {args.base} is too small for the boot site")

    insn = struct.unpack_from("<I", raw, POST_INSN)[0]
    if insn != POST_INSN_WORD:
        raise SystemExit(
            f"refusing to patch: expected {POST_INSN_WORD:#010x} (ldr r1,[pc,#0x188]) at "
            f"0x{POST_INSN:x}, found {insn:#010x} - wrong base image?")

    old = struct.unpack_from("<I", raw, POST_LITERAL)[0]
    if old != MENU_MODE:
        raise SystemExit(
            f"refusing to patch: expected the boot mode literal at 0x{POST_LITERAL:x} to be "
            f"{MENU_MODE:#x} (select menu), found {old:#x} - already patched?")

    struct.pack_into("<I", raw, POST_LITERAL, mode)

    out_dir = os.path.dirname(args.out)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    with open(args.out, "wb") as f:
        f.write(raw)

    print(f"{args.out}")
    print(f"  patched  : 0x{POST_LITERAL:x}  {old:#x} (menu) -> {mode:#x}", end="")
    if mode == PHOTO_MODE:
        print(" (photo)")
    else:
        print()
    print(f"  image    : {len(raw)} bytes (0x{len(raw):x}) from {args.base}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
