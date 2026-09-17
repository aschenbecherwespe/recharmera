#!/usr/bin/env python3
"""
Unicorn function-level emulation of the GPCV/CHARMERA SD-card upgrade gate.

Why
---
Every candidate upgrade costs an SD-card round trip and a battery pull.  Both
gates that accept/reject one are pure software and run from SPI flash bank 0 at
address == file offset, so the camera's own code can be executed under Unicorn
with the fatfs / flash-peripheral calls trapped.

The gate, as executed by the camera (see REVERSE_ENGINEERING_NOTES.md section 3)
------------------------------------------------------------------------------
    check_fn 0x21818   find-first("C:\\JH_5408*.bin", &filinfo, 0x77)
                       memcmp(filinfo.fname+7, "202505201029", 12)   (0x110BAD)
                       != 0 -> update available;  == 0 -> file ignored

    flasher  0x21370   parse 8 ASCII hex at filinfo.fname+0x14 (= fname[20..28))
                       open(filinfo.fname); read the WHOLE file in 64 KiB chunks
                       summing bytes mod 2^32; mismatch -> "Program error" hang
                       (abort byte at 0x110B88+0); match -> erase + program 1:1.

0x110B94 is the SDK's FILINFO, +0x12 is the filename buffer, so `desc+0x19` and
`desc+0x26` are filename characters - NOT upgrade-file offsets.  A valid file is
therefore a raw flash image plus a *name*:

    JH_5408<12-char version><1 free char><8 hex byte-sum>.bin

Memory map (boot-stub literals at 0x3E0 / 0x408 / 0x410):
    0x000000-0x0FFFFF  SPI flash bank 0, XIP  (file offsets 0x0-0xFFFFF)
    0x100000-0x1FFFFF  RAM; BSS zero-filled 0x10AF30..0x1AE750, SVC sp 0x1AE950
    0x02000000 / 0xC0000000 / 0xD0000000  MMIO (scratch-backed here)

Usage
    uv run scripts/emu_updater.py <image.bin> [--name NAME] [--trace]
    --name defaults to the canonical name for that image (version 202609101200
    plus its own byte-sum), which is what scripts/build_upgrade_files.py emits.
"""
import argparse
import struct
import sys

from unicorn import (
    Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_MODE_LITTLE_ENDIAN,
    UC_HOOK_CODE, UC_PROT_ALL, UcError,
)
from unicorn.arm_const import (
    UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3,
    UC_ARM_REG_R4, UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_CPSR,
)

# ------------------------------------------------------------------ memory map
FLASH_SIZE = 0x100000                       # bank 0
RAM_BASE, RAM_SIZE = 0x00100000, 0x00100000
MMIO = [(0x02000000, 0x10000), (0xC0000000, 0x10000), (0xD0000000, 0x10000)]
STACK_TOP = 0x001AF000
HEAP_BASE, HEAP_END = 0x001B0000, 0x001FF000

# --------------------------------------------------------------- updater ABI
CHECK_FN = 0x21818
FLASHER = 0x21370
FILINFO = 0x00110B94                  # literal 0x21734
FNAME_OFF = 0x12                      # filename inside FILINFO
SIZE_OFF = 0x02                       # size: u16 low / u16 high (0xE6A78/84)
SUM_CTX = 0x00110B88                  # +0 abort byte, +8 sum (literal 0x20E60)
VER_OFF, CKSUM_OFF = FNAME_OFF + 7, FNAME_OFF + 0x14      # fname[7] / fname[20]
VERSION_CONST = b"202505201029"       # at 0x218C4, compared by check_fn
NAME_PREFIX, NAME_SUFFIX = b"JH_5408", b".bin"
FREE_CHAR_OFF = FNAME_OFF + 19        # fname[19]: never read by the updater

WATCH = {
    0x214B8: "sum-compare",           # cmp r0, r4  (r0 = sum, r4 = parsed expected)
    0x214D0: "mismatch-flag",         # strb #1,[r8] -> "Program error" hang
    0x21890: "version-compare",       # cmp r0,#0 after memcmp(fname+7, const, 12)
    0x21874: "find-first-result",     # cmp r0,#0 : < 0 = no file found
}
RETURN_ADDR = 0x000000A0              # mapped flash, never executed by the updater

# SPI NOR geometry.  charmera.bin is a raw SOIC8 read, so CHIP_SIZE is the real
# device size and the whole 2 MiB is addressable.
CHIP_SIZE = 0x200000
PAGE = 0x100                          # program granularity (0x1CEC)
SECTOR = 0x10000                      # erase granularity (0x1D20, 64 KiB block)
# After the last data sector the flasher erases ONE MORE sector at
# (image_size + SECTOR) -- instruction 0x217B4 (`add r0, sl, #0x10000; bl 0x1d20`).
# That address must still be inside the chip: an out-of-range erase is decoded
# modulo the device capacity by the NOR, so it destroys a sector at the *start* of
# the flash instead of a no-op.  Hence the hard ceiling on the image size:
MAX_IMAGE = CHIP_SIZE - 2 * SECTOR    # 0x1E0000
WAIT_LOOP = 0x217D8                   # post-write loop (status already shown)
FLASH_OPS = {                         # reached only when the gate passed
    0x1D20: "sector-erase",
    0x1CEC: "sector-program",
    0x139C: "flash-write",
    0x06CC: "flash-verify",
}
NOOPS = {                             # display / beep / delay / progress / OS
    0x20AE4: "progress", 0x286A8: "power-off?", 0x30D54: "init?", 0x30EE8: "reset?",
    0x30FF4: "misc", 0x3017C: "flash-init?", 0x310FC: "poll?", 0x901F4: "beep",
    0x906E4: "delay",
}

# ARM->library veneers ("ldr ip,[pc]; bx ip").  Their literals do NOT resolve to
# coherent code in either ISA at the address they name (ARM and Thumb decodes are
# both mid-function; region entropy 6.1-6.8 vs 5.9 for known updater code), while
# the *direct* ARM calls next door (memcpy 0xDB5F0, bzero 0xDB594, uidiv 0xDB808)
# execute fine.  The primitives are therefore provided by the host, identified
# from unambiguous call sites.  Open question, see RE notes.
LIBC = {
    0xDECD8: "strlen", 0xDECF0: "memcpy", 0xDECFC: "memcmp",
    0xDECE4: "libc-unknown-1", 0xDED08: "libc-unknown-2", 0xDED14: "libc-unknown-3",
    0xDED20: "libc-unknown-4", 0xDED2C: "libc-unknown-5", 0xDED38: "libc-unknown-6",
    0xDED44: "libc-unknown-7", 0xDED50: "libc-unknown-8",
}


def byte_sum(data: bytes) -> int:
    return sum(data) & 0xFFFFFFFF


def canonical_name(data: bytes, version: bytes = b"202609101200") -> bytes:
    """JH_5408<version12><free><sum8>.bin - the name the updater accepts."""
    return (NAME_PREFIX + version + b"_" + b"%08X" % byte_sum(data) + NAME_SUFFIX)


class VFS:
    """Serves one candidate image for whatever path the firmware opens."""

    def __init__(self, data: bytes):
        self.data = data
        self.handles = {}
        self.next_fd = 3
        self.reads = []

    def open(self):
        fd = self.next_fd
        self.next_fd += 1
        self.handles[fd] = 0
        return fd

    def read(self, fd, length):
        if fd not in self.handles:
            return b""
        pos = self.handles[fd]
        chunk = self.data[pos:pos + length]
        self.handles[fd] = pos + len(chunk)
        self.reads.append((pos, length, len(chunk)))
        return chunk


class Emu:
    def __init__(self, fw: bytes, image: bytes, name: bytes, trace=False,
                 found: bool = True):
        self.uc = Uc(UC_ARCH_ARM, UC_MODE_ARM + UC_MODE_LITTLE_ENDIAN)
        self.uc.mem_map(0, FLASH_SIZE, UC_PROT_ALL)
        self.uc.mem_write(0, fw[:FLASH_SIZE].ljust(FLASH_SIZE, b"\xff"))
        self.uc.mem_map(RAM_BASE, RAM_SIZE, UC_PROT_ALL)
        for base, size in MMIO:
            self.uc.mem_map(base, size, UC_PROT_ALL)

        self.vfs = VFS(image)
        self.image = image
        self.fw = fw
        self.name = name
        self.found = found
        self.trace = trace
        self.heap = HEAP_BASE
        self.events = []
        self.stopped = None
        self.power_state = 0              # < 0x1F4 -> past check_fn's guard
        self.opened = None

        for addr, label in NOOPS.items():
            self.stub(addr, label, lambda uc, a=addr: 0)
        self.stub(0x908B8, "power-state", lambda uc: self.power_state)
        self.stub(0x744, "alloc", lambda uc: self._alloc(uc))
        self.stub(0xE2D40, "chdir", lambda uc: 0)
        for addr, name in LIBC.items():
            self.stub(addr, name, lambda uc, a=addr: self._libc(a))
        for addr, label in WATCH.items():
            self.watch(addr, label)

        def on_return(uc, address, size, user):
            uc.emu_stop()

        self.uc.hook_add(UC_HOOK_CODE, on_return, begin=RETURN_ADDR, end=RETURN_ADDR)

    # -------------------------------------------------------------- machinery
    def stub(self, addr, name, handler):
        def cb(uc, address, size, user):
            lr = uc.reg_read(UC_ARM_REG_LR)
            self.log(f"-> {name}")
            ret = handler(uc)
            if self.stopped:
                uc.emu_stop()
                return
            uc.reg_write(UC_ARM_REG_R0, (ret or 0) & 0xFFFFFFFF)
            uc.reg_write(UC_ARM_REG_PC, lr)

        self.uc.hook_add(UC_HOOK_CODE, cb, begin=addr, end=addr)

    def watch(self, addr, label):
        def cb(uc, address, size, user):
            self.observe(label, uc)
            if self.stopped:
                uc.emu_stop()

        self.uc.hook_add(UC_HOOK_CODE, cb, begin=addr, end=addr)

    def observe(self, label, uc):
        r = [uc.reg_read(x) for x in (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3)]
        if label == "sum-compare":
            expected = uc.reg_read(UC_ARM_REG_R4)          # cmp r0, r4
            self.events.append(("sum", r[0], expected))
            self.log(f"<- sum compare: computed=0x{r[0]:08X} expected=0x{expected:08X}")
        elif label == "mismatch-flag":
            self.events.append(("mismatch",))
            self.stopped = "GATE FAILED: byte-sum mismatch -> 'Program error' hang path"
            self.log("<- MISMATCH -> 'Program error' hang path")
        elif label == "version-compare":
            self.events.append(("version", r[0]))
            self.log(f"<- version compare memcmp()={r[0]} "
                     f"({'DIFFERS -> update' if r[0] else 'MATCHES -> ignored'})")
        elif label == "find-first-result":
            result = r[0] - 2**32 if r[0] >= 2**31 else r[0]
            self.events.append(("found", result))
            self.log(f"<- find-first returned {result} "
                     f"({'found' if result >= 0 else 'not found'})")

    def log(self, text):
        if self.trace:
            print("      " + text)

    # ----------------------------------------------------------- stub bodies
    def _flash_op(self, addr):
        self.stopped = f"GATE PASSED: reached {FLASH_OPS[addr]} (0x{addr:x}) - camera would flash"
        return 0

    def _alloc(self, uc):
        size = uc.reg_read(UC_ARM_REG_R0)
        p = (self.heap + 7) & ~7
        self.heap = p + size
        if self.heap > HEAP_END:
            raise RuntimeError("harness heap exhausted")
        return p

    def _libc(self, addr):
        name = LIBC[addr]
        r = [self.uc.reg_read(x) for x in (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2)]
        if name == "strlen":
            return len(self._cstr(r[0], 4096))
        if name == "memcpy":
            data = self.mem_read(r[1], r[2])
            self.mem_write(r[0], data)
            return r[0]
        if name == "memcmp":
            a, b = self.mem_read(r[0], r[2]), self.mem_read(r[1], r[2])
            return 0 if a == b else (-1 if a < b else 1)
        raise RuntimeError(f"unemulated library veneer {name} (0x{addr:x}) reached")

    # ------------------------------------------------------------- entrypoints
    def mem_read(self, addr, n):
        return bytes(self.uc.mem_read(addr, n))

    def mem_write(self, addr, data):
        self.uc.mem_write(addr, data)

    def run(self, addr, args=(), lr=RETURN_ADDR, count=20_000_000):
        uc = self.uc
        uc.reg_write(UC_ARM_REG_CPSR, 0x000000D3)
        uc.reg_write(UC_ARM_REG_SP, STACK_TOP)
        uc.reg_write(UC_ARM_REG_LR, lr)
        for reg, val in zip((UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3), args):
            uc.reg_write(reg, val)
        self.stopped = None
        try:
            uc.emu_start(addr, lr, count=count)
        except UcError as e:
            self.stopped = f"UcError: {e}"
        return uc.reg_read(UC_ARM_REG_R0)

    # ---------------------------------------------------------------- stages
    def _install_fileio(self):
        """fatfs calls the updater makes; find-first fills FILINFO with our name."""

        def find_first(uc):
            info = uc.reg_read(UC_ARM_REG_R1)
            if not self.found:
                self.log("find-first: nothing on the card matches C:\\JH_5408*.bin")
                return -1
            if not self._matches_pattern():
                self.log(f"find-first: {self.name!r} does not match C:\\JH_5408*.bin -> return -1")
                return -1
            name = self.name + b"\x00"
            self.mem_write(info + FNAME_OFF, name)
            self.mem_write(info + SIZE_OFF, struct.pack("<HH", len(self.image) & 0xFFFF,
                                                        (len(self.image) >> 16) & 0xFFFF))
            self.mem_write(info, b"\x00")              # attribute: regular file
            return 0

        def find_close(uc):
            return 0

        def f_open(uc):
            self.opened = self._cstr(uc.reg_read(UC_ARM_REG_R0))
            return self.vfs.open()

        def f_size(uc):
            fd, out = uc.reg_read(UC_ARM_REG_R0), uc.reg_read(UC_ARM_REG_R1)
            if fd not in self.vfs.handles:
                return -1
            self.mem_write(out + 4, struct.pack("<I", len(self.vfs.data)))
            return 0

        def f_seek(uc):
            self.vfs.handles[uc.reg_read(UC_ARM_REG_R0)] = uc.reg_read(UC_ARM_REG_R1)
            return 0

        def f_read(uc):
            fd, buf, n = (uc.reg_read(x) for x in (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2))
            chunk = self.vfs.read(fd, n)
            self.mem_write(buf, chunk)
            return len(chunk)

        for addr, name, fn in (
            (0xE2EF0, "find-first", find_first), (0xE2E54, "find-close/f_close", find_close),
            (0xE33BC, "f_open", f_open), (0xE2FC8, "f_stat", f_size),
            (0xE32F4, "f_seek", f_seek), (0xE341C, "f_read", f_read),
        ):
            self.stub(addr, name, fn)

    def _matches_pattern(self):
        """The updater's find-first pattern is C:\\JH_5408*.bin (built at 0x2182C)."""
        n = self.name.upper()
        return n.startswith(NAME_PREFIX) and n.endswith(NAME_SUFFIX.upper())

    def stage_check(self):
        self._install_fileio()
        ret = self.run(CHECK_FN)
        verdict = {1: "UPDATE AVAILABLE (version differs)",
                   0: "IGNORED (version matches, or no file found)"}[ret]
        return {"ret": ret, "verdict": verdict, "log": list(self.events)}

    def stage_flash(self):
        self._install_fileio()
        self._install_flash_stops()
        self.mem_write(FILINFO, b"\x00" * 0x60)
        self.mem_write(FILINFO + FNAME_OFF, self.name + b"\x00")
        self.mem_write(FILINFO + SIZE_OFF, struct.pack("<HH", len(self.image) & 0xFFFF,
                                                       (len(self.image) >> 16) & 0xFFFF))
        self.mem_write(SUM_CTX, b"\x00" * 16)
        ret = self.run(FLASHER)
        sums = [e for e in self.events if e[0] == "sum"]
        computed, expected = (sums[-1][1], sums[-1][2]) if sums else (None, None)
        return {"ret": ret, "computed": computed, "expected": expected,
                "reads": self.vfs.reads, "opened": self.opened, "stopped": self.stopped}

    def _install_flash_stops(self):
        for addr, label in FLASH_OPS.items():
            self.stub(addr, label, lambda uc, a=addr: self._flash_op(a))

    def stage_write(self):
        """Replay the ENTIRE erase/program/verify sequence against a modelled chip.

        This is what stage_flash deliberately does not do (it stops at the first
        erase): the write tail is where a full-size image goes wrong, because of
        the extra sector erase at image_size + SECTOR.
        """
        device = bytearray(self.fw[:CHIP_SIZE].ljust(CHIP_SIZE, b"\xff"))
        erases, progs, reads = [], [], []

        def erase(uc):
            addr = uc.reg_read(UC_ARM_REG_R0)
            erases.append(addr)
            if addr + SECTOR <= CHIP_SIZE:
                device[addr:addr + SECTOR] = b"\xff" * SECTOR
            return 0

        def program(uc):
            addr, src = uc.reg_read(UC_ARM_REG_R0), uc.reg_read(UC_ARM_REG_R1)
            progs.append(addr)
            if addr + PAGE <= CHIP_SIZE:
                device[addr:addr + PAGE] = self.mem_read(src, PAGE)
            return 0

        def read(uc):
            addr, dst = uc.reg_read(UC_ARM_REG_R0), uc.reg_read(UC_ARM_REG_R1)
            reads.append(addr)
            self.mem_write(dst, bytes(device[addr:addr + PAGE]))
            return 0

        self._install_fileio()
        self.stub(0x1D20, "sector-erase", erase)
        self.stub(0x1CEC, "page-program", program)
        self.stub(0x139C, "page-read", read)
        self.mem_write(FILINFO, b"\x00" * 0x60)
        self.mem_write(FILINFO + FNAME_OFF, self.name + b"\x00")
        self.mem_write(FILINFO + SIZE_OFF, struct.pack("<HH", len(self.image) & 0xFFFF,
                                                       (len(self.image) >> 16) & 0xFFFF))
        self.mem_write(SUM_CTX, b"\x00" * 16)

        def stop_at_wait(uc, address, size, user):
            uc.emu_stop()

        self.uc.hook_add(UC_HOOK_CODE, stop_at_wait, begin=WAIT_LOOP, end=WAIT_LOOP)
        self.run(FLASHER, count=2_000_000_000)

        trailing = erases[-1] if erases else None
        alias = None if trailing is None else trailing % CHIP_SIZE
        return {
            "erases": erases, "programs": progs, "reads": reads,
            "trailing": trailing, "alias": alias,
            "in_range": trailing is not None and trailing + SECTOR <= CHIP_SIZE,
            "stopped": self.stopped,
        }

    def _cstr(self, addr, limit=300):
        try:
            raw = self.mem_read(addr, limit)
        except UcError:
            return "<unmapped>"
        return raw.split(b"\x00")[0].decode("latin-1", "replace")


def _hex(v):
    return "None" if v is None else "0x%08X" % v


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("image", help="candidate upgrade image (raw flash image)")
    ap.add_argument("--name", help="SD filename to evaluate (default: canonical name)")
    ap.add_argument("--fw", default="charmera.bin", help="firmware dump holding the updater code")
    ap.add_argument("--not-found", action="store_true", help="simulate find-first finding nothing")
    ap.add_argument("--stage", choices=("check", "flash", "write", "both"), default="both")
    ap.add_argument("--trace", action="store_true")
    args = ap.parse_args()

    fw = open(args.fw, "rb").read()
    image = open(args.image, "rb").read()
    name = args.name.encode() if args.name else canonical_name(image)

    print(f"fw={args.fw} ({len(fw)} B)   image={args.image} ({len(image)} B)")
    print(f"name={name.decode()!r}  ({len(name)} chars)")

    if args.stage in ("check", "both"):
        emu = Emu(fw, image, name, args.trace, found=not args.not_found)
        r = emu.stage_check()
        found = [e for e in r["log"] if e[0] == "found"]
        detail = ("nothing on the card matched C:\\JH_5408*.bin" if args.not_found
                  else "matched" if not found or found[-1][1] >= 0 else
                  "file name does not match C:\\JH_5408*.bin")
        print(f"[check] find-first  : {detail}")
        print(f"[check] name fields : fname[7:19]={name[7:19]!r} vs installed {VERSION_CONST!r}")
        print(f"[check] check_fn()  : {r['ret']}  -> {r['verdict']}")

    if args.stage in ("flash", "both"):
        emu = Emu(fw, image, name, args.trace, found=not args.not_found)
        r = emu.stage_flash()
        reads = r["reads"]
        chunks = [x for x in reads if x[2]]
        span = (f"0x0..{max(p + n for p, _, n in chunks):#x} in {len(chunks)} chunk(s)"
                if chunks else "none")
        print(f"[flash] opened as   : {r['opened']!r}")
        print(f"[flash] expected    : {_hex(r['expected'])}  (parsed from fname[20:28]={name[20:28]!r})")
        print(f"[flash] computed sum: {_hex(r['computed'])}  (camera's own loop)")
        print(f"[flash] bytes summed: {span}")
        print(f"[flash] outcome     : {r['stopped'] or 'ran to completion'}")
        if r["expected"] is not None and r["computed"] is not None:
            d = (r["computed"] - r["expected"] + 2**31) % 2**32 - 2**31
            print(f"[flash] gate        : {'PASS' if d == 0 else 'FAIL'}  (delta {d:+d})")

    if args.stage in ("write", "both"):
        emu = Emu(fw, image, name, args.trace, found=not args.not_found)
        r = emu.stage_write()
        er, pr = r["erases"], r["programs"]
        span = f"0x0..0x{max(pr) + PAGE:x}" if pr else "none"
        print(f"[write] image size  : {len(image)} bytes (0x{len(image):x})"
              f"   safe maximum: 0x{MAX_IMAGE:x} ({MAX_IMAGE} bytes)")
        print(f"[write] sectors     : {len(er)} erase(s), {len(pr)} page program(s) over {span}")
        print(f"[write] last sector : 0x{r['trailing']:x}  (image size + 0x{SECTOR:x})"
              if r["trailing"] is not None else "[write] last sector : none")
        if r["trailing"] is not None and not r["in_range"]:
            print(f"[write] *** OUT OF RANGE *** the chip is 0x{CHIP_SIZE:x} bytes; an erase at "
                  f"0x{r['trailing']:x} is decoded modulo capacity -> it wipes the sector at "
                  f"0x{r['alias']:x}")
        elif r["trailing"] is not None:
            print(f"[write] range check : OK (erase ends at 0x{r['trailing'] + SECTOR:x} "
                  f"<= 0x{CHIP_SIZE:x})")
        if len(image) > MAX_IMAGE:
            print(f"[write] VERDICT     : image too large - use scripts/build_upgrade_files.py "
                  f"to size it correctly")
        else:
            print(f"[write] VERDICT     : {'flash sequence in range' if r['in_range'] else 'UNSAFE'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
