#!/usr/bin/env python3
"""
ARM disassembly helper for the GPCV dump (code runs XIP from flash at address 0).

Requires: the project env (one-off `uv sync`; `uv run` keeps it in step)

Usage:
    uv run scripts/arm_disasm.py charmera.bin 0x21818 0x80
    uv run scripts/arm_disasm.py charmera.bin 0x21370 0x100 --strings
"""
import struct
import sys

try:
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN
except ImportError:
    print("capstone missing - run: uv sync")
    sys.exit(1)

from capstone.arm import *  # noqa


def ror(v, r):
    r %= 32
    return ((v >> r) | (v << (32 - r))) & 0xFFFFFFFF if r else v


def add_pc_target(ins, raw, data):
    """For `add rd, pc, #imm` (ARM), return the runtime target (file offset, base-0)."""
    if (raw >> 26) != 0b00:
        return None
    opcode = (raw >> 21) & 0xF
    rn = (raw >> 16) & 0xF
    if rn != 15:  # must be PC
        return None
    I = (raw >> 25) & 1
    if I:
        imm = ror(raw & 0xFF, ((raw >> 8) & 0xF) * 2)
    else:
        imm = raw & 0xFFF
    if opcode == 0b0100:
        return ins.address + 8 + imm
    if opcode == 0b0010:
        return ins.address + 8 - imm
    return None


def main():
    if len(sys.argv) < 4:
        print(__doc__)
        sys.exit(1)
    fw = open(sys.argv[1], "rb").read()
    start = int(sys.argv[2], 0)
    length = int(sys.argv[3], 0)
    show_strings = "--strings" in sys.argv

    md = Cs(CS_ARCH_ARM, CS_MODE_ARM + CS_MODE_LITTLE_ENDIAN)
    for ins in md.disasm(fw[start:start + length], start):
        raw = struct.unpack("<I", fw[ins.address:ins.address + 4])[0]
        extra = ""
        if show_strings:
            t = add_pc_target(ins, raw, fw)
            if t is not None and t < len(fw):
                s = fw[t:t + 24].split(b"\x00")[0]
                if 3 <= len(s) <= 24:
                    extra = f'   ; "{s.decode(errors="replace")}"'
            if ins.mnemonic == "ldr" and "[pc" in ins.op_str:
                imm12 = raw & 0xFFF
                U = (raw >> 23) & 1
                p = ins.address + 8 + (imm12 if U else -imm12)
                if 0 <= p + 4 <= len(fw):
                    v = struct.unpack("<I", fw[p:p + 4])[0]
                    if 0x20000 <= v < 0x30000:
                        s = fw[v:v + 24].split(b"\x00")[0]
                        if s:
                            extra = f'   ; pool->0x{v:05x} "{s.decode(errors="replace")}"'
        print(f"0x{ins.address:05x}: {ins.mnemonic:8s} {ins.op_str}{extra}")


if __name__ == "__main__":
    main()
