#!/usr/bin/env python3
"""
Recursive ARM disassembler + cross-reference map for the GPCV dump.

Linear disassembly desyncs on this image (data islands mid-code), so this walks
the binary recursively from real entry points and builds a code/xref map that
`arm_disasm.py` cannot give you.

Address model (measured; see REVERSE_ENGINEERING_NOTES.md section 10.1)
---------------------------------------------------------------------
CPU address = file offset - 0x200.  The vector table sits at file 0x200 and its
literal pool holds *CPU* addresses, so the reset stub is at file 0x23c.  Hence:

  * `bl`/`b`/`ldr pc,[...]` targets from capstone are FILE offsets (pc-relative,
    and both pc and target shift by the same 0x200).
  * literal-pool words are CPU addresses: a flash pointer is `file = value + 0x200`
    (only followed when `value < 0x100000`; 0x100000+ is RAM/MMIO, not code).
  * `add rx, pc, #imm` string/table refs are FILE offsets directly.

Seed set: the reset vector plus every `stmfd sp!,{...,lr}` prologue in the image.
On charmera.bin that reaches ~194k instructions / ~4.5k functions / ~16.7k calls,
covering the RTOS, wifi, updater and app/UI layers.

Usage
-----
    .venv/bin/python scripts/find_xrefs.py                  # summary
    .venv/bin/python scripts/find_xrefs.py --callers 0x14054
    .venv/bin/python scripts/find_xrefs.py --refs 0x10fbc5
    .venv/bin/python scripts/find_xrefs.py --disasm 0x1617c [LEN]
    .venv/bin/python scripts/find_xrefs.py --funcs [--in 0x14000-0x1e000]
    .venv/bin/python scripts/find_xrefs.py --strings 0x1617c   # literals in a func

Options --dump FILE / --base N exist for other dumps; defaults match charmera.bin.
"""
import argparse
import bisect
import struct
import sys
from collections import defaultdict

try:
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN
    from capstone.arm import ARM_OP_IMM, ARM_OP_MEM, ARM_REG_PC
except ImportError:
    print("pip install capstone  (use the project venv)")
    sys.exit(1)

CONDS = {'eq', 'ne', 'cs', 'hs', 'cc', 'lo', 'mi', 'pl', 'vs', 'vc',
         'hi', 'ls', 'ge', 'lt', 'gt', 'le', 'al'}


def split_branch(mnem):
    """Classify a branch-like mnemonic -> (base, cond) or None.

    `blne`, `bleq` … are conditional *calls* (they fall through when not taken)
    and were previously mis-handled as unconditional branches, which silently
    truncated large functions (e.g. the app handler at 0x1d6fc).
    """
    for base in ('blx', 'bl', 'bx', 'b'):
        if mnem.startswith(base):
            rest = mnem[len(base):]
            if rest == '' or rest in CONDS:
                return base, rest
            return None
    return None


class Analyzer:
    def __init__(self, data, base_shift=0x200):
        self.fw = data
        self.shift = base_shift
        self.md = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)
        self.md.detail = True
        self.code = {}                                 # addr -> CsInsn
        self.funcs = set()
        self.calls = defaultdict(list)                 # target -> [(site, kind)]
        self.refs = defaultdict(list)                  # FILE target -> [(site, kind)]
        self._ran = False

    # -- helpers -----------------------------------------------------------
    def to_file(self, cpu):
        """Literal-pool word (CPU addr) -> file offset, or None if not code."""
        if 0 <= cpu < self.shift + 0x100000:
            return cpu + self.shift
        return None

    @staticmethod
    def _branch_target(ins):
        for op in ins.operands:
            if op.type == ARM_OP_IMM:
                return op.imm
        return None

    def prologues(self):
        """Every `stmfd sp!,{...,lr}` (0xE92Dxxxx with lr in the list)."""
        out = []
        for i in range(self.shift, len(self.fw) - 4, 4):
            w = struct.unpack('<I', self.fw[i:i + 4])[0]
            if (w & 0xFFFF0000) == 0xE92D0000 and (w & 0x4000):
                out.append(i)
        return out

    # -- pass --------------------------------------------------------------
    def run(self):
        if self._ran:
            return self
        fw, md = self.fw, self.md
        seeds = self.prologues() + [self.shift, self.shift + 0x3c]
        self.funcs.update(seeds)
        work = list(seeds)
        seen = set()

        while work:
            a = work.pop()
            while True:
                if a in seen or a + 4 > len(fw):
                    break
                ins = next(md.disasm(fw[a:a + 4], a), None)
                if ins is None:
                    break
                seen.add(a)
                self.code[a] = ins
                mnem, ops = ins.mnemonic, ins.op_str

                # pc-relative pool / string references
                for op in ins.operands:
                    if op.type == ARM_OP_MEM and op.mem.base == ARM_REG_PC:
                        p = a + 8 + op.mem.disp
                        if 0 <= p + 4 <= len(fw):
                            val = struct.unpack('<I', fw[p:p + 4])[0]
                            self.refs[val].append((a, 'pool'))
                if mnem in ('add', 'sub', 'adr') and 'pc' in ops and '#' in ops:
                    try:
                        imm = int(ops.split('#')[-1], 0)
                    except ValueError:
                        imm = None
                    if imm is not None:
                        tgt = a + 8 + imm if mnem != 'sub' else a + 8 - imm
                        self.refs[tgt].append((a, 'adr'))

                br = split_branch(mnem)
                if br is not None:
                    base, cond = br
                    if base in ('bl', 'blx'):
                        t = self._branch_target(ins)
                        if t is not None and 0 <= t < len(fw):
                            self.calls[t].append((a, 'call'))
                            self.funcs.add(t)
                            work.append(t)
                        a += 4                      # conditional calls fall through
                        continue
                    if base == 'bx':                # register branch: unresolvable
                        break
                    t = self._branch_target(ins)
                    if t is not None and 0 <= t < len(fw):
                        self.calls[t].append((a, 'jmp'))
                        work.append(t)
                        if cond == '':              # unconditional `b`
                            break
                    a += 4
                    continue

                # ARM switch tables — the app code is full of these and they are
                # the main source of missed functions:
                #   add<cond> pc, pc, rX, lsl #2   -> inline table of `b` stubs
                #   ldr<cond> pc, [pc, rX, lsl #2] -> table of code pointers
                nops = ops.replace(' ', '')
                if mnem.startswith('add') and nops.startswith('pc,pc,') and 'lsl#2' in nops:
                    base = a + 8
                    for k in range(128):
                        p = base + 4 * k
                        if p + 4 > len(fw):
                            break
                        w = struct.unpack('<I', fw[p:p + 4])[0]
                        if (w & 0x0F000000) != 0x0A000000:      # not a `b`
                            break
                        imm24 = w & 0xFFFFFF
                        if imm24 & 0x800000:
                            imm24 -= 0x1000000
                        t = p + 8 + imm24 * 4
                        if 0 <= t < len(fw):
                            self.calls[t].append((p, 'case'))
                            work.append(t)
                    a += 4
                    continue
                if mnem.startswith('ldr') and nops.startswith('pc,[pc,') and 'lsl#2' in nops:
                    base = a + 8
                    for k in range(128):
                        p = base + 4 * k
                        if p + 4 > len(fw):
                            break
                        val = struct.unpack('<I', fw[p:p + 4])[0]
                        tf = self.to_file(val)
                        if tf is None:
                            break
                        self.calls[tf].append((p, 'case'))
                        self.funcs.add(tf)
                        work.append(tf)
                    a += 4
                    continue

                if mnem == 'ldr' and ops.startswith('pc,'):
                    for op in ins.operands:
                        if op.type == ARM_OP_MEM and op.mem.base == ARM_REG_PC:
                            p = a + 8 + op.mem.disp
                            val = struct.unpack('<I', fw[p:p + 4])[0]
                            self.calls[val].append((a, 'tail'))
                            self.funcs.add(val)
                            tf = self.to_file(val)
                            if tf is not None:
                                work.append(tf)
                    break

                if mnem == 'mov' and ops.replace(' ', '').startswith('pc,'):
                    break
                if mnem == 'pop' and 'pc' in ops:
                    break
                a += 4

        self._ran = True
        return self

    # -- queries -----------------------------------------------------------
    def func_of(self, addr):
        starts = sorted(self.funcs)
        i = bisect.bisect_right(starts, addr) - 1
        return starts[i] if i >= 0 else None

    def extent(self, func):
        starts = sorted(self.funcs)
        i = bisect.bisect_right(starts, func)
        return starts[i] if i < len(starts) else len(self.fw)

    def callers(self, target):
        return self.calls.get(target, [])

    def string_at(self, addr, n=40):
        if not (0 <= addr < len(self.fw)):
            return None
        raw = self.fw[addr:addr + n].split(b'\x00')[0]
        if len(raw) >= 3 and all(32 <= c < 127 for c in raw):
            return raw.decode()
        return None

    def literals(self, func):
        """pc-relative refs made from inside `func`, with any printable text."""
        lo, hi = func, self.extent(func)
        out = []
        for tgt, sites in self.refs.items():
            for site, kind in sites:
                if lo <= site < hi:
                    out.append((site, kind, tgt, self.string_at(tgt)))
        return sorted(out)


def parse_range(text):
    if '-' in text:
        a, b = text.split('-', 1)
        return int(a, 0), int(b, 0)
    v = int(text, 0)
    return v, v + 0x1000


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('dump', nargs='?', default='charmera.bin')
    ap.add_argument('--base', type=lambda s: int(s, 0), default=0x200,
                    help='code base shift; file = cpu + base (default 0x200)')
    ap.add_argument('--callers', type=lambda s: int(s, 0), metavar='ADDR')
    ap.add_argument('--refs', type=lambda s: int(s, 0), metavar='ADDR',
                    help='all pc-relative refs to a FILE address (incl. RAM globals)')
    ap.add_argument('--disasm', type=lambda s: int(s, 0), metavar='ADDR')
    ap.add_argument('--len', type=lambda s: int(s, 0), default=0x100)
    ap.add_argument('--funcs', action='store_true')
    ap.add_argument('--in', dest='within', metavar='LO-HI')
    ap.add_argument('--strings', type=lambda s: int(s, 0), metavar='FUNC',
                    help='pc-relative literals referenced from a function')
    args = ap.parse_args()

    with open(args.dump, 'rb') as fh:
        fw = fh.read()
    an = Analyzer(fw, base_shift=args.base).run()

    if args.callers is not None:
        rows = an.callers(args.callers)
        print(f'{len(rows)} caller(s) of {args.callers:#x}')
        for site, kind in sorted(rows):
            print(f'  {site:#07x}  {kind:5s}  in func {an.func_of(site):#07x}')
        return 0

    if args.refs is not None:
        rows = an.refs.get(args.refs, [])
        print(f'{len(rows)} pc-relative ref(s) to {args.refs:#x}'
              + (f'  "{an.string_at(args.refs)}"' if an.string_at(args.refs) else ''))
        for site, kind in sorted(rows):
            print(f'  {site:#07x}  {kind:5s}  in func {an.func_of(site):#07x}')
        return 0

    if args.disasm is not None:
        start, end = args.disasm, args.disasm + args.len
        for ins in an.md.disasm(fw[start:end], start):
            extra = ''
            for op in ins.operands:
                if op.type == ARM_OP_MEM and op.mem.base == ARM_REG_PC:
                    p = ins.address + 8 + op.mem.disp
                    if 0 <= p + 4 <= len(fw):
                        extra += f'   ; pool={struct.unpack("<I", fw[p:p + 4])[0]:#x}'
            if ins.mnemonic in ('add', 'sub', 'adr') and 'pc' in ins.op_str and '#' in ins.op_str:
                try:
                    imm = int(ins.op_str.split('#')[-1], 0)
                except ValueError:
                    imm = None
                if imm is not None:
                    tgt = ins.address + 8 + imm if ins.mnemonic != 'sub' else ins.address + 8 - imm
                    s = an.string_at(tgt)
                    if s:
                        extra += f'   ; "{s}"'
            print(f'{ins.address:07x}: {ins.mnemonic:8s} {ins.op_str}{extra}')
        return 0

    if args.funcs:
        lo, hi = parse_range(args.within) if args.within else (0, len(fw))
        fs = sorted(f for f in an.funcs if lo <= f < hi)
        print(f'{len(fs)} function(s) in {lo:#x}..{hi:#x}')
        for f in fs:
            print(f'  {f:#07x}')
        return 0

    if args.strings is not None:
        for site, kind, tgt, s in an.literals(args.strings):
            note = f'"{s}"' if s else ''
            print(f'  {site:#07x}  {kind:5s}  {tgt:#07x}  {note}')
        return 0

    print(f'dump          : {args.dump} ({len(fw)} bytes, base +{args.base:#x})')
    print(f'instructions  : {len(an.code)}')
    print(f'functions     : {len(an.funcs)}')
    print(f'call targets  : {len(an.calls)}')
    print(f'ref targets   : {len(an.refs)}')
    print('queries       : --callers / --refs / --disasm / --funcs / --strings')
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except BrokenPipeError:          # e.g. `| head`
        import os
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        raise SystemExit(0)
