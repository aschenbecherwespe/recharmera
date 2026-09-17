#!/usr/bin/env python3
"""
Carve JPEGs out of a GPCV/Generalplus flash dump.

Two classes of hit are reported, and they must not be confused:

  complete     SOI..SOF..DHT..SOS + entropy data + EOI -> real pixels
  header-only  SOI..SOS and then non-entropy bytes     -> a bare 'GPEncoder' header
               template left in the image, zero pixels

Usage:
    uv run scripts/carve_jpegs.py charmera.bin [outdir]

Default outdir `carved/`; complete files go to `carved/`, header-only stubs to
`carved/partial/`. Header strings (EXIF Make/Model/DateTime, COM) are printed so a
stock SDK template ("DSC Turnkey", 2012) can be told apart from a camera-written
capture.
"""
import os
import re
import sys

SOI = b"\xff\xd8\xff"
SOF = {0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF}


def walk(data, off):
    """Walk markers from SOI. Return (dims, sos_end, eoi) — None for what is absent.

    dims: (width, height) from the first SOF; sos_end: offset just past the SOS
    segment (start of entropy data); eoi: (start, end) of the EOI marker.
    """
    i = off + 2
    dims = None
    sos_end = None
    while i < len(data) - 1:
        if data[i] != 0xFF:
            return dims, sos_end, None
        j = i
        while data[j] == 0xFF:
            j += 1
        m = data[j]
        if m == 0xD9:
            return dims, sos_end, (i, j + 1)
        if m == 0xD8 or 0xD0 <= m <= 0xD7:
            i = j + 1
            continue
        seglen = int.from_bytes(data[j + 1:j + 3], "big")
        if m in SOF:
            dims = (int.from_bytes(data[j + 6:j + 8], "big"),
                    int.from_bytes(data[j + 4:j + 6], "big"))
        if m == 0xDA:  # SOS: entropy-coded data follows
            k = j + 1 + seglen
            sos_end = k
            while k < len(data) - 1:
                if data[k] == 0xFF:
                    n = data[k + 1]
                    if n == 0x00 or 0xD0 <= n <= 0xD7:  # stuffing / restart marker
                        k += 2
                        continue
                    return dims, sos_end, (k, k + 2) if n == 0xD9 else None
                k += 1
            return dims, sos_end, None
        i = j + 1 + seglen
    return dims, sos_end, None


def header_strings(data, off, end):
    out = []
    for m in re.finditer(rb"[ -~]{8,}", data[off:end]):
        s = m.group().decode()
        if s.strip():
            out.append(s.strip())
    return out


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    fw = open(sys.argv[1], "rb").read()
    outdir = sys.argv[2] if len(sys.argv) > 2 else "carved"
    full = os.path.join(outdir, "")
    part = os.path.join(outdir, "partial")
    os.makedirs(full, exist_ok=True)
    os.makedirs(part, exist_ok=True)

    n_full = n_part = 0
    for m in re.finditer(re.escape(SOI), fw):
        off = m.start()
        dims, sos_end, eoi = walk(fw, off)
        if dims is None:  # SOI/EOI byte pair inside other data, not a frame
            continue
        size = f"{dims[0]}x{dims[1]}"
        strings = ", ".join(header_strings(fw, off, sos_end or off + 0x400))
        if eoi is None or sos_end is None:
            blob = fw[off:sos_end] if sos_end else fw[off:off + 0x400]
            path = os.path.join(part, f"{off:06x}_{size}_header_only.jpg")
            n_part += 1
            print(f"{off:#08x}  HEADER-ONLY  {size:>9}  {len(blob):5d} B  -> {path}")
        else:
            blob = fw[off:eoi[1]]
            path = os.path.join(full, f"{off:06x}_{size}.jpg")
            n_full += 1
            print(f"{off:#08x}  complete     {size:>9}  {len(blob):5d} B  -> {path}")
        if strings:
            print(f"            strings: {strings}")
        with open(path, "wb") as fh:
            fh.write(blob)

    print(f"\n{n_full} complete, {n_part} header-only "
          f"(no pixels) in {outdir}/, {outdir}/partial/")


if __name__ == "__main__":
    main()
