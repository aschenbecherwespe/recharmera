# CHARMERA (KODAK CHARMERA / Generalplus GPCV) Firmware Reverse Engineering Notes

> Working notes on `charmera.bin` — a 2 MiB SPI flash dump from a KODAK CHARMERA toy/action camera.
> Goal: build a valid SD-card firmware upgrade file (`C:\JH_5408*.bin`) so we can flash custom firmware without a CH341A programmer.

---

## 1. Device Identity

| Property | Value | Evidence |
|---|---|---|
| SoC family | **Generalplus GPCV** (SuperCamera) | SDK path `F:\gp15\GPCV1235F_WIFI_SingleCam_SDK_20191212\...` in strings |
| CPU | **ARM** (32-bit A32) | reset vector `0x200`: `ldr pc,[pc,#0x18]`; `0x23c: e32ff0d3` = `MSR CPSR_c,#0xD3` |
| OS | Bare-metal proprietary RTOS (MicroC) + lwIP 1.4.0 | strings `...\MicroC\rtos.c`, `lwip-1.4.0` |
| Camera model | **WH5408 / JH5408** | strings `JH5408  20250520`, `D.WH5408`; build path `G:\code\2247\5408\v006` |
| WiFi | SSV6158/SSV6020 (companion chip) | `GPCV1235F_WIFI_SingleCam_SDK`, `ssv6xxx_chip_init` |
| Firmware build | `202505201029` | version token in upgrade code |
| Flash size | **2 MiB (0x200000)** | file size; matches `W25Q16`-class SPI NOR |
| Flash format | **`SPII`** container | magic at offset 0 (LE: `SPII`) |

### Note
The bundled `charmera.bin.png` (2048×1228) is a *user-created analysis artifact*, NOT a file inside the firmware.

---

## 2. Firmware Layout / Region Map

| Offset | Contents |
|---|---|
| `0x000000` – `0x0001FF` | `SPII` header + descriptor table (`SPII`, `SRIy` tags), boot vector that reads it minimally |
| `0x000200` | ARM reset vector (`ldr pc,[pc,#0x18]`), boot stub |
| `0x000200` – `0x0F5XXX` | Core firmware code (RTOS, lwIP, WiFi, camera app), runs **XIP from flash (address 0)** |
| `0x0F6000`+ | Code/data continues (string table areas, font/geom tables) |
| `0x100000` – `0x10B12C` | Encoder/parser tables + 4 header-only `GPEncoder` JPEG stubs (§9) |
| `0x10B12D` – `0x11FFFF` | zero-filled (0x00) — *not* erased flash, so a real write happened here |
| `0x120000` | **`GP+` UI resource filesystem** (name→ID index + sector-aligned asset data, §9.4) |
| `0x120600` – `0x168E99` | GPZP-compressed UI images / JPG / WAV assets (42 files extracted to `assets/`) |
| `0x168E9A` – `0x16FFFF` | erased `0xFF` |
| `0x170000` – `0x1717FF` | **GPNV non-volatile records** — 12× `0x200` slots, CRC-32'd (§11) |
| `0x171800` – `0x17EFFF` | erased `0xFF` — spare GPNV ring slots |
| `0x17F000` – `0x17F1FF` | **internal photo-store index** — `(u32 slot, u32 size)` LE entries (§11.4) |
| `0x17F200` – `0x17FFFF` | erased `0xFF` |
| `0x180000` – … | **internal photo store** (`C:\SPIDCIM\SPI%02d.jpg`) — GPEncoder 960×720 JPEGs, one per slot (§9.1, §11.4) |

### Boot behavior (verified by disassembly)
- Boot stub (`0x200`–`0x800`): register setup (`0xD0100038`, `0xD03000xx`, `0xD05001fc`, `0xD07023c0`), zero-fills RAM `0x10AF30` (len `0xA3820`).
- Firmware executes **in place from flash** (XIP at address 0). RAM globals live at ~`0x110000+`.
- **Boot ROM does NOT read offset `0x19`** — the header region `0x00..0x200` is only touched by the *updater itself*. Patching `+0x19` does not affect boot.

---

## 3. SD-Card Upgrade Mechanism (the key target)

### Trigger file
- Path pattern built as: `"C:\JH_" + "5408" + "*.bin"` → **`C:\JH_5408*.bin`** (SD card root, no subfolder).
- Concretely: file named `JH_5408.bin` (or anything starting `JH_5408`, ending `.bin`) at the **root** of a FAT32 SD card.

### Firmware functions (ARM, file offsets)
- `0x21818` — **`check_fn()`**: the "is there an update?" gate.
- `0x21370` — **`flasher()`**: opens file, validates, erases+writes flash in 0x400-byte sectors.
- `0x216d4` — the **erase/program loop** entry (invoked from the state-machine drawer).
- `0x2117c` — string `"check file"`; `0x20e7c` — `"Program error"`; `0x20e90` — `"not poweroff"`; `0x20e38` — `"Upgrade     "`; `0x20e48` — `"%s%3d%%"` (progress).

### `check_fn()` (0x21818) — confirmed semantics
```
if (power_state > 0x1f4) return 0;             // "not poweroff" guard (0x908b8)
pattern = "C:\JH_5408*.bin";                   // built on the stack (0x2182C..0x2185C)
if (find_first(pattern, &FILINFO, 0x77) < 0)   // 0xE2EF0; FILINFO = RAM 0x110B94
    return 0;                                  // nothing matching on the card
if (memcmp(FILINFO.fname + 7, "202505201029", 12) != 0)
    return 1;    // version DIFFERS  -> "there's an update"   -> PROCEED
else
    return 0;    // version MATCHES  -> "already current"     -> IGNORE
```
> **KEY — corrected 2026-09:** `0x110B94` is the SDK's **FILINFO** (directory-search
> result), and `+0x12` is the *filename* buffer. The two fields the updater reads are
> therefore `fname[7..19]` (version) and `fname[20..28]` (byte-sum) — **characters of the
> SD filename, not offsets inside the file**. `0xE693C` writes the matched name to
> `arg+0x12` (`add r0,r0,#0x12` @0xE6944, copy @0xE6A04); the sibling enumerators for
> `*.jpg` (0x5B44) and `*.avi` (0x70A18) read their name at `buf+0x12` too.
> The earlier "file offset 0x19 / 0x26" model (and the `JH5408_v*`/`v[CDE]_*` files built
> from it) is **refuted** — those files patch bytes inside the image, which the updater
> never inspects, and flashing them would write a corrupted header to flash.

### `flasher()` (0x21370) — byte-sum gate
```
expected = parse_hex( FILINFO.fname[20..28] );  // 8 ASCII hex chars, 0x211FC
fp = open( FILINFO.fname );                     // 0xE33BC — the matched file name
size = stat(fp);                                // 0xE2FC8
sum = 0;                                        // ctx 0x110B88+8
while (read chunk of <= 0x10000 bytes from fp): // 0xE341C
    for each byte b: sum += b;                  // 32-bit mod sum
if (sum != expected) -> set abort byte (0x110B88+0) -> "Program error" hang
// else: erase+program the whole file 1:1 to flash (64 KiB sectors)
```
- Coverage is the **entire file**, offset 0 .. size, in 64 KiB chunks (emulator-verified:
  32 × 0x10000 for a 2 MiB image). The checksum is *not* self-referential because it
  lives in the filename.
- The write loop erases a sector, verifies erased (all `0xFF`), programs 256 B, reads
  back and memcmps (`0x1D20` erase-64K, `0x1CEC` program-256B, `0x139C` read-256B,
  `0x06CC` verify). **File offset N → flash offset N** (raw flash image semantics).

### File format (confirmed model)
A valid upgrade is a **raw flash image plus a specific SD filename** — the image needs
no header patching at all:

```
C:\JH_5408*.bin                 <- find-first pattern (card root)
JH_5408<VER12><X><CK8>.bin      <- 32 chars
  fname[0..7]   "JH_5408"       fixed prefix (pattern)
  fname[7..19]  VER12           12-char version; must DIFFER from 202505201029
  fname[19]     X               free separator char (never read)
  fname[20..28] CK8             8 ASCII hex = sum(image) mod 2^32
  fname[28..]   ".bin"
```
Example: `JH_5408202609101200_117C97DA.bin` (= sum of `charmera.bin`, 0x117C97DA).

**Image size is load-bearing.** After the last data sector the flasher erases one
extra sector at `image_size + 0x10000` (`0x217B4: add r0, sl, #0x10000; bl 0x1d20`).
A NOR chip decodes addresses modulo its capacity, so an address past the end of the
2 MiB part is **not** a no-op — it destroys a sector near the start of the flash:

| image size | trailing erase | result |
|---|---|---|
| 0x200000 (raw dump) | 0x210000 | out of range → 0x210000 % 0x200000 = **0x010000 erased** → brick |
| 0x1E0000 (max safe) | 0x1F0000 | in range (ends at 0x200000) |
| 0x1B0000 (SPII header length) | 0x1C0000 | in range |

So the upgrade image must be **≤ 0x1E0000 bytes** (`CHIP_SIZE - 2 * SECTOR`).
Everything past 0x186000 in this dump is `0xFF` (a used camera stores further photos
there — §11.1), so truncating loses nothing.
`scripts/build_upgrade_files.py` truncates automatically and
`scripts/emu_updater.py --stage write` replays the whole erase/program sequence
against a modelled chip and flags any out-of-range address.

This also re-explains the old test log: files named `JH5408_vA.bin` / `JH5408_vB.bin`
never match the pattern (no `_` after `JH`) so find-first fails and the camera ignores
them; a file named `JH_5408.bin` gives `fname[7..19] = ".bin"` (differs → attempt) and
`fname[20..28]` empty (parses to 0 ≠ sum → "Program error check file").

---

## 4. Empirical Test Log

### Hardware run 2026-09-10 #1 — format CONFIRMED
`JH_5408202609101200_117C97DA.bin` on a FAT32 card root, booted on the camera: no
"Program error", the upgrade ran and reached **`Upgrade     100 %`** — which is the
*success* label, not a percentage:

```
status routine 0x20AE4:
  status 0 -> sprintf(buf, "%s%3d%%",  "Upgrade     ", percent)   ; progress
  status 1 -> sprintf(buf, "%s%3d% %", "Upgrade     ", 100)       ; <- completion
  (status 2 -> the "Program error" path)
```
So the filename version compare, the whole-file byte sum **and** the erase/program/verify
write loop all passed on real hardware, exactly as the emulator predicted.

**Post-write state:** after the last data sector the flasher erases one more sector and
shows the completion status, then parks in a wait loop (`0x217DC`-`0x21814`):

```
loop:  bit = bit0 of MMIO 0xD0000068   (via 0x310FC(0))
       if (bit == 0) { retries = 0; delay(5); continue; }
       if (++retries < 20) { delay(5); continue; }
       power_off(0) / reset(0)                      ; 0x286A8 / 0x30EE8
```
i.e. it self-powers-off only once that input reads high 20 times in a row; otherwise it
sits on `Upgrade     100 %` (+ the "not poweroff" warning window) indefinitely. The signal
at `0xD0000068` bit0 is polled elsewhere as a level input (waited for high with a 0x4B0-tick
panic timeout at `0x8470`; waited for *low* during a shutdown sequence at `0x232CC`) —
identity not yet pinned (power key / charger / power-good).

### Hardware run 2026-09-10 #2 — BRICKED (own goal: image size)
The *name* format worked; what killed it was using a **full 2 MiB image** (#1 above), which
walks the flasher's trailing erase past the end of the chip. Replaying the whole sequence
offline (`emu_updater.py --stage write`) reproduces it exactly:

```
[write] image size  : 2097152 bytes (0x200000)   safe maximum: 0x1e0000
[write] sectors     : 33 erase(s), 8192 page program(s) over 0x0..0x200000
[write] last sector : 0x210000  (image size + 0x10000)
[write] *** OUT OF RANGE ***  -> it wipes the sector at 0x10000
```

The data write itself was clean — all 32 sectors erased, programmed, read-back verified
(hence the success status) — and then the 33rd, out-of-range erase ran. Damage map
(2 MiB part; a NOR decodes addresses modulo 0x200000):

| flash region | state | impact |
|---|---|---|
| `0x000000-0x00FFFF` | intact | SPII header + boot vectors survive |
| `0x010000-0x01FFFF` | **erased (0xFF)** | 64 KiB of core firmware code/data gone → no boot |
| `0x020000`+ | intact | updater `0x21370`, fatfs `0xE2xxx`, flash driver all survive |

Also explains #1's hang better than the GPIO condition alone: the CPU was executing from
flash that had just lost 64 KiB, so the wait loop could never complete its power-off.

**Recovery options, best first:**
1. External programmer write-back of `charmera.bin` (SOIC8 clip / desolder) — full restore.
2. USB ISP via `GPDevFWUpdater.dll` from the G+ IDE, if the boot ROM drops into download
   mode with a damaged image (untested; sector 0 still holds a valid SPII header).
3. SD path self-repair — the updater survived, but it only runs after the firmware boots,
   and the firmware is broken at `0x010000`; low probability, free to try.

### Earlier hardware rows, re-explained by the confirmed model (see §3)

| File on the SD card | What actually happened |
|---|---|
| `JH_5408.bin` (original dump) | name matches pattern; `fname[7..19]=".bin"` differs → attempt; `fname[20..28]` empty → parse 0 ≠ sum → **"Program error check file"** |
| `JH5408_vA.bin`, `JH5408_vB.bin` | **never match `C:\JH_5408*.bin`** (no `_`) → find-first fails → silently ignored |
| `JH_5408.bin` with version bytes patched at file `0x19` | same name as row 1 → identical behaviour; the content patch has no effect |

> The old "patching the file's `0x19` disabled the upgrade" reading was a misattribution:
> the filename, not the file content, drives both gates.

Every row above is now reproducible offline with the emulator (§8) — no SD card needed:

| image | name | `check_fn` | byte-sum gate |
|---|---|---|---|
| `charmera.bin` | `JH_5408.bin` | 1 → update | FAIL (`Program error`) |
| `JH5408_vA.bin` | `JH5408_vA.bin` | 0 → ignored (pattern mismatch) | n/a |
| `JH5408_vB.bin` | `JH5408_vB.bin` | 0 → ignored (pattern mismatch) | n/a |
| `charmera.bin` | `JH_5408202505201029_117C97DA.bin` | 0 → ignored (version matches) | PASS |
| `charmera.bin` | `JH_5408202609101200_117C97DA.bin` | 1 → update | **PASS → sector erase** |
| `vC_whole.bin` | any | 1 → update | FAIL (delta −18: builder's fixed point was off) |
| `vD_body.bin`, `vE_after26.bin` | any | 1 → update | FAIL (delta +1812: wrong coverage model) |

**Do not flash `vC/vD/vE` or `JH5408_v*`** — they patch image bytes the updater never
reads, so they would either fail the gate or (if renamed to carry a valid checksum)
program a corrupted header region into flash.

---

## 5. Assets / Files Created

- `assets/` — 42 extracted files from the `GP+` UI filesystem (`0x120000`):
  - 35 `.gpzp` (Generplus-compressed images — need GPZP codec to view/edit)
  - 5 `.wav` (valid PCM: `BEEP`, `CLICK`, `IMG`, `POWERON_AUDIO`, `POWEROFF_AUDIO`)
  - 3 `.jpg` (valid: `AUDIO_REC_BG` @`0x120800`, `POWER_ON_LOGO` @`0x161600` = the Kodak logo;
    `standalone_0180000_large_jpg_180000.jpg` @`0x180000` is **not** a UI asset but a stored
    960×720 **photo** — see §9)
- G+ IDE (564 MB MSI / zip present in folder) extracted to `msi_extract/`:
  - `GPDevFWUpdater.dll` — USB ISP/MSDC production flasher (NOT the SD format)
  - `GImagePreviewer.exe` — GPZP image previewer/encoder (unformatted image support)
  - **No tool in the IDE generates the `JH_5408*.bin` SD-upgrade file** — it's camera-firmware-specific.

---

## 6. Open Questions / Next Steps

1. **Hardware confirmation of the name-carried format** — flash
   `JH_5408202609101200_117C97DA.bin` (byte-identical to the current dump, so the risk is
   a no-op rewrite). Expect: no "Program error", the upgrade progress UI, reboot.
2. **Real change to flash** — patch the image (boot logo / behaviour), re-run
   `scripts/build_upgrade_files.py`; it recomputes the filename's checksum. Validate
   with `scripts/emu_updater.py` first.
3. **Unresolved anomaly (§8.3)** — the ARM→library veneers at `0xDECd8..0xDED50` name
   targets that do not decode as coherent code in either ISA; the three the updater uses
   are host-implemented in the harness. Worth chasing (possible overlay / runtime patch).
4. Later: editing UI assets for real requires the GPZP codec (Generplus-proprietary;
   `GImagePreviewer.exe` is a lead).

---

## 7. Python Environment

- Global python was accidentally given `capstone` via `--break-system-packages` during RE; **uninstalled**.
- Use the project venv (deps declared in `pyproject.toml`: capstone + unicorn):
  ```
  python3 -m venv .venv
  uv pip install --python .venv/bin/python capstone unicorn
  .venv/bin/python scripts/arm_disasm.py charmera.bin 0x21818 0x80 --strings
  ```
- No other global packages were touched.

---

## 8. Emulating the updater (Unicorn) — `scripts/emu_updater.py`

The two gates are pure software, so they can be executed offline with the camera's own
code instead of burning SD-card cycles.

**Memory map used** (from the boot literals at `0x3E0`/`0x408`/`0x410`):
`0x000000-0x0FFFFF` flash bank 0 (XIP, address == file offset), `0x100000-0x1FFFFF` RAM
(BSS `0x10AF30..0x1AE750`, SVC sp `0x1AE950`), plus scratch-backed MMIO
(`0x02000000`, `0xC0000000`, `0xD0000000`).

**Trapped firmware APIs** (all verified against disassembly): `find-first 0xE2EF0`,
`f_close 0xE2E54`, `f_open 0xE33BC`, `f_stat 0xE2FC8`, `f_seek 0xE32F4`, `f_read 0xE341C`,
`malloc 0x744`, `power_state 0x908B8`, flash primitives `0x1D20/0x1CEC/0x139C/0x06CC`
(erase/program/read/verify — the harness *stops* at the first one, i.e. "camera would
flash"), and the display/beep/delay/progress helpers. Everything else executes natively:
`memcpy 0xDB5F0`, `bzero 0xDB594`, `strcpy 0x470`, `strcat 0x51C`, `memcmp 0x4B4`,
`uidiv 0xDB808`, the hex parser `0x211FC`, and the gate logic itself.

```
.venv/bin/python scripts/emu_updater.py <image.bin> [--name FILENAME] [--trace]
```
`--name` defaults to the canonical name for that image. Observed events: the `check_fn`
verdict, the version `memcmp`, the parsed expected sum, the sum the camera's own loop
computes, the byte ranges read, and whether it reaches sector-erase or the "Program
error" hang. It reproduces every logged hardware result (§4).

### 8.1 Limits
- Only the *decision* path is emulated; the SPI flash controller and SD hardware are not
  modelled, so the harness says "the camera would flash", not "the flash succeeded".
- The FILINFO is filled by the harness's find-first stub (name + size); FAT directory
  parsing is not emulated.

### 8.2 Result
Validating a candidate now costs seconds instead of an SD round trip: the emulator
refuted the old file-offset model, proved the coverage is the whole file, showed the
`vC/vD/vE` candidates would all have failed (deltas −18 / +1812 / +1812), and confirmed
that the generated name+image pair passes both gates and reaches sector-erase.

### 8.3 Open anomaly: the ARM→library veneers
`0xDECd8..0xDED50` holds `ldr ip,[pc]; bx ip` veneers whose pool words
(`0x000DB94D`, `0x000DB249`, …) point at addresses that decode as *mid-function* in both
ARM and Thumb, and the surrounding region has entropy 6.1–6.8 vs 5.9 for known updater
code — yet the *direct* ARM calls next door (`memcpy 0xDB5F0`, `uidiv 0xDB808`) execute
correctly under emulation. The three veneers the updater uses (`0xDECd8` strlen,
`0xDECF0` memcpy, `0xDECFC` memcmp — identified from unambiguous call sites) are
therefore implemented in the harness rather than executed. Likely an overlay or
runtime-patched region; unresolved.

---

## 9. Images in the dump — `scripts/carve_jpegs.py`

Carving every `FF D8 FF` in `charmera.bin` gives **3 complete JPEGs and 4 header-only
stubs** (which contain no pixels and must not be mistaken for photos):

| Offset | Kind | Size | What it is |
|---|---|---|---|
| `0x120800` | complete | 160×80, 4358 B | `GP+` asset `AUDIO_REC_BG` (id 4) |
| `0x161600` | complete | 160×80, 3532 B | `GP+` asset `POWER_ON_LOGO` (id `0x20B`) — Kodak logo; XMP says Photoshop 23.2, 2021-12-15 |
| `0x180000` | complete | 960×720, 24227 B | **stored photo**, see §9.1 |
| `0xffb78`, `0x1079d8`, `0x107c48` | header-only | 640×480, 624 B each | `SOI..SOF0..COM("GPEncoder")..DQT..DHT..SOS` and then non-entropy data |
| `0x107448` | header-only | 640×480, 1424 B | as above + the stock SDK EXIF (`Generalplus` / `DSC Turnkey` / `20121115` / `2012:01:21 16:24:08`) |

```
.venv/bin/python scripts/carve_jpegs.py charmera.bin carved
# -> carved/*.jpg (complete) and carved/partial/*_header_only.jpg
```

### 9.1 The 960×720 photo at `0x180000`
- `GPEncoder` JPEG (SOF `0x3C0`×`0x2D0`), EXIF `Make=Generalplus`, `Model=CBB3`,
  `Software=20150615`, `DateTime=2025:02:23:10:11:18` (three copies: IFD0/ExifIFD/IFD1).
- The date is **written by the camera, not copied from a template**: the SDK stubs format
  the same field `2012:01:21 16:24:08` (space before the time), this one is
  `2025:02:23:10:11:18` (colon) — different producer, so the image is a real capture.
- Store geometry: the resource partition ends at `0x168E99`; `0x168E9A`–`0x16FFFF` is
  erased, `0x170000`–`0x1717FF` holds GPNV records (§11), `0x17F000` holds the internal
  store's index (§11.4), and the JPEG starts exactly at `0x180000`, ending `0x185EA3`, then
  92 bytes of `0x00` padding (to `0x185F00`) and `0xFF` to the end of the chip. One image
  plus its one index entry; nothing else in `0x180000`–`0x200000`.
- It is *not* referenced by the `GP+` name table (highest id `0x240` → `0x168000`), so it
  is not a UI asset: it sits in the area after the resource partition.
- Content: a blurred, over-exposed close-up (pink/red, light source upper right) — an
  accidental/defocused shot, not artwork.

### 9.2 The camera really can store photos with no SD card
Both storage back-ends are present as path strings in the code region:

| Path | Offset | Storage |
|---|---|---|
| `C:\DCIM\PICT%04d.jpg`, `…\MOVI%04d.avi`, `…\RECR%04d.wav` | `0xf378c`–`0xf37cb` | SD card |
| `C:\SPIDCIM\SPI%02d.jpg` | `0xf37dc` | internal SPI flash |
| `SPI_XX.JPG` | `0xf3874` (used from the pool at `0x191e0`) | internal SPI flash |

`SPI_XX.JPG` is followed at `0xf3880` by a `(u16 w, u16 h, char *name)` table
(320×240 QVGA … 4032×3024 12M — same names as the SD table at `0xf38f0`), i.e. the
internal path is a first-class capture target, not dead code. The single photo in §9.1 is
the only thing this dump has in that store — the donor dump carries two (§11.1).

**No filesystem wrapper is present anywhere in the dump**: no FAT boot sector (`55 AA` at
`+0x1FE` of any 512-byte boundary), no FAT volume label (`NO NAME`/`MSWIN4.1` occur only
inside the `f_mkfs` template at `0xfef5f`), and no directory entries (`SPI00`… /`PICT0001`
do not occur as data). In this state the internal area is a raw JPEG slot, not a
formatted volume.

### 9.3 The four header-only stubs are not truncated photos
Each ends at its `SOS` — the 8 bytes after it are the *next* stub's `SOI`, and the data
between the stubs (encoder tables, `GPLUSPRO`/`12345678` at `0x108530`, quant/huffman
tables at `0x1093xx`, driver state with `ssv6020` at `0x10ad84`) is ordinary structured
data, not JPEG entropy. Read them as encoder headers left in the data partition; there is
no recoverable image in them.

### 9.4 `GP+` index format (measured)
`0x120000`: `"GP+"`, 0x14-byte header, then 43 entries of 24 bytes —
`char name[16]` (`NAME` immediately followed by `GPZP`/`JPG`/`WAV`, NUL-padded) + one zero
`u32` + `u32 id`. Asset data lives at `0x120000 + id*0x200`, sector-aligned, in table
order. Last entry `USB_CONNECTGPZP` id `0x240` → `0x168000` (its data runs to `0x168E99`,
the last non-`0xFF` byte before the GPNV area);
`GPRSPAK` (id `0x10A` → `0x141400`) is the only blob that is not `GPZP`/`RIFF`/JPEG.

---

## 10. Application / UI layer — power-on mode menu (exploratory pass 2026-09-10)

> **Goal:** make the camera boot straight into photo mode instead of showing the
> "photo / video / settings" menu on power-on. Everything below is static analysis of
> `charmera.bin`; the patch is built and updater-validated but **not yet flashed** (§10.9).

### 10.0 Method

Linear disassembly desyncs on this image, so all xrefs below come from
**`scripts/find_xrefs.py`** — a recursive ARM disassembler seeded from the reset vector and
from every `stmfd sp!,{…,lr}` prologue, which also follows `add pc,pc,rX,lsl #2` /
`ldr pc,[pc,rX,lsl #2]` switch tables. It covers ~193k instructions / ~4.6k functions /
~16k calls and reaches the updater (`0x21818`), the RTOS, the wifi stack and the app/UI
layer:

```
.venv/bin/python scripts/find_xrefs.py                 # summary
.venv/bin/python scripts/find_xrefs.py --callers 0x25868
.venv/bin/python scripts/find_xrefs.py --refs 0x10fbc5
.venv/bin/python scripts/find_xrefs.py --disasm 0x14054 --len 0x40
.venv/bin/python scripts/find_xrefs.py --strings 0x1617c
```

### 10.1 Code base (needed to read any of this)

`CPU addr = file offset − 0x200`. The vector table at **file `0x200`** has a literal pool
at `0x220` holding `0x3c, 0x168, 0x174, …` — those are *CPU* addresses, so the reset stub
lives at **file `0x23c`** (`msr cpsr_fsxc,#0xd3` …) and ends with `b #0x2dd48`.
Consequence: pool words (function pointers) are CPU addresses, while `add rX,pc,#imm`
targets and `bl` targets are already file offsets.

### 10.2 Task table — `main` @ `0x2dd48`

`main` calls `0x2dcac`, which calls `0x9012c(entry, arg=0, stack_ptr, slot)` once per task
and finally `0x901f4(0xff)` to start the scheduler:

| slot | entry (file) | notes |
|---|---|---|
| `0x11` | `0x13310` | system/state-control task; jump table @ `0x133b8` maps messages `0x10000100+state` → "set state 0…7" (handlers `0x13428`/`0x13434`/`0x13454`/`0x134b4`/`0x134c0`) |
| `0x07` | `0x16dd4` | **display/UI task** (calls `ap_display_init`, dispatches on `msg>>24`) |
| `0x01` | `0x12478` | browse/slider task |
| `0x34` | `0x5cf0` | |
| `0x30` | `0x8558` | |
| `0x32` | `0x36970` | |
| `0x2d` | `0x25868` | **mode dispatcher** — task-table pool word is the CPU ptr `0x25668`; body is file `0x25868` (§10.7) |

Message IDs seen: `0x100001xx` (state/control), `0x100007xx`, `0x50xx` (keys),
`0x70xx` (keys/power/USB; the updater/USB task `0x65b0` handles `0x703e/0x703f/0x7040/0x7042`).

### 10.3 UI framework globals (RAM)

| address | role | evidence |
|---|---|---|
| `0x10fbc4` | **UI/screen context** — `+1` = mode byte (§10.5), `+8` = screen count, `+0xA..0xC` = h:m:s, `+0x1c/+0x20/+0x24` = screen buf ptrs, `+0x34` = flag, `+0x48` = callback, `+0x4c` = icon buf | `ap_display_init` `0x165ac`, `0x15648`, `0x14a54` |
| `0x10fcc0` | menu-handler context; 10 handlers registered by `0x1a958` into `+0,+4,+8,+0xc,+0x10,+0x18,+0x1c,+0x20,+0x24,+0x28` (`+0x14` is a 4-word array cleared by `0x14158`) | `0x1a958`, `0x14158` |
| `0x10fc18` | current **draw** handler; `0x10fc1c` = tick/2nd handler | display task `0x16dd4` calls `[0x10fc18]` |
| `0x10fc20` | screen-table base (entries 24 B, count at `0x10fbc4+8`) | `0x165ac`, `0x1617c` |
| `0x10fd58` | display queue context | `0x16dd4` |

`ap_display_init` (`0x165ac`) allocates **exactly 4** screen slots (`ctx+8 = 4`).

### 10.4 The power-on screen *is* the mode menu

Display init `0x16ce8` installs the initial handler pair via `0x1670c`, reading the pool
at `0x167f0`:

```
pool[0x167f0] = 0x15f7c (CPU)  -> file 0x1617c   ; draw
pool[0x167f4] = 0x144f4 (CPU)  -> file 0x146f4   ; tick
```

**Draw handler `0x1617c` is the select-mode screen.** It:
- draws the literal **`SELECT MODE`** at `0x16474` (`mov r1,#0x98; bl 0x14e28`, id 152 = `0x98`); §10.6
- draws the clock (`0x10fbce`, written by `0x14a54` / `0x14bc8`);
- loads the mode icons: at `0x16258` it calls **`0x14054`**, which `sprintf`s
  **`"PV0%02d.GPZP"`** (format string at `0x14100`) with index `mode_byte − 4` and loads
  it with `0x1510`. So menu item *i* ⇔ `mode_byte = 4+i` ⇔ `PV00{i}`.

Highlight/cursor painter **`0x2d568`** draws one of three bar shapes for cursor 0…3
(called only from `0x1d6fc`).

### 10.5 The mode byte: RAM `0x10fbc5` (= `ctx+1`)

**Reads**
| site | interpretation |
|---|---|
| `0x14054` | icon index = `v − 4` (valid 4…7 → `PV000`–`PV003`) |
| `0xec9c`, `0xeef0` | frame assets `F_%d_%03d.GPZP` (fmt @ `0xed6a`), index = `v − 4` |
| `0x6e188` (`avi_front_capture_set`), `0x6e61c` | capture path: `v − 8 ∈ 0…3` |
| `0x6e4dc` | theme colours, switch on `v` = 8 / 9 / 10 |

**Writes**
| site | value |
|---|---|
| `0x1c6a4` (func `0x1c644`) | `0` |
| `0x1d72c`, `0x1d740` (func `0x1d6fc`) | `0` |
| `0x1de84` / `0x1df14` (func `0x1d6fc`) | prev/next: `v ∓ 1`, wrap `0xb → 0` |

**Model (corrected — see §10.7):** `0x10fbc5` is the **menu cursor**, not the mode.
The `− 4` uses select which `PV00{v-4}` icon is drawn for the highlighted item. The
`− 8 ∈ 0…3` test on the capture path (`0x6e188`, `0x6e61c`) is still unexplained; the
*active mode* is a separate id at RAM `0x110d1e` (§10.7). All 9 pool-load sites of
`0x10fbc5` are enumerated above, so the read/write sets are believed complete.

### 10.6 `GPRSPAK` string ids (`0x141400`) — measured

Strings begin at `+0x5E4` (`"English"`), NUL-separated and contiguous, so the **ordinal is
the runtime string id**. Draw APIs: `0x21a6c(target, id, …)` (assert name
`ap_state_handling_str_draw`) and `0x14e28(target, id, x, y, …)`.

Verified ids (cross-check: `0x1be80` draws id `0x54` on the no-SD branch of `0x22094`):

| id | text | id | text |
|---|---|---|---|
| `0x54` | `NO CARD` | `132` | `Video` |
| `0x55` | `Disk Full` | `142` | `PHOTO` |
| `0x7F` | `WIFI Infor` | `143` | `VIDEO` |
| `131` | `Photo` | `145` | `TIME` |
| | | `149` | `SET DATE` |
| | | `152` | `SELECT MODE` |

### 10.7 RESOLVED — the mode is a separate id; `ctx+1` is only the menu cursor

The earlier "mode entry writes `0x10fbc5 = 8…11`" model was **wrong**. There is a separate
**mode id** and a dispatcher:

**Mode dispatcher = task slot `0x2d`** (launched by `main` `0x2dcac` → `0x9012c`; the
task-table pool word `0x25668` is a CPU ptr, so the file body is **`0x25868`**):

- receives a message on the mode queue (handle slot RAM `0x110d90` = ctx `0x110d80+0x10`;
  `0x8f760`), takes the **low 9 bits**
  (`lsl #0x17 / lsr #0x17`) as the mode id,
- stores it as `u16` at **RAM `0x110d1e`** (the field the driver handlers `0x78c0`/`0x798c`/
  `0x7a34`/`0x7afc` and the boot menu `0x1617c` read),
- switches on `id − 0x100` via the jump table at `0x258e0`:

| mode id | case | state function | what it is (evidence) |
|---|---|---|---|
| `0x100` | `0x2591c` | `0x65b0` | USB/power task (shows `POWER_ON_LOGO`) |
| `0x101` | `0x25950` | **`0x1c644`** | **video record** — contains the `__func__` string `state_video_record_entry` (`0x1cb8c`) |
| `0x102` | `0x25934` | **`0x1d6fc`** | **still capture** — sets up the camera (`0x7e28`), drives the shutter, PV icons, cursor nav |
| `0x104` | `0x25968` | — | |
| `0x105` | `0x2598c` | — | |
| `0x10A`…`0x10D` | `0x259c0`… | — | |

`0x2591c/0x25934/0x25950` also write `[0x110d80+0x14] = mode` and `[0x110d80+4] = 0/1/2`.

**Menu index → mode id table** (switch on `[msg+1]` at `0x2552c`, func `0x2526c`):

| menu index | mode id |
|---|---|
| 1 | `0x102` (**photo**) |
| 2 | `0x101` (**video**) |
| 3 | `0x105` |
| 4 | `0x104` |
| 5 | `0x10B` |
| 6 | `0x10A` |

So `ctx+1` (`0x10fbc5`) really is just the menu cursor/highlight; the *active mode* is the
id at `0x110d1e`. `0x1617c` (boot menu) reads it at `0x16234` (`ldrh r0,[0x110d1e]`,
`… == 0x102` branch).

**Tooling note:** the first version of the recursive disassembler (and the ad-hoc session
pass) treated conditional `bl<cond>` (`blne`, `bleq`, …) as *terminating* branches, which
silently truncated large app functions — that is why `0x1c644`/`0x1d6fc` looked like they
had no callers and why only 7 of the 9 pool sites for `0x10fbc5` were visible. Both are
fixed in `scripts/find_xrefs.py` (`split_branch()`); the callers are `0x25960` and
`0x25948` in `0x25868`.

### 10.8 PATCHED — the boot-mode post is pinned (2026-09-10)

The boot-time sender is **not** among the `0x110d80` refs of §10.5: senders reach the
queue through its handle slot at **`0x110d90`** (`= mode ctx 0x110d80 + 0x10`), so a
pool-ref scan for `0x110d80` structurally cannot see them. Mode-queue handle users
(`--refs 0x110d90`): `0x6578` (boot exit, below), `0x65b0` (power-on), `0x0af80`,
`0x17e80`, `0x17f94`, `0x1b3d0`, `0x1c644`, `0x1d6fc`, `0x77eac`.

Boot chain (all disassembly-confirmed):

1. Dispatcher task `0x25868` inits (`0x24f7c`) and seeds the mode queue with **`0x100`**
   (`0x25874` `mov r1,#64,#30` = `0x40 ror 30` = `0x100`; `0x25878` `ldr r0,[r5,#0x10]`;
   `0x2587c` `bl 0x8f87c`).
2. Id `0x100` → case `0x2591c` → **`0x65b0`** (power-on handler). It polls the *event*
   queue (ctx `0x110d88`, handle `[ctx+8]`) via `0x25c38`/`0x8f760`. Its only loop exit is
   `mov r4,#7` on event **`0x5025`** (`0x6644`; `0x5025` is synthesised at runtime, so it
   has no pool site to search for).
3. That event posts `0x108` (`0x6638`, SD-update gate → `0x21370`) and then leaves through
   **`0x6578`**, which posts the UI mode to the same queue:
   ```
   0x6578: ldr r0,[pc,#0x198]  ; =0x110d90   (mode-queue handle slot)
   0x657c: push {r3,lr}
   0x6580: ldr r0,[r0]
   0x6584: ldr r1,[pc,#0x188]  ; literal 0x6714 = 0x10D   <-- boot UI mode
   0x6588: bl 0x8f87c          ; msgQSend(queue, mode)
   ```
4. `0x6578` has exactly **one** caller (`0x668c`, inside `0x65b0`) and its literal `0x6714`
   is loaded only by `0x6584`. Net boot is therefore
   `0x100` (logo) → `0x108` (SD-update check) → **`0x10D` (select menu)** — and the last
   post is the single thing to change.

Mode-id → handler (case table `0x258e0`, index `id − 0x100`):
`0x100`→`0x65b0`, `0x108`→`0x21370` (updater), `0x10D`→`0x2526c` (menu),
`0x101`→`0x1c644` (video), **`0x102`→`0x1d6fc` (still capture)**.

### 10.9 Patch applied — `scripts/patch_boot_mode.py`

Rewrites the single literal `0x6714` (`0x10D` → `0x102`); the loader `0x6584` is guarded
as `0xE59F1188` and the old value must be `0x10D`, so a wrong/patched base is refused.

```
.venv/bin/python scripts/patch_boot_mode.py                        # -> patched/charmera_photo.bin
.venv/bin/python scripts/build_upgrade_files.py patched/charmera_photo.bin
.venv/bin/python scripts/emu_updater.py --stage both  <JH_5408*.bin>
.venv/bin/python scripts/emu_updater.py --stage write <JH_5408*.bin>
```

* Updater gates both pass: `check_fn()=1` (UPDATE AVAILABLE) and the byte-sum gate
  reaches sector-erase; write stage `31` erases / `7680` page programs, last sector
  `0x1f0000`, range OK. The patch site (`0x6714`) is outside the updater's executed path.
* The SD-update gate is preserved (boot still posts `0x108`), and the menu stays reachable:
  photo and video post `0x10D` themselves (`0x1d6fc` at `0x1e0c0`, `0x1c644` at `0x1ccfc`).
* **Not yet flashed.** `0x1d6fc`'s only caller is the dispatcher case and it self-initialises
  (clears `0x10fbc5`, `0x110278[2/3]`, `0x10fd58`; calls `0x14158` via `0x1d6c0`), but in
  stock firmware it is entered *after* the menu preamble `0x2526c` — entering it directly
  from power-on is the remaining hardware risk to watch on first flash.

### 10.10 Unknowns

- `PV000`–`PV003` `.gpzp` headers are just `GPZP` + compressed payload (no dimensions/ID),
  so **which icon is the camera is unknown** without the GPZP codec (existing TODO).
- `0x146f4` is installed as the 2nd handler next to the select screen; its role
  (tick vs key) is not confirmed.

---

## 11. GPNV non-volatile records at `0x170000` (donor-dump contrast, 2026-09-10)

Found by diffing `charmera.bin` against a second, independent 2 MiB dump
(`../Project-Sirius/Original_Firmware.bin`, "donor"). **The firmware is byte-identical:**
`0x000000`–`0x170200` matches exactly (`md5 e4c462a67812fac70025e38cc800c875`); every
difference is device state *after* the resource partition. Both dumps together pin down
that state as follows.

### 11.1 Diff summary (donor vs `charmera.bin`)

| Region | Donor | `charmera.bin` |
|---|---|---|
| `0x000000` – `0x1701FF` | *identical* | *identical* (whole firmware + `GP+` assets) |
| `0x170200` – `0x1717FF` | 11 further GPNV records (12 total) | erased — 1 record |
| `0x17F004` – `0x17F00E` | 2 photo-index entries | 1 entry |
| `0x180000` | 960×720 photo, 38478 B, EXIF `2025:01:01:00:10:41` | 960×720 photo, 24227 B, EXIF `2025:02:23:10:11:18` |
| `0x1A5800` | 2nd 960×720 photo, 38286 B, EXIF `2025:01:01:00:10:45` | erased `0xFF` |
| everything else | *identical* | *identical* |

Carved with the existing `scripts/carve_jpegs.py`: donor → 4 complete + 4 header-only,
`charmera.bin` → 3 + 4. Both `0x180000` JPEGs share the encoder header but are different
captures, so this is camera usage state, **not** firmware.

### 11.2 What the record *is*

`0x170000` + N×`0x200` is a **GPNV** (Generalplus non-volatile) settings store:

- The literal `"GPNV"` sits at file `0xF3BC0`, next to the default field values
  `"CAM05_"` (7 B @ `0xF3BA4`) and `"12345678"` (9 B @ `0xF3BAB`) — both appear verbatim
  in the record at `+0xAC` and `+0xCE`.
- `func 0x1F89C` is the default-init path: it copies those two literals (lengths 7 and 9)
  and zeroes a **`0x200`-byte RAM struct at `0x1107DC`**.
- GPNV load: `0x1F89C` → `func 0x23E60` → `func 0xF0820`. `0xF0820` is the shared flash-read
  API (device id u16 in RAM `0x110D5C`, open, then read) — 23 callers, so GPNV is one client
  of a generic storage layer. `0x23E60` reads exactly `0x200` bytes into `0x1107DC`.
- `func 0x1FAA8` (GPNV entry; one caller `0x24FD4`) touches `[0x1107DC+0xFA]`, the same byte
  the record carries at `+0xFA`. The device-id → flash-address binding inside `0xF0820` is
  **not yet traced**.

### 11.3 Checksum — solved

Record bytes `0xFC–0xFF` are a **big-endian standard CRC-32 (IEEE / zlib)** over bytes
`0x00–0xFB`:

```
crc32(rec[0x00:0xFC]) == u32be(rec[0xFC:0x100])    # 12/12 donor records, 1/1 here
```

Corroborated by the firmware's own CRC-32 routine at `func 0x1FB0C`, which builds a
256-entry table from polynomial `0xEDB88320`.

### 11.4 The photo-store index at `0x17F000`

One sector of `(u32 slot, u32 size)` little-endian pairs, zero-terminated:

| dump | entries |
|---|---|
| donor | `(0x00010000, 38478)`, `(0x00010001, 38286)` |
| `charmera.bin` | `(0x00010000, 24227)` |

The sizes match the carved JPEG lengths exactly, so this is the internal store's directory;
the low 16 bits of `slot` are the photo ordinal. Donor photo #2 sits at `0x1A5800`, i.e.
slots are not packed — the exact slot size/stride is not pinned.

### 11.5 What varies, and what's still unknown

Across the donor's 12 records only five content bytes ever differ from record 0 —
`0x00`, `0x03`, `0x12`, `0x52`, `0x53` — plus the CRC. `u16@0x00` runs
`513, 513, 515, 517, 519, 521` and `u16@0x52` runs `0, 1, 257, 257, …`, so these read as a
write/version counter: the slots are successive snapshots (wear-levelled ring), not 12
different settings.

Still open:

- semantics of the fixed `0x00`–`0x51` field block (defaults look encoder/driver-ish — unverified);
- the slot ring's exact bound/policy (`0x170000`–`0x17F000` is 120 sectors; 12 used on the donor);
- whether the CRC is verified on read;
- whether `"CAM05_"` really is the model string (inferred from the default-init copy only).

---

*Last updated: 2026-09-10 (donor-dump contrast: firmware identical; §11 GPNV records + photo-store index)*