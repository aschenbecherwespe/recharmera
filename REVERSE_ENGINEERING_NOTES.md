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
| `0x10C000` – `0x11F000` | all-zeros gap |
| `0x120000` | **`GP+` UI resource filesystem** (name→ID index + sector-aligned asset data) |
| `0x120600`+ | GPZP-compressed UI images / JPG / WAV assets (42 files extracted to `assets/`) |
| `0x180000` | large standalone JPEG (boot logo, Generalplus `GPEncoder`, EXIF model `CBB3`) |
| `0x186000` – end | mostly `0xFF` (unused flash) |

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
if (power_state > 0x1f4) return 0;            // "not poweroff" guard
buf = "C:\JH_5408*.bin";
open(buf, mode 0x77);                          // FATFS-ish open
if (open < 0) return 0;
read file into buffer
if (memcmp(buf+0x19, "202505201029", 12) != 0)
    return 1;    // version DIFFERS  → "there's an update"   → PROCEED
else
    return 0;    // version MATCHES  → "already current"     → IGNORE
```
> **KEY (learned empirically):** a version at `0x19` that **differs** from `202505201029` makes the camera attempt the upgrade. A *matching* version makes it silently skip the file. My first patch (setting version = `202505201029`) accidentally **disabled** the upgrade → camera ignored the file.

### `flasher()` (0x21370) — byte-sum gate
```
expected = parse_hex( 8 bytes at RAM_global+0x26 );   // 8-char hex checksum
fp = open( path at RAM_global+0x12 );
if (fp < 0) -> "check file" / fail
fp_size = f_size(fp);
sum = 0;
while (read chunk of <=0x400 bytes from fp):
    for each byte b: sum += b;            // 32-bit mod sum
if (sum != expected) -> ABORT BEFORE ANY WRITE (silent-ish / error)
// else: erase+program whole file 1:1 to flash at same offsets
```
- The write loop erases a 0x400 sector, verifies erased (all `0xFF`), programs the file bytes, next sector. **Total bytes written = file size; file offset N → flash offset N** (raw flash image semantics).

### File format (current model)
The upgrade file is essentially a **raw flash image** (2 MiB, our dump) with header fields the updater validates:
- offset `0x19` … `0x25` — version marker; must **differ** from current installed version to trigger
- offset `0x26` … `0x2E` — 8 ASCII hex chars = **byte-sum expected** (coverage TBD)
- rest — the raw flash content

---

## 4. Empirical Test Log

| File | version @0x19 | checksum @0x26 | Camera result |
|---|---|---|---|
| `charmera.bin` (original dump) | `05 00 01 01…` (differs) | binary garbage | **"Program error check file"** (attempted, byte-sum/parse failed) |
| `JH_5408.bin` (version patched to match) | `202505201029` (matches) | binary garbage | **ignored** (version says "already current") |
| `JH5408_vA.bin` | `202505201029` (matches) | `117C977A` (whole-file sum) | **ignored** |
| `JH5408_vB.bin` | `202505201029` (matches) | `117C90E0` (body sum) | **ignored** |
| `vC_whole.bin` | `100000000000` (differs) | `117C980C` (whole-file sum) | **PENDING TEST** |
| `vD_body.bin` | `100000000000` (differs) | `117C90E0` (body sum) | **PENDING TEST** |
| `vE_after26.bin` | `100000000000` (differs) | `117C90E0` (sum after 0x26) | **PENDING TEST** |

**Interpretation of results so far:**
1. Version **must differ** from `202505201029` to be accepted as an update.
2. The byte-sum gate exists and aborts *before* writing (safe), but its exact coverage is still unresolved.

---

## 5. Assets / Files Created

- `assets/` — 42 extracted files from the `GP+` UI filesystem (`0x120000`):
  - 35 `.gpzp` (Generplus-compressed images — need GPZP codec to view/edit)
  - 5 `.wav` (valid PCM: `BEEP`, `CLICK`, `IMG`, `POWERON_AUDIO`, `POWEROFF_AUDIO`)
  - 3 `.jpg` (valid: `AUDIO_REC_BG`, `POWER_ON_LOGO`, plus large `standalone_0180000_large_jpg_180000.jpg`)
- G+ IDE (564 MB MSI / zip present in folder) extracted to `msi_extract/`:
  - `GPDevFWUpdater.dll` — USB ISP/MSDC production flasher (NOT the SD format)
  - `GImagePreviewer.exe` — GPZP image previewer/encoder (unformatted image support)
  - **No tool in the IDE generates the `JH_5408*.bin` SD-upgrade file** — it's camera-firmware-specific.

---

## 6. Open Questions / Next Steps

1. **Exact byte-sum coverage** — test `vC` (whole file) then `vD`/`vE`. Whichever gets past `"Program error check file"` wins.
2. **Checksum source** — the RAM global at `0x110b94+0x26`; who fills it and from where (possibly parsed from the file header in an earlier state).
3. After file validation, confirm the flash-write actually completes and the camera boots the (near-identical, header-patched) image.
4. Later: editing UI assets for real requires the GPZP codec (Generplus-proprietary; `GImagePreviewer.exe` is a lead).

---

## 7. Python Environment

- Global python was accidentally given `capstone` via `--break-system-packages` during RE; **uninstalled**.
- Use the project venv instead:
  ```
  python3 -m venv .venv
  .venv/bin/pip install capstone
  .venv/bin/python scripts/arm_disasm.py charmera.bin 0x21818 0x80 --strings
  ```
- No other global packages were touched (scripts use only stdlib except capstone-for-disasm).

---

*Last updated: 2026-01 (session)*