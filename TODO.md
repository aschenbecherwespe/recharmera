# CHARMERA RE — TODO / status

Status page for the firmware-modding project. Companion to `REVERSE_ENGINEERING_NOTES.md` and `scripts/`.

---

## 1. Goal 1 — get a valid SD-card upgrade file (solved, pending hardware run)

The camera's SD upgrade (`C:\JH_5408*.bin`) is the only in-field path (no CH341A programmer available).

### Confirmed
- Firmware: Generalplus GPCV, ARM, WH5408/JH5408, 2 MiB SPI flash (`SPII` container).
- Updater looks for `C:\JH_5408*.bin` at the **SD card root** (FAT32).
- **The metadata lives in the FILENAME, not the file** (corrected 2026-09; see notes §3):
  - `fname[7..19]` = 12-char version, memcmp'd against the installed `202505201029`.
    Must **differ** or the file is ignored.
  - `fname[20..28]` = 8 ASCII hex chars = `sum(image) mod 2^32` (whole file, 64 KiB chunks).
  - `fname[19]` is a free separator char; the image content needs **no header patching**.
- Canonical name: `JH_5408<VER12>_<CK8>.bin`, e.g. `JH_5408202609101200_117C97DA.bin`.
- Write is 1:1 (file offset N → flash offset N), erase+program+verify per 64 KiB sector.

### Next steps (in priority order)
- [x] **Hardware run #1 (2026-09-10)**: name format CONFIRMED — the camera accepted
      `JH_5408202609101200_117C97DA.bin` and reached `Upgrade     100 %` (the success
      label; `0x20AE4` status 1 prints a hardcoded 100). Gates + write loop pass.
- [x] **Hardware run #2 (2026-09-10)**: camera BRICKED — own goal, not the name format.
      The full 2 MiB image drives the flasher's trailing erase to `0x210000`; the 2 MiB
      part decodes that modulo capacity, so it erased flash `0x010000-0x01FFFF`
      (64 KiB of core code). Reproducible offline: `emu_updater.py --stage write`.
- [x] **Recover the camera (2026-09-14)**: external programmer write-back of
      `charmera.bin` via `pico-serprog` (Raspberry Pi Pico, `0xcafe:4001`) + SOIC8 clip.
      Pre-restore dump of the bricked state (`broken_flash_dump.bin`) confirms exactly
      one 64 KiB sector erased at `0x010000`–`0x020000`, matching the predicted damage
      map. Write verified clean and the camera boots.
- [ ] **Never flash an image > 0x1E0000 bytes.** `build_upgrade_files.py` now truncates
      automatically and `emu_updater.py --stage write` verifies the whole erase/program
      sequence including the trailing sector.
- [ ] Once recovered and re-validated: patch a *real* change, rebuild (name recomputed),
      check with `--stage both` **and** `--stage write`, then flash.

### Open questions
- Internal photo store (`C:\SPIDCIM\SPI%02d.jpg`, `SPI_XX.JPG`): **RESOLVED by the donor
  dump** (notes §11.4). It is a real, indexed store: directory at `0x17F000`
  (`(u32 slot, u32 size)` LE, sizes match the carved JPEGs), photos from `0x180000`, no FAT
  wrapper. `charmera.bin` holds 1 capture (24227 B); the donor 2 (`0x180000`, `0x1A5800`) —
  so `0x180000` is slot 0 of the store, not a factory leftover. Remaining: slot size/stride
  (donor slot 1 is not adjacent — `0x1A5800`).
- Unconfirmed on hardware: FAT32 vs exFAT, and the power state in which the updater runs
  (`check_fn` returns 0 when `power_state > 0x1f4`, string "not poweroff").
- The `0xDECd8..0xDED50` ARM→library veneers do not decode as coherent code in either ISA
  (notes §8.3) — possible overlay; the three used by the updater are host-implemented.

---

## 2. Future deeper goals

This is the reason for the whole project — editing what the camera does.

- [ ] Modify **boot logo** (`POWER_ON_LOGO.jpg` in `assets/`) → repack JPEG into the `GP+`
      filesystem (likely needs GPZP codec for newly-encoded images).
- [ ] Modify **UI assets** (35 `.gpzp` files in `assets/`) → need the GPZP codec.
      Lead: `GImagePreviewer.exe` (in the G+ IDE extraction) — inspect whether it can encode.
- [ ] Modify **behavior/code** (e.g. disable "Select program", always start recording) →
      patch ARM binary, rebuild the image + filename, validate with the emulator, flash.
      → **active, see §4** (boot straight into photo mode).
- [ ] Optional: repack the `SPII` dump cleanly into a `GP+` partition as a standalone base image.

---

## 3. Tooling / housekeeping

- [x] `scripts/build_upgrade_files.py` — rewritten for the confirmed format (emits the file
      **and** its canonical name; computes the whole-file byte sum).
- [x] `--clean` flag added to `build_upgrade_files.py` — blanks GPNV settings
      (0x170000–0x17EFFF), photo-store index (0x17F000–0x17FFFF), and stored photos
      (0x180000–0x185FFF) to 0xFF so the upgrade file is a factory-fresh firmware+assets
      image.  Emulator-validated; GPNV default-init path (0x1F89C) should re-initialise
      on first boot (unverified on hardware).
- [x] `scripts/emu_updater.py` — Unicorn harness: runs `check_fn` + `flasher` offline and
      reports both gates; reproduces every logged hardware result.
- [x] `scripts/carve_jpegs.py` — carves every JPEG in a dump and separates *complete*
      frames from *header-only* `GPEncoder` stubs (no pixels). Findings in notes §9.
- [ ] `scripts/extract_gpz_assets.py` — could add a `--names-only` / manifest output.
- [ ] Add the GPZP codec disassembly (find encode/decode in the ARM target) — long-term unlock
      for asset modding.
- [ ] Check `GImagePreviewer.exe` behaviour (pack GPZP, or view only?) — decides repack route.
- [ ] Optional: emulate the SPI flash controller + W25Q16 command set so the harness can
      validate the write/verify phase too (currently it stops at the first erase).

---

## 4. Goal 2 — boot straight into photo mode (app/UI layer)

**Want:** power-on goes directly to the camera/photo screen; today it shows the
"photo / video / settings" menu and you must pick photo every time.

**Verdict:** achievable — pure app logic, no signature anywhere. Patch built and
updater-validated 2026-09-10; **not yet flashed** (camera still bricked). Write-up: notes §10.

### Confirmed (notes §10)
- Boot screen *is* the mode menu: display init `0x16ce8` installs draw handler
  **`0x1617c`** (via `0x1670c`), which draws `SELECT MODE` (`0x16474`, str id `0x98`) and
  loads the mode icons `PV0%02d.GPZP` in `0x14054` using `menu_cursor − 4`.
- **Menu cursor = RAM `0x10fbc5`** (`ctx 0x10fbc4` +1); 9 pool sites image-wide, 3 writers.
- **Active mode is a separate id**, low 9 bits of a message, stored at RAM **`0x110d1e`**.
- **Mode dispatcher = task slot `0x2d`**, body **`0x25868`** (task-table pool word `0x25668`
  is a CPU ptr): receives on the mode queue whose handle slot is RAM **`0x110d90`**
  (= ctx `0x110d80`+0x10), decodes the id, stores it at `0x110d1e`, and switch-dispatches at
  `0x258e0`:
  `0x100`→`0x65b0` (power-on), `0x108`→`0x21370` (SD updater), `0x10D`→`0x2526c` (menu),
  **`0x101`→`0x1c644` = video record** (`state_video_record_entry`),
  **`0x102`→`0x1d6fc` = still capture**, `0x104`/`0x105`/`0x10A`/`0x10B`.
- **Menu index → mode id** (switch at `0x2552c`, func `0x2526c`):
  `1→0x102 (photo)`, `2→0x101 (video)`, `3→0x105`, `4→0x104`, `5→0x10B`, `6→0x10A`.
- `ap_display_init` `0x165ac` allocates exactly **4** screen slots.
- `GPRSPAK` string ids == ordinals from `+0x5E4`; ids `131 Photo`, `132 Video`,
  `142 PHOTO`, `143 VIDEO`, `149 SET DATE`, `152 SELECT MODE`, `0x54 NO CARD`.

### Done this pass (2026-09-10)
- [x] **Boot-mode sender pinned** — `0x6578`, with exactly one caller (`0x668c`, in the
      power-on handler `0x65b0`), posts `0x10D` (select menu) with `msgQSend 0x8f87c`.
      It reaches the queue via the **handle slot `0x110d90`** (= ctx `0x110d80`+0x10), which
      is why a pool scan for `0x110d80` never showed it. Boot chain:
      `0x100` (logo) → `0x108` (SD-update gate `0x21370`) → `0x10D` (menu).
- [x] **Patch** `scripts/patch_boot_mode.py` — rewrites the single literal `0x6714`
      (`0x10D` → `0x102`); guarded on the loader insn `0xE59F1188` and the old value.
- [x] Built `patched/charmera_photo.bin` → `JH_5408202609101200_0F7E97CF.bin`
      (0x1E0000, in-range tail erase); `emu_updater.py --stage both` and `--stage write`
      both pass.

### Next steps (in order)
- [ ] Hardware-verify (when the camera is recovered): power on → lands in photo, shutter
      works, menu still reachable. Watch the direct-`0x1d6fc` entry (stock enters it after
      the menu preamble `0x2526c`) — notes §10.9.
- [ ] Decode `PV000`–`PV003` (GPZP codec / `GImagePreviewer.exe`) to confirm the icon order
      matches the index→mode table (`1 = photo`).

### Tooling
- [x] `scripts/find_xrefs.py` — recursive ARM disassembler + xref map (reset vector +
      `stmfd` prologues + switch tables; ~193k insns / 4.6k funcs / 16k calls).
      Note: conditional `bl<cond>` must fall through — treating it as terminating silently
      truncates app functions (this hid the `0x1c644`/`0x1d6fc` callers).
- [x] `scripts/patch_boot_mode.py` — rewrites boot UI mode literal `0x6714` (`0x10D`→`0x102`)
      with loader/value guards; `patched/` is generated (gitignored).

### Hardware run 2026-09-14
- [x] Flashed `JH_5408202609101200_0F7E97CF.bin` on hardware: boots straight to
      photo mode. Patch confirmed working.
- [x] Double-flash identified: firmware version string at `0x218C4` was not
      patched, so camera re-flashed on every boot. Fixed by `--bump` in
      `scripts/build_upgrade_files.py` (rewrites image version to match filename).

---

## 5. Committed / done (no more action unless noted)

- [x] Firmware analysis / region map (notes).
- [x] Assets extracted (35 `.gpzp`, 5 `.wav`, 3 `.jpg` + `standalone`).
- [x] JPEG carve (notes §9): 3 complete JPEGs + 4 header-only stubs; the `0x180000`
      "standalone boot logo" was a **stored 960×720 photo** — corrected.
- [x] SD-upgrade path identified, format confirmed, candidates built and emulator-verified.
- [x] **Refuted** the old "version @file 0x19 / checksum @file 0x26" model — `0x110B94` is a
      FILINFO whose `+0x12` is the filename. `JH5408_v*` / `v[CDE]_*` are dead ends; do not flash.
- [x] G+ IDE extracted, confirmed it has no SD-upgrade packer (only USB ISP plus GPZP/preview tool).
- [x] Git repo initialized (local-only), binary tracked via LFS, `uv`/`pyproject.toml` env.

---

## 6. GPNV non-volatile records (`0x170000`) — donor-dump contrast (2026-09-10)

Trigger: a second, independent 2 MiB dump (`../Project-Sirius/Original_Firmware.bin`).
Full write-up in notes §11; short form:

- **Firmware identical.** `0x000000`–`0x170200` is byte-identical between the two dumps
  (`md5 e4c462a67812fac70025e38cc800c875`); every md5 difference is device state after the
  resource partition — GPNV records, photo index, stored photos. (So md5 alone is *not* a
  firmware-identity test on these dumps.)
- **GPNV store found** at `0x170000`, `0x200`-byte slots: donor 12, `charmera.bin` 1
  (slot 0 identical in both). Markers `"GPNV"` (`0xF3BC0`), `"CAM05_"`, `"12345678"`;
  RAM struct `0x1107DC`; load path `0x1F89C` → `0x23E60` → `0xF0820`.
- **Checksum solved:** `+0xFC..0xFF` = big-endian IEEE CRC-32 over `+0x00..0xFB` (12/12
  donor records). Firmware CRC-32 routine at `0x1FB0C` (poly `0xEDB88320`).
- **Photo index found** at `0x17F000` — `(u32 slot, u32 size)` LE; entries match the carved
  JPEG sizes (see §1 open questions).
- Still open: field semantics (`0x00`–`0x51`), ring bound/policy, CRC enforced on read?,
  `CAM05_` == model string?

---

## 7. Peripherals + video codec (scouting pass 2026-09-11)

### Peripherals — what we know
- **Sensor: unnamed.** No `GC*/OV*/SC*/SP0A*/HM*/IMX*/BF3*` part string anywhere; programmed
  only via the SoC's CDSP/ISP block (`drv_l2_cdsp_open` `0x6a3e0`, `sensor_preview_init`
  `0x6c368`), AE/AWB `GP$ v1.5.0 ... by Comi 20200318` (`0x97548`). No sensor init table in
  flash → naming it needs a physical teardown. Encoder offers QVGA…12M (`0xf3880`).
- **Display: `GPLIB_VIDMUX`** (`0xb7764`, build 2018/08/30), panel part **unknown** (no
  `ST77xx`/`ILI9xxx`/`GC9xxx`/`NT35xxx`, no panel init sequence). UI art is 160×80.
- WiFi = SSV6158 host + SSV6020 PHY; flash 2 MiB SPI NOR; SD via FatFs; audio WAV only.
- Full write-up: notes §12.

### Video: AVI is a container; codec is MJPEG; MP4 is mux/dec only
- `C:\DCIM\MOVI%04d.avi` written by `AviPackerV3` (RIFF/AVI muxer, banner @ `0x8c540`).
- Codec = **MJPEG** — supported-name list at `0xfc84` is `XVID M4S2 H263 MJPG`; hardware JPEG
  block (`Disp_Mjpeg_Init` `0x106c8`, `drv_l1_jpeg_*`). So AVI is just the wrapper; frames are
  hardware JPEGs, no interframe compression.
- MP4/MOV **muxers are present** (`vidMP4HeaderInit H264` `0xb38a4`, full ISO-BMFF boxes,
  `MovPacker` `0x90cb0`+) but only for **decode/playback** — no H.264 encoder in the image.
  So "record MP4" is not a config toggle; there's no HW H.264 encoder to enable.
- Notes §13.

### Codec feasibility (done this pass — notes §14)
- **CPU has no FPU/SIMD.** ~222k insns of real code disassemble with no genuine VFP/NEON
  (the few `v*` hits are cond=0xF aliases on data), and zero `clz`/`rev`/`ldrex`/`movw`.
  Plain ARM9-class core, soft-float — no vector unit for a SW codec.
- **RAM ≈ 640 KB total**, shared (boot zero-fills `0x10AF30`+`0xA3820`). No DDR.
  Flash headroom ~660 KB clean (`0x185F00`–`0x200000` is the bulk).
- **No HW encoder beyond JPEG.** `XVID M4S2 H263 MJPG` (`0xfc84`) sits next to
  `vid_dec_set_aud_dec_work_mem` → it is a **decode** list, and none of the FourCCs appears
  as a code constant anywhere. Media block `0xD0800000` (202 refs / 191 funcs) is driven by
  the `drv_l1_jpeg_*` (baseline-JPEG: quant/Huffman/VLC) module — no SPS/PPS/rate-control.
- **Verdict:** MP4 recording is neither a config flag nor a "link in a lib" job. Practical
  file-size lever is MJPEG frame size/rate + JPEG quantisation (`0x1093xx`).

### Open questions
- Name sensor + panel from a teardown (package/flex markings).
- **The one real codec lead:** if a sibling GPCV product records MP4/MOV, this SoC may have
  an MPEG-4 *encode* mode the product driver never initialises — a driver/muxer job, not an
  encoder job. Test: diff a sibling's `0xD0800000` register sequence against this one.
- WiFi-strip feasibility: quantify recoverable bytes and the call-site re-pointing needed
  (see §8).

---

## 8. Future: reclaiming space (idea, not started)

The unit has **no WiFi hardware**, yet the image carries the SSV6158/6020 stack + lwIP +
DHCP/DNS/AP-STA MLME (path strings `0xf8c27`–`0xfe1ef`, lwIP `0x3a4e2`–`0xf5776`). Stripping
it is the obvious way to free flash/RAM for custom code, but it is a real linker-style job:
- [ ] Map the WiFi/lwIP code extents (not just strings) and the RAM pool it reserves
      (`gp_wifi_malloc*`).
- [ ] Find the top-level wifi init/start call sites and neuter them cleanly (boot must still
      reach the mode queue).
- [ ] Remove the string pool + tables, keep the `SPII` image bootable and flashable.
- [ ] Re-verify the SD-updater path after any such strip (it lives near this code).

---

## Key references
- `REVERSE_ENGINEERING_NOTES.md` — full findings, region map, corrected upgrade format, emulator.
- `scripts/find_xrefs.py` — recursive disassembler + xref map (use this for any
  "who calls / who references X" question; `--callers`, `--refs`, `--disasm`, `--strings`).
- `scripts/emu_updater.py` (validate), `scripts/build_upgrade_files.py` (build),
  `scripts/patch_boot_mode.py` (boot-to-photo patch).
- `scripts/arm_disasm.py`, `firmware_analysis.py`, `extract_gpz_assets.py`.
- Binary: `charmera.bin` (LFS-tracked); `patched/` holds generated images (gitignored).

_Updated: 2026-09-11 (peripherals inventory + video codec findings — §7/notes §12–13)_
