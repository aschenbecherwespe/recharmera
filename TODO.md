# CHARMERA RE — TODO / status

Status page for the firmware-modding project. Companion to `REVERSE_ENGINEERING_NOTES.md` and `scripts/`.

---

## 1. Active goal: get a valid SD-card upgrade file (solved, pending hardware run)

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
- [ ] **Recover the camera** (in this order):
      1. external programmer write-back of `charmera.bin` (SOIC8 clip / desolder);
      2. USB ISP via `GPDevFWUpdater.dll` from the G+ IDE, if the boot ROM enters
         download mode (untested);
      3. try the SD path anyway with the correctly sized image (updater code survived at
         `0x20000`, but the firmware is broken at `0x010000`, so this is a long shot).
- [ ] **Never flash an image > 0x1E0000 bytes.** `build_upgrade_files.py` now truncates
      automatically and `emu_updater.py --stage write` verifies the whole erase/program
      sequence including the trailing sector.
- [ ] Once recovered and re-validated: patch a *real* change, rebuild (name recomputed),
      check with `--stage both` **and** `--stage write`, then flash.

### Open questions
- Internal photo store (`C:\SPIDCIM\SPI%02d.jpg`, `SPI_XX.JPG`): code confirms the feature,
  and `charmera.bin` holds exactly one 960×720 capture at `0x180000` (notes §9.1) with the
  rest of `0x180000`–`0x200000` erased and **no FAT wrapper**. Unresolved: is that slot a
  factory-leftover photo, or the first write of the internal store? Once the camera is
  recovered: shoot one photo with **no SD card**, re-dump, and diff `0x180000`–`0x200000`
  (a second image / an index at `0x186000` would settle it).
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
- [ ] Optional: repack the `SPII` dump cleanly into a `GP+` partition as a standalone base image.

---

## 3. Tooling / housekeeping

- [x] `scripts/build_upgrade_files.py` — rewritten for the confirmed format (emits the file
      **and** its canonical name; computes the whole-file byte sum).
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

## 4. Committed / done (no more action unless noted)

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

## Key references
- `REVERSE_ENGINEERING_NOTES.md` — full findings, region map, corrected upgrade format, emulator.
- `scripts/emu_updater.py` (validate), `scripts/build_upgrade_files.py` (build).
- `scripts/arm_disasm.py`, `firmware_analysis.py`, `extract_gpz_assets.py`.
- Binary: `charmera.bin` (LFS-tracked).

_Updated: 2026-09 (emulator session)_
