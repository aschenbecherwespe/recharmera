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
      → **active, see §4** (boot straight into photo mode).
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

## 4. Goal 2 — boot straight into photo mode (app/UI layer)

**Want:** power-on goes directly to the camera/photo screen; today it shows the
"photo / video / settings" menu and you must pick photo every time.

**Verdict:** achievable — pure app logic, no signature anywhere. Static analysis done
2026-09-10; **nothing flashed yet**. Full write-up: notes §10.

### Confirmed (notes §10)
- Boot screen *is* the mode menu: display init `0x16ce8` installs draw handler
  **`0x1617c`** (via `0x1670c`), which draws `SELECT MODE` (`0x16474`, str id `0x98`) and
  loads the mode icons `PV0%02d.GPZP` in `0x14054` using `menu_cursor − 4`.
- **Menu cursor = RAM `0x10fbc5`** (`ctx 0x10fbc4` +1); 9 pool sites image-wide, 3 writers.
- **Active mode is a separate id**, low 9 bits of a message, stored at RAM **`0x110d1e`**.
- **Mode dispatcher = task slot `0x2d`**, body **`0x25868`**: decodes the id, stores it at
  `0x110d1e`, and switch-dispatches at `0x258e0`:
  `0x100`→`0x65b0` (USB/power), **`0x101`→`0x1c644` = video record** (`state_video_record_entry`),
  **`0x102`→`0x1d6fc` = still capture**, `0x104`/`0x105`/`0x10A`/`0x10B`/`0x10D`.
- **Menu index → mode id** (switch at `0x2552c`, func `0x2526c`):
  `1→0x102 (photo)`, `2→0x101 (video)`, `3→0x105`, `4→0x104`, `5→0x10B`, `6→0x10A`.
- `ap_display_init` `0x165ac` allocates exactly **4** screen slots.
- `GPRSPAK` string ids == ordinals from `+0x5E4`; ids `131 Photo`, `132 Video`,
  `142 PHOTO`, `143 VIDEO`, `149 SET DATE`, `152 SELECT MODE`, `0x54 NO CARD`.

### Next steps (in order)
- [ ] **Pin the boot-time mode sender.** Find what first posts a mode id to the queue ctx
      at `0x110d80`; users of that ctx: `0x1617c`, `0x1d6c0`, `0x24f7c`, `0x24ff0`,
      `0x2526c`, `0x25868`, `0x259f0`, `0x25a00`.
- [ ] Decode `PV000`–`PV003` (GPZP codec / `GImagePreviewer.exe`) to confirm the icon order
      matches the index→mode table (`1 = photo`).
- [ ] Patch (preferred → fallback): force the boot mode request to `0x102`; else auto-run
      the menu's OK path for photo; else default in the dispatcher.
- [ ] Rebuild with `build_upgrade_files.py`, validate `emu_updater.py --stage both` **and**
      `--stage write`, size ≤ `0x1E0000`, then flash (when the camera is recovered).
- [ ] Hardware-verify: power on → lands in photo, shutter works, menu still reachable.

### Tooling
- [x] `scripts/find_xrefs.py` — recursive ARM disassembler + xref map (reset vector +
      `stmfd` prologues + switch tables; ~193k insns / 4.6k funcs / 16k calls).
      Note: conditional `bl<cond>` must fall through — treating it as terminating silently
      truncates app functions (this hid the `0x1c644`/`0x1d6fc` callers).

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

## Key references
- `REVERSE_ENGINEERING_NOTES.md` — full findings, region map, corrected upgrade format, emulator.
- `scripts/find_xrefs.py` — recursive disassembler + xref map (use this for any
  "who calls / who references X" question; `--callers`, `--refs`, `--disasm`, `--strings`).
- `scripts/emu_updater.py` (validate), `scripts/build_upgrade_files.py` (build).
- `scripts/arm_disasm.py`, `firmware_analysis.py`, `extract_gpz_assets.py`.
- Binary: `charmera.bin` (LFS-tracked).

_Updated: 2026-09-10 (emulator session + app/UI pass — §4/notes §10: power-on mode menu)_
