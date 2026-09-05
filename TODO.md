# CHARMERA RE — TODO / status

Status page for the firmware-modding project. Companion to `REVERSE_ENGINEERING_NOTES.md` and `scripts/`.

---

## 1. Active goal: get a valid SD-card upgrade file (in progress)

The camera's SD upgrade (`C:\JH_5408*.bin`) is the only in-field path (no CH341A programmer available).

### Confirmed so far
- Firmware: Generalplus GPCV, ARM, WH5408/JH5408, 2 MiB SPI flash (`SPII` container).
- Updater looks for `C:\JH_5408*.bin` at the **SD card root** (FAT32).
- Version at file offset `0x19` **must differ** from `202505201029` → camera attempts upgrade.
  - **Matching** version → camera silently ignores the file (this burned earlier attempts — patching the version to match disabled the upgrade).
- Flasher (`0x21370`) byte-sums the file and compares to an 8-hex-char value parsed from the header; mismatch = fail **before** any flash write (safe).
- Write is 1:1: file offset N → flash offset N, erase+program in 0x400-byte sectors.

### Next steps (in priority order)
- [ ] **Test `vC_whole.bin`** (version differs + whole-file byte-sum at `0x26`).
  - rename to `JH_5408.bin`, SD root, FAT32, ≤32 GB card, boot camera, observe.
- [ ] If still "Program error check file" → try `vD_body.bin` (sum after `0x30`).
- [ ] If still failing → determine exact byte-sum coverage:
      - Scripts already make variants; extend `scripts/build_upgrade_files.py` with more ranges (e.g. `0x00..0x26`, xor-vs-add) as needed.
- [ ] Confirm the byte-sum source: `RAM 0x110b94+0x26` — who fills it (caller state), from which file offset.
- [ ] Once a file is accepted: verify flash completes AND camera boots the (near-identical, header-patched) image.
- [ ] Then: figure out how to make a **new** image that changes behavior (see section 2).

### Open questions
- Exact byte-sum coverage/algorithm (most likely : whole file, mod 2³², but unverified).
- Whether version at `0x19` must differ to be *any* other string, or specifically a "newer" build.
- SD card / FAT32 vs exFAT still unconfirmed on the hardware.

---

## 2. Future deeper goals

This is the reason for the whole project — editing what the camera does.

- [ ] Modify **boot logo** (`POWER_ON_LOGO.jpg` in `assets/`) → need to repack JPEG back into the `GP+` filesystem (likely needs GPZP codec for newly-encoded images).
- [ ] Modify **UI assets** (`.gpzp` files — 35 of them in `assets/`) → need the GPZP codec.
    - Lead: `GImagePreviewer.exe` (in `G+ IDE` extraction) — inspect whether it can encode/decode.
- [ ] Modify **behavior/code** (e.g. disable the "Select program" / make camera always start recording?) — deep: patch ARM binary, recompute header, rebuild upgrade file. Not near-term.
- [ ] Optional: repack the `SPII` dump cleanly into `GP+` partition to have a standalone base image.

## 3. Tooling / housekeeping

- [ ] `scripts/build_upgrade_files.py` — add param for checksum range (extend the variants).
- [ ] `scripts/extract_gpz_assets.py` — already solid; could add a `--names-only` / manifest output.
- [ ] Add the GPZP codec disassembly (find the encode/decode routines in the ARM target) when time permits — that's the long-term unlock for asset modding.
- [ ] Check `GImagePreviewer.exe` behavior (does it pack GPZP, or only view?) — decides the repack route.

## 4. Committed / done (no more action unless noted)

- [x] Firmware analysis / region map (notes).
- [x] Assets extracted (35 `.gpzp`, 5 `.wav`, 3 `.jpg + `standalone`).
- [x] SD-upgrade path identified + first test files built.
- [x] G+ IDE extracted, confirmed it has no SD-upgrade packer (only USB ISP plus GPZP/preview tool).
- [x] Git repo initialized (local-only), binary tracked via LFS, `uv`/`pyproject.toml` env.

---

## Key references
- `REVERSE_ENGINEERING_NOTES.md` — full findings & region map.
- `scripts/arm_disasm.py`, `firmware_analysis.py`, `build_upgrade_files.py`, `extract_gpz_assets.py`.
- Binary: `charmera.bin` (LFS-tracked).

_Updated: 2026-01 (session)_