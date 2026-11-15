# Panasonic Lumix DC-GH5 — Firmware 2.8 Reverse Engineering

Working notes on the GH5 firmware update, its service/EEPROM data, and what is and
isn't possible. **Goal that started this:** get **false color** (an exposure tool) on
a regular Photo Style.

**Bottom line:** the firmware can be *understood* but not *modified* — decryption needs
a key fused into the camera's chip (not in the file), and reflashing is blocked by an
ECDSA signature. False color is achievable today without any of that, via V-Log View
Assist (see [False color](#false-color-the-actual-answer)).

**Long-term goal:** Magic-Lantern-like access to the GH5. This started as "get false
color on a regular Photo Style" and turned into mapping the firmware. The two blockers
below (in-silicon key, ECDSA signature) are where the community effort needs to go.

**Help wanted:** anyone with GH5 hardware-hacking skills — UART/JTAG on the mainboard to
dump decrypted firmware from a running camera, boot-ROM key extraction, or an existing
decrypted GH5 image. See [why decryption is blocked](#encryption--why-decryption-is-blocked).

> **Not in this repo (on purpose):** the Panasonic firmware binary (`*.bin`,
> copyrighted — download it from Panasonic) and the EEPROM dumps (`GH5U/F/A.TXT`, which
> contain a specific camera's serial number and calibration). The `inspect_gh5_upd.py`
> parser runs against a firmware `.bin` you supply yourself.

---

## Files in this folder

| File | What it is |
|---|---|
| `GH5__V28.bin` | Official firmware 2.8 update, 68,246,016 bytes, `UPD` container, model `MC561` |
| `GH5U.TXT` | EEPROM dump, **UPDATE** area — user region (settings, counters incl. shutter count) |
| `GH5A.TXT` | EEPROM dump, **ADJUST** area — factory sensor/IBIS/AF calibration |
| `GH5F.TXT` | EEPROM dump, **FIX** area — serial, model, fixed flags |
| `inspect_gh5_upd.py` | Read-only parser for the `UPD` container (verified) |

The three `.TXT` files were written by the camera's hidden service menu
(**ROM BACKUP → DSC→SD**). Despite the extension they are 64 KB EEPROM images printed
as hex-in-text, each with a `###### EEPROM DATA INFORMATION ######` header. They are
per-camera data, **not** firmware code.

---

## Service mode (how the EEPROM dumps were made)

- Enter: single-shot drive mode, then hold **PLAYBACK + AF/AE LOCK** while powering on.
  Confirm by Setup (wrench) menu → last page shows **ERR CODE DISP**.
- The **ROM BACKUP** screen moves EEPROM between camera (`DSC`) and card (`SD`):
  - `DSC→SD` — dump camera EEPROM to card (safe, read-only). Produced the `.TXT` files.
  - `SDALL→DSC (ID CHECK)` — restore, only if backup matches this serial (the safe undo).
  - `SDALL/SDUSER→DSC (FORCE)` — restore with **no** serial check (risky).
  - `ADJFLAG→ALL F` — mark all calibration "not done" (**very risky**, may need a service centre).
- Exit: power off.

> Warning: back up V-Log L before service mode if installed — it can be deactivated and
> need a fresh key. The FORCE / ADJFLAG options can leave the camera needing factory
> recalibration. Everything in this repo was read-only; nothing was written to the camera.

---

## Firmware container format (reverse-engineered)

The `GH5__V28.bin` update is a Panasonic `UPD` container, same family as the
`flwrgirl/lumix-g9-firmware` research project (that one was the G9, model `MC471`).

### Header (offset 0x00)
```
0x00  'UPD\0'
0x0C  'MC561'              model code
0x3C  u32 = 0x04115A00     total file size
0x2E8 u8  = 0x28           component count (40)
```

### Directory — 40 entries starting at 0x2EC, stride 0x5C (92) bytes
```
+0x00  name[12]            ascii, null-padded
+0x0C  u32 fileoff         offset of component data, relative to base 0x200
+0x10  u32 size            component size in bytes
+0x14  u32 loadaddr        RAM load/exec address  <- use as Ghidra base address
+0x18  u32 type            3 = encrypted code, 2 = data/empty
+0x1C  sha[32]             per-component hash (SHA-256, inferred)
+0x3C  iv[16]              per-component AES-128-CBC IV
```

**Verification:** component regions are perfectly contiguous and the last one ends
exactly at EOF (`0x4115A00`). Run `python inspect_gh5_upd.py GH5__V28.bin`.

### Component map

| name | file offset | size | RAM loadaddr | type | notes |
|---|---|---|---|---|---|
| loader1 | 0x00001200 | 0x0001000 | 0x00000000 | 3 | first boot stage |
| loader2 | 0x00002200 | 0x0005800 | 0x00001000 | 3 | |
| loader3 | 0x00007A00 | 0x000C000 | 0x00006800 | 3 | |
| **program** | 0x00013A00 | 0x09C0000 | 0x00080000 | 3 | **main ARM firmware (~10 MB); menu/profile logic** |
| storage | 0x009D3A00 | 0 | 0x00CA0000 | 2 | empty placeholder |
| postboot1 | 0x009D3A00 | 0x0460000 | 0x00CA0000 | 3 | |
| postboot3 | 0x00E33A00 | 0x0020000 | 0x017E0000 | 3 | |
| postboot4 | 0x00E53A00 | 0x0020000 | 0x01800000 | 3 | |
| postboot5 | 0x00E73A00 | 0x00C0000 | 0x01820000 | 3 | |
| dram_sleep | 0x00F33A00 | 0x0001800 | 0x018E0000 | 3 | |
| eep_ow_a/b | 0x00F35200 | 0x0020000 | 0x01900000 | 3 | eeprom overwrite |
| eep_adj | 0x00F75200 | 0x0020000 | 0x01940000 | 3 | |
| eep_fix | 0x00F95200 | 0x0020000 | 0x01960000 | 3 | |
| eep_act_a/b | 0x00FB5200 | 0x0000800 | 0x01980000 | 3 | |
| music | 0x00FB6200 | 0x0360000 | 0x01A00000 | 3 | startup sound |
| osdover | 0x01316200 | 0x0800000 | 0x01D60000 | 3 | on-screen graphics |
| osddata | 0x01B16200 | 0x0900000 | 0x02560000 | 3 | on-screen graphics |
| koutei_kao | 0x02416200 | 0x001C000 | 0x02FE0000 | 3 | factory ("koutei") data |
| avchd_info | 0x02432200 | 0x0004000 | 0x03000000 | 2 | plaintext (zero-fill) |
| eep_net_a/b | 0x02436200 | 0x0020000 | 0x03020000 | 2 | plaintext (zero-fill) |
| zboot | 0x02476200 | 0x0000800 | 0x030A0000 | 3 | Linux boot |
| dtb | 0x02476A00 | 0x0001000 | 0x030A0800 | 3 | device tree |
| zimage | 0x02477A00 | 0x0280000 | 0x030C0000 | 3 | Linux kernel |
| rootfs1 | 0x026F7A00 | 0x0400000 | 0x03340000 | 3 | root filesystem |
| rootfs2 | 0x02AF7A00 | 0x0C00000 | 0x03740000 | 3 | root filesystem |
| apu0_data/code_i/e | 0x036F7A00 | 0x0010000–0x20000 | 0x04340000+ | 3 | audio DSP |
| ipu_data | 0x03757A00 | 0x0040000 | 0x043A0000 | 3 | **Image Processing Unit data** |
| **ipu_code** | 0x03797A00 | 0x0010000 | 0x043E0000 | 3 | **Image Processing Unit code — where a LUT is applied to pixels** |
| rc_data/code | 0x037A7A00 | 0x0040000/0x10000 | 0x04400000 | 3 | raw/resolution convert |
| nr_data/code | 0x037F7A00 | 0x0040000/0x10000 | 0x04460000 | 3 | noise reduction |
| sound_data | 0x03847A00 | 0x018E000 | 0x044C0000 | 3 | |
| postboot2 | 0x039D5A00 | 0x0740000 | 0x04660000 | 3 | |

The GH5 runs embedded Linux (`zimage` + `rootfs1/2`) plus the ARM `program` and several
DSP blobs (`ipu`, `rc`, `nr`, `apu`). The photo pipeline is `program` + `ipu_code`.

---

## Encryption / why decryption is blocked

- Every **type-3** component is AES-128-CBC encrypted (measured entropy ~7.9–8.0),
  **including `loader1`**, the first stage the chip runs.
- The only plaintext components (`avchd_info`, `eep_net_a/b`, type 2) are **zero-fill**
  placeholders — no code, no key.
- The AES key is stored *inside* the encrypted `program` (the G9 project found the G9
  key at an offset in its already-decrypted program — circular for us).
- `loader1` is unsealed only by the **SoC boot ROM using a key fused into the silicon**,
  which is not present in the update file.

**Therefore the update cannot be decrypted from the file alone.** Bootstrapping the key
requires hardware-level work:
1. A RAM dump of the decrypted firmware off a **running** GH5 (UART/JTAG console) — the
   Magic-Lantern-style route. Needs opening the camera and soldering to a debug port.
2. Extracting the fused boot-ROM key (voltage glitching / decap) — lab work.
3. An existing community dump of a decrypted GH5 image.

## Why modification is blocked even if decrypted

The update carries an **ECDSA directory signature**. No private signing key is public,
and the G9 research explicitly did **not** bypass it ("modified-update acceptance and
signature bypass are not established"). So a modified image cannot be flashed to the
camera. This project is **read/understand only**, never modify-and-reflash.

---

## LUT engine on the GH5

The GH5 **does** have an in-camera monitor LUT engine: **V-Log View Assist** loads a
`.vlt` LUT and previews it on the LCD/EVF/HDMI (preview only; recording stays V-Log).
It is **firmware-gated to V-Log L mode** — the menu only appears when the Photo Style is
V-Log L. Ungating it to regular profiles would require editing `program` and reflashing,
which the signature blocks.

## False color — the actual answer

False color is just a LUT that maps brightness to colors, so use the engine where it's
already unlocked. **No firmware work needed:**

1. Install **V-Log L** (paid upgrade DMW-SFU1 — required for View Assist).
2. Get a false-color `.vlt` (e.g. IWLTBAP's free one).
3. Copy the `.vlt` to the **top level** of the SD card.
4. Camera: Photo Style → **V-Log L**, then **Menu → V-Log View Assist → Read LUT File**.
5. Shoot V-Log L — false color shows on the monitor as a preview overlay.

The only thing not possible: false color over a **baked regular profile** (Standard,
Cinelike, etc.), because that needs ungating the LUT engine = modified firmware = blocked.
Newer bodies (S5 II / GH7 / G9 II) have Real-time LUT on regular profiles natively.

---

## Status

| Item | State |
|---|---|
| `UPD` container format | ✅ reverse-engineered + verified |
| Component map (offsets/sizes/load addrs) | ✅ done, Ghidra-ready |
| Firmware decryption | ❌ blocked — key is in-silicon, not in the file |
| Modify + reflash | ❌ blocked — ECDSA signature |
| False color (goal) | ✅ achievable via V-Log View Assist, no hacking |

## Tools / references

- `inspect_gh5_upd.py` — this repo's container parser.
- `flwrgirl/lumix-g9-firmware` — the G9 (MC471) research this builds on. Documents the
  same AES-128-CBC + ECDSA scheme; no key, flasher, or signature bypass published.
- Ghidra (ARM/Thumb) — for disassembly *if* a decrypted `program`/`ipu_code` is obtained.
