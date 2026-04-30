# Hardware build guide

Three tiers, depending on how serious you are about real hardware.

| Tier | What it is                              | Cost  | Effort                | Use                                  |
| ---- | --------------------------------------- | ----- | --------------------- | ------------------------------------ |
| 0    | Pure software emulator                  | $0    | 5 min                 | Development, CI, demos               |
| 1    | M5Stack Cardputer (off-the-shelf)       | ~$30  | 30 min, no soldering  | Production for small councils        |
| 2    | Custom ESP32-S3 + IPS display + USB-C   | ~$20  | 2 hours, soldering    | Larger deployments, custom enclosure |

The protocol and firmware are the same across tiers 1 and 2. Tier 0 runs the same protocol over a software-only signing key, which **defeats the security goal** and is therefore for development only.

---

## Tier 0: software emulator

For protocols that want to test the integration before buying devices, or for CI tests.

```bash
cd attester/host
npm install
npm run emulate
```

The emulator generates an in-memory ed25519 keypair, prints its pubkey, and behaves like a real device for `Hello`, `Enroll`, and `ProposeIntent` messages. Auto-confirms every proposal.

**Do not use the emulator's pubkey in a production intentguard vault.** Anyone who runs your software has the signing key.

---

## Tier 1: M5Stack Cardputer

The recommended starting point. Off-the-shelf, $30, USB-C, 240x135 IPS display, 56-key QWERTY, side button, ESP32-S3-FN8 (8MB flash). No soldering, no enclosure design, ships in a small plastic case ready to use.

### Bill of materials

| Item                              | Where                              | Cost      |
| --------------------------------- | ---------------------------------- | --------- |
| M5Stack Cardputer (K128)          | shop.m5stack.com / mouser / digikey | ~$30 USD |
| USB-C to USB-A or USB-C cable     | already have one                   | $0        |

That's it.

### Flashing

1. Install the Rust nightly toolchain and the ESP32-S3 target:

   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   rustup install nightly
   rustup target add xtensa-esp32s3-none-elf --toolchain nightly
   cargo install espflash espup
   espup install
   . $HOME/export-esp.sh
   ```

2. Build and flash from the firmware directory:

   ```bash
   cd attester/firmware
   cargo build --release
   espflash flash --monitor target/xtensa-esp32s3-none-elf/release/attester
   ```

3. Plug the Cardputer into a USB port. It should appear as a serial device:

   - macOS: `/dev/tty.usbmodem*`
   - Linux: `/dev/ttyACM*`
   - Windows: `COM*` (uses the built-in `usbser.sys` driver)

4. Verify the firmware hash on first boot. The device prints its firmware SHA-256 to the screen at boot. Compare against the hash published in this repo's GitHub release. **If they don't match, do not enroll the device.**

5. Run enrollment from the host:

   ```bash
   cd ../host
   npm install
   npm run enroll -- --port /dev/tty.usbmodem<NN>
   ```

   The host prints the device's pubkey. The device prints the same pubkey on its screen. Compare them character by character. They must match. Then submit that pubkey to your intentguard vault as an attester for your signer entry.

### Operational notes

- Charge before long offline use (small internal battery).
- Keep the device in a known physical location. Loss is a key-rotation event.
- A dropped Cardputer is fine; a Cardputer that has been out of your sight for an extended period should be re-enrolled rather than reused.

---

## Tier 2: custom build

For councils that want a fixed-purpose device without the keyboard, or that want to put the attester in a custom enclosure.

### Bill of materials

| Component                                                  | Where                       | Cost     |
| ---------------------------------------------------------- | --------------------------- | -------- |
| ESP32-S3-WROOM-1U-N8 module (8MB flash, no PSRAM, U.FL ant)| Mouser / Digikey / LCSC     | ~$5      |
| 1.14" 240x135 IPS display, ST7789, SPI, 4-pin              | Adafruit / AliExpress       | ~$8      |
| USB-C breakout (USB 2.0 data, 5V power)                    | Adafruit                    | ~$2      |
| 2x momentary tactile buttons (CONFIRM, CANCEL)             | any electronics supplier    | $0.50    |
| 3.7V 500mAh LiPo + TP4056 charger                          | Adafruit                    | ~$5      |
| Hookup wire, perfboard, M3 standoffs                       | any                         | ~$2      |

Total: ~$22.50 + shipping.

### Wiring

```
ESP32-S3 pin   ->  peripheral
GPIO 9         ->  ST7789 SCK
GPIO 10        ->  ST7789 SDA (MOSI)
GPIO 11        ->  ST7789 RES
GPIO 12        ->  ST7789 DC
GPIO 13        ->  ST7789 CS
GPIO 14        ->  ST7789 BLK (backlight)

GPIO 4         ->  CONFIRM button (other leg to GND, internal pull-up)
GPIO 5         ->  CANCEL button (other leg to GND, internal pull-up)

USB D+/D-      ->  ESP32-S3 USB peripheral (built-in)
3V3, GND       ->  shared rails
LiPo +/-       ->  TP4056 BAT+/BAT-, output to 3V3 rail
```

The ESP32-S3 has built-in USB serial/JTAG, so no separate USB-to-serial chip is needed. The display, buttons, and battery management are the only off-module parts.

### Firmware target

Same firmware as Tier 1; reconfigure the GPIO pin map in `firmware/src/ui.rs` to match your wiring.

### Enclosure

Out of scope for v0.1. A 3D-printed shell with cutouts for the screen, two buttons, and the USB-C port works fine. STL files welcome as PRs.

---

## Verifying authenticity of a device you received from someone else

If a device was assembled or flashed by someone other than you, **assume it's compromised** until you've:

1. Wiped flash and re-flashed firmware you built yourself from this repo.
2. Verified the SHA-256 of the flashed firmware matches the published release.
3. Performed enrollment from your laptop and compared the pubkey on the device's screen against what your laptop received.

The supply chain for hardware attesters is exactly the kind of attack surface this primitive is supposed to defend against. Treat it accordingly.

---

## What's not covered yet

- A reference PCB design (Gerbers + KiCad).
- A signed firmware update mechanism (current firmware updates wipe the key by design; a real product needs in-place update with the signing key preserved, which adds significant complexity to the secure flash region).
- A reference enclosure.
- Production secure boot configuration (eFuse burning, signed bootloader).

PRs for any of the above are welcome.
