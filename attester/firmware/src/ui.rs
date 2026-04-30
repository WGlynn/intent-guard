// Display + buttons + clock + RNG abstractions.
//
// On the M5Stack Cardputer:
//   - Display is a 240x135 ST7789 IPS over SPI.
//   - Inputs are the built-in 56-key keyboard plus the side button.
//   - Clock is the ESP32-S3 RTC, persisted across deep sleep.
//   - RNG is the ESP32 hardware RNG (esp_hal::rng::Rng).
//
// This file is a skeleton: each method has the real shape but stubs the
// hardware-touching code. Filling these in is the main work for first
// flash.

use crate::render::{Line, Severity};

pub struct Hardware {
    pub display: Display,
    pub buttons: Buttons,
    pub clock: Clock,
    pub rng: Rng,
}

impl Hardware {
    pub fn init() -> Self {
        Self {
            display: Display::init(),
            buttons: Buttons::init(),
            clock: Clock::init(),
            rng: Rng::init(),
        }
    }
}

pub struct Display;
impl Display {
    pub fn init() -> Self { Self }

    pub fn show_boot(&mut self, _short_pubkey: &heapless::String<24>) {
        // Real impl: clear screen, draw "INTENTGUARD" header in white,
        // small "ready" status, pubkey short form at bottom.
    }

    pub fn show_enrollment(&mut self, _short_pubkey: &heapless::String<24>) {
        // Real impl: large text "ENROLLMENT", show full pubkey in 4-line
        // hex blocks for the user to compare against the host's display.
    }

    pub fn show_intent(&mut self, lines: &heapless::Vec<Line, 8>) {
        // Real impl: paint each line label/value, color by severity:
        //   Info -> white
        //   Warn -> yellow
        //   Danger -> red
        // Footer prompt: "ENTER = confirm | ESC = cancel".
        // Force at least 5 seconds before the confirm key is accepted on
        // Severity::Danger lines, so the user actually reads.
        let _ = lines;
    }

    pub fn show_complete(&mut self) {
        // Real impl: brief "SIGNED" splash, return to ready screen.
    }
}

pub struct Buttons;
impl Buttons {
    pub fn init() -> Self { Self }

    /// Block until the user presses CONFIRM (returns true) or CANCEL (false),
    /// up to `timeout_ms` milliseconds. Returns false on timeout.
    pub fn wait_for_confirm_or_cancel(&mut self, _timeout_ms: u32) -> bool {
        // Real impl: poll keyboard, debounce, watch for ENTER vs ESC.
        false
    }
}

pub struct Clock;
impl Clock {
    pub fn init() -> Self { Self }

    /// Seconds since some monotonic epoch. Need not match wall time.
    pub fn now_seconds(&self) -> u64 {
        // Real impl: read RTC.
        0
    }
}

pub struct Rng;
impl Rng {
    pub fn init() -> Self { Self }
}

impl rand_core::RngCore for Rng {
    fn next_u32(&mut self) -> u32 { 0 }
    fn next_u64(&mut self) -> u64 { 0 }
    fn fill_bytes(&mut self, _dest: &mut [u8]) { /* real impl: esp_hal::rng */ }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}
