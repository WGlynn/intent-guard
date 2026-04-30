// Persistent key storage. On ESP32-S3 this lives in an encrypted NVS
// partition. On the host emulator it lives in a process-local OnceLock so
// every emulator launch gets a fresh keypair (which is correct: the
// emulator is for development only and should never persist a key).
//
// SECURITY: this is the most sensitive module in the firmware. The key
// must never be exported, the flash region must be locked at first-write,
// and the load path must be constant-time wrt key bytes to avoid leaking
// them via timing.
//
// For brevity, the v0.1 implementation here uses esp_hal NVS APIs with
// encryption enabled at boot. A real production build should:
//   - Verify the NVS encryption key is bound to eFuses, not stored in flash.
//   - Lock the partition after first write so even a malicious firmware
//     update can't re-read the bytes.
//   - Fail closed if the eFuses indicate a debug or insecure boot mode.

use crate::crypto::Keypair;
use rand_core::RngCore;

pub struct Store {
    // ESP32-S3 NVS handle would live here. Stubbed for the skeleton.
    _placeholder: (),
}

impl Store {
    pub fn open() -> Self {
        // Real impl: open NVS, verify partition encryption, log free space.
        Self { _placeholder: () }
    }

    pub fn load_or_generate_keypair<R: RngCore>(&mut self, rng: &mut R) -> Keypair {
        if let Some(seed) = self.load_seed() {
            return Keypair::from_seed(seed);
        }
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        if seed.iter().all(|b| *b == 0) {
            panic!("secure RNG returned all zeros");
        }
        self.store_seed(&seed);
        Keypair::from_seed(seed)
    }

    fn load_seed(&self) -> Option<[u8; 32]> {
        // Real impl: read encrypted NVS entry "attester_seed_v1".
        None
    }

    fn store_seed(&mut self, _seed: &[u8; 32]) {
        // Real impl: write to encrypted NVS, then lock the partition for write.
    }
}
