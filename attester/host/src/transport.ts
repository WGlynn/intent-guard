// USB CDC (serial-over-USB) transport for talking to the attester device.
//
// Uses `serialport` for cross-platform support. WebSerial is the obvious
// alternative for in-browser use; the same protocol layer (./protocol.ts)
// can be wired to either.
//
// In v0.1 the host opens the serial port, writes a framed request, and
// reads framed responses until it sees the response with the matching
// proposal_id. This is intentionally simple: one request in flight at a
// time, no streaming.

import { SerialPort } from "serialport";
import { frame, unframe, cborDecode, cborEncode, type CborValue } from "./protocol.js";

export interface AttesterDevice {
  call(message: CborValue, timeoutMs?: number): Promise<{ [k: string]: CborValue }>;
  close(): Promise<void>;
}

/**
 * Open a serial connection to an attester device. Returns a `call`
 * function that round-trips one message and resolves the response.
 *
 * @param path  Serial port path. On macOS typically `/dev/tty.usbmodem*`,
 *              on Linux `/dev/ttyACM*`, on Windows `COM*`.
 */
export async function openDevice(path: string): Promise<AttesterDevice> {
  const port = await new Promise<SerialPort>((resolve, reject) => {
    const p = new SerialPort({ path, baudRate: 115200 }, (err) => {
      if (err) reject(err);
      else resolve(p);
    });
  });

  let buffer = new Uint8Array(0);
  const waiters: Array<(payload: { [k: string]: CborValue }) => void> = [];

  port.on("data", (data: Buffer) => {
    const merged = new Uint8Array(buffer.length + data.length);
    merged.set(buffer);
    merged.set(data, buffer.length);
    buffer = merged;

    while (true) {
      const out = unframe(buffer);
      if (out === null) break;
      buffer = out.rest;
      if (out.payload.length === 0) continue; // resync
      try {
        const decoded = cborDecode(out.payload);
        const w = waiters.shift();
        if (w) w(decoded.value as { [k: string]: CborValue });
      } catch (err) {
        console.error("decode error:", err);
      }
    }
  });

  return {
    async call(message, timeoutMs = 90_000) {
      const payload = cborEncode(message);
      const framed = frame(payload);
      await new Promise<void>((resolve, reject) =>
        port.write(Buffer.from(framed), (err) => (err ? reject(err) : resolve())),
      );
      return new Promise((resolve, reject) => {
        const timer = setTimeout(() => {
          const idx = waiters.indexOf(resolve as never);
          if (idx >= 0) waiters.splice(idx, 1);
          reject(new Error("device call timed out"));
        }, timeoutMs);
        waiters.push((v) => {
          clearTimeout(timer);
          resolve(v);
        });
      });
    },
    async close() {
      return new Promise<void>((resolve) => port.close(() => resolve()));
    },
  };
}

/**
 * Software-only emulator. Behaves like a connected device but signs in
 * memory. Useful for protocols that haven't bought hardware yet, and for
 * CI tests. Tier 0 deployment per BUILD.md.
 *
 * SECURITY WARNING: the emulator's signing key lives in the host process.
 * This defeats the whole point of the attester. Use ONLY for development.
 */
export async function openEmulator(): Promise<AttesterDevice> {
  const { ed25519 } = await import("@noble/curves/ed25519");
  const key = ed25519.utils.randomPrivateKey();
  const pubkey = ed25519.getPublicKey(key);

  const handlers: Record<string, (msg: { [k: string]: CborValue }) => { [k: string]: CborValue }> = {
    Hello: () => ({
      type: "HelloAck",
      firmware_ver: "emulator-0.1",
      curves: "ed25519",
      device_pubkey: pubkey,
    }),
    Enroll: () => ({ type: "EnrollAck", device_pubkey: pubkey }),
    ProposeIntent: (msg) => {
      const intentHash = msg["intent_hash"] as Uint8Array;
      const signedAt = BigInt(Math.floor(Date.now() / 1000));
      // Build digest matching SPEC §5 (simplified for emulator).
      const digest = new Uint8Array(32);
      const ih = intentHash;
      for (let i = 0; i < 32; i++) digest[i] = ih[i]!;
      const sig = ed25519.sign(digest, key);
      return {
        type: "IntentAck",
        proposal_id: msg["proposal_id"] as Uint8Array,
        signature: sig,
        device_pubkey: pubkey,
        signed_at: signedAt,
        firmware_ver: "emulator-0.1",
      };
    },
  };

  return {
    async call(message) {
      const m = message as { [k: string]: CborValue };
      const type = m["type"] as string;
      const handler = handlers[type];
      if (!handler) throw new Error(`emulator: no handler for ${type}`);
      console.log(`[emulator] ${type} -> auto-confirming`);
      return handler(m);
    },
    async close() {
      /* nothing to do */
    },
  };
}
