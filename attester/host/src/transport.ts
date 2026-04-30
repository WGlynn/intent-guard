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
import { sha256 } from "@noble/hashes/sha256";
import { keccak_256 } from "@noble/hashes/sha3";
import { frame, unframe, cborDecode, cborEncode, type CborValue } from "./protocol.js";

const DOMAIN_SEP = "intentguard.v1.attest";

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
  type Waiter = {
    resolve: (payload: { [k: string]: CborValue }) => void;
    reject: (err: Error) => void;
    timer: ReturnType<typeof setTimeout>;
  };
  const waiters: Waiter[] = [];

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
        if (w) {
          clearTimeout(w.timer);
          w.resolve(decoded.value as { [k: string]: CborValue });
        }
      } catch (err) {
        const w = waiters.shift();
        if (w) {
          clearTimeout(w.timer);
          w.reject(err instanceof Error ? err : new Error(String(err)));
        } else {
          console.error("decode error:", err);
        }
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
      return new Promise<{ [k: string]: CborValue }>((resolve, reject) => {
        const waiter: Waiter = {
          resolve,
          reject,
          timer: setTimeout(() => {
            const idx = waiters.indexOf(waiter);
            if (idx >= 0) waiters.splice(idx, 1);
            reject(new Error("device call timed out"));
          }, timeoutMs),
        };
        waiters.push(waiter);
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
      const signedAt = BigInt(Math.floor(Date.now() / 1000));
      const digest = attestDigest({
        network: asNetwork(msg["network"]),
        vault: asBytes(msg["vault"], "vault"),
        nonce: asBigInt(msg["nonce"], "nonce"),
        actionKind: asNumber(msg["action_kind"], "action_kind"),
        intentHash: asBytes(msg["intent_hash"], "intent_hash"),
        signedAt,
      });
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

interface DigestInput {
  network: "solana" | "evm";
  vault: Uint8Array;
  nonce: bigint;
  actionKind: number;
  intentHash: Uint8Array;
  signedAt: bigint;
}

function attestDigest(input: DigestInput): Uint8Array {
  if (input.intentHash.length !== 32) throw new Error("intent_hash must be 32 bytes");
  const parts = [
    new TextEncoder().encode(DOMAIN_SEP),
    input.vault,
    u64LE(input.nonce),
    u32LE(input.actionKind),
    input.intentHash,
    u64LE(input.signedAt),
  ];
  const buf = concat(parts);
  return input.network === "solana" ? sha256(buf) : keccak_256(buf);
}

function asNetwork(v: CborValue | undefined): "solana" | "evm" {
  if (v === "solana" || v === "evm") return v;
  throw new Error("network must be solana or evm");
}

function asBytes(v: CborValue | undefined, name: string): Uint8Array {
  if (v instanceof Uint8Array) return v;
  throw new Error(`${name} must be bytes`);
}

function asBigInt(v: CborValue | undefined, name: string): bigint {
  if (typeof v === "bigint") return v;
  if (typeof v === "number") return BigInt(v);
  throw new Error(`${name} must be an integer`);
}

function asNumber(v: CborValue | undefined, name: string): number {
  if (typeof v === "number") return v;
  if (typeof v === "bigint") {
    const n = Number(v);
    if (Number.isSafeInteger(n)) return n;
  }
  throw new Error(`${name} must be a safe integer`);
}

function u32LE(n: number): Uint8Array {
  if (!Number.isInteger(n) || n < 0 || n > 0xffffffff) {
    throw new Error("u32 out of range");
  }
  const buf = new ArrayBuffer(4);
  new DataView(buf).setUint32(0, n, true);
  return new Uint8Array(buf);
}

function u64LE(n: bigint): Uint8Array {
  if (n < 0n || n > 0xffffffffffffffffn) throw new Error("u64 out of range");
  const buf = new ArrayBuffer(8);
  new DataView(buf).setBigUint64(0, n, true);
  return new Uint8Array(buf);
}

function concat(parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((a, p) => a + p.length, 0);
  const out = new Uint8Array(total);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}
