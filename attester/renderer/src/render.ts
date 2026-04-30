// Canonical intent computation and rendering.

import { sha256 } from "@noble/hashes/sha256";
import { keccak_256 } from "@noble/hashes/sha3";
import type { CanonicalIntent, RenderedIntent } from "./schema.js";
import { getAdapter } from "./adapters/index.js";

const DOMAIN_SEP = "intentguard.v1.attest";

export interface IntentInput {
  network: "solana" | "evm";
  vault: Uint8Array;
  nonce: bigint;
  actionKind: number;
  actionArgs: Uint8Array;
}

/**
 * Decode + render in one step. This is what the host bridge calls before
 * sending a proposal to the device, and what the device firmware calls
 * after receiving one. Both sides MUST produce identical output for the
 * same input or the attester will refuse to sign.
 */
export function renderIntent(input: IntentInput): RenderedIntent {
  const adapter = getAdapter(input.actionKind);
  if (!adapter) {
    throw new Error(`no adapter registered for action_kind=${input.actionKind}`);
  }
  const canonical = adapter.decode(input.actionArgs);
  return adapter.render(canonical);
}

/**
 * Compute the canonical intent hash. Must match the on-chain guard exactly.
 *
 * Layout:
 *   H(
 *     domain_sep_bytes ||
 *     vault ||
 *     u64_le(nonce) ||
 *     u32_le(action_kind) ||
 *     canonical_serialise(decoded_intent)
 *   )
 *
 * `H` is sha256 on Solana, keccak_256 on EVM.
 */
export function computeIntentHash(input: IntentInput): Uint8Array {
  const adapter = getAdapter(input.actionKind);
  if (!adapter) {
    throw new Error(`no adapter registered for action_kind=${input.actionKind}`);
  }
  const canonical = adapter.decode(input.actionArgs);
  const canonicalBytes = canonicalSerialise(canonical);

  const parts: Uint8Array[] = [
    new TextEncoder().encode(DOMAIN_SEP),
    input.vault,
    u64LE(input.nonce),
    u32LE(input.actionKind),
    canonicalBytes,
  ];
  const buf = concat(parts);
  return input.network === "solana" ? sha256(buf) : keccak_256(buf);
}

/**
 * Canonical serialisation rule:
 *   - Object: keys sorted ascending by UTF-8 bytes, then for each key
 *     encode `length-prefixed key bytes` followed by encoded value.
 *   - String: 0x01 || varint(len) || utf8 bytes
 *   - Bytes: 0x02 || varint(len) || raw bytes
 *   - u64:   0x03 || 8 bytes little-endian
 *   - i64:   0x04 || 8 bytes little-endian (two's complement)
 *   - bool:  0x05 || 0x00 or 0x01
 *   - bigint (positive, fits in u128): 0x06 || 16 bytes little-endian
 *   - object: 0x10 || varint(field_count) || repeat (key + value)
 *
 * Designed to be deterministic, easy to implement in no_std Rust, and
 * hostile to ambiguity. NOT designed to be human-readable; use `renderIntent`
 * for that.
 */
export function canonicalSerialise(v: CanonicalIntent | unknown): Uint8Array {
  if (v === null || v === undefined) {
    throw new Error("canonicalSerialise: null/undefined not allowed");
  }
  if (typeof v === "string") {
    const bytes = new TextEncoder().encode(v);
    return concat([Uint8Array.of(0x01), varint(bytes.length), bytes]);
  }
  if (v instanceof Uint8Array) {
    return concat([Uint8Array.of(0x02), varint(v.length), v]);
  }
  if (typeof v === "number") {
    if (!Number.isInteger(v)) throw new Error("canonicalSerialise: non-integer number");
    if (v < 0) {
      const buf = new ArrayBuffer(8);
      new DataView(buf).setBigInt64(0, BigInt(v), true);
      return concat([Uint8Array.of(0x04), new Uint8Array(buf)]);
    }
    const buf = new ArrayBuffer(8);
    new DataView(buf).setBigUint64(0, BigInt(v), true);
    return concat([Uint8Array.of(0x03), new Uint8Array(buf)]);
  }
  if (typeof v === "bigint") {
    if (v < 0n) throw new Error("canonicalSerialise: negative bigint not yet supported");
    const out = new Uint8Array(16);
    let n = v;
    for (let i = 0; i < 16; i++) {
      out[i] = Number(n & 0xffn);
      n >>= 8n;
    }
    if (n !== 0n) throw new Error("canonicalSerialise: bigint exceeds u128");
    return concat([Uint8Array.of(0x06), out]);
  }
  if (typeof v === "boolean") {
    return concat([Uint8Array.of(0x05), Uint8Array.of(v ? 1 : 0)]);
  }
  if (typeof v === "object") {
    const obj = v as Record<string, unknown>;
    const keys = Object.keys(obj).sort();
    const parts: Uint8Array[] = [Uint8Array.of(0x10), varint(keys.length)];
    for (const k of keys) {
      const keyBytes = new TextEncoder().encode(k);
      parts.push(varint(keyBytes.length));
      parts.push(keyBytes);
      parts.push(canonicalSerialise(obj[k] as CanonicalIntent));
    }
    return concat(parts);
  }
  throw new Error(`canonicalSerialise: unsupported value of type ${typeof v}`);
}

// ----- byte helpers -----

function u32LE(n: number): Uint8Array {
  const buf = new ArrayBuffer(4);
  new DataView(buf).setUint32(0, n, true);
  return new Uint8Array(buf);
}

function u64LE(n: bigint): Uint8Array {
  const buf = new ArrayBuffer(8);
  new DataView(buf).setBigUint64(0, n, true);
  return new Uint8Array(buf);
}

function varint(n: number): Uint8Array {
  const out: number[] = [];
  let x = n;
  while (x >= 0x80) {
    out.push((x & 0x7f) | 0x80);
    x >>>= 7;
  }
  out.push(x & 0x7f);
  return Uint8Array.from(out);
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
