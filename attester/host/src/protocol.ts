// Wire protocol implementation matching attester/SPEC.md §3 and §4.
//
//   | 0xA7 0x77 | u16 length BE | CBOR payload | u32 CRC32 BE |
//
// CBOR encoder/decoder is implemented inline here for the small subset we
// need (uint, bytes, text, map). This keeps the host bridge dependency-free
// for the wire layer, which matters because the same encoder is mirrored in
// the no_std firmware where pulling in a full CBOR crate is heavy.

const MAGIC_0 = 0xa7;
const MAGIC_1 = 0x77;

export type CborValue =
  | number
  | bigint
  | string
  | Uint8Array
  | boolean
  | { [k: string]: CborValue };

// ---------- Framing ----------

export function frame(payload: Uint8Array): Uint8Array {
  if (payload.length > 0xffff) throw new Error("payload too large");
  const out = new Uint8Array(2 + 2 + payload.length + 4);
  out[0] = MAGIC_0;
  out[1] = MAGIC_1;
  out[2] = (payload.length >> 8) & 0xff;
  out[3] = payload.length & 0xff;
  out.set(payload, 4);
  const crc = crc32(out.subarray(0, 4 + payload.length));
  out[4 + payload.length] = (crc >>> 24) & 0xff;
  out[5 + payload.length] = (crc >>> 16) & 0xff;
  out[6 + payload.length] = (crc >>> 8) & 0xff;
  out[7 + payload.length] = crc & 0xff;
  return out;
}

export function unframe(buf: Uint8Array): { payload: Uint8Array; rest: Uint8Array } | null {
  if (buf.length < 8) return null;
  if (buf[0] !== MAGIC_0 || buf[1] !== MAGIC_1) {
    // Skip one byte and let caller try again.
    return { payload: new Uint8Array(0), rest: buf.subarray(1) };
  }
  const length = ((buf[2]! << 8) | buf[3]!) & 0xffff;
  const total = 4 + length + 4;
  if (buf.length < total) return null;
  const payload = buf.subarray(4, 4 + length);
  const expectedCrc =
    (buf[4 + length]! << 24) |
    (buf[5 + length]! << 16) |
    (buf[6 + length]! << 8) |
    buf[7 + length]!;
  const actualCrc = crc32(buf.subarray(0, 4 + length));
  if ((expectedCrc >>> 0) !== (actualCrc >>> 0)) {
    throw new Error("CRC mismatch on framed payload");
  }
  return { payload, rest: buf.subarray(total) };
}

// ---------- CBOR (subset: uint, bytes, text, bool, map) ----------

export function cborEncode(v: CborValue): Uint8Array {
  if (typeof v === "boolean") return Uint8Array.of(v ? 0xf5 : 0xf4);
  if (typeof v === "number") {
    if (!Number.isInteger(v) || v < 0) throw new Error("only non-negative ints supported");
    return cborEncodeUint(0, BigInt(v));
  }
  if (typeof v === "bigint") {
    if (v < 0n) throw new Error("negative bigint not supported");
    return cborEncodeUint(0, v);
  }
  if (typeof v === "string") {
    const bytes = new TextEncoder().encode(v);
    return concat([cborEncodeUint(3, BigInt(bytes.length)), bytes]);
  }
  if (v instanceof Uint8Array) {
    return concat([cborEncodeUint(2, BigInt(v.length)), v]);
  }
  if (typeof v === "object") {
    const keys = Object.keys(v).sort();
    const parts: Uint8Array[] = [cborEncodeUint(5, BigInt(keys.length))];
    for (const k of keys) {
      parts.push(cborEncode(k));
      parts.push(cborEncode(v[k]!));
    }
    return concat(parts);
  }
  throw new Error(`cborEncode: unsupported value of type ${typeof v}`);
}

export function cborDecode(buf: Uint8Array): { value: CborValue; rest: Uint8Array } {
  const first = buf[0]!;
  const major = first >> 5;
  const info = first & 0x1f;
  const { value: len, rest: r1 } = readUint(info, buf.subarray(1));
  switch (major) {
    case 0: return { value: len, rest: r1 };
    case 2: {
      const n = Number(len);
      return { value: r1.subarray(0, n), rest: r1.subarray(n) };
    }
    case 3: {
      const n = Number(len);
      return { value: new TextDecoder().decode(r1.subarray(0, n)), rest: r1.subarray(n) };
    }
    case 5: {
      const out: { [k: string]: CborValue } = {};
      let cur = r1;
      for (let i = 0; i < Number(len); i++) {
        const k = cborDecode(cur);
        if (typeof k.value !== "string") throw new Error("non-string map key");
        const v = cborDecode(k.rest);
        out[k.value] = v.value;
        cur = v.rest;
      }
      return { value: out, rest: cur };
    }
    case 7:
      if (info === 20) return { value: false, rest: r1 };
      if (info === 21) return { value: true, rest: r1 };
      throw new Error(`unsupported simple value ${info}`);
    default:
      throw new Error(`unsupported CBOR major type ${major}`);
  }
}

// ---------- helpers ----------

function cborEncodeUint(major: number, n: bigint): Uint8Array {
  if (n < 24n) return Uint8Array.of((major << 5) | Number(n));
  if (n < 0x100n) return Uint8Array.of((major << 5) | 24, Number(n));
  if (n < 0x10000n) {
    const out = new Uint8Array(3);
    out[0] = (major << 5) | 25;
    new DataView(out.buffer).setUint16(1, Number(n));
    return out;
  }
  if (n < 0x100000000n) {
    const out = new Uint8Array(5);
    out[0] = (major << 5) | 26;
    new DataView(out.buffer).setUint32(1, Number(n));
    return out;
  }
  const out = new Uint8Array(9);
  out[0] = (major << 5) | 27;
  new DataView(out.buffer).setBigUint64(1, n);
  return out;
}

function readUint(info: number, rest: Uint8Array): { value: bigint; rest: Uint8Array } {
  if (info < 24) return { value: BigInt(info), rest };
  if (info === 24) return { value: BigInt(rest[0]!), rest: rest.subarray(1) };
  if (info === 25) {
    const v = new DataView(rest.buffer, rest.byteOffset, 2).getUint16(0);
    return { value: BigInt(v), rest: rest.subarray(2) };
  }
  if (info === 26) {
    const v = new DataView(rest.buffer, rest.byteOffset, 4).getUint32(0);
    return { value: BigInt(v), rest: rest.subarray(4) };
  }
  if (info === 27) {
    const v = new DataView(rest.buffer, rest.byteOffset, 8).getBigUint64(0);
    return { value: v, rest: rest.subarray(8) };
  }
  throw new Error(`unsupported additional info ${info}`);
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

// CRC-32 (IEEE polynomial 0xEDB88320, same as zlib).
function crc32(buf: Uint8Array): number {
  let crc = 0xffffffff;
  for (let i = 0; i < buf.length; i++) {
    crc ^= buf[i]!;
    for (let j = 0; j < 8; j++) crc = (crc >>> 1) ^ (0xedb88320 & -(crc & 1));
  }
  return (crc ^ 0xffffffff) >>> 0;
}
