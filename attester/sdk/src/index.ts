import { ed25519 } from "@noble/curves/ed25519";
import { sha256 } from "@noble/hashes/sha256";
import { keccak_256 } from "@noble/hashes/sha3";
import { TextEncoder } from "node:util";
import { computeIntentHash, renderIntent, type RenderedIntent } from "@intentguard/attester-renderer";

const DOMAIN_SEP = "intentguard.v1.attest";

export type Network = "solana" | "evm";

export interface BuildIntentBundleInput {
  network: Network;
  vault: Uint8Array;
  nonce: bigint;
  actionKind: number;
  actionArgs: Uint8Array;
}

export interface IntentBundle extends BuildIntentBundleInput {
  intentHash: Uint8Array;
  rendered: RenderedIntent;
}

export interface AttesterApproval {
  network: Network;
  vault: Uint8Array;
  nonce: bigint;
  actionKind: number;
  intentHash: Uint8Array;
  signature: Uint8Array;
  devicePubkey: Uint8Array;
  signedAt: bigint;
  firmwareVer: string;
}

export interface EmulatorAttester {
  publicKey: Uint8Array;
  attest(bundle: IntentBundle, options?: { signedAt?: bigint }): Promise<AttesterApproval>;
}

export function buildIntentBundle(input: BuildIntentBundleInput): IntentBundle {
  return {
    ...input,
    intentHash: computeIntentHash(input),
    rendered: renderIntent(input),
  };
}

export function createEmulatorAttester(seed?: Uint8Array): EmulatorAttester {
  const privateKey = seed ?? ed25519.utils.randomPrivateKey();
  if (privateKey.length !== 32) throw new Error("emulator seed must be 32 bytes");
  const publicKey = ed25519.getPublicKey(privateKey);

  return {
    publicKey,
    async attest(bundle, options) {
      const signedAt = options?.signedAt ?? BigInt(Math.floor(Date.now() / 1000));
      const digest = attesterDigest({
        network: bundle.network,
        vault: bundle.vault,
        nonce: bundle.nonce,
        actionKind: bundle.actionKind,
        intentHash: bundle.intentHash,
        signedAt,
      });
      return {
        network: bundle.network,
        vault: bundle.vault,
        nonce: bundle.nonce,
        actionKind: bundle.actionKind,
        intentHash: bundle.intentHash,
        signature: ed25519.sign(digest, privateKey),
        devicePubkey: publicKey,
        signedAt,
        firmwareVer: "emulator-0.1",
      };
    },
  };
}

export function verifyEmulatorAttestation(approval: AttesterApproval): boolean {
  const digest = attesterDigest({
    network: approval.network,
    vault: approval.vault,
    nonce: approval.nonce,
    actionKind: approval.actionKind,
    intentHash: approval.intentHash,
    signedAt: approval.signedAt,
  });
  return ed25519.verify(approval.signature, digest, approval.devicePubkey);
}

export function attesterDigest(input: {
  network: Network;
  vault: Uint8Array;
  nonce: bigint;
  actionKind: number;
  intentHash: Uint8Array;
  signedAt: bigint;
}): Uint8Array {
  if (input.intentHash.length !== 32) throw new Error("intentHash must be 32 bytes");
  const buf = concat([
    new TextEncoder().encode(DOMAIN_SEP),
    input.vault,
    u64LE(input.nonce),
    u32LE(input.actionKind),
    input.intentHash,
    u64LE(input.signedAt),
  ]);
  return input.network === "solana" ? sha256(buf) : keccak_256(buf);
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
