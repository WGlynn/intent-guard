#!/usr/bin/env node
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { ADAPTERS } from "../adapters/index.js";
import { canonicalSerialise, computeIntentHash, renderIntent } from "../render.js";

interface VectorSource {
  name: string;
  network: "solana" | "evm";
  vault: Uint8Array;
  nonce: bigint;
  actionKind: number;
  actionArgs: Uint8Array;
}

const sources: VectorSource[] = [
  whitelistCollateralBasic(),
  transferAdminBasic(),
];

const vectors = sources.map((source) => {
  const adapter = ADAPTERS.get(source.actionKind);
  if (!adapter) throw new Error(`missing adapter for action_kind=${source.actionKind}`);
  const decoded = adapter.decode(source.actionArgs);
  const rendered = renderIntent(source);
  const canonical = canonicalSerialise(decoded);
  const intentHash = computeIntentHash(source);
  return {
    name: source.name,
    network: source.network,
    vaultHex: hex(source.vault),
    nonce: source.nonce.toString(),
    actionKind: source.actionKind,
    actionName: rendered.actionKindName,
    actionArgsHex: hex(source.actionArgs),
    renderedLines: rendered.lines,
    warning: rendered.warning,
    canonicalHex: hex(canonical),
    intentHashHex: hex(intentHash),
  };
});

const outDir = join(new URL("../../..", import.meta.url).pathname, "vectors");
mkdirSync(outDir, { recursive: true });
writeFileSync(join(outDir, "generated.json"), JSON.stringify(vectors, null, 2) + "\n");
console.log(`wrote ${vectors.length} vectors to ${join(outDir, "generated.json")}`);

function whitelistCollateralBasic(): VectorSource {
  const actionArgs = new Uint8Array(80);
  actionArgs.fill(0xab, 0, 32);
  new DataView(actionArgs.buffer).setBigUint64(32, 1_000_000n, true);
  actionArgs.fill(0xcd, 40, 72);
  new DataView(actionArgs.buffer).setBigUint64(72, 500_000_000n, true);
  const vault = new Uint8Array(32);
  vault.fill(0x11);
  return {
    name: "whitelist_collateral_basic",
    network: "solana",
    vault,
    nonce: 1n,
    actionKind: 1,
    actionArgs,
  };
}

function transferAdminBasic(): VectorSource {
  const actionArgs = new Uint8Array(32);
  actionArgs.fill(0xee);
  const vault = new Uint8Array(20);
  vault.fill(0x22);
  return {
    name: "transfer_admin_basic",
    network: "evm",
    vault,
    nonce: 42n,
    actionKind: 3,
    actionArgs,
  };
}

function hex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("hex");
}
