#!/usr/bin/env node
// CLI for the attester host bridge.
//
//   attester enroll   --port <serial-path> | --emulator
//   attester attest   --port <serial-path> | --emulator
//                     --network <solana|evm>
//                     --vault <hex>
//                     --nonce <u64>
//                     --action-kind <u32>
//                     --action-args-hex <hex>
//
// `enroll` returns the device pubkey. `attest` runs the full propose →
// confirm → signature flow and prints the signature for the caller to
// bundle into intentguard.attest.

import { renderIntent, computeIntentHash } from "@intentguard/attester-renderer";
import { openDevice, openEmulator, type AttesterDevice } from "./transport.js";

interface Args {
  cmd: "enroll" | "attest" | "emulate";
  port?: string;
  emulator: boolean;
  network: "solana" | "evm";
  vault?: string;
  nonce?: string;
  actionKind?: string;
  actionArgsHex?: string;
}

function parseArgs(argv: string[]): Args {
  const a: Args = { cmd: "attest", emulator: false, network: "solana" };
  if (argv[0] === "enroll" || argv[0] === "attest" || argv[0] === "emulate") {
    a.cmd = argv[0];
  }
  for (let i = 1; i < argv.length; i++) {
    const k = argv[i];
    const v = argv[i + 1];
    if (k === "--port") { a.port = v; i++; }
    else if (k === "--emulator") { a.emulator = true; }
    else if (k === "--network") { a.network = (v === "evm" ? "evm" : "solana"); i++; }
    else if (k === "--vault") { a.vault = v; i++; }
    else if (k === "--nonce") { a.nonce = v; i++; }
    else if (k === "--action-kind") { a.actionKind = v; i++; }
    else if (k === "--action-args-hex") { a.actionArgsHex = v; i++; }
  }
  return a;
}

async function openTarget(a: Args): Promise<AttesterDevice> {
  if (a.emulator) return openEmulator();
  if (!a.port) {
    throw new Error("either --port <path> or --emulator must be specified");
  }
  return openDevice(a.port);
}

async function main(): Promise<void> {
  const a = parseArgs(process.argv.slice(2));

  if (a.cmd === "emulate") {
    const dev = await openEmulator();
    const r = await dev.call({ type: "Hello" });
    console.log("emulator pubkey:", hex(r["device_pubkey"] as Uint8Array));
    await dev.close();
    return;
  }

  const dev = await openTarget(a);

  if (a.cmd === "enroll") {
    const r = await dev.call({ type: "Enroll" });
    const pk = r["device_pubkey"] as Uint8Array;
    console.log("");
    console.log("============================================================");
    console.log("  ENROLLMENT");
    console.log("  Compare the pubkey below against what the device displays");
    console.log("  on its own screen. They MUST match.");
    console.log("============================================================");
    console.log("");
    console.log("  device pubkey:", hex(pk));
    console.log("");
    console.log("  Submit this pubkey to your intentguard vault as an");
    console.log("  attester for your signer entry.");
    console.log("");
    await dev.close();
    return;
  }

  if (a.cmd === "attest") {
    if (!a.vault || !a.nonce || !a.actionKind || !a.actionArgsHex) {
      throw new Error("attest requires --vault, --nonce, --action-kind, --action-args-hex");
    }
    const vault = unhex(a.vault);
    const nonce = BigInt(a.nonce);
    const actionKind = Number(a.actionKind);
    const actionArgs = unhex(a.actionArgsHex);

    // 1. Render locally and compute the canonical intent hash. The host
    //    renderer must produce the same intent the device will produce; if
    //    the device decodes differently, the device rejects with IntentMismatch.
    const rendered = renderIntent({ network: a.network, vault, nonce, actionKind, actionArgs });
    const intentHash = computeIntentHash({ network: a.network, vault, nonce, actionKind, actionArgs });

    console.log("\nLocal render preview (this is what the device should display):\n");
    console.log("  action:", rendered.actionKindName);
    for (const line of rendered.lines) {
      console.log(`  ${line.label.padEnd(22)} ${line.value}`);
    }
    if (rendered.warning) console.log(`\n  ⚠ ${rendered.warning}\n`);

    // 2. Send the proposal to the device.
    const proposalId = randomBytes(16);
    const signedAt = BigInt(Math.floor(Date.now() / 1000));
    const expiresAt = signedAt + 600n;

    console.log("Sending to device. Read its screen carefully and press CONFIRM if it matches.\n");

    const r = await dev.call({
      type: "ProposeIntent",
      proposal_id: proposalId,
      network: a.network,
      vault,
      nonce,
      action_kind: actionKind,
      action_args: actionArgs,
      intent_hash: intentHash,
      signed_at: signedAt,
      expires_at: expiresAt,
      domain_sep: "intentguard.v1.attest",
    }, 120_000);

    if (r["type"] === "IntentReject") {
      console.error("Device rejected:", r["reason"]);
      await dev.close();
      process.exit(2);
    }
    if (r["type"] !== "IntentAck") {
      console.error("Unexpected response:", r);
      await dev.close();
      process.exit(2);
    }

    const sig = r["signature"] as Uint8Array;
    const pk = r["device_pubkey"] as Uint8Array;
    const dev_signed_at = r["signed_at"] as bigint;

    console.log("\n────────────────────────────────────────────────────");
    console.log("  ATTESTER SIGNATURE");
    console.log("────────────────────────────────────────────────────");
    console.log("  pubkey:    ", hex(pk));
    console.log("  signed_at: ", dev_signed_at.toString());
    console.log("  signature: ", hex(sig));
    console.log("\n  Bundle this with your wallet signature when calling");
    console.log("  intentguard.attest(...).");

    await dev.close();
  }
}

function hex(b: Uint8Array): string {
  return Array.from(b).map((x) => x.toString(16).padStart(2, "0")).join("");
}

function unhex(s: string): Uint8Array {
  const clean = s.startsWith("0x") ? s.slice(2) : s;
  if (clean.length % 2 !== 0) throw new Error(`hex length not even: ${s}`);
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.substr(i * 2, 2), 16);
  }
  return out;
}

function randomBytes(n: number): Uint8Array {
  const out = new Uint8Array(n);
  for (let i = 0; i < n; i++) out[i] = Math.floor(Math.random() * 256);
  return out;
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
