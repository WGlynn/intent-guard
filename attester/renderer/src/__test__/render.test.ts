// Lightweight self-test (no test framework). Run with `npm test` from the
// renderer/ directory. Confirms decode+render+canonical hash are stable.

import { renderIntent, computeIntentHash } from "../render.js";

let passed = 0;
let failed = 0;

function eq<T>(name: string, actual: T, expected: T): void {
  const a = JSON.stringify(actual);
  const b = JSON.stringify(expected);
  if (a === b) {
    passed++;
    console.log(`✓ ${name}`);
  } else {
    failed++;
    console.error(`✗ ${name}\n  expected: ${b}\n  actual:   ${a}`);
  }
}

// --- WhitelistCollateral ---
{
  const args = new Uint8Array(80);
  for (let i = 0; i < 32; i++) args[i] = 0xab;       // token
  new DataView(args.buffer).setBigUint64(32, 1_000_000n, true); // fair_value_usd_micros = 1.00
  for (let i = 40; i < 72; i++) args[i] = 0xcd;      // oracle
  new DataView(args.buffer).setBigUint64(72, 500_000_000n, true); // max_deposit_usd

  const rendered = renderIntent({
    network: "solana",
    vault: new Uint8Array(32),
    nonce: 1n,
    actionKind: 1,
    actionArgs: args,
  });

  eq("WhitelistCollateral name", rendered.actionKindName, "WHITELIST_COLLATERAL");
  eq("WhitelistCollateral lines.length", rendered.lines.length, 4);
  eq("WhitelistCollateral fair value", rendered.lines[1]!.value, "$1.00");

  // Hash determinism.
  const h1 = computeIntentHash({
    network: "solana", vault: new Uint8Array(32), nonce: 1n, actionKind: 1, actionArgs: args,
  });
  const h2 = computeIntentHash({
    network: "solana", vault: new Uint8Array(32), nonce: 1n, actionKind: 1, actionArgs: args,
  });
  eq("WhitelistCollateral hash deterministic", Buffer.from(h1).toString("hex"), Buffer.from(h2).toString("hex"));

  // Different network → different hash.
  const hEvm = computeIntentHash({
    network: "evm", vault: new Uint8Array(32), nonce: 1n, actionKind: 1, actionArgs: args,
  });
  eq("WhitelistCollateral hash differs by network",
    Buffer.from(h1).toString("hex") !== Buffer.from(hEvm).toString("hex"), true);
}

// --- TransferAdmin ---
{
  const args = new Uint8Array(32);
  for (let i = 0; i < 32; i++) args[i] = 0xee;
  const rendered = renderIntent({
    network: "evm",
    vault: new Uint8Array(20),
    nonce: 42n,
    actionKind: 3,
    actionArgs: args,
  });
  eq("TransferAdmin name", rendered.actionKindName, "TRANSFER_ADMIN");
  eq("TransferAdmin lines.length", rendered.lines.length, 1);
}

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed > 0 ? 1 : 0);
