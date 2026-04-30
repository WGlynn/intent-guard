// Adapter for action_kind = 1, "WhitelistCollateral".
//
// Wire layout of action_args:
//   token:           [u8; 32]  (Solana mint or EVM address right-padded)
//   fair_value_usd_micros: u64 (fixed-point with 6 decimals, e.g. 1.00 USD = 1_000_000)
//   oracle:          [u8; 32]  (oracle account / feed identifier)
//   max_deposit_usd: u64
//
// = 32 + 8 + 32 + 8 = 80 bytes exactly.

import type { Adapter } from "./index.js";
import type { CanonicalIntent, RenderedIntent } from "../schema.js";

const ACTION_KIND = 1;

export const whitelistCollateralAdapter: Adapter = {
  actionKind: ACTION_KIND,
  actionKindName: "WHITELIST_COLLATERAL",

  decode(bytes: Uint8Array): CanonicalIntent {
    if (bytes.length !== 80) {
      throw new Error(`WHITELIST_COLLATERAL: expected 80 bytes, got ${bytes.length}`);
    }
    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    return {
      token: bytes.slice(0, 32),
      fair_value_usd_micros: dv.getBigUint64(32, true),
      oracle: bytes.slice(40, 72),
      max_deposit_usd: dv.getBigUint64(72, true),
    };
  },

  render(intent: CanonicalIntent): RenderedIntent {
    const token = intent["token"] as Uint8Array;
    const oracle = intent["oracle"] as Uint8Array;
    const fair = intent["fair_value_usd_micros"] as bigint;
    const cap = intent["max_deposit_usd"] as bigint;

    return {
      actionKindName: "WHITELIST_COLLATERAL",
      lines: [
        { label: "Token", value: hex(token) },
        { label: "Fair value (USD)", value: formatUsd(fair), severity: "danger" },
        { label: "Oracle", value: hex(oracle), severity: "warn" },
        { label: "Max deposit (USD)", value: cap.toString() },
      ],
      warning: "Adding collateral. Confirm fair value matches the live oracle.",
    };
  },
};

function hex(bytes: Uint8Array): string {
  // Show first 4 + last 4 bytes; the device truncates further if needed.
  if (bytes.length <= 8) return Buffer.from(bytes).toString("hex");
  const head = Buffer.from(bytes.slice(0, 4)).toString("hex");
  const tail = Buffer.from(bytes.slice(-4)).toString("hex");
  return `${head}..${tail}`;
}

function formatUsd(micros: bigint): string {
  const dollars = micros / 1_000_000n;
  const cents = micros % 1_000_000n;
  return `$${dollars}.${String(cents).padStart(6, "0").slice(0, 2)}`;
}
