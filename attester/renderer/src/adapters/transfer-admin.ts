// Adapter for action_kind = 3, "TransferAdmin".
//
// Wire layout of action_args:
//   new_admin: [u8; 32]  (Solana pubkey or EVM address right-padded)
//
// = 32 bytes.

import type { Adapter } from "./index.js";
import type { CanonicalIntent, RenderedIntent } from "../schema.js";

const ACTION_KIND = 3;

export const transferAdminAdapter: Adapter = {
  actionKind: ACTION_KIND,
  actionKindName: "TRANSFER_ADMIN",

  decode(bytes: Uint8Array): CanonicalIntent {
    if (bytes.length !== 32) {
      throw new Error(`TRANSFER_ADMIN: expected 32 bytes, got ${bytes.length}`);
    }
    return {
      new_admin: bytes.slice(0, 32),
    };
  },

  render(intent: CanonicalIntent): RenderedIntent {
    const newAdmin = intent["new_admin"] as Uint8Array;
    return {
      actionKindName: "TRANSFER_ADMIN",
      lines: [
        { label: "New admin", value: hex(newAdmin), severity: "danger" },
      ],
      warning: "Transferring administrative control. Verify the destination off-band before confirming.",
    };
  },
};

function hex(bytes: Uint8Array): string {
  if (bytes.length <= 8) return Buffer.from(bytes).toString("hex");
  const head = Buffer.from(bytes.slice(0, 6)).toString("hex");
  const tail = Buffer.from(bytes.slice(-6)).toString("hex");
  return `${head}..${tail}`;
}
