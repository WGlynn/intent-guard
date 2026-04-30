// Adapter registry. Action kinds are looked up by their numeric ID, the same
// number that intentguard uses on-chain.

import type { CanonicalIntent, RenderedIntent } from "../schema.js";
import { whitelistCollateralAdapter } from "./whitelist-collateral.js";
import { transferAdminAdapter } from "./transfer-admin.js";

export interface Adapter {
  actionKind: number;
  actionKindName: string;
  /** Decode the raw action_args bytes into a canonical intent object. Must be deterministic. */
  decode(bytes: Uint8Array): CanonicalIntent;
  /** Render the decoded intent for human display. */
  render(intent: CanonicalIntent): RenderedIntent;
}

const REGISTRY = new Map<number, Adapter>();

export function registerAdapter(a: Adapter): void {
  if (REGISTRY.has(a.actionKind)) {
    throw new Error(`adapter for action_kind=${a.actionKind} already registered`);
  }
  REGISTRY.set(a.actionKind, a);
}

export function getAdapter(actionKind: number): Adapter | undefined {
  return REGISTRY.get(actionKind);
}

// Built-in adapters.
registerAdapter(whitelistCollateralAdapter);
registerAdapter(transferAdminAdapter);

export const ADAPTERS = REGISTRY;
