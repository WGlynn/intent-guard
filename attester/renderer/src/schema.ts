// Type definitions for intent payloads, schemas, and rendered output.

/** A single line on the device display. */
export interface RenderLine {
  /** Label shown to the human. Short. */
  label: string;
  /** Value shown next to the label. Will be truncated on small screens. */
  value: string;
  /** Severity hint to the firmware UI: `info` is normal, `warn` is yellow, `danger` is red. */
  severity?: "info" | "warn" | "danger";
}

export interface RenderedIntent {
  /** Action kind name in capitals (e.g. "WHITELIST_COLLATERAL"). The user will be asked to type this to confirm. */
  actionKindName: string;
  /** Lines to display, in order. */
  lines: RenderLine[];
  /** Optional trailing summary banner. Useful to call out high-risk fields. */
  warning?: string;
}

/**
 * The canonical schema used to compute the intent hash. Every adapter must
 * produce a value that serializes through `canonicalSerialise` to the same
 * bytes as the on-chain guard's adapter for that action kind.
 *
 * Field naming is significant: keys are hashed in alphabetical order.
 */
export type CanonicalIntent = {
  [k: string]: string | number | bigint | boolean | Uint8Array | CanonicalIntent;
};

export interface IntentSchema {
  actionKind: number;
  actionKindName: string;
  /** A short human description; not security-critical. */
  description: string;
  /** Field names that should be highlighted as oracle-bound or otherwise dangerous. */
  highlight?: string[];
}
