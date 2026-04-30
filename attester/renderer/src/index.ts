// Public API of the attester renderer.
//
// This is the *canonical* renderer used by both the host bridge (TypeScript)
// and mirrored in the device firmware (Rust). The rule is simple: the host
// renderer and the firmware renderer must produce the same canonical intent
// hash for the same input, otherwise the attester rejects the proposal as
// `IntentMismatch`.
//
// To add a new action kind:
//   1. Add a schema entry to ./schema.ts
//   2. Add a decoder under ./adapters/<your-action-kind>.ts
//   3. Register it in ./adapters/index.ts
//   4. Mirror the decoder in firmware/src/adapters/<same-name>.rs
//   5. Add a regression test in ./__test__/

export { renderIntent, computeIntentHash } from "./render.js";
export type { IntentSchema, RenderedIntent, RenderLine } from "./schema.js";
export { ADAPTERS, registerAdapter, getAdapter } from "./adapters/index.js";
export type { Adapter } from "./adapters/index.js";
