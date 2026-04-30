import { buildIntentBundle, createEmulatorAttester, verifyEmulatorAttestation } from "../src/index.js";

const actionArgs = new Uint8Array(80);
actionArgs.fill(0xab, 0, 32);
new DataView(actionArgs.buffer).setBigUint64(32, 1_000_000n, true);
actionArgs.fill(0xcd, 40, 72);
new DataView(actionArgs.buffer).setBigUint64(72, 500_000_000n, true);

const vault = new Uint8Array(32);
vault.fill(0x11);

const bundle = buildIntentBundle({
  network: "solana",
  vault,
  nonce: 1n,
  actionKind: 1,
  actionArgs,
});

console.log(bundle.rendered.actionKindName);
for (const line of bundle.rendered.lines) {
  console.log(`${line.label}: ${line.value}`);
}

const attester = createEmulatorAttester();
const approval = await attester.attest(bundle, { signedAt: 1_900_000_000n });

console.log("device pubkey:", hex(approval.devicePubkey));
console.log("signature:", hex(approval.signature));
console.log("verified:", verifyEmulatorAttestation(approval));

function hex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("hex");
}
