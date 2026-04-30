# intentguard attester SDK

This package is the easiest way for protocol developers to try the attester flow before hardware exists.

It gives you:

- `buildIntentBundle`: canonical render plus intent hash.
- `createEmulatorAttester`: software-only attester for demos and CI.
- `verifyEmulatorAttestation`: local verification for test flows.

The emulator is not a production signer. Its key lives in the host process. Use it to integrate the API shape, write tests, and demo governance flows.

## Quick start

```ts
import { buildIntentBundle, createEmulatorAttester } from "@intentguard/attester-sdk";

const bundle = buildIntentBundle({
  network: "solana",
  vault,
  nonce: 1n,
  actionKind: 1,
  actionArgs,
});

console.log(bundle.rendered.lines);

const attester = createEmulatorAttester();
const approval = await attester.attest(bundle);

console.log(Buffer.from(approval.signature).toString("hex"));
```

See `examples/basic.ts` for a complete whitelist-collateral emulator flow.

## Protocol integration checklist

1. Define a narrow `actionKind`.
2. Add a renderer adapter with strict byte-length checks.
3. Add shared test vectors.
4. Require attester signatures in the guard before queueing.
5. Use the emulator in CI.
6. Switch signers to hardware or secure-enclave attesters for production.
