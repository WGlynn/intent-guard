# Attester test vectors

Run this from `attester/renderer` after dependencies are installed:

```sh
npm run vectors
```

The generator writes `generated.json` with:

- raw `actionArgsHex`,
- rendered lines,
- canonical bytes,
- Solana or EVM intent hash.

Every new adapter should add at least three vectors:

1. a normal proposal,
2. a boundary-value proposal,
3. a malformed payload that must be rejected.

Use the generated vectors in:

- TypeScript renderer tests,
- firmware renderer tests,
- EVM verifier tests,
- Solana verifier tests,
- auditor review notes.
