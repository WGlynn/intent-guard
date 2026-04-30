# Security

This fork is **unaudited reference work**, same as upstream. Don't deploy as-is to secure funds.

## Reporting

Issues with the fork's adapters or integration scaffolding: open a private security advisory at https://github.com/WGlynn/intent-guard/security/advisories/new, or reach the maintainer at the GitHub profile.

Issues with the upstream module, spec, or whitepaper: file at https://github.com/uwecerron/intent-guard/security/advisories.

## What this fork's threat model covers

The adapters in `contracts/` aim to make dishonesty unprofitable across these admin surfaces:

| Surface | Adapter | Class of attack defended |
|---|---|---|
| UUPS upgrades | `UUPSUpgradeAdapter` | Pre-signed approval → impl swap (CREATE2 + SELFDESTRUCT redeployment) |
| Treasury | `DAOTreasuryAdapter` | Recipient substitution, asset substitution, cap evasion |
| LayerZero peers | `CrossChainPeerAdapter` | Peer-substitution attack on inbound message authentication |
| AccessControl roles | `RoleGrantAdapter` | Privilege-escalation grants, removal of frozen roles |
| Pausable | `PausableAdapter` | Lock-the-protocol pause without unpause |
| Ownership | `OwnershipTransferAdapter` | Transfer to attacker, accidental renunciation |
| Numeric params | `BoundedParameterAdapter` | Bounds-violating values, drift-attack ratio defeats |
| Allowlist roots | `MerkleRootSetAdapter` | Malicious-root substitution at signing time |

What each adapter *cannot* defend against — same caveats as the module:

- Total signer collusion at threshold + no veto raised
- Smart-contract bugs in the guarded protocol itself (the adapter only gates the privileged call path)
- Compromised signer device that the human is fooled by even with fresh on-chain typed-intent rendering
- Bridge or RPC compromise that delivers false context

## Known gaps in this fork

- `IntentGuardModule.sol` is unaudited. The stack-depth refactor (PR upstream) preserves behavior but has not been independently reviewed.
- Each new adapter has unit + integration coverage but has not been independently reviewed.
- Integration test for the stale-signature path is stubbed; the freshness invariant has unit-level coverage in the module but a follow-up debug pass is needed for the end-to-end signing flow.
- `slither` / `mythril` / formal verification has not been run on this fork's contracts.

## Disclosure window

For non-critical issues, please allow 30 days for triage and remediation before public disclosure. For critical issues, contact directly and we'll triage immediately.

## License

Reporting a vulnerability does not constitute a license grant. Findings remain the reporter's intellectual property.
