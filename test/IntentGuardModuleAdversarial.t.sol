// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {IntentGuardModule, IActionAdapter} from "../contracts/IntentGuardModule.sol";

/// @notice Minimal Safe mock implementing only execTransactionFromModule.
/// @dev Used by all adversarial tests; mirrors the helper in IntegrationUUPS.t.sol.
contract MockSafe {
    error UnauthorizedModule();
    address public guard;

    function setGuard(address g) external {
        guard = g;
    }

    function execTransactionFromModule(address to, uint256 value, bytes calldata data, uint8)
        external
        payable
        returns (bool success)
    {
        if (msg.sender != guard) revert UnauthorizedModule();
        (success,) = to.call{value: value}(data);
    }

    receive() external payable {}
}

/// @notice Permissive mock adapter — any (target, value, data) is mapped to
/// `keccak256(abi.encode(target, value, keccak256(data)))`. Validate is a
/// no-op. Lets us probe the module's surface without dragging in real
/// adapter policy logic.
contract MockAdapter is IActionAdapter {
    function intentHash(address target, uint256 value, bytes calldata data) external pure returns (bytes32) {
        return keccak256(abi.encode(target, value, keccak256(data)));
    }

    function validate(address, uint256, bytes calldata, bytes32) external pure {
        return;
    }
}

/// @notice Mock target that the module will execute against. Records calls
/// and exposes a hook so we can drive reentrancy tests.
contract MockTarget {
    uint256 public callCount;
    bytes public lastData;

    /// Optional re-entrant call we make BACK into the module during a target
    /// call. Set by tests that want to probe reentrancy. If unset, target is
    /// a passive recorder.
    address public reentryModule;
    bytes public reentryCalldata;
    bool public reentryAttempted;
    bool public reentrySucceeded;
    bytes public reentryRevertData;

    function setReentry(address mod, bytes calldata cdata) external {
        reentryModule = mod;
        reentryCalldata = cdata;
    }

    fallback() external payable {
        callCount += 1;
        lastData = msg.data;

        if (reentryModule != address(0)) {
            reentryAttempted = true;
            (bool ok, bytes memory rd) = reentryModule.call(reentryCalldata);
            reentrySucceeded = ok;
            reentryRevertData = rd;
            // Clear so we don't re-enter on every subsequent call.
            reentryModule = address(0);
        }
    }

    receive() external payable {}
}

/// @notice Reusable signing payload — must match the encoding in
/// `_attestationDigest` exactly.
struct AttestPayload {
    bytes32 vaultId;
    uint64 vaultNonce;
    address target;
    uint256 value;
    bytes32 dataHash;
    bytes32 intentHash;
    address adapterAddr;
    uint64 signedAt;
    uint64 expiresAt;
}

/// @title IntentGuardModuleAdversarialTest
/// @notice Adversarial review suite for `contracts/IntentGuardModule.sol`.
///
/// Findings (real, marked `_findings_*`, skipped via `vm.skip(true)`):
///   F1: Signature `v` normalization accepts BOTH legacy `{27,28}` and
///       compact `{0,1}` forms for the SAME `(r,s)` — same signer recovers
///       from two distinct signature byte strings. On-chain effects bounded
///       by signer-as-dedup-key, but off-chain consumers must dedupe by
///       signer/digest, never by raw signature bytes.
///
/// Defensive regressions (assert-correct-behavior, all green):
///   - initializeVault: rejects address(0) signer, rejects duplicate
///     signers, rejects threshold==0 / vetoThreshold==0, rejects
///     threshold > signers.length, rejects vetoThreshold > signers.length,
///     rejects minProposalLifetimeSecs < cooloffSecs+executeDelaySecs,
///     and ALLOWS vetoThreshold > threshold (documented policy choice —
///     stricter veto liveness).
///   - queue: rejects unknown vault, unknown adapter, intent-hash mismatch,
///     proposalExpiresAt below the floor; verifies ALL attestations
///     when length > threshold (no trailing-skip), reverts on duplicate
///     proposal slot reuse.
///   - cancel: scoped to the proposal's vault — a signer of vault A
///     cannot cancel vault B's proposal; per-signer dedup blocks the
///     same signer counting twice; cancelled state is terminal (cannot
///     re-queue identical params).
///   - execute: dataHash check rejects mutated data; nonce gate rejects
///     a stale proposal whose nonce no longer matches the vault; CEI
///     ordering blocks double-execute via reentrancy.
///   - _verifyAttestations: strict-ascending order rejects address(0)
///     in the signer slot AND rejects unsorted signers.
///   - _attestationDigest: cross-chain bound (chainid) and cross-module
///     bound (address(this)) — attestations cannot be replayed across
///     either dimension.
///
/// No `contracts/IntentGuardModule.sol` modifications. F1 fix belongs in
/// an upstream PR after #2 lands.
contract IntentGuardModuleAdversarialTest is Test {
    IntentGuardModule module;
    MockAdapter adapter;
    MockSafe safe;
    MockTarget target;

    bytes32 constant VAULT_ID = keccak256("adversarial-vault");

    // Three signers, sorted ascending so the strict-order check passes.
    uint256 keyA = 0xA11CE;
    uint256 keyB = 0xB0B;
    uint256 keyC = 0xCAFE;
    address signerLow;
    address signerMid;
    address signerHigh;
    uint256 keyLow;
    uint256 keyMid;
    uint256 keyHigh;

    uint64 constant FRESH_WINDOW = 600;
    uint64 constant COOLOFF = 86400;
    uint64 constant EXECUTE_DELAY = 60;
    uint64 constant MIN_PROPOSAL_LIFETIME = 86460 + 3600;

    function setUp() public {
        address a = vm.addr(keyA);
        address b = vm.addr(keyB);
        address c = vm.addr(keyC);
        (signerLow, signerMid, signerHigh, keyLow, keyMid, keyHigh) = _sortByAddress(a, keyA, b, keyB, c, keyC);

        module = new IntentGuardModule();
        adapter = new MockAdapter();
        safe = new MockSafe();
        safe.setGuard(address(module));
        target = new MockTarget();

        address[] memory signers = new address[](3);
        signers[0] = signerLow;
        signers[1] = signerMid;
        signers[2] = signerHigh;

        vm.prank(address(safe));
        module.initializeVault(
            VAULT_ID,
            address(safe),
            signers,
            2, // threshold
            2, // vetoThreshold
            FRESH_WINDOW,
            COOLOFF,
            EXECUTE_DELAY,
            MIN_PROPOSAL_LIFETIME
        );

        vm.prank(address(safe));
        module.setAdapter(VAULT_ID, address(target), address(adapter), true);
    }

    // ============================================================
    // Helpers
    // ============================================================

    function _sortByAddress(address a, uint256 ka, address b, uint256 kb, address c, uint256 kc)
        internal
        pure
        returns (address sa, address sb, address sc, uint256 ksa, uint256 ksb, uint256 ksc)
    {
        sa = a;
        sb = b;
        sc = c;
        ksa = ka;
        ksb = kb;
        ksc = kc;
        if (sa > sb) {
            (sa, sb) = (sb, sa);
            (ksa, ksb) = (ksb, ksa);
        }
        if (sb > sc) {
            (sb, sc) = (sc, sb);
            (ksb, ksc) = (ksc, ksb);
        }
        if (sa > sb) {
            (sa, sb) = (sb, sa);
            (ksa, ksb) = (ksb, ksa);
        }
    }

    function _typedHash(AttestPayload memory p) internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                module.ATTESTATION_TYPEHASH(),
                p.vaultId,
                p.vaultNonce,
                p.target,
                p.value,
                p.dataHash,
                p.intentHash,
                p.adapterAddr,
                p.signedAt,
                p.expiresAt,
                block.chainid,
                address(module)
            )
        );
    }

    function _ethSignedHash(AttestPayload memory p) internal view returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", _typedHash(p)));
    }

    function _signAttestation(uint256 privKey, AttestPayload memory p)
        internal
        view
        returns (IntentGuardModule.Attestation memory att)
    {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privKey, _ethSignedHash(p));
        att.signer = vm.addr(privKey);
        att.signedAt = p.signedAt;
        att.expiresAt = p.expiresAt;
        att.signature = abi.encodePacked(r, s, v);
    }

    function _buildPayload(bytes memory data, uint64 signedAt, uint64 expiresAt)
        internal
        view
        returns (AttestPayload memory p)
    {
        p.vaultId = VAULT_ID;
        p.vaultNonce = 0;
        p.target = address(target);
        p.value = 0;
        p.dataHash = keccak256(data);
        p.intentHash = adapter.intentHash(address(target), 0, data);
        p.adapterAddr = address(adapter);
        p.signedAt = signedAt;
        p.expiresAt = expiresAt;
    }

    function _atts2(uint256 ka, uint256 kb, AttestPayload memory p)
        internal
        view
        returns (IntentGuardModule.Attestation[] memory atts)
    {
        atts = new IntentGuardModule.Attestation[](2);
        atts[0] = _signAttestation(ka, p);
        atts[1] = _signAttestation(kb, p);
    }

    function _atts3(uint256 ka, uint256 kb, uint256 kc, AttestPayload memory p)
        internal
        view
        returns (IntentGuardModule.Attestation[] memory atts)
    {
        atts = new IntentGuardModule.Attestation[](3);
        atts[0] = _signAttestation(ka, p);
        atts[1] = _signAttestation(kb, p);
        atts[2] = _signAttestation(kc, p);
    }

    function _queueDefault(bytes memory data) internal returns (bytes32 proposalId) {
        AttestPayload memory p = _buildPayload(
            data,
            uint64(block.timestamp),
            uint64(block.timestamp) + 200
        );
        uint64 proposalExpiresAt = uint64(block.timestamp) + MIN_PROPOSAL_LIFETIME + 100;
        proposalId = module.queue(
            VAULT_ID,
            address(target),
            0,
            data,
            p.intentHash,
            address(adapter),
            proposalExpiresAt,
            _atts2(keyLow, keyMid, p)
        );
    }

    // ============================================================
    // F1 (FINDING, low/informational): signature v normalization
    // accepts both compact {0,1} and legacy {27,28} for the same (r,s).
    // The same signer recovers from two distinct signature byte strings.
    //
    // Threat surface: `_recover` does:
    //     if (v < 27) v += 27;
    //     if (v != 27 && v != 28) revert;
    // So v=0 → 27 and v=1 → 28 normalize, but v=27/28 also pass directly.
    // Two valid encodings ⇒ off-chain dedup by raw signature bytes is
    // unsound. On-chain dedup uses signer address (in `cancelledBy` and
    // the `lastSigner` strict-order check), so direct exploit is bounded:
    // a malleated signature does NOT let you double-vote, double-cancel,
    // or bypass the strict-order check.
    //
    // We mark this `_findings_` and skip it as a regression failure,
    // because the BEHAVIOR ITSELF is what we want to flag — the test
    // asserts that BOTH forms verify successfully (i.e., the malleability
    // exists). When fixed upstream (e.g., reject v < 27 outright, or
    // require v ∈ {27,28} only), this test will start failing and we
    // unskip it as a regression.
    //
    // Suggested fix: replace the two-line block with
    //     if (v != 27 && v != 28) revert BadSignature();
    // dropping the `if (v < 27) v += 27;` normalization. Off-chain
    // signers that produce v=0/1 must add 27 before submitting.
    // ============================================================

    /// @dev Helper: spin up a 1-of-1 vault tied to safe2 and allow our adapter.
    function _setupF1Vault() internal returns (bytes32 vaultId2, MockSafe safe2) {
        vaultId2 = keccak256("F1-vault");
        address[] memory signers = new address[](1);
        signers[0] = signerLow;
        safe2 = new MockSafe();
        safe2.setGuard(address(module));
        vm.prank(address(safe2));
        module.initializeVault(
            vaultId2, address(safe2), signers,
            1, 1, FRESH_WINDOW, COOLOFF, EXECUTE_DELAY, MIN_PROPOSAL_LIFETIME
        );
        vm.prank(address(safe2));
        module.setAdapter(vaultId2, address(target), address(adapter), true);
    }

    /// @dev Helper: sign payload with keyLow but FORCE v into compact-form
    /// {0,1} regardless of the canonical {27,28} that vm.sign returns. Caller
    /// passes the result to `module.queue()` to observe whether the module
    /// accepts the malleated encoding.
    function _signCompactV(AttestPayload memory p) internal view returns (IntentGuardModule.Attestation memory att) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(keyLow, _ethSignedHash(p));
        require(v == 27 || v == 28, "vm.sign should produce 27 or 28");
        att.signer = signerLow;
        att.signedAt = p.signedAt;
        att.expiresAt = p.expiresAt;
        att.signature = abi.encodePacked(r, s, uint8(v - 27));
    }

    function test_findings_F1_signature_v_malleability() public {
        vm.skip(true);
        // Both encodings — canonical {27,28} and compact {0,1} — recover
        // to the same signer via `_recover`. We can't call internal
        // `_recover` directly, so we construct an Attestation with v∈{0,1}
        // and run it through `queue()`. Acceptance ⇒ malleability exists.
        (bytes32 vaultId2, ) = _setupF1Vault();

        bytes memory data = hex"deadbeef";
        AttestPayload memory p = _buildPayload(data, uint64(block.timestamp), uint64(block.timestamp) + 200);
        p.vaultId = vaultId2;

        IntentGuardModule.Attestation[] memory atts = new IntentGuardModule.Attestation[](1);
        atts[0] = _signCompactV(p);

        uint64 proposalExpiresAt = uint64(block.timestamp) + MIN_PROPOSAL_LIFETIME + 100;
        // If the module rejects v<27 (after upstream fix), this will revert
        // BadSignature. Today, with the `if (v < 27) v += 27;` normalization,
        // this succeeds — that is the finding.
        bytes32 pid = module.queue(
            vaultId2, address(target), 0, data, p.intentHash,
            address(adapter), proposalExpiresAt, atts
        );
        assertTrue(pid != bytes32(0), "compact-v form must verify (current state) - fix removes this");
    }

    // ============================================================
    // Defensive regressions: initializeVault
    // ============================================================

    function test_init_rejectsZeroSafe() public {
        bytes32 vid = keccak256("init-zero-safe");
        address[] memory s = new address[](1);
        s[0] = signerLow;
        vm.prank(address(0));
        vm.expectRevert(IntentGuardModule.BadConfig.selector);
        module.initializeVault(vid, address(0), s, 1, 1, FRESH_WINDOW, COOLOFF, EXECUTE_DELAY, MIN_PROPOSAL_LIFETIME);
    }

    function test_init_rejectsNonSafeCaller() public {
        bytes32 vid = keccak256("init-non-safe-caller");
        address[] memory s = new address[](1);
        s[0] = signerLow;
        MockSafe other = new MockSafe();
        // msg.sender (this test contract) != safe
        vm.expectRevert(IntentGuardModule.BadConfig.selector);
        module.initializeVault(vid, address(other), s, 1, 1, FRESH_WINDOW, COOLOFF, EXECUTE_DELAY, MIN_PROPOSAL_LIFETIME);
    }

    function test_init_rejectsZeroThreshold() public {
        bytes32 vid = keccak256("init-zero-threshold");
        address[] memory s = new address[](1);
        s[0] = signerLow;
        MockSafe s2 = new MockSafe();
        vm.prank(address(s2));
        vm.expectRevert(IntentGuardModule.BadConfig.selector);
        module.initializeVault(vid, address(s2), s, 0, 1, FRESH_WINDOW, COOLOFF, EXECUTE_DELAY, MIN_PROPOSAL_LIFETIME);
    }

    function test_init_rejectsZeroVetoThreshold() public {
        bytes32 vid = keccak256("init-zero-veto");
        address[] memory s = new address[](1);
        s[0] = signerLow;
        MockSafe s2 = new MockSafe();
        vm.prank(address(s2));
        vm.expectRevert(IntentGuardModule.BadConfig.selector);
        module.initializeVault(vid, address(s2), s, 1, 0, FRESH_WINDOW, COOLOFF, EXECUTE_DELAY, MIN_PROPOSAL_LIFETIME);
    }

    function test_init_rejectsThresholdGreaterThanSigners() public {
        bytes32 vid = keccak256("init-thr-gt-signers");
        address[] memory s = new address[](2);
        s[0] = signerLow;
        s[1] = signerMid;
        MockSafe s2 = new MockSafe();
        vm.prank(address(s2));
        vm.expectRevert(IntentGuardModule.BadConfig.selector);
        module.initializeVault(vid, address(s2), s, 3, 1, FRESH_WINDOW, COOLOFF, EXECUTE_DELAY, MIN_PROPOSAL_LIFETIME);
    }

    function test_init_rejectsVetoThresholdGreaterThanSigners() public {
        bytes32 vid = keccak256("init-veto-gt-signers");
        address[] memory s = new address[](2);
        s[0] = signerLow;
        s[1] = signerMid;
        MockSafe s2 = new MockSafe();
        vm.prank(address(s2));
        vm.expectRevert(IntentGuardModule.BadConfig.selector);
        module.initializeVault(vid, address(s2), s, 1, 3, FRESH_WINDOW, COOLOFF, EXECUTE_DELAY, MIN_PROPOSAL_LIFETIME);
    }

    function test_init_rejectsZeroAddressSigner() public {
        bytes32 vid = keccak256("init-zero-signer");
        address[] memory s = new address[](2);
        s[0] = signerLow;
        s[1] = address(0);
        MockSafe s2 = new MockSafe();
        vm.prank(address(s2));
        vm.expectRevert(IntentGuardModule.BadConfig.selector);
        module.initializeVault(vid, address(s2), s, 1, 1, FRESH_WINDOW, COOLOFF, EXECUTE_DELAY, MIN_PROPOSAL_LIFETIME);
    }

    function test_init_rejectsDuplicateSigner() public {
        bytes32 vid = keccak256("init-dup-signer");
        address[] memory s = new address[](2);
        s[0] = signerLow;
        s[1] = signerLow;
        MockSafe s2 = new MockSafe();
        vm.prank(address(s2));
        vm.expectRevert(IntentGuardModule.BadConfig.selector);
        module.initializeVault(vid, address(s2), s, 1, 1, FRESH_WINDOW, COOLOFF, EXECUTE_DELAY, MIN_PROPOSAL_LIFETIME);
    }

    function test_init_rejectsMinLifetimeBelowCooloffPlusExecuteDelay() public {
        bytes32 vid = keccak256("init-lifetime-too-low");
        address[] memory s = new address[](1);
        s[0] = signerLow;
        MockSafe s2 = new MockSafe();
        vm.prank(address(s2));
        vm.expectRevert(IntentGuardModule.BadConfig.selector);
        // minLifetime = COOLOFF + EXECUTE_DELAY - 1
        module.initializeVault(vid, address(s2), s, 1, 1, FRESH_WINDOW, COOLOFF, EXECUTE_DELAY, COOLOFF + EXECUTE_DELAY - 1);
    }

    function test_init_rejectsZeroFreshWindow() public {
        bytes32 vid = keccak256("init-zero-fresh");
        address[] memory s = new address[](1);
        s[0] = signerLow;
        MockSafe s2 = new MockSafe();
        vm.prank(address(s2));
        vm.expectRevert(IntentGuardModule.BadConfig.selector);
        module.initializeVault(vid, address(s2), s, 1, 1, 0, COOLOFF, EXECUTE_DELAY, MIN_PROPOSAL_LIFETIME);
    }

    function test_init_rejectsDoubleInit() public {
        // Already initialized in setUp(); a second call must revert.
        address[] memory s = new address[](3);
        s[0] = signerLow;
        s[1] = signerMid;
        s[2] = signerHigh;
        vm.prank(address(safe));
        vm.expectRevert(IntentGuardModule.AlreadyInitialized.selector);
        module.initializeVault(VAULT_ID, address(safe), s, 2, 2, FRESH_WINDOW, COOLOFF, EXECUTE_DELAY, MIN_PROPOSAL_LIFETIME);
    }

    /// @notice Documented design choice: vetoThreshold > threshold is allowed
    /// (and sometimes desirable — stricter veto liveness against silent signers).
    /// Asserts this remains permitted so we notice if a future PR tightens it.
    function test_init_allowsVetoThresholdGreaterThanThreshold() public {
        bytes32 vid = keccak256("init-veto-gt-thr");
        address[] memory s = new address[](3);
        s[0] = signerLow;
        s[1] = signerMid;
        s[2] = signerHigh;
        MockSafe s2 = new MockSafe();
        vm.prank(address(s2));
        // threshold=2, vetoThreshold=3 (all signers required to veto)
        module.initializeVault(vid, address(s2), s, 2, 3, FRESH_WINDOW, COOLOFF, EXECUTE_DELAY, MIN_PROPOSAL_LIFETIME);
        (,,,,, uint8 thr, uint8 vetoThr,, bool initialized) = module.vaults(vid);
        assertTrue(initialized);
        assertEq(thr, 2);
        assertEq(vetoThr, 3);
    }

    // ============================================================
    // Defensive regressions: queue
    // ============================================================

    function test_queue_rejectsUnknownVault() public {
        bytes memory data = hex"01";
        AttestPayload memory p = _buildPayload(data, uint64(block.timestamp), uint64(block.timestamp) + 200);
        bytes32 unknown = keccak256("not-a-vault");
        IntentGuardModule.Attestation[] memory atts = _atts2(keyLow, keyMid, p);
        uint64 expiresAt = uint64(block.timestamp) + MIN_PROPOSAL_LIFETIME + 100;
        vm.expectRevert(IntentGuardModule.UnknownVault.selector);
        module.queue(unknown, address(target), 0, data, p.intentHash, address(adapter), expiresAt, atts);
    }

    function test_queue_rejectsUnregisteredAdapter() public {
        bytes memory data = hex"02";
        MockAdapter rogue = new MockAdapter();
        AttestPayload memory p = _buildPayload(data, uint64(block.timestamp), uint64(block.timestamp) + 200);
        // Re-stamp the payload's adapter field so the digest matches what
        // would be signed for the rogue adapter — this isolates the adapter
        // allowlist check from the signature check.
        p.intentHash = rogue.intentHash(address(target), 0, data);
        p.adapterAddr = address(rogue);
        IntentGuardModule.Attestation[] memory atts = _atts2(keyLow, keyMid, p);
        vm.expectRevert(IntentGuardModule.BadAdapter.selector);
        module.queue(VAULT_ID, address(target), 0, data, p.intentHash, address(rogue),
            uint64(block.timestamp) + MIN_PROPOSAL_LIFETIME + 100, atts);
    }

    function test_queue_rejectsIntentHashMismatch() public {
        bytes memory data = hex"03";
        AttestPayload memory p = _buildPayload(data, uint64(block.timestamp), uint64(block.timestamp) + 200);
        bytes32 wrongIntent = keccak256("wrong");
        IntentGuardModule.Attestation[] memory atts = _atts2(keyLow, keyMid, p);
        uint64 expiresAt = uint64(block.timestamp) + MIN_PROPOSAL_LIFETIME + 100;
        vm.expectRevert(IntentGuardModule.BadIntent.selector);
        module.queue(VAULT_ID, address(target), 0, data, wrongIntent, address(adapter), expiresAt, atts);
    }

    function test_queue_rejectsProposalExpiresAtBelowFloor() public {
        bytes memory data = hex"04";
        AttestPayload memory p = _buildPayload(data, uint64(block.timestamp), uint64(block.timestamp) + 200);
        IntentGuardModule.Attestation[] memory atts = _atts2(keyLow, keyMid, p);
        // Just below the floor.
        uint64 expires = uint64(block.timestamp) + MIN_PROPOSAL_LIFETIME - 1;
        vm.expectRevert(IntentGuardModule.ProposalExpired.selector);
        module.queue(VAULT_ID, address(target), 0, data, p.intentHash, address(adapter), expires, atts);
    }

    /// @notice Threat surface (queue): "can attestations.length > threshold
    /// skip checking the trailing entries?" — No. _verifyAttestations
    /// iterates ALL entries unconditionally. A bogus signature in slot 2
    /// of a 3-attestation array (threshold=2) still reverts.
    function test_queue_extraAttestationsAreAllVerified() public {
        bytes memory data = hex"05";
        AttestPayload memory p = _buildPayload(data, uint64(block.timestamp), uint64(block.timestamp) + 200);
        IntentGuardModule.Attestation[] memory atts = _atts3(keyLow, keyMid, keyHigh, p);
        // Corrupt the signature on the LAST (trailing) attestation.
        atts[2].signature = abi.encodePacked(bytes32(uint256(1)), bytes32(uint256(2)), uint8(27));

        vm.expectRevert(IntentGuardModule.BadSignature.selector);
        module.queue(VAULT_ID, address(target), 0, data, p.intentHash, address(adapter),
            uint64(block.timestamp) + MIN_PROPOSAL_LIFETIME + 100, atts);
    }

    /// @notice Threat surface (queue): can the same proposalId be queued twice?
    /// `keccak256(abi.encode(vaultId, nonce, target, value, dataHash,
    /// intentHash, adapter))` is the slot key. After a successful queue, the
    /// state is Queued (not None), and a second queue with identical params
    /// reverts at `proposal.state != ProposalState.None`.
    function test_queue_rejectsDuplicateProposal() public {
        bytes memory data = hex"06";
        bytes32 pid = _queueDefault(data);
        assertTrue(pid != bytes32(0));

        // Try again with identical params.
        AttestPayload memory p = _buildPayload(data, uint64(block.timestamp), uint64(block.timestamp) + 200);
        IntentGuardModule.Attestation[] memory atts = _atts2(keyLow, keyMid, p);
        uint64 expiresAt = uint64(block.timestamp) + MIN_PROPOSAL_LIFETIME + 100;
        vm.expectRevert(IntentGuardModule.BadState.selector);
        module.queue(VAULT_ID, address(target), 0, data, p.intentHash, address(adapter), expiresAt, atts);
    }

    /// @notice Threat surface (_verifyAttestations): unsorted signers fail
    /// the strict `att.signer <= lastSigner` check, regardless of whether
    /// they're all valid signers individually.
    function test_queue_rejectsUnsortedAttestations() public {
        bytes memory data = hex"07";
        AttestPayload memory p = _buildPayload(data, uint64(block.timestamp), uint64(block.timestamp) + 200);
        IntentGuardModule.Attestation[] memory atts = new IntentGuardModule.Attestation[](2);
        // Reverse order: high signer FIRST, low signer SECOND ⇒ violates strict ascending.
        atts[0] = _signAttestation(keyMid, p);
        atts[1] = _signAttestation(keyLow, p);
        vm.expectRevert(IntentGuardModule.DuplicateSigner.selector);
        module.queue(VAULT_ID, address(target), 0, data, p.intentHash, address(adapter),
            uint64(block.timestamp) + MIN_PROPOSAL_LIFETIME + 100, atts);
    }

    /// @notice Threat surface (_verifyAttestations): address(0) in the
    /// signer slot fails. `lastSigner` initializes to 0, and the check
    /// `att.signer <= lastSigner` rejects `att.signer == 0` immediately.
    /// Even if it didn't, isSigner[v][address(0)] is unreachable since
    /// initializeVault rejects address(0) signers.
    function test_queue_rejectsZeroAddressSigner() public {
        bytes memory data = hex"08";
        AttestPayload memory p = _buildPayload(data, uint64(block.timestamp), uint64(block.timestamp) + 200);
        IntentGuardModule.Attestation[] memory atts = new IntentGuardModule.Attestation[](2);
        atts[0].signer = address(0);
        atts[0].signedAt = p.signedAt;
        atts[0].expiresAt = p.expiresAt;
        atts[0].signature = abi.encodePacked(bytes32(0), bytes32(0), uint8(27));
        atts[1] = _signAttestation(keyLow, p);
        vm.expectRevert(IntentGuardModule.DuplicateSigner.selector);
        module.queue(VAULT_ID, address(target), 0, data, p.intentHash, address(adapter),
            uint64(block.timestamp) + MIN_PROPOSAL_LIFETIME + 100, atts);
    }

    /// @notice Threat surface (_attestationDigest): cross-chain bound.
    /// A signature produced under chainid=A must not verify under chainid=B.
    function test_queue_rejectsAttestationFromDifferentChainId() public {
        bytes memory data = hex"09";
        AttestPayload memory p = _buildPayload(data, uint64(block.timestamp), uint64(block.timestamp) + 200);

        // Sign while pretending we're on a different chain id. We do this by
        // computing the typed hash with a mutated chainid, then signing it
        // and packing as an Attestation. The module re-derives chainid from
        // block.chainid at verify time — so this must NOT recover to the signer.
        uint256 fakeChainId = block.chainid + 1;
        bytes32 typedHash = keccak256(
            abi.encode(
                module.ATTESTATION_TYPEHASH(),
                p.vaultId, p.vaultNonce, p.target, p.value, p.dataHash,
                p.intentHash, p.adapterAddr, p.signedAt, p.expiresAt,
                fakeChainId, address(module)
            )
        );
        bytes32 ethSignedHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", typedHash));
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(keyLow, ethSignedHash);
        IntentGuardModule.Attestation memory bad;
        bad.signer = signerLow;
        bad.signedAt = p.signedAt;
        bad.expiresAt = p.expiresAt;
        bad.signature = abi.encodePacked(r1, s1, v1);

        IntentGuardModule.Attestation[] memory atts = new IntentGuardModule.Attestation[](2);
        // Place bad in correct sort order.
        if (signerLow < signerMid) {
            atts[0] = bad;
            atts[1] = _signAttestation(keyMid, p);
        } else {
            atts[0] = _signAttestation(keyMid, p);
            atts[1] = bad;
        }

        vm.expectRevert(IntentGuardModule.BadSignature.selector);
        module.queue(VAULT_ID, address(target), 0, data, p.intentHash, address(adapter),
            uint64(block.timestamp) + MIN_PROPOSAL_LIFETIME + 100, atts);
    }

    /// @notice Threat surface (_attestationDigest): cross-module bound.
    /// A signature produced for module A must not verify on module B.
    function test_queue_rejectsAttestationForDifferentModule() public {
        bytes memory data = hex"0a";
        AttestPayload memory p = _buildPayload(data, uint64(block.timestamp), uint64(block.timestamp) + 200);

        IntentGuardModule otherModule = new IntentGuardModule();
        bytes32 typedHash = keccak256(
            abi.encode(
                module.ATTESTATION_TYPEHASH(),
                p.vaultId, p.vaultNonce, p.target, p.value, p.dataHash,
                p.intentHash, p.adapterAddr, p.signedAt, p.expiresAt,
                block.chainid, address(otherModule)
            )
        );
        bytes32 ethSignedHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", typedHash));
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(keyLow, ethSignedHash);
        IntentGuardModule.Attestation memory bad;
        bad.signer = signerLow;
        bad.signedAt = p.signedAt;
        bad.expiresAt = p.expiresAt;
        bad.signature = abi.encodePacked(r1, s1, v1);

        IntentGuardModule.Attestation[] memory atts = new IntentGuardModule.Attestation[](2);
        if (signerLow < signerMid) {
            atts[0] = bad;
            atts[1] = _signAttestation(keyMid, p);
        } else {
            atts[0] = _signAttestation(keyMid, p);
            atts[1] = bad;
        }

        vm.expectRevert(IntentGuardModule.BadSignature.selector);
        module.queue(VAULT_ID, address(target), 0, data, p.intentHash, address(adapter),
            uint64(block.timestamp) + MIN_PROPOSAL_LIFETIME + 100, atts);
    }

    // ============================================================
    // Defensive regressions: cancel
    // ============================================================

    /// @notice Threat surface (cancel): can a signer of vault A cancel
    /// a proposal scoped to vault B? No — `isSigner[proposal.vaultId]`
    /// is checked, so a non-signer of the proposal's vault gets NotSigner.
    function test_cancel_signerScopedToProposalVault() public {
        bytes memory data = hex"10";
        bytes32 pid = _queueDefault(data);

        // Set up a SECOND vault with a different signer set.
        bytes32 vid2 = keccak256("vault-2-cancel-scope");
        uint256 outsiderKey = 0xFEEED;
        address outsider = vm.addr(outsiderKey);
        address[] memory s = new address[](1);
        s[0] = outsider;
        MockSafe safe2 = new MockSafe();
        safe2.setGuard(address(module));
        vm.prank(address(safe2));
        module.initializeVault(vid2, address(safe2), s, 1, 1, FRESH_WINDOW, COOLOFF, EXECUTE_DELAY, MIN_PROPOSAL_LIFETIME);

        // outsider is a signer of vid2 only — must NOT be able to cancel pid (vault VAULT_ID).
        vm.prank(outsider);
        vm.expectRevert(IntentGuardModule.NotSigner.selector);
        module.cancel(pid, "wrong vault");
    }

    /// @notice Threat surface (cancel): per-signer dedup via
    /// `cancelledBy[proposalId][msg.sender]`. Same signer cannot count twice.
    function test_cancel_sameSignerCannotCountTwice() public {
        bytes memory data = hex"11";
        bytes32 pid = _queueDefault(data);

        vm.prank(signerLow);
        module.cancel(pid, "first");

        vm.prank(signerLow);
        vm.expectRevert(IntentGuardModule.DuplicateSigner.selector);
        module.cancel(pid, "second");
    }

    /// @notice Threat surface (cancel/queue): once cancelled, the slot
    /// is terminal. Re-queueing identical params reverts. This is
    /// intended (a vetoed action should not be silently re-queueable),
    /// but it has a side-effect: signers who change their mind must
    /// alter SOME field (data, value, etc.) to escape the slot. To
    /// re-queue the SAME logical action, they must wait for a
    /// successful execute (which bumps vault.nonce) — which can't
    /// happen here. Documented limitation.
    function test_cancel_cancelledStateIsTerminal() public {
        bytes memory data = hex"12";
        bytes32 pid = _queueDefault(data);

        vm.prank(signerLow);
        module.cancel(pid, "veto1");
        vm.prank(signerHigh);
        module.cancel(pid, "veto2");

        // Now state should be Cancelled.
        // Try re-queue with identical params.
        AttestPayload memory p = _buildPayload(data, uint64(block.timestamp), uint64(block.timestamp) + 200);
        IntentGuardModule.Attestation[] memory atts = _atts2(keyLow, keyMid, p);
        uint64 expiresAt = uint64(block.timestamp) + MIN_PROPOSAL_LIFETIME + 100;
        vm.expectRevert(IntentGuardModule.BadState.selector);
        module.queue(VAULT_ID, address(target), 0, data, p.intentHash, address(adapter), expiresAt, atts);
    }

    /// @notice Threat surface (cancel): cancelling a proposal that is
    /// not in Queued state (None, Cancelled, Executed) reverts BadState.
    function test_cancel_rejectsNonQueuedProposal() public {
        bytes32 madeUpPid = keccak256("nonexistent");
        vm.prank(signerLow);
        vm.expectRevert(IntentGuardModule.BadState.selector);
        module.cancel(madeUpPid, "nope");
    }

    /// @notice Threat surface (cancel): non-signer of the vault gets NotSigner.
    function test_cancel_rejectsNonSigner() public {
        bytes memory data = hex"13";
        bytes32 pid = _queueDefault(data);
        address outsider = address(0x1111);
        vm.prank(outsider);
        vm.expectRevert(IntentGuardModule.NotSigner.selector);
        module.cancel(pid, "outsider");
    }

    // ============================================================
    // Defensive regressions: execute
    // ============================================================

    /// @notice Threat surface (execute): the `data` parameter is
    /// dataHash-checked. Mutating any byte changes the keccak and reverts.
    function test_execute_rejectsMutatedData() public {
        bytes memory data = hex"20";
        bytes32 pid = _queueDefault(data);
        vm.warp(block.timestamp + COOLOFF + EXECUTE_DELAY + 1);
        bytes memory mutated = hex"21";
        vm.expectRevert(IntentGuardModule.BadIntent.selector);
        module.execute(pid, mutated);
    }

    /// @notice Threat surface (execute): proposal.nonce vs vault.nonce
    /// gate. After one execute, vault.nonce increments. A pre-existing
    /// proposal queued at the OLD nonce no longer satisfies the gate.
    /// (We can only construct this scenario by queuing two proposals
    /// at the same vault.nonce — which the slot uniqueness check
    /// already blocks for identical params, so we test with different
    /// params: queue A and B both at nonce=0, execute A → nonce=1,
    /// then B should revert BadNonce.)
    function test_execute_staleNonceRejected() public {
        bytes memory dataA = hex"30";
        bytes memory dataB = hex"31";
        bytes32 pidA = _queueDefault(dataA);
        bytes32 pidB = _queueDefault(dataB);

        vm.warp(block.timestamp + COOLOFF + EXECUTE_DELAY + 1);
        module.execute(pidA, dataA);

        // Vault.nonce now = 1; pidB was queued at nonce=0.
        vm.expectRevert(IntentGuardModule.BadNonce.selector);
        module.execute(pidB, dataB);
    }

    /// @notice Threat surface (execute): expired proposal cannot run.
    function test_execute_rejectsExpiredProposal() public {
        bytes memory data = hex"32";
        AttestPayload memory p = _buildPayload(data, uint64(block.timestamp), uint64(block.timestamp) + 200);
        uint64 expiresAt = uint64(block.timestamp) + MIN_PROPOSAL_LIFETIME + 50;
        bytes32 pid = module.queue(
            VAULT_ID, address(target), 0, data, p.intentHash, address(adapter),
            expiresAt, _atts2(keyLow, keyMid, p)
        );
        // Warp past expiresAt.
        vm.warp(uint256(expiresAt) + 1);
        vm.expectRevert(IntentGuardModule.ProposalExpired.selector);
        module.execute(pid, data);
    }

    /// @notice Threat surface (execute, reentrancy): the call to
    /// `execTransactionFromModule` happens AFTER `proposal.state =
    /// Executed` and `vault.nonce += 1`. So if the called target
    /// re-enters and tries to execute the SAME proposalId, it must
    /// fail (state is no longer Queued). Asserts CEI ordering.
    function test_execute_reentryCannotDoubleExecute() public {
        bytes memory data = hex"40";
        bytes32 pid = _queueDefault(data);
        vm.warp(block.timestamp + COOLOFF + EXECUTE_DELAY + 1);

        // Set the target to re-enter execute(pid) during the call.
        bytes memory reentryCall = abi.encodeWithSelector(IntentGuardModule.execute.selector, pid, data);
        target.setReentry(address(module), reentryCall);

        module.execute(pid, data);

        // The reentry was attempted, but the inner execute reverted because
        // state was already Executed.
        assertTrue(target.reentryAttempted(), "reentry path should have run");
        assertFalse(target.reentrySucceeded(), "inner execute must NOT succeed");
    }

    // ============================================================
    // Misc defensive regressions
    // ============================================================

    /// @notice Threat surface (setAdapter): rejects address(0) target or adapter.
    function test_setAdapter_rejectsZeroTarget() public {
        vm.prank(address(safe));
        vm.expectRevert(IntentGuardModule.BadAdapter.selector);
        module.setAdapter(VAULT_ID, address(0), address(adapter), true);
    }

    function test_setAdapter_rejectsZeroAdapter() public {
        vm.prank(address(safe));
        vm.expectRevert(IntentGuardModule.BadAdapter.selector);
        module.setAdapter(VAULT_ID, address(target), address(0), true);
    }

    function test_setAdapter_rejectsNonSafeCaller() public {
        // msg.sender (this test contract) is not the Safe.
        vm.expectRevert(IntentGuardModule.UnknownVault.selector);
        module.setAdapter(VAULT_ID, address(target), address(adapter), true);
    }

    /// @notice Threat surface (queue freshness): a single attestation
    /// signed before block.timestamp - freshWindowSecs is rejected.
    function test_queue_rejectsStaleAttestation() public {
        vm.warp(10_000);
        bytes memory data = hex"50";
        AttestPayload memory p = _buildPayload(data, uint64(block.timestamp), uint64(block.timestamp) + 200_000);
        IntentGuardModule.Attestation[] memory atts = _atts2(keyLow, keyMid, p);
        // Now warp past the freshness window.
        vm.warp(uint256(p.signedAt) + uint256(FRESH_WINDOW) + 1);
        uint64 proposalExpiresAt = uint64(block.timestamp) + MIN_PROPOSAL_LIFETIME + 100;
        vm.expectRevert(IntentGuardModule.SignatureNotFresh.selector);
        module.queue(VAULT_ID, address(target), 0, data, p.intentHash, address(adapter),
            proposalExpiresAt, atts);
    }

    /// @notice Threat surface (queue freshness): the module has TWO freshness
    /// gates — per-att (`block.timestamp - signedAt <= freshWindow`, line 307)
    /// AND inter-att spread (`newest - oldest <= freshWindow`, line 285).
    ///
    /// Observation (defensive): under the `att.signedAt <= block.timestamp`
    /// constraint (line 306), if every att's signedAt is within freshWindow
    /// of NOW, then their spread is also <= freshWindow. So the spread gate
    /// is effectively redundant given the per-att gate — but it's a
    /// belt-and-suspenders against future relaxation. We assert that two
    /// attestations signed close together (within freshWindow) queue
    /// successfully, exercising both gates without violating either.
    function test_queue_freshnessGatesPassWhenSpreadWithinWindow() public {
        vm.warp(10_500);
        bytes memory data = hex"51";
        AttestPayload memory pA = _buildPayload(data, uint64(block.timestamp - 100), uint64(block.timestamp + 200));
        AttestPayload memory pB = _buildPayload(data, uint64(block.timestamp - 50), uint64(block.timestamp + 200));
        IntentGuardModule.Attestation[] memory clean = new IntentGuardModule.Attestation[](2);
        clean[0] = _signAttestation(keyLow, pA);
        clean[1] = _signAttestation(keyMid, pB);
        // Each per-att digest binds its own signedAt; signers sign distinct
        // payloads by design.
        module.queue(VAULT_ID, address(target), 0, data, pA.intentHash, address(adapter),
            uint64(block.timestamp) + MIN_PROPOSAL_LIFETIME + 100, clean);
    }

    /// @notice Threat surface (_recover): malformed signature length is rejected.
    function test_recover_rejectsBadSignatureLength() public {
        bytes memory data = hex"60";
        AttestPayload memory p = _buildPayload(data, uint64(block.timestamp), uint64(block.timestamp) + 200);
        IntentGuardModule.Attestation[] memory atts = _atts2(keyLow, keyMid, p);
        // Truncate to 64 bytes.
        bytes memory full = atts[0].signature;
        bytes memory short_ = new bytes(64);
        for (uint256 i = 0; i < 64; i++) short_[i] = full[i];
        atts[0].signature = short_;
        vm.expectRevert(IntentGuardModule.BadSignature.selector);
        module.queue(VAULT_ID, address(target), 0, data, p.intentHash, address(adapter),
            uint64(block.timestamp) + MIN_PROPOSAL_LIFETIME + 100, atts);
    }

    /// @dev Helper: flip a canonical signature into its high-S counterpart
    /// (s' = N - s, v' = v ^ 1). Both forms recover to the same signer in raw
    /// ecrecover, but the module's `s > N/2` check rejects the high-S form.
    function _toHighS(bytes memory sig) internal pure returns (bytes memory) {
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
        uint256 N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
        return abi.encodePacked(r, bytes32(N - uint256(s)), uint8(v == 27 ? 28 : 27));
    }

    /// @notice Threat surface (_recover): high-S (s > secp256k1n/2) is
    /// rejected. The module's bound 0x7fff...20a0 is exactly secp256k1n/2,
    /// the canonical EIP-2 boundary. Flipping s against the curve order
    /// produces an alternate signature that recovers the SAME signer in
    /// raw ecrecover, but the `s > N/2` check rejects it — closing the
    /// classic ECDSA s-malleability path.
    function test_recover_rejectsHighSMalleability() public {
        bytes memory data = hex"61";
        AttestPayload memory p = _buildPayload(data, uint64(block.timestamp), uint64(block.timestamp) + 200);
        IntentGuardModule.Attestation[] memory atts = _atts2(keyLow, keyMid, p);
        atts[0].signature = _toHighS(atts[0].signature);
        vm.expectRevert(IntentGuardModule.BadSignature.selector);
        module.queue(VAULT_ID, address(target), 0, data, p.intentHash, address(adapter),
            uint64(block.timestamp) + MIN_PROPOSAL_LIFETIME + 100, atts);
    }
}
