// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {StdInvariant} from "forge-std/StdInvariant.sol";
import {IntentGuardModule} from "../../contracts/IntentGuardModule.sol";

/// @notice Minimal Safe mock that routes the module's
/// execTransactionFromModule call to the target with the provided data.
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

/// @notice Mock action adapter that always passes. The point of these
/// invariant tests is to exercise the *module's* state machine, not adapter
/// validation logic — so this adapter is a transparent identity:
///   intentHash := keccak256(abi.encode(target, value, data))
///   validate   := no-op
contract MockPassthroughAdapter {
    function intentHash(address target, uint256 value, bytes calldata data) external pure returns (bytes32) {
        return keccak256(abi.encode(target, value, data));
    }

    function validate(address, uint256, bytes calldata, bytes32) external pure {}
}

/// @notice Inert call target. Always succeeds when called from the Safe.
contract MockTarget {
    uint256 public lastValue;
    bytes public lastData;

    fallback() external payable {
        lastValue = msg.value;
        lastData = msg.data;
    }

    receive() external payable {}
}

/// @notice Per-attestation parameter bundle.
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

/// @notice The handler is the contract Foundry's invariant fuzzer drives.
/// It exposes a small set of valid-by-construction actions (queue / cancel
/// / execute / warp / toggle-adapter) and tracks ghost state used by the
/// invariant assertions.
contract IntentGuardHandler is Test {
    // ============ infrastructure ============
    IntentGuardModule public module;
    MockSafe public safe;
    MockPassthroughAdapter public adapterPrimary;
    MockPassthroughAdapter public adapterDisposable;
    MockTarget public target;
    MockTarget public targetDisposable;

    bytes32 public constant VAULT_ID = keccak256("invariant-vault");

    uint256 internal keyA = 0xA11CE;
    uint256 internal keyB = 0xB0B;
    uint256 internal keyC = 0xCAFE;
    address public signerLow;
    address public signerMid;
    address public signerHigh;
    uint256 public keyLow;
    uint256 public keyMid;
    uint256 public keyHigh;

    uint64 public constant FRESH_WINDOW = 600;
    uint64 public constant COOLOFF = 3600;        // 1 hour
    uint64 public constant EXECUTE_DELAY = 60;
    uint64 public constant MIN_PROPOSAL_LIFETIME = 3660 + 600;
    uint64 public constant PROPOSAL_LIFETIME_PAD = 30 days; // wide enough to survive deep call stacks

    // ============ ghost state ============

    /// @dev Set of proposalIds we have ever observed.
    bytes32[] public proposalIds;
    mapping(bytes32 => bool) public seenProposal;

    /// @dev Per-proposal expected state, mirrored from successful actions.
    mapping(bytes32 => IntentGuardModule.ProposalState) public expectedState;
    mapping(bytes32 => uint64) public expectedQueuedAt;
    mapping(bytes32 => uint64) public expectedCooloffEnd; // queuedAt + COOLOFF + EXECUTE_DELAY
    mapping(bytes32 => uint64) public expectedExpiresAt;
    mapping(bytes32 => uint8) public expectedCancelCount;
    mapping(bytes32 => uint64) public expectedNonce;
    mapping(bytes32 => mapping(address => bool)) public expectedCancelledBy;
    mapping(bytes32 => bool) public adapterDisposableUsed;
    /// @dev The exact data bytes the proposal was queued with, so execute_
    /// can reconstruct them and pass the dataHash check.
    mapping(bytes32 => bytes) public proposalData;

    /// @dev Ghost: total executed count, must equal vault.nonce.
    uint64 public expectedVaultNonce;

    /// @dev Ghost: every executed proposalId, used to assert no double-execute.
    mapping(bytes32 => bool) public executedOnce;
    uint256 public executedCount;

    /// @dev Tracks whether adapterDisposable is currently allowed for targetDisposable.
    bool public disposableAllowed;

    constructor() {
        address a = vm.addr(keyA);
        address b = vm.addr(keyB);
        address c = vm.addr(keyC);
        (signerLow, signerMid, signerHigh, keyLow, keyMid, keyHigh) = _sortByAddress(a, keyA, b, keyB, c, keyC);

        module = new IntentGuardModule();
        safe = new MockSafe();
        safe.setGuard(address(module));

        adapterPrimary = new MockPassthroughAdapter();
        adapterDisposable = new MockPassthroughAdapter();
        target = new MockTarget();
        targetDisposable = new MockTarget();

        address[] memory signers = new address[](3);
        signers[0] = signerLow;
        signers[1] = signerMid;
        signers[2] = signerHigh;

        vm.prank(address(safe));
        module.initializeVault(
            VAULT_ID, address(safe), signers,
            2, 2,
            FRESH_WINDOW, COOLOFF, EXECUTE_DELAY, MIN_PROPOSAL_LIFETIME
        );

        vm.prank(address(safe));
        module.setAdapter(VAULT_ID, address(target), address(adapterPrimary), true);

        vm.prank(address(safe));
        module.setAdapter(VAULT_ID, address(targetDisposable), address(adapterDisposable), true);
        disposableAllowed = true;

        // Anchor block.timestamp away from 0 so all freshness arithmetic is well-defined.
        vm.warp(1_000_000);
    }

    // ============ helpers ============

    function _sortByAddress(address a, uint256 ka, address b, uint256 kb, address c, uint256 kc)
        internal
        pure
        returns (address sa, address sb, address sc, uint256 ksa, uint256 ksb, uint256 ksc)
    {
        sa = a; sb = b; sc = c;
        ksa = ka; ksb = kb; ksc = kc;
        if (sa > sb) { (sa, sb) = (sb, sa); (ksa, ksb) = (ksb, ksa); }
        if (sb > sc) { (sb, sc) = (sc, sb); (ksb, ksc) = (ksc, ksb); }
        if (sa > sb) { (sa, sb) = (sb, sa); (ksa, ksb) = (ksb, ksa); }
    }

    function _signAttestation(uint256 privKey, AttestPayload memory p)
        internal
        view
        returns (IntentGuardModule.Attestation memory att)
    {
        bytes32 typedHash = keccak256(
            abi.encode(
                module.ATTESTATION_TYPEHASH(),
                p.vaultId, p.vaultNonce, p.target, p.value,
                p.dataHash, p.intentHash, p.adapterAddr,
                p.signedAt, p.expiresAt, block.chainid, address(module)
            )
        );
        bytes32 ethSignedHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", typedHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privKey, ethSignedHash);
        att.signer = vm.addr(privKey);
        att.signedAt = p.signedAt;
        att.expiresAt = p.expiresAt;
        att.signature = abi.encodePacked(r, s, v);
    }

    function _twoSortedAttestations(AttestPayload memory p)
        internal
        view
        returns (IntentGuardModule.Attestation[] memory atts)
    {
        atts = new IntentGuardModule.Attestation[](2);
        atts[0] = _signAttestation(keyLow, p);
        atts[1] = _signAttestation(keyMid, p);
    }

    /// @dev Returns the current vault.nonce read from the module. Useful for
    /// invariant assertions that don't have direct access to the storage.
    function moduleNonce() external view returns (uint64) {
        ( , , , , , , , uint64 n, ) = module.vaults(VAULT_ID);
        return n;
    }

    function proposalIdsLength() external view returns (uint256) {
        return proposalIds.length;
    }

    /// @dev Read the live ProposalState the module has stored.
    function liveState(bytes32 pid) external view returns (IntentGuardModule.ProposalState s) {
        ( , , , , , , , , , , s) = module.proposals(pid);
    }

    /// @dev Read the live cancelCount the module has stored.
    function liveCancelCount(bytes32 pid) external view returns (uint8 c) {
        ( , , , , , , , , , c, ) = module.proposals(pid);
    }

    function liveQueuedAt(bytes32 pid) external view returns (uint64 q) {
        ( , , , , , , , q, , , ) = module.proposals(pid);
    }

    function liveProposalNonce(bytes32 pid) external view returns (uint64 n) {
        ( , n, , , , , , , , , ) = module.proposals(pid);
    }

    // ============ actions ============

    /// @dev Queue a fresh proposal against the primary target. The fuzzer
    /// supplies a data-seed so different calls produce different proposalIds.
    function queue_(uint96 dataSeed, uint8 valueByte) external {
        // Build distinct calldata per seed.
        bytes memory data = abi.encodePacked(uint256(dataSeed));
        uint256 value = uint256(valueByte); // not transferred; just contributes to id distinctness

        uint64 currentNonce = this.moduleNonce();
        uint64 nowTs = uint64(block.timestamp);
        uint64 expiresAt = nowTs + PROPOSAL_LIFETIME_PAD;
        bytes32 intent = adapterPrimary.intentHash(address(target), value, data);

        AttestPayload memory p;
        p.vaultId = VAULT_ID;
        p.vaultNonce = currentNonce;
        p.target = address(target);
        p.value = value;
        p.dataHash = keccak256(data);
        p.intentHash = intent;
        p.adapterAddr = address(adapterPrimary);
        p.signedAt = nowTs;
        p.expiresAt = nowTs + 200; // within fresh window

        IntentGuardModule.Attestation[] memory atts = _twoSortedAttestations(p);

        try module.queue(VAULT_ID, address(target), value, data, intent, address(adapterPrimary), expiresAt, atts) returns (bytes32 pid) {
            // Successfully queued a NEW proposal.
            if (!seenProposal[pid]) {
                seenProposal[pid] = true;
                proposalIds.push(pid);
            }
            expectedState[pid] = IntentGuardModule.ProposalState.Queued;
            expectedQueuedAt[pid] = nowTs;
            expectedCooloffEnd[pid] = nowTs + COOLOFF + EXECUTE_DELAY;
            expectedExpiresAt[pid] = expiresAt;
            expectedCancelCount[pid] = 0;
            expectedNonce[pid] = currentNonce;
            proposalData[pid] = data;
        } catch {
            // Common cases: duplicate proposalId (BadState) — not interesting.
        }
    }

    /// @dev Queue against the disposable target (whose adapter allowlist
    /// can be toggled by toggleDisposableAdapter_). This lets the
    /// allowlist-invariance invariant exercise a real flip.
    function queueDisposable_(uint96 dataSeed) external {
        bytes memory data = abi.encodePacked(uint256(dataSeed), "disposable");

        uint64 currentNonce = this.moduleNonce();
        uint64 nowTs = uint64(block.timestamp);
        uint64 expiresAt = nowTs + PROPOSAL_LIFETIME_PAD;
        bytes32 intent = adapterDisposable.intentHash(address(targetDisposable), 0, data);

        AttestPayload memory p;
        p.vaultId = VAULT_ID;
        p.vaultNonce = currentNonce;
        p.target = address(targetDisposable);
        p.value = 0;
        p.dataHash = keccak256(data);
        p.intentHash = intent;
        p.adapterAddr = address(adapterDisposable);
        p.signedAt = nowTs;
        p.expiresAt = nowTs + 200;

        IntentGuardModule.Attestation[] memory atts = _twoSortedAttestations(p);

        bool wasAllowed = disposableAllowed;
        try module.queue(VAULT_ID, address(targetDisposable), 0, data, intent, address(adapterDisposable), expiresAt, atts) returns (bytes32 pid) {
            // INVARIANT (allowlist): a successful queue against the disposable
            // pair must imply disposableAllowed == true at the moment of queue.
            require(wasAllowed, "INVARIANT VIOLATION: queue succeeded with de-allowlisted adapter");

            if (!seenProposal[pid]) {
                seenProposal[pid] = true;
                proposalIds.push(pid);
            }
            expectedState[pid] = IntentGuardModule.ProposalState.Queued;
            expectedQueuedAt[pid] = nowTs;
            expectedCooloffEnd[pid] = nowTs + COOLOFF + EXECUTE_DELAY;
            expectedExpiresAt[pid] = expiresAt;
            expectedCancelCount[pid] = 0;
            expectedNonce[pid] = currentNonce;
            adapterDisposableUsed[pid] = true;
            proposalData[pid] = data;
        } catch {
            // INVARIANT (allowlist): if disposableAllowed == false, queue MUST
            // revert with BadAdapter. We can't easily distinguish revert
            // reasons in a try/catch (low-level error data), but we assert
            // the contrapositive in the success branch above.
        }
    }

    /// @dev Toggle the disposable adapter's allowlist entry. Exercises the
    /// allowlist-invariance invariant.
    function toggleDisposableAdapter_(bool nextAllowed) external {
        if (nextAllowed == disposableAllowed) return;
        vm.prank(address(safe));
        module.setAdapter(VAULT_ID, address(targetDisposable), address(adapterDisposable), nextAllowed);
        disposableAllowed = nextAllowed;
    }

    /// @dev Cancel a proposal as a (deterministic) signer, if currently Queued.
    function cancel_(uint256 pidSeed, uint8 signerSeed) external {
        if (proposalIds.length == 0) return;
        bytes32 pid = proposalIds[pidSeed % proposalIds.length];

        // Pick a signer.
        address whoSigner;
        if (signerSeed % 3 == 0) whoSigner = signerLow;
        else if (signerSeed % 3 == 1) whoSigner = signerMid;
        else whoSigner = signerHigh;

        IntentGuardModule.ProposalState st = this.liveState(pid);
        bool already = expectedCancelledBy[pid][whoSigner];

        vm.prank(whoSigner);
        try module.cancel(pid, "fuzz-veto") {
            // Module accepted: must have been Queued and signer not previously cancelled.
            require(st == IntentGuardModule.ProposalState.Queued, "INVARIANT VIOLATION: cancel accepted on non-Queued state");
            require(!already, "INVARIANT VIOLATION: cancel accepted twice from same signer");

            expectedCancelledBy[pid][whoSigner] = true;
            expectedCancelCount[pid] += 1;

            if (expectedCancelCount[pid] >= 2) {
                expectedState[pid] = IntentGuardModule.ProposalState.Cancelled;
            }
        } catch {
            // Expected when state != Queued OR signer already cancelled OR not a signer.
        }
    }

    /// @dev Try to execute a proposal. Will succeed only if state == Queued,
    /// nonce matches the live vault nonce (i.e. it's the next-in-line),
    /// not expired, and cool-off+executeDelay has elapsed.
    function execute_(uint256 pidSeed) external {
        if (proposalIds.length == 0) return;
        bytes32 pid = proposalIds[pidSeed % proposalIds.length];

        // Reconstruct the exact data bytes used at queue from ghost state.
        bytes memory data = proposalData[pid];

        uint64 currentNonce = this.moduleNonce();
        IntentGuardModule.ProposalState preState = this.liveState(pid);
        uint64 preProposalNonce = this.liveProposalNonce(pid);
        uint64 preQueuedAt = this.liveQueuedAt(pid);
        bool preExecuted = executedOnce[pid];

        try module.execute(pid, data) {
            // Module accepted execution.
            require(preState == IntentGuardModule.ProposalState.Queued, "INVARIANT VIOLATION: execute on non-Queued");
            require(preProposalNonce == currentNonce, "INVARIANT VIOLATION: execute with stale nonce");
            require(uint64(block.timestamp) >= preQueuedAt + COOLOFF + EXECUTE_DELAY, "INVARIANT VIOLATION: execute during cool-off");
            require(!preExecuted, "INVARIANT VIOLATION: same proposalId executed twice");

            expectedState[pid] = IntentGuardModule.ProposalState.Executed;
            executedOnce[pid] = true;
            executedCount += 1;
            expectedVaultNonce += 1;
        } catch {
            // Catch-all: stale nonce, bad-state, cool-off, bad-intent (data mismatch),
            // or expired. None of these should violate invariants.
        }
    }

    /// @dev Time travel forward, bounded so cool-off can be cleared but
    /// proposals don't trivially expire (PROPOSAL_LIFETIME_PAD = 30 days).
    function warp_(uint256 secs) external {
        secs = bound(secs, 1, 7 days);
        vm.warp(block.timestamp + secs);
    }
}

/// @notice The invariant test contract that targets the handler. Foundry's
/// invariant fuzzer will call random handler functions in sequence between
/// each invariant check.
contract IntentGuardInvariantsTest is StdInvariant, Test {
    IntentGuardHandler public handler;

    function setUp() public {
        handler = new IntentGuardHandler();

        // Restrict the fuzzer to handler entry points.
        targetContract(address(handler));

        // Don't let the fuzzer call into the module / adapters / safe directly —
        // those would produce arbitrary state outside our handler's tracking.
        bytes4[] memory selectors = new bytes4[](6);
        selectors[0] = IntentGuardHandler.queue_.selector;
        selectors[1] = IntentGuardHandler.queueDisposable_.selector;
        selectors[2] = IntentGuardHandler.cancel_.selector;
        selectors[3] = IntentGuardHandler.execute_.selector;
        selectors[4] = IntentGuardHandler.warp_.selector;
        selectors[5] = IntentGuardHandler.toggleDisposableAdapter_.selector;
        targetSelector(FuzzSelector({addr: address(handler), selectors: selectors}));
    }

    // ============ invariants ============

    /// @dev Invariant 1 (nonce monotonicity / nonce == executed count):
    /// vault.nonce equals the number of successful executes the handler
    /// observed. Because the handler's `expectedVaultNonce` ghost is only
    /// ever incremented (never decremented), equality with the live nonce
    /// implies the live nonce is also monotonically non-decreasing — and
    /// strictly +1 per accepted execute.
    function invariant_nonceEqualsExecuteCount() public view {
        uint64 live = handler.moduleNonce();
        assertEq(live, handler.expectedVaultNonce(), "vault.nonce diverged from ghost-tracked execute count");
    }

    /// @dev Invariant 3 (state machine soundness):
    /// For every tracked proposal, the live module state must match the
    /// ghost state computed by valid transitions. This implies:
    ///   - state ∈ {None, Queued, Cancelled, Executed} (enum)
    ///   - transitions only follow None → Queued → {Cancelled | Executed}
    ///   - terminal states (Cancelled, Executed) never revert to Queued
    ///   - Queued state never re-enters from Cancelled/Executed
    /// The ghost only ever transitions in the legal direction; if the module
    /// ever sits in a different state, that's a violation.
    function invariant_stateMachineSoundness() public view {
        uint256 n = handler.proposalIdsLength();
        for (uint256 i = 0; i < n; i++) {
            bytes32 pid = handler.proposalIds(i);
            IntentGuardModule.ProposalState live = handler.liveState(pid);
            IntentGuardModule.ProposalState ghost = handler.expectedState(pid);
            assertEq(uint256(live), uint256(ghost), "proposal state diverged from ghost");
        }
    }

    /// @dev Invariant 4 (veto monotonicity):
    /// cancelCount only ever increases; once it crosses vetoThreshold (= 2),
    /// state is Cancelled and cannot leave that state.
    function invariant_vetoMonotonic() public view {
        uint256 n = handler.proposalIdsLength();
        for (uint256 i = 0; i < n; i++) {
            bytes32 pid = handler.proposalIds(i);
            uint8 live = handler.liveCancelCount(pid);
            uint8 ghost = handler.expectedCancelCount(pid);
            assertEq(live, ghost, "cancelCount diverged from ghost");

            if (ghost >= 2) {
                IntentGuardModule.ProposalState liveState = handler.liveState(pid);
                assertEq(
                    uint256(liveState),
                    uint256(IntentGuardModule.ProposalState.Cancelled),
                    "ghost cancelCount >= veto threshold but live state != Cancelled"
                );
            }
        }
    }

    /// @dev Invariant 5 (replay protection):
    /// No proposalId that has been Executed can re-enter the Queued state.
    /// Equivalently: executedOnce[pid] ⇒ liveState(pid) == Executed.
    function invariant_replayProtection() public view {
        uint256 n = handler.proposalIdsLength();
        for (uint256 i = 0; i < n; i++) {
            bytes32 pid = handler.proposalIds(i);
            if (handler.executedOnce(pid)) {
                IntentGuardModule.ProposalState live = handler.liveState(pid);
                assertEq(
                    uint256(live),
                    uint256(IntentGuardModule.ProposalState.Executed),
                    "executed proposal escaped Executed terminal state"
                );
            }
        }
    }

    /// @dev Invariant 6 (cool-off enforcement, derived):
    /// For every executed proposal, block.timestamp at the time of execute
    /// must have been >= queuedAt + COOLOFF + EXECUTE_DELAY. This is asserted
    /// inline in handler.execute_ via require(); the invariant here re-checks
    /// the structural condition: if a proposal is Executed, its queuedAt
    /// must be at least COOLOFF + EXECUTE_DELAY in the past.
    function invariant_cooloffEnforced() public view {
        uint256 n = handler.proposalIdsLength();
        for (uint256 i = 0; i < n; i++) {
            bytes32 pid = handler.proposalIds(i);
            if (handler.executedOnce(pid)) {
                uint64 queuedAt = handler.expectedQueuedAt(pid);
                uint64 mustBeAfter = queuedAt + handler.COOLOFF() + handler.EXECUTE_DELAY();
                assertGe(uint64(block.timestamp), mustBeAfter, "execute observed before cool-off cleared");
            }
        }
    }

    /// @dev Invariant 7 (executed count consistency):
    /// expectedVaultNonce equals the count of executedOnce[pid] true entries
    /// across the tracked proposalIds, and equals the live vault.nonce.
    function invariant_executedCountConsistent() public view {
        uint256 counted;
        uint256 n = handler.proposalIdsLength();
        for (uint256 i = 0; i < n; i++) {
            bytes32 pid = handler.proposalIds(i);
            if (handler.executedOnce(pid)) counted++;
        }
        assertEq(counted, handler.executedCount(), "executedCount ghost diverged from per-pid ghosts");
        assertEq(uint64(counted), handler.moduleNonce(), "executed-pid count diverged from live vault.nonce");
    }

    // ============ self-validation ============

    /// @dev Sanity test (not an invariant): drive the handler manually to
    /// confirm the queue → warp → execute pipeline actually succeeds. If
    /// this regresses, the invariant fuzzer's executes are no-ops and the
    /// suite is silently weak.
    function test_handler_canExecute() public {
        handler.queue_(uint96(1), uint8(0));
        // Need to clear COOLOFF + EXECUTE_DELAY (= 3660s).
        handler.warp_(7 days);
        handler.execute_(0);

        assertEq(handler.executedCount(), 1, "handler did not execute a queued proposal end-to-end");
        assertEq(handler.moduleNonce(), 1, "module.vault.nonce did not advance after handler execute");
    }

    /// @dev Sanity test: a queue with a de-allowlisted disposable adapter
    /// reverts at the module boundary. This validates the
    /// allowlist-invariance assertion path inside queueDisposable_.
    function test_handler_disposableQueueRevertsWhenDeallowed() public {
        handler.toggleDisposableAdapter_(false);
        // Should not throw — the handler swallows the revert in its try/catch.
        handler.queueDisposable_(uint96(42));
        // No proposal should have been recorded.
        assertEq(handler.proposalIdsLength(), 0, "queue against de-allowlisted disposable adapter unexpectedly tracked");
    }
}
