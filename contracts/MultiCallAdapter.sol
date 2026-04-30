// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IActionAdapter} from "./IntentGuardModule.sol";

/// @notice Adapter for the canonical "atomic batched call" admin pattern:
///
///     batchExecute(address[] targets, bytes[] payloads)
///
/// Multicall contracts let admin sequences run atomically — e.g. upgrade
/// impl + grant role + unpause, all in one transaction. The threat: an
/// attacker tricks signers into approving a malicious sub-call hidden inside
/// a batch where every other entry looks benign. Without per-sub-action
/// review the malicious entry slips through.
///
/// The adapter binds `keccak256(abi.encode(targets, payloads))` — the entire
/// batch as a single hash — into the typed intent so signers approve the
/// batch as an indivisible unit. Swapping any sub-target or any sub-payload
/// byte produces a different intent hash and breaks the signature.
///
/// `validate()` enforces three invariants at execute time:
///
///   1. The multicall target itself is on the top-level allowlist.
///   2. The decoded batch size is ≤ the per-target `maxBatchSize` cap
///      (when set), defending against gas griefing via huge batches.
///   3. Every sub-target in the decoded batch is on the per-multicall-target
///      sub-target allowlist.
///
/// Invariant (3) is the load-bearing check. Even if a signer is tricked
/// into approving a batch hash with a malicious sub-call, that sub-call
/// will not execute unless its target was pre-approved by the adapter
/// owner — the adapter owner acts as a second pair of eyes on the
/// destination address space.
contract MultiCallAdapter is IActionAdapter {
    bytes4 public constant BATCH_EXECUTE_SELECTOR =
        bytes4(keccak256("batchExecute(address[],bytes[])"));

    bytes32 public constant BATCH_INTENT_TYPEHASH = keccak256(
        "MultiCallBatch(address target,uint256 value,bytes32 batchHash)"
    );

    address public immutable owner;

    /// @notice Top-level allowlist: which multicall contracts the module
    /// is willing to dispatch through at all.
    mapping(address => bool) public multicallAllowed;

    /// @notice Per-multicall-target sub-target allowlist. A batch only
    /// passes `validate` if every entry's `target` is set true here.
    mapping(address => mapping(address => bool)) public subTargetAllowed;

    /// @notice Per-multicall-target maximum batch size. Zero means "no
    /// cap" (NOT recommended for production — set a sane ceiling so a
    /// malicious queuer can't grief execution gas with a 10k-entry batch).
    mapping(address => uint256) public maxBatchSize;

    event MulticallAllowed(address indexed multicallTarget, bool allowed);
    event SubTargetAllowed(
        address indexed multicallTarget,
        address indexed subTarget,
        bool allowed
    );
    event MaxBatchSizeSet(address indexed multicallTarget, uint256 maxSize);

    error NotOwner();
    error BadSelector();
    error MulticallNotAllowed();
    error SubTargetNotAllowed();
    error BatchTooLarge();
    error BatchLengthMismatch();
    error ZeroOwner();

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    constructor(address owner_) {
        if (owner_ == address(0)) revert ZeroOwner();
        owner = owner_;
    }

    // ============ Owner setters ============

    function setMulticallAllowed(address multicallTarget, bool allowed) external onlyOwner {
        multicallAllowed[multicallTarget] = allowed;
        emit MulticallAllowed(multicallTarget, allowed);
    }

    function setSubTargetAllowed(
        address multicallTarget,
        address subTarget,
        bool allowed
    ) external onlyOwner {
        subTargetAllowed[multicallTarget][subTarget] = allowed;
        emit SubTargetAllowed(multicallTarget, subTarget, allowed);
    }

    function setMaxBatchSize(address multicallTarget, uint256 maxSize) external onlyOwner {
        maxBatchSize[multicallTarget] = maxSize;
        emit MaxBatchSizeSet(multicallTarget, maxSize);
    }

    // ============ IActionAdapter ============

    /// @inheritdoc IActionAdapter
    function intentHash(address target, uint256 value, bytes calldata data)
        external
        pure
        returns (bytes32)
    {
        (address[] memory targets, bytes[] memory payloads) = _decode(data);
        bytes32 batchHash = keccak256(abi.encode(targets, payloads));
        return keccak256(
            abi.encode(BATCH_INTENT_TYPEHASH, target, value, batchHash)
        );
    }

    /// @inheritdoc IActionAdapter
    function validate(address target, uint256, bytes calldata data, bytes32) external view {
        if (!multicallAllowed[target]) revert MulticallNotAllowed();

        (address[] memory targets, ) = _decode(data);

        uint256 cap = maxBatchSize[target];
        if (cap > 0 && targets.length > cap) revert BatchTooLarge();

        // Every sub-target in the batch must be on the per-multicall-target
        // sub-target allowlist. Empty batches pass this loop trivially —
        // they are not useful but they are not unsafe either, and the
        // intent hash binding is enough to prevent replay.
        mapping(address => bool) storage allowed = subTargetAllowed[target];
        uint256 n = targets.length;
        for (uint256 i = 0; i < n; ++i) {
            if (!allowed[targets[i]]) revert SubTargetNotAllowed();
        }
    }

    // ============ Decode ============

    function _decode(bytes calldata data)
        internal
        pure
        returns (address[] memory targets, bytes[] memory payloads)
    {
        if (data.length < 4) revert BadSelector();
        bytes4 selector;
        assembly {
            selector := calldataload(data.offset)
        }
        if (selector != BATCH_EXECUTE_SELECTOR) revert BadSelector();

        // Minimum ABI-encoding of (address[], bytes[]) is two 32-byte
        // offsets + two 32-byte lengths = 128 bytes after the selector.
        if (data.length < 4 + 128) revert BadSelector();

        (targets, payloads) = abi.decode(data[4:], (address[], bytes[]));

        if (targets.length != payloads.length) revert BatchLengthMismatch();
    }
}
