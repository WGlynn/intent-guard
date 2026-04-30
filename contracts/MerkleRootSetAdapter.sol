// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IActionAdapter} from "./IntentGuardModule.sol";

/// @notice Adapter for the canonical "set the allowlist Merkle root" admin
/// shape:
///
///     setMerkleRoot(bytes32 root)
///
/// Common in airdrop claim contracts, KYC gates, claim-window
/// distributions, and any protocol that uses a Merkle tree to
/// allowlist a fixed set of addresses or claims.
///
/// The attack class: an attacker tricks signers into setting a Merkle
/// root they computed off-chain — one that includes the attacker's
/// addresses with inflated allocations. Without an off-chain
/// pre-announcement step, the only thing signers can verify is the
/// 32-byte root hash, which carries no semantics by itself.
///
/// The adapter binds (target, root) into the typed intent and at
/// execute time enforces a **pre-announcement** requirement:
///
///   - The owner must call `announceMerkleRoot(target, root)` BEFORE the
///     proposal is queued. The announcement records the announcer +
///     timestamp so off-chain monitors can verify the root is the one
///     the team intended.
///   - validate() rejects any root whose pre-announcement is missing.
///
/// This converts "trust the signer flow" into "trust the public
/// announcement record" — the same pattern intent-guard applies at the
/// transaction level, applied here at the data-construction level.
contract MerkleRootSetAdapter is IActionAdapter {
    bytes4 public constant SET_MERKLE_ROOT_SELECTOR = bytes4(keccak256("setMerkleRoot(bytes32)"));

    bytes32 public constant SET_MERKLE_ROOT_INTENT_TYPEHASH = keccak256(
        "MerkleRootSet(address target,uint256 value,bytes32 root)"
    );

    struct TargetPolicy {
        bool allowed;
        // If true, the root must have been announced before queueing.
        // Default: true. Setting to false allows skipping pre-announcement
        // for low-stakes targets (NOT recommended).
        bool requireAnnouncement;
    }

    struct Announcement {
        bool announced;
        address announcer;
        uint64 announcedAt;
    }

    address public immutable owner;
    mapping(address => TargetPolicy) public targetPolicy;
    // announcement[target][root]
    mapping(address => mapping(bytes32 => Announcement)) public announcement;

    event TargetPolicySet(address indexed target, bool allowed, bool requireAnnouncement);
    event MerkleRootAnnounced(address indexed target, bytes32 indexed root, address indexed announcer, uint64 announcedAt);

    error NotOwner();
    error BadSelector();
    error TargetNotAllowed();
    error RootNotAnnounced();

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    constructor(address owner_) {
        owner = owner_;
    }

    function setTargetPolicy(address target, bool allowed, bool requireAnnouncement) external onlyOwner {
        targetPolicy[target] = TargetPolicy({allowed: allowed, requireAnnouncement: requireAnnouncement});
        emit TargetPolicySet(target, allowed, requireAnnouncement);
    }

    /// @notice Pre-announce a Merkle root for a target. Should be called
    /// off-chain (or by an off-chain monitor) before the proposal is
    /// queued, leaving an on-chain breadcrumb signers can cross-check.
    function announceMerkleRoot(address target, bytes32 root) external onlyOwner {
        announcement[target][root] = Announcement({
            announced: true,
            announcer: msg.sender,
            announcedAt: uint64(block.timestamp)
        });
        emit MerkleRootAnnounced(target, root, msg.sender, uint64(block.timestamp));
    }

    /// @inheritdoc IActionAdapter
    function intentHash(address target, uint256 value, bytes calldata data) external pure returns (bytes32) {
        bytes32 root = _decode(data);
        return keccak256(abi.encode(SET_MERKLE_ROOT_INTENT_TYPEHASH, target, value, root));
    }

    /// @inheritdoc IActionAdapter
    function validate(address target, uint256, bytes calldata data, bytes32) external view {
        TargetPolicy memory pol = targetPolicy[target];
        if (!pol.allowed) revert TargetNotAllowed();

        if (pol.requireAnnouncement) {
            bytes32 root = _decode(data);
            if (!announcement[target][root].announced) revert RootNotAnnounced();
        }
    }

    function _decode(bytes calldata data) internal pure returns (bytes32 root) {
        if (data.length != 4 + 32) revert BadSelector();
        bytes4 selector;
        assembly {
            selector := calldataload(data.offset)
        }
        if (selector != SET_MERKLE_ROOT_SELECTOR) revert BadSelector();
        root = abi.decode(data[4:], (bytes32));
    }
}
