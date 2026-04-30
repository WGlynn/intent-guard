// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IActionAdapter} from "./IntentGuardModule.sol";

/// @notice Adapter for OpenZeppelin Ownable ownership administration:
///
///     transferOwnership(address newOwner)
///     renounceOwnership()
///
/// Ownership is the root of every Ownable hierarchy. A malicious
/// `transferOwnership(attacker)` is the protocol-ending event. A
/// malicious `renounceOwnership()` permanently locks the protocol with
/// no path to upgrade or recover.
///
/// The adapter binds (action, target, newOwner) into the typed intent
/// and at execute time enforces:
///
///   - Per-target newOwner allowlist for transferOwnership. Only
///     pre-approved owner candidates can be set.
///   - Per-target `renounceAllowed` flag for renounceOwnership.
///     Defaults to false — renouncing is usually a foot-gun and most
///     protocols want it permanently disabled. Owner must opt in.
contract OwnershipTransferAdapter is IActionAdapter {
    bytes4 public constant TRANSFER_OWNERSHIP_SELECTOR = bytes4(keccak256("transferOwnership(address)"));
    bytes4 public constant RENOUNCE_OWNERSHIP_SELECTOR = bytes4(keccak256("renounceOwnership()"));

    bytes32 public constant TRANSFER_INTENT_TYPEHASH = keccak256(
        "OwnershipTransfer(address target,uint256 value,address newOwner)"
    );
    bytes32 public constant RENOUNCE_INTENT_TYPEHASH = keccak256(
        "OwnershipRenounce(address target,uint256 value)"
    );

    enum Action {
        Transfer,
        Renounce
    }

    struct TargetPolicy {
        bool transferAllowed;
        bool renounceAllowed;
    }

    address public immutable owner;
    mapping(address => TargetPolicy) public targetPolicy;
    // allowedNewOwner[target][candidate]
    mapping(address => mapping(address => bool)) public allowedNewOwner;

    event TargetPolicySet(address indexed target, bool transferAllowed, bool renounceAllowed);
    event AllowedNewOwnerSet(address indexed target, address indexed candidate, bool allowed);

    error NotOwner();
    error BadSelector();
    error ActionNotAllowed();
    error NewOwnerNotAllowed();
    error ZeroOwner();
    error TransferToZero();

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    constructor(address owner_) {
        if (owner_ == address(0)) revert ZeroOwner();
        owner = owner_;
    }

    function setTargetPolicy(address target, bool transferAllowed, bool renounceAllowed) external onlyOwner {
        targetPolicy[target] = TargetPolicy({transferAllowed: transferAllowed, renounceAllowed: renounceAllowed});
        emit TargetPolicySet(target, transferAllowed, renounceAllowed);
    }

    function setAllowedNewOwner(address target, address candidate, bool allowed) external onlyOwner {
        allowedNewOwner[target][candidate] = allowed;
        emit AllowedNewOwnerSet(target, candidate, allowed);
    }

    /// @inheritdoc IActionAdapter
    function intentHash(address target, uint256 value, bytes calldata data) external pure returns (bytes32) {
        (Action action, address newOwner) = _decode(data);
        if (action == Action.Transfer) {
            return keccak256(abi.encode(TRANSFER_INTENT_TYPEHASH, target, value, newOwner));
        }
        return keccak256(abi.encode(RENOUNCE_INTENT_TYPEHASH, target, value));
    }

    /// @inheritdoc IActionAdapter
    function validate(address target, uint256, bytes calldata data, bytes32) external view {
        (Action action, address newOwner) = _decode(data);
        TargetPolicy memory pol = targetPolicy[target];

        if (action == Action.Transfer) {
            if (!pol.transferAllowed) revert ActionNotAllowed();
            // `transferOwnership(address(0))` is semantically equivalent to
            // `renounceOwnership()` in OZ Ownable. Without this check, a
            // signer (or owner who allowlisted address(0)) could bypass the
            // dedicated `renounceAllowed` gate by routing the renounce
            // through the transfer selector. Reject zero-address transfers
            // unconditionally — callers wanting to renounce must use the
            // renounce selector with `renounceAllowed = true`.
            if (newOwner == address(0)) revert TransferToZero();
            if (!allowedNewOwner[target][newOwner]) revert NewOwnerNotAllowed();
        } else {
            if (!pol.renounceAllowed) revert ActionNotAllowed();
        }
    }

    function _decode(bytes calldata data) internal pure returns (Action action, address newOwner) {
        if (data.length < 4) revert BadSelector();
        bytes4 selector;
        assembly {
            selector := calldataload(data.offset)
        }
        if (selector == TRANSFER_OWNERSHIP_SELECTOR) {
            if (data.length != 4 + 32) revert BadSelector();
            action = Action.Transfer;
            newOwner = abi.decode(data[4:], (address));
        } else if (selector == RENOUNCE_OWNERSHIP_SELECTOR) {
            if (data.length != 4) revert BadSelector();
            action = Action.Renounce;
            newOwner = address(0);
        } else {
            revert BadSelector();
        }
    }
}
