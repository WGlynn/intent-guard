// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IActionAdapter} from "./IntentGuardModule.sol";

/// @notice Adapter for protocols with explicit emergency-shutdown sequences:
///
///     triggerEmergencyShutdown()
///     cancelShutdown()
///
/// Common in MakerDAO (DAI emergency shutdown), Liquity (recovery
/// modes), legacy stable protocols, and any system with an irrevocable
/// kill-switch.
///
/// Two attack patterns:
///   1. Premature shutdown: a malicious or socially-engineered trigger
///      ends the protocol. Often irrevocable depending on design.
///   2. Shutdown hostage: an attacker triggers shutdown then cancels in
///      a pattern that disrupts the system or extracts during the
///      disruption window.
///
/// The adapter gates both directions, with a strong default toward
/// shutdown being a permanent action: cancelShutdown is disabled by
/// default per target. Most protocols treat shutdown as irrevocable;
/// permitting cancel re-introduces the trigger-then-cancel disruption
/// attack class.
contract EmergencyShutdownAdapter is IActionAdapter {
    bytes4 public constant TRIGGER_SHUTDOWN_SELECTOR = bytes4(keccak256("triggerEmergencyShutdown()"));
    bytes4 public constant CANCEL_SHUTDOWN_SELECTOR = bytes4(keccak256("cancelShutdown()"));

    bytes32 public constant TRIGGER_INTENT_TYPEHASH = keccak256(
        "EmergencyShutdownTrigger(address target,uint256 value)"
    );
    bytes32 public constant CANCEL_INTENT_TYPEHASH = keccak256(
        "EmergencyShutdownCancel(address target,uint256 value)"
    );

    struct ShutdownPolicy {
        bool triggerAllowed;
        bool cancelAllowed;
    }

    address public immutable owner;
    mapping(address target => ShutdownPolicy) public policy;

    event PolicySet(address indexed target, bool triggerAllowed, bool cancelAllowed);

    error NotOwner();
    error BadSelector();
    error ZeroOwner();
    error TriggerNotAllowed();
    error CancelNotAllowed();

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    constructor(address owner_) {
        if (owner_ == address(0)) revert ZeroOwner();
        owner = owner_;
    }

    function setPolicy(address target, bool triggerAllowed, bool cancelAllowed) external onlyOwner {
        policy[target] = ShutdownPolicy({triggerAllowed: triggerAllowed, cancelAllowed: cancelAllowed});
        emit PolicySet(target, triggerAllowed, cancelAllowed);
    }

    /// @inheritdoc IActionAdapter
    function intentHash(address target, uint256 value, bytes calldata data) external pure returns (bytes32) {
        bytes4 selector = _decodeSelector(data);
        if (selector == TRIGGER_SHUTDOWN_SELECTOR) {
            return keccak256(abi.encode(TRIGGER_INTENT_TYPEHASH, target, value));
        }
        return keccak256(abi.encode(CANCEL_INTENT_TYPEHASH, target, value));
    }

    /// @inheritdoc IActionAdapter
    function validate(address target, uint256, bytes calldata data, bytes32) external view {
        bytes4 selector = _decodeSelector(data);
        ShutdownPolicy memory pol = policy[target];
        if (selector == TRIGGER_SHUTDOWN_SELECTOR) {
            if (!pol.triggerAllowed) revert TriggerNotAllowed();
        } else {
            if (!pol.cancelAllowed) revert CancelNotAllowed();
        }
    }

    function _decodeSelector(bytes calldata data) internal pure returns (bytes4 selector) {
        if (data.length != 4) revert BadSelector();
        assembly {
            selector := calldataload(data.offset)
        }
        if (selector != TRIGGER_SHUTDOWN_SELECTOR && selector != CANCEL_SHUTDOWN_SELECTOR) revert BadSelector();
    }
}
