// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IActionAdapter} from "./IntentGuardModule.sol";

/// @notice Adapter for OpenZeppelin Pausable pause/unpause administration:
///
///     pause()
///     unpause()
///
/// Pause/unpause is a small but high-leverage attack surface. A protocol
/// can be locked indefinitely by a malicious `pause()` (no `unpause()`
/// follow-up), trapping user funds while an attacker positions
/// elsewhere. Equally, a malicious `unpause()` during a known-bad period
/// can re-open the protocol while it's still vulnerable.
///
/// The adapter binds (action, target) into the typed intent and at
/// execute time enforces:
///
///   - Per-target opt-in: pause and unpause each gated independently
///     (allow protocols that want to keep `unpause()` permissioned
///     even while `pause()` is delegated to faster emergency paths)
contract PausableAdapter is IActionAdapter {
    bytes4 public constant PAUSE_SELECTOR = bytes4(keccak256("pause()"));
    bytes4 public constant UNPAUSE_SELECTOR = bytes4(keccak256("unpause()"));

    bytes32 public constant PAUSE_INTENT_TYPEHASH = keccak256(
        "PausableAction(address target,uint256 value,bytes4 selector)"
    );

    enum Action {
        Pause,
        Unpause
    }

    struct TargetPolicy {
        bool pauseAllowed;
        bool unpauseAllowed;
    }

    address public immutable owner;
    mapping(address => TargetPolicy) public targetPolicy;

    event TargetPolicySet(address indexed target, bool pauseAllowed, bool unpauseAllowed);

    error NotOwner();
    error BadSelector();
    error ActionNotAllowed();
    error ZeroOwner();

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    constructor(address owner_) {
        if (owner_ == address(0)) revert ZeroOwner();
        owner = owner_;
    }

    function setTargetPolicy(address target, bool pauseAllowed, bool unpauseAllowed) external onlyOwner {
        targetPolicy[target] = TargetPolicy({pauseAllowed: pauseAllowed, unpauseAllowed: unpauseAllowed});
        emit TargetPolicySet(target, pauseAllowed, unpauseAllowed);
    }

    /// @inheritdoc IActionAdapter
    function intentHash(address target, uint256 value, bytes calldata data) external pure returns (bytes32) {
        bytes4 selector = _decodeSelector(data);
        return keccak256(abi.encode(PAUSE_INTENT_TYPEHASH, target, value, selector));
    }

    /// @inheritdoc IActionAdapter
    function validate(address target, uint256, bytes calldata data, bytes32) external view {
        bytes4 selector = _decodeSelector(data);
        TargetPolicy memory pol = targetPolicy[target];
        if (selector == PAUSE_SELECTOR) {
            if (!pol.pauseAllowed) revert ActionNotAllowed();
        } else {
            if (!pol.unpauseAllowed) revert ActionNotAllowed();
        }
    }

    function _decodeSelector(bytes calldata data) internal pure returns (bytes4 selector) {
        if (data.length != 4) revert BadSelector();
        assembly {
            selector := calldataload(data.offset)
        }
        if (selector != PAUSE_SELECTOR && selector != UNPAUSE_SELECTOR) revert BadSelector();
    }
}
