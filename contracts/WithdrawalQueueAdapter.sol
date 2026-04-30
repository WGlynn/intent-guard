// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IActionAdapter} from "./IntentGuardModule.sol";

/// @notice Adapter for withdrawal-queue admin functions common to liquid
/// staking tokens (Lido stETH, Rocket Pool rETH, Frax sfrxETH), lending
/// markets with epoch-based withdrawal windows, and yield vaults with
/// delayed redemption:
///
///     setWithdrawalDelay(uint256 newDelay)
///     setMaxWithdrawalPerEpoch(uint256 newMax)
///     pauseWithdrawals()
///     unpauseWithdrawals()
///
/// Two attack classes the adapter defends against:
///
///   1. Lock-out: malicious `setWithdrawalDelay(MAX_UINT)` or
///      `pauseWithdrawals()` traps user funds while attacker positions
///      or exits elsewhere.
///   2. Drain: malicious `setMaxWithdrawalPerEpoch(MAX_UINT)` removes
///      the per-epoch rate limit and enables fast extraction.
///
/// Per-target policy bounds the delay parameter, bounds the
/// max-per-epoch parameter, and gates pause/unpause independently
/// (e.g. allow emergency pause but require manual operator unpause).
contract WithdrawalQueueAdapter is IActionAdapter {
    bytes4 public constant SET_WITHDRAWAL_DELAY_SELECTOR = bytes4(keccak256("setWithdrawalDelay(uint256)"));
    bytes4 public constant SET_MAX_PER_EPOCH_SELECTOR = bytes4(keccak256("setMaxWithdrawalPerEpoch(uint256)"));
    bytes4 public constant PAUSE_WITHDRAWALS_SELECTOR = bytes4(keccak256("pauseWithdrawals()"));
    bytes4 public constant UNPAUSE_WITHDRAWALS_SELECTOR = bytes4(keccak256("unpauseWithdrawals()"));

    bytes32 public constant SET_DELAY_INTENT_TYPEHASH = keccak256(
        "WithdrawalQueueSetDelay(address target,uint256 value,uint256 newDelay)"
    );
    bytes32 public constant SET_MAX_PER_EPOCH_INTENT_TYPEHASH = keccak256(
        "WithdrawalQueueSetMaxPerEpoch(address target,uint256 value,uint256 newMax)"
    );
    bytes32 public constant PAUSE_INTENT_TYPEHASH = keccak256(
        "WithdrawalQueuePause(address target,uint256 value)"
    );
    bytes32 public constant UNPAUSE_INTENT_TYPEHASH = keccak256(
        "WithdrawalQueueUnpause(address target,uint256 value)"
    );

    struct WithdrawalPolicy {
        bool allowed;
        uint256 minDelay;
        uint256 maxDelay;
        uint256 minMaxPerEpoch;
        uint256 maxMaxPerEpoch;
        bool pauseAllowed;
        bool unpauseAllowed;
    }

    address public immutable owner;
    mapping(address => WithdrawalPolicy) internal policy;

    event WithdrawalPolicySet(
        address indexed target,
        bool allowed,
        uint256 minDelay,
        uint256 maxDelay,
        uint256 minMaxPerEpoch,
        uint256 maxMaxPerEpoch,
        bool pauseAllowed,
        bool unpauseAllowed
    );

    error NotOwner();
    error BadSelector();
    error TargetNotAllowed();
    error DelayOutOfRange();
    error MaxPerEpochOutOfRange();
    error ActionNotAllowed();

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    constructor(address owner_) {
        owner = owner_;
    }

    function setWithdrawalPolicy(
        address target,
        bool allowed,
        uint256 minDelay,
        uint256 maxDelay,
        uint256 minMaxPerEpoch,
        uint256 maxMaxPerEpoch,
        bool pauseAllowed,
        bool unpauseAllowed
    ) external onlyOwner {
        policy[target] = WithdrawalPolicy({
            allowed: allowed,
            minDelay: minDelay,
            maxDelay: maxDelay,
            minMaxPerEpoch: minMaxPerEpoch,
            maxMaxPerEpoch: maxMaxPerEpoch,
            pauseAllowed: pauseAllowed,
            unpauseAllowed: unpauseAllowed
        });
        emit WithdrawalPolicySet(
            target, allowed, minDelay, maxDelay, minMaxPerEpoch, maxMaxPerEpoch, pauseAllowed, unpauseAllowed
        );
    }

    function getWithdrawalPolicy(address target) external view returns (WithdrawalPolicy memory) {
        return policy[target];
    }

    /// @inheritdoc IActionAdapter
    function intentHash(address target, uint256 value, bytes calldata data) external pure returns (bytes32) {
        bytes4 selector = _selector(data);
        if (selector == SET_WITHDRAWAL_DELAY_SELECTOR) {
            uint256 newDelay = _decodeUint(data);
            return keccak256(abi.encode(SET_DELAY_INTENT_TYPEHASH, target, value, newDelay));
        } else if (selector == SET_MAX_PER_EPOCH_SELECTOR) {
            uint256 newMax = _decodeUint(data);
            return keccak256(abi.encode(SET_MAX_PER_EPOCH_INTENT_TYPEHASH, target, value, newMax));
        } else if (selector == PAUSE_WITHDRAWALS_SELECTOR) {
            _expectNoArgs(data);
            return keccak256(abi.encode(PAUSE_INTENT_TYPEHASH, target, value));
        } else if (selector == UNPAUSE_WITHDRAWALS_SELECTOR) {
            _expectNoArgs(data);
            return keccak256(abi.encode(UNPAUSE_INTENT_TYPEHASH, target, value));
        } else {
            revert BadSelector();
        }
    }

    /// @inheritdoc IActionAdapter
    function validate(address target, uint256, bytes calldata data, bytes32) external view {
        bytes4 selector = _selector(data);
        WithdrawalPolicy memory pol = policy[target];
        if (!pol.allowed) revert TargetNotAllowed();

        if (selector == SET_WITHDRAWAL_DELAY_SELECTOR) {
            uint256 newDelay = _decodeUint(data);
            if (newDelay < pol.minDelay || newDelay > pol.maxDelay) revert DelayOutOfRange();
        } else if (selector == SET_MAX_PER_EPOCH_SELECTOR) {
            uint256 newMax = _decodeUint(data);
            if (newMax < pol.minMaxPerEpoch || newMax > pol.maxMaxPerEpoch) revert MaxPerEpochOutOfRange();
        } else if (selector == PAUSE_WITHDRAWALS_SELECTOR) {
            _expectNoArgs(data);
            if (!pol.pauseAllowed) revert ActionNotAllowed();
        } else if (selector == UNPAUSE_WITHDRAWALS_SELECTOR) {
            _expectNoArgs(data);
            if (!pol.unpauseAllowed) revert ActionNotAllowed();
        } else {
            revert BadSelector();
        }
    }

    function _selector(bytes calldata data) internal pure returns (bytes4 selector) {
        if (data.length < 4) revert BadSelector();
        assembly {
            selector := calldataload(data.offset)
        }
    }

    function _decodeUint(bytes calldata data) internal pure returns (uint256) {
        if (data.length != 4 + 32) revert BadSelector();
        return abi.decode(data[4:], (uint256));
    }

    function _expectNoArgs(bytes calldata data) internal pure {
        if (data.length != 4) revert BadSelector();
    }
}
