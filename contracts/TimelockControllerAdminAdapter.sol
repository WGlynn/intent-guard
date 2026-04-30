// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IActionAdapter} from "./IntentGuardModule.sol";

/// @notice Adapter for the OpenZeppelin `TimelockController` admin surface.
/// Specifically gates the load-bearing governance call:
///
///     updateDelay(uint256 newDelay)
///
/// `updateDelay` is the load-bearing attack on a TimelockController.
/// The whole point of a timelock is that privileged calls have to wait
/// `delay` seconds between scheduling and execution, giving holders time
/// to react. An attacker who controls the proposer/executor roles (or
/// who has compromised signers) can pre-stage a `updateDelay(1)` call
/// and, the moment it lands, execute every other queued attack with a
/// 1-second wait. Lowering the delay defeats the timelock.
///
/// This adapter forces signers' approval of an updateDelay call to be
/// bound to the specific newDelay, AND enforces a per-target [minDelay,
/// maxDelay] band at validate() time. Even if signers approve a value
/// inside the technical bounds (e.g. 1 second) by mistake or under
/// social-engineering pressure, the policy floor blocks the call.
///
/// `grantRole` / `revokeRole` on the TimelockController's AccessControl
/// surface are intentionally NOT covered here — they are the
/// responsibility of `RoleGrantAdapter`. That adapter already handles
/// the role-administration shape uniformly across any AccessControl
/// contract (TimelockController included).
contract TimelockControllerAdminAdapter is IActionAdapter {
    bytes4 public constant UPDATE_DELAY_SELECTOR = bytes4(keccak256("updateDelay(uint256)"));

    bytes32 public constant UPDATE_DELAY_INTENT_TYPEHASH = keccak256(
        "TimelockUpdateDelay(address target,uint256 value,uint256 newDelay)"
    );

    struct DelayPolicy {
        bool allowed;
        uint256 minDelay;
        uint256 maxDelay;
    }

    address public immutable owner;
    mapping(address => DelayPolicy) internal delayPolicy;

    event DelayPolicySet(address indexed target, bool allowed, uint256 minDelay, uint256 maxDelay);

    error NotOwner();
    error BadSelector();
    error TargetNotAllowed();
    error BelowMinDelay();
    error AboveMaxDelay();
    error BadBand();

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    constructor(address owner_) {
        owner = owner_;
    }

    /// @notice Set the updateDelay policy for a TimelockController target.
    /// `minDelay` is the floor (e.g. 24 hours). `maxDelay` is the ceiling
    /// (defaults can be type(uint256).max if no upper bound is desired,
    /// but a sane operational ceiling is recommended). Setting `allowed`
    /// to false disables the adapter for this target.
    function setDelayPolicy(address target, bool allowed, uint256 minDelay, uint256 maxDelay) external onlyOwner {
        if (allowed && minDelay > maxDelay) revert BadBand();
        delayPolicy[target] = DelayPolicy({allowed: allowed, minDelay: minDelay, maxDelay: maxDelay});
        emit DelayPolicySet(target, allowed, minDelay, maxDelay);
    }

    function getDelayPolicy(address target) external view returns (DelayPolicy memory) {
        return delayPolicy[target];
    }

    /// @inheritdoc IActionAdapter
    function intentHash(address target, uint256 value, bytes calldata data) external pure returns (bytes32) {
        uint256 newDelay = _decode(data);
        return keccak256(abi.encode(UPDATE_DELAY_INTENT_TYPEHASH, target, value, newDelay));
    }

    /// @inheritdoc IActionAdapter
    function validate(address target, uint256, bytes calldata data, bytes32) external view {
        DelayPolicy memory pol = delayPolicy[target];
        if (!pol.allowed) revert TargetNotAllowed();

        uint256 newDelay = _decode(data);
        if (newDelay < pol.minDelay) revert BelowMinDelay();
        if (newDelay > pol.maxDelay) revert AboveMaxDelay();
    }

    function _decode(bytes calldata data) internal pure returns (uint256 newDelay) {
        if (data.length != 4 + 32) revert BadSelector();
        bytes4 selector;
        assembly {
            selector := calldataload(data.offset)
        }
        if (selector != UPDATE_DELAY_SELECTOR) revert BadSelector();
        newDelay = abi.decode(data[4:], (uint256));
    }
}
