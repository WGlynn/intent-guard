// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IActionAdapter} from "./IntentGuardModule.sol";

/// @notice Adapter for the canonical "set a numeric parameter" admin shape:
///
///     setParam(bytes32 key, uint256 value)
///
/// This pattern covers a large swath of protocol governance: circuit-breaker
/// thresholds (volume cap, price-deviation cap, withdrawal cap), oracle
/// staleness tolerance, fee tiers, AMM parameters (TWAP window, slippage
/// floor), Shapley weights, Fibonacci-damping coefficients — anything where
/// the admin call is "name a param, set its value."
///
/// Intent binding: signers approve (target, key, value).
///
/// validate() enforces per-(target, key) bounds:
///
///   - The (target, key) pair must be on the allowlist
///   - New value must be in [minValue, maxValue] inclusive
///   - Optional: max ratio of change from a registered "current" baseline
///     value (caller updates baseline as values change). Catches drift
///     attacks where each individual change passes bounds but the
///     cumulative drift defeats the cap.
///
/// The bounds protect against the social-engineering case where signers
/// approve a value within technical bounds but outside operational sanity
/// (e.g. setting a circuit-breaker volume cap to MAX_UINT, effectively
/// disabling the breaker).
contract BoundedParameterAdapter is IActionAdapter {
    bytes4 public constant SET_PARAM_SELECTOR = bytes4(keccak256("setParam(bytes32,uint256)"));

    bytes32 public constant SET_PARAM_INTENT_TYPEHASH = keccak256(
        "BoundedParam(address target,uint256 value,bytes32 key,uint256 newValue)"
    );

    uint256 public constant BPS = 10_000;

    struct ParamPolicy {
        bool allowed;
        uint256 minValue;
        uint256 maxValue;
        // Max change in bps from the registered baseline. 0 means no
        // ratio check (only min/max bounds apply).
        uint256 maxChangeBps;
        uint256 baseline;
    }

    address public immutable owner;
    // paramPolicy[target][key]
    mapping(address => mapping(bytes32 => ParamPolicy)) internal paramPolicy;

    event ParamPolicySet(
        address indexed target,
        bytes32 indexed key,
        bool allowed,
        uint256 minValue,
        uint256 maxValue,
        uint256 maxChangeBps,
        uint256 baseline
    );
    event BaselineUpdated(address indexed target, bytes32 indexed key, uint256 newBaseline);

    error NotOwner();
    error BadSelector();
    error ParamNotAllowed();
    error BelowMin();
    error AboveMax();
    error ExceedsChangeRatio();
    error ZeroOwner();
    error InvalidBounds();

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    constructor(address owner_) {
        if (owner_ == address(0)) revert ZeroOwner();
        owner = owner_;
    }

    function setParamPolicy(
        address target,
        bytes32 key,
        bool allowed,
        uint256 minValue,
        uint256 maxValue,
        uint256 maxChangeBps,
        uint256 baseline
    ) external onlyOwner {
        // Reject inverted bounds. With minValue > maxValue every newValue
        // would fail validate (BelowMin or AboveMax), but the policy would
        // silently exist on-chain and look "active" via getParamPolicy.
        // Fail loud at policy-set time so owners notice the mistake.
        // The check only applies when allowed = true (a disabled policy
        // can carry any sentinel values).
        if (allowed && minValue > maxValue) revert InvalidBounds();
        paramPolicy[target][key] = ParamPolicy({
            allowed: allowed,
            minValue: minValue,
            maxValue: maxValue,
            maxChangeBps: maxChangeBps,
            baseline: baseline
        });
        emit ParamPolicySet(target, key, allowed, minValue, maxValue, maxChangeBps, baseline);
    }

    /// @notice Update the baseline value for a (target, key) pair. Should
    /// be called after a successful parameter change so the next
    /// proposal's max-change ratio check is computed from the new value.
    function updateBaseline(address target, bytes32 key, uint256 newBaseline) external onlyOwner {
        paramPolicy[target][key].baseline = newBaseline;
        emit BaselineUpdated(target, key, newBaseline);
    }

    function getParamPolicy(address target, bytes32 key) external view returns (ParamPolicy memory) {
        return paramPolicy[target][key];
    }

    /// @inheritdoc IActionAdapter
    function intentHash(address target, uint256 value, bytes calldata data) external pure returns (bytes32) {
        (bytes32 key, uint256 newValue) = _decode(data);
        return keccak256(abi.encode(SET_PARAM_INTENT_TYPEHASH, target, value, key, newValue));
    }

    /// @inheritdoc IActionAdapter
    function validate(address target, uint256, bytes calldata data, bytes32) external view {
        (bytes32 key, uint256 newValue) = _decode(data);
        ParamPolicy memory pol = paramPolicy[target][key];

        if (!pol.allowed) revert ParamNotAllowed();
        if (newValue < pol.minValue) revert BelowMin();
        if (newValue > pol.maxValue) revert AboveMax();

        if (pol.maxChangeBps > 0 && pol.baseline > 0) {
            uint256 diff = newValue > pol.baseline ? newValue - pol.baseline : pol.baseline - newValue;
            if (diff * BPS > pol.baseline * pol.maxChangeBps) revert ExceedsChangeRatio();
        }
    }

    function _decode(bytes calldata data) internal pure returns (bytes32 key, uint256 newValue) {
        if (data.length != 4 + 32 * 2) revert BadSelector();
        bytes4 selector;
        assembly {
            selector := calldataload(data.offset)
        }
        if (selector != SET_PARAM_SELECTOR) revert BadSelector();
        return abi.decode(data[4:], (bytes32, uint256));
    }
}
