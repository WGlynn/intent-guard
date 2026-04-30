// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IActionAdapter} from "./IntentGuardModule.sol";

/// @notice Adapter for the canonical "set the price oracle for an asset"
/// admin shape:
///
///     function setOracle(address asset, address oracle) external onlyOwner;
///
/// Common in lending markets (Aave, Compound, Morpho), oracle aggregators
/// (Chainlink consumers), and any protocol that maintains a per-asset
/// price feed.
///
/// Threat class: a malicious `setOracle(asset, attackerOracle)` is the
/// canonical price-manipulation attack. The attacker deploys an oracle
/// that returns whatever value they want, then drains the protocol via
/// the asset whose price is now under their control.
///
/// The adapter binds (target, asset, oracle) into the typed intent and
/// at execute time enforces a three-dimensional per-(target, asset)
/// oracle allowlist. Only oracle addresses explicitly registered for an
/// (asset on a specific target) pair pass validate. Unknown targets,
/// unknown assets, and unknown oracles all fail closed.
contract OracleSourceAdapter is IActionAdapter {
    bytes4 public constant SET_ORACLE_SELECTOR = bytes4(keccak256("setOracle(address,address)"));

    bytes32 public constant SET_ORACLE_INTENT_TYPEHASH = keccak256(
        "OracleSourceSet(address target,uint256 value,address asset,address oracle)"
    );

    address public immutable owner;

    /// @notice Three-dimensional allowlist:
    ///   allowed[target][asset][oracle] == true ⇒ oracle is permitted as
    ///   the price source for `asset` on `target`.
    ///
    /// Multiple oracles MAY be registered for the same (target, asset)
    /// pair (e.g. a primary feed and a fallback); validate passes if the
    /// signed-and-decoded oracle matches any registered entry.
    mapping(address target => mapping(address asset => mapping(address oracle => bool allowed)))
        public allowed;

    event OracleAllowed(
        address indexed target,
        address indexed asset,
        address indexed oracle,
        bool allowed
    );

    error NotOwner();
    error BadSelector();
    error OracleNotAllowed();

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    constructor(address owner_) {
        owner = owner_;
    }

    /// @notice Toggle an `(target, asset, oracle)` allowlist entry. Owner only.
    /// Setting `allowed_` to `false` removes the entry; the mapping returns
    /// `false` for any unset combination, so unregistered tuples always
    /// fail validate.
    function setOracleAllowed(
        address target,
        address asset,
        address oracle,
        bool allowed_
    ) external onlyOwner {
        allowed[target][asset][oracle] = allowed_;
        emit OracleAllowed(target, asset, oracle, allowed_);
    }

    /// @inheritdoc IActionAdapter
    function intentHash(address target, uint256 value, bytes calldata data)
        external
        pure
        returns (bytes32)
    {
        (address asset, address oracle) = _decode(data);
        return keccak256(
            abi.encode(SET_ORACLE_INTENT_TYPEHASH, target, value, asset, oracle)
        );
    }

    /// @inheritdoc IActionAdapter
    function validate(address target, uint256, bytes calldata data, bytes32) external view {
        (address asset, address oracle) = _decode(data);
        if (!allowed[target][asset][oracle]) revert OracleNotAllowed();
    }

    function _decode(bytes calldata data) internal pure returns (address asset, address oracle) {
        if (data.length != 4 + 32 * 2) revert BadSelector();
        bytes4 selector;
        assembly {
            selector := calldataload(data.offset)
        }
        if (selector != SET_ORACLE_SELECTOR) revert BadSelector();
        (asset, oracle) = abi.decode(data[4:], (address, address));
    }
}
