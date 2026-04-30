// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IActionAdapter} from "./IntentGuardModule.sol";

/// @notice Adapter for the OpenZeppelin Transparent Proxy admin pattern, where
/// upgrades flow through a `ProxyAdmin` contract rather than through the
/// proxy itself (the UUPS pattern). The ProxyAdmin's privileged calls:
///
///     upgrade(address proxy, address implementation)
///     upgradeAndCall(address proxy, address implementation, bytes data)
///
/// (OZ 4.x and 5.x ABIs both use this shape, with 5.x folding `upgrade` into
/// `upgradeAndCall(address,address,bytes)` in some variants. This adapter
/// supports both selectors explicitly.)
///
/// Threat class: same as UUPS — pre-signed approval for an implementation
/// address gets exploited via CREATE2 + SELFDESTRUCT redeployment between
/// sign-time and execute-time. The ProxyAdmin pattern adds one more layer
/// of indirection (an extra contract between Safe and proxy) but the
/// underlying attack class is identical.
///
/// Adapter binds (proxy, newImplementation, callDataHash) into the typed
/// intent. `validate()` enforces:
///
///   1. The proxy is on the per-(proxyAdmin, proxy) allowlist
///   2. The new implementation is on the per-proxy implementation allowlist
///   3. The new implementation's runtime EXTCODEHASH matches the codehash
///      registered for it
///
/// The "target" passed to the adapter is the **ProxyAdmin** address. The
/// "proxy" is the first argument of the call's calldata.
contract ProxyAdminAdapter is IActionAdapter {
    bytes4 public constant UPGRADE_SELECTOR = bytes4(keccak256("upgrade(address,address)"));
    bytes4 public constant UPGRADE_AND_CALL_SELECTOR = bytes4(keccak256("upgradeAndCall(address,address,bytes)"));

    bytes32 public constant UPGRADE_INTENT_TYPEHASH = keccak256(
        "ProxyAdminUpgrade(address target,uint256 value,address proxy,address newImplementation,bytes32 callDataHash)"
    );

    struct ProxyPolicy {
        bool allowed;
        // Per-proxy mapping of (newImpl => expectedCodehash). Zero means
        // implementation NOT allowed.
        mapping(address => bytes32) allowedImplCodehash;
    }

    address public immutable owner;
    // proxyPolicy[proxyAdmin][proxy]
    mapping(address => mapping(address => ProxyPolicy)) internal proxyPolicy;

    event ProxyAllowed(address indexed proxyAdmin, address indexed proxy, bool allowed);
    event ImplAllowed(address indexed proxyAdmin, address indexed proxy, address indexed impl, bytes32 expectedCodehash);

    error NotOwner();
    error BadSelector();
    error ProxyNotAllowed();
    error ImplNotAllowed();
    error CodehashMismatch();

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    constructor(address owner_) {
        owner = owner_;
    }

    /// @notice Toggle a (proxyAdmin, proxy) pair on the allowlist.
    function setProxyAllowed(address proxyAdmin, address proxy, bool allowed) external onlyOwner {
        proxyPolicy[proxyAdmin][proxy].allowed = allowed;
        emit ProxyAllowed(proxyAdmin, proxy, allowed);
    }

    /// @notice Register an expected codehash for `(proxyAdmin, proxy, impl)`.
    function setImplCodehash(address proxyAdmin, address proxy, address impl, bytes32 expectedCodehash)
        external
        onlyOwner
    {
        proxyPolicy[proxyAdmin][proxy].allowedImplCodehash[impl] = expectedCodehash;
        emit ImplAllowed(proxyAdmin, proxy, impl, expectedCodehash);
    }

    function isProxyAllowed(address proxyAdmin, address proxy) external view returns (bool) {
        return proxyPolicy[proxyAdmin][proxy].allowed;
    }

    function getImplCodehash(address proxyAdmin, address proxy, address impl) external view returns (bytes32) {
        return proxyPolicy[proxyAdmin][proxy].allowedImplCodehash[impl];
    }

    /// @inheritdoc IActionAdapter
    function intentHash(address target, uint256 value, bytes calldata data) external pure returns (bytes32) {
        (address proxy, address newImpl, bytes memory callData) = _decode(data);
        return keccak256(
            abi.encode(
                UPGRADE_INTENT_TYPEHASH, target, value, proxy, newImpl, keccak256(callData)
            )
        );
    }

    /// @inheritdoc IActionAdapter
    function validate(address target, uint256, bytes calldata data, bytes32) external view {
        (address proxy, address newImpl, ) = _decode(data);
        ProxyPolicy storage policy = proxyPolicy[target][proxy];
        if (!policy.allowed) revert ProxyNotAllowed();

        bytes32 expected = policy.allowedImplCodehash[newImpl];
        if (expected == bytes32(0)) revert ImplNotAllowed();
        if (newImpl.codehash != expected) revert CodehashMismatch();
    }

    function _decode(bytes calldata data)
        internal
        pure
        returns (address proxy, address newImpl, bytes memory callData)
    {
        if (data.length < 4) revert BadSelector();
        bytes4 selector;
        assembly {
            selector := calldataload(data.offset)
        }
        if (selector == UPGRADE_SELECTOR) {
            if (data.length != 4 + 32 * 2) revert BadSelector();
            (proxy, newImpl) = abi.decode(data[4:], (address, address));
            callData = "";
        } else if (selector == UPGRADE_AND_CALL_SELECTOR) {
            (proxy, newImpl, callData) = abi.decode(data[4:], (address, address, bytes));
        } else {
            revert BadSelector();
        }
    }
}
