// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IActionAdapter} from "./IntentGuardModule.sol";

/// @notice Adapter for OpenZeppelin UUPS upgradeable proxies.
///
/// Decodes the two UUPS upgrade selectors (`upgradeTo(address)` and
/// `upgradeToAndCall(address,bytes)`) and binds the load-bearing fields
/// — target proxy, new implementation, and the hash of any post-upgrade
/// initializer calldata — into a typed intent hash signers approve.
///
/// `validate()` enforces three invariants at execute time:
///
///   1. The proxy is on the adapter's proxy allowlist.
///   2. The new implementation is on the per-proxy implementation allowlist.
///   3. The new implementation's runtime EXTCODEHASH matches the codehash
///      that was registered for it when the policy was set.
///
/// Invariant (3) is the load-bearing check. A malicious actor who pre-signed
/// an upgrade approval for an implementation address cannot redeploy that
/// address with different code between sign-time and execute-time, because
/// the on-chain EXTCODEHASH is checked at execute against the registered
/// hash. This closes the CREATE2-redeployment + SELFDESTRUCT class of
/// upgrade-front-running attacks.
contract UUPSUpgradeAdapter is IActionAdapter {
    bytes4 public constant UPGRADE_TO_SELECTOR = bytes4(keccak256("upgradeTo(address)"));
    bytes4 public constant UPGRADE_TO_AND_CALL_SELECTOR = bytes4(keccak256("upgradeToAndCall(address,bytes)"));

    bytes32 public constant UPGRADE_INTENT_TYPEHASH = keccak256(
        "UUPSUpgrade(address target,uint256 value,address newImplementation,bytes32 callDataHash)"
    );

    struct ProxyPolicy {
        bool allowed;
        // Per-proxy mapping of (newImpl => expectedCodehash). A zero codehash
        // means the implementation is NOT allowed (cannot pass validate()).
        mapping(address => bytes32) allowedImplCodehash;
    }

    address public immutable owner;
    mapping(address => ProxyPolicy) internal proxyPolicy;

    event ProxyAllowed(address indexed proxy, bool allowed);
    event ImplAllowed(address indexed proxy, address indexed impl, bytes32 expectedCodehash);

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

    /// @notice Toggle proxy allowlist entry. Owner only.
    function setProxyAllowed(address proxy, bool allowed) external onlyOwner {
        proxyPolicy[proxy].allowed = allowed;
        emit ProxyAllowed(proxy, allowed);
    }

    /// @notice Register an expected codehash for `(proxy, impl)`. Set
    /// `expectedCodehash` to zero to remove the implementation from the
    /// allowlist. The codehash MUST be the EXTCODEHASH of the deployed
    /// implementation contract.
    ///
    /// Recommended workflow: deploy the new implementation, read its
    /// EXTCODEHASH off-chain, register it here BEFORE the upgrade
    /// proposal is queued. If the implementation is later redeployed at
    /// the same address (e.g. via CREATE2 + SELFDESTRUCT), the new
    /// codehash will not match and `validate()` reverts.
    function setImplCodehash(address proxy, address impl, bytes32 expectedCodehash) external onlyOwner {
        proxyPolicy[proxy].allowedImplCodehash[impl] = expectedCodehash;
        emit ImplAllowed(proxy, impl, expectedCodehash);
    }

    function isProxyAllowed(address proxy) external view returns (bool) {
        return proxyPolicy[proxy].allowed;
    }

    function getImplCodehash(address proxy, address impl) external view returns (bytes32) {
        return proxyPolicy[proxy].allowedImplCodehash[impl];
    }

    /// @inheritdoc IActionAdapter
    function intentHash(address target, uint256 value, bytes calldata data) external pure returns (bytes32) {
        (address newImpl, bytes memory callData) = _decode(data);
        bytes32 callDataHash = keccak256(callData);
        return keccak256(
            abi.encode(UPGRADE_INTENT_TYPEHASH, target, value, newImpl, callDataHash)
        );
    }

    /// @inheritdoc IActionAdapter
    function validate(address target, uint256, bytes calldata data, bytes32) external view {
        ProxyPolicy storage policy = proxyPolicy[target];
        if (!policy.allowed) revert ProxyNotAllowed();

        (address newImpl, ) = _decode(data);
        bytes32 expected = policy.allowedImplCodehash[newImpl];
        if (expected == bytes32(0)) revert ImplNotAllowed();

        bytes32 actual = newImpl.codehash;
        if (actual != expected) revert CodehashMismatch();
    }

    function _decode(bytes calldata data) internal pure returns (address newImpl, bytes memory callData) {
        if (data.length < 4) revert BadSelector();
        bytes4 selector;
        assembly {
            selector := calldataload(data.offset)
        }

        if (selector == UPGRADE_TO_SELECTOR) {
            if (data.length != 4 + 32) revert BadSelector();
            newImpl = abi.decode(data[4:], (address));
            callData = "";
        } else if (selector == UPGRADE_TO_AND_CALL_SELECTOR) {
            (newImpl, callData) = abi.decode(data[4:], (address, bytes));
        } else {
            revert BadSelector();
        }
    }
}
