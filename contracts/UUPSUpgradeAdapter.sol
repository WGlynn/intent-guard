// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IActionAdapter} from "./IntentGuardModule.sol";

/// @notice Adapter for OpenZeppelin UUPS upgradeable proxies.
///
/// Decodes the two UUPS upgrade selectors (`upgradeTo(address)` and
/// `upgradeToAndCall(address,bytes)`) and binds the load-bearing fields
/// — target proxy, new implementation, the hash of any post-upgrade
/// initializer calldata, AND the expected runtime EXTCODEHASH of the
/// new implementation — into a typed intent hash signers approve.
///
/// Binding the codehash INTO the signed intent (not just checking it
/// at execute time against mutable adapter policy) is what closes the
/// CREATE2-redeployment + SELFDESTRUCT class of upgrade attacks. If
/// only validate() checked the codehash against a mutable policy, an
/// attacker who redeployed the implementation address with different
/// code AND a colluding/compromised adapter owner who updated the
/// policy could re-authorize an upgrade against signatures whose
/// signed bytes never bound the new bytecode. With the codehash
/// inside intentHash(), the signature itself authorizes the EXACT
/// bytecode — any divergence reproduces a different intent hash and
/// the signatures don't verify.
///
/// `validate()` enforces three invariants at execute time as
/// defense-in-depth:
///
///   1. The proxy is on the adapter's proxy allowlist.
///   2. The new implementation is on the per-proxy implementation allowlist.
///   3. The new implementation's runtime EXTCODEHASH matches the codehash
///      that was registered for it when the policy was set.
///
/// `intentHash()` ALSO fails closed for unallowed proxies / unregistered
/// implementations, so signers cannot accidentally produce a valid hash
/// for a target the adapter would later reject.
contract UUPSUpgradeAdapter is IActionAdapter {
    bytes4 public constant UPGRADE_TO_SELECTOR = bytes4(keccak256("upgradeTo(address)"));
    bytes4 public constant UPGRADE_TO_AND_CALL_SELECTOR = bytes4(keccak256("upgradeToAndCall(address,bytes)"));

    bytes32 public constant UPGRADE_INTENT_TYPEHASH = keccak256(
        "UUPSUpgrade(address target,uint256 value,address newImplementation,bytes32 callDataHash,bytes32 expectedCodehash)"
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
    error ZeroOwner();
    error EmptyCodeImpl();

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    constructor(address owner_) {
        if (owner_ == address(0)) revert ZeroOwner();
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
    /// proposal is signed. Because intentHash() reads this codehash and
    /// binds it into the signed bytes, signers approve the EXACT
    /// bytecode, not just the address.
    ///
    /// Reverts with `EmptyCodeImpl` if the implementation address has
    /// no deployed code (would brick the proxy on upgrade). The zero
    /// codehash is still accepted as the explicit "remove from allowlist"
    /// operation regardless of the impl's current code state.
    function setImplCodehash(address proxy, address impl, bytes32 expectedCodehash) external onlyOwner {
        if (expectedCodehash != bytes32(0) && impl.code.length == 0) revert EmptyCodeImpl();
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
    /// @dev `view` (not `pure`) because it reads the registered codehash
    /// from policy and binds it INTO the returned hash. This is what
    /// makes the signed intent authorize a specific bytecode, not just
    /// an address. Fails closed for unallowed proxies and unregistered
    /// impls so signers cannot produce a hash for a target validate()
    /// would later reject.
    function intentHash(address target, uint256 value, bytes calldata data) external view returns (bytes32) {
        ProxyPolicy storage policy = proxyPolicy[target];
        if (!policy.allowed) revert ProxyNotAllowed();

        (address newImpl, bytes memory callData) = _decode(data);
        bytes32 expectedCodehash = policy.allowedImplCodehash[newImpl];
        if (expectedCodehash == bytes32(0)) revert ImplNotAllowed();

        bytes32 callDataHash = keccak256(callData);
        return keccak256(
            abi.encode(
                UPGRADE_INTENT_TYPEHASH,
                target,
                value,
                newImpl,
                callDataHash,
                expectedCodehash
            )
        );
    }

    /// @inheritdoc IActionAdapter
    function validate(address target, uint256, bytes calldata data, bytes32) external view {
        ProxyPolicy storage policy = proxyPolicy[target];
        if (!policy.allowed) revert ProxyNotAllowed();

        (address newImpl, ) = _decode(data);
        bytes32 expected = policy.allowedImplCodehash[newImpl];
        if (expected == bytes32(0)) revert ImplNotAllowed();

        // Belt-and-suspenders: even though the signed intent now binds
        // expectedCodehash, recompute and compare against the currently-
        // deployed runtime codehash. This guards against the policy
        // being mutated between intent-hash time and execute time AND
        // against the implementation address being redeployed with
        // different code.
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
            // Minimum ABI-encoding of (address, bytes) is:
            //   32 bytes (address slot)
            // + 32 bytes (offset to bytes)
            // + 32 bytes (bytes length)
            // = 96 bytes minimum after the selector. Reject anything
            // shorter with BadSelector so callers get a clean failure
            // mode instead of a downstream abi.decode revert.
            if (data.length < 4 + 96) revert BadSelector();
            (newImpl, callData) = abi.decode(data[4:], (address, bytes));
        } else {
            revert BadSelector();
        }
    }
}
