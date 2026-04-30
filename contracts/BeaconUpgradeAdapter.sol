// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IActionAdapter} from "./IntentGuardModule.sol";

/// @notice Adapter for the OpenZeppelin `UpgradeableBeacon` pattern, where a
/// single Beacon contract holds the implementation address that N
/// BeaconProxies dereference at call time. The Beacon's privileged call:
///
///     upgradeTo(address newImplementation)
///
/// One Beacon serves N BeaconProxies. Upgrading the Beacon updates every
/// proxy that points at it simultaneously — strictly higher leverage than a
/// UUPS upgrade, which only affects one proxy. A compromised beacon
/// upgrade is therefore a fan-out catastrophe; this adapter is the same
/// defense as `UUPSUpgradeAdapter` reshaped for that fan-out.
///
/// Threat class: identical to UUPS. Pre-signed approval for an
/// implementation address gets exploited via CREATE2 + SELFDESTRUCT
/// redeployment between sign-time and execute-time. The defense is the
/// same: bind (target=beacon, newImpl) into the typed intent and check
/// the new implementation's runtime EXTCODEHASH at validate() time
/// against the codehash that was registered when the policy was set.
///
/// The "target" passed to the adapter is the **Beacon** address itself
/// (NOT a proxy). One adapter instance can gate many beacons.
contract BeaconUpgradeAdapter is IActionAdapter {
    bytes4 public constant UPGRADE_TO_SELECTOR = bytes4(keccak256("upgradeTo(address)"));

    bytes32 public constant BEACON_UPGRADE_INTENT_TYPEHASH = keccak256(
        "BeaconUpgrade(address target,uint256 value,address newImplementation)"
    );

    struct BeaconPolicy {
        bool allowed;
        // Per-beacon mapping of (newImpl => expectedCodehash). A zero
        // codehash means the implementation is NOT allowed (cannot pass
        // validate()).
        mapping(address => bytes32) allowedImplCodehash;
    }

    address public immutable owner;
    mapping(address => BeaconPolicy) internal beaconPolicy;

    event BeaconAllowed(address indexed beacon, bool allowed);
    event ImplAllowed(address indexed beacon, address indexed impl, bytes32 expectedCodehash);

    error NotOwner();
    error BadSelector();
    error BeaconNotAllowed();
    error ImplNotAllowed();
    error CodehashMismatch();

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    constructor(address owner_) {
        owner = owner_;
    }

    /// @notice Toggle beacon allowlist entry. Owner only.
    function setBeaconAllowed(address beacon, bool allowed) external onlyOwner {
        beaconPolicy[beacon].allowed = allowed;
        emit BeaconAllowed(beacon, allowed);
    }

    /// @notice Register an expected codehash for `(beacon, impl)`. Set
    /// `expectedCodehash` to zero to remove the implementation from the
    /// allowlist. The codehash MUST be the EXTCODEHASH of the deployed
    /// implementation contract.
    ///
    /// Recommended workflow: deploy the new implementation, read its
    /// EXTCODEHASH off-chain, register it here BEFORE the upgrade
    /// proposal is queued. If the implementation is later redeployed at
    /// the same address (e.g. via CREATE2 + SELFDESTRUCT), the new
    /// codehash will not match and `validate()` reverts.
    function setImplCodehash(address beacon, address impl, bytes32 expectedCodehash) external onlyOwner {
        beaconPolicy[beacon].allowedImplCodehash[impl] = expectedCodehash;
        emit ImplAllowed(beacon, impl, expectedCodehash);
    }

    function isBeaconAllowed(address beacon) external view returns (bool) {
        return beaconPolicy[beacon].allowed;
    }

    function getImplCodehash(address beacon, address impl) external view returns (bytes32) {
        return beaconPolicy[beacon].allowedImplCodehash[impl];
    }

    /// @inheritdoc IActionAdapter
    function intentHash(address target, uint256 value, bytes calldata data) external pure returns (bytes32) {
        address newImpl = _decode(data);
        return keccak256(
            abi.encode(BEACON_UPGRADE_INTENT_TYPEHASH, target, value, newImpl)
        );
    }

    /// @inheritdoc IActionAdapter
    function validate(address target, uint256, bytes calldata data, bytes32) external view {
        BeaconPolicy storage policy = beaconPolicy[target];
        if (!policy.allowed) revert BeaconNotAllowed();

        address newImpl = _decode(data);
        bytes32 expected = policy.allowedImplCodehash[newImpl];
        if (expected == bytes32(0)) revert ImplNotAllowed();

        bytes32 actual = newImpl.codehash;
        if (actual != expected) revert CodehashMismatch();
    }

    function _decode(bytes calldata data) internal pure returns (address newImpl) {
        if (data.length < 4) revert BadSelector();
        bytes4 selector;
        assembly {
            selector := calldataload(data.offset)
        }
        if (selector != UPGRADE_TO_SELECTOR) revert BadSelector();
        if (data.length != 4 + 32) revert BadSelector();
        newImpl = abi.decode(data[4:], (address));
    }
}
