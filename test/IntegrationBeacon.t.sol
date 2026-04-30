// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IntegrationBase, AttestPayload} from "./helpers/IntegrationBase.t.sol";
import {IntentGuardModule} from "../contracts/IntentGuardModule.sol";
import {BeaconUpgradeAdapter} from "../contracts/BeaconUpgradeAdapter.sol";

/// @notice Mock UpgradeableBeacon target. Records the implementation
/// supplied by upgradeTo and a call counter. We don't model the real
/// beacon storage layout — we only need the selector to exist and be
/// observable post-execute.
contract MockBeacon {
    address public lastImpl;
    uint256 public callCount;

    function upgradeTo(address newImpl) external {
        lastImpl = newImpl;
        callCount += 1;
    }
}

/// @notice Two distinct implementation contracts so we have something
/// with a real, distinct codehash to allowlist and to swap in for the
/// codehash-mismatch scenario.
contract MockBeaconImplV2 {
    uint256 public constant VERSION = 2;
}

contract MockBeaconImplV3 {
    uint256 public constant VERSION = 3;
    function extra() external pure returns (uint256) { return 99; }
}

/// @notice End-to-end integration: IntentGuardModule + BeaconUpgradeAdapter
/// + MockSafe + MockBeacon. Exercises queue → cool-off → execute, the
/// per-(beacon, impl) codehash allowlist, and the codehash mismatch
/// defense (the canonical CREATE2 + SELFDESTRUCT redeploy attack).
contract IntegrationBeaconTest is IntegrationBase {
    BeaconUpgradeAdapter adapter;
    MockBeacon beacon;
    MockBeaconImplV2 implV2;
    MockBeaconImplV3 implV3;

    address adapterOwner = address(0xDEAF);

    function setUp() public {
        _setUpBase();

        beacon = new MockBeacon();
        implV2 = new MockBeaconImplV2();
        implV3 = new MockBeaconImplV3();
        adapter = new BeaconUpgradeAdapter(adapterOwner);

        vm.startPrank(adapterOwner);
        adapter.setBeaconAllowed(address(beacon), true);
        // Register implV2 with its actual codehash. implV3 is intentionally
        // NOT registered so we can hit ImplNotAllowed.
        adapter.setImplCodehash(address(beacon), address(implV2), address(implV2).codehash);
        vm.stopPrank();

        _registerAdapter(address(beacon), address(adapter));
    }

    // ============ happy path: registered impl with matching codehash ============

    function test_endToEnd_registeredImplLands() public {
        bytes memory data = abi.encodeWithSignature("upgradeTo(address)", address(implV2));
        bytes32 intent = adapter.intentHash(address(beacon), 0, data);
        AttestPayload memory p = _buildPayload(
            address(beacon), 0, address(adapter), intent, data,
            uint64(block.timestamp), uint64(block.timestamp) + 200
        );
        uint64 proposalExpiresAt = uint64(block.timestamp) + MIN_PROPOSAL_LIFETIME + 100;

        bytes32 proposalId = module.queue(
            VAULT_ID, address(beacon), 0, data, intent, address(adapter),
            proposalExpiresAt, _twoSortedAttestations(p)
        );

        vm.warp(block.timestamp + COOLOFF + EXECUTE_DELAY + 1);
        module.execute(proposalId, data);

        assertEq(beacon.lastImpl(), address(implV2));
        assertEq(beacon.callCount(), 1);
    }

    // ============ block: unregistered impl ============

    function test_endToEnd_unregisteredImplBlockedAtExecute() public {
        // implV3 was deliberately not registered with setImplCodehash.
        bytes memory data = abi.encodeWithSignature("upgradeTo(address)", address(implV3));
        bytes32 intent = adapter.intentHash(address(beacon), 0, data);
        AttestPayload memory p = _buildPayload(
            address(beacon), 0, address(adapter), intent, data,
            uint64(block.timestamp), uint64(block.timestamp) + 200
        );
        uint64 proposalExpiresAt = uint64(block.timestamp) + MIN_PROPOSAL_LIFETIME + 100;

        bytes32 proposalId = module.queue(
            VAULT_ID, address(beacon), 0, data, intent, address(adapter),
            proposalExpiresAt, _twoSortedAttestations(p)
        );

        vm.warp(block.timestamp + COOLOFF + EXECUTE_DELAY + 1);

        vm.expectRevert(BeaconUpgradeAdapter.ImplNotAllowed.selector);
        module.execute(proposalId, data);

        assertEq(beacon.callCount(), 0);
        assertEq(beacon.lastImpl(), address(0));
    }

    // ============ block: codehash mismatch ============
    //
    // Models the redeploy attack: implV2 was registered with its codehash
    // at policy-setup time, but between then and execute the on-chain
    // bytecode at that address changed. We simulate the redeploy by
    // overwriting implV2's runtime code with implV3's via vm.etch — same
    // address (still on the allowlist) but a fresh codehash that no
    // longer matches the registered expected value. validate() catches
    // it.

    function test_endToEnd_codehashMismatchBlockedAtExecute() public {
        bytes memory data = abi.encodeWithSignature("upgradeTo(address)", address(implV2));
        bytes32 intent = adapter.intentHash(address(beacon), 0, data);
        AttestPayload memory p = _buildPayload(
            address(beacon), 0, address(adapter), intent, data,
            uint64(block.timestamp), uint64(block.timestamp) + 200
        );
        uint64 proposalExpiresAt = uint64(block.timestamp) + MIN_PROPOSAL_LIFETIME + 100;

        bytes32 proposalId = module.queue(
            VAULT_ID, address(beacon), 0, data, intent, address(adapter),
            proposalExpiresAt, _twoSortedAttestations(p)
        );

        // Simulate a CREATE2 + SELFDESTRUCT redeploy: implV2's bytecode
        // is replaced with implV3's, so implV2's codehash now diverges
        // from what the adapter recorded.
        vm.etch(address(implV2), address(implV3).code);

        vm.warp(block.timestamp + COOLOFF + EXECUTE_DELAY + 1);

        vm.expectRevert(BeaconUpgradeAdapter.CodehashMismatch.selector);
        module.execute(proposalId, data);

        assertEq(beacon.callCount(), 0);
        assertEq(beacon.lastImpl(), address(0));
    }
}
