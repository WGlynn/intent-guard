// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IntegrationBase, AttestPayload} from "./helpers/IntegrationBase.t.sol";
import {IntentGuardModule} from "../contracts/IntentGuardModule.sol";
import {TimelockControllerAdminAdapter} from "../contracts/TimelockControllerAdminAdapter.sol";

/// @notice Mock TimelockController target. Just records the last delay
/// passed to updateDelay; we do not model the rest of the OZ TimelockController.
contract MockTimelock {
    uint256 public lastDelay;
    uint256 public callCount;

    function updateDelay(uint256 newDelay) external {
        lastDelay = newDelay;
        callCount += 1;
    }
}

/// @notice End-to-end integration: IntentGuardModule +
/// TimelockControllerAdminAdapter + MockSafe + MockTimelock. Exercises
/// queue → cool-off → execute with the per-target [minDelay, maxDelay]
/// band. Demonstrates that signers approving an out-of-band delay (e.g.
/// the canonical updateDelay(1) social-engineering attack) is caught at
/// validate() time even when the call would otherwise be technically
/// well-formed.
contract IntegrationTimelockTest is IntegrationBase {
    TimelockControllerAdminAdapter adapter;
    MockTimelock timelock;

    address adapterOwner = address(0xDEAF);

    uint256 constant MIN_DELAY = 24 hours;
    uint256 constant MAX_DELAY = 30 days;

    function setUp() public {
        _setUpBase();

        timelock = new MockTimelock();
        adapter = new TimelockControllerAdminAdapter(adapterOwner);

        vm.prank(adapterOwner);
        adapter.setDelayPolicy(address(timelock), true, MIN_DELAY, MAX_DELAY);

        _registerAdapter(address(timelock), address(adapter));
    }

    function _queueDelay(uint256 newDelay)
        internal
        returns (bytes32 proposalId, bytes memory data)
    {
        data = abi.encodeWithSignature("updateDelay(uint256)", newDelay);
        bytes32 intent = adapter.intentHash(address(timelock), 0, data);
        AttestPayload memory p = _buildPayload(
            address(timelock), 0, address(adapter), intent, data,
            uint64(block.timestamp), uint64(block.timestamp) + 200
        );
        uint64 proposalExpiresAt = uint64(block.timestamp) + MIN_PROPOSAL_LIFETIME + 100;

        proposalId = module.queue(
            VAULT_ID, address(timelock), 0, data, intent, address(adapter),
            proposalExpiresAt, _twoSortedAttestations(p)
        );
    }

    // ============ happy path: in-band delay ============

    function test_endToEnd_inBandDelayLands() public {
        // 7 days is between MIN_DELAY (1 day) and MAX_DELAY (30 days).
        (bytes32 proposalId, bytes memory data) = _queueDelay(7 days);

        vm.warp(block.timestamp + COOLOFF + EXECUTE_DELAY + 1);
        module.execute(proposalId, data);

        assertEq(timelock.lastDelay(), 7 days);
        assertEq(timelock.callCount(), 1);
    }

    // ============ block: below-min delay (the load-bearing attack) ============

    function test_endToEnd_belowMinDelayBlockedAtExecute() public {
        // 1 second — the canonical "lower delay to neuter the timelock"
        // attack. Signers may have been social-engineered into approving
        // it, but the policy floor (MIN_DELAY = 1 day) blocks at validate().
        (bytes32 proposalId, bytes memory data) = _queueDelay(1);

        vm.warp(block.timestamp + COOLOFF + EXECUTE_DELAY + 1);

        vm.expectRevert(TimelockControllerAdminAdapter.BelowMinDelay.selector);
        module.execute(proposalId, data);

        assertEq(timelock.callCount(), 0);
        assertEq(timelock.lastDelay(), 0);
    }

    // ============ block: above-max delay ============

    function test_endToEnd_aboveMaxDelayBlockedAtExecute() public {
        // 60 days > MAX_DELAY (30 days). The ceiling exists to prevent a
        // less-obvious form of timelock sabotage: setting the delay so
        // high that legitimate operations become impractical.
        (bytes32 proposalId, bytes memory data) = _queueDelay(60 days);

        vm.warp(block.timestamp + COOLOFF + EXECUTE_DELAY + 1);

        vm.expectRevert(TimelockControllerAdminAdapter.AboveMaxDelay.selector);
        module.execute(proposalId, data);

        assertEq(timelock.callCount(), 0);
        assertEq(timelock.lastDelay(), 0);
    }
}
