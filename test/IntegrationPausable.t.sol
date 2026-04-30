// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IntegrationBase, AttestPayload} from "./helpers/IntegrationBase.t.sol";
import {IntentGuardModule} from "../contracts/IntentGuardModule.sol";
import {PausableAdapter} from "../contracts/PausableAdapter.sol";

/// @notice Mock Pausable target.
contract MockPausable {
    bool public paused;
    uint256 public pauseCalls;
    uint256 public unpauseCalls;

    function pause() external {
        paused = true;
        pauseCalls += 1;
    }

    function unpause() external {
        paused = false;
        unpauseCalls += 1;
    }
}

contract IntegrationPausableTest is IntegrationBase {
    PausableAdapter adapter;
    MockPausable pausableTarget;

    address adapterOwner = address(0xDEAF);

    function setUp() public {
        _setUpBase();

        pausableTarget = new MockPausable();
        adapter = new PausableAdapter(adapterOwner);

        // pause allowed; unpause NOT allowed (lock-once policy)
        vm.prank(adapterOwner);
        adapter.setTargetPolicy(address(pausableTarget), true, false);

        _registerAdapter(address(pausableTarget), address(adapter));
    }

    function _queue(bytes memory data) internal returns (bytes32 proposalId) {
        bytes32 intent = adapter.intentHash(address(pausableTarget), 0, data);
        AttestPayload memory p = _buildPayload(
            address(pausableTarget), 0, address(adapter), intent, data,
            uint64(block.timestamp), uint64(block.timestamp) + 200
        );
        uint64 proposalExpiresAt = uint64(block.timestamp) + MIN_PROPOSAL_LIFETIME + 100;

        proposalId = module.queue(
            VAULT_ID, address(pausableTarget), 0, data, intent, address(adapter),
            proposalExpiresAt, _twoSortedAttestations(p)
        );
    }

    function test_endToEnd_pauseSucceeds() public {
        bytes memory data = abi.encodeWithSignature("pause()");
        bytes32 proposalId = _queue(data);

        vm.warp(block.timestamp + COOLOFF + EXECUTE_DELAY + 1);
        module.execute(proposalId, data);

        assertTrue(pausableTarget.paused());
        assertEq(pausableTarget.pauseCalls(), 1);
    }

    function test_endToEnd_unpauseBlockedByPolicy() public {
        // Adapter policy disables unpause on this target → "lock once" mode
        // useful when an emergency pause should require a slower governance
        // path to undo (or never be undone).
        bytes memory data = abi.encodeWithSignature("unpause()");
        bytes32 proposalId = _queue(data);

        vm.warp(block.timestamp + COOLOFF + EXECUTE_DELAY + 1);

        vm.expectRevert(PausableAdapter.ActionNotAllowed.selector);
        module.execute(proposalId, data);

        assertEq(pausableTarget.unpauseCalls(), 0);
    }
}
