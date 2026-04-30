// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IntegrationBase, AttestPayload} from "./helpers/IntegrationBase.t.sol";
import {IntentGuardModule} from "../contracts/IntentGuardModule.sol";
import {OwnershipTransferAdapter} from "../contracts/OwnershipTransferAdapter.sol";

/// @notice Mock Ownable target. Records the new owner on transferOwnership.
contract MockOwnable {
    address public owner;
    uint256 public callCount;

    function transferOwnership(address newOwner) external {
        owner = newOwner;
        callCount += 1;
    }

    function renounceOwnership() external {
        owner = address(0);
        callCount += 1;
    }
}

/// @notice Demonstrates the IntegrationBase helper used by inheriting from
/// it. Subclass setUp() does only what's adapter-specific; the base owns
/// the module + Safe + signers + signing helpers.
contract IntegrationOwnershipTest is IntegrationBase {
    OwnershipTransferAdapter adapter;
    MockOwnable ownable;

    address adapterOwner = address(0xDEAF);
    address newOwnerLegit = address(0x1111);
    address newOwnerMalicious = address(0x9999);

    function setUp() public {
        _setUpBase();

        ownable = new MockOwnable();
        adapter = new OwnershipTransferAdapter(adapterOwner);

        vm.startPrank(adapterOwner);
        adapter.setTargetPolicy(address(ownable), true, false);
        adapter.setAllowedNewOwner(address(ownable), newOwnerLegit, true);
        vm.stopPrank();

        _registerAdapter(address(ownable), address(adapter));
    }

    // ============ happy path: transfer to allowlisted account ============

    function test_endToEnd_transferToAllowlistedNewOwner() public {
        bytes memory data = abi.encodeWithSignature("transferOwnership(address)", newOwnerLegit);
        bytes32 intent = adapter.intentHash(address(ownable), 0, data);
        AttestPayload memory p = _buildPayload(
            address(ownable), 0, address(adapter), intent, data,
            uint64(block.timestamp), uint64(block.timestamp) + 200
        );
        uint64 proposalExpiresAt = uint64(block.timestamp) + MIN_PROPOSAL_LIFETIME + 100;

        bytes32 proposalId = module.queue(
            VAULT_ID, address(ownable), 0, data, intent, address(adapter),
            proposalExpiresAt, _twoSortedAttestations(p)
        );

        vm.warp(block.timestamp + COOLOFF + EXECUTE_DELAY + 1);
        module.execute(proposalId, data);

        assertEq(ownable.owner(), newOwnerLegit);
        assertEq(ownable.callCount(), 1);
    }

    // ============ block: transfer to attacker ============

    function test_endToEnd_transferToAttackerBlockedAtExecute() public {
        bytes memory data = abi.encodeWithSignature("transferOwnership(address)", newOwnerMalicious);
        bytes32 intent = adapter.intentHash(address(ownable), 0, data);
        AttestPayload memory p = _buildPayload(
            address(ownable), 0, address(adapter), intent, data,
            uint64(block.timestamp), uint64(block.timestamp) + 200
        );
        uint64 proposalExpiresAt = uint64(block.timestamp) + MIN_PROPOSAL_LIFETIME + 100;

        bytes32 proposalId = module.queue(
            VAULT_ID, address(ownable), 0, data, intent, address(adapter),
            proposalExpiresAt, _twoSortedAttestations(p)
        );

        vm.warp(block.timestamp + COOLOFF + EXECUTE_DELAY + 1);

        vm.expectRevert(OwnershipTransferAdapter.NewOwnerNotAllowed.selector);
        module.execute(proposalId, data);

        assertEq(ownable.callCount(), 0);
        assertEq(ownable.owner(), address(0));
    }

    // ============ block: renounce default-disabled ============

    function test_endToEnd_renounceBlockedByDefault() public {
        bytes memory data = abi.encodeWithSignature("renounceOwnership()");
        bytes32 intent = adapter.intentHash(address(ownable), 0, data);
        AttestPayload memory p = _buildPayload(
            address(ownable), 0, address(adapter), intent, data,
            uint64(block.timestamp), uint64(block.timestamp) + 200
        );
        uint64 proposalExpiresAt = uint64(block.timestamp) + MIN_PROPOSAL_LIFETIME + 100;

        bytes32 proposalId = module.queue(
            VAULT_ID, address(ownable), 0, data, intent, address(adapter),
            proposalExpiresAt, _twoSortedAttestations(p)
        );

        vm.warp(block.timestamp + COOLOFF + EXECUTE_DELAY + 1);

        vm.expectRevert(OwnershipTransferAdapter.ActionNotAllowed.selector);
        module.execute(proposalId, data);

        assertEq(ownable.callCount(), 0);
    }
}
