// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IntegrationBase, AttestPayload} from "./helpers/IntegrationBase.t.sol";
import {IntentGuardModule} from "../contracts/IntentGuardModule.sol";
import {BoundedParameterAdapter} from "../contracts/BoundedParameterAdapter.sol";

/// @notice Mock target supporting the canonical setParam(bytes32, uint256) shape.
contract MockParameterized {
    mapping(bytes32 => uint256) public params;
    uint256 public callCount;

    function setParam(bytes32 key, uint256 value) external {
        params[key] = value;
        callCount += 1;
    }
}

/// @notice Integration: signers approve a parameter change that respects
/// the bounds → it lands. A change that exceeds the change-ratio cap
/// (despite being within absolute bounds) fails at validate() time.
contract IntegrationBoundedParameterTest is IntegrationBase {
    BoundedParameterAdapter adapter;
    MockParameterized parameterized;

    address adapterOwner = address(0xDEAF);

    bytes32 constant KEY_VOLUME_CAP = keccak256("volume_cap");
    uint256 constant BASELINE = 1_000_000e18;
    uint256 constant ABS_MAX = 10_000_000e18;
    uint256 constant CHANGE_RATIO_BPS = 5000; // 50% max change per proposal

    function setUp() public {
        _setUpBase();

        parameterized = new MockParameterized();
        adapter = new BoundedParameterAdapter(adapterOwner);

        vm.prank(adapterOwner);
        adapter.setParamPolicy(
            address(parameterized),
            KEY_VOLUME_CAP,
            true,                  // allowed
            100_000e18,            // min
            ABS_MAX,               // max
            CHANGE_RATIO_BPS,      // 50% max change
            BASELINE
        );

        _registerAdapter(address(parameterized), address(adapter));
    }

    function _paramData(bytes32 key, uint256 value) internal pure returns (bytes memory) {
        return abi.encodeWithSignature("setParam(bytes32,uint256)", key, value);
    }

    function _queueParamProposal(uint256 newValue)
        internal
        returns (bytes32 proposalId, bytes memory data)
    {
        data = _paramData(KEY_VOLUME_CAP, newValue);
        bytes32 intent = adapter.intentHash(address(parameterized), 0, data);
        AttestPayload memory p = _buildPayload(
            address(parameterized), 0, address(adapter), intent, data,
            uint64(block.timestamp), uint64(block.timestamp) + 200
        );
        uint64 proposalExpiresAt = uint64(block.timestamp) + MIN_PROPOSAL_LIFETIME + 100;

        proposalId = module.queue(
            VAULT_ID, address(parameterized), 0, data, intent, address(adapter),
            proposalExpiresAt, _twoSortedAttestations(p)
        );
    }

    // ============ happy path: change within bounds + ratio ============

    function test_endToEnd_changeWithinRatio() public {
        // Baseline 1M, target 1.4M = 40% change, within 50% cap
        (bytes32 proposalId, bytes memory data) = _queueParamProposal(1_400_000e18);

        vm.warp(block.timestamp + COOLOFF + EXECUTE_DELAY + 1);
        module.execute(proposalId, data);

        assertEq(parameterized.params(KEY_VOLUME_CAP), 1_400_000e18);
        assertEq(parameterized.callCount(), 1);
    }

    // ============ block: change exceeds ratio cap ============

    function test_endToEnd_changeExceedingRatioBlockedAtExecute() public {
        // Baseline 1M, target 1.6M = 60% change, exceeds 50% cap.
        // Within absolute bounds (1.6M < 10M ABS_MAX), so signers could
        // approve, but adapter.validate() catches the ratio violation.
        (bytes32 proposalId, bytes memory data) = _queueParamProposal(1_600_000e18);

        vm.warp(block.timestamp + COOLOFF + EXECUTE_DELAY + 1);

        vm.expectRevert(BoundedParameterAdapter.ExceedsChangeRatio.selector);
        module.execute(proposalId, data);

        assertEq(parameterized.callCount(), 0);
        assertEq(parameterized.params(KEY_VOLUME_CAP), 0);
    }

    // ============ block: above absolute max ============

    function test_endToEnd_aboveAbsoluteMaxBlockedAtExecute() public {
        (bytes32 proposalId, bytes memory data) = _queueParamProposal(50_000_000e18);

        vm.warp(block.timestamp + COOLOFF + EXECUTE_DELAY + 1);

        vm.expectRevert(BoundedParameterAdapter.AboveMax.selector);
        module.execute(proposalId, data);

        assertEq(parameterized.callCount(), 0);
    }
}
