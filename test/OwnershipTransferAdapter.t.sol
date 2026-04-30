// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {OwnershipTransferAdapter} from "../contracts/OwnershipTransferAdapter.sol";

contract OwnershipTransferAdapterTest is Test {
    OwnershipTransferAdapter adapter;
    address owner = address(0xA11CE);
    address target = address(0xCAFE);
    address targetNoRenounce = address(0xBEEF);
    address targetRenounceOK = address(0xFEED);
    address targetUnregistered = address(0xDEAD);

    address newOwnerLegit = address(0x1111);
    address newOwnerMalicious = address(0x9999);

    function setUp() public {
        adapter = new OwnershipTransferAdapter(owner);

        vm.startPrank(owner);
        adapter.setTargetPolicy(target, true, false);
        adapter.setAllowedNewOwner(target, newOwnerLegit, true);

        adapter.setTargetPolicy(targetNoRenounce, true, false);
        adapter.setAllowedNewOwner(targetNoRenounce, newOwnerLegit, true);

        adapter.setTargetPolicy(targetRenounceOK, true, true);
        adapter.setAllowedNewOwner(targetRenounceOK, newOwnerLegit, true);
        vm.stopPrank();
    }

    function _transferCalldata(address to) internal pure returns (bytes memory) {
        return abi.encodeWithSignature("transferOwnership(address)", to);
    }

    function _renounceCalldata() internal pure returns (bytes memory) {
        return abi.encodeWithSignature("renounceOwnership()");
    }

    // ============ intentHash ============

    function test_intentHash_isDeterministic() public view {
        bytes memory data = _transferCalldata(newOwnerLegit);
        bytes32 a = adapter.intentHash(target, 0, data);
        bytes32 b = adapter.intentHash(target, 0, data);
        assertEq(a, b);
    }

    function test_intentHash_transferAndRenounceDiffer() public view {
        bytes32 hashTransfer = adapter.intentHash(target, 0, _transferCalldata(newOwnerLegit));
        bytes32 hashRenounce = adapter.intentHash(target, 0, _renounceCalldata());
        assertTrue(hashTransfer != hashRenounce, "transfer and renounce must produce different intents");
    }

    function test_intentHash_bindsNewOwner() public view {
        bytes32 a = adapter.intentHash(target, 0, _transferCalldata(newOwnerLegit));
        bytes32 b = adapter.intentHash(target, 0, _transferCalldata(newOwnerMalicious));
        assertTrue(a != b, "different new owners must produce different intents");
    }

    function test_intentHash_revertsOnUnknownSelector() public {
        bytes memory data = abi.encodeWithSignature("foo()");
        vm.expectRevert(OwnershipTransferAdapter.BadSelector.selector);
        adapter.intentHash(target, 0, data);
    }

    function test_intentHash_revertsOnTransferWithExtraData() public {
        bytes memory data = abi.encodePacked(
            adapter.TRANSFER_OWNERSHIP_SELECTOR(),
            uint256(uint160(newOwnerLegit)),
            uint256(42)
        );
        vm.expectRevert(OwnershipTransferAdapter.BadSelector.selector);
        adapter.intentHash(target, 0, data);
    }

    function test_intentHash_revertsOnRenounceWithArgs() public {
        bytes memory data = abi.encodePacked(adapter.RENOUNCE_OWNERSHIP_SELECTOR(), uint256(0));
        vm.expectRevert(OwnershipTransferAdapter.BadSelector.selector);
        adapter.intentHash(target, 0, data);
    }

    // ============ validate ============

    function test_validate_passesTransferToAllowedNewOwner() public view {
        bytes memory data = _transferCalldata(newOwnerLegit);
        adapter.validate(target, 0, data, bytes32(0));
    }

    function test_validate_revertsTransferToDisallowedNewOwner() public {
        bytes memory data = _transferCalldata(newOwnerMalicious);
        vm.expectRevert(OwnershipTransferAdapter.NewOwnerNotAllowed.selector);
        adapter.validate(target, 0, data, bytes32(0));
    }

    function test_validate_revertsRenounceByDefault() public {
        bytes memory data = _renounceCalldata();
        vm.expectRevert(OwnershipTransferAdapter.ActionNotAllowed.selector);
        adapter.validate(target, 0, data, bytes32(0));
    }

    function test_validate_passesRenounceWhenExplicitlyAllowed() public view {
        bytes memory data = _renounceCalldata();
        adapter.validate(targetRenounceOK, 0, data, bytes32(0));
    }

    function test_validate_revertsForUnregisteredTarget() public {
        bytes memory data = _transferCalldata(newOwnerLegit);
        vm.expectRevert(OwnershipTransferAdapter.ActionNotAllowed.selector);
        adapter.validate(targetUnregistered, 0, data, bytes32(0));
    }

    function test_validate_revertsAfterTransferDisabled() public {
        vm.prank(owner);
        adapter.setTargetPolicy(target, false, false);
        bytes memory data = _transferCalldata(newOwnerLegit);
        vm.expectRevert(OwnershipTransferAdapter.ActionNotAllowed.selector);
        adapter.validate(target, 0, data, bytes32(0));
    }

    // ============ access control ============

    function test_setTargetPolicy_revertsForNonOwner() public {
        vm.expectRevert(OwnershipTransferAdapter.NotOwner.selector);
        adapter.setTargetPolicy(target, false, false);
    }

    function test_setAllowedNewOwner_revertsForNonOwner() public {
        vm.expectRevert(OwnershipTransferAdapter.NotOwner.selector);
        adapter.setAllowedNewOwner(target, newOwnerLegit, true);
    }

    // ============ adversarial: zero-owner & renounce-bypass checks ============

    /// @notice Adversarial review finding: deploying with `owner = address(0)`
    /// would brick the adapter. Must fail closed at construction.
    function test_constructor_revertsOnZeroOwner() public {
        vm.expectRevert(OwnershipTransferAdapter.ZeroOwner.selector);
        new OwnershipTransferAdapter(address(0));
    }

    /// @notice Adversarial review finding: `transferOwnership(address(0))`
    /// is semantically equivalent to `renounceOwnership()` in OZ Ownable.
    /// Before the fix, an adapter owner could (intentionally or by mistake)
    /// allowlist address(0) as a candidate new-owner — bypassing the
    /// explicit `renounceAllowed = false` gate. The adapter now fails closed
    /// on any zero-address transfer regardless of allowlist state.
    function test_validate_revertsTransferToZeroAddress_evenWhenAllowlisted() public {
        // Owner naively allowlists address(0). Renounce remains disabled.
        vm.prank(owner);
        adapter.setAllowedNewOwner(target, address(0), true);

        bytes memory data = _transferCalldata(address(0));
        vm.expectRevert(OwnershipTransferAdapter.TransferToZero.selector);
        adapter.validate(target, 0, data, bytes32(0));
    }

    /// @notice Adversarial regression: even on a target where renounce is
    /// allowed, transferOwnership(0) must still fail closed — the dedicated
    /// renounce selector is the only legitimate path to renounce.
    function test_validate_revertsTransferToZero_evenWhenRenounceAllowed() public {
        bytes memory data = _transferCalldata(address(0));
        vm.expectRevert(OwnershipTransferAdapter.TransferToZero.selector);
        adapter.validate(targetRenounceOK, 0, data, bytes32(0));
    }
}
