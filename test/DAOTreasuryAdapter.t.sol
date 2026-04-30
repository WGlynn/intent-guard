// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {DAOTreasuryAdapter} from "../contracts/DAOTreasuryAdapter.sol";

contract DAOTreasuryAdapterTest is Test {
    DAOTreasuryAdapter adapter;
    address owner = address(0xA11CE);
    address treasury = address(0xCAFE);
    address recipient = address(0xBEEF);
    address recipientAlt = address(0xFEED);

    address asset = address(0xDEAD); // mock ERC20 address
    address ethAsset = address(0); // native token sentinel
    address blockedAsset = address(0xDEAF);

    uint256 constant CAP = 1_000_000e18;
    uint256 constant AMOUNT_BELOW_CAP = 500_000e18;
    uint256 constant AMOUNT_AT_CAP = 1_000_000e18;
    uint256 constant AMOUNT_ABOVE_CAP = 2_000_000e18;

    function setUp() public {
        adapter = new DAOTreasuryAdapter(owner);

        vm.startPrank(owner);
        adapter.setAssetPolicy(asset, true, CAP);
        adapter.setAssetPolicy(ethAsset, true, 100 ether);
        // blockedAsset deliberately not set (allowed=false by default)
        vm.stopPrank();
    }

    function _withdrawCalldata(address r, address a, uint256 amt) internal pure returns (bytes memory) {
        return abi.encodeWithSignature("withdraw(address,address,uint256)", r, a, amt);
    }

    // ============ intentHash ============

    function test_intentHash_isDeterministic() public view {
        bytes memory data = _withdrawCalldata(recipient, asset, AMOUNT_BELOW_CAP);
        bytes32 a = adapter.intentHash(treasury, 0, data);
        bytes32 b = adapter.intentHash(treasury, 0, data);
        assertEq(a, b);
        assertTrue(a != bytes32(0));
    }

    function test_intentHash_bindsRecipient() public view {
        bytes32 a = adapter.intentHash(treasury, 0, _withdrawCalldata(recipient, asset, AMOUNT_BELOW_CAP));
        bytes32 b = adapter.intentHash(treasury, 0, _withdrawCalldata(recipientAlt, asset, AMOUNT_BELOW_CAP));
        assertTrue(a != b, "different recipients must produce different intents");
    }

    function test_intentHash_bindsAsset() public view {
        bytes32 a = adapter.intentHash(treasury, 0, _withdrawCalldata(recipient, asset, AMOUNT_BELOW_CAP));
        bytes32 b = adapter.intentHash(treasury, 0, _withdrawCalldata(recipient, ethAsset, AMOUNT_BELOW_CAP));
        assertTrue(a != b, "different assets must produce different intents");
    }

    function test_intentHash_bindsAmount() public view {
        bytes32 a = adapter.intentHash(treasury, 0, _withdrawCalldata(recipient, asset, AMOUNT_BELOW_CAP));
        bytes32 b = adapter.intentHash(treasury, 0, _withdrawCalldata(recipient, asset, AMOUNT_AT_CAP));
        assertTrue(a != b, "different amounts must produce different intents");
    }

    function test_intentHash_bindsTarget() public view {
        bytes memory data = _withdrawCalldata(recipient, asset, AMOUNT_BELOW_CAP);
        bytes32 a = adapter.intentHash(treasury, 0, data);
        bytes32 b = adapter.intentHash(address(0xABCD), 0, data);
        assertTrue(a != b, "different targets must produce different intents");
    }

    function test_intentHash_revertsOnUnknownSelector() public {
        bytes memory data = abi.encodeWithSignature("foo()");
        vm.expectRevert(DAOTreasuryAdapter.BadSelector.selector);
        adapter.intentHash(treasury, 0, data);
    }

    function test_intentHash_revertsOnMalformedCalldata() public {
        // Correct selector but wrong arg layout (only one address packed)
        bytes memory data = abi.encodePacked(adapter.WITHDRAW_SELECTOR(), uint256(uint160(recipient)));
        vm.expectRevert(DAOTreasuryAdapter.BadSelector.selector);
        adapter.intentHash(treasury, 0, data);
    }

    // ============ validate ============

    function test_validate_passesWithinCap() public view {
        bytes memory data = _withdrawCalldata(recipient, asset, AMOUNT_BELOW_CAP);
        adapter.validate(treasury, 0, data, bytes32(0));
    }

    function test_validate_passesAtCap() public view {
        bytes memory data = _withdrawCalldata(recipient, asset, AMOUNT_AT_CAP);
        adapter.validate(treasury, 0, data, bytes32(0));
    }

    function test_validate_revertsAboveCap() public {
        bytes memory data = _withdrawCalldata(recipient, asset, AMOUNT_ABOVE_CAP);
        vm.expectRevert(DAOTreasuryAdapter.AmountExceedsCap.selector);
        adapter.validate(treasury, 0, data, bytes32(0));
    }

    function test_validate_revertsOnDisallowedAsset() public {
        bytes memory data = _withdrawCalldata(recipient, blockedAsset, AMOUNT_BELOW_CAP);
        vm.expectRevert(DAOTreasuryAdapter.AssetNotAllowed.selector);
        adapter.validate(treasury, 0, data, bytes32(0));
    }

    function test_validate_passesWithoutCapWhenZero() public {
        // Owner sets a policy with maxAmount = 0 (no cap)
        vm.prank(owner);
        adapter.setAssetPolicy(asset, true, 0);

        bytes memory data = _withdrawCalldata(recipient, asset, AMOUNT_ABOVE_CAP);
        adapter.validate(treasury, 0, data, bytes32(0));
    }

    function test_validate_skipsRecipientAllowlistByDefault() public view {
        // requireRecipientAllowlist is false by default
        bytes memory data = _withdrawCalldata(address(0x1234), asset, AMOUNT_BELOW_CAP);
        adapter.validate(treasury, 0, data, bytes32(0));
    }

    function test_validate_revertsOnRecipientNotAllowed_whenAllowlistRequired() public {
        vm.prank(owner);
        adapter.setRequireRecipientAllowlist(true);

        bytes memory data = _withdrawCalldata(recipient, asset, AMOUNT_BELOW_CAP);
        vm.expectRevert(DAOTreasuryAdapter.RecipientNotAllowed.selector);
        adapter.validate(treasury, 0, data, bytes32(0));
    }

    function test_validate_passesWhenRecipientAllowed_whenAllowlistRequired() public {
        vm.startPrank(owner);
        adapter.setRequireRecipientAllowlist(true);
        adapter.setRecipientAllowed(recipient, true);
        vm.stopPrank();

        bytes memory data = _withdrawCalldata(recipient, asset, AMOUNT_BELOW_CAP);
        adapter.validate(treasury, 0, data, bytes32(0));
    }

    // ============ access control ============

    function test_setAssetPolicy_revertsForNonOwner() public {
        vm.expectRevert(DAOTreasuryAdapter.NotOwner.selector);
        adapter.setAssetPolicy(asset, false, 0);
    }

    function test_setRecipientAllowed_revertsForNonOwner() public {
        vm.expectRevert(DAOTreasuryAdapter.NotOwner.selector);
        adapter.setRecipientAllowed(recipient, true);
    }

    function test_setRequireRecipientAllowlist_revertsForNonOwner() public {
        vm.expectRevert(DAOTreasuryAdapter.NotOwner.selector);
        adapter.setRequireRecipientAllowlist(true);
    }

    // ============ adversarial: zero-address & boundary checks ============

    /// @notice Adversarial review finding: deploying with `owner = address(0)`
    /// would brick the adapter (no asset policies, recipient allowlist, or
    /// allowlist-enable toggles can ever be set). Must fail closed at
    /// construction.
    function test_constructor_revertsOnZeroOwner() public {
        vm.expectRevert(DAOTreasuryAdapter.ZeroOwner.selector);
        new DAOTreasuryAdapter(address(0));
    }

    /// @notice Adversarial review finding: with `requireRecipientAllowlist`
    /// off (the default), `recipient = address(0)` would pass validate,
    /// allowing a signed intent to burn treasury funds. Many real treasury
    /// implementations either revert internally or silently send to the zero
    /// address — neither outcome is a legitimate "withdraw". Adapter should
    /// fail closed on a zero recipient regardless of allowlist policy.
    function test_validate_revertsOnZeroRecipient() public {
        bytes memory data = _withdrawCalldata(address(0), asset, AMOUNT_BELOW_CAP);
        vm.expectRevert(DAOTreasuryAdapter.ZeroRecipient.selector);
        adapter.validate(treasury, 0, data, bytes32(0));
    }

    /// @notice Adversarial review finding (defense in depth): even when the
    /// recipient allowlist is enabled and address(0) was somehow added to
    /// it, the zero-recipient check should still fire first.
    function test_validate_revertsOnZeroRecipient_evenWhenAllowlisted() public {
        vm.startPrank(owner);
        adapter.setRequireRecipientAllowlist(true);
        adapter.setRecipientAllowed(address(0), true);
        vm.stopPrank();

        bytes memory data = _withdrawCalldata(address(0), asset, AMOUNT_BELOW_CAP);
        vm.expectRevert(DAOTreasuryAdapter.ZeroRecipient.selector);
        adapter.validate(treasury, 0, data, bytes32(0));
    }
}
