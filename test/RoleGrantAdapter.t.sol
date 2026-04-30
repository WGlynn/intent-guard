// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {RoleGrantAdapter} from "../contracts/RoleGrantAdapter.sol";

contract RoleGrantAdapterTest is Test {
    RoleGrantAdapter adapter;
    address owner = address(0xA11CE);
    address target = address(0xCAFE);
    address targetAlt = address(0xFADE);
    address account = address(0xBEEF);
    address accountAlt = address(0xFEED);

    bytes32 constant ROLE_OPERATOR = keccak256("OPERATOR_ROLE");
    bytes32 constant ROLE_ADMIN = keccak256("ADMIN_ROLE");
    bytes32 constant ROLE_FROZEN = keccak256("FROZEN_ROLE");
    bytes32 constant ROLE_UNREGISTERED = keccak256("UNKNOWN_ROLE");

    function setUp() public {
        adapter = new RoleGrantAdapter(owner);

        vm.startPrank(owner);

        // OPERATOR: open (no allowlist) — any account in the signed intent passes
        adapter.setRolePolicy(target, ROLE_OPERATOR, true, false, false);

        // ADMIN: allowlist required, only `account` is allowed
        adapter.setRolePolicy(target, ROLE_ADMIN, true, false, true);
        adapter.setAllowedAccount(target, ROLE_ADMIN, account, true);

        // FROZEN: allowed but frozen — neither grant nor revoke can pass
        adapter.setRolePolicy(target, ROLE_FROZEN, true, true, false);

        vm.stopPrank();
    }

    function _grantCalldata(bytes32 role, address acc) internal pure returns (bytes memory) {
        return abi.encodeWithSignature("grantRole(bytes32,address)", role, acc);
    }

    function _revokeCalldata(bytes32 role, address acc) internal pure returns (bytes memory) {
        return abi.encodeWithSignature("revokeRole(bytes32,address)", role, acc);
    }

    // ============ intentHash ============

    function test_intentHash_isDeterministic() public view {
        bytes memory data = _grantCalldata(ROLE_OPERATOR, account);
        bytes32 a = adapter.intentHash(target, 0, data);
        bytes32 b = adapter.intentHash(target, 0, data);
        assertEq(a, b);
    }

    function test_intentHash_grantAndRevokeDiffer() public view {
        bytes32 hashGrant = adapter.intentHash(target, 0, _grantCalldata(ROLE_OPERATOR, account));
        bytes32 hashRevoke = adapter.intentHash(target, 0, _revokeCalldata(ROLE_OPERATOR, account));
        assertTrue(hashGrant != hashRevoke, "grant and revoke must produce different intents");
    }

    function test_intentHash_bindsRoleAndAccount() public view {
        bytes32 a = adapter.intentHash(target, 0, _grantCalldata(ROLE_OPERATOR, account));
        bytes32 b = adapter.intentHash(target, 0, _grantCalldata(ROLE_ADMIN, account));
        bytes32 c = adapter.intentHash(target, 0, _grantCalldata(ROLE_OPERATOR, accountAlt));
        assertTrue(a != b, "different roles must produce different intents");
        assertTrue(a != c, "different accounts must produce different intents");
    }

    function test_intentHash_revertsOnUnknownSelector() public {
        bytes memory data = abi.encodeWithSignature("foo()");
        vm.expectRevert(RoleGrantAdapter.BadSelector.selector);
        adapter.intentHash(target, 0, data);
    }

    // ============ validate — open role (no allowlist) ============

    function test_validate_passesGrantOnOpenRole() public view {
        bytes memory data = _grantCalldata(ROLE_OPERATOR, account);
        adapter.validate(target, 0, data, bytes32(0));
    }

    function test_validate_passesRevokeOnOpenRole() public view {
        bytes memory data = _revokeCalldata(ROLE_OPERATOR, account);
        adapter.validate(target, 0, data, bytes32(0));
    }

    function test_validate_passesGrantOnOpenRoleForAnyAccount() public view {
        bytes memory data = _grantCalldata(ROLE_OPERATOR, accountAlt);
        adapter.validate(target, 0, data, bytes32(0));
    }

    // ============ validate — allowlisted role ============

    function test_validate_passesGrantOnAllowedAccount() public view {
        bytes memory data = _grantCalldata(ROLE_ADMIN, account);
        adapter.validate(target, 0, data, bytes32(0));
    }

    function test_validate_revertsGrantOnDisallowedAccount() public {
        bytes memory data = _grantCalldata(ROLE_ADMIN, accountAlt);
        vm.expectRevert(RoleGrantAdapter.AccountNotAllowed.selector);
        adapter.validate(target, 0, data, bytes32(0));
    }

    function test_validate_passesRevokeIgnoresAllowlist() public view {
        // Revoke doesn't add membership; allowlist not enforced
        bytes memory data = _revokeCalldata(ROLE_ADMIN, accountAlt);
        adapter.validate(target, 0, data, bytes32(0));
    }

    // ============ validate — frozen role ============

    function test_validate_revertsGrantOnFrozenRole() public {
        bytes memory data = _grantCalldata(ROLE_FROZEN, account);
        vm.expectRevert(RoleGrantAdapter.RoleFrozen.selector);
        adapter.validate(target, 0, data, bytes32(0));
    }

    function test_validate_revertsRevokeOnFrozenRole() public {
        bytes memory data = _revokeCalldata(ROLE_FROZEN, account);
        vm.expectRevert(RoleGrantAdapter.RoleFrozen.selector);
        adapter.validate(target, 0, data, bytes32(0));
    }

    // ============ validate — unregistered role / target ============

    function test_validate_revertsOnUnregisteredRole() public {
        bytes memory data = _grantCalldata(ROLE_UNREGISTERED, account);
        vm.expectRevert(RoleGrantAdapter.RoleNotAllowed.selector);
        adapter.validate(target, 0, data, bytes32(0));
    }

    function test_validate_revertsForUnregisteredTarget() public {
        bytes memory data = _grantCalldata(ROLE_OPERATOR, account);
        vm.expectRevert(RoleGrantAdapter.RoleNotAllowed.selector);
        adapter.validate(targetAlt, 0, data, bytes32(0));
    }

    // ============ access control ============

    function test_setRolePolicy_revertsForNonOwner() public {
        vm.expectRevert(RoleGrantAdapter.NotOwner.selector);
        adapter.setRolePolicy(target, ROLE_OPERATOR, true, false, false);
    }

    function test_setAllowedAccount_revertsForNonOwner() public {
        vm.expectRevert(RoleGrantAdapter.NotOwner.selector);
        adapter.setAllowedAccount(target, ROLE_ADMIN, account, true);
    }

    // ============ adversarial: zero-address & malformed-calldata checks ============

    /// @notice Adversarial review finding: deploying with `owner = address(0)`
    /// would brick the adapter (no role policies or account allowlists could
    /// ever be set). Must fail closed at construction.
    function test_constructor_revertsOnZeroOwner() public {
        vm.expectRevert(RoleGrantAdapter.ZeroOwner.selector);
        new RoleGrantAdapter(address(0));
    }

    /// @notice Adversarial regression: malformed grant/revoke calldata where
    /// the selector is correct but the args are truncated must revert with
    /// BadSelector (locked behavior — exact-length check in _decode).
    function test_intentHash_revertsOnTruncatedGrant() public {
        bytes memory data = abi.encodePacked(adapter.GRANT_ROLE_SELECTOR(), bytes16(0));
        vm.expectRevert(RoleGrantAdapter.BadSelector.selector);
        adapter.intentHash(target, 0, data);
    }
}
