// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {IntentGuardModule} from "../contracts/IntentGuardModule.sol";
import {RoleGrantAdapter} from "../contracts/RoleGrantAdapter.sol";

contract MockSafe {
    error UnauthorizedModule();
    address public guard;

    function setGuard(address g) external {
        guard = g;
    }

    function execTransactionFromModule(address to, uint256 value, bytes calldata data, uint8)
        external
        payable
        returns (bool success)
    {
        if (msg.sender != guard) revert UnauthorizedModule();
        (success,) = to.call{value: value}(data);
    }

    receive() external payable {}
}

/// @notice Mock AccessControl-style target. Records grant/revoke calls for assertion.
contract MockAccessControlled {
    event RoleGranted(bytes32 role, address account);
    event RoleRevoked(bytes32 role, address account);

    bytes32 public lastRole;
    address public lastAccount;
    bool public lastWasGrant;
    uint256 public callCount;

    function grantRole(bytes32 role, address account) external {
        lastRole = role;
        lastAccount = account;
        lastWasGrant = true;
        callCount += 1;
        emit RoleGranted(role, account);
    }

    function revokeRole(bytes32 role, address account) external {
        lastRole = role;
        lastAccount = account;
        lastWasGrant = false;
        callCount += 1;
        emit RoleRevoked(role, account);
    }
}

struct AttestPayload {
    bytes32 vaultId;
    uint64 vaultNonce;
    address target;
    uint256 value;
    bytes32 dataHash;
    bytes32 intentHash;
    address adapterAddr;
    uint64 signedAt;
    uint64 expiresAt;
}

contract IntegrationRoleGrantTest is Test {
    IntentGuardModule module;
    RoleGrantAdapter adapter;
    MockSafe safe;
    MockAccessControlled accessControlled;

    bytes32 constant VAULT_ID = keccak256("role-grant-vault");
    bytes32 constant ROLE_OPERATOR = keccak256("OPERATOR_ROLE");
    bytes32 constant ROLE_FROZEN_ADMIN = keccak256("FROZEN_ADMIN_ROLE");

    uint256 keyA = 0xA11CE;
    uint256 keyB = 0xB0B;
    uint256 keyC = 0xCAFE;
    address signerLow;
    address signerMid;
    address signerHigh;
    uint256 keyLow;
    uint256 keyMid;
    uint256 keyHigh;

    address adapterOwner = address(0xDEAF);
    address newOperator = address(0x1234);
    address attackerAccount = address(0x9999);

    uint64 constant FRESH_WINDOW = 600;
    uint64 constant COOLOFF = 86400;
    uint64 constant EXECUTE_DELAY = 60;
    uint64 constant MIN_PROPOSAL_LIFETIME = 86460 + 3600;

    function setUp() public {
        address a = vm.addr(keyA);
        address b = vm.addr(keyB);
        address c = vm.addr(keyC);
        (signerLow, signerMid, signerHigh, keyLow, keyMid, keyHigh) = _sortByAddress(a, keyA, b, keyB, c, keyC);

        module = new IntentGuardModule();
        safe = new MockSafe();
        safe.setGuard(address(module));
        accessControlled = new MockAccessControlled();
        adapter = new RoleGrantAdapter(adapterOwner);

        vm.startPrank(adapterOwner);
        // OPERATOR_ROLE: allowed, account-allowlist required, only newOperator on it
        adapter.setRolePolicy(address(accessControlled), ROLE_OPERATOR, true, false, true);
        adapter.setAllowedAccount(address(accessControlled), ROLE_OPERATOR, newOperator, true);

        // FROZEN_ADMIN_ROLE: allowed but frozen — no membership changes
        adapter.setRolePolicy(address(accessControlled), ROLE_FROZEN_ADMIN, true, true, false);
        vm.stopPrank();

        address[] memory signers = new address[](3);
        signers[0] = signerLow;
        signers[1] = signerMid;
        signers[2] = signerHigh;

        vm.prank(address(safe));
        module.initializeVault(
            VAULT_ID, address(safe), signers, 2, 2,
            FRESH_WINDOW, COOLOFF, EXECUTE_DELAY, MIN_PROPOSAL_LIFETIME
        );
        vm.prank(address(safe));
        module.setAdapter(VAULT_ID, address(accessControlled), address(adapter), true);
    }

    function _sortByAddress(address a, uint256 ka, address b, uint256 kb, address c, uint256 kc)
        internal
        pure
        returns (address sa, address sb, address sc, uint256 ksa, uint256 ksb, uint256 ksc)
    {
        sa = a;
        sb = b;
        sc = c;
        ksa = ka;
        ksb = kb;
        ksc = kc;
        if (sa > sb) { (sa, sb) = (sb, sa); (ksa, ksb) = (ksb, ksa); }
        if (sb > sc) { (sb, sc) = (sc, sb); (ksb, ksc) = (ksc, ksb); }
        if (sa > sb) { (sa, sb) = (sb, sa); (ksa, ksb) = (ksb, ksa); }
    }

    function _signAttestation(uint256 privKey, AttestPayload memory p)
        internal
        view
        returns (IntentGuardModule.Attestation memory att)
    {
        bytes32 typedHash = keccak256(
            abi.encode(
                module.ATTESTATION_TYPEHASH(),
                p.vaultId, p.vaultNonce, p.target, p.value,
                p.dataHash, p.intentHash, p.adapterAddr,
                p.signedAt, p.expiresAt, block.chainid, address(module)
            )
        );
        bytes32 ethSignedHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", typedHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privKey, ethSignedHash);
        att.signer = vm.addr(privKey);
        att.signedAt = p.signedAt;
        att.expiresAt = p.expiresAt;
        att.signature = abi.encodePacked(r, s, v);
    }

    function _buildPayload(bytes memory data, uint64 signedAt, uint64 expiresAt)
        internal
        view
        returns (AttestPayload memory p)
    {
        p.vaultId = VAULT_ID;
        p.vaultNonce = 0;
        p.target = address(accessControlled);
        p.value = 0;
        p.dataHash = keccak256(data);
        p.intentHash = adapter.intentHash(address(accessControlled), 0, data);
        p.adapterAddr = address(adapter);
        p.signedAt = signedAt;
        p.expiresAt = expiresAt;
    }

    function _atts(uint256 ka, uint256 kb, AttestPayload memory p)
        internal
        view
        returns (IntentGuardModule.Attestation[] memory atts)
    {
        atts = new IntentGuardModule.Attestation[](2);
        atts[0] = _signAttestation(ka, p);
        atts[1] = _signAttestation(kb, p);
    }

    // ============ happy path: grant on allowlisted account ============

    function test_endToEnd_grantOnAllowedAccount() public {
        bytes memory data = abi.encodeWithSignature(
            "grantRole(bytes32,address)", ROLE_OPERATOR, newOperator
        );
        AttestPayload memory p = _buildPayload(
            data, uint64(block.timestamp), uint64(block.timestamp) + 200
        );
        uint64 proposalExpiresAt = uint64(block.timestamp) + MIN_PROPOSAL_LIFETIME + 100;

        bytes32 proposalId = module.queue(
            VAULT_ID, address(accessControlled), 0, data, p.intentHash, address(adapter),
            proposalExpiresAt, _atts(keyLow, keyMid, p)
        );

        vm.warp(block.timestamp + COOLOFF + EXECUTE_DELAY + 1);
        module.execute(proposalId, data);

        assertEq(accessControlled.lastRole(), ROLE_OPERATOR);
        assertEq(accessControlled.lastAccount(), newOperator);
        assertTrue(accessControlled.lastWasGrant());
    }

    // ============ block: grant to attacker account (off allowlist) ============

    function test_endToEnd_grantToAttackerBlockedAtExecute() public {
        bytes memory data = abi.encodeWithSignature(
            "grantRole(bytes32,address)", ROLE_OPERATOR, attackerAccount
        );
        AttestPayload memory p = _buildPayload(
            data, uint64(block.timestamp), uint64(block.timestamp) + 200
        );
        uint64 proposalExpiresAt = uint64(block.timestamp) + MIN_PROPOSAL_LIFETIME + 100;

        // Even if signers were socially-engineered into approving a grant
        // to the attacker, the adapter's account-allowlist gate fires at
        // execute time.
        bytes32 proposalId = module.queue(
            VAULT_ID, address(accessControlled), 0, data, p.intentHash, address(adapter),
            proposalExpiresAt, _atts(keyLow, keyMid, p)
        );

        vm.warp(block.timestamp + COOLOFF + EXECUTE_DELAY + 1);

        vm.expectRevert(RoleGrantAdapter.AccountNotAllowed.selector);
        module.execute(proposalId, data);

        assertEq(accessControlled.callCount(), 0);
    }

    // ============ block: grant to frozen role ============

    function test_endToEnd_grantOnFrozenRoleBlockedAtExecute() public {
        bytes memory data = abi.encodeWithSignature(
            "grantRole(bytes32,address)", ROLE_FROZEN_ADMIN, newOperator
        );
        AttestPayload memory p = _buildPayload(
            data, uint64(block.timestamp), uint64(block.timestamp) + 200
        );
        uint64 proposalExpiresAt = uint64(block.timestamp) + MIN_PROPOSAL_LIFETIME + 100;

        bytes32 proposalId = module.queue(
            VAULT_ID, address(accessControlled), 0, data, p.intentHash, address(adapter),
            proposalExpiresAt, _atts(keyLow, keyMid, p)
        );

        vm.warp(block.timestamp + COOLOFF + EXECUTE_DELAY + 1);

        vm.expectRevert(RoleGrantAdapter.RoleFrozen.selector);
        module.execute(proposalId, data);

        assertEq(accessControlled.callCount(), 0);
    }
}
