// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {IntentGuardModule} from "../contracts/IntentGuardModule.sol";
import {UUPSUpgradeAdapter} from "../contracts/UUPSUpgradeAdapter.sol";

/// @notice Minimal Safe mock implementing only execTransactionFromModule.
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

/// @notice Mock UUPS proxy that records the upgrade target. We don't need
/// real ERC1967 storage slots — we just need upgradeToAndCall / upgradeTo
/// to exist and be checkable.
contract MockUUPSProxy {
    address public lastImpl;
    bytes public lastData;

    function upgradeToAndCall(address newImpl, bytes calldata data) external payable {
        lastImpl = newImpl;
        lastData = data;
    }

    function upgradeTo(address newImpl) external {
        lastImpl = newImpl;
    }
}

contract MockImplV2 {
    uint256 public constant VERSION = 2;
}

/// @notice Parameters for signing an attestation. Packed into a struct
/// because the legacy compile pipeline can't fit ~12 args + locals in
/// the per-call stack window.
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

/// @notice End-to-end integration: IntentGuardModule + UUPSUpgradeAdapter
/// + a mock Safe + a mock UUPS proxy. Exercises the full
/// queue → cool-off → execute pipeline with signed attestations.
contract IntegrationUUPSTest is Test {
    IntentGuardModule module;
    UUPSUpgradeAdapter adapter;
    MockSafe safe;
    MockUUPSProxy proxy;
    MockImplV2 newImpl;

    bytes32 constant VAULT_ID = keccak256("integration-vault");

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

    uint64 constant FRESH_WINDOW = 600;
    uint64 constant COOLOFF = 86400;
    uint64 constant EXECUTE_DELAY = 60;
    uint64 constant MIN_PROPOSAL_LIFETIME = 86460 + 3600;

    function setUp() public {
        // Resolve and sort signer addresses ascending so the module's
        // strict-ordering check on attestations passes.
        address a = vm.addr(keyA);
        address b = vm.addr(keyB);
        address c = vm.addr(keyC);
        (signerLow, signerMid, signerHigh, keyLow, keyMid, keyHigh) = _sortByAddress(a, keyA, b, keyB, c, keyC);

        module = new IntentGuardModule();
        safe = new MockSafe();
        safe.setGuard(address(module));

        adapter = new UUPSUpgradeAdapter(adapterOwner);
        proxy = new MockUUPSProxy();
        newImpl = new MockImplV2();

        vm.startPrank(adapterOwner);
        adapter.setProxyAllowed(address(proxy), true);
        adapter.setImplCodehash(address(proxy), address(newImpl), address(newImpl).codehash);
        vm.stopPrank();

        address[] memory signers = new address[](3);
        signers[0] = signerLow;
        signers[1] = signerMid;
        signers[2] = signerHigh;

        vm.prank(address(safe));
        module.initializeVault(
            VAULT_ID,
            address(safe),
            signers,
            2,
            2,
            FRESH_WINDOW,
            COOLOFF,
            EXECUTE_DELAY,
            MIN_PROPOSAL_LIFETIME
        );

        vm.prank(address(safe));
        module.setAdapter(VAULT_ID, address(proxy), address(adapter), true);
    }

    // ============ helpers ============

    function _sortByAddress(address a, uint256 ka, address b, uint256 kb, address c, uint256 kc)
        internal
        pure
        returns (address sa, address sb, address sc, uint256 ksa, uint256 ksb, uint256 ksc)
    {
        // 3-element bubble sort
        sa = a;
        sb = b;
        sc = c;
        ksa = ka;
        ksb = kb;
        ksc = kc;
        if (sa > sb) {
            (sa, sb) = (sb, sa);
            (ksa, ksb) = (ksb, ksa);
        }
        if (sb > sc) {
            (sb, sc) = (sc, sb);
            (ksb, ksc) = (ksc, ksb);
        }
        if (sa > sb) {
            (sa, sb) = (sb, sa);
            (ksa, ksb) = (ksb, ksa);
        }
    }

    function _signAttestation(uint256 privKey, AttestPayload memory p)
        internal
        view
        returns (IntentGuardModule.Attestation memory att)
    {
        bytes32 typedHash = keccak256(
            abi.encode(
                module.ATTESTATION_TYPEHASH(),
                p.vaultId,
                p.vaultNonce,
                p.target,
                p.value,
                p.dataHash,
                p.intentHash,
                p.adapterAddr,
                p.signedAt,
                p.expiresAt,
                block.chainid,
                address(module)
            )
        );
        bytes32 ethSignedHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", typedHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privKey, ethSignedHash);
        att.signer = vm.addr(privKey);
        att.signedAt = p.signedAt;
        att.expiresAt = p.expiresAt;
        att.signature = abi.encodePacked(r, s, v);
    }

    function _buildPayload(bytes memory upgradeData, uint64 signedAt, uint64 expiresAt)
        internal
        view
        returns (AttestPayload memory p)
    {
        p.vaultId = VAULT_ID;
        p.vaultNonce = 0;
        p.target = address(proxy);
        p.value = 0;
        p.dataHash = keccak256(upgradeData);
        p.intentHash = adapter.intentHash(address(proxy), 0, upgradeData);
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

    // ============ happy path ============

    function test_endToEnd_upgrade_succeeds() public {
        bytes memory upgradeData = abi.encodeWithSignature(
            "upgradeToAndCall(address,bytes)", address(newImpl), bytes("")
        );
        AttestPayload memory p = _buildPayload(
            upgradeData,
            uint64(block.timestamp),
            uint64(block.timestamp) + 200
        );
        uint64 proposalExpiresAt = uint64(block.timestamp) + MIN_PROPOSAL_LIFETIME + 100;

        bytes32 proposalId = module.queue(
            VAULT_ID, address(proxy), 0, upgradeData, p.intentHash, address(adapter),
            proposalExpiresAt, _atts(keyLow, keyMid, p)
        );

        vm.warp(block.timestamp + COOLOFF + EXECUTE_DELAY + 1);

        module.execute(proposalId, upgradeData);

        assertEq(proxy.lastImpl(), address(newImpl), "proxy.lastImpl should be the new impl after execute");
    }

    // ============ veto path ============

    function test_endToEnd_vetoBlocksExecution() public {
        bytes memory upgradeData = abi.encodeWithSignature("upgradeTo(address)", address(newImpl));
        AttestPayload memory p = _buildPayload(
            upgradeData, uint64(block.timestamp), uint64(block.timestamp) + 200
        );
        uint64 proposalExpiresAt = uint64(block.timestamp) + MIN_PROPOSAL_LIFETIME + 100;

        bytes32 proposalId = module.queue(
            VAULT_ID, address(proxy), 0, upgradeData, p.intentHash, address(adapter),
            proposalExpiresAt, _atts(keyLow, keyMid, p)
        );

        // Two distinct signers veto during cool-off (vetoThreshold = 2)
        vm.prank(signerLow);
        module.cancel(proposalId, "looks suspicious");
        vm.prank(signerHigh);
        module.cancel(proposalId, "agreed, abort");

        vm.warp(block.timestamp + COOLOFF + EXECUTE_DELAY + 1);

        vm.expectRevert(IntentGuardModule.BadState.selector);
        module.execute(proposalId, upgradeData);

        assertEq(proxy.lastImpl(), address(0), "proxy must not be upgraded after veto");
    }

    // ============ cool-off enforcement ============

    function test_endToEnd_executeBeforeCooloffReverts() public {
        bytes memory upgradeData = abi.encodeWithSignature("upgradeTo(address)", address(newImpl));
        AttestPayload memory p = _buildPayload(
            upgradeData, uint64(block.timestamp), uint64(block.timestamp) + 200
        );
        uint64 proposalExpiresAt = uint64(block.timestamp) + MIN_PROPOSAL_LIFETIME + 100;

        bytes32 proposalId = module.queue(
            VAULT_ID, address(proxy), 0, upgradeData, p.intentHash, address(adapter),
            proposalExpiresAt, _atts(keyLow, keyMid, p)
        );

        // Execute immediately, before cool-off elapses
        vm.expectRevert(IntentGuardModule.CooloffActive.selector);
        module.execute(proposalId, upgradeData);
    }

    // ============ stale signature ============

    function test_endToEnd_staleSignaturesRejectAtQueue() public {
        // Anchor block.timestamp to a known starting value so the freshness
        // arithmetic is unambiguous.
        vm.warp(10_000);

        bytes memory upgradeData = abi.encodeWithSignature("upgradeTo(address)", address(newImpl));

        // Sign at T=10_000, then warp past the freshness window.
        uint64 oldSignedAt = uint64(block.timestamp);
        uint64 expiresAt = oldSignedAt + 200_000; // far enough out to clear the proposalExpiresAt check
        bytes32 intent = adapter.intentHash(address(proxy), 0, upgradeData);

        AttestPayload memory p;
        p.vaultId = VAULT_ID;
        p.vaultNonce = 0;
        p.target = address(proxy);
        p.value = 0;
        p.dataHash = keccak256(upgradeData);
        p.intentHash = intent;
        p.adapterAddr = address(adapter);
        p.signedAt = oldSignedAt;
        p.expiresAt = expiresAt;

        IntentGuardModule.Attestation[] memory atts = _atts(keyLow, keyMid, p);

        // Now warp past the freshness window
        vm.warp(uint256(oldSignedAt) + uint256(FRESH_WINDOW) + 1);

        uint64 proposalExpiresAt = uint64(block.timestamp) + MIN_PROPOSAL_LIFETIME + 100;

        vm.expectRevert(IntentGuardModule.SignatureNotFresh.selector);
        module.queue(
            VAULT_ID, address(proxy), 0, upgradeData, intent, address(adapter),
            proposalExpiresAt, atts
        );
    }
}
