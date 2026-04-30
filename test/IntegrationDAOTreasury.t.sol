// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {IntentGuardModule} from "../contracts/IntentGuardModule.sol";
import {DAOTreasuryAdapter} from "../contracts/DAOTreasuryAdapter.sol";

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

/// @notice Minimal treasury that records the last withdraw call.
contract MockTreasury {
    address public lastRecipient;
    address public lastAsset;
    uint256 public lastAmount;
    uint256 public callCount;

    function withdraw(address recipient, address asset, uint256 amount) external {
        lastRecipient = recipient;
        lastAsset = asset;
        lastAmount = amount;
        callCount += 1;
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

/// @notice End-to-end: a treasury withdrawal proposal flows queue → cool-off
/// → execute and lands the call on the treasury contract. Per-asset caps
/// rejected at validate() time.
contract IntegrationDAOTreasuryTest is Test {
    IntentGuardModule module;
    DAOTreasuryAdapter adapter;
    MockSafe safe;
    MockTreasury treasury;

    bytes32 constant VAULT_ID = keccak256("treasury-vault");

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
    address recipient = address(0x1234);
    address asset = address(0xDEAD);

    uint256 constant CAP = 100_000e18;

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
        treasury = new MockTreasury();
        adapter = new DAOTreasuryAdapter(adapterOwner);

        vm.prank(adapterOwner);
        adapter.setAssetPolicy(asset, true, CAP);

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
        module.setAdapter(VAULT_ID, address(treasury), address(adapter), true);
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

    function _buildPayload(bytes memory data, uint64 signedAt, uint64 expiresAt)
        internal
        view
        returns (AttestPayload memory p)
    {
        p.vaultId = VAULT_ID;
        p.vaultNonce = 0;
        p.target = address(treasury);
        p.value = 0;
        p.dataHash = keccak256(data);
        p.intentHash = adapter.intentHash(address(treasury), 0, data);
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

    function test_endToEnd_withdrawalLandsAtTreasury() public {
        uint256 amount = 50_000e18;
        bytes memory data = abi.encodeWithSignature(
            "withdraw(address,address,uint256)", recipient, asset, amount
        );
        AttestPayload memory p = _buildPayload(
            data, uint64(block.timestamp), uint64(block.timestamp) + 200
        );
        uint64 proposalExpiresAt = uint64(block.timestamp) + MIN_PROPOSAL_LIFETIME + 100;

        bytes32 proposalId = module.queue(
            VAULT_ID, address(treasury), 0, data, p.intentHash, address(adapter),
            proposalExpiresAt, _atts(keyLow, keyMid, p)
        );

        vm.warp(block.timestamp + COOLOFF + EXECUTE_DELAY + 1);
        module.execute(proposalId, data);

        assertEq(treasury.lastRecipient(), recipient);
        assertEq(treasury.lastAsset(), asset);
        assertEq(treasury.lastAmount(), amount);
        assertEq(treasury.callCount(), 1);
    }

    // ============ cap enforcement at execute ============

    function test_endToEnd_overCapWithdrawalRevertsAtExecute() public {
        // Build a proposal whose amount is over the CAP. Adapter's intentHash
        // doesn't reject — that's the signers' approval. validate() at
        // execute time is where the cap fires.
        uint256 amount = CAP + 1;
        bytes memory data = abi.encodeWithSignature(
            "withdraw(address,address,uint256)", recipient, asset, amount
        );
        AttestPayload memory p = _buildPayload(
            data, uint64(block.timestamp), uint64(block.timestamp) + 200
        );
        uint64 proposalExpiresAt = uint64(block.timestamp) + MIN_PROPOSAL_LIFETIME + 100;

        bytes32 proposalId = module.queue(
            VAULT_ID, address(treasury), 0, data, p.intentHash, address(adapter),
            proposalExpiresAt, _atts(keyLow, keyMid, p)
        );

        vm.warp(block.timestamp + COOLOFF + EXECUTE_DELAY + 1);

        vm.expectRevert(DAOTreasuryAdapter.AmountExceedsCap.selector);
        module.execute(proposalId, data);

        // Treasury must be unchanged
        assertEq(treasury.callCount(), 0);
    }
}
