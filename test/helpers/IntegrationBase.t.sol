// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {IntentGuardModule} from "../../contracts/IntentGuardModule.sol";

/// @notice Minimal Safe mock that routes the module's
/// execTransactionFromModule call to the target with the provided data + value.
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

/// @notice Per-attestation parameter bundle. Packed into a struct because
/// the legacy compile pipeline can't fit ~12 args + locals in the stack
/// window of a single helper invocation.
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

/// @notice Shared scaffolding for end-to-end integration tests of
/// IntentGuardModule + an adapter + a target. Subclasses provide the
/// concrete adapter and target setup; this base supplies the signer set,
/// the MockSafe, the attestation signing helper, and the conventional
/// vault parameters (cool-off, freshness window, etc).
abstract contract IntegrationBase is Test {
    IntentGuardModule public module;
    MockSafe public safe;

    bytes32 public constant VAULT_ID = keccak256("integration-base-vault");

    uint256 public keyA = 0xA11CE;
    uint256 public keyB = 0xB0B;
    uint256 public keyC = 0xCAFE;
    address public signerLow;
    address public signerMid;
    address public signerHigh;
    uint256 public keyLow;
    uint256 public keyMid;
    uint256 public keyHigh;

    uint64 public constant FRESH_WINDOW = 600;
    uint64 public constant COOLOFF = 86400;
    uint64 public constant EXECUTE_DELAY = 60;
    uint64 public constant MIN_PROPOSAL_LIFETIME = 86460 + 3600;

    /// @dev Subclasses call this from their setUp() to initialize the
    /// module + Safe + signers. After this returns, subclasses can deploy
    /// their adapter + target and call `_registerAdapter(target, adapter)`.
    function _setUpBase() internal {
        address a = vm.addr(keyA);
        address b = vm.addr(keyB);
        address c = vm.addr(keyC);
        (signerLow, signerMid, signerHigh, keyLow, keyMid, keyHigh) = _sortByAddress(a, keyA, b, keyB, c, keyC);

        module = new IntentGuardModule();
        safe = new MockSafe();
        safe.setGuard(address(module));

        address[] memory signers = new address[](3);
        signers[0] = signerLow;
        signers[1] = signerMid;
        signers[2] = signerHigh;

        vm.prank(address(safe));
        module.initializeVault(
            VAULT_ID, address(safe), signers, 2, 2,
            FRESH_WINDOW, COOLOFF, EXECUTE_DELAY, MIN_PROPOSAL_LIFETIME
        );
    }

    function _registerAdapter(address target, address adapter) internal {
        vm.prank(address(safe));
        module.setAdapter(VAULT_ID, target, adapter, true);
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

    function _twoAttestations(uint256 ka, uint256 kb, AttestPayload memory p)
        internal
        view
        returns (IntentGuardModule.Attestation[] memory atts)
    {
        atts = new IntentGuardModule.Attestation[](2);
        atts[0] = _signAttestation(ka, p);
        atts[1] = _signAttestation(kb, p);
    }

    function _twoSortedAttestations(AttestPayload memory p)
        internal
        view
        returns (IntentGuardModule.Attestation[] memory atts)
    {
        return _twoAttestations(keyLow, keyMid, p);
    }

    /// @dev Build the AttestPayload for a target that has already been
    /// registered with `_registerAdapter`. Subclasses pass the adapter
    /// address explicitly because they own the adapter deployment.
    function _buildPayload(
        address target,
        uint256 value,
        address adapter,
        bytes32 intentHash,
        bytes memory data,
        uint64 signedAt,
        uint64 expiresAt
    ) internal pure returns (AttestPayload memory p) {
        p.vaultId = VAULT_ID;
        p.vaultNonce = 0;
        p.target = target;
        p.value = value;
        p.dataHash = keccak256(data);
        p.intentHash = intentHash;
        p.adapterAddr = adapter;
        p.signedAt = signedAt;
        p.expiresAt = expiresAt;
    }
}
