// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface ISafe {
    enum Operation {
        Call,
        DelegateCall
    }

    function execTransactionFromModule(
        address to,
        uint256 value,
        bytes calldata data,
        Operation operation
    ) external returns (bool success);
}

interface IActionAdapter {
    /// @notice Decode a concrete call and return the canonical typed intent hash.
    /// @dev Must fail closed for unknown selectors, targets, feeds, or unsafe params.
    function intentHash(address target, uint256 value, bytes calldata data) external view returns (bytes32);

    /// @notice Optional final pre-execution validation, e.g. live oracle checks.
    function validate(address target, uint256 value, bytes calldata data, bytes32 expectedIntentHash) external view;
}

/// @notice IntentGuardModule gates privileged Safe actions behind fresh typed intent approvals,
/// a public cool-off window, and K-of-N cancellation.
/// @dev This module is not enough by itself if Safe owners can still call guarded targets directly.
/// Transfer guarded ownership to this module, install an enforcing Safe Guard, or update protected
/// contracts so covered functions only accept calls from this module.
contract IntentGuardModule {
    enum ProposalState {
        None,
        Queued,
        Cancelled,
        Executed
    }

    struct VaultConfig {
        address safe;
        uint64 freshWindowSecs;
        uint64 cooloffSecs;
        uint64 executeDelaySecs;
        uint64 minProposalLifetimeSecs;
        uint8 threshold;
        uint8 vetoThreshold;
        uint64 nonce;
        bool initialized;
    }

    struct Proposal {
        bytes32 vaultId;
        uint64 nonce;
        address target;
        uint256 value;
        bytes32 dataHash;
        bytes32 intentHash;
        address adapter;
        uint64 queuedAt;
        uint64 expiresAt;
        uint8 cancelCount;
        ProposalState state;
    }

    struct Attestation {
        address signer;
        uint64 signedAt;
        uint64 expiresAt;
        bytes signature;
    }

    bytes32 public constant ATTESTATION_TYPEHASH = keccak256(
        "IntentGuardAttestation(bytes32 vaultId,uint64 nonce,address target,uint256 value,bytes32 dataHash,bytes32 intentHash,address adapter,uint64 signedAt,uint64 expiresAt,uint256 chainId,address module)"
    );

    mapping(bytes32 => VaultConfig) public vaults;
    mapping(bytes32 => mapping(address => bool)) public isSigner;
    mapping(bytes32 => mapping(address => mapping(address => bool))) public allowedAdapter;
    mapping(bytes32 => Proposal) public proposals;
    mapping(bytes32 => mapping(address => bool)) public cancelledBy;

    event VaultInitialized(bytes32 indexed vaultId, address indexed safe, uint8 threshold, uint8 vetoThreshold);
    event AdapterAllowed(bytes32 indexed vaultId, address indexed target, address indexed adapter, bool allowed);
    event ProposalQueued(bytes32 indexed proposalId, bytes32 indexed vaultId, uint64 nonce, address indexed target, bytes32 intentHash, uint64 executeAfter, uint64 expiresAt);
    event ProposalCancelled(bytes32 indexed proposalId, address indexed signer, uint8 cancelCount, string reason);
    event ProposalExecuted(bytes32 indexed proposalId, address indexed target, uint256 value);

    error AlreadyInitialized();
    error BadConfig();
    error UnknownVault();
    error UnknownProposal();
    error BadAdapter();
    error BadIntent();
    error BadState();
    error BadNonce();
    error BadSignature();
    error DuplicateSigner();
    error InsufficientSignatures();
    error SignatureNotFresh();
    error ProposalExpired();
    error CooloffActive();
    error NotSigner();
    error SafeExecutionFailed();

    modifier onlySafe(bytes32 vaultId) {
        if (msg.sender != vaults[vaultId].safe) revert UnknownVault();
        _;
    }

    function initializeVault(
        bytes32 vaultId,
        address safe,
        address[] calldata signers,
        uint8 threshold,
        uint8 vetoThreshold,
        uint64 freshWindowSecs,
        uint64 cooloffSecs,
        uint64 executeDelaySecs,
        uint64 minProposalLifetimeSecs
    ) external {
        if (vaults[vaultId].initialized) revert AlreadyInitialized();
        if (msg.sender != safe) revert BadConfig();
        if (safe == address(0) || threshold == 0 || vetoThreshold == 0 || threshold > signers.length || vetoThreshold > signers.length) {
            revert BadConfig();
        }
        if (freshWindowSecs == 0 || minProposalLifetimeSecs < cooloffSecs + executeDelaySecs) revert BadConfig();

        vaults[vaultId] = VaultConfig({
            safe: safe,
            freshWindowSecs: freshWindowSecs,
            cooloffSecs: cooloffSecs,
            executeDelaySecs: executeDelaySecs,
            minProposalLifetimeSecs: minProposalLifetimeSecs,
            threshold: threshold,
            vetoThreshold: vetoThreshold,
            nonce: 0,
            initialized: true
        });

        for (uint256 i = 0; i < signers.length; i++) {
            if (signers[i] == address(0) || isSigner[vaultId][signers[i]]) revert BadConfig();
            isSigner[vaultId][signers[i]] = true;
        }

        emit VaultInitialized(vaultId, safe, threshold, vetoThreshold);
    }

    /// @notice Called by the Safe to allow or remove a target/adapter pair.
    /// @dev Adapter changes themselves should be routed through a slower vault in production.
    function setAdapter(bytes32 vaultId, address target, address adapter, bool allowed) external onlySafe(vaultId) {
        if (target == address(0) || adapter == address(0)) revert BadAdapter();
        allowedAdapter[vaultId][target][adapter] = allowed;
        emit AdapterAllowed(vaultId, target, adapter, allowed);
    }

    function queue(
        bytes32 vaultId,
        address target,
        uint256 value,
        bytes calldata data,
        bytes32 expectedIntentHash,
        address adapter,
        uint64 proposalExpiresAt,
        Attestation[] calldata attestations
    ) external returns (bytes32 proposalId) {
        VaultConfig storage vault = vaults[vaultId];
        if (!vault.initialized) revert UnknownVault();
        if (!allowedAdapter[vaultId][target][adapter]) revert BadAdapter();
        if (proposalExpiresAt < uint64(block.timestamp) + vault.minProposalLifetimeSecs) revert ProposalExpired();

        bytes32 dataHash = keccak256(data);
        bytes32 decodedIntentHash = IActionAdapter(adapter).intentHash(target, value, data);
        if (decodedIntentHash != expectedIntentHash) revert BadIntent();

        _verifyAttestations(vaultId, vault, target, value, dataHash, expectedIntentHash, adapter, proposalExpiresAt, attestations);

        proposalId = keccak256(abi.encode(vaultId, vault.nonce, target, value, dataHash, expectedIntentHash, adapter));
        Proposal storage proposal = proposals[proposalId];
        if (proposal.state != ProposalState.None) revert BadState();

        proposal.vaultId = vaultId;
        proposal.nonce = vault.nonce;
        proposal.target = target;
        proposal.value = value;
        proposal.dataHash = dataHash;
        proposal.intentHash = expectedIntentHash;
        proposal.adapter = adapter;
        proposal.queuedAt = uint64(block.timestamp);
        proposal.expiresAt = proposalExpiresAt;
        proposal.state = ProposalState.Queued;

        emit ProposalQueued(
            proposalId,
            vaultId,
            vault.nonce,
            target,
            expectedIntentHash,
            uint64(block.timestamp) + vault.cooloffSecs + vault.executeDelaySecs,
            proposalExpiresAt
        );
    }

    function cancel(bytes32 proposalId, string calldata reason) external {
        Proposal storage proposal = proposals[proposalId];
        if (proposal.state != ProposalState.Queued) revert BadState();
        if (!isSigner[proposal.vaultId][msg.sender]) revert NotSigner();
        if (cancelledBy[proposalId][msg.sender]) revert DuplicateSigner();

        cancelledBy[proposalId][msg.sender] = true;
        proposal.cancelCount += 1;

        emit ProposalCancelled(proposalId, msg.sender, proposal.cancelCount, reason);

        if (proposal.cancelCount >= vaults[proposal.vaultId].vetoThreshold) {
            proposal.state = ProposalState.Cancelled;
        }
    }

    function execute(bytes32 proposalId, bytes calldata data) external {
        Proposal storage proposal = proposals[proposalId];
        if (proposal.state != ProposalState.Queued) revert BadState();

        VaultConfig storage vault = vaults[proposal.vaultId];
        if (proposal.nonce != vault.nonce) revert BadNonce();
        if (proposal.expiresAt < block.timestamp) revert ProposalExpired();
        if (keccak256(data) != proposal.dataHash) revert BadIntent();
        if (block.timestamp < proposal.queuedAt + vault.cooloffSecs + vault.executeDelaySecs) revert CooloffActive();

        IActionAdapter(proposal.adapter).validate(proposal.target, proposal.value, data, proposal.intentHash);

        proposal.state = ProposalState.Executed;
        vault.nonce += 1;

        bool ok = ISafe(vault.safe).execTransactionFromModule(
            proposal.target,
            proposal.value,
            data,
            ISafe.Operation.Call
        );
        if (!ok) revert SafeExecutionFailed();

        emit ProposalExecuted(proposalId, proposal.target, proposal.value);
    }

    function _verifyAttestations(
        bytes32 vaultId,
        VaultConfig storage vault,
        address target,
        uint256 value,
        bytes32 dataHash,
        bytes32 intentHash,
        address adapter,
        uint64 proposalExpiresAt,
        Attestation[] calldata attestations
    ) internal view {
        if (attestations.length < vault.threshold) revert InsufficientSignatures();

        address lastSigner;
        uint64 oldest = type(uint64).max;
        uint64 newest;

        for (uint256 i = 0; i < attestations.length; i++) {
            Attestation calldata att = attestations[i];

            if (att.signer <= lastSigner) revert DuplicateSigner();
            lastSigner = att.signer;

            if (att.signedAt < oldest) oldest = att.signedAt;
            if (att.signedAt > newest) newest = att.signedAt;

            _verifyAttestation(
                vaultId,
                vault,
                target,
                value,
                dataHash,
                intentHash,
                adapter,
                proposalExpiresAt,
                att
            );
        }

        // Defensive bottom-of-loop recheck per upstream review feedback
        // (https://github.com/uwecerron/intent-guard/pull/2). Functionally
        // equivalent to a `valid >= vault.threshold` assert because every
        // loop iteration above either reverts or runs to completion, so
        // the iteration count equals `attestations.length`. Re-reading the
        // calldata length here (rather than tracking a `uint256 valid`
        // counter inside the loop) avoids adding a stack local that would
        // push `_verifyAttestations` back over the legacy compile pipeline's
        // stack budget the refactor was written to fit under.
        if (attestations.length < vault.threshold) revert InsufficientSignatures();
        if (newest - oldest > vault.freshWindowSecs) revert SignatureNotFresh();
    }

    /// @notice Per-attestation validation: signer membership, freshness, and
    /// signature recovery against the canonical attestation digest.
    /// @dev Extracted from `_verifyAttestations` so the outer loop fits within
    /// the legacy compilation pipeline's stack budget. Behavior preserved.
    function _verifyAttestation(
        bytes32 vaultId,
        VaultConfig storage vault,
        address target,
        uint256 value,
        bytes32 dataHash,
        bytes32 intentHash,
        address adapter,
        uint64 proposalExpiresAt,
        Attestation calldata att
    ) internal view {
        if (!isSigner[vaultId][att.signer]) revert BadSignature();

        if (att.expiresAt < block.timestamp || att.expiresAt > proposalExpiresAt) revert SignatureNotFresh();
        if (att.signedAt > block.timestamp) revert SignatureNotFresh();
        if (block.timestamp - att.signedAt > vault.freshWindowSecs) revert SignatureNotFresh();

        bytes32 digest = _attestationDigest(
            vaultId,
            vault.nonce,
            target,
            value,
            dataHash,
            intentHash,
            adapter,
            att.signedAt,
            att.expiresAt
        );

        if (_recover(digest, att.signature) != att.signer) revert BadSignature();
    }

    /// @notice Compute the EIP-191 digest a signer must sign over.
    /// @dev Extracted from `_verifyAttestations` so the loop body fits within
    /// the legacy compilation pipeline's stack budget. Bytecode under the
    /// optimizer is equivalent to the inline form.
    function _attestationDigest(
        bytes32 vaultId,
        uint64 vaultNonce,
        address target,
        uint256 value,
        bytes32 dataHash,
        bytes32 intentHash,
        address adapter,
        uint64 signedAt,
        uint64 expiresAt
    ) internal view returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                "\x19Ethereum Signed Message:\n32",
                keccak256(
                    abi.encode(
                        ATTESTATION_TYPEHASH,
                        vaultId,
                        vaultNonce,
                        target,
                        value,
                        dataHash,
                        intentHash,
                        adapter,
                        signedAt,
                        expiresAt,
                        block.chainid,
                        address(this)
                    )
                )
            )
        );
    }

    function _recover(bytes32 digest, bytes calldata signature) internal pure returns (address) {
        if (signature.length != 65) revert BadSignature();

        bytes32 r;
        bytes32 s;
        uint8 v;

        assembly {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 32))
            v := byte(0, calldataload(add(signature.offset, 64)))
        }

        if (v < 27) v += 27;
        if (v != 27 && v != 28) revert BadSignature();
        if (uint256(s) > 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0) revert BadSignature();

        address signer = ecrecover(digest, v, r, s);
        if (signer == address(0)) revert BadSignature();
        return signer;
    }
}
