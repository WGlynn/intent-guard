// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IActionAdapter} from "./IntentGuardModule.sol";

/// @notice Adapter for mutable signer / validator / council membership:
///
///     addSigner(address newSigner)
///     removeSigner(address oldSigner)
///     setThreshold(uint256 newThreshold)
///
/// This is the most recursive governance attack class. Signer-set updates
/// are gated by the very signers being updated: a captured signer set can
/// approve adding more attacker-controlled signers, and once enough are
/// admitted the threshold is mechanically overwhelmed. From there every
/// other guard collapses, because the set that authenticates everything
/// has been quietly rewritten.
///
/// The adapter binds (action, target, parameter) into the typed intent and
/// at execute time enforces per-target policy with two asymmetric controls:
///
///   - addSigner requires both `addAllowed` AND a per-target candidate
///     allowlist (admission control — admitting a member is the
///     dangerous direction)
///   - removeSigner only requires `removeAllowed` (shedding a member is
///     less recursive; protocols often want fast paths to drop a
///     compromised signer without an additional allowlist hop)
///   - setThreshold requires `thresholdChangeAllowed` AND the new value
///     to lie inside [minThreshold, maxThreshold] (in-band guard against
///     "set threshold to 1" or "set threshold to MAX_UINT to brick set")
///
/// Zero policy = all flags false = every action reverts. Use that for
/// frozen signer sets that should never change post-launch.
contract SignerSetUpdateAdapter is IActionAdapter {
    bytes4 public constant ADD_SIGNER_SELECTOR = bytes4(keccak256("addSigner(address)"));
    bytes4 public constant REMOVE_SIGNER_SELECTOR = bytes4(keccak256("removeSigner(address)"));
    bytes4 public constant SET_THRESHOLD_SELECTOR = bytes4(keccak256("setThreshold(uint256)"));

    bytes32 public constant ADD_SIGNER_INTENT_TYPEHASH = keccak256(
        "SignerSetAddSigner(address target,uint256 value,address newSigner)"
    );
    bytes32 public constant REMOVE_SIGNER_INTENT_TYPEHASH = keccak256(
        "SignerSetRemoveSigner(address target,uint256 value,address oldSigner)"
    );
    bytes32 public constant SET_THRESHOLD_INTENT_TYPEHASH = keccak256(
        "SignerSetSetThreshold(address target,uint256 value,uint256 newThreshold)"
    );

    enum Action {
        AddSigner,
        RemoveSigner,
        SetThreshold
    }

    struct SignerSetPolicy {
        bool addAllowed;
        bool removeAllowed;
        bool thresholdChangeAllowed;
        uint256 minThreshold;
        uint256 maxThreshold;
    }

    address public immutable owner;
    mapping(address => SignerSetPolicy) public policy;
    // addCandidateAllowed[target][candidate]
    mapping(address => mapping(address => bool)) public addCandidateAllowed;

    event PolicySet(
        address indexed target,
        bool addAllowed,
        bool removeAllowed,
        bool thresholdChangeAllowed,
        uint256 minThreshold,
        uint256 maxThreshold
    );
    event AddCandidateSet(address indexed target, address indexed candidate, bool allowed);

    error NotOwner();
    error BadSelector();
    error ZeroOwner();
    error AddNotAllowed();
    error RemoveNotAllowed();
    error ThresholdChangeNotAllowed();
    error CandidateNotAllowed();
    error ThresholdOutOfRange();

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    constructor(address owner_) {
        if (owner_ == address(0)) revert ZeroOwner();
        owner = owner_;
    }

    function setPolicy(
        address target,
        bool addAllowed,
        bool removeAllowed,
        bool thresholdChangeAllowed,
        uint256 minThreshold,
        uint256 maxThreshold
    ) external onlyOwner {
        policy[target] = SignerSetPolicy({
            addAllowed: addAllowed,
            removeAllowed: removeAllowed,
            thresholdChangeAllowed: thresholdChangeAllowed,
            minThreshold: minThreshold,
            maxThreshold: maxThreshold
        });
        emit PolicySet(target, addAllowed, removeAllowed, thresholdChangeAllowed, minThreshold, maxThreshold);
    }

    function setAddCandidate(address target, address candidate, bool allowed) external onlyOwner {
        addCandidateAllowed[target][candidate] = allowed;
        emit AddCandidateSet(target, candidate, allowed);
    }

    /// @inheritdoc IActionAdapter
    function intentHash(address target, uint256 value, bytes calldata data) external pure returns (bytes32) {
        (Action action, bytes32 param) = _decode(data);
        if (action == Action.AddSigner) {
            return keccak256(abi.encode(ADD_SIGNER_INTENT_TYPEHASH, target, value, address(uint160(uint256(param)))));
        } else if (action == Action.RemoveSigner) {
            return keccak256(abi.encode(REMOVE_SIGNER_INTENT_TYPEHASH, target, value, address(uint160(uint256(param)))));
        } else {
            return keccak256(abi.encode(SET_THRESHOLD_INTENT_TYPEHASH, target, value, uint256(param)));
        }
    }

    /// @inheritdoc IActionAdapter
    function validate(address target, uint256, bytes calldata data, bytes32) external view {
        (Action action, bytes32 param) = _decode(data);
        SignerSetPolicy memory pol = policy[target];

        if (action == Action.AddSigner) {
            if (!pol.addAllowed) revert AddNotAllowed();
            address candidate = address(uint160(uint256(param)));
            if (!addCandidateAllowed[target][candidate]) revert CandidateNotAllowed();
        } else if (action == Action.RemoveSigner) {
            if (!pol.removeAllowed) revert RemoveNotAllowed();
        } else {
            if (!pol.thresholdChangeAllowed) revert ThresholdChangeNotAllowed();
            uint256 newThreshold = uint256(param);
            if (newThreshold < pol.minThreshold || newThreshold > pol.maxThreshold) revert ThresholdOutOfRange();
        }
    }

    function _decode(bytes calldata data) internal pure returns (Action action, bytes32 param) {
        if (data.length != 4 + 32) revert BadSelector();
        bytes4 selector;
        assembly {
            selector := calldataload(data.offset)
        }
        if (selector == ADD_SIGNER_SELECTOR) {
            action = Action.AddSigner;
        } else if (selector == REMOVE_SIGNER_SELECTOR) {
            action = Action.RemoveSigner;
        } else if (selector == SET_THRESHOLD_SELECTOR) {
            action = Action.SetThreshold;
        } else {
            revert BadSelector();
        }
        param = bytes32(data[4:36]);
    }
}
