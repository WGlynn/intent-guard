// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IActionAdapter} from "./IntentGuardModule.sol";

/// @notice Adapter for DAO treasury withdrawals shaped as:
///
///     withdraw(address recipient, address asset, uint256 amount)
///
/// where `asset == address(0)` denotes the native chain token (e.g. ETH).
///
/// The adapter binds (recipient, asset, amount) into the typed intent so
/// signers approve a specific destination, asset, and quantity. `validate()`
/// adds optional defense-in-depth controls:
///
///   - Per-asset allowlist with optional per-withdrawal cap
///   - Optional recipient allowlist (off by default — typically the
///     intent binding is enough, but high-stakes vaults may want to gate
///     the address space further)
///
/// Both controls default to "no policy" (everything passes validate beyond
/// the intent binding). The adapter owner opts in to caps and allowlists
/// per asset / recipient.
contract DAOTreasuryAdapter is IActionAdapter {
    bytes4 public constant WITHDRAW_SELECTOR = bytes4(keccak256("withdraw(address,address,uint256)"));

    bytes32 public constant WITHDRAW_INTENT_TYPEHASH = keccak256(
        "DAOTreasuryWithdraw(address target,uint256 value,address recipient,address asset,uint256 amount)"
    );

    struct AssetPolicy {
        bool allowed;
        // Per-withdrawal cap in the asset's smallest unit (wei for ETH,
        // 1e6 USDC, 1e18 DAI, etc.). Zero means "no cap on this asset"
        // (NOT recommended for production — set a sane ceiling).
        uint256 maxAmount;
    }

    address public immutable owner;
    mapping(address => AssetPolicy) public assetPolicy;
    mapping(address => bool) public recipientAllowed;

    /// @notice If true, validate() requires the recipient to be on
    /// `recipientAllowed`. Off by default — when false, recipients are
    /// constrained only by the signed intent, not by an allowlist.
    bool public requireRecipientAllowlist;

    event AssetPolicySet(address indexed asset, bool allowed, uint256 maxAmount);
    event RecipientAllowed(address indexed recipient, bool allowed);
    event RequireRecipientAllowlistSet(bool required);

    error NotOwner();
    error BadSelector();
    error AssetNotAllowed();
    error AmountExceedsCap();
    error RecipientNotAllowed();
    error ZeroOwner();
    error ZeroRecipient();

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    constructor(address owner_) {
        if (owner_ == address(0)) revert ZeroOwner();
        owner = owner_;
    }

    function setAssetPolicy(address asset, bool allowed, uint256 maxAmount) external onlyOwner {
        assetPolicy[asset] = AssetPolicy({allowed: allowed, maxAmount: maxAmount});
        emit AssetPolicySet(asset, allowed, maxAmount);
    }

    function setRecipientAllowed(address recipient, bool allowed) external onlyOwner {
        recipientAllowed[recipient] = allowed;
        emit RecipientAllowed(recipient, allowed);
    }

    function setRequireRecipientAllowlist(bool required) external onlyOwner {
        requireRecipientAllowlist = required;
        emit RequireRecipientAllowlistSet(required);
    }

    /// @inheritdoc IActionAdapter
    function intentHash(address target, uint256 value, bytes calldata data) external pure returns (bytes32) {
        (address recipient, address asset, uint256 amount) = _decode(data);
        return keccak256(
            abi.encode(WITHDRAW_INTENT_TYPEHASH, target, value, recipient, asset, amount)
        );
    }

    /// @inheritdoc IActionAdapter
    function validate(address, uint256, bytes calldata data, bytes32) external view {
        (address recipient, address asset, uint256 amount) = _decode(data);

        // Always reject the zero-address as a recipient regardless of
        // allowlist policy. Burning treasury funds via withdraw(0, ...)
        // is never the intent, and the zero-address is impossible to
        // explicitly add via setRecipientAllowed in any meaningful way
        // (an off-by-default allowlist would still let it slip through
        // when requireRecipientAllowlist is false). Fail closed.
        if (recipient == address(0)) revert ZeroRecipient();

        AssetPolicy memory pol = assetPolicy[asset];
        if (!pol.allowed) revert AssetNotAllowed();
        if (pol.maxAmount > 0 && amount > pol.maxAmount) revert AmountExceedsCap();

        if (requireRecipientAllowlist && !recipientAllowed[recipient]) revert RecipientNotAllowed();
    }

    function _decode(bytes calldata data)
        internal
        pure
        returns (address recipient, address asset, uint256 amount)
    {
        if (data.length != 4 + 32 * 3) revert BadSelector();
        bytes4 selector;
        assembly {
            selector := calldataload(data.offset)
        }
        if (selector != WITHDRAW_SELECTOR) revert BadSelector();
        return abi.decode(data[4:], (address, address, uint256));
    }
}
