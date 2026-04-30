// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IActionAdapter} from "./IntentGuardModule.sol";

/// @notice Adapter for OpenZeppelin AccessControl role administration:
///
///     grantRole(bytes32 role, address account)
///     revokeRole(bytes32 role, address account)
///
/// Role administration is the most common privilege-escalation path in
/// AccessControl-based protocols: an attacker who can quietly grant a
/// privileged role to an attacker-controlled account doesn't need to
/// touch implementation contracts at all — the protocol's own
/// access-checked functions become the attack surface.
///
/// The adapter binds (action, role, account) into the typed intent and
/// at execute time enforces per-(target, role) policy:
///
///   - Each (target, role) pair must be on the adapter's allowlist;
///     unknown roles fail closed
///   - Per-(target, role) optional account allowlist for grants — if
///     non-empty, only allowlisted accounts can be granted that role
///   - Per-(target, role) "frozen" flag — when true, neither grant nor
///     revoke can pass validate, locking the role's membership
///
/// Use the frozen flag for roles that should never change post-launch
/// (e.g. a role intentionally set to a multisig and meant to stay there).
contract RoleGrantAdapter is IActionAdapter {
    bytes4 public constant GRANT_ROLE_SELECTOR = bytes4(keccak256("grantRole(bytes32,address)"));
    bytes4 public constant REVOKE_ROLE_SELECTOR = bytes4(keccak256("revokeRole(bytes32,address)"));

    bytes32 public constant GRANT_INTENT_TYPEHASH = keccak256(
        "RoleGrant(address target,uint256 value,bytes32 role,address account)"
    );
    bytes32 public constant REVOKE_INTENT_TYPEHASH = keccak256(
        "RoleRevoke(address target,uint256 value,bytes32 role,address account)"
    );

    enum Action {
        Grant,
        Revoke
    }

    struct RolePolicy {
        bool roleAllowed;
        bool frozen;
        // If true, only accounts in `allowedAccounts` can be granted this role.
        // If false, any account in the signed intent passes (account ⇐ signers).
        bool useAccountAllowlist;
    }

    address public immutable owner;
    // rolePolicy[target][role]
    mapping(address => mapping(bytes32 => RolePolicy)) public rolePolicy;
    // allowedAccounts[target][role][account]
    mapping(address => mapping(bytes32 => mapping(address => bool))) public allowedAccounts;

    event RolePolicySet(address indexed target, bytes32 indexed role, bool allowed, bool frozen, bool useAllowlist);
    event AllowedAccountSet(address indexed target, bytes32 indexed role, address indexed account, bool allowed);

    error NotOwner();
    error BadSelector();
    error RoleNotAllowed();
    error RoleFrozen();
    error AccountNotAllowed();
    error ZeroOwner();

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    constructor(address owner_) {
        if (owner_ == address(0)) revert ZeroOwner();
        owner = owner_;
    }

    function setRolePolicy(
        address target,
        bytes32 role,
        bool allowed,
        bool frozen,
        bool useAllowlist
    ) external onlyOwner {
        rolePolicy[target][role] = RolePolicy({
            roleAllowed: allowed,
            frozen: frozen,
            useAccountAllowlist: useAllowlist
        });
        emit RolePolicySet(target, role, allowed, frozen, useAllowlist);
    }

    function setAllowedAccount(address target, bytes32 role, address account, bool allowed) external onlyOwner {
        allowedAccounts[target][role][account] = allowed;
        emit AllowedAccountSet(target, role, account, allowed);
    }

    /// @inheritdoc IActionAdapter
    function intentHash(address target, uint256 value, bytes calldata data) external pure returns (bytes32) {
        (Action action, bytes32 role, address account) = _decode(data);
        bytes32 typehash = action == Action.Grant ? GRANT_INTENT_TYPEHASH : REVOKE_INTENT_TYPEHASH;
        return keccak256(abi.encode(typehash, target, value, role, account));
    }

    /// @inheritdoc IActionAdapter
    function validate(address target, uint256, bytes calldata data, bytes32) external view {
        (Action action, bytes32 role, address account) = _decode(data);

        RolePolicy memory pol = rolePolicy[target][role];
        if (!pol.roleAllowed) revert RoleNotAllowed();
        if (pol.frozen) revert RoleFrozen();

        // Account allowlist applies only to grants — revokes don't add
        // membership, so the allowlist isn't relevant for revokes.
        if (action == Action.Grant && pol.useAccountAllowlist && !allowedAccounts[target][role][account]) {
            revert AccountNotAllowed();
        }
    }

    function _decode(bytes calldata data)
        internal
        pure
        returns (Action action, bytes32 role, address account)
    {
        if (data.length != 4 + 32 * 2) revert BadSelector();
        bytes4 selector;
        assembly {
            selector := calldataload(data.offset)
        }
        if (selector == GRANT_ROLE_SELECTOR) {
            action = Action.Grant;
        } else if (selector == REVOKE_ROLE_SELECTOR) {
            action = Action.Revoke;
        } else {
            revert BadSelector();
        }
        (role, account) = abi.decode(data[4:], (bytes32, address));
    }
}
