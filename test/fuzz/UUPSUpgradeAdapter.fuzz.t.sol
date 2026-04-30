// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {UUPSUpgradeAdapter} from "../../contracts/UUPSUpgradeAdapter.sol";

/// @notice Property-style fuzz tests for UUPSUpgradeAdapter.
contract UUPSUpgradeAdapterFuzzTest is Test {
    UUPSUpgradeAdapter adapter;
    address owner = address(0xA11CE);

    function setUp() public {
        adapter = new UUPSUpgradeAdapter(owner);
    }

    function _upgradeToCalldata(address impl) internal pure returns (bytes memory) {
        return abi.encodeWithSignature("upgradeTo(address)", impl);
    }

    function _upgradeToAndCallCalldata(address impl, bytes memory cd) internal pure returns (bytes memory) {
        return abi.encodeWithSignature("upgradeToAndCall(address,bytes)", impl, cd);
    }

    /// @dev Property: intent hash is deterministic over random inputs.
    function testFuzz_intentHash_deterministic(
        address target,
        uint256 value,
        address newImpl
    ) public view {
        bytes memory data = _upgradeToCalldata(newImpl);
        bytes32 a = adapter.intentHash(target, value, data);
        bytes32 b = adapter.intentHash(target, value, data);
        assertEq(a, b);
    }

    /// @dev Property: changing the new-impl changes the intent hash.
    function testFuzz_intentHash_bindsNewImpl(
        address target,
        uint256 value,
        address impl1,
        address impl2
    ) public view {
        vm.assume(impl1 != impl2);
        bytes32 hash1 = adapter.intentHash(target, value, _upgradeToCalldata(impl1));
        bytes32 hash2 = adapter.intentHash(target, value, _upgradeToCalldata(impl2));
        assertTrue(hash1 != hash2);
    }

    /// @dev Property: changing the target changes the intent hash.
    function testFuzz_intentHash_bindsTarget(
        address t1,
        address t2,
        uint256 value,
        address newImpl
    ) public view {
        vm.assume(t1 != t2);
        bytes memory data = _upgradeToCalldata(newImpl);
        bytes32 hash1 = adapter.intentHash(t1, value, data);
        bytes32 hash2 = adapter.intentHash(t2, value, data);
        assertTrue(hash1 != hash2);
    }

    /// @dev Property: changing the upgradeToAndCall callData changes the intent hash.
    function testFuzz_intentHash_bindsCallData(
        address target,
        address newImpl,
        bytes calldata cd1,
        bytes calldata cd2
    ) public view {
        vm.assume(keccak256(cd1) != keccak256(cd2));
        bytes32 hash1 = adapter.intentHash(target, 0, _upgradeToAndCallCalldata(newImpl, cd1));
        bytes32 hash2 = adapter.intentHash(target, 0, _upgradeToAndCallCalldata(newImpl, cd2));
        assertTrue(hash1 != hash2);
    }

    /// @dev Property: validate reverts on any unregistered (target, impl) pair.
    function testFuzz_validate_revertsOnUnregistered(
        address target,
        uint256 value,
        address newImpl
    ) public {
        // No policy registered for (target, newImpl) → revert (either
        // ProxyNotAllowed or ImplNotAllowed depending on which check
        // fires first).
        bytes memory data = _upgradeToCalldata(newImpl);
        vm.expectRevert();
        adapter.validate(target, value, data, bytes32(0));
    }
}
