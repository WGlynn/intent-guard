// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {UUPSUpgradeAdapter} from "../../contracts/UUPSUpgradeAdapter.sol";

/// @notice Property-style fuzz tests for UUPSUpgradeAdapter.
///
/// After the Cerron PR #2 fix, intentHash() reads the registered
/// expectedCodehash from policy and binds it into the returned hash.
/// That means intentHash() now reverts for unallowed proxies and
/// unregistered impls — the helper `_register()` here primes policy
/// with a deterministic codehash so the fuzzed inputs can produce a
/// valid hash.
contract UUPSUpgradeAdapterFuzzTest is Test {
    UUPSUpgradeAdapter adapter;
    address owner = address(0xA11CE);

    // Sentinel codehashes registered for any (proxy, impl) the fuzzers
    // need a valid hash for. Distinct from zero (which means
    // "unregistered") and any plausible real EXTCODEHASH.
    bytes32 constant FAKE_CODEHASH_A = keccak256("fuzz-codehash-A");
    bytes32 constant FAKE_CODEHASH_B = keccak256("fuzz-codehash-B");

    function setUp() public {
        adapter = new UUPSUpgradeAdapter(owner);
    }

    // ============ helpers ============

    function _upgradeToCalldata(address impl) internal pure returns (bytes memory) {
        return abi.encodeWithSignature("upgradeTo(address)", impl);
    }

    function _upgradeToAndCallCalldata(address impl, bytes memory cd) internal pure returns (bytes memory) {
        return abi.encodeWithSignature("upgradeToAndCall(address,bytes)", impl, cd);
    }

    /// @dev Register `(proxy, impl)` with a non-zero codehash so that
    /// intentHash() will not revert. Uses vm.etch to ensure the impl
    /// has non-empty code (required by setImplCodehash for non-zero
    /// codehash registration).
    function _register(address proxy, address impl, bytes32 codehash) internal {
        // Ensure impl has at least 1 byte of code so setImplCodehash
        // does not revert with EmptyCodeImpl.
        if (impl.code.length == 0) {
            vm.etch(impl, hex"00");
        }
        vm.startPrank(owner);
        adapter.setProxyAllowed(proxy, true);
        adapter.setImplCodehash(proxy, impl, codehash);
        vm.stopPrank();
    }

    // ============ fuzz: intentHash properties ============

    /// @dev Property: intent hash is deterministic over random inputs.
    function testFuzz_intentHash_deterministic(
        address target,
        uint256 value,
        address newImpl
    ) public {
        // Skip cheatcode-reserved precompile addresses.
        vm.assume(target > address(0x100));
        vm.assume(newImpl > address(0x100));
        vm.assume(target != newImpl);

        _register(target, newImpl, FAKE_CODEHASH_A);

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
    ) public {
        vm.assume(impl1 != impl2);
        vm.assume(target > address(0x100));
        vm.assume(impl1 > address(0x100));
        vm.assume(impl2 > address(0x100));
        vm.assume(target != impl1 && target != impl2);

        _register(target, impl1, FAKE_CODEHASH_A);
        _register(target, impl2, FAKE_CODEHASH_A);

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
    ) public {
        vm.assume(t1 != t2);
        vm.assume(t1 > address(0x100));
        vm.assume(t2 > address(0x100));
        vm.assume(newImpl > address(0x100));
        vm.assume(t1 != newImpl && t2 != newImpl);

        _register(t1, newImpl, FAKE_CODEHASH_A);
        _register(t2, newImpl, FAKE_CODEHASH_A);

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
    ) public {
        vm.assume(keccak256(cd1) != keccak256(cd2));
        vm.assume(target > address(0x100));
        vm.assume(newImpl > address(0x100));
        vm.assume(target != newImpl);

        _register(target, newImpl, FAKE_CODEHASH_A);

        bytes32 hash1 = adapter.intentHash(target, 0, _upgradeToAndCallCalldata(newImpl, cd1));
        bytes32 hash2 = adapter.intentHash(target, 0, _upgradeToAndCallCalldata(newImpl, cd2));
        assertTrue(hash1 != hash2);
    }

    /// @dev Property (Cerron PR #2 fix): changing the registered codehash
    /// for an otherwise-identical (target, value, impl, callDataHash) MUST
    /// change the intent hash. This is the binding property that closes
    /// the policy-substitution attack.
    function testFuzz_intentHash_bindsCodehash(
        address target,
        uint256 value,
        address newImpl
    ) public {
        vm.assume(target > address(0x100));
        vm.assume(newImpl > address(0x100));
        vm.assume(target != newImpl);

        bytes memory data = _upgradeToCalldata(newImpl);

        _register(target, newImpl, FAKE_CODEHASH_A);
        bytes32 hashA = adapter.intentHash(target, value, data);

        // Re-register with a different codehash — same proxy, same impl,
        // same calldata. The intent hash MUST change.
        vm.prank(owner);
        adapter.setImplCodehash(target, newImpl, FAKE_CODEHASH_B);

        bytes32 hashB = adapter.intentHash(target, value, data);
        assertTrue(hashA != hashB);
    }

    // ============ fuzz: failure-mode properties ============

    /// @dev Property (Cerron PR #2 fix): intentHash() fails closed for
    /// any unregistered (target, impl) pair.
    function testFuzz_intentHash_revertsOnUnregistered(
        address target,
        uint256 value,
        address newImpl
    ) public {
        bytes memory data = _upgradeToCalldata(newImpl);
        vm.expectRevert();
        adapter.intentHash(target, value, data);
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
