// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {DAOTreasuryAdapter} from "../../contracts/DAOTreasuryAdapter.sol";

contract DAOTreasuryAdapterFuzzTest is Test {
    DAOTreasuryAdapter adapter;
    address owner = address(0xA11CE);
    address treasury = address(0xCAFE);
    address asset = address(0xDEAD);
    uint256 constant CAP = 1e24;

    function setUp() public {
        adapter = new DAOTreasuryAdapter(owner);
        vm.prank(owner);
        adapter.setAssetPolicy(asset, true, CAP);
    }

    function _withdraw(address r, address a, uint256 amt) internal pure returns (bytes memory) {
        return abi.encodeWithSignature("withdraw(address,address,uint256)", r, a, amt);
    }

    function testFuzz_intentHash_deterministic(address recipient, uint256 amount) public view {
        bytes memory data = _withdraw(recipient, asset, amount);
        bytes32 a = adapter.intentHash(treasury, 0, data);
        bytes32 b = adapter.intentHash(treasury, 0, data);
        assertEq(a, b);
    }

    function testFuzz_intentHash_bindsRecipient(address r1, address r2, uint256 amount) public view {
        vm.assume(r1 != r2);
        bytes32 a = adapter.intentHash(treasury, 0, _withdraw(r1, asset, amount));
        bytes32 b = adapter.intentHash(treasury, 0, _withdraw(r2, asset, amount));
        assertTrue(a != b);
    }

    function testFuzz_intentHash_bindsAmount(address recipient, uint256 a1, uint256 a2) public view {
        vm.assume(a1 != a2);
        bytes32 h1 = adapter.intentHash(treasury, 0, _withdraw(recipient, asset, a1));
        bytes32 h2 = adapter.intentHash(treasury, 0, _withdraw(recipient, asset, a2));
        assertTrue(h1 != h2);
    }

    function testFuzz_validate_belowCapPasses(address recipient, uint256 amount) public view {
        amount = bound(amount, 0, CAP);
        bytes memory data = _withdraw(recipient, asset, amount);
        adapter.validate(treasury, 0, data, bytes32(0));
    }

    function testFuzz_validate_aboveCapReverts(address recipient, uint256 amount) public {
        amount = bound(amount, CAP + 1, type(uint128).max);
        bytes memory data = _withdraw(recipient, asset, amount);
        vm.expectRevert(DAOTreasuryAdapter.AmountExceedsCap.selector);
        adapter.validate(treasury, 0, data, bytes32(0));
    }

    function testFuzz_validate_unregisteredAssetReverts(address recipient, address randomAsset, uint256 amount)
        public
    {
        vm.assume(randomAsset != asset);
        amount = bound(amount, 0, CAP);
        bytes memory data = _withdraw(recipient, randomAsset, amount);
        vm.expectRevert(DAOTreasuryAdapter.AssetNotAllowed.selector);
        adapter.validate(treasury, 0, data, bytes32(0));
    }
}
