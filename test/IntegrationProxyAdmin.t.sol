// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IntegrationBase, AttestPayload} from "./helpers/IntegrationBase.t.sol";
import {IntentGuardModule} from "../contracts/IntentGuardModule.sol";
import {ProxyAdminAdapter} from "../contracts/ProxyAdminAdapter.sol";

/// @notice Mock OZ-style ProxyAdmin target. Records the (proxy, impl)
/// supplied by the upgrade call. Stand-in for OpenZeppelin's
/// ProxyAdmin (4.x and 5.x) — we don't model the real
/// TransparentUpgradeableProxy integration, just the selector surface
/// so we can observe whether the upgrade landed.
contract MockProxyAdmin {
    address public lastProxy;
    address public lastImpl;
    uint256 public callCount;

    function upgrade(address proxy, address impl) external {
        lastProxy = proxy;
        lastImpl = impl;
        callCount += 1;
    }
}

/// @notice Two distinct implementations so we have real distinct codehashes.
contract MockPAImplV2 {
    uint256 public constant VERSION = 2;
}

contract MockPAImplV3 {
    uint256 public constant VERSION = 3;
    function extra() external pure returns (uint256) { return 99; }
}

/// @notice Stand-in proxy address. We don't need real proxy code — the
/// adapter only consults the proxy in the per-(proxyAdmin, proxy)
/// allowlist; nothing on the proxy is invoked at validate or execute time.
contract MockTransparentProxy {
    uint256 public sentinel;
}

/// @notice End-to-end integration: IntentGuardModule + ProxyAdminAdapter
/// + MockSafe + MockProxyAdmin + a tracked proxy. Exercises queue →
/// cool-off → execute, the per-(proxyAdmin, proxy) proxy allowlist, the
/// per-(proxyAdmin, proxy, impl) codehash allowlist, and the codehash
/// mismatch defense (the canonical CREATE2 + SELFDESTRUCT redeploy
/// attack — same as UUPS but flowing through ProxyAdmin instead of
/// directly through the proxy).
contract IntegrationProxyAdminTest is IntegrationBase {
    ProxyAdminAdapter adapter;
    MockProxyAdmin proxyAdmin;
    MockTransparentProxy proxyAllowed;
    MockTransparentProxy proxyUnregistered;
    MockPAImplV2 implV2;
    MockPAImplV3 implV3;

    address adapterOwner = address(0xDEAF);

    function setUp() public {
        _setUpBase();

        proxyAdmin = new MockProxyAdmin();
        proxyAllowed = new MockTransparentProxy();
        proxyUnregistered = new MockTransparentProxy();
        implV2 = new MockPAImplV2();
        implV3 = new MockPAImplV3();
        adapter = new ProxyAdminAdapter(adapterOwner);

        vm.startPrank(adapterOwner);
        adapter.setProxyAllowed(address(proxyAdmin), address(proxyAllowed), true);
        // implV2 registered for proxyAllowed, implV3 deliberately not.
        adapter.setImplCodehash(
            address(proxyAdmin),
            address(proxyAllowed),
            address(implV2),
            address(implV2).codehash
        );
        vm.stopPrank();

        _registerAdapter(address(proxyAdmin), address(adapter));
    }

    function _queueUpgrade(address proxyArg, address implArg)
        internal
        returns (bytes32 proposalId, bytes memory data)
    {
        data = abi.encodeWithSignature("upgrade(address,address)", proxyArg, implArg);
        bytes32 intent = adapter.intentHash(address(proxyAdmin), 0, data);
        AttestPayload memory p = _buildPayload(
            address(proxyAdmin), 0, address(adapter), intent, data,
            uint64(block.timestamp), uint64(block.timestamp) + 200
        );
        uint64 proposalExpiresAt = uint64(block.timestamp) + MIN_PROPOSAL_LIFETIME + 100;

        proposalId = module.queue(
            VAULT_ID, address(proxyAdmin), 0, data, intent, address(adapter),
            proposalExpiresAt, _twoSortedAttestations(p)
        );
    }

    // ============ happy path: registered proxy + impl + matching codehash ============

    function test_endToEnd_registeredUpgradeLands() public {
        (bytes32 proposalId, bytes memory data) = _queueUpgrade(address(proxyAllowed), address(implV2));

        vm.warp(block.timestamp + COOLOFF + EXECUTE_DELAY + 1);
        module.execute(proposalId, data);

        assertEq(proxyAdmin.lastProxy(), address(proxyAllowed));
        assertEq(proxyAdmin.lastImpl(), address(implV2));
        assertEq(proxyAdmin.callCount(), 1);
    }

    // ============ block: unregistered proxy ============

    function test_endToEnd_unregisteredProxyBlockedAtExecute() public {
        // proxyUnregistered was deliberately not registered. The
        // implementation address itself doesn't matter — the proxy
        // gate fires first.
        (bytes32 proposalId, bytes memory data) = _queueUpgrade(address(proxyUnregistered), address(implV2));

        vm.warp(block.timestamp + COOLOFF + EXECUTE_DELAY + 1);

        vm.expectRevert(ProxyAdminAdapter.ProxyNotAllowed.selector);
        module.execute(proposalId, data);

        assertEq(proxyAdmin.callCount(), 0);
    }

    // ============ block: codehash mismatch ============
    //
    // Same as the Beacon and UUPS scenarios: implV2 was registered with
    // its codehash at policy-setup time, but between then and execute
    // the bytecode at that address has changed. We model the redeploy
    // by overwriting implV2's runtime code via vm.etch — same address
    // (still on the impl allowlist) but a fresh codehash that no
    // longer matches the registered expected value. validate() catches
    // it.

    function test_endToEnd_codehashMismatchBlockedAtExecute() public {
        (bytes32 proposalId, bytes memory data) = _queueUpgrade(address(proxyAllowed), address(implV2));

        // Simulate the CREATE2 + SELFDESTRUCT redeploy.
        vm.etch(address(implV2), address(implV3).code);

        vm.warp(block.timestamp + COOLOFF + EXECUTE_DELAY + 1);

        vm.expectRevert(ProxyAdminAdapter.CodehashMismatch.selector);
        module.execute(proposalId, data);

        assertEq(proxyAdmin.callCount(), 0);
        assertEq(proxyAdmin.lastImpl(), address(0));
    }
}
