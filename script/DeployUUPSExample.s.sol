// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console2} from "forge-std/Script.sol";
import {IntentGuardModule} from "../contracts/IntentGuardModule.sol";
import {UUPSUpgradeAdapter} from "../contracts/UUPSUpgradeAdapter.sol";

/// @notice Worked example: deploy IntentGuardModule + UUPSUpgradeAdapter,
/// initialize a vault for an existing Safe, and register the adapter so
/// future UUPS upgrades on a specific proxy must flow through the
/// queue → cool-off → execute pipeline.
///
/// This is a TEMPLATE. Adapt the constants for your protocol:
///
/// - SAFE: your protocol's existing Safe multisig address
/// - PROXY: the UUPS proxy whose upgrades you want to gate
/// - INITIAL_IMPL: the implementation address you currently trust
///   (its EXTCODEHASH gets registered so any future upgrade to a
///    different implementation address must also be registered)
/// - SIGNERS: the Safe signers who will sign attestations
/// - THRESHOLD / VETO_THRESHOLD: standard multi-sig knobs
///
/// Run with:
///
///     forge script script/DeployUUPSExample.s.sol --rpc-url $RPC --broadcast
contract DeployUUPSExample is Script {
    // ===== Adapt these for your deployment =====
    address constant SAFE = 0x0000000000000000000000000000000000000000;
    address constant PROXY = 0x0000000000000000000000000000000000000000;
    address constant INITIAL_IMPL = 0x0000000000000000000000000000000000000000;
    address constant ADAPTER_OWNER = 0x0000000000000000000000000000000000000000;

    uint8 constant THRESHOLD = 2;
    uint8 constant VETO_THRESHOLD = 2;
    uint64 constant FRESH_WINDOW_SECS = 600;       // 10 minutes
    uint64 constant COOLOFF_SECS = 24 hours;
    uint64 constant EXECUTE_DELAY_SECS = 60;
    uint64 constant MIN_PROPOSAL_LIFETIME_SECS = 24 hours + 1 hours;

    function run() external {
        require(SAFE != address(0), "Set SAFE address before running");
        require(PROXY != address(0), "Set PROXY address before running");
        require(INITIAL_IMPL != address(0), "Set INITIAL_IMPL address before running");
        require(ADAPTER_OWNER != address(0), "Set ADAPTER_OWNER before running");

        bytes32 vaultId = keccak256(abi.encodePacked("vault-uups-", PROXY));

        // Replace this with your real signer set.
        address[] memory signers = new address[](3);
        signers[0] = address(0); // signer 1
        signers[1] = address(0); // signer 2
        signers[2] = address(0); // signer 3

        for (uint256 i = 0; i < signers.length; i++) {
            require(signers[i] != address(0), "Set all signer addresses before running");
        }

        vm.startBroadcast();

        // 1. Deploy the module
        IntentGuardModule module = new IntentGuardModule();
        console2.log("Deployed IntentGuardModule at", address(module));

        // 2. Deploy the UUPS adapter
        UUPSUpgradeAdapter adapter = new UUPSUpgradeAdapter(ADAPTER_OWNER);
        console2.log("Deployed UUPSUpgradeAdapter at", address(adapter));

        // The remaining steps must be performed BY the Safe and BY the adapter
        // owner respectively. They can't be done from a deploy script unless
        // the script's tx.origin is one of those. Logged here as a checklist:

        console2.log("");
        console2.log("Next steps (perform via your Safe / governance flow):");
        console2.log("");
        console2.log("From the Safe:");
        console2.log("  module.initializeVault(");
        console2.logBytes32(vaultId);
        console2.log("    SAFE, signers, ");
        console2.log("    THRESHOLD, VETO_THRESHOLD,");
        console2.log("    FRESH_WINDOW_SECS, COOLOFF_SECS,");
        console2.log("    EXECUTE_DELAY_SECS, MIN_PROPOSAL_LIFETIME_SECS");
        console2.log("  )");
        console2.log("");
        console2.log("  module.setAdapter(vaultId, PROXY, adapter, true)");
        console2.log("");
        console2.log("From the adapter owner:");
        console2.log("  adapter.setProxyAllowed(PROXY, true)");
        console2.log("  adapter.setImplCodehash(PROXY, INITIAL_IMPL, INITIAL_IMPL.codehash)");
        console2.log("");
        console2.log("Then transfer ownership of the proxy to the module address,");
        console2.log("install a Safe Guard that blocks direct UUPS upgrade calls, OR");
        console2.log("update the proxy contract so upgradeToAndCall only accepts");
        console2.log("calls from the module. See upstream README for direct-bypass guidance.");

        vm.stopBroadcast();
    }
}
