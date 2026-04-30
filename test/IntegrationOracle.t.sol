// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IntegrationBase, AttestPayload} from "./helpers/IntegrationBase.t.sol";
import {IntentGuardModule} from "../contracts/IntentGuardModule.sol";
import {OracleSourceAdapter} from "../contracts/OracleSourceAdapter.sol";

/// @notice Mock oracle-aware target. Records the oracle assigned per asset.
/// Stand-in for any contract with `setOracle(address asset, address oracle)`
/// (Aave-style price oracle setters, Compound oracle migrations, Morpho
/// oracle aggregators, etc).
contract MockOracleConsumer {
    mapping(address => address) public oracleFor;
    uint256 public callCount;

    function setOracle(address asset, address oracle) external {
        oracleFor[asset] = oracle;
        callCount += 1;
    }
}

/// @notice End-to-end integration: IntentGuardModule + OracleSourceAdapter
/// + MockSafe + MockOracleConsumer. Exercises the per-(target, asset, oracle)
/// allowlist over the full queue → cool-off → execute pipeline.
///
/// The "attacker-oracle defense" scenario is the load-bearing one: signers
/// are tricked (social engineering, malicious frontend, prompt injection
/// in a co-signing service) into approving setOracle(asset, ATTACKER).
/// Since the (target, asset, attackerOracle) tuple is not on the allowlist,
/// validate() reverts at execute time — the policy is the last line of
/// defense after signer approval has already been compromised.
contract IntegrationOracleTest is IntegrationBase {
    OracleSourceAdapter adapter;
    MockOracleConsumer consumer;

    address adapterOwner = address(0xDEAF);

    address constant ASSET = address(0xA55E1);
    address constant LEGIT_ORACLE = address(0x0FACADE);
    address constant FALLBACK_ORACLE = address(0xFA11BAC);
    address constant ATTACKER_ORACLE = address(0xBADBAD);

    function setUp() public {
        _setUpBase();

        consumer = new MockOracleConsumer();
        adapter = new OracleSourceAdapter(adapterOwner);

        // Two oracles registered (primary + fallback), one attacker oracle
        // intentionally NOT registered.
        vm.startPrank(adapterOwner);
        adapter.setOracleAllowed(address(consumer), ASSET, LEGIT_ORACLE, true);
        adapter.setOracleAllowed(address(consumer), ASSET, FALLBACK_ORACLE, true);
        vm.stopPrank();

        _registerAdapter(address(consumer), address(adapter));
    }

    function _queueOracle(address asset, address oracle)
        internal
        returns (bytes32 proposalId, bytes memory data)
    {
        data = abi.encodeWithSignature("setOracle(address,address)", asset, oracle);
        bytes32 intent = adapter.intentHash(address(consumer), 0, data);
        AttestPayload memory p = _buildPayload(
            address(consumer), 0, address(adapter), intent, data,
            uint64(block.timestamp), uint64(block.timestamp) + 200
        );
        uint64 proposalExpiresAt = uint64(block.timestamp) + MIN_PROPOSAL_LIFETIME + 100;

        proposalId = module.queue(
            VAULT_ID, address(consumer), 0, data, intent, address(adapter),
            proposalExpiresAt, _twoSortedAttestations(p)
        );
    }

    // ============ happy path: registered (target, asset, oracle) ============

    function test_endToEnd_registeredOracleLands() public {
        (bytes32 proposalId, bytes memory data) = _queueOracle(ASSET, LEGIT_ORACLE);

        vm.warp(block.timestamp + COOLOFF + EXECUTE_DELAY + 1);
        module.execute(proposalId, data);

        assertEq(consumer.oracleFor(ASSET), LEGIT_ORACLE);
        assertEq(consumer.callCount(), 1);
    }

    // ============ block: unregistered oracle for a known asset ============

    function test_endToEnd_unregisteredOracleBlockedAtExecute() public {
        // Asset is registered (with two valid oracles), but this oracle
        // address is not on the (target, asset, *) allowlist.
        address unregistered = address(0xC0FFEE);
        (bytes32 proposalId, bytes memory data) = _queueOracle(ASSET, unregistered);

        vm.warp(block.timestamp + COOLOFF + EXECUTE_DELAY + 1);

        vm.expectRevert(OracleSourceAdapter.OracleNotAllowed.selector);
        module.execute(proposalId, data);

        assertEq(consumer.callCount(), 0);
        assertEq(consumer.oracleFor(ASSET), address(0));
    }

    // ============ defense: signers tricked into approving an attacker oracle ============
    //
    // This is the threat scenario the adapter exists for. The signers'
    // attestations are perfectly valid — same vault, same target, same
    // adapter, same intent hash, fresh signatures, two of three present
    // and sorted. Everything required to queue the proposal succeeds.
    //
    // The defense is not at queue time. It's at execute time, when
    // validate() consults the on-chain allowlist that was set up by the
    // adapter owner under different (slower, scrutinized, multi-eyed)
    // conditions than the live signer flow. The allowlist catches what
    // the signer set could not.

    function test_endToEnd_attackerOracleDefenseBlocksAtExecute() public {
        (bytes32 proposalId, bytes memory data) = _queueOracle(ASSET, ATTACKER_ORACLE);

        // Cool-off elapses normally — the attack passed signer review and
        // sat through the timelock. The only thing that saves the
        // protocol is the validate() check at execute time.
        vm.warp(block.timestamp + COOLOFF + EXECUTE_DELAY + 1);

        vm.expectRevert(OracleSourceAdapter.OracleNotAllowed.selector);
        module.execute(proposalId, data);

        // Belt-and-braces: the legitimate oracle wasn't already in place,
        // and the attacker oracle never got installed.
        assertEq(consumer.callCount(), 0);
        assertEq(consumer.oracleFor(ASSET), address(0));

        // After the attack is blocked, the legitimate oracle path still
        // works — the policy is a filter, not a freeze. (We re-queue;
        // the failed attempt did not consume the vault nonce since
        // queue succeeded then execute reverted, leaving the proposal
        // in place. We can't re-execute the same proposal — module
        // semantics — so we issue a fresh proposal with the legit oracle.)
        (bytes32 legitId, bytes memory legitData) = _queueOracle(ASSET, LEGIT_ORACLE);
        vm.warp(block.timestamp + COOLOFF + EXECUTE_DELAY + 1);
        module.execute(legitId, legitData);
        assertEq(consumer.oracleFor(ASSET), LEGIT_ORACLE);
        assertEq(consumer.callCount(), 1);
    }
}
