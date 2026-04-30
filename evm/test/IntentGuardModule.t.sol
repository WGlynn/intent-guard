// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "../src/IntentGuardModule.sol";

/// @notice Smoke-test scaffolding for the Foundry layout.
/// @dev This file intentionally avoids external Safe dependencies. Add protocol-
/// specific tests before any deployment.
contract IntentGuardModuleSmokeTest {
    function testTypehashExists() public pure {
        bytes32 expected = keccak256(
            "IntentGuardAttestation(bytes32 vaultId,uint64 nonce,address target,uint256 value,bytes32 dataHash,bytes32 intentHash,address adapter,uint64 signedAt,uint64 expiresAt,uint256 chainId,address module)"
        );
        require(IntentGuardModule.ATTESTATION_TYPEHASH() == expected, "bad typehash");
    }
}
