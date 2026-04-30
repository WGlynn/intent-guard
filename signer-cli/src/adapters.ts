import {
  encodeAbiParameters,
  keccak256,
  parseAbiParameters,
  stringToBytes,
  type Hex,
} from "viem";

// ============ UUPSUpgradeAdapter ============

export type UUPSUpgradeIntent = {
  target: Hex;
  value: bigint;
  newImplementation: Hex;
  callDataHash: Hex;
};

export function uupsUpgradeIntentHash(intent: UUPSUpgradeIntent): Hex {
  return keccak256(
    encodeAbiParameters(
      parseAbiParameters(
        "bytes32 typeHash, address target, uint256 value, address newImplementation, bytes32 callDataHash",
      ),
      [
        keccak256(
          stringToBytes(
            "UUPSUpgrade(address target,uint256 value,address newImplementation,bytes32 callDataHash)",
          ),
        ),
        intent.target,
        intent.value,
        intent.newImplementation,
        intent.callDataHash,
      ],
    ),
  );
}

// ============ DAOTreasuryAdapter ============

export type DAOTreasuryWithdrawIntent = {
  target: Hex;
  value: bigint;
  recipient: Hex;
  asset: Hex;
  amount: bigint;
};

export function daoTreasuryWithdrawIntentHash(intent: DAOTreasuryWithdrawIntent): Hex {
  return keccak256(
    encodeAbiParameters(
      parseAbiParameters(
        "bytes32 typeHash, address target, uint256 value, address recipient, address asset, uint256 amount",
      ),
      [
        keccak256(
          stringToBytes(
            "DAOTreasuryWithdraw(address target,uint256 value,address recipient,address asset,uint256 amount)",
          ),
        ),
        intent.target,
        intent.value,
        intent.recipient,
        intent.asset,
        intent.amount,
      ],
    ),
  );
}

// ============ CrossChainPeerAdapter ============

export type LayerZeroSetPeerIntent = {
  target: Hex;
  value: bigint;
  eid: number;
  peer: Hex;
};

export function layerZeroSetPeerIntentHash(intent: LayerZeroSetPeerIntent): Hex {
  return keccak256(
    encodeAbiParameters(
      parseAbiParameters(
        "bytes32 typeHash, address target, uint256 value, uint32 eid, bytes32 peer",
      ),
      [
        keccak256(
          stringToBytes("LayerZeroSetPeer(address target,uint256 value,uint32 eid,bytes32 peer)"),
        ),
        intent.target,
        intent.value,
        intent.eid,
        intent.peer,
      ],
    ),
  );
}

// ============ RoleGrantAdapter ============

export type RoleGrantIntent = {
  target: Hex;
  value: bigint;
  role: Hex;
  account: Hex;
};

export function roleGrantIntentHash(intent: RoleGrantIntent): Hex {
  return keccak256(
    encodeAbiParameters(
      parseAbiParameters(
        "bytes32 typeHash, address target, uint256 value, bytes32 role, address account",
      ),
      [
        keccak256(stringToBytes("RoleGrant(address target,uint256 value,bytes32 role,address account)")),
        intent.target,
        intent.value,
        intent.role,
        intent.account,
      ],
    ),
  );
}

export function roleRevokeIntentHash(intent: RoleGrantIntent): Hex {
  return keccak256(
    encodeAbiParameters(
      parseAbiParameters(
        "bytes32 typeHash, address target, uint256 value, bytes32 role, address account",
      ),
      [
        keccak256(stringToBytes("RoleRevoke(address target,uint256 value,bytes32 role,address account)")),
        intent.target,
        intent.value,
        intent.role,
        intent.account,
      ],
    ),
  );
}

// ============ PausableAdapter ============

export type PausableActionIntent = {
  target: Hex;
  value: bigint;
  selector: Hex; // 4-byte selector for pause() or unpause()
};

export function pausableActionIntentHash(intent: PausableActionIntent): Hex {
  return keccak256(
    encodeAbiParameters(
      parseAbiParameters("bytes32 typeHash, address target, uint256 value, bytes4 selector"),
      [
        keccak256(stringToBytes("PausableAction(address target,uint256 value,bytes4 selector)")),
        intent.target,
        intent.value,
        intent.selector,
      ],
    ),
  );
}

// ============ OwnershipTransferAdapter ============

export type OwnershipTransferIntent = {
  target: Hex;
  value: bigint;
  newOwner: Hex;
};

export function ownershipTransferIntentHash(intent: OwnershipTransferIntent): Hex {
  return keccak256(
    encodeAbiParameters(
      parseAbiParameters("bytes32 typeHash, address target, uint256 value, address newOwner"),
      [
        keccak256(stringToBytes("OwnershipTransfer(address target,uint256 value,address newOwner)")),
        intent.target,
        intent.value,
        intent.newOwner,
      ],
    ),
  );
}

export function ownershipRenounceIntentHash(target: Hex, value: bigint): Hex {
  return keccak256(
    encodeAbiParameters(parseAbiParameters("bytes32 typeHash, address target, uint256 value"), [
      keccak256(stringToBytes("OwnershipRenounce(address target,uint256 value)")),
      target,
      value,
    ]),
  );
}

// ============ BoundedParameterAdapter ============

export type BoundedParamIntent = {
  target: Hex;
  value: bigint;
  key: Hex;
  newValue: bigint;
};

export function boundedParamIntentHash(intent: BoundedParamIntent): Hex {
  return keccak256(
    encodeAbiParameters(
      parseAbiParameters(
        "bytes32 typeHash, address target, uint256 value, bytes32 key, uint256 newValue",
      ),
      [
        keccak256(stringToBytes("BoundedParam(address target,uint256 value,bytes32 key,uint256 newValue)")),
        intent.target,
        intent.value,
        intent.key,
        intent.newValue,
      ],
    ),
  );
}

// ============ MerkleRootSetAdapter ============

export type MerkleRootSetIntent = {
  target: Hex;
  value: bigint;
  root: Hex;
};

export function merkleRootSetIntentHash(intent: MerkleRootSetIntent): Hex {
  return keccak256(
    encodeAbiParameters(
      parseAbiParameters("bytes32 typeHash, address target, uint256 value, bytes32 root"),
      [
        keccak256(stringToBytes("MerkleRootSet(address target,uint256 value,bytes32 root)")),
        intent.target,
        intent.value,
        intent.root,
      ],
    ),
  );
}
