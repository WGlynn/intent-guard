#!/usr/bin/env node
/**
 * intentguard signer CLI sketch.
 *
 * This file shows the signer UX: fetch a proposal, render the decoded intent,
 * compare oracle-bound claims, require explicit human confirmation, then sign.
 *
 * Production deployments must replace fetchProposal() and signProposal() with
 * real chain clients and a hardware wallet, KMS, or separate attester device.
 */

import { createInterface } from "node:readline/promises";
import { stdin, stdout } from "node:process";

interface Proposal {
  id: string;
  vault: string;
  actionKindName: string;
  decoded: Record<string, unknown>;
  oracle?: string;
  claimedValueE8?: string;
  liveValueE8?: string;
  oracleStaleSeconds?: number;
  intentHash: string;
  nonce: string;
  expiresAt: string;
}

async function main(): Promise<void> {
  const [, , cmd, chain, vault, proposalId] = process.argv;
  if (cmd !== "review" || !chain || !vault || !proposalId) {
    console.error("usage: signer-cli review <ethereum|solana> <vault> <proposal-id>");
    process.exit(2);
  }

  const proposal = await fetchProposal(chain, vault, proposalId);
  printProposal(proposal);
  printOracleWarning(proposal);

  const expected = proposal.actionKindName.toUpperCase();
  const rl = createInterface({ input: stdin, output: stdout });
  const answer = await rl.question(`\nType "${expected}" exactly to sign, or anything else to abort: `);
  rl.close();

  if (answer.trim() !== expected) {
    console.log("aborted. no signature produced.");
    return;
  }

  const signedAt = Math.floor(Date.now() / 1000);
  const signature = await signProposal(proposal.intentHash, signedAt);
  console.log("\nsignature:", signature);
  console.log("signed_at:", signedAt);
}

async function fetchProposal(_chain: string, _vault: string, _id: string): Promise<Proposal> {
  return {
    id: _id,
    vault: _vault,
    actionKindName: "WhitelistCollateral",
    decoded: {
      token: "CVT",
      fair_value_usd: "1.00",
      max_deposit_usd: "500000000",
      target: "RiskManager",
    },
    oracle: "Chainlink/CVT-USD",
    claimedValueE8: "100000000",
    liveValueE8: "10000",
    oracleStaleSeconds: 5,
    intentHash: "0x" + "ab".repeat(32),
    nonce: "12",
    expiresAt: "2026-04-30T18:00:00Z",
  };
}

async function signProposal(_intentHash: string, _signedAt: number): Promise<string> {
  return "<replace-with-real-signature>";
}

function printProposal(p: Proposal): void {
  console.log("");
  console.log("============================================================");
  console.log("  INTENTGUARD SIGNER REVIEW");
  console.log("============================================================");
  console.log(`vault:       ${p.vault}`);
  console.log(`proposal:    ${p.id}`);
  console.log(`nonce:       ${p.nonce}`);
  console.log(`action:      ${p.actionKindName}`);
  console.log(`expires:     ${p.expiresAt}`);
  console.log(`intentHash:  ${p.intentHash}`);
  console.log("");
  console.log("decoded intent:");
  for (const [key, value] of Object.entries(p.decoded)) {
    console.log(`  ${key.padEnd(20)} ${String(value)}`);
  }
}

function printOracleWarning(p: Proposal): void {
  if (!p.oracle || !p.claimedValueE8 || !p.liveValueE8) return;

  const claimed = BigInt(p.claimedValueE8);
  const live = BigInt(p.liveValueE8);
  const diff = claimed > live ? claimed - live : live - claimed;
  const bps = Number((diff * 10_000n) / claimed);

  console.log("");
  console.log("oracle-bound claim:");
  console.log(`  oracle:       ${p.oracle}`);
  console.log(`  claimed E8:   ${p.claimedValueE8}`);
  console.log(`  live E8:      ${p.liveValueE8}`);
  console.log(`  staleness:    ${p.oracleStaleSeconds ?? "unknown"}s`);

  if (bps > 200) {
    console.log("");
    console.log(`WARNING: claim deviates from oracle by ${bps} bps (>200).`);
    console.log("Do not sign unless this is expected and independently verified.");
  }
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
