---
title: Playground
description: Try the intentguard attester live in your browser. See what the device would render, what the canonical intent hash is, and what digest the attester would sign. No install, no hardware.
hero_label: Playground
hero_title: See what the attester sees.
hero_subtitle: Pick a sample scenario or paste your own intent payload. The browser computes the canonical hash, simulates the on-device renderer, and shows the exact digest the attester would sign. Zero install.
---

This page runs the same canonical renderer the firmware and host bridge use. The decode and hash logic is identical, so the byte-level output you see here is the byte-level output a real attester device would produce. The only thing missing is the device screen and the human pressing CONFIRM.

Pick a scenario below, or edit the form fields directly to construct your own.

<div class="pg-scenarios">
  <button class="pg-chip" data-scenario="drift">Replay the Drift attack</button>
  <button class="pg-chip" data-scenario="routineUsdc">Routine USDC listing</button>
  <button class="pg-chip" data-scenario="badAdmin">Admin transfer to attacker</button>
  <button class="pg-chip" data-scenario="routineAdmin">Routine admin rotation</button>
</div>

<div class="pg-grid">

  <div class="pg-panel">
    <h3 class="pg-panel-title">Inputs</h3>
    <label class="pg-label">Network<select id="pg-network">
      <option value="solana">Solana (SHA-256)</option>
      <option value="evm">EVM (Keccak-256)</option>
    </select></label>
    <label class="pg-label">Vault (hex)<input id="pg-vault" placeholder="0x..." spellcheck="false"></label>
    <label class="pg-label">Nonce<input id="pg-nonce" type="number" min="0" placeholder="0"></label>
    <label class="pg-label">Action kind<select id="pg-action-kind">
      <option value="1">1 · WHITELIST_COLLATERAL</option>
      <option value="3">3 · TRANSFER_ADMIN</option>
    </select></label>
    <label class="pg-label">action_args (hex)<textarea id="pg-action-args" rows="6" placeholder="0x..." spellcheck="false"></textarea></label>
    <label class="pg-label">signed_at (unix seconds)<input id="pg-signed-at" type="number" min="0" placeholder="auto"></label>
    <div class="pg-error" id="pg-error" role="alert"></div>
  </div>

  <div class="pg-panel">
    <h3 class="pg-panel-title">What the device shows</h3>
    <div class="pg-device">
      <div class="pg-device-frame">
        <div class="pg-device-screen" id="pg-device-screen"></div>
      </div>
      <div class="pg-device-caption">simulated 240×135 IPS, JetBrains Mono</div>
    </div>

    <h3 class="pg-panel-title pg-panel-title--gap">Canonical bytes</h3>
    <pre class="pg-hex" id="pg-canonical"></pre>

    <h3 class="pg-panel-title pg-panel-title--gap">Intent hash</h3>
    <pre class="pg-hex" id="pg-intent-hash"></pre>

    <h3 class="pg-panel-title pg-panel-title--gap">Digest the attester signs</h3>
    <pre class="pg-hex" id="pg-attest-digest"></pre>
  </div>

</div>

## What just happened

Four things, all client-side, all matching the firmware byte-for-byte:

1. **Decoded** the raw `action_args` hex into a structured intent using the registered adapter for that `action_kind`. Unknown kinds fail closed.
2. **Canonicalised** the structured intent into a deterministic byte sequence (sorted-key, length-prefixed, type-tagged). The firmware does the same on its own CPU.
3. **Computed the intent hash** as `H(domain_sep || vault || u64_le(nonce) || u32_le(action_kind) || canonical)`. SHA-256 for Solana, Keccak-256 for EVM. This is the value the on-chain guard recomputes from the actual call and compares against what the signers approved.
4. **Computed the attest digest** as `H(domain_sep || vault || u64_le(nonce) || u32_le(action_kind) || intent_hash || u64_le(signed_at))`. This is what the attester device's signing key actually signs. The on-chain guard verifies the same digest against the device's enrolled pubkey.

If a malicious laptop swapped the `action_args` between rendering and signing, the recomputed intent hash would not match the bound hash and the action would not execute. That is the entire point of the primitive.

## Try the Drift scenario

Click "Replay the Drift attack" above. The screen shows what a Drift Council member would have seen on their attester device the day of the attack: a `WHITELIST_COLLATERAL` action whitelisting a token they had no reason to trust, at a fair value of $1.00, with a $500M deposit cap. Compare that screen to the routine USDC listing scenario right next to it. Same action kind, same shape of payload. The difference is in the fields. The point of putting the rendered intent on a separate trust domain is that a human gets a chance to see that difference.

## Read

- [Whitepaper](intentguard.html)
- [Attester specification](attester/SPEC.md)
- [Source code on GitHub](https://github.com/uwecerron/intent-guard)

<style>
  /* Widen the content area for the playground without touching the global layout. */
  .content-inner { max-width: 1100px; }

  .pg-scenarios {
    display: flex;
    flex-wrap: wrap;
    gap: 10px;
    margin: 32px 0 40px;
  }
  .pg-chip {
    appearance: none;
    border: 1px solid var(--border-strong);
    background: transparent;
    color: var(--text);
    padding: 10px 18px;
    font-family: 'Inter', sans-serif;
    font-size: 12px;
    font-weight: 500;
    letter-spacing: 0.12em;
    text-transform: uppercase;
    cursor: pointer;
    transition: all 0.25s cubic-bezier(0.4, 0, 0.2, 1);
  }
  .pg-chip:hover { border-color: var(--accent); color: var(--accent); }
  .pg-chip.is-active { background: var(--accent); border-color: var(--accent); color: #fff; }

  .pg-grid {
    display: grid;
    grid-template-columns: 1fr 1.05fr;
    gap: 36px;
    margin: 0 0 64px;
  }
  @media (max-width: 920px) {
    .pg-grid { grid-template-columns: 1fr; gap: 28px; }
  }

  .pg-panel {
    border: 1px solid var(--border);
    background: var(--bg-alt);
    padding: 28px 28px 32px;
  }
  .pg-panel-title {
    font-family: 'Inter', sans-serif;
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 0.22em;
    text-transform: uppercase;
    color: var(--text-secondary);
    margin: 0 0 18px;
  }
  .pg-panel-title--gap { margin-top: 28px; }

  .pg-label {
    display: block;
    font-size: 11px;
    font-weight: 500;
    letter-spacing: 0.18em;
    text-transform: uppercase;
    color: var(--text-tertiary);
    margin-bottom: 16px;
  }
  .pg-label input,
  .pg-label select,
  .pg-label textarea {
    display: block;
    width: 100%;
    margin-top: 6px;
    padding: 10px 12px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 13px;
    color: var(--text);
    background: var(--bg);
    border: 1px solid var(--border-strong);
    border-radius: 0;
    outline: none;
    text-transform: none;
    letter-spacing: 0;
    transition: border-color 0.2s ease, box-shadow 0.2s ease;
  }
  .pg-label textarea {
    resize: vertical;
    font-size: 12px;
    line-height: 1.5;
    word-break: break-all;
    overflow-wrap: anywhere;
  }
  .pg-label input:focus,
  .pg-label select:focus,
  .pg-label textarea:focus {
    border-color: var(--accent);
    box-shadow: 0 0 0 3px rgba(232, 100, 44, 0.12);
  }

  .pg-error {
    display: none;
    margin-top: 4px;
    padding: 10px 14px;
    background: #fff;
    border-left: 3px solid var(--accent);
    color: var(--accent);
    font-family: 'JetBrains Mono', monospace;
    font-size: 12px;
    line-height: 1.5;
  }

  /* Device frame */
  .pg-device { margin-bottom: 8px; }
  .pg-device-frame {
    background: linear-gradient(180deg, #1f1f24 0%, #16161a 100%);
    border: 1px solid #2a2a30;
    border-radius: 6px;
    padding: 18px;
    box-shadow: inset 0 1px 0 rgba(255,255,255,0.06), 0 8px 24px rgba(0,0,0,0.18);
  }
  .pg-device-screen {
    background: #0a0a0e;
    color: #f1f1f0;
    font-family: 'JetBrains Mono', monospace;
    font-size: 12px;
    line-height: 1.55;
    min-height: 220px;
    padding: 14px 16px;
    border: 1px solid #050507;
    border-radius: 2px;
  }
  .pg-device-caption {
    margin-top: 10px;
    text-align: right;
    font-family: 'JetBrains Mono', monospace;
    font-size: 10px;
    letter-spacing: 0.18em;
    text-transform: uppercase;
    color: var(--text-tertiary);
  }

  /* Device screen contents */
  .pg-dev-action {
    color: #fff;
    font-weight: 500;
    letter-spacing: 0.18em;
    margin-bottom: 8px;
  }
  .pg-dev-rule {
    height: 1px;
    background: #2a2a30;
    margin: 0 0 10px;
  }
  .pg-dev-line {
    display: flex;
    justify-content: space-between;
    gap: 12px;
    margin: 4px 0;
  }
  .pg-dev-label { color: #8e8e8e; }
  .pg-dev-value { color: #d6d6d6; word-break: break-all; text-align: right; }
  .pg-dev-value.pg-info { color: #d6d6d6; }
  .pg-dev-value.pg-warn { color: #ffd76b; }
  .pg-dev-value.pg-danger { color: #ff7b6b; font-weight: 500; }

  .pg-dev-warning {
    margin-top: 12px;
    padding: 8px 10px;
    background: rgba(255, 123, 107, 0.08);
    border-left: 2px solid #ff7b6b;
    color: #ff9d8e;
    font-size: 11px;
    line-height: 1.45;
  }
  .pg-dev-footer {
    margin-top: 14px;
    padding-top: 10px;
    border-top: 1px dashed #2a2a30;
    color: #6e6e73;
    font-size: 10px;
    letter-spacing: 0.16em;
    text-align: center;
  }
  .pg-dev-error {
    color: #ff7b6b;
    font-weight: 500;
    letter-spacing: 0.2em;
    text-align: center;
    padding: 80px 0;
  }

  .pg-hex {
    margin: 0;
    padding: 12px 14px;
    background: var(--bg);
    border: 1px solid var(--border);
    font-family: 'JetBrains Mono', monospace;
    font-size: 12px;
    line-height: 1.55;
    word-break: break-all;
    white-space: pre-wrap;
    color: var(--text);
  }
</style>

<script type="module">
  import { sha256 } from 'https://esm.sh/@noble/hashes@1.4.0/sha256';
  import { keccak_256 } from 'https://esm.sh/@noble/hashes@1.4.0/sha3';

  // ---------------------------------------------------------------------- //
  // Canonical serializer. Mirrors attester/renderer/src/render.ts and the   //
  // firmware's render.rs encode_object_header / encode_bytes / encode_u128. //
  // ---------------------------------------------------------------------- //

  const DOMAIN_SEP = new TextEncoder().encode('intentguard.v1.attest');

  function canonical(v) {
    if (v instanceof Uint8Array) {
      return concat([Uint8Array.of(0x02), varint(v.length), v]);
    }
    if (typeof v === 'string') {
      const bytes = new TextEncoder().encode(v);
      return concat([Uint8Array.of(0x01), varint(bytes.length), bytes]);
    }
    if (typeof v === 'bigint') {
      if (v < 0n) throw new Error('negative bigint not supported');
      const out = new Uint8Array(16);
      let n = v;
      for (let i = 0; i < 16; i++) { out[i] = Number(n & 0xffn); n >>= 8n; }
      if (n !== 0n) throw new Error('bigint exceeds u128');
      return concat([Uint8Array.of(0x06), out]);
    }
    if (typeof v === 'number') {
      if (!Number.isInteger(v) || v < 0) throw new Error('non-positive integer');
      const buf = new ArrayBuffer(8);
      new DataView(buf).setBigUint64(0, BigInt(v), true);
      return concat([Uint8Array.of(0x03), new Uint8Array(buf)]);
    }
    if (typeof v === 'boolean') {
      return concat([Uint8Array.of(0x05), Uint8Array.of(v ? 1 : 0)]);
    }
    if (typeof v === 'object' && v !== null) {
      const keys = Object.keys(v).sort();
      const parts = [Uint8Array.of(0x10), varint(keys.length)];
      for (const k of keys) {
        const kb = new TextEncoder().encode(k);
        parts.push(varint(kb.length));
        parts.push(kb);
        parts.push(canonical(v[k]));
      }
      return concat(parts);
    }
    throw new Error(`unsupported value type: ${typeof v}`);
  }

  function intentHash(network, vault, nonce, actionKind, decoded) {
    const buf = concat([DOMAIN_SEP, vault, u64LE(nonce), u32LE(actionKind), canonical(decoded)]);
    return network === 'solana' ? sha256(buf) : keccak_256(buf);
  }

  function attestDigest(network, vault, nonce, actionKind, ih, signedAt) {
    const buf = concat([DOMAIN_SEP, vault, u64LE(nonce), u32LE(actionKind), ih, u64LE(signedAt)]);
    return network === 'solana' ? sha256(buf) : keccak_256(buf);
  }

  // ---------------------------------------------------------------------- //
  // Adapters. Mirror attester/renderer/src/adapters/*.ts.                  //
  // ---------------------------------------------------------------------- //

  const ADAPTERS = {
    1: {
      name: 'WHITELIST_COLLATERAL',
      decode(bytes) {
        if (bytes.length !== 80) throw new Error(`WHITELIST_COLLATERAL: expected 80 bytes, got ${bytes.length}`);
        const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
        return {
          token: bytes.slice(0, 32),
          fair_value_usd_micros: dv.getBigUint64(32, true),
          oracle: bytes.slice(40, 72),
          max_deposit_usd: dv.getBigUint64(72, true),
        };
      },
      render(intent) {
        return {
          actionKindName: 'WHITELIST_COLLATERAL',
          lines: [
            { label: 'Token', value: hexShort(intent.token), severity: 'info' },
            { label: 'Fair value (USD)', value: formatUsd(intent.fair_value_usd_micros), severity: 'danger' },
            { label: 'Oracle', value: hexShort(intent.oracle), severity: 'warn' },
            { label: 'Max deposit (USD)', value: intent.max_deposit_usd.toString(), severity: 'info' },
          ],
          warning: 'Adding collateral. Confirm fair value matches the live oracle.',
        };
      },
    },
    3: {
      name: 'TRANSFER_ADMIN',
      decode(bytes) {
        if (bytes.length !== 32) throw new Error(`TRANSFER_ADMIN: expected 32 bytes, got ${bytes.length}`);
        return { new_admin: bytes.slice(0, 32) };
      },
      render(intent) {
        return {
          actionKindName: 'TRANSFER_ADMIN',
          lines: [
            { label: 'New admin', value: hexShort(intent.new_admin), severity: 'danger' },
          ],
          warning: 'Transferring administrative control. Verify the destination off-band before confirming.',
        };
      },
    },
  };

  // ---------------------------------------------------------------------- //
  // Sample scenarios. Hex strings constructed to match the wire layouts.    //
  // ---------------------------------------------------------------------- //

  const SCENARIOS = {
    drift: {
      label: 'Replay the Drift attack',
      network: 'solana',
      vault: '0x' + '11'.repeat(32),
      nonce: 12,
      actionKind: 1,
      // 32 bytes token (CC = 'CVT' visual stand-in)
      // 8 bytes fair_value_usd_micros = 1_000_000 LE = 40420f0000000000  ($1.00)
      // 32 bytes oracle (AA = fake Pyth feed)
      // 8 bytes max_deposit_usd = 500_000_000 LE = 0065cd1d00000000  ($500M)
      actionArgs:
        '0x' + 'cc'.repeat(32) + '40420f0000000000' + 'aa'.repeat(32) + '0065cd1d00000000',
      signedAt: 1745700000,
    },
    routineUsdc: {
      label: 'Routine USDC listing',
      network: 'solana',
      vault: '0x' + '11'.repeat(32),
      nonce: 13,
      actionKind: 1,
      // token = stand-in for USDC mint, fair_value $1.00, oracle = stand-in for Pyth USDC, cap $50M
      actionArgs:
        '0x' + 'ee'.repeat(32) + '40420f0000000000' + 'bb'.repeat(32) + '80f0fa0200000000',
      signedAt: 1745700000,
    },
    badAdmin: {
      label: 'Admin transfer to attacker',
      network: 'solana',
      vault: '0x' + '11'.repeat(32),
      nonce: 14,
      actionKind: 3,
      // 32 bytes new_admin = obvious burn / sentinel
      actionArgs: '0xdead' + '00'.repeat(30),
      signedAt: 1745700000,
    },
    routineAdmin: {
      label: 'Routine admin rotation',
      network: 'solana',
      vault: '0x' + '11'.repeat(32),
      nonce: 15,
      actionKind: 3,
      actionArgs: '0x' + 'a1b2c3d4e5f6'.repeat(5) + 'a1b2',
      signedAt: 1745700000,
    },
  };

  // ---------------------------------------------------------------------- //
  // UI wiring                                                               //
  // ---------------------------------------------------------------------- //

  const els = {
    network: document.getElementById('pg-network'),
    vault: document.getElementById('pg-vault'),
    nonce: document.getElementById('pg-nonce'),
    actionKind: document.getElementById('pg-action-kind'),
    actionArgs: document.getElementById('pg-action-args'),
    signedAt: document.getElementById('pg-signed-at'),
    device: document.getElementById('pg-device-screen'),
    intentHash: document.getElementById('pg-intent-hash'),
    canonical: document.getElementById('pg-canonical'),
    digest: document.getElementById('pg-attest-digest'),
    error: document.getElementById('pg-error'),
  };

  function render() {
    els.error.style.display = 'none';
    try {
      const network = els.network.value;
      const vault = unhex(els.vault.value);
      const nonceStr = els.nonce.value || '0';
      const nonce = BigInt(nonceStr);
      const actionKind = parseInt(els.actionKind.value, 10);
      const actionArgs = unhex(els.actionArgs.value);
      const signedAtStr = els.signedAt.value || Math.floor(Date.now() / 1000).toString();
      const signedAt = BigInt(signedAtStr);

      const adapter = ADAPTERS[actionKind];
      if (!adapter) throw new Error(`No adapter registered for action_kind=${actionKind}`);

      const decoded = adapter.decode(actionArgs);
      const rendered = adapter.render(decoded);
      const cb = canonical(decoded);
      const ih = intentHash(network, vault, nonce, actionKind, decoded);
      const dig = attestDigest(network, vault, nonce, actionKind, ih, signedAt);

      paintDevice(rendered);
      els.canonical.textContent = '0x' + hex(cb) + '\n\n' + cb.length + ' bytes';
      els.intentHash.textContent = '0x' + hex(ih);
      els.digest.textContent = '0x' + hex(dig);
    } catch (e) {
      els.error.textContent = e.message;
      els.error.style.display = 'block';
      els.device.innerHTML = '<div class="pg-dev-error">DECODE FAILURE</div>';
      els.canonical.textContent = '';
      els.intentHash.textContent = '';
      els.digest.textContent = '';
    }
  }

  function paintDevice(r) {
    let html = `<div class="pg-dev-action">${escapeHtml(r.actionKindName)}</div>`;
    html += `<div class="pg-dev-rule"></div>`;
    for (const line of r.lines) {
      html += `<div class="pg-dev-line">`
        + `<span class="pg-dev-label">${escapeHtml(line.label)}</span>`
        + `<span class="pg-dev-value pg-${line.severity || 'info'}">${escapeHtml(line.value)}</span>`
        + `</div>`;
    }
    if (r.warning) {
      html += `<div class="pg-dev-warning">! ${escapeHtml(r.warning)}</div>`;
    }
    html += `<div class="pg-dev-footer">[ENTER] confirm    [ESC] cancel</div>`;
    els.device.innerHTML = html;
  }

  // Sample-scenario chips.
  document.querySelectorAll('[data-scenario]').forEach((btn) => {
    btn.addEventListener('click', () => {
      const s = SCENARIOS[btn.dataset.scenario];
      if (!s) return;
      els.network.value = s.network;
      els.vault.value = s.vault;
      els.nonce.value = String(s.nonce);
      els.actionKind.value = String(s.actionKind);
      els.actionArgs.value = s.actionArgs;
      els.signedAt.value = String(s.signedAt);
      document.querySelectorAll('.pg-chip').forEach((c) => c.classList.toggle('is-active', c === btn));
      render();
    });
  });

  // Re-render on any input change.
  ['network', 'vault', 'nonce', 'actionKind', 'actionArgs', 'signedAt'].forEach((k) => {
    els[k].addEventListener('input', render);
    els[k].addEventListener('change', render);
  });

  // ---------------------------------------------------------------------- //
  // Helpers                                                                 //
  // ---------------------------------------------------------------------- //

  function u32LE(n) {
    const b = new ArrayBuffer(4);
    new DataView(b).setUint32(0, n, true);
    return new Uint8Array(b);
  }
  function u64LE(n) {
    const b = new ArrayBuffer(8);
    new DataView(b).setBigUint64(0, n, true);
    return new Uint8Array(b);
  }
  function varint(n) {
    const out = [];
    while (n >= 0x80) { out.push((n & 0x7f) | 0x80); n >>>= 7; }
    out.push(n & 0x7f);
    return Uint8Array.from(out);
  }
  function concat(parts) {
    const total = parts.reduce((a, p) => a + p.length, 0);
    const out = new Uint8Array(total);
    let off = 0;
    for (const p of parts) { out.set(p, off); off += p.length; }
    return out;
  }
  function hex(b) {
    return Array.from(b).map((x) => x.toString(16).padStart(2, '0')).join('');
  }
  function unhex(s) {
    const c = (s || '').trim().replace(/^0x/, '').replace(/\s+/g, '');
    if (c.length === 0) return new Uint8Array(0);
    if (c.length % 2 !== 0) throw new Error('hex length must be even');
    if (!/^[0-9a-fA-F]+$/.test(c)) throw new Error('hex contains non-hex characters');
    const out = new Uint8Array(c.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(c.substr(i * 2, 2), 16);
    return out;
  }
  function hexShort(b) {
    if (b.length <= 8) return hex(b);
    return hex(b.slice(0, 4)) + '..' + hex(b.slice(-4));
  }
  function formatUsd(micros) {
    const d = micros / 1_000_000n;
    const c = micros % 1_000_000n;
    return `$${d}.${String(c).padStart(6, '0').slice(0, 2)}`;
  }
  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, (c) => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
    }[c]));
  }

  // Initial: load the Drift scenario.
  document.querySelector('[data-scenario="drift"]').click();
</script>
