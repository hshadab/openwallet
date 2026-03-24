# Jailbreak-Proof Wallet

AI agents can be tricked into signing malicious transactions. This demo shows how OWS (Open Wallet Standard) and ICME Preflight combine local key custody with formal verification to block prompt injection before `sign()` is ever called.

## What this does

AI agents are increasingly used to manage crypto wallets. An attacker can hide instructions inside normal-looking data (like an invoice memo) that trick an AI into sending funds to the wrong address. This is called a **prompt injection attack**.

This demo runs the same attack against two wallet setups side by side:

1. **Naive LLM-Judge Wallet** -- An AI reviews the transaction and decides if it looks safe. The attack fools it. Funds are drained.

2. **OWS + ICME Preflight Wallet** -- Before any transaction is signed, the request passes through a policy engine that uses a formal math solver (Z3/SMT) instead of an AI opinion. The solver proves the transaction violates the policy (destination not in allowlist, memo contains injection). Signing is blocked. A ZK proof receipt is issued so anyone can independently verify the guardrail worked.

No AI was consulted for the security decision. The policy is compiled to formal logic and checked by a theorem prover. It either satisfies the constraints or it doesn't -- there is no way to "convince" a math solver to ignore the rules.

## How it works

```
Server starts
  --> Calls ICME checkIt API with the attack payload
  --> Caches the UNSAT result to disk

User clicks "Start Demo"
  --> Frontend calls /api/check (real ICME verification)
  --> 5-step animated comparison plays out
  --> After step 3, frontend calls /api/ows-demo
      --> Server uses the OWS SDK (real Rust FFI calls):
          1. createWallet("demo-treasury") -- 8-chain universal wallet
          2. createPolicy() -- links to preflight-policy.cjs executable
          3. createApiKey() -- scoped agent token
          4. Runs the policy executable with the attack context
          5. Executable reads cached ICME result --> { allow: false }
      --> Returns step-by-step log to the frontend
  --> Proof receipt appears with "Verify Proof" button

User clicks "Verify Proof"
  --> Frontend calls /api/verify-proof
  --> Server checks the ZK proof from ICME
  --> Shows VERIFIED status
```

## What is real in this demo

- **Real OWS SDK calls.** `createWallet`, `createPolicy`, `createApiKey` all call the actual `@open-wallet-standard/core` Rust binary via Node.js FFI. Real wallet IDs, real EVM addresses, real policy registration.

- **Real ICME API calls.** The attack payload is sent to the ICME checkIt endpoint. A real Z3 solver evaluates the policy constraints. The result (UNSAT) comes back with a real ZK proof ID and proof URL.

- **Real policy executable.** `policies/preflight-policy.cjs` is a standalone Node.js script that OWS would spawn as a subprocess during signing. It reads the cached ICME result and returns `{ allow: false }`.

- **Mock mode available.** Pass `--mock` to skip all external calls. Everything still works with scripted responses.

## Why OWS needs formal verification

OWS solves key custody: private keys are encrypted at rest, decrypted only to sign, held in protected memory, and wiped immediately. An agent never sees the key material.

But key isolation doesn't stop a compromised agent from *requesting* a valid signature for a malicious transaction. If an attacker injects instructions into an invoice memo, an LLM-based guardrail can be convinced the transaction is legitimate. The agent calls `sign()`, OWS dutifully decrypts the key and signs, and the funds are gone.

The OWS policy engine supports spending limits and allowlists, but the rules are only as strong as the enforcement layer. ICME Preflight adds the missing piece:

1. **English → formal logic.** The policy is compiled to SMT-LIB constraints by ICME's `makeRules` endpoint.
2. **Z3 solver evaluation.** Every signing request is checked by a theorem prover. The result is SAT (satisfies all constraints) or UNSAT (violates at least one). There is no "maybe" and no way to talk the solver into changing its answer.
3. **ZK proof receipt.** Each check produces a cryptographic proof that the policy was evaluated correctly. Auditors, regulators, or counterparties can verify it independently — no trust in ICME or the agent operator required.

This demo runs the full flow with real OWS SDK calls and real ICME API calls to show the integration end to end.

## Tech stack

| Component | What it does |
|-----------|-------------|
| [Open Wallet Standard](https://openwallet.sh) | Local key custody + policy-gated signing for every chain |
| [ICME Preflight](https://docs.icme.io) | Compiles English policies to SMT-LIB formal logic, runs Z3 solver, issues ZK proofs |
| Node.js + TypeScript | Server and build |
| Vanilla HTML/CSS/JS | Frontend (no framework) |

## Setup

```bash
# 1. Clone and install
git clone https://github.com/hshadab/openwallet.git
cd openwallet
npm install

# 2. Add your ICME API key
cp .env.example .env
# Edit .env and set ICME_API_KEY=your_key

# 3. Compile the policy (one-time)
npm run compile-policy

# 4. Run the demo
npm run ui          # Live mode (real ICME + OWS SDK)
npm run ui:mock     # Mock mode (no API calls needed)

# 5. Open http://localhost:3001
```

## Project structure

```
openwallet/
  src/
    server.ts          -- HTTP server, OWS SDK integration, ICME proxy
    icme-client.ts     -- ICME API client (makeRules, checkIt)
    compile-policy.ts  -- One-time policy compilation script
  web/
    index.html         -- Demo UI
    style.css          -- Styles
    app.js             -- Frontend logic and animations
  policies/
    compiled.json      -- Compiled ICME policy (generated)
    preflight-policy.cjs -- OWS policy executable (reads ICME cache)
    .icme-cache.json   -- Cached ICME result (generated at startup)
  .ows-demo-vault/     -- Temporary OWS vault (created/cleaned per demo run)
```

## API endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/check` | Proxy to ICME checkIt -- verifies an action against the compiled policy |
| GET | `/api/policy` | Returns the compiled policy text |
| GET | `/api/icme-cache` | Serves the cached ICME result (used by the policy executable) |
| POST | `/api/ows-demo` | Runs the full OWS flow: create wallet, policy, key, run policy check |
| POST | `/api/verify-proof` | Verifies a ZK proof from ICME |

## The policy

The wallet signing policy, written in plain English and compiled to formal logic by ICME:

> A wallet signing request is permitted only if all of the following are true:
> the destination address is a member of the verified wallets allowlist,
> and the transaction amount does not exceed the per-transaction spending limit,
> and the memo field does not contain instruction-like language or prompt injection patterns,
> and the request originates from an authorized agent identity.

The attack fails on two clauses: the destination (`0xDEAD...f00d`) is not in the allowlist, and the memo contains prompt injection language.

## License

MIT
