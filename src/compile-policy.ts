/**
 * Compile the wallet signing policy via ICME makeRules.
 *
 * Run:  npm run compile-policy
 *
 * The resulting policy_id is saved to policies/compiled.json
 * and reused by the demo server.
 */

import "dotenv/config";
import { mkdirSync, writeFileSync } from "node:fs";
import { makeRules } from "./icme-client.js";

const POLICY_TEXT = `A wallet signing request is permitted only if all of the following are true:
the destination address is a member of the verified wallets allowlist,
and the transaction amount does not exceed the per-transaction spending limit,
and the memo field does not contain instruction-like language or prompt injection patterns,
and the request originates from an authorized agent identity.`;

async function main() {
  console.log("Compiling wallet signing policy via ICME makeRules...");
  console.log(`Policy:\n  ${POLICY_TEXT.replace(/\n/g, "\n  ")}\n`);

  const start = Date.now();
  const response = await makeRules(POLICY_TEXT);
  const elapsed = ((Date.now() - start) / 1000).toFixed(1);

  console.log(`Done in ${elapsed}s`);
  console.log("Response:", JSON.stringify(response, null, 2));

  const out = {
    policy_id: response.policy_id,
    policy_text: POLICY_TEXT,
    compiled_at: new Date().toISOString(),
    raw_response: response,
  };

  mkdirSync("policies", { recursive: true });
  writeFileSync("policies/compiled.json", JSON.stringify(out, null, 2));
  console.log(`\nSaved to policies/compiled.json`);
  console.log(`Policy ID: ${response.policy_id}`);
}

main().catch((err) => {
  console.error("Failed:", err);
  process.exit(1);
});
