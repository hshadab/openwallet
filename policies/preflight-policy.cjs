#!/usr/bin/env node
/**
 * OWS Policy Executable — ICME Preflight Check
 *
 * Reads PolicyContext JSON from stdin, checks the cached ICME result,
 * and returns { allow: true/false, reason: "..." } on stdout.
 *
 * Uses only Node.js built-ins (no npm dependencies).
 */

const fs = require("fs");
const path = require("path");
const http = require("http");

const CACHE_PATH = path.resolve(__dirname, ".icme-cache.json");
const FALLBACK_URL = "http://localhost:3001/api/icme-cache";

function readStdin() {
  return new Promise((resolve) => {
    let data = "";
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", (chunk) => (data += chunk));
    process.stdin.on("end", () => resolve(data));
    // If no stdin after 100ms, resolve empty
    setTimeout(() => resolve(data), 100);
  });
}

function readCache() {
  try {
    if (fs.existsSync(CACHE_PATH)) {
      const raw = fs.readFileSync(CACHE_PATH, "utf8");
      return JSON.parse(raw);
    }
  } catch (_) {
    // fall through to HTTP fallback
  }
  return null;
}

function fetchCache() {
  return new Promise((resolve) => {
    const req = http.get(FALLBACK_URL, { timeout: 3000 }, (res) => {
      let body = "";
      res.on("data", (chunk) => (body += chunk));
      res.on("end", () => {
        try {
          resolve(JSON.parse(body));
        } catch (_) {
          resolve(null);
        }
      });
    });
    req.on("error", () => resolve(null));
    req.on("timeout", () => {
      req.destroy();
      resolve(null);
    });
  });
}

async function main() {
  // Read policy context from stdin (OWS sends this)
  const stdinData = await readStdin();
  let context = {};
  try {
    if (stdinData.trim()) context = JSON.parse(stdinData);
  } catch (_) {
    // proceed without context
  }

  // Try file cache first (sub-millisecond), then HTTP fallback
  let icmeResult = readCache();
  if (!icmeResult) {
    icmeResult = await fetchCache();
  }

  if (!icmeResult) {
    // No ICME data available — fail-closed (deny)
    const output = {
      allow: false,
      reason: "ICME cache unavailable — fail-closed",
    };
    process.stdout.write(JSON.stringify(output));
    process.exit(0);
  }

  // Evaluate the ICME result
  const result = icmeResult.result || "";
  const isBlocked = result === "UNSAT" || result === "AR uncertain";

  if (isBlocked) {
    const detail = icmeResult.detail || "policy violated";
    const output = {
      allow: false,
      reason: `UNSAT: ${detail}`,
      icme_result: result,
      z3_result: icmeResult.z3_result || result,
      zk_proof_id: icmeResult.zk_proof_id || null,
      zk_proof_url: icmeResult.zk_proof_url || null,
    };
    process.stdout.write(JSON.stringify(output));
  } else {
    const output = {
      allow: true,
      reason: "Policy satisfied (SAT)",
      icme_result: result,
    };
    process.stdout.write(JSON.stringify(output));
  }

  process.exit(0);
}

main().catch((err) => {
  process.stdout.write(
    JSON.stringify({ allow: false, reason: `Error: ${err.message}` })
  );
  process.exit(0);
});
