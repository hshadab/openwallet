import "dotenv/config";

const BASE_URL = "https://api.icme.io/v1";
const API_KEY = process.env.ICME_API_KEY;

if (!API_KEY) {
  throw new Error("ICME_API_KEY not set in .env");
}

export interface MakeRulesResponse {
  policy_id: string;
  [key: string]: unknown;
}

export interface CheckItResponse {
  result: string;
  extracted: Record<string, boolean | number>;
  llm_result: string;
  ar_result: string;
  ar_detail?: string;
  z3_result: string;
  detail?: string;
  zk_proof_id?: string;
  zk_proof_url?: string;
}

async function parseSSE(res: Response): Promise<MakeRulesResponse> {
  const text = await res.text();
  const lines = text.split("\n").filter((l) => l.startsWith("data: "));

  let lastObj: Record<string, unknown> = {};

  for (const line of lines) {
    const json = line.slice("data: ".length).trim();
    if (!json) continue;
    try {
      const parsed = JSON.parse(json);
      lastObj = { ...lastObj, ...parsed };
      if (parsed.msg) {
        console.log(`  [makeRules] ${parsed.msg}`);
      }
    } catch {
      // skip non-JSON lines
    }
  }

  if (!lastObj.policy_id) {
    throw new Error(
      `makeRules did not return a policy_id. Full response:\n${text}`
    );
  }

  return lastObj as MakeRulesResponse;
}

export async function makeRules(policy: string): Promise<MakeRulesResponse> {
  const res = await fetch(`${BASE_URL}/makeRules`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-API-Key": API_KEY!,
    },
    body: JSON.stringify({ policy }),
  });

  if (!res.ok) {
    const body = await res.text();
    throw new Error(`makeRules failed (${res.status}): ${body}`);
  }

  return parseSSE(res);
}

export async function checkIt(
  policyId: string,
  action: string
): Promise<CheckItResponse> {
  const res = await fetch(`${BASE_URL}/checkIt`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-API-Key": API_KEY!,
    },
    body: JSON.stringify({ policy_id: policyId, action }),
  });

  if (!res.ok) {
    const body = await res.text();
    throw new Error(`checkIt failed (${res.status}): ${body}`);
  }

  const text = await res.text();
  if (text.startsWith("data: ")) {
    const lines = text.split("\n").filter((l) => l.startsWith("data: "));
    let result: Record<string, unknown> = {};
    for (const line of lines) {
      try {
        const parsed = JSON.parse(line.slice("data: ".length).trim());
        result = { ...result, ...parsed };
      } catch {
        // skip
      }
    }
    return result as unknown as CheckItResponse;
  }

  return JSON.parse(text) as CheckItResponse;
}
