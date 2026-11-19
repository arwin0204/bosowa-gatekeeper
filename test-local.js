// Local end-to-end test for bosowa-gatekeeper.
// Spawns server.js with a test HMAC secret, then exercises:
// preflight, valid approve, trap reject, replay (byte-identical),
// bad signature (401), invalid JSON (400). Verifies proofs + response HMAC.
const { spawn } = require("child_process");
const crypto = require("crypto");
const snarkjs = require("snarkjs");
const fs = require("fs");

const SECRET = "test-secret-123";
const PORT = 3123;
const URL = `http://localhost:${PORT}/agent`;
const ADDR = "0x1111111111111111111111111111111111111111";
const OTHER = "0x2222222222222222222222222222222222222222";

function hmac(body) {
  return crypto.createHmac("sha256", SECRET).update(body).digest("hex");
}

async function post(bodyObj, { sign = true, raw = null } = {}) {
  const body = raw !== null ? raw : JSON.stringify(bodyObj);
  const headers = { "content-type": "application/json" };
  if (sign) headers["x-agent-games-signature"] = hmac(Buffer.from(body));
  const res = await fetch(URL, { method: "POST", headers, body });
  const text = await res.text();
  return { status: res.status, text, sig: res.headers.get("x-agent-games-signature") };
}

function checkSig(text, sig) {
  if (!sig) return false;
  const expect = crypto.createHmac("sha256", SECRET).update(Buffer.from(text)).digest("hex");
  return crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expect));
}

async function verifyProof(json) {
  if (!json.proof || !json.publicSignals) return "no-proof";
  const vkey = JSON.parse(fs.readFileSync("circuits/verification_key.json", "utf8"));
  return (await snarkjs.groth16.verify(vkey, json.publicSignals, json.proof)) ? "OK" : "FAIL";
}

async function main() {
  const server = spawn("node", ["server.js"], {
    env: { ...process.env, AGENT_GAMES_HMAC_SECRET: SECRET, PORT: String(PORT) },
    stdio: ["ignore", "pipe", "pipe"],
  });
  server.stdout.on("data", (d) => process.stdout.write("[srv] " + d));
  server.stderr.on("data", (d) => process.stdout.write("[srv:err] " + d));
  await new Promise((r) => setTimeout(r, 1500));
  const results = [];
  const check = (name, cond) => {
    results.push([name, !!cond]);
    console.log((cond ? "PASS" : "FAIL") + "  " + name);
  };

  // 1. Preflight / health (no task fields)
  let r = await post({ type: "preflight", hello: "agent-games" });
  let j = JSON.parse(r.text);
  check("preflight 200 + ok", r.status === 200 && j.ok === true);
  check("preflight response signed", checkSig(r.text, r.sig));

  // 2. Valid task -> APPROVE with valid proof
  // Real tasks carry proof_vk + registered_vk (must match for APPROVE).
  // The test previously omitted them, so decide() always failed the VK
  // check and every task REJECTed. Use the tournament VK hash for both.
  const VK = "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";
  const valid = {
    taskId: "task-001",
    minimum: 1000,
    publicBalance: 1460,
    expiryBlock: 8430000,
    currentBlock: 8420000,
    recipient: ADDR,
    conditionRecipient: ADDR,
    amount: 500,
    maxTransfer: 1000,
    proofVk: VK,
    registeredVk: VK,
  };
  const t0 = Date.now();
  r = await post(valid);
  const ms = Date.now() - t0;
  j = JSON.parse(r.text);
  check("valid task 200", r.status === 200);
  check("valid task decision=1", j.decision === "APPROVE");
  check("valid task proof verifies", (await verifyProof(j)) === "OK");
  // 2026-11-19 fix: proof must carry ONLY pi_a/pi_b/pi_c (no
  // snarkjs `protocol`/`curve` fields) or the platform's on-chain
  // verifier may reject it during serialization.
  check(
    "proof has only pi_a/pi_b/pi_c",
    !!j.proof &&
      Object.keys(j.proof).sort().join(",") === "pi_a,pi_b,pi_c"
  );
  check("valid task response signed", checkSig(r.text, r.sig));
  console.log(`      approve round-trip: ${ms} ms`);

  // 3. Trap task (recipient mismatch) -> REJECT with valid proof
  const trap = { ...valid, taskId: "task-002", recipient: OTHER };
  r = await post(trap);
  j = JSON.parse(r.text);
  check("trap task decision=0", j.decision === "REJECT");
  check("trap task proof verifies", (await verifyProof(j)) === "OK");

  // 4. Replay: same taskId as #2 -> byte-identical cached response
  const r1 = await post(valid);
  const r2 = await post(valid);
  check("replay identical bodies", r1.text === r2.text);

  // 5. Bad signature -> 401
  r = await post(valid, { sign: false });
  check("bad signature 401", r.status === 401);

  // 6. Invalid JSON -> 400
  r = await post(null, { raw: "{not json" });
  check("invalid json 400", r.status === 400);

  // 7. Expired task -> REJECT
  const expired = { ...valid, taskId: "task-003", expiryBlock: 8410000 };
  r = await post(expired);
  j = JSON.parse(r.text);
  check("expired task decision=0", j.decision === "REJECT");
  check("expired task proof verifies", (await verifyProof(j)) === "OK");

  // 8. Amount over cap -> REJECT
  const overcap = { ...valid, taskId: "task-004", amount: 1500 };
  r = await post(overcap);
  j = JSON.parse(r.text);
  check("over-cap task decision=0", j.decision === "REJECT");

  server.kill();
  const failed = results.filter(([, ok]) => !ok);
  console.log(`\n${results.length - failed.length}/${results.length} checks passed`);
  process.exit(failed.length ? 1 : 0);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
