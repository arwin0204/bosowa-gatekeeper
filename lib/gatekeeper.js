// bosowa-gatekeeper — Proof Gatekeeper agent for zkVerify Agent Games.
// Agent: bosowa123 (X @bosowa123). Track: Proof Gatekeeper.
// Rule: if you cannot prove it, do not approve it. Fail closed, always.
//
// Flow: verify HMAC on the raw body -> decide deterministically ->
// generate a Groth16 proof with the tournament's own circuit -> return
// the decision + proof + public signals in a signed response.
// A retried taskId returns the byte-identical cached response.
// A reused proofReference returns the decision alone, without a new proof.

const crypto = require("crypto");
const snarkjs = require("snarkjs");
const path = require("path");
const fs = require("fs");

const VK_HASH_HEX =
  "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";
const FIELD_PRIME = BigInt(
  "21888242871839275222246405745257275088548364400416034343698204186575808495617"
);
const WASM_PATH = path.join(__dirname, "..", "circuits", "gatekeeper.wasm");
const ZKEY_PATH = path.join(
  __dirname,
  "..",
  "circuits",
  "gatekeeper_final.zkey"
);

// ---------------------------------------------------------------- HMAC ---
const SIG_HEADERS = [
  "x-agent-games-signature",
  "x-signature",
  "signature",
  "x-hub-signature-256",
  "x-agent-signature",
];

function hmacHex(secret, rawBody) {
  return crypto.createHmac("sha256", secret).update(rawBody).digest("hex");
}

function hmacB64(secret, rawBody) {
  return crypto.createHmac("sha256", secret).update(rawBody).digest("base64");
}

function timingEqual(a, b) {
  const ba = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}

// Verify the platform signature on the raw body BEFORE parsing anything.
// Returns { ok: true } or { ok: false, reason }.
// When no secret is configured (local dev), verification is skipped.
function verifySignature(rawBody, headers) {
  const secret = process.env.AGENT_GAMES_HMAC_SECRET;
  if (!secret) return { ok: true, skipped: true };
  const lower = {};
  for (const k of Object.keys(headers || {})) lower[k.toLowerCase()] = headers[k];
  for (const name of SIG_HEADERS) {
    const sig = lower[name];
    if (!sig) continue;
    const clean = String(sig).replace(/^sha256=/, "").trim();
    if (timingEqual(clean, hmacHex(secret, rawBody))) return { ok: true, header: name };
    if (timingEqual(clean, hmacB64(secret, rawBody))) return { ok: true, header: name };
  }
  return { ok: false, reason: "bad-signature" };
}

function signResponse(rawBody) {
  const secret = process.env.AGENT_GAMES_HMAC_SECRET;
  if (!secret) return null;
  return hmacHex(secret, rawBody);
}

// ------------------------------------------------------- task extraction ---
// The platform envelope is not documented field-by-field, so extract the
// task fields flexibly: top level first, then under task / data / payload /
// envelope. Values may be numbers, decimal strings, or hex strings.
const TASK_FIELDS = [
  "minimum",
  "publicBalance",
  "expiryBlock",
  "currentBlock",
  "recipient",
  "conditionRecipient",
  "amount",
  "maxTransfer",
  "taskId",
];

function findTaskObject(body) {
  if (!body || typeof body !== "object") return null;
  const hasFields = (o) =>
    o && typeof o === "object" && TASK_FIELDS.some((f) => o[f] !== undefined);
  if (hasFields(body)) return body;
  for (const key of ["task", "data", "payload", "envelope", "input", "request"]) {
    if (hasFields(body[key])) return body[key];
  }
  return null;
}

function toBigInt(value) {
  if (typeof value === "bigint") return value;
  if (typeof value === "number") return BigInt(Math.trunc(value));
  const s = String(value).trim();
  if (/^0x[0-9a-fA-F]+$/.test(s)) return BigInt(s);
  if (/^-?\d+$/.test(s)) return BigInt(s);
  return null;
}

// taskId must become a field element. Numeric ids pass through; anything
// else is hashed deterministically (SHA-256, reduced mod the field prime).
function taskIdToField(taskId) {
  if (taskId === undefined || taskId === null) return "0";
  const n = toBigInt(taskId);
  if (n !== null) return (n % FIELD_PRIME).toString();
  const h = crypto.createHash("sha256").update(String(taskId)).digest();
  return (BigInt("0x" + h.toString("hex")) % FIELD_PRIME).toString();
}

function randomSalt() {
  const b = crypto.randomBytes(31);
  return (BigInt("0x" + b.toString("hex")) % FIELD_PRIME).toString();
}

// ------------------------------------------------------------ decision -----
// The circuit enforces: decision == 1 if and only if every check passes.
// The JS decision MUST mirror the circuit exactly, or fullProve fails.
function decide(t) {
  const minimum = toBigInt(t.minimum);
  const publicBalance = toBigInt(t.publicBalance);
  const expiryBlock = toBigInt(t.expiryBlock);
  const currentBlock = toBigInt(t.currentBlock);
  const recipient = toBigInt(t.recipient);
  const conditionRecipient = toBigInt(t.conditionRecipient);
  const amount = toBigInt(t.amount);
  const maxTransfer = toBigInt(t.maxTransfer);
  const checks = {
    balanceMeetsMinimum:
      minimum !== null && publicBalance !== null && publicBalance >= minimum,
    amountWithinCap:
      amount !== null && maxTransfer !== null && amount <= maxTransfer,
    recipientMatches:
      recipient !== null &&
      conditionRecipient !== null &&
      recipient === conditionRecipient,
    notExpired:
      expiryBlock !== null && currentBlock !== null && expiryBlock > currentBlock,
  };
  const allPass = Object.values(checks).every(Boolean);
  return { decision: allPass ? 1 : 0, checks };
}

// --------------------------------------------------------------- proof -----
async function proveDecision(t, decision) {
  const vkHash = BigInt(VK_HASH_HEX).toString();
  const input = {
    registeredVkHash: vkHash,
    proofVkHash: vkHash,
    minimum: toBigInt(t.minimum).toString(),
    publicBalance: toBigInt(t.publicBalance).toString(),
    expiryBlock: toBigInt(t.expiryBlock).toString(),
    currentBlock: toBigInt(t.currentBlock).toString(),
    recipient: toBigInt(t.recipient).toString(),
    conditionRecipient: toBigInt(t.conditionRecipient).toString(),
    amount: toBigInt(t.amount).toString(),
    maxTransfer: toBigInt(t.maxTransfer).toString(),
    decision: String(decision),
    taskId: taskIdToField(t.taskId),
    salt: randomSalt(),
  };
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    input,
    WASM_PATH,
    ZKEY_PATH
  );
  return { proof, publicSignals };
}

// --------------------------------------------------------- replay cache ----
const taskCache = new Map(); // taskId string -> cached response Buffer
const usedProofRefs = new Set();

function cacheKey(t) {
  return t.taskId === undefined ? null : String(t.taskId);
}

// ------------------------------------------------------------ handler ------
async function handleRawRequest(rawBody, headers) {
  // 1. Verify signature before parsing.
  const sig = verifySignature(rawBody, headers);
  if (!sig.ok) {
    return { status: 401, body: Buffer.from(JSON.stringify({ error: "bad-signature" })) };
  }

  let body;
  try {
    body = JSON.parse(rawBody.toString("utf8"));
  } catch {
    return { status: 400, body: Buffer.from(JSON.stringify({ error: "invalid-json" })) };
  }

  const task = findTaskObject(body);
  // No recognizable task fields: treat as a preflight / health check.
  // The platform requires exactly this signed JSON for preflight:
  // {"ok":true,"protocolVersion":"v1"} + x-agent-games-signature header.
  if (!task) {
    return respond({ ok: true, protocolVersion: "v1" });
  }

  // 2. Replay: a retried taskId returns the byte-identical cached response.
  const key = cacheKey(task);
  if (key && taskCache.has(key)) {
    return { status: 200, body: taskCache.get(key), cached: true };
  }

  // 3. A reused proof reference returns the decision alone, no new proof.
  const proofRef = body.proofReference || body.proof_reference || (task && (task.proofReference || task.proof_reference));
  if (proofRef && usedProofRefs.has(String(proofRef))) {
    const d = decide(task);
    return respond({ decision: d.decision, taskId: task.taskId, reusedProofReference: true });
  }

  // 4. Decide deterministically, fail closed on any error.
  let d;
  try {
    d = decide(task);
  } catch {
    return respond({ decision: 0, taskId: task.taskId, error: "decision-error" });
  }

  // 5. Prove the decision.
  let proofOut;
  try {
    proofOut = await proveDecision(task, d.decision);
  } catch (e) {
    // fullProve fails when the decision contradicts the circuit (wrong
    // approve / wrong reject). Fail closed: REJECT without a proof.
    // (A correct decision always proves; this path should not happen
    // when the JS decision mirrors the circuit.)
    console.error("prove failed:", e && e.message);
    return respond({ decision: 0, taskId: task.taskId, error: "proof-failed" });
  }

  const proofReference = crypto
    .createHash("sha256")
    .update(JSON.stringify(proofOut.proof))
    .digest("hex");
  usedProofRefs.add(proofReference);

  const out = {
    decision: d.decision,
    approved: d.decision === 1,
    taskId: task.taskId,
    proof: proofOut.proof,
    publicSignals: proofOut.publicSignals,
    public_signals: proofOut.publicSignals,
    proofReference,
  };
  const res = respond(out);
  if (key) taskCache.set(key, res.body);
  return res;
}

function respond(obj) {
  const body = Buffer.from(JSON.stringify(obj));
  return { status: 200, body };
}

module.exports = {
  handleRawRequest,
  verifySignature,
  signResponse,
  decide,
  proveDecision,
  VK_HASH_HEX,
};
