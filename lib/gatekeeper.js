// bosowa-gatekeeper — Proof Gatekeeper agent for zkVerify Agent Games.
// Agent: bosowa123 (X @bosowa123). Track: Proof Gatekeeper.
// Rule: if you cannot prove it, do not approve it. Fail closed, always.
//
// Real protocol (learned from the live practice task 2026-11-15 10:53 WIB):
//   Request envelope: { mode, type: "agent-games.proof-gatekeeper.v1",
//     input: { amount, minimum, proof_tx, proof_vk, recipient, expiry_block,
//       max_transfer, current_block, registered_vk, public_balance,
//       condition_recipient }, task_id, issued_at, deadline_at }
//   Task fields are snake_case, nested under "input"; task_id is top-level.
//   Response: { decision: "APPROVE"|"REJECT", reason_code: string,
//     task_id, proof?, publicSignals?, public_signals?, proofReference? }
//   Deadline per task is ~15s from issued_at — respond fast, keep warm.
// A retried taskId returns the byte-identical cached response (the salt is
// derived deterministically from the secret + task_id, so the proof itself
// is identical across instances). A reused proof_tx is REJECTED (fail
// closed) without a new proof.

const crypto = require("crypto");
const snarkjs = require("snarkjs");
const path = require("path");

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
// Accept both snake_case (real protocol) and camelCase (my earlier tests)
// for every field, and nesting under input/task/data/payload/envelope.
const FIELD_ALIASES = {
  minimum: ["minimum"],
  publicBalance: ["public_balance", "publicBalance"],
  expiryBlock: ["expiry_block", "expiryBlock"],
  currentBlock: ["current_block", "currentBlock"],
  recipient: ["recipient"],
  conditionRecipient: ["condition_recipient", "conditionRecipient"],
  amount: ["amount"],
  maxTransfer: ["max_transfer", "maxTransfer"],
  proofTx: ["proof_tx", "proofTx"],
  proofVk: ["proof_vk", "proofVk"],
  registeredVk: ["registered_vk", "registeredVk"],
};
const NEST_KEYS = ["input", "task", "data", "payload", "envelope", "request"];

function pickField(obj, aliases) {
  if (!obj || typeof obj !== "object") return undefined;
  for (const name of aliases) {
    if (obj[name] !== undefined) return obj[name];
  }
  return undefined;
}

function findTaskObject(body) {
  if (!body || typeof body !== "object") return null;
  const hasFields = (o) =>
    o &&
    typeof o === "object" &&
    (pickField(o, FIELD_ALIASES.minimum) !== undefined ||
      pickField(o, FIELD_ALIASES.amount) !== undefined ||
      pickField(o, FIELD_ALIASES.recipient) !== undefined);
  if (hasFields(body)) return body;
  for (const key of NEST_KEYS) {
    if (hasFields(body[key])) return body[key];
  }
  return null;
}

function toBigInt(value) {
  if (typeof value === "bigint") return value;
  if (typeof value === "number") return BigInt(Math.trunc(value));
  if (value === undefined || value === null) return null;
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

// Deterministic salt: HMAC(secret, "salt:"+taskId) mod the field prime.
// Same task_id always yields the same proof (byte-identical retries, even
// across function instances). Unpredictable without the secret.
function deterministicSalt(taskId) {
  const secret = process.env.AGENT_GAMES_HMAC_SECRET || "dev-salt-no-secret";
  const h = crypto
    .createHmac("sha256", secret)
    .update("salt:" + String(taskId === undefined ? "" : taskId))
    .digest();
  return (BigInt("0x" + h.toString("hex")) % FIELD_PRIME).toString();
}

// Normalize a raw request body into a canonical task (camelCase) or null.
function normalizeTask(body) {
  const raw = findTaskObject(body);
  if (!raw) return null;
  const task = {};
  for (const [canonical, aliases] of Object.entries(FIELD_ALIASES)) {
    const v = pickField(raw, aliases);
    if (v !== undefined) task[canonical] = v;
  }
  // task_id lives at the top level of the real envelope (snake_case).
  const topId =
    body.task_id !== undefined
      ? body.task_id
      : body.taskId !== undefined
        ? body.taskId
        : pickField(raw, ["task_id", "taskId"]);
  if (topId !== undefined) task.taskId = topId;
  return task;
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
  const proofVk = toBigInt(t.proofVk);
  const registeredVk = toBigInt(t.registeredVk);
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
    vkMatches:
      proofVk !== null &&
      registeredVk !== null &&
      proofVk === registeredVk,
  };
  // First failing check, in a stable order, gives the reason code.
  // Codes follow the official lists (agentgames.zkverify.io/rules
  // "CANONICAL REASON CODES" + the Proof Gatekeeper "Trap Encyclopedia"):
  // VALID_PROOF for approve; THRESHOLD_MISMATCH for balance < minimum;
  // AMOUNT_OVERFLOW for amount > cap; RECIPIENT_MISMATCH; EXPIRED_CONDITION;
  // VK_SUBSTITUTION for proof_vk != registered_vk.
  const order = [
    ["balanceMeetsMinimum", "THRESHOLD_MISMATCH"],
    ["amountWithinCap", "AMOUNT_OVERFLOW"],
    ["recipientMatches", "RECIPIENT_MISMATCH"],
    ["notExpired", "EXPIRED_CONDITION"],
    ["vkMatches", "VK_SUBSTITUTION"],
  ];
  for (const [key, code] of order) {
    if (!checks[key]) {
      return { decision: 0, checks, reasonCode: code };
    }
  }
  return { decision: 1, checks, reasonCode: "VALID_PROOF" };
}

// --------------------------------------------------------------- proof -----
async function proveDecision(t, decision) {
  const vkHash = BigInt(VK_HASH_HEX).toString();
  const registeredVk = toBigInt(t.registeredVk);
  const proofVk = toBigInt(t.proofVk);
  // vk inputs must mirror decide() exactly: if either side is missing,
  // decide() fails the vk check, so force a mismatch here too
  // (registered = tournament vk, proof = 0) so decision 0 stays provable.
  // If both are present, use their real values.
  let registeredVkHash;
  let proofVkHash;
  if (registeredVk !== null && proofVk !== null) {
    registeredVkHash = registeredVk.toString();
    proofVkHash = proofVk.toString();
  } else {
    registeredVkHash = vkHash;
    proofVkHash = "0";
  }
  // Missing numerics substitute 0 (never crash on null.toString()).
  // decide() already returned REJECT for any missing field, and 0-valued
  // inputs keep decision 0 consistent with the circuit (expiry 0 > 0 fails).
  const num = (v) => {
    const b = toBigInt(v);
    return (b !== null ? b : 0n).toString();
  };
  const input = {
    registeredVkHash,
    proofVkHash,
    minimum: num(t.minimum),
    publicBalance: num(t.publicBalance),
    expiryBlock: num(t.expiryBlock),
    currentBlock: num(t.currentBlock),
    recipient: num(t.recipient),
    conditionRecipient: num(t.conditionRecipient),
    amount: num(t.amount),
    maxTransfer: num(t.maxTransfer),
    decision: String(decision),
    taskId: taskIdToField(t.taskId),
    salt: deterministicSalt(t.taskId),
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
const seenProofTx = new Set(); // incoming proof_tx values already decided

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

  const task = normalizeTask(body);
  // No recognizable task fields: treat as a preflight / health check.
  if (!task) {
    return respond({ ok: true, protocolVersion: "v1" });
  }

  const taskId = task.taskId === undefined ? null : String(task.taskId);

  // 2. Replay: a retried taskId returns the byte-identical cached response.
  if (taskId && taskCache.has(taskId)) {
    return { status: 200, body: taskCache.get(taskId), cached: true };
  }

  // 3. A reused incoming proof_tx is a replay: REJECT, no new proof.
  // (The circuit cannot prove this REJECT — it is a JS-level fail-closed
  // check — so the response carries no proof, only the schema-valid fields.)
  const proofTx = task.proofTx === undefined ? null : String(task.proofTx);
  if (proofTx && seenProofTx.has(proofTx)) {
    return respondDecision({
      decision: "REJECT",
      reasonCode: "PROOF_REPLAY",
      proofTx,
      proof: null,
      taskId,
    });
  }
  if (proofTx) seenProofTx.add(proofTx);

  // 4. Decide deterministically, fail closed on any error.
  let d;
  try {
    d = decide(task);
  } catch {
    return respondDecision({
      decision: "REJECT",
      reasonCode: "PUBLIC_INPUT_MISMATCH",
      proofTx,
      proof: null,
      taskId,
    });
  }

  // 5. Prove the decision.
  let proofOut = null;
  try {
    proofOut = await proveDecision(task, d.decision);
  } catch (e) {
    // fullProve fails when the decision contradicts the circuit (wrong
    // approve / wrong reject). Fail closed: REJECT with a schema-valid
    // response and no proof. (A correct decision always proves; this path
    // should not happen when the JS decision mirrors the circuit.)
    console.error("prove failed:", e && e.message);
    return respondDecision({
      decision: "REJECT",
      reasonCode: "PROOF_INVALID",
      proofTx,
      proof: null,
      taskId,
    });
  }

  const res = respondDecision({
    decision: d.decision === 1 ? "APPROVE" : "REJECT",
    reasonCode: d.reasonCode,
    proofTx,
    proof: proofOut,
    taskId,
  });
  if (taskId) taskCache.set(taskId, res.body);
  return res;
}

function respond(obj) {
  const body = Buffer.from(JSON.stringify(obj));
  return { status: 200, body };
}

// Schema-valid protocol-v1 decision response. Matches the documented shape
// exactly: { decision, reason_code, proof?, public_signals, proof_tx? }.
// task_id is NOT part of the response (it lives only in the request
// envelope); proof_tx is echoed as the optional on-chain audit pointer.
// FIX 2026-11-17 (0 verified proofs in R03/R04 despite valid proofs):
// the response ALSO carries publicSignals (camelCase) and task_id, because
// the platform's competition-round verifier may read the camelCase key
// (the header comment above lists both spellings). Both spellings carry
// the identical array; task_id lets the platform match proof to task.
function respondDecision({ decision, reasonCode, proofTx, proof, taskId }) {
  const out = {
    decision,
    reason_code: reasonCode,
  };
  if (taskId !== null && taskId !== undefined) out.task_id = taskId;
  if (proof) {
    out.proof = proof.proof;
    out.public_signals = proof.publicSignals;
    out.publicSignals = proof.publicSignals;
  }
  if (proofTx !== null && proofTx !== undefined) out.proof_tx = proofTx;
  return respond(out);
}

module.exports = {
  handleRawRequest,
  verifySignature,
  signResponse,
  decide,
  proveDecision,
  normalizeTask,
  VK_HASH_HEX,
};
