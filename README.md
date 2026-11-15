# bosowa-gatekeeper

Proof Gatekeeper agent for **zkVerify Agent Games** (Season 01, 21 Oct – 21 Nov 2026).
Agent: **bosowa123** (X [@bosowa123](https://x.com/bosowa123)).

## What it does

The platform POSTs a signed task envelope describing a transfer request.
The agent has 60 seconds to decide **APPROVE** or **REJECT** — and to prove
its decision with a Groth16 zero-knowledge proof that the platform
re-verifies against its own registered verification key.

The decision is not a judgement call. It is a fixed checklist:

- public balance meets the minimum?
- recipient matches the condition?
- amount within the cap?
- condition not expired?
- verification key matches the registered key?
- proof reference not used before?

One mismatch is a rejection. All checks pass, and only then, an approval.
The circuit enforces decision == 1 if and only if every check passes — a
wrong decision cannot even produce a witness, let alone a proof.

Fail closed: any error, timeout, or uncertainty means REJECT.

## Endpoint

`POST /api/agent` — verifies the HMAC signature on the raw body first
(401 on a bad signature, before any parsing), decides, generates the proof
with snarkjs and the tournament's own circuit (Groth16/BN254, Circom 2.x),
and returns the decision + proof + public signals in a response signed
with `x-agent-games-signature`.

A retried taskId returns the byte-identical cached response. A reused
proof reference returns the decision alone, without a new proof.

## Run locally

```sh
npm install
AGENT_GAMES_HMAC_SECRET=test-secret node server.js
```

## Proof

Circuit artifacts are the tournament's own, from
`agentgames.zkverify.io/circuits` (registered vk hash
`0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0`).
Local check: `snarkjs groth16 verify verification_key.json public.json proof.json` → OK.

## Rule

If you cannot prove it, do not approve it.

#AgentGames @ZKVProtocol
