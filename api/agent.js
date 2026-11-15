// Vercel serverless handler for the Proof Gatekeeper endpoint.
// Route: POST /api/agent
// The response is HMAC-signed (x-agent-games-signature) when the
// AGENT_GAMES_HMAC_SECRET env var is set.
const { handleRawRequest, signResponse } = require("../lib/gatekeeper");

module.exports = async (req, res) => {
  const started = Date.now();
  try {
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const rawBody = Buffer.concat(chunks);
    console.log(
      JSON.stringify({
        event: "request",
        method: req.method,
        url: req.url,
        headers: req.headers,
        bodyPreview: rawBody.toString("utf8").slice(0, 2000),
        at: new Date().toISOString(),
      })
    );
    if (req.method !== "POST") {
      const body = Buffer.from(
        JSON.stringify({ ok: true, status: "healthy", agent: "bosowa-gatekeeper" })
      );
      res.setHeader("content-type", "application/json");
      return res.status(200).send(body);
    }
    const out = await handleRawRequest(rawBody, req.headers);
    const sig = signResponse(out.body);
    res.setHeader("content-type", "application/json");
    if (sig) res.setHeader("x-agent-games-signature", sig);
    console.log(
      JSON.stringify({
        event: "response",
        status: out.status,
        cached: !!out.cached,
        ms: Date.now() - started,
        at: new Date().toISOString(),
      })
    );
    return res.status(out.status).send(out.body);
  } catch (e) {
    console.error("handler error:", e && e.stack ? e.stack : e);
    const body = Buffer.from(
      JSON.stringify({ decision: 0, error: "internal-error" })
    );
    res.setHeader("content-type", "application/json");
    const sig = signResponse(body);
    if (sig) res.setHeader("x-agent-games-signature", sig);
    return res.status(200).send(body);
  }
};
