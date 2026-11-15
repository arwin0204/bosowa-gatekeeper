// Local standalone server for testing the gatekeeper (not used on Vercel).
// Usage: AGENT_GAMES_HMAC_SECRET=test-secret node server.js
// Then: curl -X POST localhost:3000/agent -d '<task json>' -H 'x-agent-games-signature: <hmac>'
const http = require("http");
const { handleRawRequest, signResponse } = require("./lib/gatekeeper");

const PORT = process.env.PORT || 3000;

const server = http.createServer(async (req, res) => {
  const started = Date.now();
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  const rawBody = Buffer.concat(chunks);
  console.log("REQ", req.method, req.url, "headers:", JSON.stringify(req.headers));
  console.log("BODY:", rawBody.toString("utf8").slice(0, 2000));
  if (req.method !== "POST") {
    const body = Buffer.from(
      JSON.stringify({ ok: true, status: "healthy", agent: "bosowa-gatekeeper" })
    );
    res.writeHead(200, { "content-type": "application/json" });
    return res.end(body);
  }
  const out = await handleRawRequest(rawBody, req.headers);
  const sig = signResponse(out.body);
  const headers = { "content-type": "application/json" };
  if (sig) headers["x-agent-games-signature"] = sig;
  res.writeHead(out.status, headers);
  res.end(out.body);
  console.log("RES", out.status, "ms:", Date.now() - started, "cached:", !!out.cached);
});

server.listen(PORT, () => {
  console.log(`bosowa-gatekeeper listening on http://localhost:${PORT}/agent`);
  console.log("HMAC secret configured:", !!process.env.AGENT_GAMES_HMAC_SECRET);
});
