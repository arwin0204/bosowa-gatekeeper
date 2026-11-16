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
  // K5 test page: serve the embedded /k5-b.html (no file dependency, so it
  // works in the Vercel bundle). Does not touch /api/agent or other routes.
  const K5_B_HTML = `<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>UJI K5 — Halaman B (Vercel)</title>
<style>
  body { font-family: sans-serif; max-width: 560px; margin: 60px auto; padding: 0 20px; }
  h1 { font-size: 22px; }
  label { display: block; margin: 18px 0 6px; font-weight: bold; }
  input { font-size: 20px; padding: 10px; width: 220px; letter-spacing: 4px; }
  .note { color: #555; margin-top: 20px; }
</style>
</head>
<body>
  <h1>UJI K5 — Halaman B</h1>
  <p>Halaman tes verifikasi (milik sendiri, bukan layanan sungguhan). Origin ini BERBEDA dari Halaman A. Masukkan kode verifikasi di bawah ini.</p>
  <form action="#" method="get" onsubmit="return false;">
    <label for="code">Enter verification code</label>
    <input id="code" name="code" type="text" inputmode="numeric" autocomplete="one-time-code" placeholder="6 digit" maxlength="6">
  </form>
  <p class="note">Halaman ini tidak pindah ke mana-mana.</p>
</body>
</html>`;
  if (req.method === "GET") {
    const urlPath = decodeURIComponent(req.url.split("?")[0]);
    if (urlPath === "/k5-b.html") {
      res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
      return res.end(K5_B_HTML);
    }
  }
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
