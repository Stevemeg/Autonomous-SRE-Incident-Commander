// Behavioral contract for the frontend health endpoints, run against the real production build
// (`npm run build` first). A fake API switches between healthy, refusing, erroring and hanging so
// the probes are exercised end to end through Next.js, not through mocks.
//
//   A. API healthy      -> /livez 200, /readyz 200
//   B. API unavailable  -> /livez 200, /readyz 503 quickly
//   C. API hangs        -> /livez 200, /readyz 503 within the explicit probe deadline
//   D. frontend frozen  -> /livez fails (POSIX SIGSTOP), and recovers on SIGCONT
import { spawn } from "node:child_process";
import { createServer } from "node:http";
import { existsSync } from "node:fs";
import { join } from "node:path";
import assert from "node:assert/strict";

const LIVENESS_TIMEOUT_MS = 2000; // Kubernetes livenessProbe.timeoutSeconds
const READINESS_TIMEOUT_MS = 3000; // Kubernetes readinessProbe.timeoutSeconds

let mode = "healthy";
const sockets = new Set();
const api = createServer((request, response) => {
  if (mode === "hang") return; // accept, never answer
  if (mode === "refuse") return request.socket.destroy();
  const ok = mode === "healthy";
  response.writeHead(ok ? 200 : 503, { "content-type": "application/json" });
  response.end(JSON.stringify({ status: ok ? "ready" : "not_ready", path: request.url }));
});
api.on("connection", (socket) => {
  sockets.add(socket);
  socket.on("close", () => sockets.delete(socket));
});
await new Promise((resolve) => api.listen(0, "127.0.0.1", resolve));
const apiPort = api.address().port;

const server = join(process.cwd(), ".next", "standalone", "server.js");
assert.ok(existsSync(server), "run `npm run build` before the health contract");
const port = 3900 + Math.floor(Math.random() * 90);
const frontend = spawn(process.execPath, [server], {
  env: {
    ...process.env,
    PORT: String(port),
    HOSTNAME: "127.0.0.1",
    NODE_ENV: "production",
    ASIC_API_BASE_URL: `http://127.0.0.1:${apiPort}/api/v1`,
  },
  stdio: ["ignore", "inherit", "inherit"],
});

async function get(path, timeoutMs) {
  const started = Date.now();
  try {
    const response = await fetch(`http://127.0.0.1:${port}${path}`, { signal: AbortSignal.timeout(timeoutMs) });
    const body = await response.json();
    return { status: response.status, body, ms: Date.now() - started };
  } catch (error) {
    return { status: 0, error: error.name, ms: Date.now() - started };
  }
}

function report(name, detail) {
  console.log(`PASS ${name}: ${JSON.stringify(detail)}`);
}

try {
  for (let attempt = 0; ; attempt++) {
    if ((await get("/livez", 1000)).status === 200) break;
    assert.ok(attempt < 60, "frontend did not start");
    await new Promise((resolve) => setTimeout(resolve, 500));
  }

  mode = "healthy";
  let live = await get("/livez", LIVENESS_TIMEOUT_MS);
  let ready = await get("/readyz", READINESS_TIMEOUT_MS);
  assert.equal(live.status, 200);
  assert.equal(ready.status, 200);
  assert.equal(ready.body.dependencies.api.status, "up");
  report("A api healthy", { livez: live.status, readyz: ready.status });

  for (const failure of ["refuse", "error"]) {
    mode = failure;
    live = await get("/livez", LIVENESS_TIMEOUT_MS);
    ready = await get("/readyz", READINESS_TIMEOUT_MS);
    assert.equal(live.status, 200, "liveness must not depend on the API");
    assert.equal(ready.status, 503);
    assert.ok(ready.ms < 1000, `unavailable API must fail fast (${ready.ms}ms)`);
    report(`B api ${failure}`, { livez: live.status, readyz: ready.status, readyz_ms: ready.ms, detail: ready.body.dependencies.api.detail });
  }

  mode = "hang";
  const [hungLive, hungReady] = await Promise.all([get("/livez", LIVENESS_TIMEOUT_MS), get("/readyz", READINESS_TIMEOUT_MS + 2000)]);
  assert.equal(hungLive.status, 200, "liveness must not wait on a hung API");
  assert.ok(hungLive.ms < 1000, `liveness stalled behind a hung API (${hungLive.ms}ms)`);
  assert.equal(hungReady.status, 503);
  assert.equal(hungReady.body.dependencies.api.detail, "timeout");
  assert.ok(hungReady.ms < READINESS_TIMEOUT_MS, `readiness exceeded the probe timeout (${hungReady.ms}ms)`);
  report("C api hangs", { livez: hungLive.status, livez_ms: hungLive.ms, readyz: hungReady.status, readyz_ms: hungReady.ms });
  for (const socket of sockets) socket.destroy();

  if (process.platform === "win32") {
    console.log("SKIP D frontend frozen: SIGSTOP is unavailable on Windows (runs on Linux CI)");
  } else {
    process.kill(frontend.pid, "SIGSTOP");
    const frozen = await get("/livez", LIVENESS_TIMEOUT_MS);
    process.kill(frontend.pid, "SIGCONT");
    assert.equal(frozen.status, 0, "a frozen frontend must fail liveness");
    const recovered = await get("/livez", LIVENESS_TIMEOUT_MS);
    assert.equal(recovered.status, 200);
    report("D frontend frozen", { livez: frozen.error, recovered: recovered.status });
  }
  console.log("frontend health contract: passed");
} finally {
  frontend.kill("SIGKILL");
  for (const socket of sockets) socket.destroy();
  api.close();
}
