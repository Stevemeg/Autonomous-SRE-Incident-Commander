// Frontend readiness: useful traffic needs a ready API. The check is bounded by an explicit
// deadline and answers 503 quickly, so Kubernetes removes the pod from Service endpoints
// (never restarts it) while the backend is unavailable.
import { probeApi } from "../../lib/health";

export const dynamic = "force-dynamic";

export async function GET(): Promise<Response> {
  const api = await probeApi("/readyz");
  const ready = api.status === "up";
  return Response.json(
    { status: ready ? "ready" : "not_ready", dependencies: { api } },
    { status: ready ? 200 : 503, headers: { "cache-control": "no-store" } },
  );
}
