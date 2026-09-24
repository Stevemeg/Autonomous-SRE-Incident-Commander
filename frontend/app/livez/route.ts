// Frontend liveness: "is this Node process serving requests?" Deliberately independent of the
// API, database and any external service, so a backend outage never restarts the frontend.

export const dynamic = "force-dynamic";

export function GET(): Response {
  return Response.json({ status: "ok" }, { headers: { "cache-control": "no-store" } });
}
