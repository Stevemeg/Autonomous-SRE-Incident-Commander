// Backend reachability with explicit deadlines. Nothing here may inherit fetch's long
// default timeout: a hung or unreachable API must fail fast, never stall a render or probe.

export const API_PROBE_TIMEOUT_MS = 1500;

export function apiBaseUrl(): string {
  return process.env.ASIC_API_BASE_URL ?? "http://127.0.0.1:8000/api/v1";
}

export function apiRootUrl(): string {
  return apiBaseUrl().replace(/\/api\/v1\/?$/, "");
}

export type ProbeResult = { status: "up" | "down"; detail: string; elapsed_ms: number };

/** GET an API probe route; any error, non-2xx status or deadline expiry is "down". */
export async function probeApi(path: string, timeoutMs = API_PROBE_TIMEOUT_MS): Promise<ProbeResult> {
  const started = Date.now();
  try {
    const response = await fetch(`${apiRootUrl()}${path}`, {
      cache: "no-store",
      signal: AbortSignal.timeout(timeoutMs),
    });
    await response.body?.cancel();
    return {
      status: response.ok ? "up" : "down",
      detail: response.ok ? "ok" : `status ${response.status}`,
      elapsed_ms: Date.now() - started,
    };
  } catch (error) {
    const timedOut = error instanceof Error && error.name === "TimeoutError";
    return { status: "down", detail: timedOut ? "timeout" : "unreachable", elapsed_ms: Date.now() - started };
  }
}
