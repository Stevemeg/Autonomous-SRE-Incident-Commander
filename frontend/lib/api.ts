import { cookies } from "next/headers";
import { apiBaseUrl, probeApi } from "./health";

export type Incident = {
  id: string;
  reference: string;
  title: string;
  severity: string;
  status: string;
  opened_at: string;
  environment_id: string;
};

export type Collection<T> = { items: T[]; next_cursor?: string | null };

export class AuthenticationRequired extends Error {}

/** Upper bound for an authenticated data request; a hung API must not hang a page render. */
export const API_REQUEST_TIMEOUT_MS = 10000;

export async function apiHealth(): Promise<"ONLINE" | "UNKNOWN"> {
  return (await probeApi("/healthz")).status === "up" ? "ONLINE" : "UNKNOWN";
}

export async function api<T>(path: string): Promise<T> {
  const token = (await cookies()).get("asic_session")?.value;
  if (!token) throw new AuthenticationRequired("No authenticated dashboard session");
  const response = await fetch(`${apiBaseUrl()}${path}`, {
    headers: { Authorization: `Bearer ${token}` },
    cache: "no-store",
    signal: AbortSignal.timeout(API_REQUEST_TIMEOUT_MS),
  });
  if (!response.ok) throw new Error(`API request failed with status ${response.status}`);
  return (await response.json()) as T;
}
