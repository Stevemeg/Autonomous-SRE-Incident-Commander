import { cookies } from "next/headers";

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

export async function api<T>(path: string): Promise<T> {
  const token = (await cookies()).get("asic_session")?.value;
  if (!token) throw new AuthenticationRequired("No authenticated dashboard session");
  const base = process.env.ASIC_API_BASE_URL ?? "http://127.0.0.1:8000/api/v1";
  const response = await fetch(`${base}${path}`, {
    headers: { Authorization: `Bearer ${token}` },
    cache: "no-store",
  });
  if (!response.ok) throw new Error(`API request failed with status ${response.status}`);
  return (await response.json()) as T;
}
