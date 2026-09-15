import Link from "next/link";
import type { ReactNode } from "react";
import { apiHealth } from "../lib/api";

export async function Shell({ children }: { children: ReactNode }) {
  const health = await apiHealth();
  return (
    <div className="app-shell">
      <aside>
        <Link className="brand" href="/">
          <span className="brand-mark">A</span>
          <span>ASIC</span>
        </Link>
        <nav aria-label="Primary navigation">
          <Link href="/">Incidents</Link>
          <Link href="/approvals">Approvals</Link>
        </nav>
        <div className="system-state"><i /> API health {health.toLowerCase()}</div>
      </aside>
      <main>{children}</main>
    </div>
  );
}
