import Link from "next/link";
import type { ReactNode } from "react";

export function Shell({ children }: { children: ReactNode }) {
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
        <div className="system-state"><i /> Policy engine online</div>
      </aside>
      <main>{children}</main>
    </div>
  );
}
