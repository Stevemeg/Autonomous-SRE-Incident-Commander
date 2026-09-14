import { Empty } from "../../components/empty";
import { api, type Collection } from "../../lib/api";

type Approval = { id: string; reason: string; tool_name: string; risk_tier: string; permission_scope: Record<string, unknown>; expected_effect: Record<string, unknown>; action_version_hash: string };

export default async function ApprovalsPage() {
  const data = await api<Collection<Approval>>("/approvals/pending");
  return <><header className="page-header"><div><p className="eyebrow">Human authority</p><h1>Pending approvals</h1><p>Every decision binds to this exact action version and current scope.</p></div><span className="count">{data.items.length} pending</span></header>
    {data.items.length === 0 ? <Empty title="Approval queue clear" detail="No bounded remediation action currently requires your authority." /> : <section className="approval-list">{data.items.map((item) => <article key={item.id}><header><span className={`risk ${item.risk_tier}`}>{item.risk_tier.toUpperCase()}</span><h2>{item.tool_name}</h2></header><p>{item.reason}</p><dl><div><dt>Scope</dt><dd>{JSON.stringify(item.permission_scope)}</dd></div><div><dt>Expected effect</dt><dd>{JSON.stringify(item.expected_effect)}</dd></div><div><dt>Version</dt><dd><code>{item.action_version_hash.slice(0, 16)}…</code></dd></div></dl><p className="decision-note">Decisions are submitted through the authenticated API client; this view never turns display text into authority.</p></article>)}</section>}
  </>;
}
