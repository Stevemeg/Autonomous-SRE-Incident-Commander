import { api, type Collection, type Incident } from "../../../lib/api";

type Evidence = { id: string; domain: string; provenance: string; content: Record<string, unknown>; quality_score: number | null; gathered_at: string };
type Hypothesis = { id: string; rank: number; statement: string; root_cause_class: string; confidence: number; status: string; remaining_gaps: string[] };
type Timeline = { id: string; sequence: number; occurred_at: string; category: string; summary: string };
type Action = { id: string; tool_name: string; reason: string; risk_tier: string; status: string; approval: string | null; verification: string | null };

export default async function IncidentRoom({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const [incident, evidence, hypotheses, timeline, actions] = await Promise.all([
    api<Incident>(`/incidents/${id}`), api<Collection<Evidence>>(`/incidents/${id}/evidence`),
    api<Collection<Hypothesis>>(`/incidents/${id}/hypotheses`), api<Collection<Timeline>>(`/incidents/${id}/timeline`),
    api<Collection<Action>>(`/incidents/${id}/actions`),
  ]);
  return <>
    <header className="page-header incident-heading"><div><p className="eyebrow">{incident.reference}</p><h1>{incident.title}</h1><p>{incident.status.replaceAll("_", " ")} · opened {new Date(incident.opened_at).toLocaleString()}</p></div><span className={`severity ${incident.severity}`}>{incident.severity.toUpperCase()}</span></header>
    <div className="command-grid">
      <section className="panel hypotheses"><div className="panel-title"><h2>Hypotheses</h2><span>{hypotheses.items.length}</span></div>{hypotheses.items.map((item) => <article key={item.id}><div className="rank">#{item.rank}</div><div><h3>{item.statement}</h3><p>{item.root_cause_class.replaceAll("_", " ")}</p><div className="confidence"><i style={{ width: `${item.confidence * 100}%` }} /></div><small>{Math.round(item.confidence * 100)}% confidence · {item.status}</small></div></article>)}</section>
      <section className="panel evidence"><div className="panel-title"><h2>Evidence</h2><span>{evidence.items.length}</span></div>{evidence.items.map((item) => <article key={item.id}><div><span className="domain">{item.domain}</span><span className="provenance">{item.provenance.replaceAll("_", " ")}</span></div><pre>{JSON.stringify(item.content, null, 2)}</pre></article>)}</section>
      <section className="panel timeline"><div className="panel-title"><h2>Timeline</h2><span>{timeline.items.length}</span></div>{timeline.items.map((item) => <article key={item.id}><time>{new Date(item.occurred_at).toLocaleTimeString()}</time><i /><div><strong>{item.category}</strong><p>{item.summary}</p></div></article>)}</section>
      <section className="panel actions"><div className="panel-title"><h2>Actions & approvals</h2><span>{actions.items.length}</span></div>{actions.items.map((item) => <article key={item.id}><div><span className={`risk ${item.risk_tier}`}>{item.risk_tier.toUpperCase()}</span><strong>{item.tool_name}</strong></div><p>{item.reason}</p><footer><span>{item.status.replaceAll("_", " ")}</span><span>Approval: {item.approval ?? "not decided"}</span><span>Verification: {item.verification ?? "pending"}</span></footer></article>)}</section>
    </div>
  </>;
}
