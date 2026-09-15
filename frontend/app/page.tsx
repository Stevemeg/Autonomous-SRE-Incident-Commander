import Link from "next/link";
import { Empty } from "../components/empty";
import { api, AuthenticationRequired, type Collection, type Incident } from "../lib/api";

function age(timestamp: string) {
  const minutes = Math.max(0, Math.floor((Date.now() - new Date(timestamp).getTime()) / 60000));
  return minutes < 60 ? `${minutes}m` : `${Math.floor(minutes / 60)}h`;
}

export default async function IncidentsPage({ searchParams }: { searchParams: Promise<{ cursor?: string }> }) {
  const { cursor } = await searchParams;
  let data: Collection<Incident>;
  try {
    data = await api<Collection<Incident>>(`/incidents${cursor ? `?cursor=${encodeURIComponent(cursor)}` : ""}`);
  } catch (error) {
    if (error instanceof AuthenticationRequired) return <Empty title="Authentication required" detail="The trusted identity proxy must provide the secure asic_session cookie." />;
    throw error;
  }
  return <>
    <header className="page-header"><div><p className="eyebrow">Incident command</p><h1>Active incidents</h1><p>Evidence-led response across authorized environments.</p></div><span className="count">{data.items.length} visible</span></header>
    {data.items.length === 0 ? <Empty title="No incidents in scope" detail="New correlated alerts will appear here." /> :
      <section className="incident-grid">{data.items.map((incident) => <Link className="incident-card" href={`/incidents/${incident.id}`} key={incident.id}>
        <div className="card-top"><span className={`severity ${incident.severity}`}>{incident.severity.toUpperCase()}</span><span className="age">{age(incident.opened_at)}</span></div>
        <h2>{incident.title}</h2><p className="reference">{incident.reference}</p>
        <div className="card-bottom"><span className="status"><i />{incident.status.replaceAll("_", " ")}</span><span>View command room →</span></div>
      </Link>)}</section>}
    {data.next_cursor ? <p><Link href={`/?cursor=${encodeURIComponent(data.next_cursor)}`}>Next page →</Link></p> : null}
  </>;
}
