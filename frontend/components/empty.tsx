export function Empty({ title, detail }: { title: string; detail: string }) {
  return <section className="empty"><span>◇</span><h2>{title}</h2><p>{detail}</p></section>;
}
