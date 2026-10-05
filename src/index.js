import { createHash } from 'node:crypto';
const hash = value => createHash('sha256').update(value).digest('hex').slice(0, 12);
const header = (headers = [], name) => headers.find(x => String(x.name).toLowerCase() === name.toLowerCase())?.value;
const resource = request => { const u = new URL(request.url); const method = request.method || 'GET'; return { key: hash(`${method} ${u.href.split('#')[0]}`), endpoint: `${method} ${u.origin}${u.pathname}` }; };
const bodyId = content => hash(`${content.encoding || 'text'}:${content.text}`);
const etagId = value => hash(String(value));
export function analyze(har) {
  const entries = har?.log?.entries;
  if (!Array.isArray(entries)) throw new Error('input is not a HAR with log.entries');
  const groups = new Map(), findings = []; let observedCount = 0;
  for (const entry of entries) {
    const status = entry.response?.status, etag = header(entry.response?.headers, 'etag'), content = entry.response?.content, res = resource(entry.request);
    if (status === 304 && !header(entry.request?.headers, 'if-none-match')) findings.push({ type: 'unconditional-304', resource: res.key, endpoint: res.endpoint });
    if (![200, 203, 206].includes(status) || etag == null || typeof content?.text !== 'string') continue;
    observedCount++;
    const g = groups.get(res.key) || { resource: res.key, endpoint: res.endpoint, etags: new Map(), bodies: new Map() }, e = etagId(etag), b = bodyId(content);
    if (!g.etags.has(e)) g.etags.set(e, new Set()); if (!g.bodies.has(b)) g.bodies.set(b, new Set());
    g.etags.get(e).add(b); g.bodies.get(b).add(e); groups.set(res.key, g);
  }
  for (const g of groups.values()) {
    for (const [etag, bodies] of g.etags) if (bodies.size > 1) findings.push({ type: 'etag-collision', resource: g.resource, endpoint: g.endpoint, etagFingerprint: etag, bodyCount: bodies.size });
    for (const [body, etags] of g.bodies) if (etags.size > 1) findings.push({ type: 'etag-churn', resource: g.resource, endpoint: g.endpoint, bodyFingerprint: body, etagCount: etags.size });
  }
  findings.sort((a, b) => a.endpoint.localeCompare(b.endpoint) || a.type.localeCompare(b.type));
  const counts = Object.fromEntries([...new Set(findings.map(x => x.type))].sort().map(type => [type, findings.filter(x => x.type === type).length]));
  return { entryCount: entries.length, observedCount, resourceCount: groups.size, findingCount: findings.length, counts, findings };
}
