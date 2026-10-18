// OutboundAuth MCP server — stateless Streamable HTTP, zero dependencies.
// Exposes the site's proven deliverability checks (SPF / DKIM / DMARC / MX)
// as MCP tools any MCP-compatible assistant (Claude, Cursor, ChatGPT…) can call.
// Deploys as a Cloudflare Pages Function: functions/mcp.js  ->  https://outboundauth.com/mcp

const SERVER = { name: 'outboundauth', version: '1.0.0', title: 'OutboundAuth Deliverability' };
const PROTOCOLS = ['2025-06-18', '2025-03-26', '2024-11-05'];
const COMMON_DKIM_SELECTORS = ['google', 'selector1', 'selector2', 's1', 's2', 'k1', 'k2', 'mail', 'dkim', 'default'];

/* ---------------- domain + DNS helpers ---------------- */

function cleanDomain(raw) {
  const d = String(raw || '').trim().toLowerCase()
    .replace(/^https?:\/\//, '').replace(/^www\./, '')
    .split('/')[0].split('?')[0].split('#')[0].split(':')[0].trim();
  return /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*\.[a-z]{2,}$/.test(d) ? d : '';
}

function parseTags(record) {
  const tags = {};
  String(record || '').split(';').forEach(part => {
    const i = part.indexOf('=');
    if (i > 0) tags[part.slice(0, i).trim().toLowerCase()] = part.slice(i + 1).trim();
  });
  return tags;
}

async function dohOne(name, type, useCF) {
  const url = useCF
    ? 'https://cloudflare-dns.com/dns-query?name=' + encodeURIComponent(name) + '&type=' + type
    : 'https://dns.google/resolve?name=' + encodeURIComponent(name) + '&type=' + type;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 8000);
  try {
    const r = await fetch(url, {
      headers: useCF ? { Accept: 'application/dns-json' } : {},
      signal: controller.signal,
      cf: { cacheTtl: 300, cacheEverything: true },
    });
    if (!r.ok) return { ok: false };
    const j = await r.json();
    if (!j || typeof j.Status !== 'number') return { ok: false };
    if (j.Status !== 0) return { ok: true, answers: [] };
    const out = [];
    (j.Answer || []).forEach(a => {
      if (a && a.data != null) out.push({ t: a.type, d: String(a.data).replace(/"/g, '') });
    });
    return { ok: true, answers: out };
  } catch (e) {
    return { ok: false };
  } finally {
    clearTimeout(timer);
  }
}

async function doh(name, type) {
  const rs = await Promise.all([dohOne(name, type, true), dohOne(name, type, false)]);
  for (const r of rs) if (r.ok && r.answers.length) return r;
  for (const r of rs) if (r.ok) return r;
  return { ok: false };
}

/* ---------------- evaluation logic (ported from outboundauth.com) ---------------- */

function f(level, title, detail) { return { level, title, detail }; }

function evalSpf(answers, domain) {
  const findings = [];
  let points = 100;
  const rec = (answers || []).filter(a => a.t === 16 && /^v=spf1/i.test(a.d))[0];
  const txt = rec ? rec.d : null;
  if (!txt) {
    findings.push(f('bad', 'No SPF record published', 'No TXT record starting with v=spf1 was found for ' + domain + '.'));
    return { points: 25, findings, record: null };
  }
  const tokens = txt.split(/\s+/);
  findings.push(f('ok', 'SPF record found', 'The record begins with v=spf1.'));
  const endings = tokens.filter(t => /^[+?~-]?all$/i.test(t));
  const redirects = tokens.filter(t => /^redirect=/i.test(t));
  if (redirects.length > 1) {
    findings.push(f('bad', 'Multiple redirect modifiers', 'An SPF record must contain at most one redirect=.'));
    points -= 30;
  } else if (redirects.length === 1 && endings.length === 0) {
    findings.push(f('ok', 'Policy delegated via redirect', 'This record hands evaluation to ' + redirects[0].slice(9) + ' — the default policy is defined there, which is valid SPF.'));
  } else if (endings.length !== 1) {
    findings.push(f('bad', 'Default policy is missing or repeated', 'End the record with exactly one all mechanism (or a single redirect=).'));
    points -= 30;
  } else if (endings[0] === '-all') {
    findings.push(f('ok', 'Strong default policy', '-all tells receivers to fail unauthorized sources.'));
  } else if (endings[0] === '~all') {
    findings.push(f('warn', 'Soft-fail policy', '~all is fine for testing but weaker than -all.'));
    points -= 12;
  } else {
    findings.push(f('warn', 'Non-enforcing default policy', '?all or +all does not protect the domain from unauthorized senders.'));
    points -= 25;
  }
  const lookups = tokens.filter(t => /^(?:[+?~-])?(include:|a(?::|\/|$)|mx(?::|\/|$)|exists:|redirect=)/i.test(t));
  if (lookups.length <= 7) {
    findings.push(f('ok', 'DNS lookup count is safe', lookups.length + ' direct lookups declared; the limit is 10 including nested includes.'));
  } else if (lookups.length <= 10) {
    findings.push(f('warn', 'Close to the SPF lookup limit', lookups.length + ' direct lookups declared — nested includes may push it over 10.'));
    points -= 18;
  } else {
    findings.push(f('bad', 'Over the SPF lookup limit', lookups.length + ' direct lookups already exceed the limit of 10.'));
    points -= 45;
  }
  if (tokens.some(t => /^ptr(?::|$)/i.test(t))) {
    findings.push(f('warn', 'PTR mechanism found', 'PTR is slow and unreliable — avoid it.'));
    points -= 12;
  }
  return { points: Math.max(0, points), findings, record: txt };
}

function evalDmarc(answers, domain) {
  const findings = [];
  let points = 100;
  const rec = (answers || []).filter(a => a.t === 16 && /^\s*v=DMARC1/i.test(a.d))[0];
  const txt = rec ? rec.d : null;
  if (!txt) {
    findings.push(f('bad', 'No DMARC record published', 'No TXT record at _dmarc.' + domain + ' was found.'));
    return { points: 40, findings, record: null };
  }
  const tags = parseTags(txt);
  findings.push(f('ok', 'DMARC record found', 'Version tag v=DMARC1 is valid.'));
  const p = (tags.p || '').toLowerCase();
  if (p === 'reject') findings.push(f('ok', 'Reject policy enabled', 'Unauthenticated mail is requested to be rejected.'));
  else if (p === 'quarantine') findings.push(f('ok', 'Quarantine policy enabled', 'Unauthenticated mail is requested to be quarantined.'));
  else if (p === 'none') {
    findings.push(f('warn', 'Monitoring-only policy', 'p=none collects data but does not request enforcement.'));
    points -= 20;
  } else {
    findings.push(f('bad', 'Policy is missing or invalid', 'Add p=none, p=quarantine or p=reject.'));
    points -= 35;
  }
  if (tags.rua) findings.push(f('ok', 'Aggregate reports configured', 'DMARC reports are requested at the rua destination.'));
  else {
    findings.push(f('warn', 'No aggregate report inbox', 'Add rua=mailto:... to see who sends as your domain.'));
    points -= 10;
  }
  return { points: Math.max(0, points), findings, record: txt };
}

function evalDkimRecord(record, label) {
  const findings = [];
  let points = 100;
  const tags = parseTags(record);
  if (!tags.v || tags.v.toUpperCase() === 'DKIM1') {
    findings.push(f('ok', 'Version is acceptable', tags.v ? 'v=DKIM1 is present.' : 'DKIM1 is the default when the tag is omitted.'));
  } else {
    findings.push(f('bad', 'Unexpected DKIM version', 'Use v=DKIM1.'));
    points -= 30;
  }
  const keyType = (tags.k || 'rsa').toLowerCase();
  if (['rsa', 'ed25519'].includes(keyType)) findings.push(f('ok', 'Recognized key type', keyType + ' key declared.'));
  else {
    findings.push(f('warn', 'Unrecognized key type', 'Check the k= tag with your email provider.'));
    points -= 15;
  }
  if (tags.p === undefined || tags.p === '') {
    findings.push(f('bad', 'Public key is missing or revoked', 'The p= tag is empty at ' + label + '.'));
    points -= 45;
  } else if (/\s/.test(tags.p)) {
    findings.push(f('warn', 'Whitespace inside the key', 'Remove copied spaces or line breaks from the public key value.'));
    points -= 20;
  } else {
    findings.push(f('ok', 'Public key is present', tags.p.length + ' key characters found.'));
  }
  return { points: Math.max(0, points), findings };
}

async function lookupDkim(domain, selector) {
  const name = selector + '._domainkey.' + domain;
  const res = await doh(name, 'TXT');
  if (!res.ok) return { ok: false };
  const txt = (res.answers || []).filter(a => a.t === 16 && /\bp=/.test(a.d))[0];
  if (txt) return { ok: true, label: name, record: txt.d };
  const cname = (res.answers || []).filter(a => a.t === 5)[0];
  if (!cname) return { ok: true, found: false };
  const res2 = await doh(cname.d, 'TXT');
  if (!res2.ok) return { ok: false };
  const txt2 = (res2.answers || []).filter(a => a.t === 16 && /\bp=/.test(a.d))[0];
  return txt2 ? { ok: true, label: name + ' (via ' + cname.d + ')', record: txt2.d } : { ok: true, found: false };
}

function evalMx(answers) {
  const findings = [];
  const hosts = [];
  (answers || []).forEach(a => {
    if (a.t !== 15) return;
    const m = a.d.match(/^\s*(\d+)\s+(\S+)\.?$/);
    if (m) hosts.push({ pri: Number(m[1]), host: m[2].replace(/\.$/, '') });
  });
  hosts.sort((a, b) => a.pri - b.pri);
  if (!hosts.length) {
    findings.push(f('warn', 'No MX records found', 'This domain cannot receive email. Sending is still possible without MX records.'));
    return { points: 70, findings };
  }
  findings.push(f('ok', hosts.length + ' mail server' + (hosts.length > 1 ? 's' : '') + ' found',
    hosts.map(h => h.host + ' (priority ' + h.pri + ')').join(', ')));
  return { points: 100, findings };
}

function renderSection(title, result) {
  const verdict = result.points >= 85 ? 'looks good' : result.points >= 60 ? 'needs review' : 'needs attention';
  const lines = [title + ': ' + result.points + '/100 — ' + verdict];
  result.findings.forEach(x => {
    const mark = x.level === 'ok' ? '[OK]' : x.level === 'warn' ? '[WARN]' : '[FAIL]';
    lines.push('  ' + mark + ' ' + x.title + ' — ' + x.detail);
  });
  return lines.join('\n');
}

/* ---------------- MCP tools ---------------- */

const TOOLS = [
  {
    name: 'check_spf',
    title: 'Check SPF record',
    description: 'Look up the live SPF TXT record for a domain and evaluate it: version tag, default policy (-all vs ~all), the 10-DNS-lookup limit, PTR use. Returns a scored verdict with findings.',
    inputSchema: {
      type: 'object',
      properties: { domain: { type: 'string', description: 'Domain to check, e.g. example.com' } },
      required: ['domain'],
    },
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  },
  {
    name: 'check_dmarc',
    title: 'Check DMARC record',
    description: 'Look up the live DMARC TXT record at _dmarc.<domain> and evaluate it: policy (none/quarantine/reject), aggregate reporting (rua). Returns a scored verdict with findings.',
    inputSchema: {
      type: 'object',
      properties: { domain: { type: 'string', description: 'Domain to check, e.g. example.com' } },
      required: ['domain'],
    },
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  },
  {
    name: 'check_dkim',
    title: 'Check DKIM record',
    description: 'Look up the live DKIM TXT record for a selector (<selector>._domainkey.<domain>) and evaluate the key: version, key type, public key presence. Follows CNAMEs (e.g. Microsoft 365 / Google selectors).',
    inputSchema: {
      type: 'object',
      properties: {
        domain: { type: 'string', description: 'Domain to check, e.g. example.com' },
        selector: { type: 'string', description: 'DKIM selector, e.g. google, selector1, s1 (ask the email provider if unknown)' },
      },
      required: ['domain', 'selector'],
    },
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  },
  {
    name: 'check_email_auth',
    title: 'Full email authentication check',
    description: 'Run the complete deliverability authentication check for a domain: SPF, DMARC, DKIM (probes common selectors), and MX records. Returns a scored verdict per area plus an overall summary.',
    inputSchema: {
      type: 'object',
      properties: { domain: { type: 'string', description: 'Domain to check, e.g. example.com' } },
      required: ['domain'],
    },
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  },
];

async function callTool(name, args) {
  const rawDomain = args && args.domain;
  const domain = cleanDomain(rawDomain);
  if (!domain) throw new Error('Provide a valid domain, e.g. example.com (no http://, no paths).');

  if (name === 'check_spf') {
    const res = await doh(domain, 'TXT');
    if (!res.ok) throw new Error('Live DNS lookup failed — try again in a moment.');
    const r = evalSpf(res.answers, domain);
    let out = 'SPF check for ' + domain + '\n' + renderSection('SPF', r);
    if (r.record) out += '\nRecord: ' + r.record;
    return out;
  }

  if (name === 'check_dmarc') {
    const res = await doh('_dmarc.' + domain, 'TXT');
    if (!res.ok) throw new Error('Live DNS lookup failed — try again in a moment.');
    const r = evalDmarc(res.answers, domain);
    let out = 'DMARC check for ' + domain + '\n' + renderSection('DMARC', r);
    if (r.record) out += '\nRecord: ' + r.record;
    return out;
  }

  if (name === 'check_dkim') {
    const selector = String((args && args.selector) || '').trim().toLowerCase().replace(/[^a-z0-9-]/g, '');
    if (!selector) throw new Error('Provide the DKIM selector (e.g. google, selector1, s1).');
    const hit = await lookupDkim(domain, selector);
    if (!hit.ok) throw new Error('Live DNS lookup failed — try again in a moment.');
    if (!hit.found && !hit.record) {
      return 'DKIM check for ' + domain + '\nDKIM: 30/100 — needs attention\n  [FAIL] No DKIM record found — nothing published at ' + selector + '._domainkey.' + domain + '. Confirm the selector with the email provider.';
    }
    const r = evalDkimRecord(hit.record, hit.label);
    return 'DKIM check for ' + domain + ' (selector "' + selector + '")\n' + renderSection('DKIM', r) + '\nDNS host: ' + hit.label;
  }

  if (name === 'check_email_auth') {
    const [spfRes, dmarcRes, mxRes, dkimHits] = await Promise.all([
      doh(domain, 'TXT'),
      doh('_dmarc.' + domain, 'TXT'),
      doh(domain, 'MX'),
      Promise.all(COMMON_DKIM_SELECTORS.map(s => lookupDkim(domain, s).catch(() => ({ ok: false })))),
    ]);
    if (!spfRes.ok && !dmarcRes.ok && !mxRes.ok) {
      throw new Error('Live DNS lookup failed — try again in a moment.');
    }
    const spf = evalSpf(spfRes.ok ? spfRes.answers : null, domain);
    const dmarc = evalDmarc(dmarcRes.ok ? dmarcRes.answers : null, domain);
    const mx = evalMx(mxRes.ok ? mxRes.answers : null);
    const found = dkimHits.filter(h => h.ok && h.record);
    let dkimSection;
    if (!found.length) {
      dkimSection = 'DKIM: 50/100 — needs review\n  [WARN] No DKIM record found for common selectors — checked ' + COMMON_DKIM_SELECTORS.join(', ') + '. If the domain signs mail, use check_dkim with the exact selector.';
    } else {
      const r = evalDkimRecord(found[0].record, found[0].label);
      dkimSection = renderSection('DKIM (' + found[0].label + ')', r);
      if (found.length > 1) dkimSection += '\n  [OK] ' + found.length + ' selectors publish keys — ' + found.map(x => x.label).join(', ');
    }
    const overall = Math.round((spf.points + dmarc.points + mx.points) / 3);
    return [
      'Email authentication check for ' + domain + ' (by OutboundAuth — https://outboundauth.com)',
      '',
      renderSection('SPF', spf),
      '',
      renderSection('DMARC', dmarc),
      '',
      dkimSection,
      '',
      renderSection('MX', mx),
      '',
      'Overall: ' + overall + '/100 — ' + (overall >= 85 ? 'solid authentication posture' : overall >= 60 ? 'usable, with gaps to close' : 'weak — fix the failures above before sending at volume'),
    ].join('\n');
  }

  throw new Error('Unknown tool: ' + name);
}

/* ---------------- MCP Streamable HTTP transport (stateless) ---------------- */

const ok = (id, result) => ({ jsonrpc: '2.0', id, result });
const rpcErr = (id, code, message) => ({ jsonrpc: '2.0', id, error: { code, message } });

async function handleMessage(msg) {
  if (!msg || typeof msg !== 'object' || Array.isArray(msg)) return rpcErr(null, -32600, 'Invalid Request');
  const { id, method, params } = msg;
  if (typeof method === 'string' && method.startsWith('notifications/')) return undefined;
  switch (method) {
    case 'initialize': {
      const asked = params && params.protocolVersion;
      return ok(id, {
        protocolVersion: PROTOCOLS.includes(asked) ? asked : '2025-06-18',
        capabilities: { tools: { listChanged: false } },
        serverInfo: SERVER,
      });
    }
    case 'ping':
      return ok(id, {});
    case 'tools/list':
      return ok(id, { tools: TOOLS });
    case 'tools/call': {
      try {
        const text = await callTool(params && params.name, params && params.arguments);
        return ok(id, { content: [{ type: 'text', text }] });
      } catch (e) {
        return ok(id, { content: [{ type: 'text', text: 'Error: ' + (e && e.message ? e.message : String(e)) }], isError: true });
      }
    }
    default:
      return rpcErr(id, -32601, 'Method not found: ' + method);
  }
}

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'POST, GET, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Accept, Mcp-Session-Id, Mcp-Protocol-Version',
};

function jsonResponse(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', ...CORS },
  });
}

export async function onRequest({ request }) {
  if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });
  if (request.method === 'GET' || request.method === 'DELETE' || request.method === 'HEAD') {
    return new Response('Method Not Allowed', { status: 405, headers: { Allow: 'POST, OPTIONS', ...CORS } });
  }
  if (request.method !== 'POST') {
    return new Response('Method Not Allowed', { status: 405, headers: CORS });
  }
  let body;
  try {
    body = await request.json();
  } catch (e) {
    return jsonResponse(rpcErr(null, -32700, 'Parse error'), 400);
  }
  const msgs = Array.isArray(body) ? body : [body];
  const replies = [];
  for (const m of msgs) {
    const r = await handleMessage(m);
    if (r !== undefined) replies.push(r);
  }
  if (!replies.length) return new Response(null, { status: 202, headers: CORS });
  return jsonResponse(Array.isArray(body) ? replies : replies[0]);
}
