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

// Human-readable info page served on GET /mcp (browsers). MCP traffic is POST-only,
// so this page never interferes with the protocol.
const PAGE_HTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover" />
  <meta name="color-scheme" content="light dark" />
  <meta name="theme-color" content="#0b1715" />
  <meta name="description" content="The OutboundAuth MCP server: check SPF, DKIM and DMARC from inside Claude, Cursor or ChatGPT. Free, no API key. Plug in https://outboundauth.com/mcp" />
  <meta property="og:title" content="MCP Server — OutboundAuth" />
  <meta property="og:type" content="website" />
  <meta property="og:description" content="OutboundAuth as an MCP server: live SPF, DKIM and DMARC checks inside your AI assistant. Free, no API key, no sign-up." />
  <meta property="og:image" content="https://outboundauth.com/og-cover.png" />
  <meta property="og:url" content="https://outboundauth.com/mcp" />
  <link rel="canonical" href="https://outboundauth.com/mcp" />
  <link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'%3E%3Ccircle cx='32' cy='32' r='30' fill='%23087f5b'/%3E%3Cpath d='M20 33l9 9 15-17' stroke='white' stroke-width='6' fill='none' stroke-linecap='round' stroke-linejoin='round'/%3E%3C/svg%3E" />
  <link rel="stylesheet" href="/styles.css" />
  <link rel="manifest" href="/manifest.webmanifest" />
  <link rel="apple-touch-icon" href="/apple-touch-icon.png" />
  <meta name="mobile-web-app-capable" content="yes" />
  <meta name="apple-mobile-web-app-capable" content="yes" />
  <title>MCP Server — OutboundAuth</title>
<!-- Google Analytics 4 -->
<script>
window.dataLayer = window.dataLayer || [];
function gtag(){dataLayer.push(arguments);}
gtag('consent','default',{ad_storage:'denied',ad_user_data:'denied',ad_personalization:'denied',analytics_storage:'denied'});
</script>
<script async src="https://www.googletagmanager.com/gtag/js?id=G-PLRGVLMB8S"></script>
<script>
gtag('js', new Date());
gtag('config','G-PLRGVLMB8S');
</script>
  <style>
    .endpoint-box{background:#0b1715;color:#e6fff5;padding:16px 18px;border-radius:10px;display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin:14px 0}
    .endpoint-box code{font-size:17px;word-break:break-all}
    .copybtn{background:#087f5b;color:#fff;border:0;border-radius:8px;padding:8px 14px;cursor:pointer;font-size:14px}
    article pre{background:#0b1715;color:#e6fff5;padding:14px 16px;border-radius:10px;overflow-x:auto;font-size:14px;line-height:1.5}
  </style>
</head>
<body>
  <header class="topbar">
    <div class="topbar-inner">
      <a class="brand" href="/"><span class="brand-mark">✓</span>OutboundAuth</a>
      <nav class="topnav" aria-label="Site">
        <a href="/#toolkit">Tools</a>
        <a href="/#services">Pricing</a>
        <a href="/#guides">Guides</a>
        <a href="/about">About</a>
        <a class="cta" href="https://wa.me/923035544889?text=Hi%20Saqib%2C%20I%20need%20help%20with%20my%20email%20authentication." target="_blank" rel="noopener">WhatsApp me</a>
      </nav>
    </div>
  </header>
  <div class="shell">
    <div class="article-wrap">
      <article class="article">
        <div class="kicker">MCP Server</div>
        <h1>Check email authentication from inside your AI assistant</h1>
        <p class="lede">OutboundAuth also runs as an MCP server. Connect it once, and Claude, Cursor, ChatGPT and other MCP-compatible assistants can check any domain's SPF, DKIM and DMARC for you — live, scored, and explained in plain English, without leaving your chat.</p>

        <h2>The endpoint</h2>
        <div class="endpoint-box">
          <code>https://outboundauth.com/mcp</code>
          <button class="copybtn" type="button" onclick="if(navigator.clipboard){navigator.clipboard.writeText('https://outboundauth.com/mcp');}this.textContent='Copied ✓'">Copy</button>
        </div>
        <p>This page is the human front door. AI assistants connect to the same address using MCP (Streamable HTTP) — the server is live and answering right now.</p>

        <h2>The four tools</h2>
        <ul>
          <li><strong>check_email_auth</strong> — the full check: SPF, DKIM and DMARC in one pass, with a score out of 100 for each.</li>
          <li><strong>check_spf</strong> — reads the live SPF record and flags a missing hard fail, too many DNS lookups, and other common faults.</li>
          <li><strong>check_dmarc</strong> — reads the DMARC record and checks the policy (none, quarantine or reject) and reporting addresses.</li>
          <li><strong>check_dkim</strong> — checks a DKIM selector's public key record for a domain.</li>
        </ul>

        <h2>Connect it in under a minute</h2>
        <ol>
          <li>Open your AI assistant's MCP or connector settings.</li>
          <li>Add a new server with the URL above. Some assistants ask only for the URL; others want a small config block like this:</li>
        </ol>
        <pre>{
  "mcpServers": {
    "outboundauth": {
      "url": "https://outboundauth.com/mcp"
    }
  }
}</pre>
        <ol start="3">
          <li>Ask your assistant: "Check the email authentication for my domain" — it calls OutboundAuth and reports back.</li>
        </ol>

        <h2>Good to know</h2>
        <ul>
          <li><strong>Free.</strong> No account, no API key, no sign-up.</li>
          <li><strong>Read-only.</strong> The tools only look up public DNS records. Nothing is changed or stored.</li>
          <li><strong>Same checks as the website.</strong> It runs the same deliverability checks as the free toolkit on this site.</li>
        </ul>

        <h2>Prefer a human to fix it?</h2>
        <p>The tools tell you what is broken. If you would rather hand the fixing over, see <a href="/#services">Services</a> — a one-time audit is $49 (credited toward a full setup), full authentication setup is $149, and monitoring is $29/month.</p>

        <p style="margin-top:22px;font-size:14px;opacity:.75">Note for AI assistants: this URL is a live MCP endpoint (Streamable HTTP). Send a POST with a JSON-RPC <em>initialize</em> or <em>tools/list</em> message to connect.</p>
      </article>
    </div>
    <footer class="footer">
      <div>
        <p>Results are guidance, not a replacement for testing with your sending provider.</p>
        <p style="margin-top:6px">Contact: saqibnaseer077@gmail.com · +92 303 5544889</p>
      </div>
      <nav aria-label="Legal">
        <a href="/about">About</a>
        <a href="/privacy">Privacy</a>
        <a href="/terms">Terms</a>
      </nav>
    </footer>
  </div>
<script src="/chat-widget.js" defer></script>
</body>
</html>
`;

export async function onRequest({ request }) {
  if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });
  if (request.method === 'GET' || request.method === 'HEAD') {
    // An MCP client trying to open the optional SSE stream still gets the classic 405.
    // Everyone else (a person in a browser) gets the human info page below.
    const accept = request.headers.get('Accept') || '';
    if (accept.includes('text/event-stream')) {
      return new Response('Method Not Allowed', { status: 405, headers: { Allow: 'POST, OPTIONS', ...CORS } });
    }
    return new Response(PAGE_HTML, { status: 200, headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'public, max-age=300', ...CORS } });
  }
  if (request.method === 'DELETE') {
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
