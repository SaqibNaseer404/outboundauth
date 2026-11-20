// functions/api/chat.js — Deliverability Copilot backend (Cloudflare Pages Functions)
// Same-origin API for /copilot. Proxies to Google Gemini (free tier,
// NATIVE :generateContent endpoint) with the API key kept server-side in the
// GEMINI_API_KEY secret.
// Deploy: "Add file → Upload files" in GitHub web UI, replacing the
// existing functions/api/chat.js (upload updates it in place).
// NOTE: Gemini free tier may use prompts to improve Google's models —
// the privacy page discloses this. Never promise "private" on this tier.
// Milestone 1 — Investigation Engine: live domain / bounce / header checks
// now run server-side and are injected into the prompt as evidence.

const SYSTEM_PROMPT = `You are the Deliverability Copilot, a friendly expert assistant on outboundauth.com, a free email deliverability toolkit. Your job: help people diagnose why their emails bounce, land in spam, or fail authentication (SPF, DKIM, DMARC).

VOICE: plain everyday English, short sentences, specific. Like a helpful friend who happens to be an expert — never corporate, never lecture-y. You may use simple analogies (SPF = guest list, DKIM = wax seal, DMARC = guard instructions). No jargon without an instant plain translation.

DIAGNOSIS PLAYBOOKS (use these, in this order):

1. If the user pastes a bounce / non-delivery message: read the 3-digit code and enhanced code FIRST.
   - 550 5.7.1 = rejected: authentication failure or policy block. Check SPF/DKIM/DMARC alignment and blacklists.
   - 550 5.1.1 / 5.1.2 = bad address: list hygiene problem, remove it.
   - 421 4.7.x = deferred / throttled: reputation or too much volume too fast — slow down, warm up, check complaint rates.
   - 552 = message too large or recipient mailbox full.
   Quote the exact line from their bounce that tells you this.

2. If the user pastes an Authentication-Results header: report each of spf / dkim / dmarc as pass or fail, in plain words.
   - All three pass with aligned domains = the gold standard.
   - dmarc=fail is what pushes mail toward spam or rejection.
   - softfail = SPF record ends in ~all (loose — needs tightening).
   - none = no record published for that check.
   - permerror on SPF = over the 10-DNS-lookup limit (see playbook 4).
   - temperror = DNS trouble, usually temporary — retry before changing anything.

3. Alignment check (the 3-way comparison): the visible From header vs the Return-Path (the envelope sender — this is what SPF actually checks) vs the d= tag in DKIM-Signature (who cryptographically signed it). If From says their domain but d= says someone else's, that is an unauthorised sender or spoofing — exactly what DMARC enforcement stops.

4. SPF permerror / intermittent failures: the SPF 10-DNS-lookup limit. include, mx, a, ptr, exists and redirect= each cost lookups; ip4, ip6 and all cost nothing. Includes NEST — a big provider's include can cost 4-5 lookups, not one. Treat 8 as the working maximum. The signature symptom: mail passes one day and fails the next, or breaks right after adding a new sending service. The fix is flattening: swap DNS-querying terms for plain ip4/ip6 ranges.

5. DMARC rollout order — never skip steps: p=none + rua tag first (1-2 weeks; read the reports — every receiving server becomes your informant), then p=quarantine with a pct ramp (10 → 50 → 100), then p=reject as the final destination (also required before a BIMI logo can display). Never jump to p=reject on day one.

6. "Why am I in spam?" — fix in this order: (1) Authentication first: SPF, DKIM, DMARC to enforcement. (2) Reputation: warm new domains gradually, keep bounce and complaint rates low, check blacklists. (3) List hygiene: verified addresses, remove chronic non-openers, make unsubscribing easy. (4) Content LAST: no subject-line tweak ever fixes broken authentication.

7. Gmail / Yahoo bulk-sender rules: SPF + DKIM + DMARC effectively required, one-click unsubscribe on marketing mail, keep complaint rates down.

RULES:
- Never invent DNS results. OutboundAuth runs live checks for you: when a block marked LIVE INVESTIGATION RESULTS is attached to the user's message, those are real results checked seconds ago — base your answer on them, give the verified facts first and your recommendations second, clearly separated, and never contradict or embellish them. When no such block is attached and you need their actual records, ask them for their domain (you can check it live) or tell them to run the free checker tools on outboundauth.com and paste the results back to you.
- Never ask for passwords, API keys, or credentials. Ever.
- Stay on email deliverability. For anything else, say briefly that you only do deliverability and offer to help with that instead.
- Keep answers focused: short paragraphs, numbered steps for fixes. No walls of text.
- When genuinely relevant, link ONE of these guides (clean URLs): /guides/spf-10-lookup-limit, /guides/dmarc-policies-none-quarantine-reject, /guides/email-headers-like-a-deliverability-pro, /guides/why-emails-go-to-spam, /guides/email-warmup-what-actually-works, /guides/dkim-explained, /guides/dmarc-guide, /guides/spf-explained, /guides/google-workspace-spf-dkim-dmarc-setup — or the free checker tools on the homepage.
- A $49 human deliverability audit exists for cases that truly need hands-on diagnosis. Mention it at most once per conversation, only when the problem genuinely needs a human, never pushy.`;

const MODELS = ["gemini-3.8-flash", "gemini-3.5-flash-lite"]; // fallback order; current GA models as of Oct 2026
const API_TIMEOUT_MS = 45000;

// Abuse guards — the free quota is shared across ALL visitors,
// so per-IP limits keep one bot from eating the day's budget.
const PER_IP_PER_HOUR = 10;
const GLOBAL_PER_DAY = 800;

const ipHits = new Map(); // ip -> array of timestamps (per isolate, approximate)
let dayCount = { date: "", count: 0 };

function todayUTC() {
  return new Date().toISOString().slice(0, 10);
}

function checkLimits(ip) {
  const today = todayUTC();
  if (dayCount.date !== today) dayCount = { date: today, count: 0 };
  if (dayCount.count >= GLOBAL_PER_DAY) return "daily";
  // Prune stale IP entries so the map can't grow forever (per isolate).
  if (ipHits.size > 5000) {
    const cutoff = Date.now() - 3600_000;
    for (const [k, v] of ipHits) {
      if (!v.some((t) => t > cutoff)) ipHits.delete(k);
    }
  }
  const now = Date.now();
  const hourAgo = now - 3600_000;
  const hits = (ipHits.get(ip) || []).filter((t) => t > hourAgo);
  if (hits.length >= PER_IP_PER_HOUR) return "ip";
  hits.push(now);
  ipHits.set(ip, hits);
  return null;
}

function recordGlobalHit() {
  const today = todayUTC();
  if (dayCount.date !== today) dayCount = { date: today, count: 0 };
  dayCount.count++;
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

/* ---------------- Investigation Engine ----------------
   The check code below is ported verbatim from functions/mcp.js, so the
   website, the MCP server and this Copilot all run the same engine. When
   the newest user message names a domain or pastes a bounce / raw email
   headers, the matching live check runs here, server-side, and its real
   results are attached to the message as evidence before the model
   answers (see buildEvidence at the end of this section). */

const COMMON_DKIM_SELECTORS = ['google', 'selector1', 'selector2', 's1', 's2', 'k1', 'k2', 'mail', 'dkim', 'default'];
const HEALTH_RBLS = ['zen.spamhaus.org', 'bl.spamcop.net', 'psbl.surriel.com', 'dnsbl-1.uceprotect.net', 'bl.mailspike.net', 'dnsbl.dronebl.org', 'ubl.unsubscore.com'];
const RBL_NAMES = {
  'zen.spamhaus.org': 'Spamhaus ZEN',
  'bl.spamcop.net': 'SpamCop',
  'psbl.surriel.com': 'PSBL',
  'dnsbl-1.uceprotect.net': 'UCEPROTECT L1',
  'bl.mailspike.net': 'Mailspike',
  'dnsbl.dronebl.org': 'DroneBL',
  'ubl.unsubscore.com': 'UBL (Unsubscore)',
};

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

/* ---------------- Stage 1 helpers: MX parsing, blacklists, bounce + header analysis ---------------- */

function parseMx(answers) {
  const hosts = [];
  (answers || []).forEach(a => {
    if (a.t !== 15) return;
    const m = a.d.match(/^\s*(\d+)\s+(\S+)\.?$/);
    if (m) hosts.push({ pri: Number(m[1]), host: m[2].replace(/\.$/, '') });
  });
  hosts.sort((a, b) => a.pri - b.pri);
  return hosts;
}

async function resolveIPv4(host) {
  const res = await doh(host, 'A');
  if (!res.ok) return null;
  const hit = (res.answers || []).filter(a => a.t === 1 && /^\d+\.\d+\.\d+\.\d+$/.test(a.d))[0];
  return hit ? hit.d : null;
}

async function resolveAny(host) {
  const [a, aaaa] = await Promise.all([doh(host, 'A'), doh(host, 'AAAA')]);
  const ips = [];
  if (a.ok) (a.answers || []).filter(x => x.t === 1).forEach(x => ips.push(x.d));
  if (aaaa.ok) (aaaa.answers || []).filter(x => x.t === 28).forEach(x => ips.push(x.d));
  return { ok: a.ok || aaaa.ok, ips };
}

// The IPs worth reputation-checking for a domain: its mail servers first
// (that is where its mail actually comes from), then the domain's own address.
async function ipsForDomain(domain, mxHosts) {
  const ips = [];
  for (const h of (mxHosts || [])) {
    const ip = await resolveIPv4(h.host);
    if (ip && !ips.includes(ip)) ips.push(ip);
    if (ips.length >= 5) break;
  }
  if (!ips.length) {
    const ip = await resolveIPv4(domain);
    if (ip) ips.push(ip);
  }
  return ips;
}

// Same 7 DNSBLs and the same listing rule as the website's health check:
// a 127.x answer (other than the 127.255.255.254 error sentinel) means listed.
async function checkIpBlacklists(ip) {
  const rev = ip.split('.').reverse().join('.');
  const results = await Promise.all(HEALTH_RBLS.map(async z => ({ zone: z, res: await doh(rev + '.' + z, 'A') })));
  const checked = [];
  const listed = [];
  results.forEach(({ zone, res }) => {
    if (!res.ok) return;
    checked.push(zone);
    const real = (res.answers || []).filter(a => a.t === 1 && /^127\./.test(a.d) && a.d !== '127.255.255.254');
    if (real.length) listed.push({ zone, codes: real.map(a => a.d) });
  });
  return { checked, listed };
}

async function evalBlacklist(domain, mxHosts) {
  const findings = [];
  const ips = await ipsForDomain(domain, mxHosts);
  if (!ips.length) {
    findings.push(f('warn', 'No IP address found to check', 'Neither the domain nor its mail servers have a public IPv4 address to test against the lists.'));
    return { points: null, findings, ips };
  }
  findings.push(f('ok', 'Checking ' + ips.length + ' IP' + (ips.length > 1 ? 's' : ''), ips.join(', ') + ' — resolved from the domain and its mail servers.'));
  let anyChecked = false;
  let anyListed = false;
  for (const ip of ips) {
    const r = await checkIpBlacklists(ip);
    if (r.checked.length) anyChecked = true;
    if (r.listed.length) {
      anyListed = true;
      r.listed.forEach(l => findings.push(f('bad', ip + ' is listed on ' + (RBL_NAMES[l.zone] || l.zone),
        l.zone + ' returned ' + l.codes.join(', ') + '. A listing drags mail into spam until it is removed — fix the cause first, then request delisting from the list operator.')));
    } else if (r.checked.length) {
      findings.push(f('ok', ip + ' is clean', 'Not listed on ' + r.checked.map(z => RBL_NAMES[z] || z).join(', ') + '.'));
    }
  }
  if (!anyChecked) {
    findings.push(f('warn', 'Blacklist check unavailable', 'The reputation lists could not be reached — try again later.'));
    return { points: null, findings, ips };
  }
  return { points: anyListed ? 20 : 100, findings, ips };
}

/* ---------------- Bounce analysis (knowledge base: the bounce-codes guide) ---------------- */

const BOUNCE_KB = [
  {
    match: (s, e, t) => e === '5.1.1' || /user unknown|unknown user|no such user|no such recipient|invalid recipient|recipient.*not found|mailbox (does ?n[o']t|does not) exist|addressee unknown/i.test(t),
    type: 'hard', title: 'The mailbox does not exist',
    meaning: 'The receiving server says there is no mailbox at that address — it was mistyped, the account was deleted, or it never existed.',
    cause: 'List quality — a bad address, not a fault in your sending setup.',
    fix: 'Remove the address from your list the same day and suppress it so it is never mailed again. If many addresses bounce this way after an import, clean or re-verify the whole list before sending more — repeated hard bounces damage your sender reputation.',
  },
  {
    match: (s, e, t) => e === '5.1.2' || /bad destination|domain.*(not found|does not exist|no such domain)|no mx (record|records)|unrouteable/i.test(t),
    type: 'hard', title: 'The recipient domain cannot receive mail',
    meaning: 'The domain in the address does not exist, or publishes no mail servers, so there is nowhere to deliver to.',
    cause: 'List quality — a mistyped or dead domain in the address.',
    fix: 'Check the domain spelling. If it is correct, the organisation has no working mail setup — remove the address and suppress it.',
  },
  {
    match: (s, e) => e === '5.2.2',
    type: 'hard', title: 'The mailbox is full (permanent)',
    meaning: 'The recipient mailbox is over its storage limit and the server has given up — the permanent version of a full-mailbox bounce.',
    cause: 'Recipient mailbox — nothing wrong on your side.',
    fix: 'Remove the address. A mailbox that stays full for good is effectively abandoned.',
  },
  {
    match: (s, e, t) => e === '4.2.2' || /mailbox full|over quota|insufficient (system )?storage|storage limit|quota exceeded/i.test(t),
    type: 'soft', title: 'The mailbox is full',
    meaning: 'The recipient mailbox has hit its storage limit, so the server cannot accept more mail right now.',
    cause: 'Recipient mailbox — temporary on the receiving side.',
    fix: 'Let your sending system retry for 2–3 days. If it never clears, treat the address as dead and remove it.',
  },
  {
    match: (s, e, t) => /^5\.7\./.test(e) || /blocked|block ?list|blacklist|dnsbl|spamhaus|spamcop|policy reasons|reputation/i.test(t),
    type: 'hard', title: 'Blocked for policy or reputation reasons',
    meaning: 'The receiving server refused the mail because of who is sending it — your IP or domain is on a blocklist, your reputation is poor, or your authentication failed their policy check.',
    cause: 'Reputation, policy or authentication — check the bounce text: if it names SPF, DKIM or DMARC, it is authentication; if it names a blocklist, it is reputation.',
    fix: 'Stop and investigate before sending more: run check_email_auth on your domain, run check_blacklists on your sending IP, and read the full bounce text for the named list or reason. Fix the cause, request delisting if listed, then restart at low volume.',
  },
  {
    match: (s, e, t) => /spam|content filter|message rejected as|looks like spam/i.test(t),
    type: 'hard', title: 'Rejected as spam-like content',
    meaning: 'The receiving filter judged the message itself — its content, links or sending pattern — to be spam.',
    cause: 'Content or reputation — the message tripped a spam filter.',
    fix: 'Check authentication first (a broken SPF, DKIM or DMARC record is a common trigger), then review the content: link-heavy or image-only mail and classic sales phrasing are the usual suspects. Test with a plainer version before resending.',
  },
  {
    match: (s, e, t) => e === '5.5.0' || (/relay/i.test(t) && /^5/.test(s)),
    type: 'hard', title: 'Relay denied / sending configuration error',
    meaning: 'A server refused to pass the message on — "relay not permitted" means the sending server tried to hand mail to a server that does not accept it from them.',
    cause: 'Sender configuration — a setup mistake on the sending side, not a list problem.',
    fix: 'Check the sending setup: the sending service must be authorised for your domain (it belongs in your SPF record), and SMTP credentials/host settings in your tool must match the provider.',
  },
  {
    match: (s) => s === '554',
    type: 'hard', title: 'Transaction failed (554)',
    meaning: 'A catch-all permanent rejection — the server will not say exactly why. It is commonly spam filtering or a failed SPF, DKIM or DMARC check.',
    cause: 'Policy or authentication in most cases.',
    fix: 'Read the full bounce message for any detail after the code, and run check_email_auth on your sending domain — a broken authentication record is a common trigger.',
  },
  {
    match: (s, e, t) => s === '421' || (/greylist|rate.?limit|too many|temporarily (unavailable|rejected|deferred)|try again later|server busy/i.test(t) && (s.charAt(0) === '4' || e.charAt(0) === '4')),
    type: 'soft', title: 'Temporary refusal — busy, rate-limited or greylisted',
    meaning: 'The receiving server could not accept the mail right now: it is busy, rate-limiting you, or greylisting (rejecting the first attempt from an unknown sender and accepting the retry a few minutes later).',
    cause: 'Temporary — usually the receiving server, or you are sending too fast.',
    fix: 'Your sending system should retry automatically and most of these clear on the second or third attempt. If they keep coming from the same provider, slow the volume down, spread the send over more time, and finish warmup before ramping up.',
  },
  {
    match: (s) => s === '450',
    type: 'soft', title: 'Requested action not taken (450)',
    meaning: 'A temporary deferral — often greylisting or a policy check the receiver wants to repeat later.',
    cause: 'Temporary — receiving side.',
    fix: 'Retry later; your sending system normally handles this on its own.',
  },
  {
    match: (s) => s === '451',
    type: 'soft', title: 'Local error in processing (451)',
    meaning: 'The receiving server hit a problem on its own side — a full queue or a temporary fault.',
    cause: 'Temporary — receiving server fault.',
    fix: 'Retry later. If every address at one provider returns 451 for days, the problem is theirs, not yours.',
  },
  {
    match: (s) => s === '452',
    type: 'soft', title: 'Insufficient system storage (452)',
    meaning: 'The receiving system is out of storage room — most often the recipient mailbox is full.',
    cause: 'Recipient mailbox or receiving server storage.',
    fix: 'Retry for a few days, then stop if it never clears and remove the address.',
  },
  {
    match: (s) => /^(500|501|503)\b/.test(s),
    type: 'hard', title: 'Syntax or command-sequence error',
    meaning: '500 is "command unrecognised", 501 is "syntax error in parameters" (often a malformed address) and 503 is "bad sequence of commands" — the sending server spoke in a way the receiver did not understand.',
    cause: 'Sender configuration — a setup problem, not a list problem.',
    fix: 'Check the address for typos or bad characters (501), and check your sending tool or server configuration. Normal senders rarely see these.',
  },
];

function analyzeBounce(rawText) {
  const text = String(rawText || '').trim();
  const enhMatch = text.match(/\b([245]\.\d{1,3}\.\d{1,3})\b/);
  const enhanced = enhMatch ? enhMatch[1] : '';
  const smtpMatch = text.match(/\b([245]\d\d)\b/);
  const smtp = smtpMatch ? smtpMatch[1] : '';
  const entry = BOUNCE_KB.filter(k => {
    try { return k.match(smtp, enhanced, text); } catch (e) { return false; }
  })[0];
  if (!entry) {
    if (/^5/.test(smtp) || /^5/.test(enhanced)) {
      return {
        smtp, enhanced, type: 'hard', title: 'Permanent failure (5xx)',
        meaning: 'A 5xx code means the server will not accept this mail until something changes — this is a hard bounce.',
        cause: 'Not identifiable from the code alone — the words in the bounce message name the cause.',
        fix: 'Read the full bounce message, not just the code, and remove the address from your list. If the wave started suddenly, check your authentication with check_email_auth and your IP with check_blacklists.',
      };
    }
    if (/^4/.test(smtp) || /^4/.test(enhanced)) {
      return {
        smtp, enhanced, type: 'soft', title: 'Temporary failure (4xx)',
        meaning: 'A 4xx code means the server could not accept the mail right now but might later — this is a soft bounce.',
        cause: 'Temporary — receiving side, in most cases.',
        fix: 'Let your sending system retry for 2–3 days. If one address keeps soft-bouncing for weeks, treat it as dead and remove it.',
      };
    }
    return null;
  }
  return { smtp, enhanced, type: entry.type, title: entry.title, meaning: entry.meaning, cause: entry.cause, fix: entry.fix };
}

/* ---------------- Email header analysis ---------------- */

function unfoldHeaders(text) {
  return String(text || '').replace(/\r\n/g, '\n').replace(/\n[ \t]+/g, ' ');
}

function headerField(text, name) {
  const m = text.match(new RegExp('^' + name + ':[ \\t]*([^\\n]*)', 'im'));
  return m ? m[1].trim() : null;
}

function domainOfAddress(value) {
  const m = String(value || '').match(/@([a-z0-9.-]+\.[a-z]{2,})/i);
  return m ? m[1].toLowerCase().replace(/[>)\s]+$/, '') : null;
}

function authSegment(source, name) {
  const parts = source.split(';');
  for (const p of parts) {
    const t = p.trim();
    if (new RegExp('^' + name + '=', 'i').test(t)) return t;
  }
  return '';
}

function analyzeHeaders(raw) {
  const text = unfoldHeaders(raw);
  const blocks = [];
  let m;
  const re = /^Authentication-Results:[ \t]*([^\n]*)/gim;
  while ((m = re.exec(text))) blocks.push(m[1]);
  const arcRe = /^ARC-Authentication-Results:[ \t]*([^\n]*)/gim;
  while ((m = arcRe.exec(text))) blocks.push(m[1]);
  const source = blocks.join(' ; ');

  const authFindings = [];
  let pass = 0;
  let anyResult = false;
  const aligned = {};
  ['spf', 'dkim', 'dmarc'].forEach(name => {
    const mm = source.match(new RegExp('\\b' + name + '=(pass|fail|softfail|neutral|none|temperror|permerror|policy)', 'i'));
    if (!mm) {
      authFindings.push(f('warn', name.toUpperCase() + ' result not found', 'This header may not include an Authentication-Results verdict for ' + name.toUpperCase() + '.'));
      return;
    }
    anyResult = true;
    const result = mm[1].toLowerCase();
    const seg = authSegment(source, name);
    let extra = '';
    if (name === 'spf') {
      const mf = seg.match(/(?:smtp\.)?mailfrom=@?([a-z0-9.-]+\.[a-z]{2,})/i);
      if (mf) { aligned.spf = mf[1].toLowerCase(); extra = ' Sending domain checked: ' + aligned.spf + '.'; }
    }
    if (name === 'dkim') {
      const dd = seg.match(/header\.d=([a-z0-9.-]+\.[a-z]{2,})/i) || seg.match(/header\.i=@?([a-z0-9.-]+\.[a-z]{2,})/i);
      if (dd) { aligned.dkim = dd[1].toLowerCase(); extra = ' Signing domain: ' + aligned.dkim + '.'; }
    }
    if (name === 'dmarc') {
      const hf = seg.match(/header\.from=([a-z0-9.-]+\.[a-z]{2,})/i);
      if (hf) { aligned.dmarc = hf[1].toLowerCase(); extra = ' From domain checked: ' + aligned.dmarc + '.'; }
      const pol = seg.match(/\(p=(none|quarantine|reject)\)/i);
      if (pol) extra += ' Domain policy applied: p=' + pol[1].toLowerCase() + '.';
    }
    if (result === 'pass') {
      pass++;
      authFindings.push(f('ok', name.toUpperCase() + ' passed', 'The receiving server recorded ' + name + '=pass.' + extra));
    } else {
      authFindings.push(f('bad', name.toUpperCase() + ' returned ' + result, 'Investigate the matching sender, domain and DNS configuration.' + extra));
    }
  });

  const pathFindings = [];
  const fromDomain = domainOfAddress(headerField(text, 'From'));
  const rpDomain = domainOfAddress(headerField(text, 'Return-Path'));
  if (fromDomain) pathFindings.push(f('ok', 'From domain is ' + fromDomain, 'This is the domain readers see and the one DMARC protects.'));
  if (rpDomain && fromDomain) {
    if (rpDomain === fromDomain) {
      pathFindings.push(f('ok', 'Return-Path matches the From domain', 'Bounces go back to the same domain that sent the message.'));
    } else {
      pathFindings.push(f('warn', 'Return-Path domain differs from the From domain', 'Return-Path is ' + rpDomain + ' but From is ' + fromDomain + '. Normal for bulk sending platforms (they handle bounces on their own domain) — a red flag only when authentication is also failing.'));
    }
  }
  if (aligned.dkim && fromDomain && aligned.dkim !== fromDomain) {
    pathFindings.push(f('warn', 'DKIM signing domain differs from the From domain', 'Signed by ' + aligned.dkim + ' for a message from ' + fromDomain + '. DMARC needs the signing domain to align with the From domain, or SPF alignment to carry the pass.'));
  }
  const hops = (text.match(/^Received:[ \t]/gim) || []).length;
  if (hops) pathFindings.push(f('ok', hops + ' Received hop' + (hops > 1 ? 's' : '') + ' in the chain', 'Each Received line is one server that handled the message on its way to the inbox.'));
  if (/^DKIM-Signature:/im.test(text)) pathFindings.push(f('ok', 'DKIM-Signature header present', 'The message was signed; the Authentication-Results verdict above says whether the signature verified.'));

  const points = anyResult ? Math.round(pass / 3 * 100) : 0;
  const verdict = !anyResult
    ? 'No Authentication-Results header found — paste the full raw headers (in Gmail: open the message, three dots, "Show original") and try again.'
    : pass === 3
      ? 'This message passed authentication cleanly — SPF, DKIM and DMARC all passed.'
      : pass === 0
        ? 'No passing verdicts found — treat this message (or this sending setup) with suspicion until the failures are explained.'
        : 'Some checks need attention — the failures above are what to investigate first.';
  return { points, anyResult, authFindings, pathFindings, verdict };
}

/* ---------------- Investigation: detection + evidence ---------------- */

// Mailbox providers and big platforms people mention in passing ("why does
// Gmail reject my mail?") — not their sending domain. They are only
// investigated when the message clearly asks for a check.
const PROVIDER_DOMAINS = new Set([
  'gmail.com', 'googlemail.com', 'yahoo.com', 'yahoo.co.uk', 'hotmail.com',
  'outlook.com', 'live.com', 'msn.com', 'icloud.com', 'me.com', 'aol.com',
  'proton.me', 'protonmail.com', 'gmx.com', 'google.com', 'microsoft.com',
  'apple.com', 'amazon.com', 'facebook.com', 'instagram.com', 'linkedin.com',
  'github.com', 'cloudflare.com', 'mxtoolbox.com', 'spamhaus.org',
  'x.com', 'twitter.com', 'youtube.com',
]);

// Tokens like "chat.js" or "report.pdf" are file names, not domains.
const FILE_TLDS = new Set([
  'js', 'mjs', 'json', 'html', 'htm', 'css', 'png', 'jpg', 'jpeg', 'gif',
  'svg', 'webp', 'txt', 'xml', 'pdf', 'zip', 'csv', 'ts', 'tsx', 'jsx',
  'php', 'asp', 'aspx', 'jsp', 'ico', 'mp4', 'mp3',
]);

const CHECK_INTENT = /\b(check|investigate|audit|scan|test|verify|health|report|status|lookup|look\s+up)\b/i;

function extractDomains(text) {
  const out = [];
  const re = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b/gi;
  let m;
  const s = String(text || '');
  while ((m = re.exec(s))) {
    const d = cleanDomain(m[0]);
    if (d && !out.includes(d)) out.push(d);
  }
  return out;
}

function pickDomain(text) {
  const domains = extractDomains(text).filter(
    (d) => !FILE_TLDS.has(d.split('.').pop())
  );
  if (!domains.length) return '';
  const own = domains.filter((d) => !PROVIDER_DOMAINS.has(d));
  if (own.length) return own[0];
  return CHECK_INTENT.test(text) ? domains[0] : '';
}

function looksLikeHeaders(text) {
  const t = String(text || '');
  if (/^Authentication-Results:/im.test(t)) return true;
  if (/^ARC-Authentication-Results:/im.test(t)) return true;
  if ((t.match(/^Received:[ \t]/gim) || []).length >= 2) return true;
  if (/^DKIM-Signature:/im.test(t) && /^From:[ \t]/im.test(t)) return true;
  return false;
}

function looksLikeBounce(text) {
  const t = String(text || '');
  if (/\b[245]\.\d{1,3}\.\d{1,3}\b/.test(t)) return true; // enhanced code, e.g. 5.7.1
  if (/(delivery status notification|undeliverable|delivery has failed|mail delivery failed|returned mail|failure notice)/i.test(t)) return true;
  if (
    /\b(421|450|451|452|550|551|552|553|554)\b/.test(t) &&
    /(bounce|undeliver|delivery|mailbox|recipient|smtp|rejected|blocked|spam|quota|relay|diagnostic-code|final-recipient|remote-mta|reporting-mta)/i.test(t)
  ) return true;
  if (/(user unknown|no such user|mailbox (full|does not exist|unavailable)|over quota|blocked using|relay (denied|not permitted))/i.test(t)) return true;
  return false;
}

function formatBounceEvidence(text) {
  const r = analyzeBounce(text);
  if (!r) return '';
  return [
    'Bounce analysis',
    'Code: ' + [r.smtp, r.enhanced].filter(Boolean).join(' ') + (r.smtp || r.enhanced ? '' : ' (from the message text)'),
    'Type: ' + (r.type === 'hard' ? 'Hard bounce — permanent failure' : 'Soft bounce — temporary failure'),
    'What it means: ' + r.title + '. ' + r.meaning,
    'Likely cause: ' + r.cause,
    'Fix: ' + r.fix,
    'Healthy bounce rate is under 2% for cold email; over 5% means stop, clean the list, and check your setup. Full guide: https://outboundauth.com/guides/email-bounce-codes-explained',
  ].join('\n');
}

function formatHeaderEvidence(headers) {
  const r = analyzeHeaders(headers);
  const lines = ['Header analysis', ''];
  lines.push(renderSection('Authentication', { points: r.points, findings: r.authFindings }));
  if (r.pathFindings.length) {
    lines.push('');
    lines.push('Sending path:');
    r.pathFindings.forEach(x => {
      const mark = x.level === 'ok' ? '[OK]' : x.level === 'warn' ? '[WARN]' : '[FAIL]';
      lines.push('  ' + mark + ' ' + x.title + ' — ' + x.detail);
    });
  }
  lines.push('');
  lines.push('Verdict: ' + r.verdict);
  return lines.join('\n');
}

// The same combined report as the MCP server's get_domain_health tool and
// the website's domain health report (same weights: SPF 30, DKIM 25,
// DMARC 25, MX 10, blacklists 10). Returns '' if DNS is unreachable, so
// the caller can fall back to plain chat.
async function investigateDomain(domain) {
  const [spfRes, dmarcRes, mxRes, dkimHits] = await Promise.all([
    doh(domain, 'TXT'),
    doh('_dmarc.' + domain, 'TXT'),
    doh(domain, 'MX'),
    Promise.all(COMMON_DKIM_SELECTORS.map(s => lookupDkim(domain, s).catch(() => ({ ok: false })))),
  ]);
  if (!spfRes.ok && !dmarcRes.ok && !mxRes.ok) return '';
  const spf = evalSpf(spfRes.ok ? spfRes.answers : null, domain);
  const dmarc = evalDmarc(dmarcRes.ok ? dmarcRes.answers : null, domain);
  const mxHosts = parseMx(mxRes.ok ? mxRes.answers : null);
  const mxSection = evalMx(mxRes.ok ? mxRes.answers : null);
  const found = dkimHits.filter(h => h.ok && h.record);
  let dkimPoints;
  let dkimSection;
  if (!found.length) {
    dkimPoints = 50;
    dkimSection = 'DKIM: 50/100 — needs review\n  [WARN] No DKIM record found for common selectors — checked ' + COMMON_DKIM_SELECTORS.join(', ') + '. The domain may still sign with a less common selector.';
  } else {
    const r = evalDkimRecord(found[0].record, found[0].label);
    dkimPoints = r.points;
    dkimSection = renderSection('DKIM (' + found[0].label + ')', r);
    if (found.length > 1) dkimSection += '\n  [OK] ' + found.length + ' selectors publish keys — ' + found.map(x => x.label).join(', ');
  }
  const bl = await evalBlacklist(domain, mxHosts);
  const blSection = bl.points === null
    ? 'Blacklists: not scored\n' + bl.findings.map(x => '  ' + (x.level === 'ok' ? '[OK]' : x.level === 'warn' ? '[WARN]' : '[FAIL]') + ' ' + x.title + ' — ' + x.detail).join('\n')
    : renderSection('Blacklists', bl);
  const parts = [
    { w: 30, p: spf.points }, { w: 25, p: dkimPoints }, { w: 25, p: dmarc.points }, { w: 10, p: mxSection.points },
  ];
  if (bl.points !== null && bl.points !== undefined) parts.push({ w: 10, p: bl.points });
  const totalW = parts.reduce((a, s) => a + s.w, 0);
  const overall = Math.round(parts.reduce((a, s) => a + s.p * s.w, 0) / totalW);
  const problems = [];
  [['SPF', spf.findings], ['DMARC', dmarc.findings], ['MX', mxSection.findings], ['Blacklists', bl.findings]].forEach(([label, fs]) => {
    fs.forEach(x => { if (x.level !== 'ok') problems.push({ label, level: x.level, title: x.title }); });
  });
  if (!found.length) problems.push({ label: 'DKIM', level: 'warn', title: 'No DKIM record found for common selectors' });
  problems.sort((a, b) => (a.level === b.level ? 0 : a.level === 'bad' ? -1 : 1));
  const lines = [
    'Domain health report for ' + domain,
    '',
    renderSection('SPF', spf),
    '',
    dkimSection,
    '',
    renderSection('DMARC', dmarc),
    '',
    renderSection('MX', mxSection),
    '',
    blSection,
    '',
    'Overall: ' + overall + '/100',
  ];
  if (spf.record) lines.push('SPF record: ' + spf.record);
  if (dmarc.record) lines.push('DMARC record: ' + dmarc.record);
  if (problems.length) {
    lines.push('');
    lines.push('Top problems:');
    problems.slice(0, 5).forEach((p, i) => lines.push('  ' + (i + 1) + '. [' + p.label + '] ' + p.title));
  } else {
    lines.push('');
    lines.push('Top problems: none found.');
  }
  return lines.join('\n');
}

function evidenceBlock(kind, bodyText) {
  return [
    '--- LIVE INVESTIGATION RESULTS (' + kind + ') ---',
    'OutboundAuth ran its real checker on this just now. These results are verified facts, not guesses.',
    bodyText,
    '--- END OF LIVE INVESTIGATION RESULTS ---',
    'Answer using these results: give the verified facts first, then your recommendations, clearly separated. Never contradict these results, and never invent results for anything they do not cover.',
  ].join('\n');
}

// Decide what (if anything) to investigate for one user message and return
// the evidence block to attach to it. '' means: no checks, plain chat.
async function buildEvidence(userText) {
  const text = String(userText || '');
  if (looksLikeHeaders(text)) {
    const h = formatHeaderEvidence(text);
    if (h) return evidenceBlock('email header analysis', h);
  }
  if (looksLikeBounce(text)) {
    const b = formatBounceEvidence(text);
    if (b) return evidenceBlock('bounce analysis', b);
  }
  const domain = pickDomain(text);
  if (domain) {
    const report = await investigateDomain(domain);
    if (report) return evidenceBlock('live domain investigation: ' + domain, report);
  }
  return '';
}

export async function onRequestGet() {
  return json({ ok: true, service: "deliverability-copilot" });
}

export async function onRequestPost(context) {
  const { request, env } = context;

  const ip =
    request.headers.get("cf-connecting-ip") ||
    request.headers.get("x-forwarded-for") ||
    "unknown";
  const limited = checkLimits(ip);
  if (limited === "ip") {
    return json(
      {
        error:
          "You've hit the hourly chat limit (10 messages). Take a coffee break and come back in a bit — or run the free checker tools on the homepage meanwhile.",
      },
      429
    );
  }
  if (limited === "daily") {
    return json(
      {
        error:
          "The copilot has answered a lot of questions today and is resting. Try again tomorrow — the free checker tools on the homepage still work right now.",
      },
      429
    );
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: "Bad request." }, 400);
  }
  const raw = Array.isArray(body.messages) ? body.messages.slice(-20) : [];
  const messages = raw
    .filter((m) => m && typeof m.content === "string" && m.content.trim())
    .map((m) => ({
      role: m.role === "assistant" ? "assistant" : "user",
      content: m.content.slice(0, 4000),
    }));
  if (!messages.length) return json({ error: "No message received." }, 400);

  if (!env.GEMINI_API_KEY) {
    return json({ error: "Copilot is not configured yet (missing API key)." }, 500);
  }

  const apiKey = env.GEMINI_API_KEY;

  // Convert chat history to Gemini's native format (roles: user/model).
  const contents = [];
  for (const m of messages) {
    if (m.role === "system") continue;
    const role = m.role === "assistant" ? "model" : "user";
    const text = m.content.slice(0, 4000);
    if (!text.trim()) continue;
    const last = contents[contents.length - 1];
    if (last && last.role === role) last.parts[0].text += "\n" + text;
    else contents.push({ role, parts: [{ text }] });
  }
  while (contents.length && contents[0].role !== "user") contents.shift();
  if (!contents.length) return json({ error: "No message received." }, 400);

  // Investigation Engine: run the live checks for the newest user message
  // and attach the results to the last user turn as evidence. Any failure
  // here just means no evidence — the chat continues exactly as before.
  const lastUser = messages.filter((m) => m.role === "user").pop();
  if (lastUser) {
    let evidence = "";
    try {
      evidence = await buildEvidence(lastUser.content);
    } catch {
      evidence = "";
    }
    if (evidence) {
      for (let i = contents.length - 1; i >= 0; i--) {
        if (contents[i].role === "user") {
          contents[i].parts[0].text += "\n\n" + evidence;
          break;
        }
      }
    }
  }

  let answerText = null;
  let lastStatus = 0;
  let diag = "";
  for (const model of MODELS) {
    try {
      const t0 = Date.now();
      const url =
        "https://generativelanguage.googleapis.com/v1beta/models/" +
        model +
        ":generateContent";
      const r = await fetch(url, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "x-goog-api-key": apiKey,
        },
        signal: AbortSignal.timeout(API_TIMEOUT_MS),
        body: JSON.stringify({
          system_instruction: { parts: [{ text: SYSTEM_PROMPT }] },
          contents,
          generationConfig: { temperature: 0.4, maxOutputTokens: 900 },
        }),
      });
      lastStatus = r.status;
      const ms = Date.now() - t0;
      if (r.ok) {
        const data = await r.json().catch(() => null);
        const cand =
          data && data.candidates && data.candidates[0] ? data.candidates[0] : null;
        const parts =
          cand && cand.content && Array.isArray(cand.content.parts)
            ? cand.content.parts
            : [];
        const text = parts.map((p) => p.text || "").join("");
        if (text.trim()) {
          answerText = text;
          break;
        }
        diag += model + ":empty-response:" + ms + "ms | ";
        continue;
      }
      const upBody = await r.text().catch(() => "");
      diag +=
        model + ":http" + r.status + ":" + ms + "ms:" + upBody.slice(0, 200) + " | ";
      // 400/404 (bad or retired model), 429 (quota) and 5xx (temporary
      // capacity trouble) are all worth trying the next model for —
      // quotas and capacity are per-model. Anything else fails fast.
    } catch (e) {
      lastStatus = -1;
      diag +=
        model +
        ":threw:" +
        (e && e.name ? e.name : "?") +
        ":" +
        (e && e.message ? e.message : e) +
        " | ";
      break;
    }
  }

  if (!answerText) {
    if (lastStatus === 429) {
      return json(
        {
          error:
            "Lots of people are asking questions right now. Try again in a few minutes.",
        },
        502
      );
    }
    return json(
      {
        error: "The AI service is unreachable right now. Try again in a minute.",
        diag: diag.slice(0, 500),
      },
      502
    );
  }
  recordGlobalHit();

  // Wrap the full answer as one SSE chunk so the existing frontend
  // streaming parser works unchanged, then [DONE].
  const sse =
    'data: {"choices":[{"delta":{"content":' +
    JSON.stringify(answerText) +
    "}}]}\n\ndata: [DONE]\n\n";
  return new Response(sse, {
    headers: {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache",
    },
  });
}
