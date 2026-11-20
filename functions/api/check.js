// OutboundAuth REST API — deploys as a Cloudflare Pages Function:
//   functions/api/check.js  ->  https://outboundauth.com/api/check
//
// The same deliverability engine as the MCP server (functions/mcp.js), exposed
// over plain HTTP + JSON for scripts, spreadsheets and other tools that do not
// speak MCP. Zero dependencies, read-only live DNS-over-HTTPS lookups; the
// check logic below is copied from mcp.js so both surfaces score identically.
// Nothing is stored.
//
// Usage:
//   GET  /api/check?domain=example.com               full domain health report
//   GET  /api/check?domain=example.com&part=dmarc    one section only:
//                                                    spf | dmarc | dkim | mx | blacklists
//   POST /api/check  {"code": "550 5.1.1"}           bounce analysis
//   POST /api/check  {"bounce_text": "<bounce>"}     bounce analysis
//   POST /api/check  {"headers": "<raw headers>"}    email header analysis
//
// All responses are JSON. Errors are JSON too — { "error": "..." } — with
// 400 for bad input, 404 for an unknown part, 405 for a wrong method and
// 502 when the live DNS lookup fails.
// v1 is free and needs no API key. Fair use: every call runs live DNS
// lookups, so cache on your side and do not hammer the endpoint. API keys
// and higher limits are planned for a later version.

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
const SOURCE = 'OutboundAuth — https://outboundauth.com';

/* ---------------- domain + DNS helpers (copied from functions/mcp.js) ---------------- */

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

/* ---------------- evaluation logic (copied from functions/mcp.js) ---------------- */

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

/* ---------------- MX parsing + blacklist helpers (copied from functions/mcp.js) ---------------- */

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

/* ---------------- Bounce analysis (copied from functions/mcp.js; knowledge base: the bounce-codes guide) ---------------- */

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

/* ---------------- Email header analysis (copied from functions/mcp.js) ---------------- */

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

/* ---------------- REST layer: JSON sections, reports, handlers ---------------- */

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Accept',
};

function jsonResponse(body, status = 200) {
  return new Response(JSON.stringify(body, null, 2), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', ...CORS },
  });
}

function errorResponse(status, message) {
  return jsonResponse({ error: message }, status);
}

function verdictFor(points) {
  if (points === null || points === undefined) return 'not scored';
  return points >= 85 ? 'looks good' : points >= 60 ? 'needs review' : 'needs attention';
}

function spfSection(r) {
  return { score: r.points, verdict: verdictFor(r.points), record: r.record, findings: r.findings };
}

function dmarcSection(r) {
  return { score: r.points, verdict: verdictFor(r.points), record: r.record, findings: r.findings };
}

function mxSection(answers) {
  const r = evalMx(answers);
  return {
    score: r.points,
    verdict: verdictFor(r.points),
    hosts: parseMx(answers).map(h => ({ priority: h.pri, host: h.host })),
    findings: r.findings,
  };
}

// `found` entries: { selector, hit } where hit is a lookupDkim() result with a record.
// Mirrors the DKIM section of the MCP get_domain_health tool, including the
// 50/100 "no key on common selectors" score when nothing is found.
function dkimSection(found) {
  if (!found.length) {
    return {
      score: 50,
      verdict: verdictFor(50),
      selectors_checked: COMMON_DKIM_SELECTORS,
      found: [],
      findings: [f('warn', 'No DKIM record found for common selectors',
        'Checked ' + COMMON_DKIM_SELECTORS.join(', ') + '. If the domain signs mail, ask the email provider for the exact selector and check that one directly.')],
    };
  }
  const r = evalDkimRecord(found[0].hit.record, found[0].hit.label);
  const findings = r.findings.slice();
  if (found.length > 1) {
    findings.push(f('ok', found.length + ' selectors publish keys', found.map(x => x.hit.label).join(', ')));
  }
  return {
    score: r.points,
    verdict: verdictFor(r.points),
    selectors_checked: COMMON_DKIM_SELECTORS,
    found: found.map(x => ({ selector: x.selector, host: x.hit.label, record: x.hit.record })),
    findings,
  };
}

function blacklistsSection(bl) {
  return { score: bl.points, verdict: verdictFor(bl.points), ips_checked: bl.ips, findings: bl.findings };
}

async function probeDkim(domain) {
  const results = await Promise.all(COMMON_DKIM_SELECTORS.map(async s => {
    try { return { selector: s, hit: await lookupDkim(domain, s) }; }
    catch (e) { return { selector: s, hit: { ok: false } }; }
  }));
  return results.filter(x => x.hit && x.hit.ok && x.hit.record);
}

// Full report — same sections, weights and problem list as the MCP
// get_domain_health tool: SPF 30, DKIM 25, DMARC 25, MX 10, blacklists 10.
async function buildFullReport(domain) {
  const [spfRes, dmarcRes, mxRes, dkimFound] = await Promise.all([
    doh(domain, 'TXT'),
    doh('_dmarc.' + domain, 'TXT'),
    doh(domain, 'MX'),
    probeDkim(domain),
  ]);
  if (!spfRes.ok && !dmarcRes.ok && !mxRes.ok) return null; // live DNS failed outright

  const spf = evalSpf(spfRes.ok ? spfRes.answers : null, domain);
  const dmarc = evalDmarc(dmarcRes.ok ? dmarcRes.answers : null, domain);
  const mxAnswers = mxRes.ok ? mxRes.answers : null;
  const mxHosts = parseMx(mxAnswers);
  const mx = mxSection(mxAnswers);
  const dkim = dkimSection(dkimFound);
  const bl = await evalBlacklist(domain, mxHosts);

  const parts = [
    { w: 30, p: spf.points }, { w: 25, p: dkim.score }, { w: 25, p: dmarc.points }, { w: 10, p: mx.score },
  ];
  if (bl.points !== null && bl.points !== undefined) parts.push({ w: 10, p: bl.points });
  const totalW = parts.reduce((a, s) => a + s.w, 0);
  const overall = Math.round(parts.reduce((a, s) => a + s.p * s.w, 0) / totalW);

  const problems = [];
  [['SPF', spf.findings], ['DMARC', dmarc.findings], ['MX', mx.findings], ['Blacklists', bl.findings]].forEach(([label, fs]) => {
    fs.forEach(x => { if (x.level !== 'ok') problems.push({ area: label, level: x.level, title: x.title }); });
  });
  if (!dkimFound.length) problems.push({ area: 'DKIM', level: 'warn', title: 'No DKIM record found for common selectors' });
  problems.sort((a, b) => (a.level === b.level ? 0 : a.level === 'bad' ? -1 : 1));

  return {
    domain,
    overall,
    verdict: overall >= 85 ? 'healthy — keep monitoring for quiet changes'
      : overall >= 60 ? 'usable, with gaps to close'
      : 'needs attention before sending at volume',
    spf: spfSection(spf),
    dkim,
    dmarc: dmarcSection(dmarc),
    mx,
    blacklists: blacklistsSection(bl),
    problems: problems.slice(0, 5),
    fix_order: 'Authentication first (SPF, then DKIM, then DMARC), then any blacklist listing, then MX issues.',
    source: SOURCE,
  };
}

const PARTS = ['spf', 'dmarc', 'dkim', 'mx', 'blacklists'];

async function handleGet(request) {
  const url = new URL(request.url);
  const domainRaw = url.searchParams.get('domain');
  if (!domainRaw || !domainRaw.trim()) {
    return errorResponse(400, 'Missing domain. Usage: GET /api/check?domain=example.com for the full report, or add &part=spf|dmarc|dkim|mx|blacklists for one section.');
  }
  const domain = cleanDomain(domainRaw);
  if (!domain) {
    return errorResponse(400, 'Provide a valid domain, e.g. example.com (no http://, no paths).');
  }
  const part = (url.searchParams.get('part') || '').trim().toLowerCase();
  if (part && !PARTS.includes(part)) {
    return errorResponse(404, 'Unknown part "' + part + '". Use one of: ' + PARTS.join(', ') + ' — or omit part for the full report.');
  }

  if (!part) {
    const report = await buildFullReport(domain);
    if (!report) return errorResponse(502, 'Live DNS lookup failed — try again in a moment.');
    return jsonResponse(report);
  }

  if (part === 'spf') {
    const res = await doh(domain, 'TXT');
    if (!res.ok) return errorResponse(502, 'Live DNS lookup failed — try again in a moment.');
    return jsonResponse({ domain, part, spf: spfSection(evalSpf(res.answers, domain)), source: SOURCE });
  }
  if (part === 'dmarc') {
    const res = await doh('_dmarc.' + domain, 'TXT');
    if (!res.ok) return errorResponse(502, 'Live DNS lookup failed — try again in a moment.');
    return jsonResponse({ domain, part, dmarc: dmarcSection(evalDmarc(res.answers, domain)), source: SOURCE });
  }
  if (part === 'dkim') {
    const found = await probeDkim(domain);
    return jsonResponse({ domain, part, dkim: dkimSection(found), source: SOURCE });
  }
  if (part === 'mx') {
    const res = await doh(domain, 'MX');
    if (!res.ok) return errorResponse(502, 'Live DNS lookup failed — try again in a moment.');
    return jsonResponse({ domain, part, mx: mxSection(res.answers), source: SOURCE });
  }
  // part === 'blacklists'
  const mxRes = await doh(domain, 'MX');
  const bl = await evalBlacklist(domain, mxRes.ok ? parseMx(mxRes.answers) : []);
  return jsonResponse({ domain, part, blacklists: blacklistsSection(bl), source: SOURCE });
}

async function handlePost(request) {
  let body;
  try {
    body = await request.json();
  } catch (e) {
    return errorResponse(400, 'Request body must be valid JSON.');
  }
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return errorResponse(400, 'POST a JSON object: {"bounce_text": "..."} or {"code": "550 5.1.1"} for bounce analysis, or {"headers": "..."} for header analysis.');
  }

  const bounceText = [body.code, body.bounce_text].filter(v => typeof v === 'string' && v.trim()).join(' ');
  if (bounceText) {
    const r = analyzeBounce(bounceText);
    if (!r) {
      return jsonResponse({
        type: 'bounce',
        found: false,
        message: 'No SMTP code (like 550 or 421) was found in what you pasted. Paste the full bounce message — the code and the sentence after it name the cause.',
        guide: 'https://outboundauth.com/guides/email-bounce-codes-explained',
        source: SOURCE,
      });
    }
    return jsonResponse({
      type: 'bounce',
      found: true,
      code: [r.smtp, r.enhanced].filter(Boolean).join(' ') || null,
      bounce_type: r.type,
      classification: r.type === 'hard' ? 'Hard bounce — permanent failure' : 'Soft bounce — temporary failure',
      title: r.title,
      meaning: r.meaning,
      likely_cause: r.cause,
      fix: r.fix,
      note: 'Healthy bounce rate is under 2% for cold email; over 5% means stop, clean the list, and check your setup.',
      guide: 'https://outboundauth.com/guides/email-bounce-codes-explained',
      source: SOURCE,
    });
  }

  if (typeof body.headers === 'string') {
    if (body.headers.trim().length < 20) {
      return errorResponse(400, 'Paste the full raw headers (in Gmail: open the message, click the three dots, then "Show original").');
    }
    const r = analyzeHeaders(body.headers);
    return jsonResponse({
      type: 'headers',
      score: r.points,
      authentication: r.authFindings,
      sending_path: r.pathFindings,
      verdict: r.verdict,
      source: SOURCE,
    });
  }

  return errorResponse(400, 'Nothing to analyse. POST {"bounce_text": "..."} or {"code": "550 5.1.1"} for bounce analysis, or {"headers": "..."} for header analysis.');
}

export async function onRequest({ request }) {
  if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });
  if (request.method === 'GET') return handleGet(request);
  if (request.method === 'POST') return handlePost(request);
  return errorResponse(405, 'Method not allowed. Use GET for domain checks and POST for bounce or header analysis.');
}
