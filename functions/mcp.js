// OutboundAuth MCP server — stateless Streamable HTTP, zero dependencies.
// Exposes the site's proven deliverability checks (SPF / DKIM / DMARC / MX)
// as MCP tools any MCP-compatible assistant (Claude, Cursor, ChatGPT…) can call.
// Deploys as a Cloudflare Pages Function: functions/mcp.js  ->  https://outboundauth.com/mcp

const SERVER = { name: 'outboundauth', version: '1.2.0', title: 'OutboundAuth Deliverability' };
const PROTOCOLS = ['2025-06-18', '2025-03-26', '2024-11-05'];
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

/* ---------------- MX health ---------------- */

function guessProvider(hosts) {
  const all = hosts.map(h => h.host.toLowerCase()).join(' ');
  if (/aspmx|gmail-smtp-in|googlemail\.com/.test(all)) return 'Google Workspace';
  if (/mail\.protection\.outlook\.com/.test(all)) return 'Microsoft 365';
  if (/zoho/.test(all)) return 'Zoho Mail';
  if (/proton/.test(all)) return 'Proton Mail';
  if (/messagingengine\.com|fastmail/.test(all)) return 'Fastmail';
  if (/yahoodns|yahoo/.test(all)) return 'Yahoo Mail';
  if (/amazonaws\.com/.test(all)) return 'Amazon (SES / WorkMail)';
  if (/pphosted\.com|proofpoint/.test(all)) return 'Proofpoint';
  if (/mimecast/.test(all)) return 'Mimecast';
  if (/iphmx\.com/.test(all)) return 'Cisco IronPort';
  return null;
}

async function evalMxHealth(domain, mxAnswers) {
  const findings = [];
  let points = 100;
  const hosts = parseMx(mxAnswers);
  if (!hosts.length) {
    findings.push(f('warn', 'No MX records found', 'This domain cannot receive email. Sending is still possible without MX records, but replies and bounces have nowhere to land.'));
    return { points: 70, findings, hosts };
  }
  findings.push(f('ok', hosts.length + ' mail server' + (hosts.length > 1 ? 's' : '') + ' found',
    hosts.map(h => h.host + ' (priority ' + h.pri + ')').join(', ')));
  const provider = guessProvider(hosts);
  if (provider) findings.push(f('ok', 'Mail provider looks like ' + provider, 'Recognised from the MX hostnames.'));
  const pris = hosts.map(h => h.pri);
  if (new Set(pris).size !== pris.length) {
    findings.push(f('warn', 'Duplicate MX priorities', 'Two or more servers share a priority — valid, but distinct priorities make the failover order clearer.'));
    points -= 5;
  }
  if (hosts.length === 1) {
    findings.push(f('warn', 'Only one mail server', 'If it goes down, incoming mail queues or bounces — a second MX record adds resilience.'));
    points -= 5;
  }
  for (const h of hosts) {
    if (h.host === 'localhost' || /^127\./.test(h.host)) {
      findings.push(f('bad', 'MX points at localhost', h.host + ' can never receive mail from the internet.'));
      points -= 40;
      continue;
    }
    if (h.host === domain) {
      findings.push(f('warn', 'MX points at the domain itself', 'Fine if the root host really runs a mail server — otherwise point MX at a dedicated mail hostname.'));
      points -= 5;
    }
    const r = await resolveAny(h.host);
    if (!r.ok) {
      findings.push(f('warn', 'Could not verify ' + h.host, 'The DNS lookup failed while checking this host, so its result is unverified.'));
      continue;
    }
    if (!r.ips.length) {
      findings.push(f('bad', 'Mail server does not resolve', h.host + ' has no A or AAAA record — mail addressed to it will bounce.'));
      points -= 30;
    } else {
      findings.push(f('ok', h.host + ' resolves', 'Reachable at ' + r.ips.slice(0, 3).join(', ') + (r.ips.length > 3 ? ' and more' : '') + '.'));
    }
  }
  return { points: Math.max(0, points), findings, hosts };
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

/* ---------------- DMARC core (shared with the web page) ---------------- */

/* ============================================================
   OutboundAuth — DMARC aggregate report core (shared)
   One parsing + analysis core used by:
     - the DMARC Report Analyzer web page (runs in the browser)
     - the analyze_dmarc_report MCP tool
   Environment-free: no DOM, no Node APIs, no network.
   ============================================================ */

function dmarcParseXml(xml) {
  if (typeof xml !== 'string') throw new Error('Report content is not text.');
  var pos = 0, len = xml.length;
  var root = null, stack = [];

  function fail(msg) { throw new Error('Could not parse the XML report: ' + msg); }
  function current() { return stack.length ? stack[stack.length - 1] : null; }
  function decodeEntities(s) {
    return s.replace(/&(#x?[0-9a-fA-F]+|amp|lt|gt|quot|apos);/g, function (m, e) {
      if (e === 'amp') return '&';
      if (e === 'lt') return '<';
      if (e === 'gt') return '>';
      if (e === 'quot') return '"';
      if (e === 'apos') return "'";
      var code = (e.charAt(1) === 'x' || e.charAt(1) === 'X')
        ? parseInt(e.slice(2), 16)
        : parseInt(e.slice(1), 10);
      return isNaN(code) ? m : String.fromCodePoint(code);
    });
  }
  function addText(t) {
    var c = current();
    if (c) c.text += t;
    else if (t.trim()) fail('text outside the root element');
  }
  function findTagEnd(s, lt) {
    var q = null;
    for (var j = lt + 1; j < s.length; j++) {
      var ch = s.charAt(j);
      if (q) { if (ch === q) q = null; }
      else if (ch === '"' || ch === "'") q = ch;
      else if (ch === '>') return j;
    }
    return -1;
  }

  while (pos < len) {
    var lt = xml.indexOf('<', pos);
    if (lt === -1) { addText(decodeEntities(xml.slice(pos))); pos = len; break; }
    if (lt > pos) addText(decodeEntities(xml.slice(pos, lt)));

    if (xml.indexOf('<!--', lt) === lt) {
      var endC = xml.indexOf('-->', lt + 4);
      if (endC === -1) fail('unterminated comment');
      pos = endC + 3;
    } else if (xml.indexOf('<![CDATA[', lt) === lt) {
      var endCd = xml.indexOf(']]>', lt + 9);
      if (endCd === -1) fail('unterminated CDATA section');
      addText(xml.slice(lt + 9, endCd));
      pos = endCd + 3;
    } else if (xml.indexOf('<?', lt) === lt) {
      var endP = xml.indexOf('?>', lt + 2);
      if (endP === -1) fail('unterminated processing instruction');
      pos = endP + 2;
    } else if (xml.indexOf('<!', lt) === lt) {
      var endD = xml.indexOf('>', lt + 2);
      if (endD === -1) fail('unterminated declaration');
      pos = endD + 1;
    } else if (xml.indexOf('</', lt) === lt) {
      var endT = xml.indexOf('>', lt + 2);
      if (endT === -1) fail('unterminated closing tag');
      var closeName = xml.slice(lt + 2, endT).trim();
      var open = stack.pop();
      if (!open) fail('unexpected closing tag </' + closeName + '>');
      if (open.tag !== closeName) fail('mismatched tags: <' + open.tag + '> closed by </' + closeName + '>');
      pos = endT + 1;
    } else {
      var gt = findTagEnd(xml, lt);
      if (gt === -1) fail('unterminated tag');
      var inner = xml.slice(lt + 1, gt);
      var selfClosing = /\/\s*$/.test(inner);
      if (selfClosing) inner = inner.replace(/\/\s*$/, '');
      var nameMatch = inner.match(/^\s*([^\s/>]+)/);
      if (!nameMatch) fail('malformed tag');
      var el = { tag: nameMatch[1], attrs: {}, children: [], text: '' };
      var attrRe = /([^\s=/>]+)\s*=\s*("([^"]*)"|'([^']*)')/g, am;
      var attrSrc = inner.slice(nameMatch[0].length);
      while ((am = attrRe.exec(attrSrc)) !== null) {
        el.attrs[am[1]] = decodeEntities(am[3] !== undefined ? am[3] : am[4]);
      }
      var parent = current();
      if (parent) parent.children.push(el);
      else if (!root) root = el;
      else fail('multiple root elements');
      if (!selfClosing) stack.push(el);
      pos = gt + 1;
    }
  }
  if (stack.length) fail('unclosed tag <' + stack[stack.length - 1].tag + '>');
  if (!root) fail('no XML element found');
  return root;
}

function dmarcLocalName(tag) {
  var i = tag.indexOf(':');
  return i === -1 ? tag : tag.slice(i + 1);
}
function dmarcChildren(el, tag) {
  if (!el) return [];
  return el.children.filter(function (c) { return dmarcLocalName(c.tag) === tag; });
}
function dmarcChild(el, tag) {
  var c = dmarcChildren(el, tag);
  return c.length ? c[0] : null;
}
function dmarcText(el, tag) {
  var c = dmarcChild(el, tag);
  return c ? c.text.trim() : '';
}
function dmarcNum(s) {
  var n = parseInt(s, 10);
  return isNaN(n) || n < 0 ? 0 : n;
}

function dmarcReadReport(root) {
  var meta = dmarcChild(root, 'report_metadata');
  var range = dmarcChild(meta, 'date_range');
  var pol = dmarcChild(root, 'policy_published');
  var report = {
    orgName: dmarcText(meta, 'org_name'),
    email: dmarcText(meta, 'email'),
    reportId: dmarcText(meta, 'report_id'),
    dateBegin: range ? dmarcNum(dmarcText(range, 'begin')) || null : null,
    dateEnd: range ? dmarcNum(dmarcText(range, 'end')) || null : null,
    domain: dmarcText(pol, 'domain'),
    adkim: dmarcText(pol, 'adkim'),
    aspf: dmarcText(pol, 'aspf'),
    policy: dmarcText(pol, 'p'),
    sp: dmarcText(pol, 'sp'),
    pct: dmarcText(pol, 'pct'),
    records: [],
  };
  dmarcChildren(root, 'record').forEach(function (rec) {
    var row = dmarcChild(rec, 'row');
    var evald = dmarcChild(row, 'policy_evaluated');
    var ids = dmarcChild(rec, 'identifiers');
    var auth = dmarcChild(rec, 'auth_results');
    var r = {
      sourceIp: dmarcText(row, 'source_ip'),
      count: dmarcNum(dmarcText(row, 'count')),
      disposition: dmarcText(evald, 'disposition'),
      evalDkim: dmarcText(evald, 'dkim'),
      evalSpf: dmarcText(evald, 'spf'),
      reasons: dmarcChildren(evald, 'reason').map(function (x) { return dmarcText(x, 'type'); }).filter(Boolean),
      headerFrom: dmarcText(ids, 'header_from'),
      envelopeFrom: dmarcText(ids, 'envelope_from'),
      authDkim: dmarcChildren(auth, 'dkim').map(function (d) {
        return { domain: dmarcText(d, 'domain'), selector: dmarcText(d, 'selector'), result: dmarcText(d, 'result') };
      }),
      authSpf: dmarcChildren(auth, 'spf').map(function (s) {
        return { domain: dmarcText(s, 'domain'), scope: dmarcText(s, 'scope'), result: dmarcText(s, 'result') };
      }),
    };
    report.records.push(r);
  });
  return report;
}

/* Split pasted content into individual <feedback> documents and parse each.
   Throws a plain-English Error when nothing usable is found. */
function dmarcParseReports(input) {
  var text = String(input == null ? '' : input);
  if (text.charCodeAt(0) === 0xFEFF) text = text.slice(1);
  var lower = text.toLowerCase();
  var segments = [], idx = 0;
  while (true) {
    var start = lower.indexOf('<feedback', idx);
    if (start === -1) break;
    var endTag = lower.indexOf('</feedback>', start);
    if (endTag === -1) break;
    segments.push(text.slice(start, endTag + '</feedback>'.length));
    idx = endTag + '</feedback>'.length;
  }
  if (!segments.length) {
    throw new Error('No DMARC aggregate report found in this content. DMARC reports are XML files with a <feedback> root element — check you pasted or picked the aggregate report (the .xml or .xml.gz files sent to your rua address), not a forensic report or a screenshot of one.');
  }
  var reports = [], errors = [];
  segments.forEach(function (seg, i) {
    try {
      var root = dmarcParseXml(seg);
      if (dmarcLocalName(root.tag) !== 'feedback') throw new Error('root element is <' + root.tag + '>, not <feedback>');
      reports.push(dmarcReadReport(root));
    } catch (e) {
      errors.push('Report ' + (i + 1) + ': ' + e.message);
    }
  });
  if (!reports.length) {
    throw new Error('The report could not be read. ' + errors.join(' '));
  }
  return { reports: reports, errors: errors };
}

function dmarcAligned(domain, headerFrom) {
  if (!domain || !headerFrom) return false;
  var d = String(domain).toLowerCase(), h = String(headerFrom).toLowerCase();
  return d === h || h.slice(-(d.length + 1)) === '.' + d || d.slice(-(h.length + 1)) === '.' + h;
}

/* A record passes DMARC when the *evaluated* (aligned) SPF or DKIM verdict
   is pass. Falls back to aligned auth_results when evaluation is absent. */
function dmarcRecordPasses(rec) {
  if (rec.evalDkim === 'pass' || rec.evalSpf === 'pass') return true;
  if (rec.evalDkim || rec.evalSpf) return false;
  return rec.authSpf.some(function (a) { return a.result === 'pass' && dmarcAligned(a.domain, rec.headerFrom); }) ||
         rec.authDkim.some(function (a) { return a.result === 'pass' && dmarcAligned(a.domain, rec.headerFrom); });
}

function dmarcFmtNum(n) {
  return String(n).replace(/\B(?=(\d{3})+(?!\d))/g, ',');
}
var DMARC_MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
function dmarcFmtDate(epochSec) {
  if (!epochSec) return '';
  var d = new Date(epochSec * 1000);
  return d.getUTCDate() + ' ' + DMARC_MONTHS[d.getUTCMonth()] + ' ' + d.getUTCFullYear();
}
function dmarcJoinSet(obj) {
  var keys = Object.keys(obj);
  return keys.length ? keys.join(' / ') : '—';
}

function dmarcFinaliseSource(s) {
  var status = s.failCount === 0 ? 'pass' : (s.passCount === 0 ? 'fail' : 'mixed');
  var spf = dmarcJoinSet(s.evalSpf), dkim = dmarcJoinSet(s.evalDkim), disp = dmarcJoinSet(s.dispositions);
  var unaligned = Object.keys(s.authPassDomains);
  var fwdReason = s.reasonTypes.some(function (t) {
    return t === 'forwarded' || t === 'mailing_list' || t === 'trusted_forwarder';
  });
  var label, detail;
  if (status === 'pass') {
    label = 'Passing — legitimate sender';
    detail = 'SPF or DKIM passes and lines up with your domain, so DMARC passes for this source.';
  } else if (status === 'mixed') {
    label = 'Mostly passing — some mail fails';
    detail = dmarcFmtNum(s.failCount) + ' of ' + dmarcFmtNum(s.count) + ' messages from this source fail DMARC. Usually one sending stream (a different tool or subdomain) is missing SPF or DKIM alignment — ask the provider to fix it.';
  } else if (unaligned.length || fwdReason) {
    label = 'Forwarding / mailing-list pattern';
    detail = 'This source\'s mail authenticates as ' + (unaligned.length ? unaligned.join(', ') : 'another domain') + ', not as your domain, so DMARC fails on alignment. Typical of forwarders and mailing lists that pass mail on — the mail is usually real, but it will keep failing until the forwarder preserves DKIM or you accept the risk.';
  } else if (disp.indexOf('reject') !== -1 || disp.indexOf('quarantine') !== -1) {
    label = 'Failing both — suspicious, investigate';
    detail = 'SPF and DKIM both fail and your policy already blocks or quarantines this mail. If this is a service you use, its authentication is broken — fix it today. If you don\'t recognise the source, this is what spoofing looks like, and your policy is doing its job.';
  } else {
    label = 'Failing both — suspicious, investigate';
    detail = 'SPF and DKIM both fail, and because the published policy is p=none these messages were still delivered. If you recognise this sender, fix its setup. If you don\'t, treat it as a spoofing attempt — this pattern is exactly what moving to p=quarantine or p=reject protects against.';
  }
  return {
    ip: s.ip, count: s.count, passCount: s.passCount, failCount: s.failCount,
    spf: spf, dkim: dkim, disposition: disp,
    headerFroms: Object.keys(s.headerFroms),
    status: status, label: label, detail: detail,
  };
}

function dmarcAnalyse(parsed) {
  var map = {}, order = [];
  var totalMessages = 0, passMessages = 0, totalRecords = 0;
  var dateBegin = null, dateEnd = null;
  var orgs = {}, domains = {}, policies = {};

  parsed.reports.forEach(function (rep) {
    if (rep.orgName) orgs[rep.orgName] = true;
    if (rep.domain) domains[rep.domain] = true;
    if (rep.policy) policies[rep.policy] = true;
    if (rep.dateBegin && (dateBegin === null || rep.dateBegin < dateBegin)) dateBegin = rep.dateBegin;
    if (rep.dateEnd && (dateEnd === null || rep.dateEnd > dateEnd)) dateEnd = rep.dateEnd;
    rep.records.forEach(function (rec) {
      totalRecords += 1;
      totalMessages += rec.count;
      var key = rec.sourceIp || '(unknown source)';
      if (!map[key]) {
        map[key] = {
          ip: key, count: 0, passCount: 0, failCount: 0,
          dispositions: {}, evalSpf: {}, evalDkim: {}, headerFroms: {},
          authPassDomains: {}, reasonTypes: [],
        };
        order.push(key);
      }
      var s = map[key];
      s.count += rec.count;
      if (dmarcRecordPasses(rec)) { s.passCount += rec.count; passMessages += rec.count; }
      else s.failCount += rec.count;
      if (rec.disposition) s.dispositions[rec.disposition] = true;
      if (rec.evalSpf) s.evalSpf[rec.evalSpf] = true;
      if (rec.evalDkim) s.evalDkim[rec.evalDkim] = true;
      if (rec.headerFrom) s.headerFroms[rec.headerFrom] = true;
      rec.reasons.forEach(function (t) { if (s.reasonTypes.indexOf(t) === -1) s.reasonTypes.push(t); });
      rec.authSpf.concat(rec.authDkim).forEach(function (a) {
        if (a.result === 'pass' && a.domain && !dmarcAligned(a.domain, rec.headerFrom)) s.authPassDomains[a.domain] = true;
      });
    });
  });

  var sources = order.map(function (k) { return dmarcFinaliseSource(map[k]); });
  sources.sort(function (a, b) { return b.count - a.count; });

  var failMessages = totalMessages - passMessages;
  var problems = [];
  var enforced = sources.filter(function (s) {
    return s.status === 'fail' && s.label.indexOf('suspicious') !== -1 &&
      (s.disposition.indexOf('reject') !== -1 || s.disposition.indexOf('quarantine') !== -1);
  });
  var unenforced = sources.filter(function (s) {
    return s.status === 'fail' && s.label.indexOf('suspicious') !== -1 && enforced.indexOf(s) === -1;
  });
  var forwarding = sources.filter(function (s) { return s.label.indexOf('Forwarding') === 0; });
  var mixed = sources.filter(function (s) { return s.status === 'mixed'; });

  enforced.forEach(function (s) {
    problems.push({ level: 'bad', title: s.ip + ' is failing both checks and being blocked (' + dmarcFmtNum(s.failCount) + ' messages)',
      detail: 'If this is a service you send through, its SPF/DKIM alignment is broken — fix it before real mail is lost. If you don\'t recognise it, it is likely spoofing and your policy is working.' });
  });
  unenforced.forEach(function (s) {
    problems.push({ level: 'bad', title: s.ip + ' is failing both checks but was still delivered (' + dmarcFmtNum(s.failCount) + ' messages)',
      detail: 'Your published policy is p=none, so receivers took no action. Recognise the sender? Get its authentication fixed. Don\'t recognise it? Treat it as spoofing — and as a reason to enforce.' });
  });
  forwarding.forEach(function (s) {
    problems.push({ level: 'warn', title: s.ip + ' looks like a forwarder or mailing list (' + dmarcFmtNum(s.failCount) + ' messages)',
      detail: 'Its mail authenticates as another domain, so DMARC fails on alignment. Usually legitimate — but decide whether you accept this source failing, because strict enforcement will quarantine its mail.' });
  });
  mixed.forEach(function (s) {
    problems.push({ level: 'warn', title: s.ip + ' passes only some of the time (' + dmarcFmtNum(s.failCount) + ' failing messages)',
      detail: 'One of this sender\'s streams is missing alignment. Ask the provider which of their systems sends without a passing, aligned SPF or DKIM result.' });
  });

  var policyList = Object.keys(policies);
  if (totalMessages > 0 && failMessages === 0 && sources.length) {
    if (policyList.indexOf('reject') !== -1) {
      problems.push({ level: 'ok', title: 'Healthy: every source passes and the policy is p=reject',
        detail: 'This is the end state you want. Keep watching reports weekly — new tools and vendors show up as new sources first.' });
    } else {
      problems.push({ level: 'ok', title: 'Every source passes — you can strengthen the policy',
        detail: 'If 1–2 weeks of reports all look like this, move from ' + (policyList.join(' / ') || 'p=none') + ' towards p=quarantine, then p=reject, so failing mail is actually stopped.' });
    }
  } else if (policyList.indexOf('none') !== -1) {
    problems.push({ level: 'warn', title: 'Published policy is p=none (monitor only)',
      detail: 'Nothing failing is being stopped yet — that is correct while you clean up. Fix the failing legitimate senders above first, then step up to p=quarantine (pct=50 is a gentle ramp), then p=reject.' });
  } else if (policyList.indexOf('quarantine') !== -1 && failMessages > 0) {
    problems.push({ level: 'warn', title: 'Policy is p=quarantine — finish the job',
      detail: 'Once the failing sources above are fixed or accepted, move to p=reject so spoofed mail is refused outright instead of landing in spam.' });
  }
  if (!problems.length) {
    problems.push({ level: 'warn', title: 'No records found in this report',
      detail: 'The report parsed but contained no <record> rows — it may cover a period with no mail, or the file may be truncated.' });
  }

  return {
    reportCount: parsed.reports.length,
    parseErrors: parsed.errors,
    orgs: Object.keys(orgs),
    domains: Object.keys(domains),
    policies: policyList,
    dateBegin: dateBegin,
    dateEnd: dateEnd,
    totalMessages: totalMessages,
    passMessages: passMessages,
    failMessages: failMessages,
    passPct: totalMessages ? Math.round((passMessages / totalMessages) * 100) : 0,
    totalRecords: totalRecords,
    sources: sources,
    problems: problems,
  };
}

/* Plain-text rendering — the MCP tool returns exactly this. */
function dmarcRenderText(a) {
  var lines = ['DMARC report analysis (by OutboundAuth — https://outboundauth.com)', ''];
  var who = (a.orgs.join(', ') || 'Unknown reporter') + ' → ' + (a.domains.join(', ') || 'unknown domain');
  var when = a.dateBegin ? ' · ' + dmarcFmtDate(a.dateBegin) + (a.dateEnd && a.dateEnd !== a.dateBegin ? ' to ' + dmarcFmtDate(a.dateEnd) : '') : '';
  lines.push('Report: ' + who + when + (a.reportCount > 1 ? ' · ' + a.reportCount + ' reports combined' : ''));
  lines.push('Published policy: ' + (a.policies.length ? 'p=' + a.policies.join(', p=') : 'not stated'));
  lines.push('Messages: ' + dmarcFmtNum(a.totalMessages) + ' total · ' + dmarcFmtNum(a.passMessages) + ' passing (' + a.passPct + '%) · ' + dmarcFmtNum(a.failMessages) + ' failing');
  lines.push('');
  lines.push('Sources, biggest risk first:');
  var risk = a.sources.slice().sort(function (x, y) {
    var rank = function (s) { return s.status === 'fail' ? 0 : s.status === 'mixed' ? 1 : 2; };
    return rank(x) - rank(y) || y.count - x.count;
  });
  if (!risk.length) lines.push('  (no sources)');
  risk.forEach(function (s) {
    lines.push('- ' + s.ip + ' — ' + dmarcFmtNum(s.count) + ' messages · SPF ' + s.spf + ' · DKIM ' + s.dkim + ' · disposition ' + s.disposition);
    lines.push('  ' + s.label + '. ' + s.detail);
  });
  lines.push('');
  lines.push('Top problems, in fix order:');
  a.problems.forEach(function (p, i) {
    var mark = p.level === 'bad' ? '[FIX FIRST]' : p.level === 'warn' ? '[CHECK]' : '[OK]';
    lines.push((i + 1) + '. ' + mark + ' ' + p.title + ' — ' + p.detail);
  });
  if (a.parseErrors.length) {
    lines.push('');
    lines.push('Note: ' + a.parseErrors.join(' '));
  }
  lines.push('');
  lines.push('How DMARC reports drive a safe rollout: https://outboundauth.com/guides/dmarc-guide');
  return lines.join('\n');
}

/* Node test hook — inert in browsers and in the MCP worker. */
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    dmarcParseXml: dmarcParseXml,
    dmarcParseReports: dmarcParseReports,
    dmarcAnalyse: dmarcAnalyse,
    dmarcRenderText: dmarcRenderText,
  };
}


/* ---------------- analyze_dmarc_report: tool definition ---------------- */

const ANALYZE_DMARC_REPORT_TOOL = {
  name: 'analyze_dmarc_report',
  title: 'Analyze a DMARC aggregate report',
  description: 'Explain a DMARC aggregate report in plain English: paste the report XML (the files sent to your rua address; several reports pasted together also work). Returns the reporting organisation and domain, total and passing message counts, a per-source breakdown (source IP, messages, SPF/DKIM verdicts, disposition) labelled as a legitimate sender, a forwarding / mailing-list pattern, or failing-and-suspicious — plus the top problems in fix order.',
  inputSchema: {
    type: 'object',
    properties: {
      report_xml: { type: 'string', description: 'The DMARC aggregate report XML in full (unzipped). Several reports pasted back to back are combined.' },
    },
    required: ['report_xml'],
  },
  annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
};

/* ---------------- analyze_dmarc_report: dispatch ---------------- */

async function analyzeDmarcReportTool(args) {
  const xml = String((args && args.report_xml) || '');
  if (!xml.trim()) {
    throw new Error('Paste the DMARC aggregate report XML (report_xml) — the .xml file receivers send to your rua address, unzipped.');
  }
  if (xml.length > 2000000) {
    throw new Error('That is very large (' + xml.length + ' characters). Paste one report at a time, or a few at most.');
  }
  const analysis = dmarcAnalyse(dmarcParseReports(xml));
  return dmarcRenderText(analysis);
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
  {
    name: 'analyze_bounce',
    title: 'Analyze a bounce message',
    description: 'Explain an email bounce in plain English: paste the full bounce message or just the error (e.g. "550 5.7.1"). Returns whether it is a hard or soft bounce, what happened, the likely cause (list quality, reputation, policy, authentication, temporary), and the fix.',
    inputSchema: {
      type: 'object',
      properties: {
        bounce_text: { type: 'string', description: 'The full bounce message or the error text from the sending tool' },
        code: { type: 'string', description: 'Just the bounce code, e.g. 550 or 550 5.7.1 (alternative to bounce_text)' },
      },
    },
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  },
  {
    name: 'check_blacklists',
    title: 'Check DNS blacklists',
    description: 'Check a domain\'s sending IPs (resolved from its mail servers) and/or a specific IP against 7 major DNS blacklists (Spamhaus ZEN, SpamCop, PSBL, UCEPROTECT, Mailspike, DroneBL, UBL). Reports listed or clean per list, per IP.',
    inputSchema: {
      type: 'object',
      properties: {
        domain: { type: 'string', description: 'Domain whose mail-server IPs should be checked, e.g. example.com' },
        ip: { type: 'string', description: 'A specific IPv4 address to check, e.g. 192.0.2.10' },
      },
    },
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  },
  {
    name: 'check_mx_health',
    title: 'Check MX health',
    description: 'Look up a domain\'s MX records and evaluate them: priorities, whether each mail server resolves, the likely mail provider (Google Workspace, Microsoft 365, …), and obvious misconfigurations. Returns a scored verdict with findings.',
    inputSchema: {
      type: 'object',
      properties: { domain: { type: 'string', description: 'Domain to check, e.g. example.com' } },
      required: ['domain'],
    },
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  },
  {
    name: 'analyze_email_headers',
    title: 'Analyze email headers',
    description: 'Explain raw email headers in plain English: the Authentication-Results verdicts for SPF, DKIM and DMARC (with the domains each check covered), From vs Return-Path alignment, and the Received hop count. Paste the full headers ("Show original" in Gmail).',
    inputSchema: {
      type: 'object',
      properties: { headers: { type: 'string', description: 'The raw email headers, pasted in full' } },
      required: ['headers'],
    },
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  },
  {
    name: 'get_domain_health',
    title: 'Full domain health report',
    description: 'One combined health report for a domain: SPF, DKIM (common selectors), DMARC, MX and blacklist status, with an overall score out of 100, the top problems, and the recommended fix order.',
    inputSchema: {
      type: 'object',
      properties: { domain: { type: 'string', description: 'Domain to check, e.g. example.com' } },
      required: ['domain'],
    },
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  },
  ANALYZE_DMARC_REPORT_TOOL,
];

async function callTool(name, args) {
  if (name === 'analyze_dmarc_report') return analyzeDmarcReportTool(args);

  if (name === 'analyze_bounce') {
    const text = [args && args.code, args && args.bounce_text].filter(Boolean).join(' ');
    if (!text.trim()) throw new Error('Provide the bounce message (bounce_text) or just the code (code), e.g. "550 5.7.1".');
    const r = analyzeBounce(text);
    if (!r) {
      return 'Bounce analysis\nNo SMTP code (like 550 or 421) was found in what you pasted. Paste the full bounce message — the code and the sentence after it name the cause. The guide explains every common code: https://outboundauth.com/guides/email-bounce-codes-explained';
    }
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

  if (name === 'analyze_email_headers') {
    const headers = String((args && args.headers) || '');
    if (headers.trim().length < 20) throw new Error('Paste the full raw headers (in Gmail: open the message, click the three dots, then "Show original").');
    const r = analyzeHeaders(headers);
    const lines = ['Header analysis (by OutboundAuth — https://outboundauth.com)', ''];
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

  if (name === 'check_blacklists') {
    const ipArg = String((args && args.ip) || '').trim();
    const domArg = cleanDomain(args && args.domain);
    const targets = [];
    if (ipArg) {
      const octets = ipArg.split('.');
      if (!/^\d+\.\d+\.\d+\.\d+$/.test(ipArg) || octets.some(o => Number(o) > 255)) {
        throw new Error('The ip value is not a valid IPv4 address.');
      }
      targets.push({ ip: ipArg, note: 'the IP you provided' });
    }
    if (domArg) {
      const mxRes = await doh(domArg, 'MX');
      const hosts = mxRes.ok ? parseMx(mxRes.answers) : [];
      const ips = await ipsForDomain(domArg, hosts);
      ips.forEach(ip => {
        if (!targets.some(t => t.ip === ip)) targets.push({ ip, note: 'an IP ' + domArg + ' sends or receives mail on' });
      });
      if (!ips.length && !targets.length) {
        return 'Blacklist check for ' + domArg + '\nNo public IPv4 address was found for this domain or its mail servers, so there is nothing to check against the lists.';
      }
    }
    if (!targets.length) throw new Error('Provide a valid domain, e.g. example.com, and/or an ip to check.');
    const lines = ['Blacklist check' + (domArg ? ' for ' + domArg : '') + ' (by OutboundAuth — https://outboundauth.com)', ''];
    let listedCount = 0;
    let checkedCount = 0;
    for (const t of targets) {
      const r = await checkIpBlacklists(t.ip);
      lines.push(t.ip + ' (' + t.note + '):');
      if (!r.checked.length) {
        lines.push('  [WARN] The blacklist servers could not be reached — this IP is unverified.');
        continue;
      }
      checkedCount++;
      HEALTH_RBLS.forEach(z => {
        if (!r.checked.includes(z)) return;
        const hit = r.listed.filter(l => l.zone === z)[0];
        if (hit) {
          listedCount++;
          lines.push('  [FAIL] ' + (RBL_NAMES[z] || z) + ' (' + z + ') — LISTED, returned ' + hit.codes.join(', '));
        } else {
          lines.push('  [OK] ' + (RBL_NAMES[z] || z) + ' (' + z + ') — clean');
        }
      });
      lines.push('');
    }
    if (!checkedCount) lines.push('Summary: the blacklist check could not be completed — try again in a moment.');
    else if (listedCount) lines.push('Summary: ' + listedCount + ' listing' + (listedCount > 1 ? 's' : '') + ' found. A listing drags mail into spam until it is removed — fix the cause first, then request delisting from the list operator.');
    else lines.push('Summary: clean on every list checked.');
    return lines.join('\n');
  }

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

  if (name === 'check_mx_health') {
    const res = await doh(domain, 'MX');
    if (!res.ok) throw new Error('Live DNS lookup failed — try again in a moment.');
    const r = await evalMxHealth(domain, res.answers);
    return 'MX health check for ' + domain + '\n' + renderSection('MX', r);
  }

  if (name === 'get_domain_health') {
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
    const mxHosts = parseMx(mxRes.ok ? mxRes.answers : null);
    const mxSection = evalMx(mxRes.ok ? mxRes.answers : null);
    const found = dkimHits.filter(h => h.ok && h.record);
    let dkimPoints;
    let dkimSection;
    if (!found.length) {
      dkimPoints = 50;
      dkimSection = 'DKIM: 50/100 — needs review\n  [WARN] No DKIM record found for common selectors — checked ' + COMMON_DKIM_SELECTORS.join(', ') + '. If the domain signs mail, use check_dkim with the exact selector.';
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
    // Same weights as the website's domain health report: SPF 30, DKIM 25, DMARC 25, MX 10, blacklists 10.
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
      'Domain health report for ' + domain + ' (by OutboundAuth — https://outboundauth.com)',
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
      'Overall: ' + overall + '/100 — ' + (overall >= 85 ? 'healthy — keep monitoring for quiet changes' : overall >= 60 ? 'usable, with gaps to close' : 'needs attention before sending at volume'),
    ];
    if (problems.length) {
      lines.push('');
      lines.push('Top problems:');
      problems.slice(0, 5).forEach((p, i) => lines.push('  ' + (i + 1) + '. [' + p.label + '] ' + p.title));
      lines.push('');
      lines.push('Recommended fix order: authentication first (SPF, then DKIM, then DMARC), then any blacklist listing, then MX issues — the same order as the deliverability checklist: https://outboundauth.com/guides/cold-email-deliverability-checklist');
    } else {
      lines.push('');
      lines.push('Top problems: none found. Records can still break quietly — re-check before every big send.');
    }
    return lines.join('\n');
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
        <a href="/mcp" aria-current="page">MCP</a>
        <a class="cta" href="https://wa.me/923035544889?text=Hi%20Saqib%2C%20I%20need%20help%20with%20my%20email%20authentication." target="_blank" rel="noopener">WhatsApp me</a>
      </nav>
    </div>
  </header>
  <div class="shell">
    <div class="article-wrap">
      <article class="article">
        <div class="kicker">MCP Server</div>
        <h1>Check email authentication from inside your AI assistant</h1>
        <p class="lede">OutboundAuth also runs as an MCP server. Connect it once, and Claude, Cursor, ChatGPT and other MCP-compatible assistants can run live deliverability checks for you — SPF, DKIM, DMARC, MX health, blacklists and more — scored and explained in plain English, without leaving your chat.</p>

        <h2>The endpoint</h2>
        <div class="endpoint-box">
          <code>https://outboundauth.com/mcp</code>
          <button class="copybtn" type="button" onclick="if(navigator.clipboard){navigator.clipboard.writeText('https://outboundauth.com/mcp');}this.textContent='Copied ✓'">Copy</button>
        </div>
        <p>This page is the human front door. AI assistants connect to the same address using MCP (Streamable HTTP) — the server is live and answering right now.</p>

        <h2>The ten tools</h2>
        <ul>
          <li><strong>check_email_auth</strong> — the full check: SPF, DKIM and DMARC in one pass, with a score out of 100 for each.</li>
          <li><strong>check_spf</strong> — reads the live SPF record and flags a missing hard fail, too many DNS lookups, and other common faults.</li>
          <li><strong>check_dmarc</strong> — reads the DMARC record and checks the policy (none, quarantine or reject) and reporting addresses.</li>
          <li><strong>check_dkim</strong> — checks a DKIM selector's public key record for a domain.</li>
          <li><strong>get_domain_health</strong> — the one-call report: SPF, DKIM, DMARC, MX and blacklist status with a single score out of 100, the top problems and the fix order.</li>
          <li><strong>check_mx_health</strong> — checks a domain's mail servers: priorities, whether each one resolves, and who the mail provider looks like.</li>
          <li><strong>check_blacklists</strong> — checks a domain's sending IPs (or one IP you name) against seven major DNS blacklists.</li>
          <li><strong>analyze_bounce</strong> — paste a bounce message or code and get the plain-English meaning, the likely cause and the fix.</li>
          <li><strong>analyze_email_headers</strong> — paste raw email headers and get the SPF, DKIM and DMARC verdicts explained, plus the sending path.</li>
          <li><strong>analyze_dmarc_report</strong> — paste a DMARC aggregate report (XML) and get, for each sending source, who passed, who failed and who looks suspicious, in plain English.</li>
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

<section id="rest-api">
  <h2>REST API</h2>
  <p>The same checks are also available as a plain REST API — one HTTP call, a JSON answer. Use it from scripts, spreadsheets, monitoring jobs, or any tool that does not speak MCP. It runs the identical engine as the MCP server above, so the scores match.</p>

  <h3>Domain health report</h3>
  <div class="endpoint-box">
    <code>GET https://outboundauth.com/api/check?domain=example.com</code>
  </div>
  <pre>curl "https://outboundauth.com/api/check?domain=example.com"</pre>
  <p>Returns the full report: SPF, DKIM (common selectors), DMARC, MX and blacklist status, each scored out of 100, plus one overall score, the top problems and the recommended fix order.</p>
  <pre>{
  "domain": "outboundauth.com",
  "overall": 85,
  "verdict": "healthy — keep monitoring for quiet changes",
  "spf": {
    "score": 100,
    "verdict": "looks good",
    "record": "v=spf1 -all",
    "findings": [
      { "level": "ok", "title": "SPF record found", "detail": "The record begins with v=spf1." },
      …
    ]
  },
  "dkim":       { "score": 50,  "verdict": "needs attention", … },
  "dmarc":      { "score": 100, "record": "v=DMARC1; p=reject; rua=mailto:…", … },
  "mx":         { "score": 70,  "hosts": [], … },
  "blacklists": { "score": 100, "ips_checked": ["…"], … },
  "problems": [
    { "area": "MX", "level": "warn", "title": "No MX records found" },
    …
  ]
}</pre>

  <h3>One section only</h3>
  <p>Add <code>&amp;part=</code> with one of <code>spf</code>, <code>dmarc</code>, <code>dkim</code>, <code>mx</code> or <code>blacklists</code> to get just that section of the report:</p>
  <pre>curl "https://outboundauth.com/api/check?domain=example.com&amp;part=dmarc"</pre>

  <h3>Bounce analysis</h3>
  <p>POST a bounce message — or just its code — and get the plain-English classification, the likely cause and the fix:</p>
  <pre>curl -X POST "https://outboundauth.com/api/check" \
  -H "Content-Type: application/json" \
  -d '{"code": "550 5.1.1"}'</pre>
  <pre>{
  "type": "bounce",
  "found": true,
  "code": "550 5.1.1",
  "bounce_type": "hard",
  "classification": "Hard bounce — permanent failure",
  "title": "The mailbox does not exist",
  "meaning": "The receiving server says there is no mailbox at that address…",
  "likely_cause": "List quality — a bad address, not a fault in your sending setup.",
  "fix": "Remove the address from your list the same day…"
}</pre>
  <p>Send the full bounce text instead with <code>{"bounce_text": "…"}</code> — the more of the message you include, the more specific the answer.</p>

  <h3>Email header analysis</h3>
  <p>POST raw email headers and get the Authentication-Results verdicts for SPF, DKIM and DMARC explained, plus the sending path:</p>
  <pre>curl -X POST "https://outboundauth.com/api/check" \
  -H "Content-Type: application/json" \
  -d '{"headers": "Authentication-Results: mx.google.com; dkim=pass …"}'</pre>
  <p>The answer carries a score out of 100, the per-check findings under <code>authentication</code>, the path findings under <code>sending_path</code>, and a one-line <code>verdict</code>.</p>

  <h3>Errors</h3>
  <p>Errors are JSON too — <code>{ "error": "…" }</code> — with HTTP 400 for bad input (for example a missing or invalid domain), 404 for an unknown <code>part</code>, and 502 when the live DNS lookup itself fails.</p>

  <h3>Good to know</h3>
  <ul>
    <li><strong>Free, no API key.</strong> Version 1 needs no key and no sign-up. Keys and higher limits are planned for a later version.</li>
    <li><strong>Fair use.</strong> Every call runs live DNS lookups. Cache results on your side, do not hammer the endpoint, and re-check at most every few minutes per domain.</li>
    <li><strong>Read-only, nothing stored.</strong> The API only looks up public DNS records. Domains, bounce text and headers you send are analysed in the request and not kept.</li>
    <li><strong>Same scores as the website and MCP.</strong> One engine powers the free toolkit on this site, the MCP server and this API.</li>
  </ul>
</section>

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
        <a href="/mcp">MCP server</a>
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
