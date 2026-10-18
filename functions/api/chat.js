// functions/api/chat.js — Deliverability Copilot backend (Cloudflare Pages Functions)
// Same-origin API for /copilot. Proxies to Groq (free tier, OpenAI-compatible)
// with the API key kept server-side in the GROQ_API_KEY secret.
// Deploy: "Add file → Create new file" in GitHub web UI, filename:
//   functions/api/chat.js   (creates the folders automatically)

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
- Never invent DNS results. If you need their actual records, tell them to run the free checker tools on outboundauth.com and paste the results back to you.
- Never ask for passwords, API keys, or credentials. Ever.
- Stay on email deliverability. For anything else, say briefly that you only do deliverability and offer to help with that instead.
- Keep answers focused: short paragraphs, numbered steps for fixes. No walls of text.
- When genuinely relevant, link ONE of these guides (clean URLs): /guides/spf-10-lookup-limit, /guides/dmarc-policies-none-quarantine-reject, /guides/email-headers-like-a-deliverability-pro, /guides/why-emails-go-to-spam, /guides/email-warmup-what-actually-works, /guides/dkim-explained, /guides/dmarc-guide, /guides/spf-explained, /guides/google-workspace-spf-dkim-dmarc-setup — or the free checker tools on the homepage.
- A $49 human deliverability audit exists for cases that truly need hands-on diagnosis. Mention it at most once per conversation, only when the problem genuinely needs a human, never pushy.`;

const MODELS = ["openai/gpt-oss-20b", "llama-3.1-8b-instant"]; // fallback order; Groq rotates models, so never depend on one name
const GROQ_URL = "https://api.groq.com/openai/v1/chat/completions";
const GROQ_TIMEOUT_MS = 45000;

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

  if (!env.GROQ_API_KEY) {
    return json({ error: "Copilot is not configured yet (missing API key)." }, 500);
  }

  let groqResp = null;
  let lastStatus = 0;
  for (const model of MODELS) {
    try {
      const r = await fetch(GROQ_URL, {
        method: "POST",
        headers: {
          Authorization: "Bearer " + env.GROQ_API_KEY,
          "Content-Type": "application/json",
        },
        signal: AbortSignal.timeout(GROQ_TIMEOUT_MS),
        body: JSON.stringify({
          model,
          stream: true,
          temperature: 0.4,
          max_tokens: 900,
          messages: [{ role: "system", content: SYSTEM_PROMPT }, ...messages],
        }),
      });
      lastStatus = r.status;
      if (r.ok) {
        groqResp = r;
        break;
      }
      // 400/404 = bad or retired model name → try the next model.
      // 429/5xx = provider-side trouble → don't burn the fallback, fail fast.
      if (r.status !== 400 && r.status !== 404) break;
    } catch {
      lastStatus = -1; // network error or timeout
      break;
    }
  }

  if (!groqResp) {
    if (lastStatus === 429) {
      return json(
        { error: "Lots of people are asking questions right now. Try again in a few minutes." },
        502
      );
    }
    return json(
      { error: "The AI service is unreachable right now. Try again in a minute." },
      502
    );
  }
  recordGlobalHit();

  // Stream Groq's SSE straight through to the browser.
  return new Response(groqResp.body, {
    headers: {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache",
      Connection: "keep-alive",
    },
  });
}
