# OutboundAuth

**Free email deliverability checks for any domain — on the web, as an MCP server for AI agents, and as a REST API.**

Live site: [outboundauth.com](https://outboundauth.com) · MCP endpoint: `https://outboundauth.com/mcp` · Listed in the [Official MCP Registry](https://registry.modelcontextprotocol.io) as `io.github.SaqibNaseer404/outboundauth` · [mcptry listing](https://mcptry.com/servers/io.github.SaqibNaseer404/outboundauth)

OutboundAuth answers one question: *why does this domain's email land in spam — and what exactly should be fixed first?* Every check reads live public DNS records and returns a score, the evidence behind it, and the problems in fix order.

## Free tools on the website

- **SPF, DKIM and DMARC checkers** — on the [homepage](https://outboundauth.com), no sign-up.
- **DMARC Report Analyser** — [outboundauth.com/dmarc-report-analyzer](https://outboundauth.com/dmarc-report-analyzer): paste or upload a DMARC aggregate report (XML or .gz) and see, per sending source, who passed, who failed and who looks suspicious. It runs entirely in your browser — your report never leaves your machine.
- **Audit Report Generator** — [outboundauth.com/audit-report](https://outboundauth.com/audit-report): enter a domain and get a printable deliverability report built from live checks.
- **Deliverability Copilot** — [outboundauth.com/copilot](https://outboundauth.com/copilot): an AI assistant connected to the same live checks. Give it a domain, a bounce message or raw headers and it investigates the real results, keeping verified facts separate from recommendations.
- **Guides** — 17 free, plain-English guides on email authentication and cold-email deliverability.

## MCP server — ten tools

AI assistants (Claude, ChatGPT and other MCP clients) can call these tools directly. The server is hosted — there is nothing to install.

| Tool | What it does |
| --- | --- |
| `check_email_auth` | The full check: SPF, DKIM and DMARC in one pass, each scored out of 100. |
| `check_spf` | Reads the live SPF record; flags a missing hard fail, too many DNS lookups and other common faults. |
| `check_dmarc` | Reads the DMARC record; checks the policy (none, quarantine or reject) and reporting addresses. |
| `check_dkim` | Checks a DKIM selector's public key record for a domain. |
| `get_domain_health` | The one-call report: SPF, DKIM, DMARC, MX and blacklist status with a single score out of 100, the top problems and the fix order. |
| `check_mx_health` | Checks a domain's mail servers: priorities, whether each one resolves, and who the mail provider looks like. |
| `check_blacklists` | Checks a domain's sending IPs (or one IP you name) against seven major DNS blacklists. |
| `analyze_bounce` | Paste a bounce message or code and get the plain-English meaning, the likely cause and the fix. |
| `analyze_email_headers` | Paste raw email headers and get the SPF, DKIM and DMARC verdicts explained, plus the sending path. |
| `analyze_dmarc_report` | Paste a DMARC aggregate report (XML) and get, for each sending source, who passed, who failed and who looks suspicious, in plain English. |

### Connect an MCP client

Add the server URL in your assistant's MCP or connector settings:

```json
{
  "mcpServers": {
    "outboundauth": {
      "url": "https://outboundauth.com/mcp"
    }
  }
}
```

The basic checks are free and need no API key.

## REST API

One endpoint, no key required:

```
GET https://outboundauth.com/api/check?domain=example.com
```

Returns the full JSON health report (overall score plus SPF, DMARC, DKIM, MX and blacklist sections). Ask for one section with `&part=spf`, `&part=dmarc`, `&part=dkim`, `&part=mx` or `&part=blacklists`.

```
POST https://outboundauth.com/api/check
{"bounce_text": "..."}   — or {"code": "550 5.7.1"} — explains a bounce
{"headers": "..."}       — explains raw email headers
```

Full documentation lives on the [MCP page](https://outboundauth.com/mcp).

## Paid services (done for you)

- **Deliverability Audit — $49 one-time:** the full findings, written up, in fix order.
- **Full Setup — $149 one-time:** SPF, DKIM and DMARC configured for you (the $49 audit is credited toward it), with a 7-day guarantee.
- **Monitoring — $29/month:** weekly re-checks of your scores, with changes flagged.

Order or ask a question via the website or WhatsApp — details on [outboundauth.com](https://outboundauth.com).

## How it works

This repository is the live website: a static site on Cloudflare Pages, with three Pages Functions doing the server work:

- `functions/mcp.js` — the MCP server (stateless Streamable HTTP) and its human-readable page.
- `functions/api/check.js` — the REST API.
- `functions/api/chat.js` — the Copilot backend, which runs the same checks server-side before answering.

All checks use public DNS records (via DNS-over-HTTPS). There is no database of private email data and no access to anyone's inbox.

## Security and privacy — honest limits

- Checks read **public DNS records only**. DKIM can only be verified for selectors that are known or guessed; a "not found" result for an unusual selector is not proof a domain does not sign mail.
- The website's DMARC analyser runs **in your browser**; reports you paste there are never uploaded.
- **No tool here can promise inbox placement.** Scores describe authentication health; inbox providers weigh many other signals too.
- On paid setup work, **we never change a client's DNS without their explicit authorisation**, and verified results are always reported separately from recommendations.

## Contributing

This repo is a production website rather than a library, so there is no local install step — the MCP server and API above are the public interfaces. Found a wrong result or a checker bug? Open an issue here, or reach us through the website.

---

Built and run by Saqib Naseer Khan — [outboundauth.com](https://outboundauth.com)
