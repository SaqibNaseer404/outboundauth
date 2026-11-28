/* Inbox Defender — a 60-second game that teaches SPF, DKIM and DMARC.
   OutboundAuth · plain JavaScript, no dependencies.
   Rule taught: allow an email only when SPF, DKIM and DMARC all pass.
   Anything else is unproven — real filters block it or send it to spam. */
(function () {
  'use strict';
  var root = document.getElementById('id-game');
  if (!root) return;

  /* status: pass | fail | none (no record / not sent) */
  var MAIL = [
    /* --- clear good mail: all three pass -> ALLOW --- */
    { from: 'billing@supplier.com', name: 'Supplier Billing', subject: 'Invoice #4821 — payment due Friday', spf: 'pass', dkim: 'pass', dmarc: 'pass', good: true,
      why: 'All three checks pass — this mail proved who sent it.' },
    { from: 'news@yourbank.com', name: 'Your Bank', subject: 'Your November statement is ready', spf: 'pass', dkim: 'pass', dmarc: 'pass', good: true,
      why: 'SPF, DKIM and DMARC all pass. Safe to allow.' },
    { from: 'orders@shopmart.com', name: 'ShopMart', subject: 'Your order has shipped — tracking inside', spf: 'pass', dkim: 'pass', dmarc: 'pass', good: true,
      why: 'Fully authenticated. This is what good mail looks like.' },
    { from: 'team@projecthub.io', name: 'ProjectHub', subject: 'Ayesha mentioned you in a comment', spf: 'pass', dkim: 'pass', dmarc: 'pass', good: true,
      why: 'All checks pass — allow it.' },
    { from: 'receipts@coffeeclub.com', name: 'Coffee Club', subject: 'Your receipt — and 20 points added', spf: 'pass', dkim: 'pass', dmarc: 'pass', good: true,
      why: 'All three pass. Allow.' },
    { from: 'support@saas-tool.com', name: 'SaaS Tool Support', subject: 'Your ticket #8812 was answered', spf: 'pass', dkim: 'pass', dmarc: 'pass', good: true,
      why: 'Authenticated on all three checks. Allow.' },
    { from: 'hr@yourcompany.com', name: 'HR Team', subject: 'Updated leave policy for 2027', spf: 'pass', dkim: 'pass', dmarc: 'pass', good: true,
      why: 'All pass. Allow.' },
    { from: 'no-reply@airline.com', name: 'Airline', subject: 'Check-in is open for your flight', spf: 'pass', dkim: 'pass', dmarc: 'pass', good: true,
      why: 'All three checks pass. Allow.' },

    /* --- bad mail: something fails -> BLOCK --- */
    { from: 'security@paypa1.com', name: 'PayPaI Secure', subject: 'URGENT: your account will be closed today', spf: 'fail', dkim: 'none', dmarc: 'fail', good: false,
      why: 'Look at the domain: paypa1.com with a number 1 — a fake. SPF and DMARC fail. Block.' },
    { from: 'alerts@bank-secure-login.xyz', name: 'Bank Alerts', subject: 'Verify your password in the next 2 hours', spf: 'fail', dkim: 'fail', dmarc: 'fail', good: false,
      why: 'Every check fails and the domain is a stranger. Classic phishing — block.' },
    { from: 'winner@lottery-prizes.net', name: 'Prize Centre', subject: 'You won $50,000 — claim now', spf: 'none', dkim: 'none', dmarc: 'none', good: false,
      why: 'No SPF, no DKIM, no DMARC — this mail proves nothing about who sent it. Block.' },
    { from: 'delivery@amaz0n-orders.com', name: 'Amaz0n Orders', subject: 'Problem with your payment method', spf: 'pass', dkim: 'fail', dmarc: 'fail', good: false,
      why: 'amaz0n with a zero, and DKIM fails — the signature does not match. Block.' },
    { from: 'it-help@yourcompany-secure.com', name: 'IT Helpdesk', subject: 'Reset your mailbox password here', spf: 'fail', dkim: 'none', dmarc: 'fail', good: false,
      why: 'It pretends to be your own company but sends from a lookalike domain, and SPF fails. Block.' },
    { from: 'promo@cheap-deals-now.com', name: 'Deals Now', subject: '90% OFF — today only, act fast', spf: 'pass', dkim: 'fail', dmarc: 'none', good: false,
      why: 'DKIM fails and there is no DMARC record — unproven bulk mail. Block.' },
    { from: 'doc-sign@secure-docs-share.net', name: 'DocuShare', subject: 'A document was shared with you', spf: 'none', dkim: 'fail', dmarc: 'fail', good: false,
      why: 'Fake document-share lure. DKIM and DMARC fail. Block.' },
    { from: 'refund@tax-office-claims.com', name: 'Tax Refunds', subject: 'Your tax refund of $1,240 is waiting', spf: 'fail', dkim: 'none', dmarc: 'none', good: false,
      why: 'Governments do not email refunds like this — and SPF fails. Block.' },

    /* --- the teaching cases: real-looking mail that is NOT fully proven -> BLOCK (this is why senders must fix their setup) --- */
    { from: 'newsletter@localgym.com', name: 'Local Gym', subject: 'December class timetable is out', spf: 'pass', dkim: 'pass', dmarc: 'none', good: false,
      why: 'Friendly mail — but the gym never set up DMARC, so nothing stops fakes using their name. In this game, unproven means block. This is why senders need DMARC.' },
    { from: 'invoices@accounting-app.com', name: 'Accounting App', subject: 'Invoice #209 from your supplier', spf: 'pass', dkim: 'none', dmarc: 'fail', good: false,
      why: 'The app sends invoices without DKIM signing, so DMARC fails. Real mail, broken setup — filters still punish it. Block.' },
    { from: 'owner@familybakery.com', name: 'Family Bakery', subject: 'This week: fresh sourdough on Saturday', spf: 'fail', dkim: 'pass', dmarc: 'fail', good: false,
      why: 'The bakery changed email tools and forgot to update SPF — now their own mail fails. A one-line DNS fix saves them. Block for now.' },
    { from: 'bookings@travel-deals.com', name: 'Travel Deals', subject: 'Your booking confirmation — Lisbon', spf: 'pass', dkim: 'pass', dmarc: 'fail', good: false,
      why: 'SPF and DKIM pass, but for the wrong domain — DMARC alignment fails. The checks must match the From address. Block.' },
    { from: 'updates@crypto-news.io', name: 'Crypto News', subject: 'Market update: what moved today', spf: 'none', dkim: 'pass', dmarc: 'none', good: false,
      why: 'No SPF record and no DMARC — only DKIM passes. One check is not proof. Block.' },
    { from: 'admin@school-portal.org', name: 'School Portal', subject: 'Term dates and fee reminder', spf: 'pass', dkim: 'fail', dmarc: 'fail', good: false,
      why: 'Their DKIM key was deleted during a website move — a common accident. Until it is fixed, their mail cannot prove itself. Block.' }
  ];

  var ROUND = 15;              /* emails per game */
  var state = null;
  var timerId = null, tickId = null;

  function el(tag, cls, text) {
    var n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text != null) n.textContent = text;
    return n;
  }
  function shuffle(a) {
    for (var i = a.length - 1; i > 0; i--) {
      var j = Math.floor(Math.random() * (i + 1));
      var t = a[i]; a[i] = a[j]; a[j] = t;
    }
    return a;
  }
  function stamp(label, status) {
    var s = el('span', 'idg-stamp idg-' + status);
    s.textContent = label + (status === 'pass' ? ' ✓ pass' : status === 'fail' ? ' ✗ fail' : ' — missing');
    return s;
  }

  function clearTimers() {
    if (timerId) { clearTimeout(timerId); timerId = null; }
    if (tickId) { clearInterval(tickId); tickId = null; }
  }

  function renderStart() {
    clearTimers();
    root.innerHTML = '';
    var box = el('div', 'idg-start');
    box.appendChild(el('div', 'idg-start-title', 'Inbox Defender'));
    var p = el('p', 'idg-start-text',
      'Emails are coming in. Each one shows its three proof stamps — SPF, DKIM and DMARC. ' +
      'Allow an email only when all three pass. Anything else is unproven, and real filters block it or dump it in spam.');
    box.appendChild(p);
    var p2 = el('p', 'idg-start-text', 'You have 3 hearts. Wrong call, or too slow, and you lose one. 15 emails — how many can you judge right?');
    box.appendChild(p2);
    var btn = el('button', 'idg-btn idg-btn-main', 'Start defending');
    btn.type = 'button';
    btn.addEventListener('click', startGame);
    box.appendChild(btn);
    root.appendChild(box);
  }

  function startGame() {
    var deck = shuffle(MAIL.slice()).slice(0, ROUND);
    state = { deck: deck, i: 0, score: 0, hearts: 3, streak: 0, best: 0, correct: 0, locked: false };
    renderMail();
  }

  function timeFor(i) { return Math.max(3200, 6000 - i * 200); } /* ms per email, speeds up */

  function renderMail() {
    clearTimers();
    var m = state.deck[state.i];
    state.locked = false;
    root.innerHTML = '';

    var hud = el('div', 'idg-hud');
    hud.appendChild(el('span', 'idg-hud-item', 'Score: ' + state.score));
    hud.appendChild(el('span', 'idg-hud-item', 'Email ' + (state.i + 1) + ' of ' + state.deck.length));
    hud.appendChild(el('span', 'idg-hud-item idg-hearts', '❤'.repeat(state.hearts) + '🖤'.repeat(3 - state.hearts)));
    root.appendChild(hud);

    var barWrap = el('div', 'idg-bar-wrap');
    var bar = el('div', 'idg-bar');
    barWrap.appendChild(bar);
    root.appendChild(barWrap);

    var card = el('div', 'idg-card');
    card.appendChild(el('div', 'idg-subject', m.subject));
    card.appendChild(el('div', 'idg-from', 'From: ' + m.name + ' <' + m.from + '>'));
    var stamps = el('div', 'idg-stamps');
    stamps.appendChild(stamp('SPF', m.spf));
    stamps.appendChild(stamp('DKIM', m.dkim));
    stamps.appendChild(stamp('DMARC', m.dmarc));
    card.appendChild(stamps);
    root.appendChild(card);

    var fb = el('div', 'idg-feedback');
    fb.setAttribute('aria-live', 'polite');
    root.appendChild(fb);

    var actions = el('div', 'idg-actions');
    var allow = el('button', 'idg-btn idg-btn-allow', '✓ Allow');
    allow.type = 'button';
    var block = el('button', 'idg-btn idg-btn-block', '✕ Block');
    block.type = 'button';
    allow.addEventListener('click', function () { decide(true); });
    block.addEventListener('click', function () { decide(false); });
    actions.appendChild(allow);
    actions.appendChild(block);
    root.appendChild(actions);

    /* countdown */
    var limit = timeFor(state.i), started = Date.now();
    bar.style.width = '100%';
    tickId = setInterval(function () {
      var left = limit - (Date.now() - started);
      bar.style.width = Math.max(0, (left / limit) * 100) + '%';
      if (left < 1500) bar.classList.add('idg-bar-low');
    }, 50);
    timerId = setTimeout(function () { decide(null); }, limit);
  }

  function decide(allowed) {
    if (!state || state.locked) return;
    state.locked = true;
    clearTimers();
    var m = state.deck[state.i];
    var fb = root.querySelector('.idg-feedback');
    var right = (allowed === m.good);
    if (allowed === null) {
      right = false;
      state.streak = 0;
      state.hearts--;
      fb.className = 'idg-feedback idg-fb-bad';
      fb.textContent = 'Too slow — the filter timed out and dropped it. ' + m.why;
    } else if (right) {
      state.correct++;
      state.streak++;
      state.best = Math.max(state.best, state.streak);
      var pts = 10 + (state.streak % 5 === 0 ? 25 : 0);
      state.score += pts;
      fb.className = 'idg-feedback idg-fb-good';
      fb.textContent = 'Correct (+' + pts + '). ' + m.why;
    } else {
      state.streak = 0;
      state.hearts--;
      fb.className = 'idg-feedback idg-fb-bad';
      fb.textContent = (allowed ? 'That one was not proven — it should have been blocked. ' : 'That one was fully proven — it should have been allowed. ') + m.why;
    }
    var hudScore = root.querySelector('.idg-hud-item');
    if (hudScore) hudScore.textContent = 'Score: ' + state.score;
    var hearts = root.querySelector('.idg-hearts');
    if (hearts) hearts.textContent = '❤'.repeat(Math.max(0, state.hearts)) + '🖤'.repeat(3 - Math.max(0, state.hearts));

    setTimeout(function () {
      state.i++;
      if (state.hearts <= 0 || state.i >= state.deck.length) renderEnd();
      else renderMail();
    }, 2100);
  }

  function renderEnd() {
    clearTimers();
    root.innerHTML = '';
    var box = el('div', 'idg-start');
    var total = state.deck.length;
    box.appendChild(el('div', 'idg-start-title', state.hearts <= 0 ? 'The inbox got flooded' : 'Shift complete'));
    var line = 'You judged ' + state.correct + ' of ' + total + ' emails right. Score: ' + state.score + ' · Best streak: ' + state.best + '.';
    box.appendChild(el('p', 'idg-start-text', line));
    box.appendChild(el('p', 'idg-start-text',
      'That is the whole game in real life too: SPF, DKIM and DMARC are the three stamps. ' +
      'If your domain is missing one, your real emails are the ones getting blocked.'));
    var cta = el('a', 'idg-btn idg-btn-main', 'Check your real domain — free');
    cta.href = '#toolkit';
    box.appendChild(cta);
    var again = el('button', 'idg-btn idg-btn-ghost', 'Play again');
    again.type = 'button';
    again.addEventListener('click', startGame);
    box.appendChild(again);
    root.appendChild(box);
  }

  renderStart();
})();
