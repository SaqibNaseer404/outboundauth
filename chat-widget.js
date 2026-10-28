/* OutboundAuth chat bubble — a floating front-end for the Deliverability
   Copilot. Talks to the same /api/chat backend as /copilot (SSE stream).
   Self-contained: injects its own styles and markup. Skips /copilot itself. */
(function () {
  if (window.__oaChatLoaded) return;
  window.__oaChatLoaded = true;
  if (location.pathname.replace(/\/+$/, '') === '/copilot') return;

  var ACCENT = '#087f5b', INK = '#10231e', SOFT = '#daf4e8', BG = '#f4f8f5', LINE = '#cbd9d2';

  var css = ''
    + '.oa-chat-btn{position:fixed;right:20px;bottom:20px;z-index:99990;width:56px;height:56px;border-radius:50%;'
    + 'border:none;background:' + ACCENT + ';color:#fff;cursor:pointer;box-shadow:0 8px 24px rgba(8,60,45,.35);'
    + 'display:flex;align-items:center;justify-content:center;transition:transform .15s ease}'
    + '.oa-chat-btn:hover{transform:scale(1.07)}'
    + '.oa-chat-btn svg{width:28px;height:28px;fill:#fff}'
    + '.oa-chat-badge{position:absolute;top:-2px;right:-2px;width:20px;height:20px;border-radius:50%;background:#e03131;'
    + 'color:#fff;font:700 12px/20px system-ui,sans-serif;text-align:center;border:2px solid #fff}'
    + '.oa-chat-panel{position:fixed;right:20px;bottom:88px;z-index:99991;width:min(370px,calc(100vw - 32px));'
    + 'height:min(540px,calc(100dvh - 116px));background:#fff;border:1px solid ' + LINE + ';border-radius:16px;'
    + 'box-shadow:0 18px 50px rgba(8,40,30,.28);display:none;flex-direction:column;overflow:hidden;'
    + 'font-family:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;color:' + INK + '}'
    + '.oa-chat-panel.open{display:flex}'
    + '.oa-chat-head{background:' + SOFT + ';padding:12px 14px;display:flex;align-items:flex-start;gap:8px;border-bottom:1px solid ' + LINE + '}'
    + '.oa-chat-head b{font-size:15px;display:block}'
    + '.oa-chat-head span{font-size:12px;color:#52665f;display:block;margin-top:1px}'
    + '.oa-chat-head a{font-size:12px;color:' + ACCENT + ';font-weight:600;text-decoration:none;white-space:nowrap}'
    + '.oa-chat-close{margin-left:auto;background:none;border:none;font-size:20px;line-height:1;cursor:pointer;color:#52665f;padding:0 2px}'
    + '.oa-chat-log{flex:1;overflow-y:auto;padding:12px;background:' + BG + ';display:flex;flex-direction:column;gap:8px}'
    + '.oa-chat-msg{max-width:86%;padding:8px 11px;border-radius:12px;font-size:14px;line-height:1.45;white-space:normal;word-wrap:break-word}'
    + '.oa-chat-msg p{margin:0 0 6px}.oa-chat-msg p:last-child{margin-bottom:0}'
    + '.oa-chat-msg ul{margin:2px 0 6px;padding-left:18px}.oa-chat-msg code{background:#0b1715;color:#daf4e8;padding:0 4px;border-radius:4px;font-size:12.5px}'
    + '.oa-chat-msg a{color:' + ACCENT + ';font-weight:600}'
    + '.oa-chat-bot{background:#fff;border:1px solid ' + LINE + ';align-self:flex-start;border-bottom-left-radius:4px}'
    + '.oa-chat-user{background:' + ACCENT + ';color:#fff;align-self:flex-end;border-bottom-right-radius:4px}'
    + '.oa-chat-chips{display:flex;flex-wrap:wrap;gap:6px;padding:8px 12px 0;background:' + BG + '}'
    + '.oa-chat-chip{border:1px solid ' + ACCENT + ';color:' + ACCENT + ';background:#fff;border-radius:999px;'
    + 'padding:5px 10px;font-size:12.5px;cursor:pointer;font-weight:600}'
    + '.oa-chat-chip:hover{background:' + SOFT + '}'
    + '.oa-chat-form{display:flex;gap:8px;padding:10px;border-top:1px solid ' + LINE + ';background:#fff}'
    + '.oa-chat-input{flex:1;border:1px solid ' + LINE + ';border-radius:10px;padding:9px 10px;font:inherit;font-size:14px;resize:none;max-height:90px;outline:none}'
    + '.oa-chat-input:focus{border-color:' + ACCENT + '}'
    + '.oa-chat-send{background:' + ACCENT + ';color:#fff;border:none;border-radius:10px;padding:0 16px;font:inherit;'
    + 'font-weight:700;cursor:pointer}.oa-chat-send:disabled{opacity:.55;cursor:default}'
    + '.oa-chat-foot{font-size:11.5px;color:#52665f;text-align:center;padding:0 10px 8px;background:#fff}'
    + '.oa-chat-foot a{color:' + ACCENT + ';font-weight:600;text-decoration:none}'
    + '.oa-chat-typing span{display:inline-block;width:6px;height:6px;border-radius:50%;background:#8fb8ab;margin-right:3px;animation:oaBlink 1s infinite}'
    + '.oa-chat-typing span:nth-child(2){animation-delay:.2s}.oa-chat-typing span:nth-child(3){animation-delay:.4s}'
    + '@keyframes oaBlink{0%,80%,100%{opacity:.25}40%{opacity:1}}'
    + '@media (max-width:480px){.oa-chat-panel{right:8px;bottom:84px}.oa-chat-btn{right:14px;bottom:14px}}';

  var style = document.createElement('style');
  style.textContent = css;
  document.head.appendChild(style);

  var btn = document.createElement('button');
  btn.className = 'oa-chat-btn';
  btn.setAttribute('aria-label', 'Chat with the Deliverability Copilot');
  btn.innerHTML = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 3C6.5 3 2 6.9 2 11.8c0 2.8 1.5 5.3 3.9 6.9-.2 1.2-.8 2.7-1.9 3.8 0 0 3.4-.2 5.7-1.6.7.2 1.5.2 2.3.2 5.5 0 10-3.9 10-8.8S17.5 3 12 3z"/></svg>'
    + '<span class="oa-chat-badge">1</span>';

  var panel = document.createElement('div');
  panel.className = 'oa-chat-panel';
  panel.setAttribute('role', 'dialog');
  panel.setAttribute('aria-label', 'Deliverability Copilot chat');
  panel.innerHTML = ''
    + '<div class="oa-chat-head"><div><b>Deliverability Copilot</b>'
    + '<span>Ask about spam, SPF, DKIM &amp; DMARC</span></div>'
    + '<a href="/copilot" target="_blank" rel="noopener">Full view ↗</a>'
    + '<button class="oa-chat-close" aria-label="Close chat">×</button></div>'
    + '<div class="oa-chat-log"></div>'
    + '<div class="oa-chat-chips"></div>'
    + '<form class="oa-chat-form"><textarea class="oa-chat-input" rows="1" placeholder="Ask a deliverability question…" aria-label="Your message"></textarea>'
    + '<button class="oa-chat-send" type="submit">Send</button></form>'
    + '<div class="oa-chat-foot">Free AI help · Full deliverability audit — <a href="/#services">from $49</a></div>';

  document.body.appendChild(btn);
  document.body.appendChild(panel);

  var log = panel.querySelector('.oa-chat-log');
  var chipsEl = panel.querySelector('.oa-chat-chips');
  var form = panel.querySelector('.oa-chat-form');
  var input = panel.querySelector('.oa-chat-input');
  var sendBtn = panel.querySelector('.oa-chat-send');
  var history = [];
  var greeted = false;

  function esc(s) {
    return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }
  // Tiny safe renderer: escape first, then **bold**, `code`, links, lists, paragraphs.
  function render(md) {
    var html = esc(md);
    html = html.replace(/\[([^\]]+)\]\(((?:https?:|\/)[^)\s]+)\)/g, '<a href="$2" target="_blank" rel="noopener">$1</a>');
    html = html.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
    html = html.replace(/`([^`]+)`/g, '<code>$1</code>');
    var lines = html.split('\n'), out = [], inList = false;
    for (var i = 0; i < lines.length; i++) {
      var ln = lines[i];
      if (/^\s*[-*]\s+/.test(ln)) {
        if (!inList) { out.push('<ul>'); inList = true; }
        out.push('<li>' + ln.replace(/^\s*[-*]\s+/, '') + '</li>');
      } else {
        if (inList) { out.push('</ul>'); inList = false; }
        if (ln.trim()) out.push('<p>' + ln + '</p>');
      }
    }
    if (inList) out.push('</ul>');
    return out.join('');
  }
  function addMsg(cls, html) {
    var d = document.createElement('div');
    d.className = 'oa-chat-msg ' + cls;
    d.innerHTML = html;
    log.appendChild(d);
    log.scrollTop = log.scrollHeight;
    return d;
  }
  function greet() {
    if (greeted) return;
    greeted = true;
    addMsg('oa-chat-bot', render("Hi! I'm the Deliverability Copilot. Paste a bounce message, an Authentication-Results header, or describe your problem in plain words — I'll tell you what's wrong and what to fix first."));
    var chips = ['Why do my emails go to spam?', 'What does the $49 audit cover?', 'What should my SPF record look like?'];
    chips.forEach(function (c) {
      var b = document.createElement('button');
      b.type = 'button';
      b.className = 'oa-chat-chip';
      b.textContent = c;
      b.addEventListener('click', function () { input.value = c; form.requestSubmit(); });
      chipsEl.appendChild(b);
    });
  }
  function toggle(open) {
    var willOpen = open != null ? open : !panel.classList.contains('open');
    panel.classList.toggle('open', willOpen);
    if (willOpen) {
      var badge = btn.querySelector('.oa-chat-badge');
      if (badge) badge.remove();
      greet();
      input.focus();
    }
  }
  btn.addEventListener('click', function () { toggle(); });
  panel.querySelector('.oa-chat-close').addEventListener('click', function () { toggle(false); });
  document.addEventListener('keydown', function (e) { if (e.key === 'Escape') toggle(false); });

  input.addEventListener('keydown', function (e) {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); form.requestSubmit(); }
  });
  input.addEventListener('input', function () {
    input.style.height = 'auto';
    input.style.height = Math.min(input.scrollHeight, 90) + 'px';
  });

  form.addEventListener('submit', function (e) {
    e.preventDefault();
    var text = input.value.trim();
    if (!text || sendBtn.disabled) return;
    input.value = ''; input.style.height = 'auto';
    chipsEl.style.display = 'none';

    addMsg('oa-chat-user', esc(text));
    history.push({ role: 'user', content: text });

    var bubble = addMsg('oa-chat-bot', '<span class="oa-chat-typing"><span></span><span></span><span></span></span>');
    sendBtn.disabled = true;

    fetch('/api/chat', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ messages: history.slice(-20) })
    }).then(function (resp) {
      if (!resp.ok) {
        return resp.json().catch(function () { return {}; }).then(function (err) {
          throw new Error(err.error || 'Something went wrong. Try again in a minute.');
        });
      }
      var reader = resp.body.getReader();
      var decoder = new TextDecoder();
      var full = '', buf = '';
      function pump() {
        return reader.read().then(function (r) {
          if (r.done) return;
          buf += decoder.decode(r.value, { stream: true });
          var parts = buf.split('\n\n');
          buf = parts.pop();
          for (var i = 0; i < parts.length; i++) {
            var line = parts[i].trim();
            if (!line.startsWith('data:')) continue;
            var data = line.slice(5).trim();
            if (data === '[DONE]') continue;
            try {
              var delta = JSON.parse(data).choices?.[0]?.delta?.content || '';
              full += delta;
              bubble.innerHTML = render(full);
              log.scrollTop = log.scrollHeight;
            } catch (ignore) { /* partial chunk */ }
          }
          return pump();
        });
      }
      return pump().then(function () {
        history.push({ role: 'assistant', content: full });
      });
    }).catch(function (err) {
      bubble.innerHTML = render('Sorry — ' + err.message + ' You can also try the [full Copilot page](/copilot).');
    }).finally(function () {
      sendBtn.disabled = false;
      input.focus();
    });
  });
})();
