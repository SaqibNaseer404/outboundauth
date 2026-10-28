// Redirect www.outboundauth.com -> outboundauth.com (301).
// The _redirects rule for this is not being honoured by the Pages project,
// so this middleware enforces the canonical host at the edge instead.
// It also injects the chat-bubble widget script into every HTML page
// (the widget itself skips /copilot, which already has the full chat).
export async function onRequest(context) {
  const url = new URL(context.request.url);
  if (url.hostname === 'www.outboundauth.com') {
    url.hostname = 'outboundauth.com';
    return Response.redirect(url.toString(), 301);
  }
  const response = await context.next();
  const type = response.headers.get('content-type') || '';
  if (context.request.method === 'GET' && type.includes('text/html')) {
    return new HTMLRewriter()
      .on('body', {
        element(el) {
          el.append('<script src="/chat-widget.js" defer></script>', { html: true });
        }
      })
      .transform(response);
  }
  return response;
}
