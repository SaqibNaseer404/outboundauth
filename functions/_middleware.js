// Redirect www.outboundauth.com -> outboundauth.com (301).
// The _redirects rule for this is not being honoured by the Pages project,
// so this middleware enforces the canonical host at the edge instead.
export async function onRequest(context) {
  const url = new URL(context.request.url);
  if (url.hostname === 'www.outboundauth.com') {
    url.hostname = 'outboundauth.com';
    return Response.redirect(url.toString(), 301);
  }
  return context.next();
}
