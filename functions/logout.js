// Cloudflare Pages Function: GET /logout
//
// Signs the visitor fully out of Cloudflare Access so the next visit asks for a
// new one-time PIN. Access keeps two sessions: one for this site (the
// CF_Authorization cookie on this hostname) and one on the team domain
// (<team>.cloudflareaccess.com), which would otherwise sign the visitor straight
// back in. This clears the first and then sends the browser to the team
// domain's logout page to end the second.
//
// The team domain is read from the `iss` claim of the Access token that Access
// attaches to every request (Cf-Access-Jwt-Assertion), so nothing needs to be
// configured. Only *.cloudflareaccess.com is ever used as a redirect target.

const TEAM_DOMAIN = /^https:\/\/[a-z0-9-]+\.cloudflareaccess\.com$/;

function teamDomain(request) {
  const jwt = request.headers.get('Cf-Access-Jwt-Assertion') || '';
  const payload = jwt.split('.')[1];
  if (!payload) return null;
  try {
    const b64 = payload.replace(/-/g, '+').replace(/_/g, '/');
    const claims = JSON.parse(atob(b64 + '='.repeat((4 - (b64.length % 4)) % 4)));
    const iss = String(claims.iss || '').replace(/\/+$/, '');
    return TEAM_DOMAIN.test(iss) ? iss : null;
  } catch {
    return null;
  }
}

export async function onRequestGet({ request }) {
  const team = teamDomain(request);
  // Without a team domain (not behind Access), fall back to this site's own Access logout page.
  const target = team ? `${team}/cdn-cgi/access/logout` : '/cdn-cgi/access/logout';
  return new Response(null, {
    status: 302,
    headers: {
      location: target,
      'cache-control': 'no-store',
      // End this site's Access session.
      'set-cookie': 'CF_Authorization=; Path=/; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Secure; HttpOnly; SameSite=Lax',
    },
  });
}
