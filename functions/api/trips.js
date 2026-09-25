// Cloudflare Pages Function: shared family "saved trips" list.
//
//   GET /api/trips  -> { rev, trips: [...] }
//   PUT /api/trips  <- { baseRev, trips: [...] }  -> { rev }   (409 + current list if baseRev is stale)
//
// Trips are plain destinations and dates (not secrets), stored as JSON in the same
// VAULT_KV namespace under their own key. Same access rules as /api/vault: the site
// sits behind Cloudflare Access and ALLOWED_EMAILS (if set) must include the user.

const KEY = 'family-trips';
const MAX_TRIPS = 100;

function json(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json', 'cache-control': 'no-store' },
  });
}

function userEmail(request) {
  return (request.headers.get('Cf-Access-Authenticated-User-Email') || '').trim().toLowerCase();
}

function isAllowed(email, env) {
  if (!email) return false;
  const allowed = (env.ALLOWED_EMAILS || '').split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
  return allowed.length === 0 || allowed.includes(email);
}

const DATE = /^\d{4}-\d{2}-\d{2}$/;
const str = (v, max) => (typeof v === 'string' ? v.trim().slice(0, max) : '');

function cleanTrip(t) {
  if (!t || typeof t !== 'object') return null;
  const trip = {
    id: str(t.id, 64),
    country: str(t.country, 80),
    city: str(t.city, 80),
    from: DATE.test(t.from) ? t.from : '',
    to: DATE.test(t.to) ? t.to : '',
    note: str(t.note, 300),
    addedBy: str(t.addedBy, 120),
    addedAt: str(t.addedAt, 40),
  };
  return trip.id && trip.country ? trip : null;
}

export async function onRequest({ request, env }) {
  if (!env.VAULT_KV) return json({ error: 'Storage is not configured (missing VAULT_KV binding).' }, 503);
  const email = userEmail(request);
  if (!isAllowed(email, env)) return json({ error: 'Forbidden' }, 403);

  const current = (await env.VAULT_KV.get(KEY, 'json')) || { rev: 0, trips: [] };

  if (request.method === 'GET') return json(current);

  if (request.method === 'PUT') {
    let body;
    try { body = await request.json(); } catch { return json({ error: 'Invalid JSON' }, 400); }
    if (!body || !Number.isInteger(body.baseRev) || !Array.isArray(body.trips)) {
      return json({ error: 'Expected { baseRev, trips }' }, 400);
    }
    if (body.baseRev !== current.rev) return json(current, 409);
    const trips = body.trips.map(cleanTrip).filter(Boolean).slice(0, MAX_TRIPS)
      .map(t => (t.addedBy ? t : { ...t, addedBy: email, addedAt: t.addedAt || new Date().toISOString() }));
    const next = { rev: current.rev + 1, trips, updatedAt: new Date().toISOString(), updatedBy: email };
    await env.VAULT_KV.put(KEY, JSON.stringify(next));
    return json({ rev: next.rev, trips });
  }

  return json({ error: 'Method not allowed' }, 405);
}
