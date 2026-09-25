// Cloudflare Pages Function: shared family password vault storage.
//
//   GET    /api/vault  -> { rev, data, updatedAt, updatedBy }  (404 { rev: 0 } when empty)
//   PUT    /api/vault  <- { baseRev, data }  -> { rev }        (409 + current vault if baseRev is stale)
//   DELETE /api/vault  -> { rev: 0 }                           (erases the shared vault)
//
// `data` is the vault exactly as the browser stores it: already encrypted with
// AES-256-GCM under a key derived from the master password. This function never
// sees the master password or any plaintext.
//
// Bindings (Pages project -> Settings -> Bindings / Variables):
//   VAULT_KV        KV namespace (required)
//   ALLOWED_EMAILS  comma-separated emails allowed to use the vault (recommended)
//
// The whole site is expected to sit behind Cloudflare Access, which adds the
// Cf-Access-Authenticated-User-Email header to every request it lets through.

const KEY = 'family-vault';
const MAX_BYTES = 2 * 1024 * 1024;

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
  if (!email) return false; // not signed in through Cloudflare Access
  const allowed = (env.ALLOWED_EMAILS || '')
    .split(',')
    .map(s => s.trim().toLowerCase())
    .filter(Boolean);
  return allowed.length === 0 || allowed.includes(email);
}

function isVaultBlob(d) {
  return d && typeof d === 'object' && d.v === 1 &&
    ['salt', 'iv', 'ct'].every(k => typeof d[k] === 'string' && d[k].length > 0);
}

export async function onRequest({ request, env }) {
  if (!env.VAULT_KV) return json({ error: 'Vault storage is not configured (missing VAULT_KV binding).' }, 503);

  const email = userEmail(request);
  if (!isAllowed(email, env)) return json({ error: 'Forbidden' }, 403);

  const current = await env.VAULT_KV.get(KEY, 'json');
  const currentRev = current ? current.rev : 0;

  switch (request.method) {
    case 'GET':
      return current ? json(current) : json({ rev: 0 }, 404);

    case 'PUT': {
      const text = await request.text();
      if (text.length > MAX_BYTES) return json({ error: 'Vault too large' }, 413);
      let body;
      try { body = JSON.parse(text); } catch { return json({ error: 'Invalid JSON' }, 400); }
      if (!body || !Number.isInteger(body.baseRev) || !isVaultBlob(body.data)) {
        return json({ error: 'Expected { baseRev, data }' }, 400);
      }
      // Optimistic concurrency: the client must have seen the latest revision.
      if (body.baseRev !== currentRev) return json(current || { rev: 0 }, 409);
      const next = { rev: currentRev + 1, data: body.data, updatedAt: new Date().toISOString(), updatedBy: email };
      await env.VAULT_KV.put(KEY, JSON.stringify(next));
      return json({ rev: next.rev, updatedAt: next.updatedAt });
    }

    case 'DELETE':
      await env.VAULT_KV.delete(KEY);
      return json({ rev: 0 });

    default:
      return json({ error: 'Method not allowed' }, 405);
  }
}
