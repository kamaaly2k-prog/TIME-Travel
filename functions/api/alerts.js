// Cloudflare Pages Function: travel safety check for a destination.
//
//   GET /api/alerts?iso2=JP&country=Japan&lat=35.0&lon=135.7
//     -> { advisory: { level, text, regional, updated, url, source } | null,
//          events: [{ type, name, level, from, to, distanceKm, url }],
//          errors: { advisory?, events? } }
//
// Sources (fetched server-side so browser CORS rules don't apply; each cached for an hour):
//   - Government of Canada travel advisories (open data, per-country risk level 0–3)
//   - GDACS (Global Disaster Alert and Coordination System) — earthquakes, cyclones,
//     floods, volcanoes, droughts and wildfires with an Orange or Red alert in the last 30 days
// Behind Cloudflare Access like the rest of the site; no user data is stored.

const ADVISORY_URL = 'https://data.international.gc.ca/travel-voyage/index-updated.json';
const GDACS_URL = 'https://www.gdacs.org/gdacsapi/api/events/geteventlist/SEARCH';
const CACHE_SECONDS = 3600;
const NEAR_KM = 800;

const EVENT_NAMES = { EQ: 'Earthquake', TC: 'Tropical cyclone', FL: 'Flood', VO: 'Volcano', DR: 'Drought', WF: 'Wildfire' };

function json(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json', 'cache-control': 'private, max-age=600' },
  });
}

// Fetch JSON through the Workers cache so upstream feeds are hit at most once an hour per URL.
async function cachedJson(url) {
  const cache = typeof caches !== 'undefined' ? caches.default : null;
  const key = new Request(url);
  if (cache) {
    const hit = await cache.match(key);
    if (hit) return hit.json();
  }
  const res = await fetch(url, { headers: { accept: 'application/json', 'user-agent': 'time-travel-family-site' } });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const text = await res.text();
  const data = JSON.parse(text);
  if (cache) {
    await cache.put(key, new Response(text, { headers: { 'content-type': 'application/json', 'cache-control': `max-age=${CACHE_SECONDS}` } }));
  }
  return data;
}

function haversineKm(lat1, lon1, lat2, lon2) {
  const r = d => (d * Math.PI) / 180;
  const a = Math.sin(r(lat2 - lat1) / 2) ** 2 + Math.cos(r(lat1)) * Math.cos(r(lat2)) * Math.sin(r(lon2 - lon1) / 2) ** 2;
  return 6371 * 2 * Math.asin(Math.sqrt(a));
}

async function getAdvisory(iso2) {
  const all = await cachedJson(ADVISORY_URL);
  const d = all && all.data && all.data[iso2];
  if (!d) return null;
  const eng = d.eng || {};
  const level = Number(d['advisory-state']);
  return {
    level: Number.isFinite(level) ? level : null,
    text: eng['advisory-text'] || null,
    regional: !!Number(d['has-regional-advisory']),
    updated: eng['friendly-date'] || d['date-published'] || null,
    url: eng['url-slug'] ? `https://travel.gc.ca/destinations/${eng['url-slug']}` : 'https://travel.gc.ca/travelling/advisories',
    source: 'Government of Canada',
  };
}

async function getEvents(lat, lon, country) {
  const day = n => new Date(Date.now() - n * 86400000).toISOString().slice(0, 10);
  const url = `${GDACS_URL}?eventlist=EQ;TC;FL;VO;DR;WF&alertlevel=Orange;Red&fromDate=${day(30)}&toDate=${day(0)}`;
  const fc = await cachedJson(url);
  const wanted = (country || '').toLowerCase();
  return (fc.features || [])
    .map(f => {
      const p = f.properties || {};
      const [flon, flat] = (f.geometry && f.geometry.coordinates) || [];
      const distanceKm = Number.isFinite(lat) && Number.isFinite(flat) ? Math.round(haversineKm(lat, lon, flat, flon)) : null;
      return {
        type: EVENT_NAMES[p.eventtype] || p.eventtype || 'Event',
        name: p.name || p.description || '',
        level: p.alertlevel || '',
        country: p.country || '',
        from: p.fromdate || '',
        to: p.todate || '',
        distanceKm,
        url: (p.url && (p.url.report || p.url.details)) || 'https://www.gdacs.org/',
      };
    })
    .filter(e => (e.distanceKm != null && e.distanceKm <= NEAR_KM) || (wanted && e.country.toLowerCase().includes(wanted)))
    .sort((a, b) => (a.distanceKm ?? 1e9) - (b.distanceKm ?? 1e9))
    .slice(0, 6);
}

export async function onRequestGet({ request, env }) {
  const email = (request.headers.get('Cf-Access-Authenticated-User-Email') || '').trim().toLowerCase();
  const allowed = (env.ALLOWED_EMAILS || '').split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
  if (!email || (allowed.length && !allowed.includes(email))) return json({ error: 'Forbidden' }, 403);

  const q = new URL(request.url).searchParams;
  const iso2 = (q.get('iso2') || '').toUpperCase();
  if (!/^[A-Z]{2}$/.test(iso2)) return json({ error: 'iso2 is required' }, 400);
  const lat = parseFloat(q.get('lat')), lon = parseFloat(q.get('lon'));
  const country = (q.get('country') || '').slice(0, 80);

  const [adv, ev] = await Promise.allSettled([getAdvisory(iso2), getEvents(lat, lon, country)]);
  const errors = {};
  if (adv.status === 'rejected') errors.advisory = String(adv.reason && adv.reason.message || adv.reason);
  if (ev.status === 'rejected') errors.events = String(ev.reason && ev.reason.message || ev.reason);
  return json({
    advisory: adv.status === 'fulfilled' ? adv.value : null,
    events: ev.status === 'fulfilled' ? ev.value : [],
    errors,
  });
}
