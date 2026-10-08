/**
 * VEA — Geolocalización y detección de VPN para el registro de accesos.
 * Proveedor: proxycheck.io (HTTPS, batch, sin llave 100 consultas/día;
 * con PROXYCHECK_API_KEY en Vercel: 1,000/día). Respaldo: ipwho.is.
 * Fail-open: nunca lanza; si todo falla devuelve Map vacío (las filas
 * quedan sin país y se reintenta en la próxima carga, con cooldown
 * para no quemar la cuota diaria cuando el proveedor está caído).
 */
const COOLDOWN_MS = 10 * 60 * 1000; // 10 min sin reintentar tras un fallo total
const TIMEOUT_MS = 6000;
const MAX_CACHE = 500;

let ultimoFallo = 0;
const cache = new Map(); // ip → { pais, pais_iso, vpn, isp }

function esIpLocal(ip) {
  const s = String(ip || '').trim().toLowerCase();
  if (!s || s === 'localhost' || s === '::1' || s === '::ffff:127.0.0.1') return true;
  if (s.startsWith('127.')) return true;
  if (s.startsWith('10.')) return true;
  if (s.startsWith('192.168.')) return true;
  const m = s.match(/^172\.(\d+)\./);
  if (m && +m[1] >= 16 && +m[1] <= 31) return true;
  return false;
}

async function getJson(url) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), TIMEOUT_MS);
  try {
    const r = await fetch(url, { signal: ctrl.signal, cache: 'no-store', redirect: 'follow' });
    if (!r.ok) return null;
    return await r.json();
  } catch (e) {
    return null;
  } finally {
    clearTimeout(t);
  }
}

function armarGeo(d) {
  // d: objeto que devuelve proxycheck o ipwho para una IP
  const iso = String(d.isocode || d.country_code || '').toUpperCase();
  const pais = String(d.country || '').trim();
  if (!pais && !iso) return null;
  const proxy = String(d.proxy || '').toLowerCase() === 'yes';
  const tipo = String(d.type || '').trim();
  const isp = String(d.provider || (d.connection && d.connection.isp) || '').trim();
  return {
    pais: pais || iso,
    pais_iso: /^[A-Z]{2}$/.test(iso) ? iso : '',
    vpn: proxy ? (tipo || 'Proxy') : 'no',
    isp
  };
}

async function porProxycheck(ips) {
  const llave = process.env.PROXYCHECK_API_KEY ? '&key=' + encodeURIComponent(process.env.PROXYCHECK_API_KEY) : '';
  const url = 'https://proxycheck.io/v2/' + ips.join(',') + '/?vpn=1&asn=1&leave=1' + llave;
  const d = await getJson(url);
  if (!d || d.status !== 'ok') return null;
  const out = new Map();
  for (const ip of ips) {
    const g = armarGeo(d[ip] || {});
    if (g) out.set(ip, g);
  }
  return out;
}

async function porIpwho(ips) {
  const out = new Map();
  await Promise.all(ips.map(async (ip) => {
    const d = await getJson('https://ipwho.is/' + encodeURIComponent(ip));
    if (!d || d.success === false) return;
    const g = armarGeo(d);
    if (g) { g.vpn = ''; out.set(ip, g); } // ipwho no informa VPN
  }));
  return out;
}

function memo(ip, g) {
  if (cache.size >= MAX_CACHE) cache.clear();
  cache.set(ip, g);
}

/**
 * Consulta geolocalización/VPN para un arreglo de IPs únicas (sin locales).
 * Devuelve Map ip → { pais, pais_iso, vpn, isp }. Nunca lanza.
 */
async function consultarGeo(ips) {
  const pendientes = [];
  for (const ip of ips) {
    const s = String(ip || '').trim();
    if (!s || esIpLocal(s)) continue;
    if (cache.has(s)) continue;
    pendientes.push(s);
  }
  const out = new Map();
  for (const [ip, g] of cache) if (ips.includes(ip)) out.set(ip, g);
  if (!pendientes.length) return out;

  if (Date.now() - ultimoFallo < COOLDOWN_MS) return out;

  let red = await porProxycheck(pendientes).catch(() => null);
  if (!red) {
    // Respaldo: ipwho.is en pequeño (sin dato de VPN) para no quemar tiempo.
    red = await porIpwho(pendientes.slice(0, 10)).catch(() => null);
  }
  if (!red || !red.size) {
    ultimoFallo = Date.now();
    return out;
  }
  for (const [ip, g] of red) { memo(ip, g); out.set(ip, g); }
  return out;
}

module.exports = { esIpLocal, consultarGeo };
