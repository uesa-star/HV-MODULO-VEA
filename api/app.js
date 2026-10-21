/**
 * VEA — Servidor del módulo (protegido).
 * GET / → exige cookie de sesión Google y devuelve el HTML del módulo.
 * Sin sesión → 302 a /login.html. El HTML vive en node_modules/modulo-vea/
 * (Vercel excluye node_modules del output estático: nadie puede copiarlo
 * con wget/curl directo, solo pasa por esta función autenticada).
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { sesionActiva, esAdminSesion, leerPermisosModulos } = require('../lib/control');

let htmlCache = null;
let semillaCache = null;
let buildCache = null;

function cargarHtml() {
  if (htmlCache) return htmlCache;
  const ruta = path.join(process.cwd(), 'node_modules', 'modulo-vea', 'index.html');
  htmlCache = fs.readFileSync(ruta, 'utf8');
  return htmlCache;
}

function huellaBuild(html) {
  if (!buildCache) buildCache = crypto.createHash('md5').update(html, 'utf8').digest('hex').slice(0, 10);
  return buildCache;
}

function conMarcaBuild(html) {
  if (html.indexOf('name="vea-build"') >= 0) return html;
  return html.replace('</head>', '<meta name="vea-build" content="' + huellaBuild(html) + '">\n</head>');
}

/**
 * Semilla IASS (1.344 casos agregados). Antes viajaba incrustada en el HTML
 * (~318 KB en cada carga). Ahora se sirve aparte en /api/app?recurso=semilla-iass
 * con la misma revalidación de sesión y permiso del módulo.
 */
function cargarSemillaIass() {
  if (semillaCache) return semillaCache;
  const ruta = path.join(process.cwd(), 'node_modules', 'modulo-vea', 'vea-seed-iass.json');
  semillaCache = fs.readFileSync(ruta, 'utf8');
  return semillaCache;
}

const SEMILLA_VACIA = '{"registros":[]}';

/**
 * IASS viaja como semilla incrustada en el HTML (no por /api/vea-data), así que
 * sin este paso llegaría a cualquiera con sesión. Si el usuario no tiene el
 * módulo iass se entrega la semilla vacía.
 */
function sinSemillaIass(html) {
  return html.replace(
    /(<script type="application\/json" id="vea-seed-iass">)[\s\S]*?(<\/script>)/,
    '$1{"registros":[]}$2'
  );
}

module.exports = async function handler(req, res) {
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    res.setHeader('Allow', 'GET, HEAD');
    return res.status(405).json({ error: 'Method Not Allowed' });
  }

  const sesionOk = await sesionActiva(req);
  if (!sesionOk.ok) {
    res.setHeader('Location', '/login.html');
    res.setHeader('Cache-Control', 'no-store');
    return res.status(302).end();
  }

  try {
    const admin = await esAdminSesion(req, sesionOk.datos);
    let modulos = [];
    if (!admin) {
      const mapa = await leerPermisosModulos();
      const correo = String((sesionOk.datos && sesionOk.datos.email) || '').trim().toLowerCase();
      modulos = (mapa && mapa[correo]) || [];
    }

    if (String((req.query && req.query.recurso) || '') === 'semilla-iass') {
      res.setHeader('Content-Type', 'application/json; charset=utf-8');
      res.setHeader('Cache-Control', 'private, max-age=300');
      res.setHeader('X-Robots-Tag', 'noindex, nofollow');
      if (!admin && modulos.indexOf('iass') < 0) return res.status(200).send(SEMILLA_VACIA);
      try { return res.status(200).send(cargarSemillaIass()); }
      catch (_) { return res.status(200).send(SEMILLA_VACIA); }
    }

    let html = cargarHtml();
    if (!admin && modulos.indexOf('iass') < 0) html = sinSemillaIass(html);
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.setHeader('Cache-Control', 'private, no-store, max-age=0');
    res.setHeader('X-Vea-Build', huellaBuild(cargarHtml()));
    html = conMarcaBuild(html);
    res.setHeader('X-Robots-Tag', 'noindex, nofollow');
    return res.status(200).send(html);
  } catch (err) {
    console.error('[VEA app]', err);
    return res.status(500).json({ error: 'Módulo no disponible' });
  }
};
