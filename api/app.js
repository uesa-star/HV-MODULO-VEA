/**
 * VEA — Servidor del módulo (protegido).
 * GET / → exige cookie de sesión Google y devuelve el HTML del módulo.
 * Sin sesión → 302 a /login.html. El HTML vive en node_modules/modulo-vea/
 * (Vercel excluye node_modules del output estático: nadie puede copiarlo
 * con wget/curl directo, solo pasa por esta función autenticada).
 */
const fs = require('fs');
const path = require('path');
const { sesionActiva, esAdminSesion, leerPermisosModulos } = require('../lib/control');

let htmlCache = null;

function cargarHtml() {
  if (htmlCache) return htmlCache;
  const ruta = path.join(process.cwd(), 'node_modules', 'modulo-vea', 'index.html');
  htmlCache = fs.readFileSync(ruta, 'utf8');
  return htmlCache;
}

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
    let html = cargarHtml();
    const admin = await esAdminSesion(req, sesionOk.datos);
    if (!admin) {
      const mapa = await leerPermisosModulos();
      const correo = String((sesionOk.datos && sesionOk.datos.email) || '').trim().toLowerCase();
      const modulos = (mapa && mapa[correo]) || [];
      if (modulos.indexOf('iass') < 0) html = sinSemillaIass(html);
    }
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.setHeader('Cache-Control', 'private, no-store, max-age=0');
    res.setHeader('X-Robots-Tag', 'noindex, nofollow');
    return res.status(200).send(html);
  } catch (err) {
    console.error('[VEA app]', err);
    return res.status(500).json({ error: 'Módulo no disponible' });
  }
};
