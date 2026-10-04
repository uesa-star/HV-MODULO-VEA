/**
 * VEA — Cierre de sesión.
 * GET /api/auth/logout → borra la cookie de sesión VEA.
 * GET /api/auth/logout?adm=1 → borra también la sesión ADM.
 * Registra la hora de salida en vea_login_log (permanencia).
 */
const { cookie, sesion, sesionAdm } = require('../../lib/session');
const { marcarSalida } = require('../../lib/control');

module.exports = async function handler(req, res) {
  if (req.method !== 'GET' && req.method !== 'POST') {
    res.setHeader('Allow', 'GET, POST');
    return res.status(405).json({ error: 'Method Not Allowed' });
  }

  const s = sesion(req);
  if (s && s.sid) await marcarSalida(s.sid);

  const limpias = [cookie('vea_session', '', 0), cookie('vea_oauth_state', '', 0)];
  const adm = String(req.query.adm || '');
  const sa = sesionAdm(req);
  if (adm === '1' || sa) {
    if (sa && sa.sid) await marcarSalida(sa.sid);
    limpias.push(cookie('vea_adm', '', 0));
  }

  res.setHeader('Set-Cookie', limpias);
  res.setHeader('Cache-Control', 'no-store');
  return res.status(200).json({ ok: true });
};
