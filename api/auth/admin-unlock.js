/**
 * VEA — Validación server-side de la clave para habilitar Google administrativo.
 * Requiere VEA_ADMIN_ACCESS_KEY y VEA_AUTH_SECRET configurados en Vercel.
 * La clave nunca se guarda en el navegador ni se devuelve al cliente.
 */
const crypto = require('crypto');
const { firmar, cookie } = require('../../lib/session');

module.exports = async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store, max-age=0');
  res.setHeader('Pragma', 'no-cache');
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).json({ error: 'Método no permitido.' });
  }

  const esperada = String(process.env.VEA_ADMIN_ACCESS_KEY || '');
  const secreto = String(process.env.VEA_AUTH_SECRET || '');
  if (!esperada || !secreto) {
    return res.status(503).json({ error: 'El acceso administrativo no está configurado en el servidor.' });
  }

  const recibida = String((req.body && req.body.clave) || '');
  const a = Buffer.from(esperada, 'utf8');
  const b = Buffer.from(recibida, 'utf8');
  const valida = a.length > 0 && a.length === b.length && crypto.timingSafeEqual(a, b);
  if (!valida) {
    return res.status(401).json({ error: 'La clave administrativa no es válida.' });
  }

  try {
    // Permiso temporal firmado por servidor; expira en 10 minutos.
    const permiso = firmar({ tipo: 'vea_admin_google_unlock' }, 1 / 6);
    res.setHeader('Set-Cookie', cookie('vea_admin_unlock', permiso, 1 / 6));
    return res.status(200).json({ ok: true });
  } catch (_) {
    return res.status(503).json({ error: 'No se pudo habilitar el acceso administrativo.' });
  }
};
