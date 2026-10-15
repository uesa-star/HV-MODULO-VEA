/**
 * VEA — Presencia de usuarios.
 * POST /api/auth/presencia  { estado }  → latido de la sesión actual
 *   (activo / inactivo / por_cerrar). Actualiza ultimo_visto y estado.
 * GET  /api/auth/presencia              → (solo ADM) sesiones abiertas y las
 *   últimas salidas, para el panel «Presencia» del módulo de administración.
 * El latido nunca requiere privilegios: cada sesión solo marca la suya.
 */
const { sesion, sesionAdm } = require('../../lib/session');
const { admActivo, marcarPresencia, sesionActiva } = require('../../lib/control');
const { asegurarTablas } = require('../../lib/tablas');

const SUPABASE_URL = 'https://qtsfkoasfoaovadilwgk.supabase.co';
const ESTADOS = ['activo', 'inactivo', 'por_cerrar'];
const CAMPOS = 'creado_en,email,nombre,proveedor,ip,user_agent,sesion_id,salida,ultimo_visto,estado,pais,pais_iso,vpn';
const CAMPOS_SIN_ESTADO = 'creado_en,email,nombre,proveedor,ip,user_agent,sesion_id,salida,ultimo_visto,pais,pais_iso,vpn';

function cabeceras(token) {
  return { apikey: token, Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' };
}

async function leer(service, campos, filtro) {
  const r = await fetch(
    `${SUPABASE_URL}/rest/v1/vea_login_log?select=${campos}&exito=eq.true&${filtro}`,
    { headers: cabeceras(service), cache: 'no-store' }
  );
  if (r.ok) return { ok: true, datos: await r.json().catch(() => []) };
  return { ok: false };
}

function cuerpoDe(req) {
  let b = req.body;
  if (Buffer.isBuffer(b)) b = b.toString('utf8');
  if (b && typeof b === 'object') return b;
  try { return JSON.parse(String(b || '{}')); } catch (_) { return {}; }
}

module.exports = async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store, max-age=0');

  if (req.method === 'POST') {
    const s = sesion(req);
    const a = sesionAdm(req);
    // Revalida la cuenta: si fue desactivada o su clave se restableció, el
    // latido responde 401 y el cliente sale al login de inmediato.
    if (s && s.sid) {
      const activa = await sesionActiva(req);
      if (!activa.ok) return res.status(401).json({ error: activa.error || 'Sesión no válida' });
    }
    const sids = [];
    if (s && s.sid) sids.push(s.sid);
    if (a && a.sid) sids.push(a.sid);
    if (!sids.length) return res.status(401).json({ error: 'No autenticado' });

    let estado = String(cuerpoDe(req).estado || '');
    if (ESTADOS.indexOf(estado) < 0) estado = 'activo';
    // Crea la columna «estado» si aún no existe (memorizado; no bloquea).
    asegurarTablas().catch(() => {});
    await Promise.all(sids.map(sid => marcarPresencia(sid, estado)));
    return res.status(200).json({ ok: true });
  }

  if (req.method === 'GET') {
    if (!(await admActivo(req))) {
      return res.status(401).json({ error: 'Se requiere sesión de administrador' });
    }
    const service = process.env.SUPABASE_SERVICE_ROLE_KEY;
    if (!service) return res.status(503).json({ error: 'Consulta no disponible' });

    // Asegura que exista la columna «estado» (idempotente y memorizado).
    try { await asegurarTablas(); } catch (_) { /* sigue sin la columna */ }

    try {
      let abiertas = await leer(service, CAMPOS, 'salida=is.null&order=ultimo_visto.desc.nullslast&limit=100');
      let cerradas = await leer(service, CAMPOS, 'salida=not.is.null&order=salida.desc&limit=30');
      // Si la columna «estado» todavía no existe, se reintenta sin ella.
      if (!abiertas.ok || !cerradas.ok) {
        abiertas = await leer(service, CAMPOS_SIN_ESTADO, 'salida=is.null&order=ultimo_visto.desc.nullslast&limit=100');
        cerradas = await leer(service, CAMPOS_SIN_ESTADO, 'salida=not.is.null&order=salida.desc&limit=30');
      }
      res.setHeader('Content-Type', 'application/json; charset=utf-8');
      return res.status(200).send(JSON.stringify({
        abiertas: abiertas.ok && Array.isArray(abiertas.datos) ? abiertas.datos : [],
        cerradas: cerradas.ok && Array.isArray(cerradas.datos) ? cerradas.datos : []
      }));
    } catch (e) {
      console.error('[auth/presencia]', String(e && e.message ? e.message : e));
      return res.status(502).json({ error: 'No se pudo leer la presencia' });
    }
  }

  res.setHeader('Allow', 'GET, POST');
  return res.status(405).json({ error: 'Method Not Allowed' });
};
