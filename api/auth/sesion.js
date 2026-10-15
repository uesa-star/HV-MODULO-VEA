/**
 * VEA — Endpoints de sesión y presencia (consolidados).
 * Se fusionaron aquí me/logout/log/presencia para no superar el límite de 12
 * Serverless Functions del plan Hobby de Vercel. El cliente sigue usando las
 * rutas originales; vercel.json las reescribe a ?recurso=<nombre>:
 *   GET       /api/auth/me
 *   POST      /api/auth/logout
 *   GET       /api/auth/log        (solo ADM)
 *   POST/GET  /api/auth/presencia
 */
const { cookie, sesion, sesionAdm } = require('../../lib/session');
const { admActivo, marcarVisto, leerConfig, sesionActiva, clavesSupabase,
        esAdminSesion, modulosDeCorreo, MODULOS_VEA,
        marcarSalida, marcarPresencia } = require('../../lib/control');
const { esIpLocal, consultarGeo } = require('../../lib/geolocalizar');
const { asegurarTablas } = require('../../lib/tablas');

const SUPABASE_URL = 'https://qtsfkoasfoaovadilwgk.supabase.co';

module.exports = async function handler(req, res) {
  const recurso = String(req.query.recurso || '');
  if (recurso === 'me') return manejarMe(req, res);
  if (recurso === 'logout') return manejarLogout(req, res);
  if (recurso === 'log') return manejarLog(req, res);
  if (recurso === 'presencia') return manejarPresencia(req, res);
  res.setHeader('Allow', 'GET, POST');
  return res.status(404).json({ error: 'Recurso no encontrado' });
};

// ── GET /api/auth/me → estado de la sesión actual ──────────────────────────
async function manejarMe(req, res) {
  if (req.method !== 'GET') {
    res.setHeader('Allow', 'GET');
    return res.status(405).json({ error: 'Method Not Allowed' });
  }

  res.setHeader('Cache-Control', 'no-store, max-age=0');
  // Misma regla que /api/vea-data, /api/alerts y /api/app: cookie vigente +
  // dominio Google permitido + cuenta activa + sesion_v sin cambiar.
  const activa = await sesionActiva(req);
  if (!activa.ok) {
    return res.status(401).json({ autenticado: false, adm: false });
  }
  const datos = activa.datos;
  let adm = false;
  const vistas = [];
  if (datos.sid) vistas.push(datos.sid);
  if (sesionAdm(req)) {
    const a = await admActivo(req);
    adm = Boolean(a);
    if (a && a.sid && a.sid !== datos.sid) vistas.push(a.sid);
  }
  await Promise.all(vistas.map(marcarVisto));
  // ¿La sesión Google actual es la del correo registrado como administrador?
  // Solo se devuelve sí/no (nunca el correo), para mostrarle la pestaña ADM
  // únicamente a él sin exponer nada a los demás usuarios.
  let admEmail = false;
  if (datos.proveedor === 'google' && datos.email) {
    try {
      const lectura = await leerConfig(['adm_email']);
      const cfg = (lectura && lectura.cfg) || {};
      admEmail = Boolean(cfg.adm_email) &&
        String(datos.email).toLowerCase() === String(cfg.adm_email).toLowerCase();
    } catch (_) { admEmail = false; }
  }
  // Permiso de «Importación de Datos»: siempre el ADM, o la cuenta de
  // vea_usuarios con puede_importar=true habilitada desde el panel ADM.
  // Fail-closed: si la columna/tabla no existe o falla la lectura → false.
  let puedeImportar = adm || admEmail;
  if (!puedeImportar && datos.email) {
    try {
      const claves = clavesSupabase();
      if (claves) {
        const rq = await fetch(
          `${SUPABASE_URL}/rest/v1/vea_usuarios?usuario=eq.${encodeURIComponent(String(datos.email).toLowerCase())}&select=puede_importar,activo&limit=1`,
          { headers: claves, cache: 'no-store' }
        );
        const fr = rq.ok ? await rq.json().catch(() => null) : null;
        const fu = Array.isArray(fr) && fr.length ? fr[0] : null;
        puedeImportar = Boolean(fu && fu.activo !== false && fu.puede_importar === true);
      }
    } catch (_) { puedeImportar = false; }
  }
  // Permisos por módulo: el ADM recibe la lista completa; el resto, la suya.
  // Fail-closed: si no se puede leer, se responde lista vacía (nada de módulos).
  const esAdmin = adm || admEmail || await esAdminSesion(req, datos);
  let modulos = [];
  if (esAdmin) {
    modulos = MODULOS_VEA.slice();
  } else if (datos.email) {
    try { modulos = await modulosDeCorreo(datos.email); } catch (_) { modulos = []; }
  }
  return res.status(200).json({
    autenticado: true,
    email: datos.email || '',
    nombre: datos.nombre || '',
    proveedor: datos.proveedor || '',
    debe_cambiar: Boolean(datos.dc),
    admEmail: admEmail,
    adm: adm,
    es_admin: esAdmin,
    modulos: modulos,
    puede_importar: puedeImportar
  });
}

// ── POST /api/auth/logout → cierre de sesión ───────────────────────────────
async function manejarLogout(req, res) {
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
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
}

// ── GET /api/auth/log → registro de accesos (solo ADM) ─────────────────────
const MAX_GEO_POR_LLAMADA = 50; // IPs nuevas a resolver por carga (acota el tiempo)

function cabeceras(token) {
  return { apikey: token, Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' };
}

async function manejarLog(req, res) {
  if (req.method !== 'GET') {
    res.setHeader('Allow', 'GET');
    return res.status(405).json({ error: 'Method Not Allowed' });
  }

  res.setHeader('Cache-Control', 'no-store, max-age=0');

  if (!(await admActivo(req))) {
    return res.status(401).json({ error: 'Se requiere sesión de administrador' });
  }

  const service = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!service) {
    return res.status(503).json({ error: 'Consulta no disponible' });
  }

  try {
    // Purga perezosa: al cargar el registro se borran filas de más de 12 meses.
    // Mantiene la tabla acotada sin necesidad de cron ni jobs externos.
    const corte = new Date(Date.now() - 365 * 24 * 60 * 60 * 1000).toISOString();
    await fetch(
      `${SUPABASE_URL}/rest/v1/vea_login_log?creado_en=lt.${encodeURIComponent(corte)}`,
      { method: 'DELETE', headers: { apikey: service, Authorization: `Bearer ${service}`, Prefer: 'return=minimal' }, cache: 'no-store' }
    );

    const r = await fetch(
      `${SUPABASE_URL}/rest/v1/vea_login_log?select=creado_en,email,nombre,proveedor,ip,exito,user_agent,sesion_id,salida,ultimo_visto,estado,pais,pais_iso,vpn,isp&order=creado_en.desc&limit=200`,
      { headers: cabeceras(service), cache: 'no-store' }
    );
    const texto = await r.text();
    if (!r.ok) {
      // El error crudo de Postgres no se devuelve al cliente.
      console.error('[auth/log] Supabase respondió', r.status, texto.slice(0, 300));
      res.setHeader('Content-Type', 'application/json; charset=utf-8');
      return res.status(502).json({ error: 'No se pudo leer el registro. Intente nuevamente.' });
    }
    const accesos = JSON.parse(texto);

    // Documento y nacionalidad del titular (join por correo, tolera errores).
    try {
      const u = await fetch(
        `${SUPABASE_URL}/rest/v1/vea_usuarios?select=usuario,nacionalidad,tipo_documento,numero_documento&activo=eq.true&limit=1000`,
        { headers: cabeceras(service), cache: 'no-store' }
      );
      if (u.ok) {
        const mapa = new Map();
        for (const f of await u.json()) if (f.usuario) mapa.set(f.usuario.toLowerCase(), f);
        for (const a of accesos) {
          const d = mapa.get(String(a.email || '').toLowerCase());
          if (d) {
            a.documento = d.numero_documento ? `${d.tipo_documento || 'DNI'} ${d.numero_documento}` : '';
            a.nacionalidad = d.nacionalidad || '';
          }
        }
      }
    } catch (e) {
      console.error('[auth/log] join usuarios:', String(e?.message || e));
    }

    // País + VPN de las filas que aún no lo tienen (una sola consulta batch).
    try {
      const sinGeo = [];
      const vistas = new Set();
      for (const a of accesos) {
        if (a.pais || !a.ip || esIpLocal(a.ip) || vistas.has(a.ip)) continue;
        vistas.add(a.ip);
        if (sinGeo.length < MAX_GEO_POR_LLAMADA) sinGeo.push(a.ip);
      }
      if (sinGeo.length) {
        const geo = await consultarGeo(sinGeo);
        if (geo.size) {
          const parcheadas = new Set();
          for (const a of accesos) {
            const g = geo.get(a.ip);
            if (!g || a.pais) continue;
            Object.assign(a, g);
            if (parcheadas.has(a.ip)) continue;
            parcheadas.add(a.ip);
            // Persiste por IP único: la próxima carga no repite la consulta.
            fetch(
              `${SUPABASE_URL}/rest/v1/vea_login_log?ip=eq.${encodeURIComponent(a.ip)}&pais=eq.`,
              { method: 'PATCH', headers: cabeceras(service), body: JSON.stringify(g), Prefer: 'return=minimal' }
            ).catch(() => null);
          }
        }
      }
    } catch (e) {
      console.error('[auth/log] geo:', String(e?.message || e));
    }

    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    return res.status(200).send(JSON.stringify({ accesos }));
  } catch (err) {
    console.error('[auth/log] error:', String(err?.message || err));
    return res.status(502).json({ error: 'No se pudo leer el registro' });
  }
}

// ── POST/GET /api/auth/presencia → latido y panel de presencia ─────────────
const ESTADOS = ['activo', 'inactivo', 'por_cerrar'];
const CAMPOS = 'creado_en,email,nombre,proveedor,ip,user_agent,sesion_id,salida,ultimo_visto,estado,pais,pais_iso,vpn';
const CAMPOS_SIN_ESTADO = 'creado_en,email,nombre,proveedor,ip,user_agent,sesion_id,salida,ultimo_visto,pais,pais_iso,vpn';

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

async function manejarPresencia(req, res) {
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
}
