/**
 * VEA — Registro de accesos (solo ADM).
 * GET /api/auth/log → { accesos: [...] } últimas 200 filas de vea_login_log.
 * Requiere cookie vea_adm válida (usuario + contraseña de administración).
 * Cada fila puede traer país/VPN (proxycheck.io, con caché en BD) y
 * documento/nacionalidad del usuario (vea_usuarios por correo).
 * La geolocalización es perezosa y jamás bloquea la respuesta.
 */
const { admActivo } = require('../../lib/control');
const { esIpLocal, consultarGeo } = require('../../lib/geolocalizar');

const SUPABASE_URL = 'https://qtsfkoasfoaovadilwgk.supabase.co';
const MAX_GEO_POR_LLAMADA = 50; // IPs nuevas a resolver por carga (acota el tiempo)

function cabeceras(token) {
  return { apikey: token, Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' };
}

module.exports = async function handler(req, res) {
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
      `${SUPABASE_URL}/rest/v1/vea_login_log?select=creado_en,email,nombre,proveedor,ip,exito,user_agent,sesion_id,salida,ultimo_visto,pais,pais_iso,vpn,isp&order=creado_en.desc&limit=200`,
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
};
