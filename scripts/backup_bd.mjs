#!/usr/bin/env node
/**
 * Respaldo de la base de datos VEA (JSON por tabla + manifiesto).
 *
 * Uso:
 *   SUPABASE_SERVICE_ROLE_KEY=... node scripts/backup_bd.mjs
 *       → por PostgREST (como lo hace GitHub Actions)
 *   SUPABASE_PAT=... node scripts/backup_bd.mjs
 *       → por Management API / SQL (para respaldo local sin service key)
 *
 * Opciones:
 *   --out <carpeta>        destino (por defecto backups/vea_respaldo_<fecha>)
 *   --tablas a,b,c         solo esas tablas
 *   --url <supabase_url>   por defecto SUPABASE_URL o el proyecto VEA
 *
 * El destino queda en backups/ (ignorado por git: contiene datos personales).
 */
import { mkdirSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

const SUPABASE_URL_DEFECTO = 'https://qtsfkoasfoaovadilwgk.supabase.co';
const args = process.argv.slice(2);
const opt = (nombre, defecto) => {
  const i = args.indexOf(nombre);
  return i >= 0 && args[i + 1] ? args[i + 1] : defecto;
};

const url = (opt('--url', process.env.SUPABASE_URL || SUPABASE_URL_DEFECTO)).replace(/\/+$/, '');
const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY || '';
const pat = process.env.SUPABASE_PAT || '';
const soloTablas = opt('--tablas', '').split(',').map(s => s.trim()).filter(Boolean);

if (!serviceKey && !pat) {
  console.error('Falta SUPABASE_SERVICE_ROLE_KEY (Actions) o SUPABASE_PAT (local).');
  process.exit(2);
}

const fecha = new Date().toISOString().replace(/[:T]/g, '-').slice(0, 16);
const destino = resolve(opt('--out', join('backups', `vea_respaldo_${fecha}`)));
mkdirSync(destino, { recursive: true });

async function sql(consulta) {
  const r = await fetch('https://api.supabase.com/v1/projects/qtsfkoasfoaovadilwgk/database/query', {
    method: 'POST',
    headers: { Authorization: `Bearer ${pat}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ query: consulta })
  });
  if (!r.ok) throw new Error(`Management API ${r.status}: ${(await r.text()).slice(0, 300)}`);
  return r.json();
}

async function listarTablas() {
  if (pat) {
    const filas = await sql(
      "select table_name from information_schema.tables where table_schema='public' and table_type='BASE TABLE' order by 1"
    );
    return filas.map(f => f.table_name);
  }
  const r = await fetch(`${url}/rest/v1/`, {
    headers: { apikey: serviceKey, Authorization: `Bearer ${serviceKey}` }
  });
  if (!r.ok) throw new Error(`OpenAPI ${r.status}`);
  const spec = await r.json();
  return Object.keys(spec.definitions || {}).sort();
}

async function listarColumnas(tabla) {
  if (pat) {
    const filas = await sql(
      `select column_name from information_schema.columns
       where table_schema='public' and table_name='${tabla.replace(/'/g, "''")}' order by ordinal_position`
    );
    return filas.map(f => f.column_name);
  }
  const r = await fetch(`${url}/rest/v1/`, {
    headers: { apikey: serviceKey, Authorization: `Bearer ${serviceKey}` }
  });
  const spec = await r.json();
  return Object.keys((spec.definitions || {})[tabla]?.properties || {});
}

async function leerTabla(tabla, columnas) {
  if (pat) {
    const filas = await sql(`select * from public."${tabla.replace(/"/g, '""')}"`);
    return Array.isArray(filas) ? filas : [];
  }
  // PostgREST limita por página; se pagina con orden total (todas las columnas)
  // para no duplicar ni perder filas entre páginas.
  const orden = columnas.map(c => `${encodeURIComponent(c)}.asc`).join(',');
  const filas = [];
  const limite = 1000;
  for (let offset = 0; ; offset += limite) {
    const u = `${url}/rest/v1/${encodeURIComponent(tabla)}?select=*` +
      (orden ? `&order=${orden}` : '') + `&limit=${limite}&offset=${offset}`;
    const r = await fetch(u, { headers: { apikey: serviceKey, Authorization: `Bearer ${serviceKey}` } });
    if (!r.ok) throw new Error(`${tabla}: HTTP ${r.status} ${(await r.text()).slice(0, 200)}`);
    const lote = await r.json();
    filas.push(...lote);
    if (lote.length < limite) break;
  }
  return filas;
}

try {
  const tablas = (await listarTablas()).filter(t => !soloTablas.length || soloTablas.includes(t));
  const manifiesto = {
    generado_en: new Date().toISOString(),
    origen: url,
    via: pat ? 'management-api' : 'postgrest',
    tablas: {},
    total_filas: 0,
    total_tablas: tablas.length
  };
  for (const tabla of tablas) {
    try {
      const columnas = await listarColumnas(tabla);
      const filas = await leerTabla(tabla, columnas);
      writeFileSync(join(destino, `${tabla}.json`), JSON.stringify(filas, null, 1), 'utf8');
      manifiesto.tablas[tabla] = { filas: filas.length, columnas: columnas.length };
      manifiesto.total_filas += filas.length;
      console.log(`OK ${tabla}: ${filas.length} filas`);
    } catch (e) {
      manifiesto.tablas[tabla] = { error: String(e.message || e) };
      console.error(`ERROR ${tabla}: ${e.message || e}`);
    }
  }
  writeFileSync(join(destino, 'manifiesto.json'), JSON.stringify(manifiesto, null, 2), 'utf8');
  const conError = Object.values(manifiesto.tablas).filter(t => t.error).length;
  console.log(`\nRespaldo en ${destino}`);
  console.log(`Tablas: ${manifiesto.total_tablas} | Filas: ${manifiesto.total_filas} | Errores: ${conError}`);
  process.exit(conError ? 1 : 0);
} catch (e) {
  console.error('Respaldo falló:', e.message || e);
  process.exit(1);
}
