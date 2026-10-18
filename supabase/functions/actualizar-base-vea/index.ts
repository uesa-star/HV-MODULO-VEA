// Supabase Edge Function: actualizar-base-vea
//
// Versión idempotente. La versión anterior INSERTABA las filas tal cual, con el
// `_row_id` explícito que envía el cliente. Como `edas._row_id` es la clave
// primaria (`edas_pkey`), reenviar las mismas filas rompía la carga con:
//     duplicate key value violates unique constraint "edas_pkey"
//
// Esta versión REEMPLAZA la tabla (borra por rango de `_row_id` e inserta), o
// hace UPSERT sobre `_row_id` cuando se pide `mode: "upsert"`. Es el mismo
// comportamiento de scripts/sync_vea.py.
//
// Contrato:
//   POST { secret, table, registros|rows, mode? }
//     secret    : debe coincidir con el secreto de función VEA_SYNC_SECRET.
//     table     : edas | iras | febriles | individual | soat | vih | tbc | iaas
//     registros : arreglo de objetos (claves = columnas; se normalizan a
//                 minúsculas/snake_case y se descartan las que no existan).
//     mode      : "replace" (default) | "upsert"
//   Respuesta: { ok, modo, tabla, recibidos, insertados, conteo }
//
// Secretos requeridos:
//   VEA_SYNC_SECRET                  (se define con `supabase secrets set`)
//   SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY  (los inyecta Supabase por defecto)

const TABLAS = new Set(['edas', 'iras', 'febriles', 'individual', 'soat', 'vih', 'tbc', 'iaas']);
const BATCH = 500;
const DELETE_RANGE = 5000;

const SUPABASE_URL = (Deno.env.get('SUPABASE_URL') ?? '').replace(/\/+$/, '');
const SERVICE_KEY = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY') ?? '';
const SYNC_SECRET = Deno.env.get('VEA_SYNC_SECRET') ?? '';

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

function cabeceras(): Record<string, string> {
  return {
    apikey: SERVICE_KEY,
    Authorization: `Bearer ${SERVICE_KEY}`,
    'Content-Type': 'application/json',
  };
}

function normalizarClave(valor: unknown): string | null {
  const texto = String(valor ?? '')
    .normalize('NFKD')
    .replace(/[\u0300-\u036f]/g, '')
    .replace(/[^a-zA-Z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '')
    .toLowerCase();
  return texto || null;
}

function normalizarFila(fila: unknown): Record<string, unknown> {
  const salida: Record<string, unknown> = {};
  if (!fila || typeof fila !== 'object' || Array.isArray(fila)) return salida;
  for (const [clave, valor] of Object.entries(fila as Record<string, unknown>)) {
    const nombre = normalizarClave(clave);
    if (!nombre) continue;
    salida[nombre] = valor === undefined ? null : valor;
  }
  return salida;
}

async function sb(
  method: string,
  table: string,
  query = '',
  extra: { headers?: Record<string, string>; body?: unknown } = {},
): Promise<Response> {
  return await fetch(`${SUPABASE_URL}/rest/v1/${table}${query}`, {
    method,
    headers: { ...cabeceras(), ...(extra.headers ?? {}) },
    body: extra.body === undefined
      ? undefined
      : (typeof extra.body === 'string' ? extra.body : JSON.stringify(extra.body)),
  });
}

async function limiteRowId(table: string, descendente: boolean): Promise<number | null> {
  const r = await sb('GET', table, '?select=_row_id&order=_row_id.' + (descendente ? 'desc' : 'asc') + '&limit=1');
  if (!r.ok) throw new Error(`${table}: no se pudo leer _row_id (${r.status})`);
  const data = await r.json();
  if (!Array.isArray(data) || data.length === 0) return null;
  const valor = data[0]?._row_id;
  return valor === null || valor === undefined ? null : Number(valor);
}

async function contar(table: string): Promise<number> {
  const r = await fetch(`${SUPABASE_URL}/rest/v1/${table}?select=_row_id`, {
    method: 'GET',
    headers: { ...cabeceras(), Prefer: 'count=exact', Range: '0-0' },
  });
  const cr = r.headers.get('content-range') ?? '';
  const m = /\/(\d+)$/.exec(cr);
  if (!m) throw new Error(`${table}: Content-Range inválido (${cr})`);
  return Number(m[1]);
}

async function limpiarPorRangos(table: string): Promise<void> {
  const min = await limiteRowId(table, false);
  const max = await limiteRowId(table, true);
  if (min === null || max === null) return;
  let inicio = min;
  while (inicio <= max) {
    const fin = inicio + DELETE_RANGE;
    const r = await sb(
      'DELETE',
      table,
      `?_row_id=gte.${inicio}&_row_id=lt.${fin}`,
      { headers: { Prefer: 'return=minimal' } },
    );
    if (!r.ok) throw new Error(`${table}: error borrando rango ${inicio}-${fin - 1} (${r.status})`);
    inicio = fin;
  }
}

async function filtrarColumnas(table: string, rows: Record<string, unknown>[]): Promise<Record<string, unknown>[]> {
  if (rows.length === 0) return rows;
  const candidatas = Array.from(new Set(rows.flatMap((fila) => Object.keys(fila)))).sort();
  let pendientes = candidatas.slice();
  const validas = new Set<string>();
  while (pendientes.length > 0) {
    const r = await sb('GET', table, `?select=${encodeURIComponent(pendientes.join(','))}&limit=1`);
    if (r.ok) {
      pendientes.forEach((c) => validas.add(c));
      break;
    }
    let mensaje = '';
    try {
      mensaje = String((await r.json())?.message ?? '');
    } catch {
      mensaje = await r.text();
    }
    const m = /column\s+[\w.]+\.(\w+)\s+does not exist/.exec(mensaje);
    if (m && pendientes.includes(m[1])) {
      pendientes = pendientes.filter((c) => c !== m[1]);
      continue;
    }
    throw new Error(`${table}: no se pudo validar el esquema (${r.status}): ${mensaje.slice(0, 300)}`);
  }
  return rows.map((fila) =>
    Object.fromEntries(Object.entries(fila).filter(([k]) => validas.has(k)))
  );
}

function uniformarClaves(rows: Record<string, unknown>[]): Record<string, unknown>[] {
  const claves = Array.from(new Set(rows.flatMap((fila) => Object.keys(fila))));
  return rows.map((fila) => Object.fromEntries(claves.map((k) => [k, fila[k] ?? null])));
}

async function reemplazar(table: string, rows: Record<string, unknown>[]) {
  const filtradas = uniformarClaves(await filtrarColumnas(table, rows));
  await limpiarPorRangos(table);
  for (let i = 0; i < filtradas.length; i += BATCH) {
    const lote = filtradas.slice(i, i + BATCH);
    const r = await sb('POST', table, '', { headers: { Prefer: 'return=minimal' }, body: lote });
    if (!r.ok) {
      throw new Error(`${table}: error insertando lote (${r.status}): ${(await r.text()).slice(0, 300)}`);
    }
  }
  const total = await contar(table);
  if (total !== filtradas.length) {
    throw new Error(`${table}: verificación final incorrecta; enviados=${filtradas.length} tabla=${total}`);
  }
  return { insertados: filtradas.length, conteo: total };
}

async function upsert(table: string, rows: Record<string, unknown>[]) {
  const filtradas = uniformarClaves(await filtrarColumnas(table, rows));
  for (let i = 0; i < filtradas.length; i += BATCH) {
    const lote = filtradas.slice(i, i + BATCH);
    const r = await sb('POST', table, '?on_conflict=_row_id', {
      headers: { Prefer: 'resolution=merge-duplicates,return=minimal' },
      body: lote,
    });
    if (!r.ok) {
      throw new Error(`${table}: error en upsert (${r.status}): ${(await r.text()).slice(0, 300)}`);
    }
  }
  return { insertados: filtradas.length, conteo: await contar(table) };
}

Deno.serve(async (req: Request): Promise<Response> => {
  try {
    if (req.method !== 'POST') return json({ ok: false, error: 'Method Not Allowed' }, 405);
    if (!SUPABASE_URL || !SERVICE_KEY) return json({ ok: false, error: 'Configuración incompleta' }, 503);
    if (!SYNC_SECRET) return json({ ok: false, error: 'Falta configurar VEA_SYNC_SECRET' }, 503);

    const body = await req.json().catch(() => null);
    if (!body || typeof body !== 'object') return json({ ok: false, error: 'JSON inválido' }, 400);
    if (String((body as Record<string, unknown>).secret ?? '') !== SYNC_SECRET) {
      return json({ ok: false, error: 'Secreto inválido' }, 401);
    }

    const table = String((body as Record<string, unknown>).table ?? '').trim().toLowerCase();
    if (!TABLAS.has(table)) return json({ ok: false, error: 'Tabla no permitida' }, 400);

    const entrada = (body as Record<string, unknown>).registros ?? (body as Record<string, unknown>).rows;
    if (!Array.isArray(entrada) || entrada.length === 0) {
      return json({ ok: false, error: 'Sin registros' }, 400);
    }

    const rows = (entrada as unknown[]).map(normalizarFila).filter((fila) => Object.keys(fila).length > 0);
    if (rows.length === 0) return json({ ok: false, error: 'Sin registros válidos' }, 400);

    const modo = String((body as Record<string, unknown>).mode ?? 'replace').toLowerCase();
    const resultado = modo === 'upsert' ? await upsert(table, rows) : await reemplazar(table, rows);

    return json({ ok: true, modo, tabla: table, recibidos: entrada.length, ...resultado });
  } catch (error) {
    return json({ ok: false, error: String((error as Error)?.message ?? error).slice(0, 500) }, 500);
  }
});
