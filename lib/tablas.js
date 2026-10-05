/**
 * VEA — Auto-creación idempotente de tablas vía Supabase Management API.
 * Si al hacer una operación falta una tabla, se crea sola en ese momento.
 * Requiere SUPABASE_ACCESS_TOKEN (PAT con permiso database:write) en Vercel.
 * El resultado se memoriza por instancia (solo se crea una vez por proceso).
 */
const PROYECTO = 'qtsfkoasfoaovadilwgk';

const SENTENCIAS = [
  `create table if not exists public.vea_usuarios (
     id bigint generated always as identity primary key,
     usuario text not null unique,
     nombre text not null default '',
     celular text not null default '',
     password_hash text not null,
     activo boolean not null default true,
     debe_cambiar boolean not null default false,
     profesion text not null default '',
     institucion text not null default '',
     sesion_v integer not null default 0,
     cod_hash text not null default '',
     cod_exp bigint not null default 0,
     cod_fallos smallint not null default 0,
     cod_enviado bigint not null default 0,
     creado_en timestamptz not null default now()
   )`,
  `alter table public.vea_usuarios add column if not exists celular text not null default ''`,
  `alter table public.vea_usuarios add column if not exists debe_cambiar boolean not null default false`,
  `alter table public.vea_usuarios add column if not exists profesion text not null default ''`,
  `alter table public.vea_usuarios add column if not exists institucion text not null default ''`,
  `alter table public.vea_usuarios add column if not exists sesion_v integer not null default 0`,
  `alter table public.vea_usuarios add column if not exists cod_hash text not null default ''`,
  `alter table public.vea_usuarios add column if not exists cod_exp bigint not null default 0`,
  `alter table public.vea_usuarios add column if not exists cod_fallos smallint not null default 0`,
  `alter table public.vea_usuarios add column if not exists cod_enviado bigint not null default 0`,
  `alter table public.vea_usuarios enable row level security`,
  `revoke all on public.vea_usuarios from anon, authenticated`,
  `grant select, insert, update, delete on public.vea_usuarios to service_role`,
  `create table if not exists public.vea_config (k text primary key, v text not null default '')`,
  `alter table public.vea_config enable row level security`,
  `revoke all on public.vea_config from anon, authenticated`,
  `grant select, insert, update, delete on public.vea_config to service_role`,
  `create table if not exists public.vea_login_log (
     id bigint generated always as identity primary key,
     creado_en timestamptz not null default now(),
     email text not null default '',
     nombre text not null default '',
     proveedor text not null default '',
     ip text not null default '',
     user_agent text not null default '',
     exito boolean not null default true,
     sesion_id text,
     salida timestamptz,
     ultimo_visto timestamptz
   )`,
  `alter table public.vea_login_log add column if not exists sesion_id text`,
  `alter table public.vea_login_log add column if not exists salida timestamptz`,
  `alter table public.vea_login_log add column if not exists ultimo_visto timestamptz`,
  `grant update, delete on public.vea_login_log to service_role`
];

let estado = null; // null = sin intentar · true = listo · false = sin token o falló

async function asegurarTablas() {
  if (estado === true) return true;
  const pat = process.env.SUPABASE_ACCESS_TOKEN;
  if (!pat) {
    estado = false;
    return false;
  }
  try {
    let creacionOk = true;
    for (const query of SENTENCIAS) {
      const r = await fetch(`https://api.supabase.com/v1/projects/${PROYECTO}/database/query`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${pat}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ query }),
        cache: 'no-store'
      });
      if (!r.ok && r.status !== 409) {
        if (query.trim().toLowerCase().startsWith('create table')) creacionOk = false;
        const texto = await r.text().catch(() => '');
        console.error('[VEA tablas] query', r.status, texto.slice(0, 200));
      }
    }
    if (creacionOk) {
      estado = true;
      return true;
    }
    estado = false;
    return false;
  } catch (e) {
    console.error('[VEA tablas]', e && e.message);
    estado = false;
    return false;
  }
}

module.exports = { asegurarTablas };
