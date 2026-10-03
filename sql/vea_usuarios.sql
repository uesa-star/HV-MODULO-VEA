-- VEA — Tabla de usuarios con registro propio (usuario + contraseña).
-- Ejecutar en Supabase → SQL Editor.
create table if not exists public.vea_usuarios (
  id bigint generated always as identity primary key,
  usuario text not null unique,
  nombre text not null default '',
  password_hash text not null,
  activo boolean not null default true,
  creado_en timestamptz not null default now()
);

alter table public.vea_usuarios enable row level security;
revoke all on public.vea_usuarios from anon, authenticated;
grant select, insert, update, delete on public.vea_usuarios to service_role;

-- Registro de accesos: permitir limpiar filas (borrar pruebas) desde la API con service key
grant update, delete on public.vea_login_log to service_role;
