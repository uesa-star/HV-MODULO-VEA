-- VEA — Tabla de usuarios con registro propio (correo + contraseña).
-- Ejecutar en Supabase → SQL Editor. (Idempotente: puede repetirse sin dañar datos.)
create table if not exists public.vea_usuarios (
  id bigint generated always as identity primary key,
  usuario text not null unique,      -- correo en minúsculas (identificador de ingreso)
  nombre text not null default '',
  dni text,
  tipo_documento text not null default 'DNI',
  numero_documento text not null default '',
  celular text not null default '',  -- para avisos / recuperación
  password_hash text not null,
  activo boolean not null default true,
  debe_cambiar boolean not null default false,   -- clave temporal puesta por el ADM
  profesion text not null default '',            -- para aprobación del ADM
  institucion text not null default '',          -- para aprobación del ADM
  sesion_v integer not null default 0,           -- versión de sesión: cambiar/restablecer clave la invalida
  clave_vence timestamptz,                       -- vencimiento de la contraseña (90 días)
  cod_hash text not null default '',             -- hash scrypt del código de recuperación
  cod_exp bigint not null default 0,             -- vencimiento (epoch ms) del código
  cod_fallos smallint not null default 0,        -- intentos fallidos con el código
  cod_enviado bigint not null default 0,         -- último envío de código (epoch ms)
  creado_en timestamptz not null default now()
);

alter table public.vea_usuarios add column if not exists celular text not null default '';
alter table public.vea_usuarios add column if not exists dni text;
alter table public.vea_usuarios add column if not exists tipo_documento text not null default 'DNI';
alter table public.vea_usuarios add column if not exists numero_documento text not null default '';
alter table public.vea_usuarios add column if not exists debe_cambiar boolean not null default false;
alter table public.vea_usuarios add column if not exists profesion text not null default '';
alter table public.vea_usuarios add column if not exists institucion text not null default '';
alter table public.vea_usuarios add column if not exists sesion_v integer not null default 0;
alter table public.vea_usuarios add column if not exists clave_vence timestamptz;
alter table public.vea_usuarios add column if not exists cod_hash text not null default '';
alter table public.vea_usuarios add column if not exists cod_exp bigint not null default 0;
alter table public.vea_usuarios add column if not exists cod_fallos smallint not null default 0;
alter table public.vea_usuarios add column if not exists cod_enviado bigint not null default 0;
create unique index if not exists vea_usuarios_dni_unq on public.vea_usuarios (dni) where dni is not null and dni <> '';
create unique index if not exists vea_usuarios_documento_unq on public.vea_usuarios (tipo_documento, numero_documento) where numero_documento <> '';
alter table public.vea_usuarios enable row level security;
revoke all on public.vea_usuarios from anon, authenticated;
grant select, insert, update, delete on public.vea_usuarios to service_role;

-- Registro de accesos: permitir limpiar filas de prueba desde la API (service key)
grant update, delete on public.vea_login_log to service_role;

-- VEA — Configuración (clave/valor): contraseña y correo propios del administrador.
create table if not exists public.vea_config (
  k text primary key,               -- p.ej. adm_password_hash, adm_email
  v text not null default ''
);
alter table public.vea_config enable row level security;
revoke all on public.vea_config from anon, authenticated;
grant select, insert, update, delete on public.vea_config to service_role;
