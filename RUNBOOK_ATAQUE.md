# RUNBOOK — Qué hacer si atacan el módulo VEA

Si la web cambió, borraron o alteraron datos, o ven accesos raros, seguir **este orden exacto**.

---

## 0. Detección (señales)

- Contenido de la web distinto al código de GitHub → mirar **Vercel → Deployments** (¿hay un deploy que tú no hiciste?).
- Usuarios reportan claves que no funcionan o claves cambiadas → **ADM → Registro de accesos** (`vea_login_log`): IPs/países raros, accesos `adm:` a horas extrañas.
- Datos que no cuadran (semanas que desaparecieron, tablas vacías).
- **GitHub → Commits** de autores desconocidos; alertas de push; sesiones nuevas en *Settings → Security log*.
- **Alerta automática**: el workflow `Verificación de seguridad VEA` envía correo de GitHub si un chequeo falla.

## 1. Contener (minutos) — NO borrar nada aún

1. Capturar evidencia: pantallazos, `git log`, lista de deployments, exportar el registro de accesos.
2. **Rotar secretos en este orden:**
   - **Supabase → Settings → Database**: rotar clave `service_role` y `anon`; cambiar la clave del usuario `postgres`.
   - **Vercel → Settings → Environment Variables**: pegar el `service_role` nuevo y **cambiar `SESSION_SECRET`** (mata todas las cookies robadas) → *Redeploy*.
   - **GitHub**: cambiar contraseña, revocar tokens/sesiones, quitar colaboradores sospechosos.
3. **Cerrarle la puerta al ADM robado**: en SQL de Supabase:
   ```sql
   update vea_config set v = <nuevo_numero> where k = 'adm_ses';   -- mata cookies ADM
   update vea_config set v = '<correo_nuevo>' where k = 'adm_email';
   ```
4. Desactivar cuentas afectadas: ADM → Usuarios → *Desactivar*.

## 2. Restaurar la web (2 minutos)

- **Rápido**: Vercel → *Deployments* → último deploy bueno → `···` → **Promote to Production**.
- **Definitivo**: ubicar el commit malo (`git log`) → `git revert <sha>` → `git push`.
- Si tocaron `.github/workflows/**` o `scripts/sync_vea.py` (corren con la service key cada 5 min): **rotar secretos ANTES de redesplegar**.

## 3. Restaurar los datos

1. **GitHub → Actions → "Respaldo semanal de la base VEA" → run más reciente → Artifacts** → descargar `respaldo-vea-*` (se conservan 90 días).
2. Respaldos locales manuales: carpeta `backups/` (fuera del repositorio, con datos personales).
3. Restaurar: cada tabla es un `.json`; por ejemplo con Supabase SQL Editor o un `POST /rest/v1/<tabla>` con service key.
4. Si se perdió la estructura: `sql/vea_usuarios.sql` + workflow `vea-restaurar-estructura-estable`.
5. Los datos semanales se reprocesan desde Drive con `sync-vea.yml` (workflow manual).

## 4. Verificar después de restaurar

```bash
node scripts/verificar_seguridad.mjs     # debe dar 9/9 PASS
```
Y en SQL (Supabase → SQL Editor):
```sql
-- privilegios anónimos: TODO debe dar false
select c.relname, has_table_privilege('anon', c.oid, 'SELECT') as anon_select
from pg_class c join pg_namespace n on n.oid = c.relnamespace
where n.nspname = 'public' and c.relkind = 'r' order by 1;

-- la firma debe seguir SECURITY DEFINER
select prosecdef from pg_proc p join pg_namespace n on n.oid = p.pronamespace
where p.proname = 'vea_firma_tabla';
```
Prueba manual: entrar con Google, abrir el módulo, recuperación de clave.

## 5. Reportar

La tabla `individual` contiene datos personales. Si hubo filtración/consulta externa:
conservar evidencia y evaluar reporte (Ley 29733 — Protección de Datos Personales,
y coordinación con SUSALUD si aplica).

---

## Blindaje activo (ya implementado)

| Control | Dónde |
|---|---|
| `/api/vea-sync` exige sesión ADM | `api/vea-sync.js` |
| Sesiones fail-closed (cuenta desactivada/clave cambiada = 401) | `lib/control.js` → `sesionActiva()` |
| `sesion_v` se sube al cambiar clave (mata cookies viejas) | `api/auth/cuentas.js` |
| XSS del panel ADM corregido | `admEsc`/`admAttr` en el módulo |
| Llave pública sin SELECT en tablas de vigilancia | Supabase (REVOKE) |
| Sin fallback directo a Supabase en producción | `node_modules/modulo-vea/index.html` |
| Cabeceras: HSTS, CSP, nosniff, frame | `vercel.json` |
| Verificación automática + alerta por correo | `.github/workflows/seguridad-semanal.yml` (lunes 06:00 UTC y en cada push) |
| Respaldo semanal de la BD (artefacto 90 días) | `.github/workflows/backup-semanal.yml` (domingos 05:00 UTC) |
| Respaldo manual | `node scripts/backup_bd.mjs` |

## Pendiente (lo debe hacer una persona con acceso de administración)

1. **2FA** en GitHub, Vercel y Supabase (Settings → Two-factor authentication).
2. **Proteger la rama `main`**: GitHub → *Settings → Branches → Add rule* → rama `main` →
   activar **“Restrict who can push”** y desactivar **Allow force pushes / Allow deletions**.
3. Rotación programada de `service_role` cada trimestre (Supabase → Settings → Database).
4. Cofia de respaldos locales en unidad/distinto sitio (los 90 días de artefactos no son eternos).
