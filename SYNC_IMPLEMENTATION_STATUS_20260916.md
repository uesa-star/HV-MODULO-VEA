# VEA — Estado de implementación de sincronización

- Endpoint creado: `api/vea-sync.js`
- Commit: `a7819a1de99c5c8e9c96bbe3fa24a7aff4535d6b`
- Estado: endpoint publicado; configuración de variables de entorno y prueba real pendientes.
- Variables requeridas en Vercel: `SUPABASE_URL` y `SUPABASE_SERVICE_ROLE_KEY`.
- Tablas permitidas: `edas`, `iras`, `febriles`, `individual`.
- No se declara sincronización operativa hasta completar configuración y prueba de extremo a extremo.

## Automatización diaria (2026-09-24)

- Frecuencia elegida: **todos los días**.
- GitHub Actions `sync-vea.yml`: cron `0 11 * * *` (06:00 Perú / 11:00 UTC).
- Módulo `index.html`: revisión remota cada **24 h** (`VEA_SYNC_SEMANAL_MS`).
- Flujo: Google Drive (Master VEA) → `scripts/sync_vea.py` → Supabase → `index.html` al abrir.
- Secretos GitHub requeridos (no van en el código):
  - `GOOGLE_SERVICE_ACCOUNT_JSON`
  - `SUPABASE_URL`
  - `SUPABASE_SERVICE_ROLE_KEY`
- Secretos Vercel requeridos para `/api/vea-data` y `/api/vea-sync`:
  - `SUPABASE_URL`
  - `SUPABASE_SERVICE_ROLE_KEY`
- La lectura pública del cliente usa solo la publishable key (RLS); la service role key solo existe en GitHub/Vercel.
