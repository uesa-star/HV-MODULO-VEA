/**
 * VEA — Sincronización automática (puente Drive -> GitHub Actions).
 *
 * IMPORTANTE: este script YA NO escribe en Supabase.
 *
 * Antes insertaba las filas del Excel directamente (vía la Edge Function
 * `actualizar-base-vea`) y por eso fallaba con:
 *     duplicate key value violates unique constraint "edas_pkey"
 * La tabla `edas` usa `_row_id` como clave primaria y reenviar el mismo
 * `_row_id` rompía la carga (insert no idempotente) y, además, competía con el
 * workflow de GitHub que ya escribe las mismas tablas (dos escritores).
 *
 * Ahora la ÚNICA vía de escritura es el workflow `.github/workflows/sync-vea.yml`
 * (scripts/sync_vea_guard.py -> scripts/sync_vea.py), que descarga el Master,
 * detecta el cambio real (vea_sync_control) y REEMPLAZA las tablas de forma
 * idempotente (borrado por rango de `_row_id` + inserción + verificación).
 *
 * Este script solo detecta el cambio del Master y dispara ese workflow.
 *
 * Propiedades del script (Proyecto > Configuración > Propiedades del script):
 *   GITHUB_TOKEN    (requerido) PAT con permiso Actions: Read and write sobre
 *                   el repositorio VEA (fine-grained) o scope `workflow` (clásico).
 *   VEA_GITHUB_REPO (opcional) por defecto "uesa-star/HV-MODULO-VEA".
 *   VEA_GITHUB_WORKFLOW (opcional) por defecto "sync-vea.yml".
 *   VEA_GITHUB_REF  (opcional) por defecto "main".
 *   VEA_SYNC_SECRET (ya no se usa aquí; se eliminó su uso).
 */

const VEA_CONF = Object.freeze({
  archivoId: '1TJaDJ5U7M3RZYgfAR6LI3kFTABBH0UYb',
  repo: 'uesa-star/HV-MODULO-VEA',
  workflow: 'sync-vea.yml',
  ref: 'main',
  propiedadUltima: 'VEA_ULTIMA_SINCRONIZACION_MS',
});

function verificarArchivoMaestro() {
  const archivo = DriveApp.getFileById(VEA_CONF.archivoId);
  const resultado = {
    ok: true,
    nombre: archivo.getName(),
    tipo: archivo.getMimeType(),
    tamanoBytes: archivo.getSize(),
    ultimaModificacion: archivo.getLastUpdated().toISOString(),
  };
  console.log(JSON.stringify(resultado, null, 2));
  return resultado;
}

function sincronizarVea() {
  const bloqueo = LockService.getScriptLock();
  if (!bloqueo.tryLock(30000)) {
    const ocupado = { ok: false, actualizado: false, mensaje: 'Otra ejecución en curso; se omite.' };
    console.log(JSON.stringify(ocupado, null, 2));
    return ocupado;
  }
  try {
    const propiedades = PropertiesService.getScriptProperties();
    const archivo = DriveApp.getFileById(VEA_CONF.archivoId);
    const modificadoMs = archivo.getLastUpdated().getTime();
    const ultimoMs = Number(propiedades.getProperty(VEA_CONF.propiedadUltima) || '0');
    if (ultimoMs && modificadoMs <= ultimoMs) {
      const sinCambios = {
        ok: true,
        actualizado: false,
        mensaje: 'El Master no presenta cambios nuevos.',
      };
      console.log(JSON.stringify(sinCambios, null, 2));
      return sinCambios;
    }

    const token = (propiedades.getProperty('GITHUB_TOKEN') || '').trim();
    if (!token) {
      const aviso = {
        ok: false,
        actualizado: false,
        mensaje: 'Falta GITHUB_TOKEN en Propiedades del script. El cron de GitHub sincronizará en <= 5 minutos.',
      };
      console.log(JSON.stringify(aviso, null, 2));
      return aviso;
    }

    dispararWorkflowVea(token, propiedades);

    propiedades.setProperty(VEA_CONF.propiedadUltima, String(modificadoMs));
    const resultado = {
      ok: true,
      actualizado: true,
      mensaje: 'Sincronización disparada en GitHub Actions.',
      archivo: archivo.getName(),
      modificado: new Date(modificadoMs).toISOString(),
    };
    console.log(JSON.stringify(resultado, null, 2));
    return resultado;
  } finally {
    bloqueo.releaseLock();
  }
}

function dispararWorkflowVea(token, propiedades) {
  const repo = (propiedades.getProperty('VEA_GITHUB_REPO') || VEA_CONF.repo).trim();
  const workflow = (propiedades.getProperty('VEA_GITHUB_WORKFLOW') || VEA_CONF.workflow).trim();
  const ref = (propiedades.getProperty('VEA_GITHUB_REF') || VEA_CONF.ref).trim();
  const url =
    'https://api.github.com/repos/' + repo +
    '/actions/workflows/' + workflow + '/dispatches';

  const respuesta = UrlFetchApp.fetch(url, {
    method: 'post',
    contentType: 'application/json',
    headers: {
      Authorization: 'Bearer ' + token,
      Accept: 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
    },
    payload: JSON.stringify({ ref: ref }),
    muteHttpExceptions: true,
  });

  const codigo = respuesta.getResponseCode();
  if (codigo !== 204) {
    throw new Error(
      'GitHub rechazó el disparo (HTTP ' + codigo + '): ' + respuesta.getContentText()
    );
  }
  return true;
}
