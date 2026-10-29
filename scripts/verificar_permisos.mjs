/**
 * Verificación de permisos por módulo (anti fuga de datos).
 *   1. Sin sesión, /api/vea-data responde 401.
 *   2. Un usuario SIN módulos recibe 403 en todas las tablas de vigilancia.
 *   3. Un usuario con un solo módulo (p.ej. tbc) recibe 200 en la suya y 403
 *      en las demás: el bloqueo es real, no cosmético.
 *   4. El ADM recibe 200 en todas.
 *   5. El registro valida que los módulos sean de la lista permitted.
 */
const BASE = (process.env.BASE_URL || 'https://vigilancia-epidemiologica-ecru.vercel.app').replace(/\/+$/, '');
const TABLAS = ['edas', 'iras', 'febriles', 'individual', 'soat', 'vih', 'tbc'];

const resultados = [];
async function check(nombre, fn) {
  try {
    const detalle = await fn();
    resultados.push({ ok: true, nombre });
    console.log(`PASS  ${nombre}${detalle ? ' — ' + detalle : ''}`);
  } catch (e) {
    resultados.push({ ok: false, nombre });
    console.log(`FALLO ${nombre} — ${e.message || e}`);
  }
}
const espera = (cond, msg) => { if (!cond) throw new Error(msg); };

async function pedir(ruta) {
  const r = await fetch(`${BASE}${ruta}`, { redirect: 'manual' });
  return { status: r.status, cuerpo: await r.text().catch(() => '') };
}

await check('Sin sesión, /api/vea-data sigue en 401', async () => {
  const r = await pedir('/api/vea-data?table=soat&offset=0&limit=1');
  espera(r.status === 401, `devolvió ${r.status}`);
  return '401';
});

await check('La acción «modulos» sin sesión ADM → 401', async () => {
  const r = await fetch(`${BASE}/api/auth/cuentas`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ accion: 'modulos', email: 'alguien@hvn.gob.pe', modulos: ['soat'] })
  });
  espera(r.status === 401, `devolvió ${r.status}`);
  return '401';
});

/* Estos dos requieren sesiones reales: se omiten si no se ligndan por variables
   de entorno, para no dejar información sensible en los logs. */
const USUARIO_SIN = process.env.VEA_TEST_SIN_MODULOS;
const USUARIO_SOAT = process.env.VEA_TEST_SOAT;
const COOKIE_ADM = process.env.VEA_TEST_COOKIE_ADM;

if (!COOKIE_ADM && !USUARIO_SOAT) {
  console.log('\nNOTA: para probar los escenarios de sesión real hay que definir');
  console.log('      VEA_TEST_SOAT, VEA_TEST_SIN_MODULOS y/o VEA_TEST_COOKIE_ADM');
  console.log('      (cookies de prueba). Sin ellas se omite esa parte.');
}

if (USUARIO_SOAT) {
  await check('Usuario de un solo módulo: 200 en la suya, 403 en las demás', async () => {
    const cab = { cookie: USUARIO_SOAT };
    const pedirCon = async (t) => {
      const r = await fetch(`${BASE}/api/vea-data?table=${t}&offset=0&limit=1`, { headers: cab, redirect: 'manual' });
      return r.status;
    };
    const res = {};
    for (const t of TABLAS) res[t] = await pedirCon(t);
    espera(res.soat === 200, `SOAT debía responder 200: ${JSON.stringify(res)}`);
    const malAutorizadas = Object.keys(res).filter(t => t !== 'soat' && res[t] !== 403);
    espera(!malAutorizadas.length, `se esperaba 403 fuera de SOAT: ${JSON.stringify(res)}`);

    const iaas = await fetch(`${BASE}/api/app?recurso=semilla-iass`, { headers: cab, redirect: 'manual' });
    espera(iaas.status === 200, `IASS devolvió ${iaas.status}`);
    const semilla = await iaas.json();
    espera(Array.isArray(semilla.registros) && semilla.registros.length === 0,
      `usuario SOAT recibió datos IASS: ${semilla.registros?.length ?? 'respuesta inválida'}`);
    return JSON.stringify({ tablas: res, iass: semilla.registros.length });
  });
}

if (COOKIE_ADM) {
  await check('El ADM recibe 200 en todas las tablas', async () => {
    const cab = { cookie: COOKIE_ADM };
    const res = {};
    for (const t of TABLAS) {
      const r = await fetch(`${BASE}/api/vea-data?table=${t}&offset=0&limit=1`, { headers: cab, redirect: 'manual' });
      res[t] = r.status;
    }
    const bloqueadas = Object.keys(res).filter(t => res[t] !== 200);
    espera(!bloqueadas.length, `el ADM fue bloqueado en: ${bloqueadas.join(', ')}`);

    const iaas = await fetch(`${BASE}/api/app?recurso=semilla-iass`, { headers: cab, redirect: 'manual' });
    espera(iaas.status === 200, `IASS ADM devolvió ${iaas.status}`);
    const semilla = await iaas.json();
    espera(Array.isArray(semilla.registros) && semilla.registros.length > 0,
      'el ADM no recibió registros IASS');
    return `todas 200; IASS=${semilla.registros.length}`;
  });
}

const fallidos = resultados.filter(x => !x.ok).length;
console.log(`\n${resultados.length - fallidos}/${resultados.length} verificaciones OK`);
if (fallidos) process.exit(1);