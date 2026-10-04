/**
 * VEA — Utilidades de sesión para las funciones serverless (Node).
 * Cookies firmadas con HMAC-SHA256 (VEA_AUTH_SECRET). Nunca se guarda
 * la contraseña ni el token de Google en la cookie: solo email/nombre/exp.
 */
const crypto = require('crypto');

const NOMBRE_SESION = 'vea_session';
const NOMBRE_ADM = 'vea_adm';

function secreto() {
  return process.env.VEA_AUTH_SECRET || '';
}

function firmar(datos, horas) {
  const secretoActual = secreto();
  if (!secretoActual) throw new Error('VEA_AUTH_SECRET no configurado');
  const payload = Buffer.from(
    JSON.stringify({ ...datos, exp: Date.now() + Math.floor(horas * 3600 * 1000) })
  ).toString('base64url');
  const firma = crypto.createHmac('sha256', secretoActual).update(payload).digest('base64url');
  return `${payload}.${firma}`;
}

// Identificador de sesión: se guarda en la cookie y en vea_login_log
// para medir la permanencia (entrada/salida) en el registro de accesos.
function nuevoSid() {
  return crypto.randomBytes(12).toString('hex');
}

function verificar(token) {
  const secretoActual = secreto();
  if (!secretoActual || !token || typeof token !== 'string') return null;
  const corte = token.lastIndexOf('.');
  if (corte <= 0) return null;
  const payload = token.slice(0, corte);
  const firma = token.slice(corte + 1);
  try {
    const esperada = crypto.createHmac('sha256', secretoActual).update(payload).digest();
    const recibida = Buffer.from(firma, 'base64url');
    if (recibida.length !== esperada.length || !crypto.timingSafeEqual(recibida, esperada)) return null;
    const datos = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    if (!datos.exp || Date.now() > datos.exp) return null;
    return datos;
  } catch (_) {
    return null;
  }
}

function leerCookie(req, nombre) {
  const cruda = (req.headers && req.headers.cookie) || '';
  for (const par of cruda.split(';')) {
    const partes = par.trim().split('=');
    if (partes[0] === nombre) return decodeURIComponent(partes.slice(1).join('='));
  }
  return null;
}

function sesion(req) {
  return verificar(leerCookie(req, NOMBRE_SESION));
}

function sesionAdm(req) {
  return verificar(leerCookie(req, NOMBRE_ADM));
}

function cookie(nombre, valor, horas) {
  const partes = [`${nombre}=${encodeURIComponent(valor)}`, 'Path=/', 'HttpOnly', 'SameSite=Lax', 'Secure'];
  if (horas === 0) partes.push('Max-Age=0');
  else partes.push(`Max-Age=${Math.floor(horas * 3600)}`);
  return partes.join('; ');
}

function cookiesSalida(listado) {
  return listado.map(({ nombre, valor, horas }) => cookie(nombre, valor, horas));
}

function ipDe(req) {
  const cruda = req.headers['x-forwarded-for'] || req.headers['x-real-ip'] || '';
  return String(cruda).split(',')[0].trim().slice(0, 60);
}

function userAgentDe(req) {
  return String(req.headers['user-agent'] || '').slice(0, 300);
}

module.exports = {
  NOMBRE_SESION,
  NOMBRE_ADM,
  firmar,
  nuevoSid,
  verificar,
  leerCookie,
  sesion,
  sesionAdm,
  cookie,
  cookiesSalida,
  ipDe,
  userAgentDe
};
