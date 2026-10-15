/**
 * VEA — Rate limiting por IP en memoria.
 * Ventana deslizante simple: cuenta intentos por IP y bloquea si exceden el máximo.
 * No persiste entre reinicios de instancia serverless (aceptable: cada intento
 * fallido también se cuenta en la base de datos como respaldo).
 */
const intentos = new Map(); // ip -> { n, ventana }

const VENTANA_MS = 15 * 60 * 1000; // 15 minutos

function rateLimit(ip, max) {
  max = max || 30;
  const ahora = Date.now();
  const reg = intentos.get(ip);
  if (!reg || ahora - reg.ventana > VENTANA_MS) {
    intentos.set(ip, { n: 1, ventana: ahora });
    return true; // permitido
  }
  reg.n++;
  if (reg.n > max) return false; // bloqueado
  return true; // permitido
}

function rateLimitRespuesta(res) {
  res.status(429).json({ error: 'Demasiados intentos. Espere unos minutos e intente de nuevo.' });
}

module.exports = { rateLimit, rateLimitRespuesta };
