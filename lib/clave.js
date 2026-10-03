/**
 * VEA — Hash de contraseñas con scrypt (formato scrypt:salt:hash).
 * Compartido por api/auth/cuentas.js y api/auth/adm.js.
 */
const crypto = require('crypto');

function hashearClave(clave) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(clave, salt, 64).toString('hex');
  return `scrypt:${salt}:${hash}`;
}

function verificarClave(clave, almacenado) {
  try {
    const partes = String(almacenado || '').split(':');
    if (partes.length !== 3 || partes[0] !== 'scrypt') return false;
    const hash = Buffer.from(partes[2], 'hex');
    const candidato = crypto.scryptSync(clave, partes[1], 64);
    if (candidato.length !== hash.length) return false;
    return crypto.timingSafeEqual(candidato, hash);
  } catch (_) {
    return false;
  }
}

function claveFalsa() {
  try { crypto.scryptSync('x', 'sal_falsa_00000000', 64); } catch (_) { /* noop */ }
}

module.exports = { hashearClave, verificarClave, claveFalsa };
