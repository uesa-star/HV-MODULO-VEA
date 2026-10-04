/**
 * VEA — Envío de correo por SMTP (Gmail: smtp.gmail.com:465 con TLS implícito).
 * Sin dependencias: usa módulos nativos tls/net.
 * Configuración en Vercel:
 *   GMAIL_USER           → cuenta Gmail que envía
 *   GMAIL_APP_PASSWORD   → contraseña de aplicación de Google (16 caracteres)
 */
const tls = require('tls');

const HOST = 'smtp.gmail.com';
const PUERTO = 465;
const TIMEOUT_MS = 7000;

function extraerRespuesta(buf) {
  let idx = 0;
  let codigo = null;
  const lineas = [];
  while (idx < buf.length) {
    const nl = buf.indexOf('\r\n', idx);
    if (nl === -1) return null;
    const linea = buf.slice(idx, nl);
    if (/^\d{3}[ -]/.test(linea)) {
      const c = linea.slice(0, 3);
      if (codigo && c !== codigo) return null;
      codigo = c;
      lineas.push(linea.slice(4));
      if (linea[3] === ' ') {
        return { resto: buf.slice(nl + 2), codigo: Number(codigo), texto: lineas.join('\n') };
      }
    }
    idx = nl + 2;
  }
  return null;
}

function crearDialogo(socket) {
  let buf = '';
  const pendientes = [];
  function procesar() {
    while (pendientes.length) {
      const r = extraerRespuesta(buf);
      if (!r) return;
      buf = r.resto;
      pendientes.shift().resolver(r);
    }
  }
  socket.on('data', function (d) {
    buf += d.toString('utf8');
    procesar();
  });
  socket.on('error', function (e) {
    while (pendientes.length) pendientes.shift().rechazar(e);
  });
  socket.on('close', function () {
    while (pendientes.length) pendientes.shift().rechazar(new Error('Conexión cerrada'));
  });
  return {
    enviar: function (texto) { socket.write(texto); },
    leer: function () {
      return new Promise(function (resolver, rechazar) {
        pendientes.push({ resolver: resolver, rechazar: rechazar });
        procesar();
      });
    }
  };
}

function conectar() {
  return new Promise(function (resolver, rechazar) {
    const socket = tls.connect({ host: HOST, port: PUERTO, servername: HOST }, function () {
      resolver(socket);
    });
    socket.setTimeout(TIMEOUT_MS, function () {
      socket.destroy();
      rechazar(new Error('Tiempo de espera agotado'));
    });
    socket.on('error', rechazar);
  });
}

async function esperar(dialogo, codigoEsperado) {
  const r = await dialogo.leer();
  if (r.codigo !== codigoEsperado) {
    const e = new Error('SMTP ' + r.codigo);
    e.codigoSmtp = r.codigo;
    throw e;
  }
  return r;
}

/**
 * Envía un correo HTML. Devuelve { ok:true } o { error, detalle }.
 */
async function enviarCorreo({ para, asunto, html }) {
  const usuario = String(process.env.GMAIL_USER || '').trim();
  const clave = String(process.env.GMAIL_APP_PASSWORD || '').trim();
  if (!usuario || !clave) {
    return { error: 'configuracion', detalle: 'Faltan GMAIL_USER / GMAIL_APP_PASSWORD en Vercel.' };
  }
  if (!para || !/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(para)) {
    return { error: 'destino', detalle: 'Correo destino inválido.' };
  }

  let socket;
  try {
    socket = await conectar();
  } catch (e) {
    return { error: 'conexion', detalle: e.message };
  }
  const d = crearDialogo(socket);
  try {
    await esperar(d, 220);
    d.enviar('EHLO localhost\r\n');
    await esperar(d, 250);
    d.enviar('AUTH LOGIN\r\n');
    await esperar(d, 334);
    d.enviar(Buffer.from(usuario, 'utf8').toString('base64') + '\r\n');
    await esperar(d, 334);
    d.enviar(Buffer.from(clave, 'utf8').toString('base64') + '\r\n');
    await esperar(d, 235);
    d.enviar('MAIL FROM:<' + usuario + '>\r\n');
    await esperar(d, 250);
    d.enviar('RCPT TO:<' + para + '>\r\n');
    await esperar(d, 250);
    d.enviar('DATA\r\n');
    await esperar(d, 354);
    const base64 = Buffer.from(html, 'utf8').toString('base64').replace(/(.{76})/g, '$1\r\n');
    const mensaje = [
      'From: Modulo VEA <' + usuario + '>',
      'To: <' + para + '>',
      'Subject: ' + asunto,
      'MIME-Version: 1.0',
      'Content-Type: text/html; charset=utf-8',
      'Content-Transfer-Encoding: base64',
      '',
      base64,
      ''
    ].join('\r\n');
    d.enviar(mensaje + '\r\n.\r\n');
    await esperar(d, 250);
    d.enviar('QUIT\r\n');
    await d.leer().catch(function () { /* fin */ });
    return { ok: true };
  } catch (e) {
    if (e.codigoSmtp === 535) {
      return { error: 'credenciales', detalle: 'SMTP 535' };
    }
    return { error: 'envio', detalle: e.message };
  } finally {
    try { socket.end(); } catch (_) { /* noop */ }
  }
}

module.exports = { enviarCorreo };
