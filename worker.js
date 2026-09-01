const BASE_PATH = "/betoalex";

function stripBase(pathname) {
  if (pathname === BASE_PATH) return "/";
  if (pathname.startsWith(BASE_PATH + "/")) return pathname.slice(BASE_PATH.length);
  return pathname;
}

function jsonResponse(obj, status, extraHeaders) {
  var headers = Object.assign({ "content-type": "application/json" }, extraHeaders || {});
  return new Response(JSON.stringify(obj), { status: status || 200, headers: headers });
}
function jsonError(msg, status) {
  return jsonResponse({ error: msg }, status || 400);
}
function escapeHtmlServer(s) {
  return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {
    return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
  });
}
async function sendTicketNotificationEmail(env, ticket) {
  try {
    if (!env.EMAIL || !env.HEMCI_KV) return;
    var raw = await env.HEMCI_KV.get("notify_emails");
    var emails = raw ? JSON.parse(raw) : [];
    if (!emails || emails.length === 0) return;
    var subject = "Nuevo ticket " + (ticket.folio || "") + " (" + (ticket.urgency || "Media") + ") — HEMCI Soporte";
    var html =
      "<p>Tienes un folio de HEMCI: <strong>" + escapeHtmlServer(ticket.folio) + "</strong></p>" +
      "<p><strong>Equipo:</strong> " + escapeHtmlServer(ticket.device) + "<br>" +
      "<strong>Área:</strong> " + escapeHtmlServer(ticket.area || "—") + "<br>" +
      "<strong>Tipo de falla:</strong> " + escapeHtmlServer(ticket.failureType) + "<br>" +
      "<strong>Urgencia:</strong> " + escapeHtmlServer(ticket.urgency) + "<br>" +
      "<strong>Reportó:</strong> " + escapeHtmlServer(ticket.reporterName) + "</p>" +
      "<p>" + escapeHtmlServer(ticket.description) + "</p>";
    var text = "Tienes un folio de HEMCI: " + ticket.folio + ". Equipo: " + ticket.device +
      ". Urgencia: " + ticket.urgency + ". Reportó: " + ticket.reporterName + ". " + ticket.description;
    await env.EMAIL.send({
      to: emails.map(function (e) { return { email: e }; }),
      from: { email: "alertas@hemci.mx", name: "HEMCI Soporte" },
      subject: subject, html: html, text: text
    });
  } catch (e) { /* nunca truena la creación del ticket por un correo fallido */ }
}

// ---------- base64url ----------
function b64urlEncode(bytes) {
  var bin = "";
  for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function b64urlDecode(str) {
  str = str.replace(/-/g, "+").replace(/_/g, "/");
  while (str.length % 4) str += "=";
  var bin = atob(str);
  var bytes = new Uint8Array(bin.length);
  for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

// ---------- cookies ----------
function getCookie(request, name) {
  var header = request.headers.get("Cookie") || "";
  var parts = header.split(/;\s*/);
  for (var i = 0; i < parts.length; i++) {
    var idx = parts[i].indexOf("=");
    if (idx === -1) continue;
    if (parts[i].slice(0, idx) === name) return decodeURIComponent(parts[i].slice(idx + 1));
  }
  return null;
}
function sessionCookieHeader(token, maxAgeSeconds) {
  return "session=" + token + "; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=" + maxAgeSeconds;
}
function clearCookieHeader() {
  return "session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0";
}

// ---------- sesiones firmadas (HMAC-SHA256) ----------
async function hmacKey(secret) {
  var enc = new TextEncoder().encode(secret);
  return crypto.subtle.importKey("raw", enc, { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
}
async function signSession(payloadObj, secret) {
  var payload = JSON.stringify(payloadObj);
  var payloadB64 = b64urlEncode(new TextEncoder().encode(payload));
  var key = await hmacKey(secret);
  var sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(payloadB64));
  return payloadB64 + "." + b64urlEncode(new Uint8Array(sig));
}
async function verifySession(token, secret) {
  if (!token) return null;
  var parts = token.split(".");
  if (parts.length !== 2) return null;
  var key = await hmacKey(secret);
  var valid = await crypto.subtle.verify("HMAC", key, b64urlDecode(parts[1]), new TextEncoder().encode(parts[0]));
  if (!valid) return null;
  var payload;
  try { payload = JSON.parse(new TextDecoder().decode(b64urlDecode(parts[0]))); } catch (e) { return null; }
  if (!payload.exp || Date.now() > payload.exp) return null;
  return payload;
}
async function requireSession(request, env) {
  if (!env.SESSION_SECRET) return null;
  var token = getCookie(request, "session");
  if (!token) return null;
  return await verifySession(token, env.SESSION_SECRET);
}

// ---------- contraseñas (PBKDF2-SHA256) ----------
async function derivePBKDF2(password, saltBytes) {
  var enc = new TextEncoder().encode(password);
  var keyMaterial = await crypto.subtle.importKey("raw", enc, "PBKDF2", false, ["deriveBits"]);
  var bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: saltBytes, iterations: 100000, hash: "SHA-256" },
    keyMaterial, 256
  );
  return new Uint8Array(bits);
}
async function hashPasswordNew(password) {
  var salt = crypto.getRandomValues(new Uint8Array(16));
  var hash = await derivePBKDF2(password, salt);
  return b64urlEncode(salt) + ":" + b64urlEncode(hash);
}
async function verifyPassword(password, stored) {
  if (!stored || stored.indexOf(":") === -1) return false;
  var parts = stored.split(":");
  var salt = b64urlDecode(parts[0]);
  var expected = parts[1];
  var hash = await derivePBKDF2(password, salt);
  var got = b64urlEncode(hash);
  if (got.length !== expected.length) return false;
  var diff = 0;
  for (var i = 0; i < got.length; i++) diff |= got.charCodeAt(i) ^ expected.charCodeAt(i);
  return diff === 0;
}
function uidServer() {
  return Date.now().toString(36) + "-" + Math.random().toString(36).slice(2, 10);
}
function isStrongPassword(pw) {
  if (typeof pw !== "string" || pw.length < 10) return false;
  if (!/[a-z]/.test(pw)) return false;
  if (!/[A-Z]/.test(pw)) return false;
  if (!/[0-9]/.test(pw)) return false;
  if (!/[^A-Za-z0-9]/.test(pw)) return false;
  return true;
}
var PASSWORD_RULE_MSG = "La contraseña debe tener al menos 10 caracteres, con mayúscula, minúscula, número y símbolo.";

function timingSafeEqual(a, b) {
  a = String(a); b = String(b);
  if (a.length !== b.length) return false;
  var diff = 0;
  for (var i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}
var MESES_ES = ["Enero","Febrero","Marzo","Abril","Mayo","Junio","Julio","Agosto","Septiembre","Octubre","Noviembre","Diciembre"];
function currentMonthPassword() {
  var parts = new Intl.DateTimeFormat("en-US", { timeZone: "America/Mexico_City", month: "numeric", year: "numeric" }).formatToParts(new Date());
  var month = parseInt(parts.find(function(p){ return p.type === "month"; }).value, 10);
  var year = parts.find(function(p){ return p.type === "year"; }).value;
  return MESES_ES[month - 1] + year;
}
function secondsUntilEndOfMonthMX() {
  var parts = new Intl.DateTimeFormat("en-US", { timeZone: "America/Mexico_City", month: "numeric", year: "numeric" }).formatToParts(new Date());
  var month = parseInt(parts.find(function(p){ return p.type === "month"; }).value, 10);
  var year = parseInt(parts.find(function(p){ return p.type === "year"; }).value, 10);
  var nextMonth = month === 12 ? 1 : month + 1;
  var nextYear = month === 12 ? year + 1 : year;
  // Medianoche del día 1 del próximo mes, hora Ciudad de México (UTC-6 todo el año).
  var endUTC = Date.UTC(nextYear, nextMonth - 1, 1, 6, 0, 0);
  var diff = Math.floor((endUTC - Date.now()) / 1000);
  return diff > 0 ? diff : 3600;
}
async function requireReportAccess(request, env) {
  // Acceso válido si tiene sesión de socio (login normal) O el acceso genérico de /reportar.
  var adminSession = await requireSession(request, env);
  if (adminSession) return true;
  if (!env.SESSION_SECRET) return false;
  var token = getCookie(request, "report_access");
  var payload = await verifySession(token, env.SESSION_SECRET);
  return !!(payload && payload.scope === "report");
}

async function nextTicketFolio(env) {
  var counterRaw = await env.HEMCI_KV.get("ticket_counter");
  var counter = counterRaw ? parseInt(counterRaw, 10) : 0;
  counter += 1;
  await env.HEMCI_KV.put("ticket_counter", String(counter));
  var year = new Intl.DateTimeFormat("en-US", { timeZone: "America/Mexico_City", year: "numeric" }).format(new Date());
  return "HEMCI-" + year + "-" + String(counter).padStart(4, "0");
}

async function nextNotaFolio(env) {
  var counterRaw = await env.HEMCI_KV.get("nota_counter");
  var counter = counterRaw ? parseInt(counterRaw, 10) : 0;
  counter += 1;
  await env.HEMCI_KV.put("nota_counter", String(counter));
  var year = new Intl.DateTimeFormat("en-US", { timeZone: "America/Mexico_City", year: "numeric" }).format(new Date());
  return "NOTA-" + year + "-" + String(counter).padStart(4, "0");
}

var LOGIN_MAX_ATTEMPTS = 5;
var LOGIN_LOCKOUT_SECONDS = 15 * 60;
async function isLoginLocked(env, key) {
  var raw = await env.HEMCI_KV.get(key);
  if (!raw) return null;
  var record = JSON.parse(raw);
  if (record.lockedUntil && Date.now() < record.lockedUntil) {
    return Math.ceil((record.lockedUntil - Date.now()) / 1000);
  }
  return null;
}
async function recordLoginResult(env, key, success) {
  if (success) { await env.HEMCI_KV.delete(key).catch(function(){}); return; }
  var raw = await env.HEMCI_KV.get(key);
  var record = raw ? JSON.parse(raw) : { count: 0 };
  record.count = (record.count || 0) + 1;
  if (record.count >= LOGIN_MAX_ATTEMPTS) {
    record.lockedUntil = Date.now() + LOGIN_LOCKOUT_SECONDS * 1000;
    record.count = 0;
  }
  await env.HEMCI_KV.put(key, JSON.stringify(record), { expirationTtl: LOGIN_LOCKOUT_SECONDS + 300 });
}
function lockedMessage(seconds) {
  var mins = Math.ceil(seconds / 60);
  return "Demasiados intentos fallidos. Intenta de nuevo en " + mins + " minuto" + (mins === 1 ? "" : "s") + ".";
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const innerPath = stripBase(url.pathname);

    // ---- Acceso genérico compartido para /reportar (usuario guardado + contraseña del mes) ----
    if (innerPath === "/api/public/report-login" && request.method === "POST") {
      if (!env.SESSION_SECRET || !env.HEMCI_KV) return jsonError("Servidor sin configurar.", 500);
      var reportLockKey = "loginlock:report";
      var reportLockedSeconds = await isLoginLocked(env, reportLockKey);
      if (reportLockedSeconds) return jsonError(lockedMessage(reportLockedSeconds), 429);
      var credsRaw = await env.HEMCI_KV.get("report_access_creds");
      var creds = credsRaw ? JSON.parse(credsRaw) : null;
      var expectedUsername = (creds && creds.username) ? creds.username : "hemci";
      var rlBody; try { rlBody = await request.json(); } catch (e) { return jsonError("Solicitud inválida.", 400); }
      var ru = String(rlBody.username || "").trim().toLowerCase();
      var rp = String(rlBody.password || "").trim();
      var reportOk = timingSafeEqual(ru, expectedUsername) && timingSafeEqual(rp, currentMonthPassword());
      await recordLoginResult(env, reportLockKey, reportOk);
      if (!reportOk) return jsonError("Usuario o contraseña incorrectos.", 401);
      var maxAge = secondsUntilEndOfMonthMX();
      var rexp = Date.now() + maxAge * 1000;
      var rtoken = await signSession({ scope: "report", exp: rexp }, env.SESSION_SECRET);
      return jsonResponse({ ok: true }, 200, { "Set-Cookie": "report_access=" + rtoken + "; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=" + maxAge });
    }
    if (innerPath === "/api/public/report-check" && request.method === "GET") {
      var hasAccess = await requireReportAccess(request, env);
      return jsonResponse({ access: hasAccess });
    }

    // ---- Endpoint público: enviar un reporte (requiere acceso genérico o sesión de socio) ----
    if (innerPath === "/api/public/report" && request.method === "POST") {
      if (!(await requireReportAccess(request, env))) return jsonError("No autorizado.", 401);
      if (!env.HEMCI_KV) return jsonError("KV no configurado.", 500);
      var body;
      try { body = await request.json(); } catch (e) { return jsonError("Solicitud inválida.", 400); }
      var kind = body.kind;
      var reporterName = String(body.reporterName || "").trim().slice(0, 120);
      if (!reporterName) return jsonError("Falta el nombre.", 400);
      if (kind === "tarea") {
        var title = String(body.title || "").trim().slice(0, 200);
        if (!title) return jsonError("Falta el título.", 400);
        var tasksRaw = await env.HEMCI_KV.get("tasks");
        var tasks = tasksRaw ? JSON.parse(tasksRaw) : [];
        var detail = String(body.taskDescription || "").trim().slice(0, 1000);
        var item = {
          id: uidServer(), title: title,
          description: "Reportado por " + reporterName + (detail ? (": " + detail) : ""),
          project: "Solicitud externa",
          assignee: "",
          priority: "media", dueDate: String(body.dueDate || "").trim().slice(0, 10),
          status: "pendiente", progress: 0, createdAt: Date.now(), updatedAt: Date.now()
        };
        tasks = [item].concat(tasks);
        await env.HEMCI_KV.put("tasks", JSON.stringify(tasks));
        return jsonResponse({ ok: true });
      }
      if (kind === "falla") {
        var device = String(body.device || "").trim().slice(0, 200);
        var desc = String(body.failureDescription || "").trim().slice(0, 1000);
        if (!device || !desc) return jsonError("Faltan datos del reporte.", 400);
        var ticketsRaw = await env.HEMCI_KV.get("tickets");
        var tickets = ticketsRaw ? JSON.parse(ticketsRaw) : [];
        var folio = await nextTicketFolio(env);
        var t = {
          id: uidServer(), folio: folio, reporterName: reporterName, device: device,
          area: String(body.area || "").trim().slice(0, 100),
          failureType: String(body.failureType || "Otro").slice(0, 50),
          urgency: String(body.urgency || "Media").slice(0, 20),
          description: desc, status: "abierto", resolution: "", assignedTo: "",
          notes: [], hasPhoto: false, createdAt: Date.now()
        };
        tickets = [t].concat(tickets);
        await env.HEMCI_KV.put("tickets", JSON.stringify(tickets));
        await sendTicketNotificationEmail(env, t);
        var waNumber = await env.HEMCI_KV.get("support_whatsapp");
        return jsonResponse({ ok: true, folio: folio, id: t.id, whatsapp: waNumber || "" });
      }
      return jsonError("Tipo de reporte inválido.", 400);
    }

    // ---- Adjuntar foto a un ticket ya creado (requiere el mismo acceso que crear el reporte) ----
    if (innerPath === "/api/public/ticket-photo" && request.method === "POST") {
      if (!(await requireReportAccess(request, env))) return jsonError("No autorizado.", 401);
      if (!env.HEMCI_KV) return jsonError("KV no configurado.", 500);
      var tpBody; try { tpBody = await request.json(); } catch (e) { return jsonError("Solicitud inválida.", 400); }
      var ticketId = String(tpBody.ticketId || "");
      var photoDataUrl = String(tpBody.photo || "");
      if (!ticketId || !photoDataUrl) return jsonError("Faltan datos.", 400);
      var ticketsRaw2 = await env.HEMCI_KV.get("tickets");
      var ticketsList = ticketsRaw2 ? JSON.parse(ticketsRaw2) : [];
      var idx6 = ticketsList.findIndex(function (t) { return t.id === ticketId; });
      if (idx6 === -1) return jsonError("Ticket no encontrado.", 404);
      await env.HEMCI_KV.put("ticket-photo:" + ticketId, photoDataUrl);
      ticketsList[idx6] = Object.assign({}, ticketsList[idx6], { hasPhoto: true });
      await env.HEMCI_KV.put("tickets", JSON.stringify(ticketsList));
      return jsonResponse({ ok: true });
    }

    // ---- Consulta pública de folio, sin necesidad de cuenta ----
    if (innerPath === "/api/public/ticket-status" && request.method === "GET") {
      if (!(await requireReportAccess(request, env))) return jsonError("No autorizado.", 401);
      if (!env.HEMCI_KV) return jsonError("KV no configurado.", 500);
      var folioParam = url.searchParams.get("folio");
      if (!folioParam) return jsonError("Falta el folio.", 400);
      var ticketsRaw3 = await env.HEMCI_KV.get("tickets");
      var ticketsList2 = ticketsRaw3 ? JSON.parse(ticketsRaw3) : [];
      var found = ticketsList2.find(function (t) { return String(t.folio || "").toLowerCase() === folioParam.trim().toLowerCase(); });
      if (!found) return jsonError("No se encontró ese folio.", 404);
      return jsonResponse({
        folio: found.folio, status: found.status, device: found.device, area: found.area || "",
        failureType: found.failureType, createdAt: found.createdAt,
        resolution: found.status === "resuelto" ? found.resolution : null,
        resolvedAt: found.resolvedAt || null
      });
    }

    // ---- Endpoint público: solo nombres del equipo (para el formulario público) ----
    if (innerPath === "/api/public/team-names" && request.method === "GET") {
      if (!env.HEMCI_KV) return jsonError("KV no configurado.", 500);
      var teamRaw0 = await env.HEMCI_KV.get("team");
      var team0 = teamRaw0 ? JSON.parse(teamRaw0) : [];
      return jsonResponse(team0.map(function (m) { return { id: m.id, name: m.name }; }));
    }

    // ---- Autenticación ----
    if (innerPath === "/api/auth/login" && request.method === "POST") {
      if (!env.SESSION_SECRET || !env.HEMCI_KV) return jsonError("Servidor sin configurar.", 500);
      var lbody; try { lbody = await request.json(); } catch (e) { return jsonError("Solicitud inválida.", 400); }
      var username = String(lbody.username || "").trim().toLowerCase();
      var password = String(lbody.password || "");
      if (!username || !password) return jsonError("Faltan datos.", 400);
      var loginLockKey = "loginlock:" + username;
      var loginLockedSeconds = await isLoginLocked(env, loginLockKey);
      if (loginLockedSeconds) return jsonError(lockedMessage(loginLockedSeconds), 429);
      var teamRaw1 = await env.HEMCI_KV.get("team");
      var team1 = teamRaw1 ? JSON.parse(teamRaw1) : [];
      var member = team1.find(function (m) { return String(m.username || "").toLowerCase() === username; });
      var ok = (member && member.passwordHash) ? await verifyPassword(password, member.passwordHash) : false;
      await recordLoginResult(env, loginLockKey, ok);
      if (!member || !member.passwordHash || !ok) return jsonError("Usuario o contraseña incorrectos.", 401);
      var exp = Date.now() + 7 * 24 * 60 * 60 * 1000;
      var token = await signSession({ sub: member.id, name: member.name, exp: exp }, env.SESSION_SECRET);
      return jsonResponse({ ok: true, name: member.name, id: member.id }, 200, { "Set-Cookie": sessionCookieHeader(token, 7 * 24 * 60 * 60) });
    }

    if (innerPath === "/api/auth/logout" && request.method === "POST") {
      return jsonResponse({ ok: true }, 200, { "Set-Cookie": clearCookieHeader() });
    }

    if (innerPath === "/api/auth/me" && request.method === "GET") {
      var session0 = await requireSession(request, env);
      if (!session0) return jsonResponse({ loggedIn: false });
      return jsonResponse({ loggedIn: true, id: session0.sub, name: session0.name });
    }

    if (innerPath === "/api/auth/bootstrap" && request.method === "POST") {
      if (!env.SESSION_SECRET || !env.HEMCI_KV) return jsonError("Servidor sin configurar.", 500);
      var bbody; try { bbody = await request.json(); } catch (e) { return jsonError("Solicitud inválida.", 400); }
      var memberId = String(bbody.memberId || "");
      var busername = String(bbody.username || "").trim().toLowerCase();
      var bpassword = String(bbody.password || "");
      if (!memberId || !busername || !bpassword) return jsonError("Faltan datos.", 400);
      if (!isStrongPassword(bpassword)) return jsonError(PASSWORD_RULE_MSG, 400);
      var teamRaw2 = await env.HEMCI_KV.get("team");
      var team2 = teamRaw2 ? JSON.parse(teamRaw2) : [];
      var idx = team2.findIndex(function (m) { return m.id === memberId; });
      if (idx === -1) return jsonError("Integrante no encontrado.", 404);
      if (team2[idx].passwordHash) return jsonError("Este integrante ya tiene acceso configurado. Inicia sesión para cambiarlo.", 409);
      var taken = team2.some(function (m) { return m.id !== memberId && String(m.username || "").toLowerCase() === busername; });
      if (taken) return jsonError("Ese usuario ya está en uso.", 409);
      team2[idx] = Object.assign({}, team2[idx], { username: busername, passwordHash: await hashPasswordNew(bpassword) });
      await env.HEMCI_KV.put("team", JSON.stringify(team2));
      return jsonResponse({ ok: true });
    }

    if (innerPath === "/api/auth/set-password" && request.method === "POST") {
      var session1 = await requireSession(request, env);
      if (!session1) return jsonError("No autenticado.", 401);
      if (!env.HEMCI_KV) return jsonError("KV no configurado.", 500);
      var sbody; try { sbody = await request.json(); } catch (e) { return jsonError("Solicitud inválida.", 400); }
      var currentPassword = String(sbody.currentPassword || "");
      var newPassword = String(sbody.newPassword || "");
      var newUsername = String(sbody.username || "").trim().toLowerCase();
      if (newPassword && !isStrongPassword(newPassword)) return jsonError(PASSWORD_RULE_MSG, 400);
      var teamRaw3 = await env.HEMCI_KV.get("team");
      var team3 = teamRaw3 ? JSON.parse(teamRaw3) : [];
      var idx3 = team3.findIndex(function (m) { return m.id === session1.sub; });
      if (idx3 === -1) return jsonError("Integrante no encontrado.", 404);
      var okCurrent = await verifyPassword(currentPassword, team3[idx3].passwordHash);
      if (!okCurrent) return jsonError("La contraseña actual no es correcta.", 401);
      var updated = Object.assign({}, team3[idx3]);
      if (newUsername) {
        var takenU = team3.some(function (m) { return m.id !== updated.id && String(m.username || "").toLowerCase() === newUsername; });
        if (takenU) return jsonError("Ese usuario ya está en uso.", 409);
        updated.username = newUsername;
      }
      if (newPassword) updated.passwordHash = await hashPasswordNew(newPassword);
      team3[idx3] = updated;
      await env.HEMCI_KV.put("team", JSON.stringify(team3));
      return jsonResponse({ ok: true });
    }

    if (innerPath === "/api/auth/set-report-access" && request.method === "POST") {
      var session4 = await requireSession(request, env);
      if (!session4) return jsonError("No autenticado.", 401);
      if (!env.HEMCI_KV) return jsonError("KV no configurado.", 500);
      var raBody; try { raBody = await request.json(); } catch (e) { return jsonError("Solicitud inválida.", 400); }
      var raUsername = String(raBody.username || "").trim().toLowerCase();
      if (!raUsername) return jsonError("Falta el usuario.", 400);
      await env.HEMCI_KV.put("report_access_creds", JSON.stringify({ username: raUsername }));
      return jsonResponse({ ok: true });
    }
    if (innerPath === "/api/auth/report-access-status" && request.method === "GET") {
      var session5 = await requireSession(request, env);
      if (!session5) return jsonError("No autenticado.", 401);
      if (!env.HEMCI_KV) return jsonError("KV no configurado.", 500);
      var raRaw = await env.HEMCI_KV.get("report_access_creds");
      var raCurrent = raRaw ? JSON.parse(raRaw) : null;
      return jsonResponse({ username: (raCurrent && raCurrent.username) ? raCurrent.username : "hemci", currentPassword: currentMonthPassword() });
    }

    if (innerPath === "/api/auth/notify-emails" && request.method === "GET") {
      var session6 = await requireSession(request, env);
      if (!session6) return jsonError("No autenticado.", 401);
      if (!env.HEMCI_KV) return jsonError("KV no configurado.", 500);
      var neRaw = await env.HEMCI_KV.get("notify_emails");
      return jsonResponse({ emails: neRaw ? JSON.parse(neRaw) : [], emailConfigured: !!env.EMAIL });
    }
    if (innerPath === "/api/auth/notify-emails" && request.method === "POST") {
      var session7 = await requireSession(request, env);
      if (!session7) return jsonError("No autenticado.", 401);
      if (!env.HEMCI_KV) return jsonError("KV no configurado.", 500);
      var neBody; try { neBody = await request.json(); } catch (e) { return jsonError("Solicitud inválida.", 400); }
      var emailList = Array.isArray(neBody.emails) ? neBody.emails : [];
      emailList = emailList.map(function (e) { return String(e).trim(); }).filter(function (e) { return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e); }).slice(0, 20);
      await env.HEMCI_KV.put("notify_emails", JSON.stringify(emailList));
      return jsonResponse({ ok: true, emails: emailList });
    }

    if (innerPath === "/api/auth/support-whatsapp" && request.method === "GET") {
      var sessionWa = await requireSession(request, env);
      if (!sessionWa) return jsonError("No autenticado.", 401);
      if (!env.HEMCI_KV) return jsonError("KV no configurado.", 500);
      var waRaw = await env.HEMCI_KV.get("support_whatsapp");
      return jsonResponse({ number: waRaw || "" });
    }
    if (innerPath === "/api/auth/support-whatsapp" && request.method === "POST") {
      var sessionWa2 = await requireSession(request, env);
      if (!sessionWa2) return jsonError("No autenticado.", 401);
      if (!env.HEMCI_KV) return jsonError("KV no configurado.", 500);
      var waBody; try { waBody = await request.json(); } catch (e) { return jsonError("Solicitud inválida.", 400); }
      var digits = String(waBody.number || "").replace(/\D/g, "");
      await env.HEMCI_KV.put("support_whatsapp", digits);
      return jsonResponse({ ok: true, number: digits });
    }

    // ---- Notas de servicio: crear (folio asignado por el servidor) ----
    if (innerPath === "/api/notas" && request.method === "POST") {
      var notaSession = await requireSession(request, env);
      if (!notaSession) return jsonError("No autenticado.", 401);
      if (!env.HEMCI_KV) return jsonError("KV no configurado.", 500);
      var nbody; try { nbody = await request.json(); } catch (e) { return jsonError("Solicitud inválida.", 400); }
      if (!nbody.cliente || !String(nbody.cliente).trim()) return jsonError("Falta el cliente.", 400);
      var notasRaw = await env.HEMCI_KV.get("notas");
      var notas = notasRaw ? JSON.parse(notasRaw) : [];
      var notaFolio = await nextNotaFolio(env);
      var nota = {
        id: uidServer(),
        folio: notaFolio,
        createdAt: Date.now(),
        createdBy: notaSession.name || "",
        cliente: String(nbody.cliente || "").trim().slice(0, 200),
        contacto: String(nbody.contacto || "").trim().slice(0, 200),
        area: String(nbody.area || "").trim().slice(0, 120),
        ticketFolio: String(nbody.ticketFolio || "").trim().slice(0, 40),
        fecha: String(nbody.fecha || "").slice(0, 10),
        items: Array.isArray(nbody.items) ? nbody.items.slice(0, 60).map(function (it) {
          return {
            descripcion: String(it.descripcion || "").slice(0, 300),
            cantidad: Number(it.cantidad) || 0,
            precioUnit: Number(it.precioUnit) || 0,
            subitems: Array.isArray(it.subitems)
              ? it.subitems.slice(0, 30).map(function (s) { return String(s || "").slice(0, 300); }).filter(function (s) { return s.trim(); })
              : []
          };
        }) : [],
        ivaRate: Number(nbody.ivaRate) || 0,
        preciosIncluyenIva: !!nbody.preciosIncluyenIva,
        subtotal: Number(nbody.subtotal) || 0,
        iva: Number(nbody.iva) || 0,
        total: Number(nbody.total) || 0,
        trabajo: String(nbody.trabajo || "").slice(0, 3000)
      };
      notas = [nota].concat(notas);
      await env.HEMCI_KV.put("notas", JSON.stringify(notas));
      return jsonResponse({ ok: true, nota: nota });
    }

    // ---- API general de datos: ahora requiere sesión válida ----
    if (innerPath.startsWith("/api/data/")) {
      var session2 = await requireSession(request, env);
      if (!session2) return jsonError("No autenticado.", 401);
      var key = innerPath.replace("/api/data/", "");
      if (!key) return jsonError("Falta la llave", 400);
      if (!env.HEMCI_KV) return jsonError("KV no configurado.", 500);

      if (request.method === "GET") {
        var value = await env.HEMCI_KV.get(key);
        if (key === "team" && value) {
          var teamData;
          try { teamData = JSON.parse(value); } catch (e) { teamData = null; }
          if (Array.isArray(teamData)) {
            var stripped = teamData.map(function (m) {
              var clean = Object.assign({}, m);
              delete clean.passwordHash;
              return clean;
            });
            return jsonResponse(stripped);
          }
        }
        return new Response(value === null ? "null" : value, { headers: { "content-type": "application/json" } });
      }
      if (request.method === "POST") {
        var rawBody = await request.text();
        try { JSON.parse(rawBody); } catch (e) { return jsonError("JSON inválido", 400); }
        await env.HEMCI_KV.put(key, rawBody);
        return jsonResponse({ ok: true });
      }
      return new Response("Método no permitido", { status: 405 });
    }

    // ---- Todo lo demás: archivos estáticos (index.html, etc.) ----
    const assetUrl = new URL(request.url);
    assetUrl.pathname = innerPath;
    const assetRequest = new Request(assetUrl.toString(), request);
    return env.ASSETS.fetch(assetRequest);
  }
};
