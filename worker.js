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

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const innerPath = stripBase(url.pathname);

    // ---- Acceso genérico compartido para /reportar (usuario guardado + contraseña del mes) ----
    if (innerPath === "/api/public/report-login" && request.method === "POST") {
      if (!env.SESSION_SECRET || !env.HEMCI_KV) return jsonError("Servidor sin configurar.", 500);
      var credsRaw = await env.HEMCI_KV.get("report_access_creds");
      var creds = credsRaw ? JSON.parse(credsRaw) : null;
      var expectedUsername = (creds && creds.username) ? creds.username : "hemci";
      var rlBody; try { rlBody = await request.json(); } catch (e) { return jsonError("Solicitud inválida.", 400); }
      var ru = String(rlBody.username || "").trim().toLowerCase();
      var rp = String(rlBody.password || "").trim();
      if (!timingSafeEqual(ru, expectedUsername) || !timingSafeEqual(rp, currentMonthPassword())) {
        return jsonError("Usuario o contraseña incorrectos.", 401);
      }
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
          assignee: String(body.assignee || "").trim(),
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
        var t = {
          id: uidServer(), reporterName: reporterName, device: device,
          failureType: String(body.failureType || "Otro").slice(0, 50),
          urgency: String(body.urgency || "Media").slice(0, 20),
          description: desc, status: "abierto", resolution: "", createdAt: Date.now()
        };
        tickets = [t].concat(tickets);
        await env.HEMCI_KV.put("tickets", JSON.stringify(tickets));
        return jsonResponse({ ok: true });
      }
      return jsonError("Tipo de reporte inválido.", 400);
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
      var teamRaw1 = await env.HEMCI_KV.get("team");
      var team1 = teamRaw1 ? JSON.parse(teamRaw1) : [];
      var member = team1.find(function (m) { return String(m.username || "").toLowerCase() === username; });
      if (!member || !member.passwordHash) return jsonError("Usuario o contraseña incorrectos.", 401);
      var ok = await verifyPassword(password, member.passwordHash);
      if (!ok) return jsonError("Usuario o contraseña incorrectos.", 401);
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

    // ---- API general de datos: ahora requiere sesión válida ----
    if (innerPath.startsWith("/api/data/")) {
      var session2 = await requireSession(request, env);
      if (!session2) return jsonError("No autenticado.", 401);
      var key = innerPath.replace("/api/data/", "");
      if (!key) return jsonError("Falta la llave", 400);
      if (!env.HEMCI_KV) return jsonError("KV no configurado.", 500);

      if (request.method === "GET") {
        var value = await env.HEMCI_KV.get(key);
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
