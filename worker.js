const BASE_PATH = "/betoalex";

function stripBase(pathname) {
  if (pathname === BASE_PATH) return "/";
  if (pathname.startsWith(BASE_PATH + "/")) return pathname.slice(BASE_PATH.length);
  return pathname;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const innerPath = stripBase(url.pathname);

    if (innerPath.startsWith("/api/data/")) {
      const key = innerPath.replace("/api/data/", "");

      if (!key) {
        return new Response(JSON.stringify({ error: "Falta la llave" }), {
          status: 400,
          headers: { "content-type": "application/json" }
        });
      }
      if (!env.HEMCI_KV) {
        return new Response(JSON.stringify({ error: "KV no configurado. Revisa kv_namespaces en wrangler.jsonc." }), {
          status: 500,
          headers: { "content-type": "application/json" }
        });
      }

      if (request.method === "GET") {
        const value = await env.HEMCI_KV.get(key);
        return new Response(value === null ? "null" : value, {
          headers: { "content-type": "application/json" }
        });
      }

      if (request.method === "POST") {
        const body = await request.text();
        try {
          JSON.parse(body);
        } catch (e) {
          return new Response(JSON.stringify({ error: "JSON inválido" }), {
            status: 400,
            headers: { "content-type": "application/json" }
          });
        }
        await env.HEMCI_KV.put(key, body);
        return new Response(JSON.stringify({ ok: true }), {
          headers: { "content-type": "application/json" }
        });
      }

      return new Response("Método no permitido", { status: 405 });
    }

    // Todo lo demás (index.html, etc.) lo sirve el sitio estático,
    // reescribiendo la URL para quitar el prefijo /control antes de buscar el archivo.
    const assetUrl = new URL(request.url);
    assetUrl.pathname = innerPath;
    const assetRequest = new Request(assetUrl.toString(), request);
    return env.ASSETS.fetch(assetRequest);
  }
};
