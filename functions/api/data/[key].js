export async function onRequestGet(context) {
  const { params, env } = context;
  const key = params.key;

  if (!env.HEMCI_KV) {
    return new Response(JSON.stringify({ error: "KV no configurado. Revisa el binding HEMCI_KV en Settings > Bindings." }), {
      status: 500,
      headers: { "content-type": "application/json" }
    });
  }

  const value = await env.HEMCI_KV.get(key);
  return new Response(value === null ? "null" : value, {
    headers: { "content-type": "application/json" }
  });
}

export async function onRequestPost(context) {
  const { params, env, request } = context;
  const key = params.key;

  if (!env.HEMCI_KV) {
    return new Response(JSON.stringify({ error: "KV no configurado. Revisa el binding HEMCI_KV en Settings > Bindings." }), {
      status: 500,
      headers: { "content-type": "application/json" }
    });
  }

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
