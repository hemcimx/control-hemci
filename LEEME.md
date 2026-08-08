# Bitácora de negocio — versión Worker (Cloudflare)

Cloudflare cambió su flujo: al conectar un repo de GitHub ahora crea un **Worker**
(no un proyecto clásico de "Pages"). Estos archivos están armados para ese tipo
de proyecto.

## Qué contiene
- `public/index.html` — la app completa.
- `worker.js` — atiende `/api/data/...` (guarda y lee de la base de datos) y
  sirve `index.html` para todo lo demás.
- `wrangler.jsonc` — le dice a Cloudflare cómo desplegar el Worker.

## Pasos

### 1. Reemplaza los archivos en tu repo de GitHub
En tu repositorio `control-hemci`, borra `functions/` e `index.html` si ya los
habías subido, y sube en su lugar estos tres:
- `wrangler.jsonc`
- `worker.js`
- `public/index.html` (respetando la carpeta `public/`)

### 2. Crea el namespace de KV (la base de datos)
1. En el dashboard de Cloudflare, ve a **Storage & Databases > KV**.
2. Click en **Create namespace**. Nómbralo, por ejemplo `hemci-control`.
3. Cópiate el **ID** que te muestra (una cadena larga tipo `123456789abcdef...`).

### 3. Pon ese ID en wrangler.jsonc
Abre `wrangler.jsonc` (puedes editarlo directo en GitHub, con el lápiz de editar
archivo) y reemplaza `PON_AQUI_EL_ID_DE_TU_NAMESPACE` con el ID que copiaste.
Guarda el cambio (commit).

### 4. Deja que Cloudflare despliegue
Con el commit del paso anterior, Cloudflare va a volver a desplegar el Worker
automáticamente (esto es justo lo automático que buscabas). Ve a la pestaña
**Deployments** de tu proyecto para ver el progreso.

### 5. Prueba
Abre la URL que te da Cloudflare (algo como `control-hemci.<tu-cuenta>.workers.dev`).
Registra un gasto o una tarea, y confirma que sigue ahí si recargas la página
o la abres desde otro dispositivo.

### 6. (Opcional) Dominio propio
En el proyecto, busca **Settings > Domains & Routes > Add**, y escribe algo como
`control.hemci.mx`. Como `hemci.mx` ya está en tu cuenta de Cloudflare, el DNS
se configura solo.

## Notas
- No hay contraseña: cualquiera con el link puede ver y editar los datos. Si
  quieres protegerlo, revisa **Zero Trust > Access** en el dashboard.
- Los datos viven en 4 llaves dentro del KV: `team`, `expenses`, `tasks`,
  `settings`. Puedes verlas desde el dashboard de KV si necesitas corregir algo
  a mano.
