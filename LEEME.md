# Bitácora de negocio — control de gastos, tareas y avances

## Qué contiene esta carpeta
- `index.html` — la app completa (no necesita build ni instalar nada).
- `functions/api/data/[key].js` — la función de Cloudflare que guarda y lee los datos.

## Pasos para publicarla en tu proyecto de Cloudflare Pages (hemci)

### 1. Crear el namespace de KV (la base de datos)
1. Entra a tu dashboard de Cloudflare: https://dash.cloudflare.com
2. En el menú lateral busca **Storage & Databases > KV** (o "Workers KV").
3. Click en **Create namespace**. Ponle un nombre, por ejemplo `hemci-control`.
4. Guarda.

### 2. Conectar el KV a tu proyecto Pages (hemci)
1. Ve a **Workers & Pages** y entra a tu proyecto `hemci`.
2. Ve a **Settings > Bindings > Add > KV namespace**.
3. En **Variable name** escribe exactamente: `HEMCI_KV`
4. En **KV namespace** selecciona el que creaste (`hemci-control`).
5. Guarda.

### 3. Subir los archivos
Depende de cómo ya subes tu sitio:

**Si tu proyecto está conectado a un repositorio (GitHub/GitLab):**
Copia estos archivos dentro de tu repo del sitio, respetando la carpeta `functions/` en la raíz del proyecto (al mismo nivel que `index.html`), y sube los cambios (`git push`). Cloudflare desplegará automáticamente.

Si quieres tener esta app en una sección aparte de tu sitio (por ejemplo `hemci.mx/control`), pon estos archivos dentro de una carpeta `control/` en tu repo, y ajusta la ruta de la función a `functions/control/api/data/[key].js` y las llamadas `fetch` en `index.html` de `/api/data/` a `/control/api/data/`.

**Si subes archivos directo (arrastrar y soltar / Wrangler CLI):**
Sube la carpeta completa (con `index.html` y `functions/` incluidos) desde la pestaña de despliegues de tu proyecto, o usa:
```
npx wrangler pages deploy . --project-name=hemci
```

### 4. Volver a desplegar
Después de agregar el binding de KV, vuelve a desplegar el proyecto (un nuevo `git push`, o un nuevo deploy manual) para que la función pueda ver la variable `HEMCI_KV`.

### 5. Probar
Abre tu página. Debe cargar la Bitácora y, si registras un gasto o una tarea desde tu celular, tu socio debe verlo al recargar la página desde el suyo — los datos viven en la nube de Cloudflare, no en el navegador.

## Notas
- No hay contraseña ni login: cualquiera con el link de la página puede ver y editar los datos. Si quieres protegerlo, puedes activar **Cloudflare Access** sobre esa ruta desde el dashboard (Zero Trust > Access).
- Los datos se guardan en 4 llaves dentro del KV: `team`, `expenses`, `tasks`, `settings`. Puedes verlas y editarlas manualmente desde el dashboard de KV si necesitas corregir algo a mano.
