# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Qué es

PWA offline-first para que un ingeniero **con matrícula** levante evaluaciones de daño
estructural en campo (semáforo ATC-20 adaptado a NSR-10, contexto Colombia) y sincronice
cuando vuelva la señal. No es auto-reporte ciudadano: quien llena el formulario es el inspector.

La UI, los comentarios y los identificadores del dominio están en español. Mantener ese idioma.

## Comandos

No hay build, ni bundler, ni package.json, ni suite de pruebas. Son archivos estáticos + un receptor FastAPI.

```bash
# Servir el frontend en local (HTTPS no hace falta en localhost)
python3 -m http.server 8080

# Base (requerida: el receptor no arranca sin BRIGADA_DSN)
cp docker-compose.example.yml docker-compose.yml && cp .env.example .env
docker compose -p brigadas up -d
docker exec -i brigadas-db psql -U brigadas -d brigadas < esquema.sql

# Receptor
pip install fastapi uvicorn "psycopg[binary,pool]"
uvicorn api_brigadas:app --port 8004     # con BRIGADA_TOKENS/DSN/FOTOS en el entorno
```

**Producción** (el VPS es compartido con otros servicios: no tocar nada fuera de estas rutas):
estáticos en `/var/www/brigadaestructural`, código en `/opt/brigadas`, secretos en
`/etc/brigadas.env` (root 0600), servicio `brigadas-api`, base `brigadas-db` en
`127.0.0.1:5433`, nginx en `sites-available/brigadaestructural`.

```bash
sudo systemctl restart brigadas-api && curl -s localhost:8004/salud
sudo journalctl -u brigadas-api -n 40 --no-pager
```

**HTTPS es obligatorio en producción**: sin él no hay service worker, ni geolocalización, ni cámara.

## Arquitectura

Sin dependencias de frontend:

- `index.html` — la aplicación entera (CSS + HTML + un IIFE en ES5 `var`/`function`, sin frameworks).
  Es deliberado: tiene que arrancar en teléfonos viejos y cachearse en un solo recurso.
- `sw.js` — service worker cache-first sobre el armazón (`./`, `index.html`, `manifest.json`).
  Ignora POST, orígenes externos, `/api` y `/admin`, y **solo cachea respuestas `res.ok`**:
  guardar un 404 lo vuelve permanente en ese teléfono, y el panel lleva datos personales
  que no pueden quedar en el disco del navegador.
  **Al cambiar los archivos cacheados hay que subir `CACHE = "brigada-vN"`**, si no los teléfonos
  se quedan con la versión vieja.
- `manifest.json` — instalación en pantalla de inicio.
- `api_brigadas.py` — receptor FastAPI sobre `psycopg` 3 con pool. Graba con
  `INSERT ... ON CONFLICT (id) DO NOTHING RETURNING id`: idempotente por `id`, y el
  `RETURNING` vacío es lo que reporta `duplicado: true`.
- `admin_brigadas.py` — alta/baja de brigadas e inspectores. Los tokens se guardan
  como sha256, nunca en claro; `brigada-alta` los muestra una sola vez.
- `admin_web.py` — panel en `/admin`, HTML renderizado en el servidor con Jinja2
  (autoescape obligatorio: los datos vienen de campo). Se monta **solo** si existe
  `BRIGADA_ADMIN_HASH`; sin clave no hay rutas. Requiere `jinja2` y `python-multipart`.
- `esquema.sql` — **fuente de verdad del esquema**, idempotente. La tabla, los índices
  y la vista `consolidado_publico` viven ahí, no en el docstring del `.py`.

### Invariantes del receptor (no romper)

- **Nunca 200 sin haber grabado.** Ante cualquier fallo de BD devuelve 503. Con un 200
  la app marca "enviada" y borra el pendiente: la evaluación se perdería en silencio.
- **`::float8` explícito en el `INSERT`.** Sin el cast, una evaluación sin GPS —caso
  normal en campo— revienta con `AmbiguousParameter` porque Postgres no infiere el
  tipo del parámetro `NULL`.
- **`ESPERA_POOL = 5`.** Con la BD caída responde 503 en 5s en vez de colgar el
  teléfono del inspector hasta el timeout del cliente.
- **Nunca rechazar por matrícula no registrada.** Se acepta y se marca
  `matricula_verificada=false`; la vista `pendientes_de_verificacion` es la cola de
  revisión. Rechazar deja evaluaciones atrapadas en un teléfono para siempre.
- **Los tokens de `BRIGADA_TOKENS` deben seguir funcionando.** Son el camino de
  compatibilidad para teléfonos ya configurados; entran sin atribución (`brigada:
  null`), no con error.
- El servidor revalida lo que la app ya valida (matrícula, rango de clasificación,
  justificación obligatoria si se cambia el semáforo calculado). Es el registro de
  responsabilidad profesional; no relajarlo porque "el frontend ya lo chequea".

### Flujo de datos

Formulario → `est` (estado en memoria) → `guardarReg()` en IndexedDB (`brigada`/`ev`, keyPath `id`)
con `estado:"pendiente"` → botón *Enviar pendientes* hace un POST por registro con header
`X-Brigada-Token` → si responde ok, el registro pasa a `estado:"enviada"` localmente.

Los fallos de red se tragan a propósito: el registro sigue pendiente y se reintenta. Nunca
borrar registros locales tras sincronizar.

Persistencia con degradación: IndexedDB → array `memoria` si falla; config en `localStorage`
bajo el prefijo `brg_` (`nom`, `mat`, `bri`, `url`, `tok`) → objeto `cfgMem` si falla.
Todo acceso pasa por `guardarReg`/`leerRegs`/`cfgGet`/`cfgSet`; no tocar las APIs directamente.

Las fotos se reducen a 1280px y viajan como data-URL base64 dentro del JSON; el receptor las
saca a disco (máximo 4, 3 MB cada una) y la base guarda rutas, no base64.

### Clasificación (`clasificar()`)

Devuelve `{v, por}` con `v`: 0 sin evaluar, 1 verde, 2 amarillo, 3 rojo. El orden de las reglas
es la regla: cualquier bandera de `BANDERAS` fuerza rojo antes de mirar los niveles de daño.
Los catálogos `DANOS` (4 categorías, escala 0–3) y `BANDERAS` (6 condiciones de cierre) son la
fuente única — el formulario se construye a partir de ellos, y el CSV y el esquema SQL usan
esas mismas claves. Cambiar una clave implica tocar el export CSV y la columna `danos`/`banderas`.

El inspector puede sobrescribir la clasificación, pero entonces `justificacion` es obligatoria;
se guardan ambos valores (`clasificacion` y `clasificacion_auto` + `motivo_auto`). No quitar
esa exigencia ni permitir guardar sin matrícula: es el registro de responsabilidad profesional.

## Restricciones del dominio (no negociables)

- Es **triaje preliminar**. La habilitación definitiva es competencia de UNGRD, Defensa Civil,
  bomberos y alcaldías; cualquier informe generado debe decirlo.
- Solo firma quien tenga matrícula vigente (Ley 400/97, NSR-10). El receptor rechaza payloads
  sin `inspector.matricula` (422) y la app bloquea el guardado.
- Dirección y coordenada son dato personal (Ley 1581 de 2012). Lo que se entrega a autoridades
  sale de `consolidado_publico`: agregado por municipio/barrio y con k-anonimato `HAVING count(*) >= 5`.
  Nunca exponer el predio en salidas públicas.
- Ningún dictamen automático llega al ciudadano: la app calcula, el ingeniero decide.

## Trampas conocidas

- `correlativo()` genera `BRG-AAAAMMDD-NNN` a partir del **total de registros del teléfono**,
  no de un contador por día ni global. Es único por dispositivo, pero dos brigadas distintas
  pueden emitir el mismo `id` el mismo día — si se consolida entre dispositivos, hay que
  prefijar por brigada antes de confiar en la idempotencia por `id`.
- El JS de `index.html` es ES5 a propósito (`var`, sin arrow functions ni `const`). Seguir el estilo.
- `Form(...)` de FastAPI exige `python-multipart` instalado, y la falla es un
  `RuntimeError` al definir la ruta, no un `ImportError`: tumba el proceso entero al
  arrancar, no solo el módulo que lo usa.
- **Parámetros `NULL` sin cast revientan con `AmbiguousParameter`.** Ya pasó dos veces
  (`lat`/`lon` en el `INSERT`, filtro opcional en `admin_brigadas.py`). Si un parámetro
  puede llegar `NULL` y se compara con `IS NULL`, lleva `::tipo` explícito.
