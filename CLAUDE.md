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

**Rutas públicas**: `/` es la landing, `/app/` la PWA, `/api/` el receptor, y el panel
vive en **`admin.brigadaestructural.co`**, en origen separado.

La app está en `/app/` y no en un subdominio a propósito: IndexedDB y localStorage son
**por origen**, así que mover el origen dejaría huérfanas las evaluaciones pendientes y la
configuración de los teléfonos ya instalados. `landing/sw.js` se sirve en `/sw.js` solo
para desactivar el service worker viejo que quedó con alcance `/`; **no borrarlo**.

**Producción** (el VPS es compartido con otros servicios: no tocar nada fuera de estas rutas):
estáticos en `/var/www/brigadaestructural`, código en `/opt/brigadas`, secretos en
`/etc/brigadas.env` (root 0600), servicio `brigadas-api`, base `brigadas-db` en
`127.0.0.1:5433`, nginx en `sites-available/brigadaestructural`.

Límite de tasa por token: zonas en `conf.d/brigadas-limites.conf`, aplicadas solo
dentro del server block de Brigada (`burst=200` para la sincronización de vuelta del
terreno, `30r/m` sostenido). Devuelve **429**, no 503: 503 significa "no pude grabar".

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
- `docs/manual.html` + `docs/build_manual.py` — el manual en PDF. La fuente es el
  HTML; el PDF se regenera con Chrome headless. Al cambiar comportamiento del sistema,
  revisar si el manual quedó desactualizado y reconstruirlo.
- `respaldo.sh` + `brigadas-respaldo.timer` — respaldo diario cifrado de base y fotos.
  La llave SSH del destino va restringida con `rrsync -wo`: el origen escribe y nada
  más. La retención remota la ejecuta el destino, no el origen — darle permiso de
  borrado sería el camino del ransomware.
  **No hace `source` de `/etc/brigadas.env`**: es un `EnvironmentFile` de systemd y varios
  valores llevan `$` (el hash scrypt), que bash expandiría. Lee con `sed`.
- Vistas: `consolidado_publico` (k-anonimato ≥5), `pendientes_de_verificacion`
  (firmas fuera del registro), `rojos_pendientes` (segunda revisión, atrasados primero).
  Reemplazarlas exige `DROP` + `CREATE`: `CREATE OR REPLACE VIEW` solo admite agregar
  columnas al final.
- Mapa del panel (`/admin/mapa`): Leaflet **vendorizado** en `vendor/`, servido desde el
  propio servidor — el panel no depende de un CDN, igual que la app de campo. Se eligió
  Leaflet (148 KB) y no MapLibre (~800 KB) porque no hay teselas vectoriales que renderizar.
  El **área** del círculo es proporcional al conteo (radio ∝ √n), no el radio.
  La rampa de color está validada; no cambiarla sin volver a validarla.
### Roles del panel

Dos: **admin** (clave maestra en `BRIGADA_ADMIN_HASH`, ve todo) y **coordinador**
(tabla `coordinador`, ve solo su brigada). Los inspectores siguen sin cuenta.

- **`alcance_brigada()` / `filtro_alcance()` son el único punto** donde se decide el
  alcance. Cada consulta del panel lo intercala en su `WHERE`. Al agregar una consulta
  nueva, pasa por ahí — o filtra datos de otras brigadas.
- **La cookie concatena cuerpo y firma sin separador**, y al leer se corta por
  longitud (sha256 = 32 bytes). Con un separador de un byte la firma podía contenerlo
  y el corte caía mal: **una de cada ocho sesiones nacía rota, al azar**.
- **El rol y la brigada van DENTRO de la firma de la cookie.** Si fueran un campo aparte,
  cualquiera cambiaría `coordinador` por `admin` en la suya.
- **`exigir()` revalida al coordinador contra la base en cada petición.** La firma no
  caduca cuando se revoca a alguien: sin esa consulta, dar de baja a un coordinador lo
  dejaba dentro hasta ocho horas.
- **`exigir_admin()` protege lo que administra el sistema** (brigadas, solicitudes). Se
  comprueba en el servidor; esconder el enlace del menú no es una defensa.
- Sin `BRIGADA_ADMIN_HASH` no se monta **ninguna** ruta del panel, tampoco la entrada de
  coordinadores: hace falta un administrador para crearlos. En ese caso se monta
  `router_sin_clave`, que responde **503 con la explicación** — un 404 en JSON no
  distingue "falta configurarlo" de "esto está roto".
- **`/etc/brigadas.env` no se edita a la ligera.** Guarda los tokens de brigada y el hash
  del panel; borrar una línea es irreversible. Va incluido cifrado en el respaldo diario.
- `api_consulta.py` — API de consulta (`/api/v1/`), solo lectura, con la tabla
  `consumidor` como credenciales **separadas** de `brigada`: leer y escribir no pueden
  compartir token. El k-anonimato se aplica sobre el resultado ya filtrado.
- `esquema.sql` — **fuente de verdad del esquema**, idempotente. La tabla, los índices
  y la vista `consolidado_publico` viven ahí, no en el docstring del `.py`.
  **Las vistas van todas juntas, después de la última columna de la que dependen.**
  `pendientes_de_catastral` estaba definida arriba y usaba `id_local` y
  `clasificacion_efectiva`, que se agregan más abajo con `ALTER`: en una base ya
  existente daba igual, pero **crear una base desde cero fallaba** —justo lo que
  hace el comando de instalación documentado acá.

### Custodia del trabajo en el teléfono

Quien viene del papel teme que «se borre y se pierda», y una parte del miedo era correcta.

- **`navigator.storage.persist()` al arrancar.** IndexedDB por defecto es *best effort*: el
  navegador la desaloja cuando le falta espacio o el sitio lleva tiempo sin abrirse. Chrome
  concede la persistencia casi siempre a una PWA **instalada** y muchas veces no a una
  pestaña suelta — por eso la invitación a instalar no es cosmética.
- **El aviso de modo degradado vive en la pestaña Evaluar, no en `syncTxt`.** Estaba ahí y
  el siguiente mensaje de sincronización lo borraba: se podía trabajar la jornada entera en
  modo volátil (`sinIDB`) sin enterarse.
- **El `id_servidor` se guarda y se muestra.** El receptor lo devolvía desde siempre y se
  tiraba. Es el equivalente al sello en la copia, y es lo que permite decir «esto ya no
  depende de su teléfono».
- **Ajustes dice en texto si el guardado es duradero o no.** Sin eufemismos: «guardado, pero
  sin garantía» cuando el navegador negó la persistencia.
- `docs/no-se-pierde.html` es la pieza que se le manda al ingeniero antes de la primera
  jornada, con el plan de transición en paralelo. Se compila con
  `python3 docs/build_manual.py no-se-pierde`.

### Despacho (rutas de inspección)

El panel ya no solo sabe qué se evaluó: sabe **qué había que evaluar**. Una `ruta` se
asigna a UNA matrícula, el teléfono la descarga al sincronizar y la trabaja sin señal, y
al enviar la evaluación **la visita se cierra sola**.

- **El cierre de la visita va en un SAVEPOINT anidado** (`with con.transaction():` dentro
  del `with pool.connection()` de `recibir()`). `pool.connection()` es UNA transacción: sin
  el savepoint, cualquier fallo del despacho tumbaría también el `INSERT` de la evaluación
  y saldría un 503. **Se pierde el enlace, nunca la evaluación.**
- **`evaluacion_brigada.visita_declarada` NO lleva foreign key**, a propósito. Un id de
  visita vencido, anulado o de otra brigada haría fallar el `INSERT` → 503 → jornada
  atrapada en un teléfono. Mismo criterio que la matrícula fuera del registro: se acepta y
  se marca. El enlace validado vive en `visita.evaluacion`; lo declarado queda aparte, como
  el par `brigada` (declarada) / `brigada_token` (autenticada).
- **`filtro_ruta()` y no `filtro_alcance()` para consultas de rutas.** `ruta` tiene columna
  `brigada`, no `brigada_token`; con la columna por defecto, un JOIN con
  `evaluacion_brigada` resuelve **en silencio** contra la columna equivocada.
- **La matrícula del `GET /api/ruta` no autoriza nada.** El token es de la brigada y lo
  comparten todos sus teléfonos. Cruzar brigadas sí es imposible —la brigada sale de
  `autenticar()`, nunca de un parámetro—, y lo que contiene el riesgo es el contenido: ahí
  no viaja nada que un compañero de la misma brigada no pueda ver.
- **La ruta se vence sola en el teléfono, por su propio reloj** (`ruta.vence_en`, por
  defecto 30 h desde la jornada, `BRIGADA_HORAS_RUTA`). Si dependiera de que el servidor
  confirme, un teléfono sin señal —o perdido— conservaría la lista de direcciones para
  siempre. También se borra si cambian la matrícula en Ajustes.
- **La ruta vive en el almacén `ev` con el id reservado `"__ruta__"`**, igual que el
  borrador. No subir `indexedDB.open("brigada",1)` a la versión 2: `abrirDB()` no maneja
  `onblocked`, y un upgrade con la PWA instalada más una pestaña abierta en `/app/` deja la
  promesa sin resolver y **la app no arranca**.
- **`count(v.id)` y nunca `count(*)` en `cobertura_ruta`**: con el `LEFT JOIN`, una ruta sin
  visitas produce una fila con `v.*` en NULL y `count(*)` contaría 1.
- **Nunca un solo porcentaje mezclado en Evolución.** Lo levantado fuera de ruta se cuenta
  aparte; sumarlo al avance haría que una brigada que evaluó cien predios equivocados
  apareciera al 100 % de cobertura.
- **`|hora`, el filtro de zona horaria del panel.** La base devuelve `timestamptz` en la
  zona de la sesión, que en el contenedor es UTC; pintarlo con `strftime` mostraba todo
  cinco horas adelantado, incluido `revision_vence`. Toda fecha que vea una persona pasa
  por ese filtro (`BRIGADA_ZONA`, por defecto `America/Bogota`). `jornada` no: es un `DATE`.

### Reporte ciudadano (`ciudadano.brigadaestructural.co`)

La única entrada que **no firma un profesional**. Es un insumo para decidir a dónde
mandar una brigada, nunca una evaluación: no produce clasificación, no escribe en
`evaluacion_brigada`, no entra en `consolidado_publico`.

- **Origen separado, y no una ruta bajo el dominio principal.** `/app/` es el único
  origen cuya IndexedDB guarda evaluaciones pendientes y direcciones de rutas
  despachadas. La página del ciudadano es la única superficie pública sin token; en
  el mismo origen, un XSS ahí podría leer ese almacenamiento.
- **`api_ciudadano.py` es proceso y pool aparte**, no una ruta más del uvicorn de
  :8004 que comparten `api_brigadas`/`api_consulta`/`admin_web`. Una avalancha
  pública —la que llega sola tras un sismo, o la que manda alguien— consumiría las
  conexiones de las que depende un teléfono en la calle, y con `ESPERA_POOL=5` el
  inspector recibiría 503.
- **El municipio lo ELIGE la persona; no se deduce de la coordenada.** Los
  centroides del DANE ponen una casa de Suba en Cota y una de Bosa en Soacha, y el
  municipio decide a qué autoridad se manda a alguien.
- **La coordenada se guarda solo si `en_sitio`.** Tras un sismo la gente evacuó: un
  GPS tomado sin preguntar registra el albergue, no la casa dañada, y produce
  racimos alrededor de los albergues que nadie sabría leer.
- **Sin evento activo se muestra la guía y no el formulario.** Un formulario abierto
  que nadie lee le hace creer a una persona que ya hizo lo que tenía que hacer.
  Un solo evento activo a la vez, garantizado por índice único parcial.
- **El contacto local se muestra solo verificado y con la fecha a la vista.** Un
  `CHECK` impide guardarlo a medias. La línea nacional no vive en esa tabla: no
  caduca. Un teléfono muerto en plena emergencia es peor que ninguno.
- **EXIF borrado al recibir** (`sin_exif()`, a mano, sin Pillow): las fotos de
  celular traen la coordenada de dónde se tomaron, que la persona no sabe que está
  mandando. Se conservan APP0/JFIF y APP2/ICC; solo se cae APP1.
- **El cupo de fotos es por evento** (`evento.fotos_bytes`, contado en la misma
  transacción). Agotado, **el reporte entra sin fotos**: nunca se pierde el reporte,
  que es lo único que la persona no va a volver a llenar.
- **La respuesta solo devuelve el folio.** Ni clasificación, ni prioridad, ni si
  escaló: devolver eso convertiría el formulario en un dictamen automático sobre una
  vivienda. Y **el folio no es consultable**: un endpoint que lo resuelva convierte
  una tanda de folios adivinados en una lista de casas dañadas y vacías.
- **El teléfono va en `reservado`** y se purga al cerrar el evento. Nada depende de
  que esa columna tenga contenido.

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
- **El `id` de la tabla es un ULID del servidor; el del teléfono vive en `id_local`.**
  La idempotencia es `UNIQUE (origen, id_local)`, donde `origen` es una columna generada
  `coalesce(brigada_token,'(sin atribuir)')` — sin ese coalesce, dos `NULL` no son iguales
  en SQL y los tokens heredados escaparían del índice.
- **La sincronización sale de a 3, no todas de golpe.** Con 80 pendientes y fotos,
  el `forEach` original abría 80 subidas simultáneas: en señal de campo fallan en
  bloque y saturan el servidor. Si se sube esa tanda, revisar el `burst` de nginx.
- **El vencimiento de la revisión NO degrada el rojo.** Un rojo vencido sigue siendo
  rojo; solo se marca como atrasado. Un temporizador no puede rebajar un desalojo.
- **La revisión no borra la firma original.** `clasificacion` es lo que firmó quien
  evaluó y queda intacta; `clasificacion_efectiva` (generada) es lo que vale para
  consolidar. Ambas se conservan: son dos actos profesionales distintos.
- **Quien firmó no puede revisar su propia evaluación.** Validado en el servidor, no
  solo escondiendo la opción en el formulario.
- El servidor revalida lo que la app ya valida (matrícula, rango de clasificación,
  justificación obligatoria si se cambia el semáforo calculado). Es el registro de
  responsabilidad profesional; no relajarlo porque "el frontend ya lo chequea".

### Flujo de datos

El panel puede **despachar una ruta**: el teléfono la baja con `GET /api/ruta` al
sincronizar (o al «Probar conexión»), la guarda en IndexedDB bajo el id reservado
`"__ruta__"` y la trabaja sin señal. Al guardar una evaluación desde una visita, el payload
lleva `visita: <id>`, y el receptor cierra esa visita en la misma petición. Lo que no
produce evaluación —nadie atendió, no existe la dirección, se negaron, no se pudo acceder—
sube por `POST /api/visitas/cierre`. Sin ruta asignada la pestaña «Ruta» ni siquiera
aparece, y todo lo demás funciona igual que siempre.

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

- `correlativo()` genera `BRG-AAAAMMDD-NNN` contra el **total de registros del teléfono**, así
  que dos brigadas emiten el mismo el mismo día. Con ese id como clave primaria, la segunda
  evaluación se descartaba en silencio y el teléfono la daba por enviada: se perdía trabajo
  de campo. Resuelto con el ULID del servidor; el id del teléfono ya no es la llave.
- El JS de `index.html` es ES5 a propósito (`var`, sin arrow functions ni `const`). Seguir el estilo.
- `Form(...)` de FastAPI exige `python-multipart` instalado, y la falla es un
  `RuntimeError` al definir la ruta, no un `ImportError`: tumba el proceso entero al
  arrancar, no solo el módulo que lo usa.
- **Parámetros `NULL` sin cast revientan con `AmbiguousParameter`.** Ya pasó dos veces
  (`lat`/`lon` en el `INSERT`, filtro opcional en `admin_brigadas.py`). Si un parámetro
  puede llegar `NULL` y se compara con `IS NULL`, lleva `::tipo` explícito.
