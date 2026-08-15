# Brigada · Evaluación estructural en campo

PWA offline-first para que un ingeniero con matrícula levante evaluaciones de daño
estructural en terreno, sin señal, y sincronice cuando vuelva la conexión.

No es auto-reporte ciudadano. Quien llena el formulario es el inspector, en sitio.

## Desplegar

### 0. Las rutas

```
/            landing pública (landing/index.html)
/app/        la PWA
/api/        el receptor
/sw.js       desactivador del service worker viejo — no borrar
admin.<dominio>   el panel, en origen separado
ciudadano.<dominio>   el reporte ciudadano, en origen separado
```

### 1. Los estáticos

`index.html`, `sw.js`, `manifest.json` y los dos iconos van a cualquier carpeta
servida por HTTPS. **HTTPS es obligatorio**: sin él no funcionan el service worker,
la geolocalización ni la cámara, o sea nada de lo que hace útil a esta app.

```nginx
server {
    server_name ejemplo.org;
    root /var/www/brigadaestructural;
    index index.html;

    # Crítico: si el service worker se cachea, la app queda congelada en campo
    # y no hay forma de actualizar los teléfonos a distancia.
    location = /sw.js { add_header Cache-Control "no-cache, no-store, must-revalidate"; }

    location /api/ {
        proxy_pass http://127.0.0.1:8004;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        client_max_body_size 12M;   # las evaluaciones llevan hasta 4 fotos
    }

    location / { try_files $uri $uri/ /index.html; }
}
```

### 2. La base

```bash
cp docker-compose.example.yml docker-compose.yml
cp .env.example .env          # completar POSTGRES_PASSWORD
docker compose -p brigadas up -d
docker exec -i brigadas-db psql -U brigadas -d brigadas < esquema.sql
```

### 3. El receptor

```bash
python3 -m venv /opt/brigadas/venv
/opt/brigadas/venv/bin/pip install fastapi uvicorn "psycopg[binary,pool]"
```

Las variables (`BRIGADA_TOKENS`, `BRIGADA_DSN`, `BRIGADA_FOTOS`) van en un archivo
aparte con permisos `0600`, nunca en el unit de systemd, que es legible por todos.
Ver `.env.example` y `brigadas-api.service.example`.

### 4. El panel de administración

```bash
/opt/brigadas/venv/bin/pip install jinja2 python-multipart
sudo env BRIGADA_DSN=... /opt/brigadas/venv/bin/python /opt/brigadas/admin_brigadas.py clave
# pide la clave, imprime la línea BRIGADA_ADMIN_HASH= para /etc/brigadas.env
sudo systemctl restart brigadas-api
```

Queda en `/admin`: resumen por brigada y por sector, listado de reportes con filtros,
y alta/baja de brigadas e inspectores. **Sin `BRIGADA_ADMIN_HASH` las rutas no se
montan**: no existe un modo sin clave, y `/admin` devuelve 404.

La clave se guarda como hash scrypt, la sesión va en cookie `HttpOnly` + `Secure` +
`SameSite=strict` firmada con una llave derivada de ese hash —cambiar la clave cierra
todas las sesiones— y el login está limitado a 8 intentos cada diez minutos por IP.

El panel muestra direcciones y coordenadas: es para coordinar la brigada, no para
difundir. Lo que se entrega a las autoridades es el consolidado por sector.

### 5. El registro de brigadas e inspectores (línea de comandos)

```bash
ADM="/opt/brigadas/venv/bin/python /opt/brigadas/admin_brigadas.py"
sudo env BRIGADA_DSN=... $ADM brigada-alta "Universidad Nacional" "coord@unal.edu.co"
sudo env BRIGADA_DSN=... $ADM inspector-alta "25101-COPNIA" "Ana Ruiz" "Universidad Nacional"
sudo env BRIGADA_DSN=... $ADM sin-verificar
```

`brigada-alta` genera el token y lo muestra **una sola vez**: la base guarda solo
su sha256, así que una filtración de la base no filtra tokens. Cada evaluación
queda atribuida a la brigada que autenticó, que no es lo mismo que el nombre que
el inspector escribe a mano en Ajustes — ese sigue siendo texto libre e informativo.

Una evaluación firmada por una matrícula que no está en el registro **se acepta
igual** y queda marcada: en una emergencia, perder trabajo de campo es peor que
aceptarlo pendiente de revisión. `sin-verificar` lista esa cola con los rojos
primero, y dar de alta al inspector reconcilia hacia atrás lo que ya había enviado.

Los tokens de `BRIGADA_TOKENS` siguen funcionando para no dejar afuera a un
teléfono ya configurado, pero no atribuyen. `brigada-adoptar` los incorpora al
registro sin rotarlos ni tocar los teléfonos.

Los tokens se generan con `openssl rand -hex 24`, uno por brigada. En Ajustes, el
inspector pega el endpoint y su token una sola vez por teléfono, y usa
**Probar conexión** antes de salir a terreno: distingue servidor inalcanzable,
token equivocado y ruta mal escrita, que en campo se ven todos igual (la cola no
baja). No envía ninguna evaluación.

Si la app se sirve desde **otro dominio** que la API, hay que autorizarlo en
`BRIGADA_ORIGENES`; si no, el navegador bloquea la sincronización en el preflight
y el fallo no se ve por ningún lado. Con app y API en el mismo dominio —lo normal—
déjelo vacío.

El endpoint está limitado por token: ráfaga de 200 —para que una brigada que vuelve
del terreno vacíe su cola de una vez— y 30 por minuto sostenido. Al pasarse responde
**429**, que la app trata como reintentable igual que un fallo de red.

El receptor devuelve **503 y no 200** si no pudo grabar. Es deliberado: con un 200
la app marcaría la evaluación como enviada y borraría el pendiente, perdiéndola sin
que nadie se entere. Con 503 el registro sobrevive en el teléfono y se reintenta.

## El reporte ciudadano (subdominio aparte)

La única entrada que **no firma un profesional**: la persona que vive en el inmueble
registra que existe y qué se ve. Es un insumo para decidir a dónde mandar una
brigada, **nunca una evaluación** — no produce clasificación, no escribe en
`evaluacion_brigada` y no entra en `consolidado_publico`.

Va en **`ciudadano.<dominio>`**, origen separado, y no en una ruta del dominio
principal. La razón no es estética: `/app/` es el único origen cuya IndexedDB
guarda evaluaciones pendientes y las direcciones de rutas despachadas, y esta
página es la única superficie pública y sin token del sistema. En el mismo origen,
un XSS acá podría leer ese almacenamiento.

Se acota por **evento**. El subdominio existe los 365 días del año y la mayoría de
esos días no hay sismo: sin evento activo se muestra la guía y **no** el
formulario. Un formulario abierto que nadie lee le hace creer a alguien que ya hizo
lo que tenía que hacer, y le consume la única acción que iba a tomar ese día. El
formulario se abre además solo en los municipios donde hay una brigada operando
(`evento_municipio.formulario_abierto`); en los demás el municipio igual aparece,
con su contacto, porque la guía sirve ahí.

```bash
sudo cp brigadas-ciudadano.service.example /etc/systemd/system/brigadas-ciudadano.service
sudo mkdir -p /var/lib/brigadas/fotos-ciudadano
sudo chown brigadas:brigadas /var/lib/brigadas/fotos-ciudadano
# en /etc/brigadas.env:
#   BRIGADA_DSN_CIUDADANO=postgresql://ciudadano:...@127.0.0.1:5433/brigadas
#   BRIGADA_FOTOS_CIUDADANO=/var/lib/brigadas/fotos-ciudadano
sudo systemctl daemon-reload && sudo systemctl enable --now brigadas-ciudadano
```

`BRIGADA_DSN_CIUDADANO` debería apuntar a un **rol restringido** a `evento`,
`evento_municipio` y `reporte_ciudadano`. Así la frontera con el lado profesional
se sostiene sola aunque alguien escriba mal una consulta dentro de seis meses. Si
falta, el servicio cae a `BRIGADA_DSN` para no bloquear un despliegue de
emergencia — mismo comportamiento, menos garantías.

```nginx
# La zona va en conf.d/brigadas-limites.conf, con el resto. La clave es la IP
# porque acá no hay token: es la única que hay.
limit_req_zone $binary_remote_addr zone=ciudadano:10m rate=20r/m;

server {
    server_name ciudadano.ejemplo.org;
    root /var/www/brigadaestructural/ciudadano;
    index index.html;

    location /api/ {
        limit_req  zone=ciudadano burst=10 nodelay;
        proxy_pass http://127.0.0.1:8005;     # el servicio del ciudadano, NO el 8004
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        client_max_body_size 10M;             # hasta 3 fotos ya reducidas
    }

    # Sin service worker y sin manifest: esta página es suelta a propósito.
    location / { try_files $uri $uri/ =404; }
}
```

El primer evento se declara por SQL mientras no exista la pantalla de admin:

```sql
INSERT INTO evento (id, nombre, ocurrido_en, estado, creado_por)
VALUES ('01J...', 'Sismo del 10 de agosto de 2026', '2026-08-10 07:34-05', 'activo', 'admin');

-- Con brigada operando: el formulario se abre acá.
INSERT INTO evento_municipio (evento, cod_dane, municipio, gravedad, formulario_abierto,
                              entidad, telefono, verificado_en, verificado_por)
VALUES ('01J...', '66001', 'Pereira', 'critica', true,
        'Gestión del Riesgo de Pereira', '606 000 0000', '2026-08-14', 'andres');

-- Afectado pero sin brigada: sale en la guía, sin formulario. El contacto es
-- todo-o-nada: o van entidad, teléfono y fecha, o no va ninguno.
INSERT INTO evento_municipio (evento, cod_dane, municipio, gravedad)
VALUES ('01J...', '27600', 'San José del Palmar', 'critica');
```

**Un teléfono sin verificar no se publica.** La línea nacional se muestra siempre
porque no caduca; el contacto local solo aparece con la fecha de verificación a la
vista, para que quien lo lea pueda juzgar qué tan viejo es el dato antes de marcar.
Un número muerto en plena emergencia es peor que ninguno.

## Material

`docs/manual-brigada.pdf` — manual completo, 22 páginas.
`docs/brigada-presentacion.pptx` — presentación institucional para alcaldías,
universidades y asociaciones profesionales. Editable; se regenera con
`python3 docs/build_presentacion.py` (necesita `python-pptx`).

## Roles del panel

**Administrador** — clave maestra en `BRIGADA_ADMIN_HASH`. Ve todo y administra el
sistema: brigadas, credenciales de la API, solicitudes, estado del respaldo.

**Coordinador** — usuario y clave propios, atado a una brigada. Ve **solo lo suyo**:
su resumen, su mapa, sus reportes, sus rojos pendientes y sus inspectores. No puede
emitir tokens, ver otras brigadas ni el estado del servidor.

Se crean **desde el panel**, en Brigadas, debajo de cada brigada: usuario y nombre, y
el sistema genera la clave y la muestra una sola vez —igual que el token—. También por
línea de comandos, si prefiere elegir la clave:

```bash
sudo env BRIGADA_DSN=... $ADM coordinador-alta "coord.unal" "Ana Ruiz" "Universidad Nacional"
sudo env BRIGADA_DSN=... $ADM coordinadores
sudo env BRIGADA_DSN=... $ADM coordinador-baja "coord.unal"
```

Si se pierde el token de una brigada —se muestra una sola vez— se emite otro con
**Reemitir token** en el panel, o `brigada-reemitir` por línea de comandos. El anterior
deja de servir en el acto: hay que reconfigurar los teléfonos de esa brigada.

El alcance se aplica **en el servidor, en cada consulta**, no escondiendo enlaces: forzar
otra brigada por parámetro o mandar el id de una evaluación ajena devuelve lo suyo o un
403. Dar de baja a un coordinador —o a su brigada— corta también las sesiones abiertas.

Los inspectores siguen sin cuenta: su matrícula es una firma, no un acceso.

## El mapa del consolidado

En `/admin/mapa`. Un círculo por sector: el **área** es la cantidad de evaluaciones
(radio ∝ √n, para que el doble de evaluaciones no se vea cuatro veces más grande) y el
color, en rampa de un solo tono, la proporción que quedó en rojo. Un anillo azul marca
los sectores con rojos sin segunda revisión — y también salen en la tabla, para que la
información nunca dependa solo del color.

Respeta el mismo umbral de anonimato que el consolidado: los sectores con menos de cinco
evaluaciones no aparecen, y el punto es el centroide del sector, nunca un predio.

Leaflet va vendorizado en `vendor/` y se sirve desde el propio servidor. Las teselas del
mapa base se configuran con `BRIGADA_TESELAS`, para que una entidad pueda apuntar a su
geoportal en vez de a un tercero.

## Doble revisión de los rojos

Cada evaluación en rojo entra en estado `pendiente` con un plazo
(`BRIGADA_REVISION_HORAS`, 24 por defecto) y necesita que **otro** inspector
registrado la mire desde el panel. Quien firmó no puede revisarse a sí mismo, y
revocar exige motivo escrito.

Dos reglas que no se relajan:

- **El vencimiento no degrada nada.** Un rojo atrasado sigue siendo rojo; solo se
  vuelve visible. Un temporizador no puede rebajar un desalojo.
- **La firma original no se borra.** `clasificacion` queda tal cual; la revisión se
  guarda aparte con su matrícula, su fecha y su motivo. Lo que cambia es
  `clasificacion_efectiva`, que es la que usan el consolidado y la API.

## API de consulta

Solo lectura, credenciales propias separadas de las de brigada, alcance por
municipio y dos niveles: `consolidado` (agregado con umbral de anonimato, sin dato
personal) y `detalle` (direcciones y coordenadas, solo para la entidad responsable).

```
GET /api/v1/                     qué puede hacer esta credencial
GET /api/v1/consolidado[.geojson]
GET /api/v1/evaluaciones[.geojson]     (alcance: detalle)
Cabecera: X-API-Token
```

El umbral de anonimato se aplica **después** de los filtros: acotar por fechas hasta
aislar un registro no lo revela, el sector desaparece de la respuesta.

```bash
sudo env BRIGADA_DSN=... $ADM consumidor-alta "Tablero de riesgo" consolidado
sudo env BRIGADA_DSN=... $ADM consumidor-alta "Alcaldía de X" detalle "X"
```

## Respaldo

```bash
sudo /opt/brigadas/respaldo.sh          # a mano
systemctl list-timers brigadas-respaldo # diario, 03:15 UTC
```

Vuelca la base y las fotos, verifica que el `.gz` descomprime, cifra con AES-256 si
hay `BRIGADA_RESPALDO_CLAVE`, y aplica retención. Con `BRIGADA_RESPALDO_REMOTO`
copia a un destino externo por rsync — y entonces el cifrado deja de ser opcional.

Incluye **`/etc/brigadas.env`** cifrado: ahí viven los tokens de brigada y el hash de
la clave del panel. Sin ese archivo, restaurar la base no alcanza — habría que emitir
tokens nuevos y reconfigurar todos los teléfonos.

⚠️ La passphrase de cifrado vive dentro de ese mismo archivo. **Guárdela fuera del
servidor**: si lo que perdió es el servidor, sin ella el respaldo no se abre.

El resultado queda en `/var/lib/brigadas/respaldo-estado.json`, que `/api/salud` y el
panel leen: sin MTA en el servidor, es la forma de enterarse de que dejó de correr.

**Un respaldo en el mismo disco no protege de perder el disco.** Configure
`BRIGADA_RESPALDO_REMOTO`. Y restaure alguna vez: hasta entonces no sabe si sirve.

### El destino, con la llave restringida

En el servidor de destino, la llave del origen debe poder **escribir y nada más**:

```
command="/usr/bin/rrsync -wo /srv/respaldos/brigadas",restrict ssh-ed25519 AAAA...
```

Sin esa restricción, `restrict` por sí solo sigue permitiendo ejecutar comandos:
el origen puede borrar los respaldos. Lo comprobamos y se borraron. Con `-wo` no
puede leerlos ni eliminarlos — que es exactamente lo que impide que un atacante en
el servidor de la app destruya las copias antes de cifrar el original.

Por lo mismo, **la retención del destino la hace el destino**, con su propio cron:

```
17 4 * * * root find /srv/respaldos/brigadas -maxdepth 1 -type f -mtime +30 -delete
```

## Manual

`docs/manual-brigada.pdf` — 22 páginas, tres partes: para el inspector en campo,
para quien coordina la brigada, y para quien administra el servidor. Incluye una
tarjeta de referencia del semáforo pensada para imprimirse aparte y llevarse.

Se reconstruye con `python3 docs/build_manual.py` (necesita Chrome o Chromium);
la fuente editable es `docs/manual.html`.

## Cómo se usa en campo

1. Con señal, abrir la URL una vez e instalar ("Agregar a pantalla de inicio"). Queda cacheada.
2. Ajustes: nombre, matrícula COPNIA, brigada, endpoint, token. Una sola vez por teléfono.
3. Evaluar. Todo se guarda en el teléfono aunque no haya red.
4. Al volver la señal: Cola → Enviar pendientes.

La cola sobrevive al cierre de la app y al reinicio del teléfono. El envío es idempotente
por `id`, así que reintentar no duplica.

## Regla de clasificación

Semáforo ATC-20 adaptado a NSR-10. Se calcula sola y el inspector puede cambiarla,
pero cambiarla exige escribir el motivo — queda registrado junto con el valor calculado.

| Resultado | Se dispara cuando |
|---|---|
| **Rojo** · inseguro | cualquier condición de cierre marcada, o daño severo en elementos portantes, entrepisos o terreno |
| **Amarillo** · uso restringido | daño moderado en portantes, entrepisos o terreno, o daño severo solo en muros divisorios y fachada |
| **Verde** · habitable | daño leve o nulo, sin condiciones de cierre |

Condiciones que fuerzan rojo sin importar lo demás: colapso parcial, inclinación visible,
columna con núcleo triturado o acero expuesto, grietas pasantes en muros portantes,
riesgo externo (vecino inestable o talud), elementos pesados sueltos sobre el acceso.

## Límites que hay que respetar

- Esto es **triaje preliminar**. La habilitación definitiva de una edificación es competencia
  de UNGRD, Defensa Civil, bomberos y las alcaldías. Dígalo en cada informe que salga.
- Solo firma quien tenga matrícula vigente (Ley 400/97, NSR-10). Los estudiantes acompañan y
  documentan; no clasifican.
- Dirección y coordenada son dato personal (Ley 1581 de 2012). Lo que se entrega a las
  autoridades sale de la vista `consolidado_publico`, agregado por sector y con umbral mínimo
  de registros. Nunca el predio.
- Ningún dictamen automático llega al ciudadano. La app calcula, el ingeniero decide.

## Qué falta si esto crece

- Verificación de matrícula contra COPNIA en el registro de inspectores.
- Doble revisión obligatoria de los rojos antes de consolidar.
- Panel de consolidado con mapa PostGIS y export para la sala de crisis.
- Reasignación: qué manzanas ya tienen cobertura y cuáles no.
- Los `id` (`BRG-AAAAMMDD-NNN`) se numeran contra el total de registros de cada
  teléfono: son únicos por dispositivo, pero dos brigadas pueden emitir el mismo
  el mismo día. Antes de consolidar entre dispositivos hay que prefijarlos por
  brigada; la idempotencia por `id` depende de eso.

## Sostener el proyecto

La herramienta es libre y no tiene costo de licencia. Lo que cuesta dinero es
sostenerla: operar el servidor, respaldar fuera de él, acompañar a las brigadas
durante una activación, y construir las integraciones que cada entidad necesita.

Las formas de apoyar son institucionales —convenio, contrato de soporte,
financiamiento de una integración concreta, cooperación académica— y se acuerdan
con Rollout Comercio e Servicios Limitada, con factura. Escriba por los
[issues](https://github.com/abenito32/brigadaestructural/issues) o por el
formulario de <https://brigadaestructural.co>.

**Lo que una entidad financie queda disponible para todas.** La AGPL obliga a
publicar las mejoras: quien pague una integración no compra una función privada,
paga una que queda en el repositorio para el siguiente municipio que la necesite.

## Licencia

Desarrollada con Amor por **Andrés Benito Revollo Vélez** · Rollout Comercio e
Servicios Limitada.

Para reportar un problema o proponer un cambio, use los
[issues del repositorio](https://github.com/abenito32/brigadaestructural/issues).
El correo de contacto no se publica acá a propósito: una dirección en un repositorio
público se rastrea en cuestión de días.

Copyright © 2026 **Rollout Comercio e Servicios Limitada / Andrés Benito Revollo Vélez**.

Software libre bajo **GNU AGPL v3**. Si lo modifica y lo distribuye —o lo ofrece
como servicio en red, que es el caso de casi cualquier despliegue de esto—, las
modificaciones también son AGPL y debe publicarlas.

La intención es que cualquier universidad, alcaldía u organismo de socorro pueda
tomarlo, adaptarlo a su normativa y usarlo — pero que las mejoras vuelvan al común.
En una emergencia nadie debería estar reescribiendo esto desde cero.

El aviso de copyright y el enlace al código en la interfaz no son decorativos: la
§13 de la AGPL obliga a ofrecer la fuente a quien usa el programa por red. Si hace
un fork, mantenga el enlace y apúntelo a su repositorio (`BRIGADA_FUENTE` para la
API, el enlace de Ajustes para la app).

Si lo adapta a otro país, lo que hay que revisar es la regla de clasificación
(`clasificar()` en `index.html`), que está calibrada al ATC-20 adaptado a NSR-10,
y los límites legales de la sección anterior, que son de Colombia.
