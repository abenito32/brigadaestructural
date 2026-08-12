# Brigada · Evaluación estructural en campo

PWA offline-first para que un ingeniero con matrícula levante evaluaciones de daño
estructural en terreno, sin señal, y sincronice cuando vuelva la conexión.

No es auto-reporte ciudadano. Quien llena el formulario es el inspector, en sitio.

## Desplegar

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

El receptor devuelve **503 y no 200** si no pudo grabar. Es deliberado: con un 200
la app marcaría la evaluación como enviada y borraría el pendiente, perdiéndola sin
que nadie se entere. Con 503 el registro sobrevive en el teléfono y se reintenta.

## Material

`docs/manual-brigada.pdf` — manual completo, 22 páginas.
`docs/brigada-presentacion.pptx` — presentación institucional para alcaldías,
universidades y asociaciones profesionales. Editable; se regenera con
`python3 docs/build_presentacion.py` (necesita `python-pptx`).

## Respaldo

```bash
sudo /opt/brigadas/respaldo.sh          # a mano
systemctl list-timers brigadas-respaldo # diario, 03:15 UTC
```

Vuelca la base y las fotos, verifica que el `.gz` descomprime, cifra con AES-256 si
hay `BRIGADA_RESPALDO_CLAVE`, y aplica retención. Con `BRIGADA_RESPALDO_REMOTO`
copia a un destino externo por rsync — y entonces el cifrado deja de ser opcional.

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
