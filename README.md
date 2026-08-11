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

Los tokens se generan con `openssl rand -hex 24`, uno por brigada. En Ajustes, el
inspector pega el endpoint y su token una sola vez por teléfono.

El receptor devuelve **503 y no 200** si no pudo grabar. Es deliberado: con un 200
la app marcaría la evaluación como enviada y borraría el pendiente, perdiéndola sin
que nadie se entere. Con 503 el registro sobrevive en el teléfono y se reintenta.

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
