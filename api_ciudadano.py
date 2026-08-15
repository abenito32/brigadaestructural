# Brigada · Reporte ciudadano
# Copyright (C) 2026 Rollout Comercio e Servicios Limitada / Andrés Benito Revollo Vélez
#
# Este programa es software libre: usted puede redistribuirlo y/o
# modificarlo bajo los términos de la Licencia Pública General Affero
# de GNU publicada por la Free Software Foundation, en su versión 3 o
# (a su elección) cualquier versión posterior.
#
# Se distribuye con la esperanza de que sea útil, pero SIN NINGUNA
# GARANTÍA; ni siquiera la garantía implícita de COMERCIABILIDAD o
# IDONEIDAD PARA UN PROPÓSITO PARTICULAR. Vea la Licencia para más detalle.
#
# Debería haber recibido una copia junto con este programa. Si no,
# vea <https://www.gnu.org/licenses/>.
#
# AGPL §13: quien use este programa a través de una red tiene derecho a
# recibir su código fuente. El enlace en la interfaz y en /api/fuente es parte
# del cumplimiento de esa obligación: no quitarlo.

"""
Receptor del reporte ciudadano. Sirve a ciudadano.brigadaestructural.co.
  uvicorn api_ciudadano:app --host 127.0.0.1 --port 8005

POR QUE ES UN PROCESO APARTE, y no una ruta mas de api_brigadas
--------------------------------------------------------------
api_brigadas, api_consulta y admin_web comparten un solo uvicorn y un solo pool
de psycopg. Este endpoint es el unico PUBLICO y SIN CREDENCIAL del sistema, o
sea el unico por donde puede entrar una avalancha: la que llega sola despues de
un sismo, y la que manda alguien a proposito. Con el pool compartido, esa
avalancha consumiria las conexiones de las que depende un telefono parado en la
calle intentando sincronizar la jornada, y con ESPERA_POOL=5 el inspector
recibiria un 503. Proceso propio, pool propio: que se sature entero sin que la
brigada se entere. Es el mismo criterio con el que ya estan separadas las zonas
de limite de tasa de nginx.

FRONTERA
--------
Esto NO es una evaluacion. No produce clasificacion de habitabilidad, no escribe
en evaluacion_brigada y no entra en consolidado_publico. Es un insumo para
decidir a donde mandar una brigada. La conexion deberia hacerse con un rol de
Postgres restringido a estas tablas: la frontera se sostiene sola aunque alguien
escriba mal una consulta dentro de seis meses.

Entorno:
  BRIGADA_DSN_CIUDADANO  DSN propio, idealmente con rol restringido.
                         Si falta, cae a BRIGADA_DSN (mismo comportamiento, menos
                         garantias) para no bloquear un despliegue de emergencia.
  BRIGADA_FOTOS_CIUDADANO  directorio de las imagenes (la BD guarda rutas)
  BRIGADA_FUENTE         URL del repositorio propio (AGPL §13)

El esquema vive en esquema.sql, que es la fuente de verdad.
"""

import base64, os, pathlib, re, secrets, time
from contextlib import asynccontextmanager
from datetime import datetime, timezone

import psycopg
from fastapi import FastAPI, HTTPException, Request
from psycopg.types.json import Jsonb
from psycopg_pool import ConnectionPool, PoolTimeout
from pydantic import BaseModel

DSN = os.getenv("BRIGADA_DSN_CIUDADANO") or os.getenv("BRIGADA_DSN", "")
FUENTE = os.getenv("BRIGADA_FUENTE", "https://github.com/abenito32/brigadaestructural")
FOTOS = pathlib.Path(os.getenv("BRIGADA_FOTOS_CIUDADANO", "./fotos-ciudadano"))
FOTOS.mkdir(parents=True, exist_ok=True)

# Tres y no cuatro. La app de campo admite cuatro porque quien las toma es un
# ingeniero con una tarea; aca las toma alguien parado afuera de su casa.
MAX_FOTOS = 3
MAX_BYTES_FOTO = 3_000_000
ESPERA_POOL = 5

# Las respuestas que se aceptan. Lista blanca: lo que no este aca se descarta en
# silencio, para que nadie use el jsonb como bolsa de basura arbitraria.
PREGUNTAS_DECIDEN = ("colapso", "inclinacion", "gas",          # escalan
                     "puertas", "grietas_nuevas",              # arman el patron de cuadra
                     "pisos", "antiguedad")                    # contexto
PREGUNTAS_OPCIONALES = ("agua", "ventanas", "escaleras", "fachada", "vecinos")
PREGUNTAS = PREGUNTAS_DECIDEN + PREGUNTAS_OPCIONALES
RESPUESTAS_VALIDAS = {"si", "no", "nose"}

# Lo que manda una brigada al sitio sin esperar turno. Son condiciones que la
# persona puede observar sin criterio tecnico, y NO una clasificacion: no se le
# muestra a quien reporta y no se parece a un semaforo. Un dictamen automatico
# nunca llega al ciudadano; la app calcula, el ingeniero decide.
REGLAS_ESCALADO = {
    "colapso": "se cayo una parte de la edificacion",
    "inclinacion": "la edificacion se ve inclinada",
    "gas": "olor a gas",
}

pool: ConnectionPool | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global pool
    if not DSN:
        raise RuntimeError("Falta BRIGADA_DSN_CIUDADANO: el receptor no arranca sin base.")
    pool = ConnectionPool(DSN, min_size=1, max_size=6, open=True,
                          timeout=ESPERA_POOL, kwargs={"connect_timeout": 5},
                          check=ConnectionPool.check_connection)
    try:
        pool.wait(timeout=30)
    except PoolTimeout:
        # Arranca igual y responde 503 hasta que la base vuelva, como el receptor
        # de brigadas: un reboot no puede dejar el servicio muerto.
        pass
    yield
    pool.close()


app = FastAPI(title="Brigadas · reporte ciudadano", lifespan=lifespan)

_B32 = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def ulid() -> str:
    """El mismo identificador que usa el receptor de brigadas. Doce lineas en vez
    de una dependencia."""
    valor = (int(time.time() * 1000) << 80) | secrets.randbits(80)
    return "".join(_B32[(valor >> despl) & 31] for despl in range(125, -1, -5))


def sin_exif(jpeg: bytes) -> bytes:
    """Borra los segmentos APP1 (EXIF y XMP) de un JPEG.

    Una foto de celular trae la coordenada de donde se tomo. Es dato personal que
    la persona no sabe que esta mandando, y guardarlo nos deja con la ubicacion
    real de gente que quizas escribio otra direccion a proposito —o que reporta
    desde un albergue y no quiere decir donde duerme—.

    Se borra APP1 y nada mas: APP0 (JFIF) y APP2 (perfil de color) se conservan
    para no alterar como se ve la imagen. Se hace a mano recorriendo los
    marcadores en vez de traer Pillow: son treinta lineas y el proyecto no
    arrastra dependencias que no necesita.

    Si el archivo no parece un JPEG, se devuelve intacto: el que decide si se
    acepta es quien llama, no esta funcion.
    """
    if len(jpeg) < 4 or jpeg[0:2] != b"\xff\xd8":
        return jpeg
    salida = bytearray(jpeg[0:2])
    i = 2
    n = len(jpeg)
    while i + 3 < n:
        if jpeg[i] != 0xFF:
            break                      # fuera de sincronia: se copia el resto tal cual
        marcador = jpeg[i + 1]
        # Inicio de los datos comprimidos: de aca al final no hay mas metadatos.
        if marcador == 0xDA:
            salida += jpeg[i:]
            return bytes(salida)
        if marcador in (0xD8, 0xD9) or 0xD0 <= marcador <= 0xD7:
            salida += jpeg[i:i + 2]
            i += 2
            continue
        largo = int.from_bytes(jpeg[i + 2:i + 4], "big")
        if largo < 2 or i + 2 + largo > n:
            break
        if marcador != 0xE1:           # APP1 = EXIF/XMP: es el que se cae
            salida += jpeg[i:i + 2 + largo]
        i += 2 + largo
    else:
        return bytes(salida)
    # Se salio por un `break`: el archivo es raro. Mejor devolverlo entero que
    # entregar un JPEG cortado a la mitad.
    return jpeg


def decodificar_fotos(fotos: list[str]) -> list[bytes]:
    """Del data-URL a bytes, ya sin EXIF. Lo que no sirve se descarta callado: una
    foto rota no puede tumbar el reporte entero."""
    salida = []
    for dataurl in fotos[:MAX_FOTOS]:
        if "," not in dataurl:
            continue
        try:
            crudo = base64.b64decode(dataurl.split(",", 1)[1])
        except (ValueError, TypeError):
            continue
        if not crudo or len(crudo) > MAX_BYTES_FOTO:
            continue
        salida.append(sin_exif(crudo))
    return salida


class Reporte(BaseModel):
    cod_dane: str = ""
    municipio: str = ""
    direccion: str = ""
    barrio: str = ""
    respuestas: dict[str, str] = {}
    relato: str = ""
    telefono: str = ""
    en_sitio: bool = False
    lat: float | None = None
    lon: float | None = None
    precision_m: int | None = None
    fotos: list[str] = []
    autoriza: bool = False
    # Campo trampa, como el del formulario de contacto de la landing.
    sitio: str = ""


def evento_activo(cur) -> tuple | None:
    cur.execute("""SELECT id, nombre, descripcion, ocurrido_en, cupo_fotos_mb, fotos_bytes
                     FROM evento WHERE estado = 'activo'""")
    return cur.fetchone()


@app.get("/api/evento")
def evento():
    """Que hay abierto ahora mismo, y a quien mandar a la gente de cada municipio.

    Sin evento activo devuelve `activo: false` y NO es un error: la pagina existe
    los 365 dias del año y ese es el estado normal. La guia se muestra igual; lo
    que no aparece es el formulario. Un formulario abierto sin nadie leyendo del
    otro lado le hace creer a una persona que ya hizo lo que tenia que hacer.
    """
    try:
        with pool.connection(timeout=ESPERA_POOL) as con, con.cursor() as cur:
            ev = evento_activo(cur)
            if not ev:
                return {"activo": False}
            cur.execute("""SELECT cod_dane, municipio, gravedad,
                                  entidad, telefono, verificado_en, formulario_abierto
                             FROM evento_municipio
                            WHERE evento = %s
                            ORDER BY municipio""", (ev[0],))
            municipios = [{
                "cod_dane": f[0], "municipio": f[1], "gravedad": f[2],
                # Afectado y "acá se puede reportar" son cosas distintas. El
                # municipio sale en la lista igual —la guia y el contacto sirven
                # ahi— pero el formulario solo aparece donde hay brigada.
                "formulario": f[6],
                # El contacto local viaja SOLO si esta verificado, y con la fecha:
                # quien lea la pagina tiene que poder juzgar que tan viejo es el
                # dato antes de marcar. El esquema ya impide guardarlo a medias.
                "contacto": ({"entidad": f[3], "telefono": f[4],
                              "verificado_en": f[5].isoformat()} if f[5] else None),
            } for f in cur.fetchall()]
    except (psycopg.Error, PoolTimeout) as e:
        print(f"[evento] {e.__class__.__name__}: {e}", flush=True)
        raise HTTPException(503, "No se pudo consultar el operativo")
    return {"activo": True, "evento": {"id": ev[0], "nombre": ev[1],
                                       "descripcion": ev[2],
                                       "ocurrido_en": ev[3].isoformat()},
            "municipios": municipios,
            "servidor_ts": datetime.now(timezone.utc).isoformat()}


def limpiar_respuestas(crudas: dict[str, str]) -> dict[str, str]:
    """Lista blanca de preguntas y de respuestas. Lo demas se cae."""
    return {k: v for k, v in crudas.items()
            if k in PREGUNTAS and isinstance(v, str) and v in RESPUESTAS_VALIDAS}


def evaluar_escalado(r: dict[str, str]) -> tuple[bool, str | None]:
    motivos = [texto for clave, texto in REGLAS_ESCALADO.items() if r.get(clave) == "si"]
    return bool(motivos), ("; ".join(motivos) if motivos else None)


TELEFONO_OK = re.compile(r"^[0-9 ()+-]{7,20}$")


@app.post("/api/reportes")
def recibir(rep: Reporte, req: Request):
    """Un reporte ciudadano.

    Sin token: es un formulario abierto. Lo contiene el limite de tasa por IP de
    nginx, el cupo de fotos por evento, y que aca no se pueda escribir en ninguna
    tabla del lado profesional.
    """
    if rep.sitio:
        # Un robot lleno el campo trampa. Se responde 200 a proposito: con un
        # error ajustarian el robot hasta pasar.
        return {"ok": True, "folio": None}

    direccion = rep.direccion.strip()
    cod_dane = rep.cod_dane.strip()
    if not cod_dane or not direccion:
        raise HTTPException(422, "Falta el municipio o la dirección")
    if not rep.autoriza:
        raise HTTPException(422, "Falta la autorización de tratamiento de datos")
    if len(direccion) > 300 or len(rep.barrio) > 120 or len(rep.relato) > 2000:
        raise HTTPException(422, "Contenido demasiado largo")

    respuestas = limpiar_respuestas(rep.respuestas)
    if not respuestas:
        raise HTTPException(422, "No llegó ninguna respuesta")
    escalado, motivo = evaluar_escalado(respuestas)

    # El punto se guarda SOLO si la persona dijo estar frente al inmueble. Sin esa
    # afirmacion, la coordenada es donde esta el telefono —un albergue, la casa de
    # un familiar, el trabajo— y no donde esta la casa dañada. Guardarla igual
    # produciria racimos alrededor de los albergues que nadie sabria leer.
    lat = rep.lat if (rep.en_sitio and rep.lat is not None) else None
    lon = rep.lon if (rep.en_sitio and rep.lon is not None) else None

    telefono = rep.telefono.strip()
    if telefono and not TELEFONO_OK.match(telefono):
        raise HTTPException(422, "El teléfono no parece un número")
    reservado = {"telefono": telefono} if telefono else None

    imagenes = decodificar_fotos(rep.fotos)
    bytes_fotos = sum(len(x) for x in imagenes)

    ident = ulid()
    rutas = [str(FOTOS / f"{ident}_{i}.jpg") for i in range(len(imagenes))]

    try:
        with pool.connection(timeout=ESPERA_POOL) as con, con.cursor() as cur:
            ev = evento_activo(cur)
            if not ev:
                # 409 y no 422: no hay nada malo en lo que mando: el operativo se
                # cerro mientras llenaba el formulario.
                raise HTTPException(409, "No hay ningún operativo activo en este momento")
            evento_id, cupo_mb, usados = ev[0], ev[4], ev[5]

            # `formulario_abierto` se comprueba EN EL SERVIDOR y no solo
            # escondiendo el formulario en la pagina: esconder un control no es
            # una defensa, y acá lo que evita es una cola de reportes de un
            # municipio al que no va a ir nadie.
            cur.execute("""SELECT municipio FROM evento_municipio
                            WHERE evento = %s AND cod_dane = %s
                              AND formulario_abierto""", (evento_id, cod_dane))
            fila = cur.fetchone()
            if not fila:
                raise HTTPException(409, "En ese municipio no hay ningún operativo activo")
            # La grafia sale del catalogo del servidor y no de lo que mando el
            # cliente: es lo que permite agrupar por sector sin que "Pereira" y
            # "pereira " sean dos municipios distintos.
            municipio = fila[0]

            # El cupo se cobra antes de escribir. Si no cabe, el reporte entra
            # SIN fotos: el dato de que esa casa esta dañada vale mas que la
            # imagen, y perder el reporte entero por falta de disco seria absurdo.
            if bytes_fotos and usados + bytes_fotos > cupo_mb * 1024 * 1024:
                imagenes, rutas, bytes_fotos = [], [], 0

            # Folio del dia. Se reintenta ante choque: dos personas pueden enviar
            # en el mismo milisegundo y el numero sale de un conteo, no de una
            # secuencia. El id de verdad es el ULID; el folio es para la persona.
            folio = None
            for _ in range(5):
                cur.execute("""SELECT count(*) FROM reporte_ciudadano
                                WHERE recibido_en >= date_trunc('day', now())""")
                candidato = f"RC-{datetime.now().strftime('%Y%m%d')}-{cur.fetchone()[0] + 1:04d}"
                try:
                    with con.transaction():
                        cur.execute("""
                            INSERT INTO reporte_ciudadano
                              (id, folio, evento, cod_dane, municipio, direccion, barrio,
                               geom, precision_m, en_sitio, respuestas, relato, fotos,
                               reservado, escalado, motivo_escalado)
                            VALUES (%s,%s,%s,%s,%s,%s,%s,
                                    CASE WHEN %s::float8 IS NULL THEN NULL
                                         ELSE ST_SetSRID(ST_MakePoint(%s::float8,%s::float8),4326) END,
                                    %s,%s,%s,%s,%s,%s,%s,%s)""",
                            (ident, candidato, evento_id, cod_dane, municipio,
                             direccion[:300], rep.barrio.strip()[:120] or None,
                             lat, lon, lat,
                             rep.precision_m, bool(lat is not None),
                             Jsonb(respuestas), rep.relato.strip()[:2000] or None,
                             rutas, Jsonb(reservado) if reservado else None,
                             escalado, motivo))
                    folio = candidato
                    break
                except psycopg.errors.UniqueViolation:
                    continue
            if folio is None:
                raise HTTPException(503, "No se pudo registrar el reporte")

            if bytes_fotos:
                cur.execute("UPDATE evento SET fotos_bytes = fotos_bytes + %s WHERE id = %s",
                            (bytes_fotos, evento_id))
    except HTTPException:
        raise
    except (psycopg.Error, PoolTimeout) as e:
        # El detalle al log y no a la respuesta: el mensaje de psycopg puede
        # llevar fragmentos del dato de la persona.
        print(f"[reporte] {e.__class__.__name__}: {e}", flush=True)
        raise HTTPException(503, "No se pudo registrar el reporte")

    # Las imagenes se escriben DESPUES de que el reporte quedo grabado. Si el
    # disco falla acá, queda un reporte con una ruta que apunta a un archivo que
    # no existe —el panel ya tiene que tolerar eso— y NO se pierde el reporte,
    # que es lo unico irremplazable: la persona no va a volver a llenarlo.
    for ruta, crudo in zip(rutas, imagenes):
        try:
            pathlib.Path(ruta).write_bytes(crudo)
        except OSError as e:
            print(f"[reporte] no se pudo escribir {ruta}: {e}", flush=True)

    # Se devuelve el folio y NADA mas. Ni clasificacion, ni prioridad, ni si
    # quedo escalado: eso es informacion operativa, y devolverla convertiria el
    # formulario en un dictamen automatico sobre una vivienda. La app calcula, el
    # ingeniero decide.
    return {"ok": True, "folio": folio}


@app.get("/api/fuente")
def fuente():
    """AGPL §13: ofrecer la fuente a quien interactúa con el programa por red."""
    return {"fuente": FUENTE, "licencia": "AGPL-3.0-or-later"}


@app.get("/api/salud")
@app.get("/salud")
def salud():
    try:
        with pool.connection(timeout=ESPERA_POOL) as con, con.cursor() as cur:
            ev = evento_activo(cur)
            cur.execute("""SELECT count(*) FROM reporte_ciudadano
                            WHERE recibido_en >= date_trunc('day', now())""")
            hoy = cur.fetchone()[0]
    except (psycopg.Error, PoolTimeout):
        raise HTTPException(503, "Base de datos no disponible")
    return {"ok": True, "evento_activo": (ev[1] if ev else None),
            "reportes_hoy": hoy,
            "fotos_mb": (round(ev[5] / 1048576, 1) if ev else 0),
            "cupo_mb": (ev[4] if ev else 0)}
