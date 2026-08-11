"""
Receptor de evaluaciones de brigada.
  pip install fastapi uvicorn "psycopg[binary,pool]"
  uvicorn api_brigadas:app --host 127.0.0.1 --port 8004

Entorno:
  BRIGADA_TOKENS  tokens separados por coma, uno por brigada
  BRIGADA_DSN     postgresql://usuario:clave@host:puerto/base
  BRIGADA_FOTOS   directorio donde se dejan las imagenes (la BD guarda rutas)

El esquema vive en esquema.sql, que es la fuente de verdad. Aca solo se escribe.
"""

import base64, os, pathlib
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any

import psycopg
from fastapi import FastAPI, Header, HTTPException
from psycopg.types.json import Jsonb
from psycopg_pool import ConnectionPool, PoolTimeout
from pydantic import BaseModel

TOKENS = set(filter(None, os.getenv("BRIGADA_TOKENS", "").split(",")))
DSN = os.getenv("BRIGADA_DSN", "")
FOTOS = pathlib.Path(os.getenv("BRIGADA_FOTOS", "./fotos"))
FOTOS.mkdir(parents=True, exist_ok=True)

MAX_FOTOS = 4
MAX_BYTES_FOTO = 3_000_000
# Si la BD no responde, mejor un 503 rapido que un telefono colgado en campo:
# la app deja el registro pendiente y reintenta cuando haya senal.
ESPERA_POOL = 5

pool: ConnectionPool | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global pool
    if not DSN:
        raise RuntimeError("Falta BRIGADA_DSN: el receptor no arranca sin base de datos.")
    # check=ConnectionPool.check_connection reconecta solo si la BD se reinicia
    # debajo del servicio; en campo nadie va a estar mirando el proceso.
    pool = ConnectionPool(DSN, min_size=1, max_size=8, open=True,
                          timeout=ESPERA_POOL, kwargs={"connect_timeout": 5},
                          check=ConnectionPool.check_connection)
    try:
        pool.wait(timeout=30)
    except PoolTimeout:
        # Arranca igual: si la BD tarda en subir tras un reboot, el servicio
        # responde 503 y se recupera solo cuando la BD vuelve.
        pass
    yield
    pool.close()


app = FastAPI(title="Brigadas · receptor de evaluaciones", lifespan=lifespan)


class Evaluacion(BaseModel):
    id: str
    ts: str
    inspector: dict[str, Any]
    lat: float | None = None
    lon: float | None = None
    precision_m: int | None = None
    direccion: str = ""
    municipio: str = ""
    barrio: str = ""
    sistema: str = ""
    uso: str = ""
    pisos: str | int | None = None
    ocupantes: str | int | None = None
    danos: dict[str, int]
    banderas: dict[str, bool]
    clasificacion: int
    clasificacion_auto: int | None = None
    motivo_auto: str = ""
    justificacion: str = ""
    observaciones: str = ""
    fotos: list[str] = []


def entero(v: Any) -> int | None:
    """El formulario manda los numericos como string vacio cuando no se llenaron."""
    if v is None or v == "":
        return None
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def guardar_fotos(eval_id: str, fotos: list[str]) -> list[str]:
    """Saca el base64 del payload y lo deja en disco. La BD guarda rutas.

    Los nombres son deterministas (<id>_<n>.jpg), asi que un reintento
    sobrescribe en vez de acumular basura.
    """
    rutas = []
    for i, dataurl in enumerate(fotos[:MAX_FOTOS]):
        if "," not in dataurl:
            continue
        try:
            crudo = base64.b64decode(dataurl.split(",", 1)[1])
        except (ValueError, TypeError):
            continue
        if len(crudo) > MAX_BYTES_FOTO:
            continue
        destino = FOTOS / f"{eval_id}_{i}.jpg"
        destino.write_bytes(crudo)
        rutas.append(str(destino))
    return rutas


INSERT = """
INSERT INTO evaluacion_brigada (
  id, ts, matricula, inspector, brigada,
  geom, precision_m, direccion, municipio, barrio,
  sistema, uso, pisos, ocupantes, danos, banderas,
  clasificacion, clasificacion_auto, motivo_auto, justificacion,
  observaciones, fotos
) VALUES (
  %(id)s, %(ts)s, %(matricula)s, %(inspector)s, %(brigada)s,
  -- Los ::float8 son obligatorios: sin ellos Postgres no infiere el tipo cuando
  -- la evaluacion viene sin GPS y falla con AmbiguousParameter. Guardar sin
  -- coordenadas es un caso normal en campo, no un error.
  CASE WHEN %(lon)s::float8 IS NULL OR %(lat)s::float8 IS NULL THEN NULL
       ELSE ST_SetSRID(ST_MakePoint(%(lon)s::float8, %(lat)s::float8), 4326) END,
  %(precision_m)s, %(direccion)s, %(municipio)s, %(barrio)s,
  %(sistema)s, %(uso)s, %(pisos)s, %(ocupantes)s, %(danos)s, %(banderas)s,
  %(clasificacion)s, %(clasificacion_auto)s, %(motivo_auto)s, %(justificacion)s,
  %(observaciones)s, %(fotos)s
)
ON CONFLICT (id) DO NOTHING
RETURNING id
"""


@app.post("/api/evaluaciones")
def recibir(ev: Evaluacion, x_brigada_token: str = Header(default="")):
    if TOKENS and x_brigada_token not in TOKENS:
        raise HTTPException(401, "Token de brigada inválido")

    matricula = str(ev.inspector.get("matricula", "")).strip()
    if not matricula:
        raise HTTPException(422, "Falta la matrícula profesional de quien firma")
    if ev.clasificacion not in (1, 2, 3):
        raise HTTPException(422, "Clasificación fuera de rango")
    # Cambiar el semaforo calculado exige motivo escrito: es el registro de
    # responsabilidad profesional, no un campo opcional.
    if (ev.clasificacion_auto is not None
            and ev.clasificacion != ev.clasificacion_auto
            and not ev.justificacion.strip()):
        raise HTTPException(422, "Modificar la clasificación calculada exige justificación")

    rutas = guardar_fotos(ev.id, ev.fotos)

    datos = {
        "id": ev.id,
        "ts": ev.ts,
        "matricula": matricula,
        "inspector": str(ev.inspector.get("nombre", "")).strip(),
        "brigada": str(ev.inspector.get("brigada", "")).strip(),
        "lat": ev.lat,
        "lon": ev.lon,
        "precision_m": entero(ev.precision_m),
        "direccion": ev.direccion,
        "municipio": ev.municipio,
        "barrio": ev.barrio,
        "sistema": ev.sistema,
        "uso": ev.uso,
        "pisos": entero(ev.pisos),
        "ocupantes": entero(ev.ocupantes),
        "danos": Jsonb(ev.danos),
        "banderas": Jsonb(ev.banderas),
        "clasificacion": ev.clasificacion,
        "clasificacion_auto": ev.clasificacion_auto,
        "motivo_auto": ev.motivo_auto,
        "justificacion": ev.justificacion,
        "observaciones": ev.observaciones,
        "fotos": Jsonb(rutas),
    }

    try:
        with pool.connection(timeout=ESPERA_POOL) as con, con.cursor() as cur:
            cur.execute(INSERT, datos)
            fila = cur.fetchone()
    except (psycopg.Error, PoolTimeout) as e:
        # 503 y NO 200: la app deja el registro como pendiente y reintenta.
        # Devolver ok aca perderia la evaluacion sin que nadie se entere.
        raise HTTPException(503, f"No se pudo grabar la evaluación: {e.__class__.__name__}")

    # fila None = ya estaba (ON CONFLICT DO NOTHING). Reintentar no duplica.
    return {"ok": True, "id": ev.id, "duplicado": fila is None,
            "recibido_en": datetime.now(timezone.utc).isoformat()}


@app.get("/salud")
def salud():
    """Incluye la BD a proposito: un receptor que no puede grabar no esta sano."""
    try:
        with pool.connection(timeout=ESPERA_POOL) as con, con.cursor() as cur:
            cur.execute("SELECT count(*) FROM evaluacion_brigada")
            total = cur.fetchone()[0]
    except (psycopg.Error, PoolTimeout, AttributeError) as e:
        raise HTTPException(503, f"Base de datos no disponible: {e.__class__.__name__}")
    return {"ok": True, "evaluaciones": total}
