# Brigada · Evaluación estructural en campo
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
# recibir su código fuente. El enlace al repositorio en la interfaz y en
# /api/fuente es parte del cumplimiento de esa obligación: no quitarlo.

"""
Receptor de evaluaciones de brigada.
  pip install fastapi uvicorn "psycopg[binary,pool]"
  uvicorn api_brigadas:app --host 127.0.0.1 --port 8004

Entorno:
  BRIGADA_TOKENS  tokens heredados, separados por coma. Siguen funcionando pero
                  no atribuyen: preferir el registro de brigadas (admin_brigadas.py)
  BRIGADA_DSN     postgresql://usuario:clave@host:puerto/base
  BRIGADA_FOTOS   directorio donde se dejan las imagenes (la BD guarda rutas)
  BRIGADA_FUENTE  URL del repositorio propio (AGPL §13); tiene un valor por defecto
  BRIGADA_ORIGENES  dominios autorizados a postear desde un navegador, separados
                    por coma. Vacio = solo mismo origen (el comportamiento por
                    defecto y el mas seguro).

El esquema vive en esquema.sql, que es la fuente de verdad. Aca solo se escribe.
"""

import base64, hashlib, json, os, pathlib, secrets, shutil, time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any

import psycopg
from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from psycopg.types.json import Jsonb
from psycopg_pool import ConnectionPool, PoolTimeout
from pydantic import BaseModel

import v2f   # catalogo y regla del formulario V2F: fuente unica de la clasificacion

TOKENS = set(filter(None, os.getenv("BRIGADA_TOKENS", "").split(",")))
DSN = os.getenv("BRIGADA_DSN", "")
# Un fork que despliegue esto debe apuntar BRIGADA_FUENTE a su propio repositorio.
FUENTE = os.getenv("BRIGADA_FUENTE", "https://github.com/abenito32/brigadaestructural")
# Origenes autorizados a sincronizar desde un navegador. La app y la API suelen
# vivir en el mismo dominio, y entonces esto no hace falta: solo se usa cuando una
# brigada sirve la app desde SU dominio y apunta a este servidor.
ORIGENES = [o.strip() for o in os.getenv("BRIGADA_ORIGENES", "").split(",") if o.strip()]
FOTOS = pathlib.Path(os.getenv("BRIGADA_FOTOS", "./fotos"))
FOTOS.mkdir(parents=True, exist_ok=True)

MAX_FOTOS = 4
MAX_BYTES_FOTO = 3_000_000
# Si la BD no responde, mejor un 503 rapido que un telefono colgado en campo:
# la app deja el registro pendiente y reintenta cuando haya senal.
ESPERA_POOL = 5
# Plazo para la segunda mirada de un rojo. Vencido no degrada nada: solo lo vuelve
# visible como atrasado en el panel.
# Plazo de la segunda revision. Distinto por nivel: un peligro de colapso no solo
# vacia el edificio, acordona la via y compromete a los vecinos. Vencido el plazo
# NADA se degrada: el nivel se mantiene y la fila solo sale marcada como atrasada.
HORAS_REVISION = int(os.getenv("BRIGADA_REVISION_HORAS", "24"))        # no habitable
HORAS_REVISION_COLAPSO = int(os.getenv("BRIGADA_REVISION_HORAS_COLAPSO", "8"))
# Lo escribe respaldo.sh. Sin MTA en el servidor, esta es la unica forma de
# enterarse de que el respaldo dejo de correr antes de necesitarlo.
ESTADO_RESPALDO = pathlib.Path(os.getenv("BRIGADA_RESPALDO_ESTADO",
                                         "/var/lib/brigadas/respaldo-estado.json"))

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

# Sin BRIGADA_ORIGENES no se monta nada: el servidor queda como estaba, aceptando
# solo peticiones del mismo origen. Se abre por lista blanca explicita y nunca con
# "*", porque bastaria con que un token se filtrara para que cualquier pagina
# pudiera escribir en la base.
# El panel de administración solo existe si hay clave configurada. Sin
# BRIGADA_ADMIN_HASH no se monta ninguna ruta /admin: no hay modo "sin clave".
try:
    import admin_web
    if admin_web.CLAVE_HASH:
        app.include_router(admin_web.router)
    else:
        # Sin clave no hay panel, pero sí una explicación: un 404 en JSON no
        # distingue "falta configurarlo" de "esto está roto".
        app.include_router(admin_web.router_sin_clave)
except ImportError:
    pass

# API de consulta (solo lectura, credenciales propias). Se monta siempre: sin
# consumidores registrados no hay token válido, así que no expone nada.
try:
    import api_consulta
    app.include_router(api_consulta.router)
except ImportError:
    pass

if ORIGENES:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=ORIGENES,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["Content-Type", "X-Brigada-Token"],
        max_age=600,
    )


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
    # 3 = telefono con la escala vieja (verde/amarillo/rojo); 4 = escala del V2F.
    # Sin el campo se asume 3: un telefono ya instalado no puede actualizarse
    # hasta tener señal, y tener señal es justo cuando intenta enviar.
    escala: int = 3
    # Formulario largo. `modo` dice con cual se lleno; `v2f` trae un bloque por
    # seccion del formulario y `reservado` los datos personales de terceros.
    modo: str = "triaje"
    tipo_inspeccion: int | None = None
    cod_catastral: str = ""
    localidad: str = ""
    departamento: str = ""
    cod_dane: str = ""
    origen_punto: str | None = None
    v2f: dict[str, Any] | None = None
    reservado: dict[str, Any] | None = None
    nivel_mayor_dano: int | None = None
    area_afectada_pct: int | None = None
    clasificacion: int
    clasificacion_auto: int | None = None
    parciales: dict[str, int] | None = None
    parcial_manda: str | None = None
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

    `eval_id` tiene que ser el ULID del servidor, NO el id que numero el telefono:
    ese se repite entre brigadas, y con el como nombre de archivo la segunda
    brigada pisaba la foto de la primera. Dos evaluaciones distintas terminaban
    apuntando al mismo archivo, y el panel mostraria el edificio equivocado.

    Con el ULID el nombre es unico, y sigue siendo determinista: un reintento
    reescribe su propio archivo en vez de acumular basura.
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
  id, id_local, ts, matricula, documento, profesion, firma_tipo, inspector, brigada,
  geom, precision_m, direccion, municipio, barrio,
  sistema, uso, pisos, ocupantes, danos, banderas,
  clasificacion, clasificacion_auto, motivo_auto, justificacion,
  observaciones, fotos, brigada_token, matricula_verificada,
  escala, parciales, parcial_manda,
  modo, tipo_inspeccion, cod_catastral, catastral_origen, localidad,
  departamento, cod_dane, origen_punto,
  nivel_mayor_dano, area_afectada_pct, bloques_faltantes, reservado,
  v2f_estructura, v2f_estado, v2f_geotecnicos, v2f_no_estructurales,
  v2f_no_estructurales_pct,
  v2f_estructurales, v2f_entorno, v2f_preexistentes, v2f_recomendaciones,
  v2f_ocupacion, v2f_comision, dano_global,
  revision_estado, revision_vence
) VALUES (
  %(id)s, %(id_local)s, %(ts)s, %(matricula)s, %(documento)s, %(profesion)s,
  %(firma_tipo)s, %(inspector)s, %(brigada)s,
  -- Los ::float8 son obligatorios: sin ellos Postgres no infiere el tipo cuando
  -- la evaluacion viene sin GPS y falla con AmbiguousParameter. Guardar sin
  -- coordenadas es un caso normal en campo, no un error.
  CASE WHEN %(lon)s::float8 IS NULL OR %(lat)s::float8 IS NULL THEN NULL
       ELSE ST_SetSRID(ST_MakePoint(%(lon)s::float8, %(lat)s::float8), 4326) END,
  %(precision_m)s, %(direccion)s, %(municipio)s, %(barrio)s,
  %(sistema)s, %(uso)s, %(pisos)s, %(ocupantes)s, %(danos)s, %(banderas)s,
  %(clasificacion)s, %(clasificacion_auto)s, %(motivo_auto)s, %(justificacion)s,
  %(observaciones)s, %(fotos)s, %(brigada_token)s,
  -- Se resuelve en la misma sentencia para no gastar otra ida a la base.
  EXISTS (SELECT 1 FROM inspector
          WHERE matricula = %(matricula)s AND vigente),
  %(escala)s, %(parciales)s, %(parcial_manda)s,
  %(modo)s, %(tipo_inspeccion)s, %(cod_catastral)s, %(catastral_origen)s, %(localidad)s,
  %(departamento)s, %(cod_dane)s, %(origen_punto)s,
  %(nivel_mayor_dano)s, %(area_afectada_pct)s, %(bloques_faltantes)s, %(reservado)s,
  %(v2f_estructura)s, %(v2f_estado)s, %(v2f_geotecnicos)s, %(v2f_no_estructurales)s,
  %(v2f_no_estructurales_pct)s,
  %(v2f_estructurales)s, %(v2f_entorno)s, %(v2f_preexistentes)s, %(v2f_recomendaciones)s,
  %(v2f_ocupacion)s, %(v2f_comision)s, %(dano_global)s,
  -- Entran en cola los dos niveles que ordenan desalojo. Un verde no necesita
  -- que dos personas confirmen que la casa sigue en pie.
  CASE WHEN %(clasificacion)s >= 3 THEN 'pendiente' END,
  CASE WHEN %(clasificacion)s = 4
       THEN now() + make_interval(hours => %(horas_revision_colapso)s)
       WHEN %(clasificacion)s = 3
       THEN now() + make_interval(hours => %(horas_revision)s) END
)
-- La idempotencia es por brigada: dos brigadas pueden mandar el mismo id_local
-- el mismo dia y son evaluaciones distintas, no un reintento.
ON CONFLICT (origen, id_local) DO NOTHING
RETURNING id, matricula_verificada
"""


# Crockford base32: sin I, L, O ni U, para que nadie confunda un caracter al
# transcribir un id a mano en un acta.
_B32 = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def ulid() -> str:
    """Identificador canonico: 48 bits de milisegundos + 80 de azar.

    Ordenable por tiempo (util para listar cronologicamente sin tocar `ts`) y con
    colision practicamente imposible aunque lo generen varias brigadas a la vez.
    Se implementa aca en vez de traer una dependencia: son doce lineas.
    """
    valor = (int(time.time() * 1000) << 80) | secrets.randbits(80)
    return "".join(_B32[(valor >> despl) & 31] for despl in range(125, -1, -5))


def sha(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def autenticar(token: str) -> tuple[str | None, bool]:
    """Devuelve (nombre de la brigada, si exige matrícula).

    El nombre es None si el token es heredado del entorno.

    Levanta 401 si el token no sirve. Los tokens de BRIGADA_TOKENS se aceptan
    igual que siempre para no dejar afuera a un teléfono ya configurado, pero no
    atribuyen: el registro es el camino nuevo, no un requisito retroactivo.
    """
    if not token:
        raise HTTPException(401, "Falta el token de brigada")
    try:
        with pool.connection(timeout=ESPERA_POOL) as con, con.cursor() as cur:
            cur.execute("SELECT nombre, exige_matricula FROM brigada "
                        "WHERE token_hash=%s AND activa", (sha(token),))
            fila = cur.fetchone()
    except (psycopg.Error, PoolTimeout):
        raise HTTPException(503, "No se pudo validar el token: base de datos no disponible")
    if fila:
        return fila[0], fila[1]
    if token in TOKENS:
        # Token heredado del entorno: no tiene brigada y por tanto no tiene
        # politica propia. Se le exige matricula, que es el criterio por defecto.
        return None, True
    raise HTTPException(401, "Token de brigada inválido")


@app.get("/api/brigada")
def brigada_de(x_brigada_token: str = Header(default="")):
    """Que sabe el servidor de esta credencial. Lo usa el boton «Probar conexion»
    para que el telefono sepa si su brigada admite firmar sin matricula: si no lo
    supiera, el bloqueo local seria el de por defecto y quien no tiene matricula
    no podria ni guardar, aunque el servidor fuera a aceptarlo."""
    nombre, exige = autenticar(x_brigada_token)
    return {"brigada": nombre, "exige_matricula": exige}


@app.post("/api/evaluaciones")
def recibir(ev: Evaluacion, x_brigada_token: str = Header(default="")):
    brigada_auth, exige_matricula = autenticar(x_brigada_token)

    matricula = str(ev.inspector.get("matricula", "")).strip()
    documento = str(ev.inspector.get("documento", "")).strip()
    profesion = str(ev.inspector.get("profesion", "")).strip()
    # Sin matricula solo se acepta si la brigada lo tiene habilitado, y entonces
    # se exige documento Y profesion: quien firma queda identificado igual, con
    # otro papel. Una evaluacion anonima no entra por ningun camino.
    if not matricula:
        if exige_matricula:
            raise HTTPException(422, "Falta la matrícula profesional de quien firma. "
                                     "Esta brigada exige matrícula.")
        if not documento or not profesion:
            raise HTTPException(422, "Sin matrícula hacen falta el número de documento "
                                     "y la profesión de quien firma")
    firma_tipo = "matricula" if matricula else "documento"
    escala = 4 if ev.escala == 4 else 3
    if ev.clasificacion not in range(1, escala + 1):
        raise HTTPException(422, "Clasificación fuera de rango")
    # Cambiar el semaforo calculado exige motivo escrito: es el registro de
    # responsabilidad profesional, no un campo opcional.
    if (ev.clasificacion_auto is not None
            and ev.clasificacion != ev.clasificacion_auto
            and not ev.justificacion.strip()):
        raise HTTPException(422, "Modificar la clasificación calculada exige justificación")

    # El automatico se recalcula ACA y se guarda el del servidor, no el del
    # telefono. La regla vive en dos sitios por fuerza —una corre sin señal en el
    # navegador y otra en Python— y esta es la forma de que una diferencia entre
    # las dos se vea en el panel en vez de quedar escondida en un telefono.
    bloques = ev.v2f or {}
    raros = v2f.codigos_desconocidos(bloques)
    if raros:
        # No se rechaza. Un codigo que este catalogo no conoce significa que el
        # telefono y el servidor tienen versiones distintas del formulario, y ese
        # es justo el caso en el que rechazar deja una jornada entera atrapada.
        # Se graba tal cual, se avisa acá, y el panel lo muestra sin traducir.
        print(f"[v2f] códigos desconocidos en {ev.id}: {raros}", flush=True)
    calculo = v2f.clasificar(ev.danos, ev.banderas, bloques)
    auto = calculo["v"] if escala == 4 else min(calculo["v"], 3)
    parciales = calculo["parciales"]
    manda = calculo["manda"]
    if ev.clasificacion_auto is not None and ev.clasificacion_auto != auto:
        # No se rechaza: la evaluacion es valida y lo firmado es lo que vale. Pero
        # que las dos implementaciones de la regla no coincidan es un defecto, y
        # tiene que doler en el log en vez de pasar inadvertido.
        print(f"[regla] discrepancia en {ev.id}: telefono={ev.clasificacion_auto} "
              f"servidor={auto} escala={escala} danos={ev.danos} banderas={ev.banderas}",
              flush=True)

    canonico = ulid()
    rutas = guardar_fotos(canonico, ev.fotos)

    datos = {
        "id": canonico,        # canonico, del servidor
        "id_local": ev.id,     # lo que numero el telefono; solo idempotencia
        "ts": ev.ts,
        "matricula": matricula or None,
        "documento": documento or None,
        "profesion": profesion or None,
        "firma_tipo": firma_tipo,
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
        "escala": escala,
        "modo": "completo" if ev.modo == "completo" else "triaje",
        "tipo_inspeccion": ev.tipo_inspeccion,
        "cod_catastral": (ev.cod_catastral or "").strip() or None,
        # Si vino del teléfono, la puso quien estaba parado frente al predio.
        "catastral_origen": "campo" if (ev.cod_catastral or "").strip() else None,
        "localidad": (ev.localidad or "").strip() or None,
        "departamento": (ev.departamento or "").strip() or None,
        "cod_dane": (ev.cod_dane or "").strip() or None,
        "origen_punto": ev.origen_punto if ev.origen_punto in ("gps", "mapa") else None,
        "nivel_mayor_dano": entero(ev.nivel_mayor_dano),
        "area_afectada_pct": entero(ev.area_afectada_pct),
        "bloques_faltantes": calculo.get("faltan") or None,
        # Tabla 10 de la guia: la escala de dano global sale del % de area
        # afectada, no de las parciales. Se calcula aca para que el V2F
        # exportado lleve esa casilla llena.
        "dano_global": v2f.dano_global(entero(ev.area_afectada_pct)),
        "reservado": Jsonb(ev.reservado) if ev.reservado else None,
        "v2f_estructura": Jsonb(bloques["estructura"]) if bloques.get("estructura") else None,
        "v2f_estado": Jsonb(bloques["estado"]) if bloques.get("estado") else None,
        "v2f_geotecnicos": Jsonb(bloques["geotecnicos"]) if bloques.get("geotecnicos") else None,
        "v2f_no_estructurales": Jsonb(bloques["no_estructurales"]) if bloques.get("no_estructurales") else None,
        "v2f_no_estructurales_pct": Jsonb(bloques["no_estructurales_pct"]) if bloques.get("no_estructurales_pct") else None,
        "v2f_estructurales": Jsonb(bloques["estructurales"]) if bloques.get("estructurales") else None,
        "v2f_entorno": Jsonb(bloques["entorno"]) if bloques.get("entorno") else None,
        "v2f_preexistentes": Jsonb(bloques["preexistentes"]) if bloques.get("preexistentes") else None,
        "v2f_recomendaciones": Jsonb(bloques["recomendaciones"]) if bloques.get("recomendaciones") else None,
        "v2f_ocupacion": Jsonb(bloques["ocupacion"]) if bloques.get("ocupacion") else None,
        "v2f_comision": Jsonb(bloques["comision"]) if bloques.get("comision") else None,
        "clasificacion": ev.clasificacion,
        "clasificacion_auto": auto,
        "parciales": Jsonb(parciales),
        "parcial_manda": manda,
        # El motivo del servidor, para que acompañe al valor del servidor.
        "motivo_auto": calculo["por"],
        "justificacion": ev.justificacion,
        "observaciones": ev.observaciones,
        "fotos": Jsonb(rutas),
        "brigada_token": brigada_auth,
        "horas_revision": HORAS_REVISION,
        "horas_revision_colapso": HORAS_REVISION_COLAPSO,
    }

    try:
        with pool.connection(timeout=ESPERA_POOL) as con, con.cursor() as cur:
            cur.execute(INSERT, datos)
            fila = cur.fetchone()
            previa = None
            verificada = fila[1] if fila else None
            # Si hubo conflicto no hay RETURNING: se busca el id que ya existe,
            # para que la respuesta sea la misma en el primer envio y en el reintento.
            if fila is None:
                cur.execute("""SELECT id, matricula_verificada FROM evaluacion_brigada
                                WHERE origen = coalesce(%s, '(sin atribuir)')
                                  AND id_local = %s""",
                            (brigada_auth, ev.id))
                previa = cur.fetchone()
                if previa:
                    verificada = previa[1]
    except (psycopg.Error, PoolTimeout) as e:
        # El detalle va al log del servidor, no a la respuesta: el mensaje de
        # psycopg puede llevar fragmentos del dato. Sin esta linea, un 503
        # obligaba a reproducir el fallo a ciegas.
        print(f"[grabar] {e.__class__.__name__} en {ev.id}: {e}", flush=True)
        # 503 y NO 200: la app deja el registro como pendiente y reintenta.
        # Devolver ok aca perderia la evaluacion sin que nadie se entere.
        raise HTTPException(503, f"No se pudo grabar la evaluación: {e.__class__.__name__}")

    # fila None = ya estaba (ON CONFLICT DO NOTHING). Reintentar no duplica.
    # matricula_verificada viaja en la respuesta a proposito: si una brigada
    # sincroniza y ve que todo entra sin verificar, sabe que le falta cargar
    # su gente en el registro antes de que el consolidado sea defendible.
    # `id` es el que mando el telefono, para que se reconozca su propio registro;
    # `id_servidor` es el canonico, el que identifica la evaluacion de verdad.
    return {"ok": True, "id": ev.id,
            "id_servidor": (fila[0] if fila else (previa[0] if previa else None)),
            "duplicado": fila is None,
            "brigada": brigada_auth, "matricula_verificada": verificada,
            "recibido_en": datetime.now(timezone.utc).isoformat()}


class Contacto(BaseModel):
    nombre: str = ""
    entidad: str = ""
    correo: str = ""
    telefono: str = ""
    mensaje: str = ""
    autoriza: bool = False
    sitio: str = ""     # trampa para robots: si viene llena, no fue una persona


@app.post("/api/contacto")
def contacto(c: Contacto):
    """Solicitudes desde la pagina publica. Sin token: es un formulario abierto.

    El limite de tasa de nginx lo cubre (cae en el cubo sin token). Aca solo se
    valida lo minimo y se corta la basura evidente.
    """
    if c.sitio:
        # Un robot lleno el campo oculto. Se responde 200 a proposito: si
        # devolvieramos error, ajustarian el robot hasta pasar.
        return {"ok": True}
    nombre, entidad, correo = c.nombre.strip(), c.entidad.strip(), c.correo.strip()
    if not (nombre and entidad and correo) or "@" not in correo[1:]:
        raise HTTPException(422, "Faltan nombre, entidad o correo válido")
    if not c.autoriza:
        raise HTTPException(422, "Falta la autorización de tratamiento de datos")
    if max(len(nombre), len(entidad), len(correo)) > 200 or len(c.mensaje) > 4000:
        raise HTTPException(422, "Contenido demasiado largo")
    try:
        with pool.connection(timeout=ESPERA_POOL) as con, con.cursor() as cur:
            cur.execute("""INSERT INTO contacto (nombre, entidad, correo, telefono, mensaje)
                           VALUES (%s,%s,%s,%s,%s)""",
                        (nombre[:200], entidad[:200], correo[:200],
                         c.telefono.strip()[:60] or None, c.mensaje.strip()[:4000] or None))
    except (psycopg.Error, PoolTimeout):
        raise HTTPException(503, "No se pudo registrar la solicitud")
    return {"ok": True}


@app.get("/api/fuente")
def fuente():
    """AGPL §13: ofrecer la fuente a quien interactúa con el programa por red.

    Si usted despliega una versión modificada, apunte FUENTE a SU repositorio:
    la obligación es entregar el código que efectivamente está corriendo.
    """
    return RedirectResponse(FUENTE, status_code=302)


@app.get("/api/salud")
@app.get("/salud")
def salud():
    """Incluye la BD a proposito: un receptor que no puede grabar no esta sano.

    Se expone tambien bajo /api/ porque nginx solo enruta ese prefijo hacia aca:
    es la ruta que usa el boton "Probar conexion" de la app.
    """
    try:
        with pool.connection(timeout=ESPERA_POOL) as con, con.cursor() as cur:
            cur.execute("""SELECT (SELECT count(*) FROM evaluacion_brigada),
                                  (SELECT count(*) FROM evaluacion_brigada
                                     WHERE NOT matricula_verificada),
                                  (SELECT count(*) FROM brigada WHERE activa),
                                  (SELECT count(*) FROM inspector WHERE vigente),
                                  (SELECT count(*) FROM evaluacion_brigada
                                     WHERE revision_estado = 'pendiente'),
                                  (SELECT count(*) FROM evaluacion_brigada
                                     WHERE revision_estado = 'pendiente'
                                       AND revision_vence < now())""")
            (total, sin_verificar, brigadas, inspectores,
             rojos_pendientes, rojos_vencidos) = cur.fetchone()
    except (psycopg.Error, PoolTimeout, AttributeError) as e:
        raise HTTPException(503, f"Base de datos no disponible: {e.__class__.__name__}")
    return {"ok": True, "evaluaciones": total, "sin_verificar": sin_verificar,
            "brigadas": brigadas, "inspectores": inspectores,
            "rojos_sin_revisar": rojos_pendientes, "rojos_vencidos": rojos_vencidos,
            "respaldo": estado_respaldo(), "disco": estado_disco()}


def estado_disco() -> dict:
    """El limite de tasa acota la inundacion, pero un token valido todavia puede
    llenar el disco despacio. La mitigacion es revocarlo; para eso hay que verlo."""
    try:
        uso = shutil.disk_usage(FOTOS)
    except OSError:
        return {"ok": False}
    libre_gb = round(uso.free / 1_000_000_000, 1)
    return {"ok": libre_gb > 2, "libre_gb": libre_gb,
            "usado_pct": round(100 * (uso.total - uso.free) / uso.total)}


def estado_respaldo() -> dict:
    """Lee el archivo que deja respaldo.sh. Ausente = nunca corrio."""
    try:
        d = json.loads(ESTADO_RESPALDO.read_text())
    except (OSError, ValueError):
        return {"ok": False, "mensaje": "nunca corrió o no se pudo leer el estado"}
    try:
        edad = time.time() - time.mktime(time.strptime(d["ts"], "%Y-%m-%dT%H:%M:%SZ"))
        d["horas"] = round(edad / 3600, 1)
        # Corre a diario: pasadas 36 horas dejo de considerarlo reciente.
        d["reciente"] = edad < 36 * 3600
    except (KeyError, ValueError):
        d["reciente"] = False
    return d
