# Brigada · Evaluación estructural en campo
# Copyright (C) 2026 Rollout Comercio e Servicios Limitada / Andrés Benito Revollo Vélez
#
# Software libre bajo la Licencia Pública General Affero de GNU, versión 3 o
# posterior. Vea <https://www.gnu.org/licenses/>.
"""
API de consulta: que los reportes lleguen a los sistemas que ya usa la entidad.

Es de SOLO LECTURA y con credenciales propias, separadas de las de brigada. Una
brigada escribe evaluaciones desde un teléfono; un consumidor lee desde el sistema
de una alcaldía. Si fueran la misma credencial, filtrar el token de un geoportal
permitiría escribir evaluaciones falsas.

Dos niveles de acceso, y la diferencia es jurídica antes que técnica:

  consolidado  Agregados por municipio y barrio, con umbral de k-anonimato. No
               lleva dato personal, así que sirve para un tablero público.
  detalle      Direcciones y coordenadas de predios. Es dato personal (Ley 1581
               de 2012): solo para la entidad dueña de esos datos y con finalidad
               declarada. Se concede por excepción, no por defecto.

El alcance también limita por municipio: una alcaldía consulta lo suyo.

  GET /api/v1/consolidado           agregado por sector
  GET /api/v1/consolidado.geojson   lo mismo como capa de puntos
  GET /api/v1/evaluaciones          detalle paginado        (alcance: detalle)
  GET /api/v1/evaluaciones.geojson  detalle como capa       (alcance: detalle)
"""
import json
from datetime import date

from fastapi import APIRouter, Header, HTTPException, Query
from fastapi.responses import JSONResponse

router = APIRouter(prefix="/api/v1")

# El mismo umbral que la vista consolidado_publico. Se aplica DESPUES de los
# filtros: si alguien acota por fechas hasta dejar dos registros en un barrio,
# ese barrio tiene que desaparecer igual.
K_ANONIMATO = 5
MAX_PAGINA = 500


def _pool():
    import api_brigadas
    return api_brigadas.pool, api_brigadas.ESPERA_POOL


def consultar(sql: str, args=()):
    import psycopg
    from psycopg_pool import PoolTimeout
    pool, espera = _pool()
    try:
        with pool.connection(timeout=espera) as con, con.cursor() as cur:
            cur.execute(sql, args)
            return cur.fetchall() if cur.description else []
    except (psycopg.Error, PoolTimeout):
        raise HTTPException(503, "Base de datos no disponible")


def autenticar(token: str):
    """Devuelve (nombre, alcance, municipios). Levanta 401 si el token no sirve."""
    import api_brigadas
    if not token:
        raise HTTPException(401, "Falta la cabecera X-API-Token")
    filas = consultar(
        "SELECT nombre, alcance, municipios FROM consumidor "
        "WHERE token_hash = %s AND activo", (api_brigadas.sha(token),))
    if not filas:
        raise HTTPException(401, "Token de consulta inválido o revocado")
    # Registrar el uso: sin esto no hay forma de saber qué integración sigue viva
    # ni de detectar un token filtrado que alguien está usando de más.
    consultar("UPDATE consumidor SET ultimo_uso = now(), consultas = consultas + 1 "
              "WHERE nombre = %s", (filas[0][0],))
    return filas[0]


def filtros(municipios_permitidos, municipio, barrio, desde, hasta, clasificacion):
    """Construye el WHERE común. El alcance por municipio no es negociable desde
    la petición: si la credencial está limitada, se intersecta siempre."""
    donde, args = ["1=1"], []
    if municipios_permitidos:
        if municipio:
            if municipio not in municipios_permitidos:
                raise HTTPException(403, f"Su credencial no cubre el municipio «{municipio}»")
            donde.append("municipio = %s"); args.append(municipio)
        else:
            donde.append("municipio = ANY(%s)"); args.append(list(municipios_permitidos))
    elif municipio:
        donde.append("municipio = %s"); args.append(municipio)
    if barrio:
        donde.append("barrio = %s"); args.append(barrio)
    if desde:
        donde.append("ts >= %s"); args.append(desde)
    if hasta:
        donde.append("ts < (%s::date + 1)"); args.append(hasta)
    if clasificacion:
        donde.append("clasificacion_efectiva = %s"); args.append(clasificacion)
    return " AND ".join(donde), args


def sin_cache(contenido):
    """Los datos cambian con cada sincronización; no se cachean en intermediarios."""
    return JSONResponse(contenido, headers={"Cache-Control": "no-store"})


# --------------------------------------------------------------- consolidado
SELECT_CONSOLIDADO = """
SELECT municipio, barrio, count(*) AS evaluadas,
       -- Efectiva: si un segundo inspector revoco un rojo, el consolidado tiene
       -- que reflejar la realidad revisada, no la primera firma.
       count(*) FILTER (WHERE clasificacion_efectiva = 3) AS rojas,
       count(*) FILTER (WHERE clasificacion_efectiva = 2) AS amarillas,
       count(*) FILTER (WHERE clasificacion_efectiva = 1) AS verdes,
       count(*) FILTER (WHERE revision_estado = 'pendiente') AS rojas_sin_revisar,
       max(recibido_en) AS ultima,
       ST_X(ST_Centroid(ST_Collect(geom))) AS lon,
       ST_Y(ST_Centroid(ST_Collect(geom))) AS lat
  FROM evaluacion_brigada
 WHERE {donde}
 GROUP BY municipio, barrio
HAVING count(*) >= %s
 ORDER BY count(*) DESC
"""


def _consolidado(cred, municipio, barrio, desde, hasta):
    donde, args = filtros(cred[2], municipio, barrio, desde, hasta, None)
    filas = consultar(SELECT_CONSOLIDADO.format(donde=donde), tuple(args) + (K_ANONIMATO,))
    return [{"municipio": f[0], "barrio": f[1], "evaluadas": f[2], "rojas": f[3],
             "amarillas": f[4], "verdes": f[5], "rojas_sin_revisar": f[6],
             "ultima_actualizacion": f[7].isoformat() if f[7] else None,
             "lon": f[8], "lat": f[9]} for f in filas]


@router.get("/consolidado")
def consolidado(x_api_token: str = Header(default=""),
                municipio: str = Query("", max_length=120),
                barrio: str = Query("", max_length=120),
                desde: date | None = None, hasta: date | None = None):
    cred = autenticar(x_api_token)
    datos = _consolidado(cred, municipio, barrio, desde, hasta)
    return sin_cache({
        "sectores": [{k: v for k, v in d.items() if k not in ("lon", "lat")} for d in datos],
        "umbral_anonimato": K_ANONIMATO,
        "nota": ("Sectores con menos de "
                 f"{K_ANONIMATO} evaluaciones se omiten: con dos o tres registros, "
                 "el barrio identifica el predio (Ley 1581 de 2012)."),
    })


@router.get("/consolidado.geojson")
def consolidado_geojson(x_api_token: str = Header(default=""),
                        municipio: str = Query("", max_length=120),
                        barrio: str = Query("", max_length=120),
                        desde: date | None = None, hasta: date | None = None):
    cred = autenticar(x_api_token)
    rasgos = []
    for d in _consolidado(cred, municipio, barrio, desde, hasta):
        if d["lon"] is None:
            continue     # el sector no tiene ninguna evaluación con coordenada
        props = {k: v for k, v in d.items() if k not in ("lon", "lat")}
        rasgos.append({"type": "Feature",
                       "geometry": {"type": "Point", "coordinates": [d["lon"], d["lat"]]},
                       "properties": props})
    return sin_cache({"type": "FeatureCollection", "features": rasgos})


# ----------------------------------------------------------------- detalle
# Los nombres van declarados, no deducidos del SQL: intentar leerlos partiendo la
# cadena por comas se rompe con la coma de dentro de coalesce(...), y el resultado
# es un dict con las claves corridas, que es peor que un error.
CAMPOS_DETALLE = [
    ("id", "id"), ("id_local", "id_local"), ("ts", "ts"),
    ("recibido_en", "recibido_en"), ("matricula", "matricula"),
    ("inspector", "inspector"), ("brigada", "brigada"),
    ("brigada_token", "brigada_token"),
    ("matricula_verificada", "matricula_verificada"),
    ("direccion", "direccion"), ("municipio", "municipio"), ("barrio", "barrio"),
    ("sistema", "sistema"), ("uso", "uso"), ("pisos", "pisos"),
    ("ocupantes", "ocupantes"), ("danos", "danos"), ("banderas", "banderas"),
    ("clasificacion", "clasificacion"), ("clasificacion_auto", "clasificacion_auto"),
    ("motivo_auto", "motivo_auto"), ("justificacion", "justificacion"),
    ("clasificacion_efectiva", "clasificacion_efectiva"),
    ("revision_estado", "revision_estado"), ("revision_matricula", "revision_matricula"),
    ("revision_clasificacion", "revision_clasificacion"),
    ("revision_motivo", "revision_motivo"),
    ("observaciones", "observaciones"),
    ("coalesce(jsonb_array_length(fotos),0)", "fotos"),
    ("ST_X(geom)", "lon"), ("ST_Y(geom)", "lat"),
]
SELECT_DETALLE = ", ".join(expr for expr, _ in CAMPOS_DETALLE)
NOMBRES_DETALLE = [nombre for _, nombre in CAMPOS_DETALLE]


def _detalle(cred, municipio, barrio, desde, hasta, clasificacion, pagina, por_pagina):
    if cred[1] != "detalle":
        raise HTTPException(
            403, "Su credencial es de alcance 'consolidado'. El detalle incluye "
                 "direcciones y coordenadas, que son dato personal.")
    donde, args = filtros(cred[2], municipio, barrio, desde, hasta, clasificacion)
    (total,), = consultar(f"SELECT count(*) FROM evaluacion_brigada WHERE {donde}", tuple(args))
    filas = consultar(
        f"SELECT {SELECT_DETALLE} FROM evaluacion_brigada WHERE {donde} "
        "ORDER BY ts DESC LIMIT %s OFFSET %s",
        tuple(args) + (por_pagina, (pagina - 1) * por_pagina))
    salida = []
    for f in filas:
        d = dict(zip(NOMBRES_DETALLE, f, strict=True))
        for k in ("ts", "recibido_en"):
            d[k] = d[k].isoformat() if d[k] else None
        salida.append(d)
    return total, salida


@router.get("/evaluaciones")
def evaluaciones(x_api_token: str = Header(default=""),
                 municipio: str = Query("", max_length=120),
                 barrio: str = Query("", max_length=120),
                 desde: date | None = None, hasta: date | None = None,
                 clasificacion: int | None = Query(None, ge=1, le=3),
                 pagina: int = Query(1, ge=1),
                 por_pagina: int = Query(100, ge=1, le=MAX_PAGINA)):
    cred = autenticar(x_api_token)
    total, datos = _detalle(cred, municipio, barrio, desde, hasta,
                            clasificacion, pagina, por_pagina)
    return sin_cache({
        "total": total, "pagina": pagina, "por_pagina": por_pagina,
        "paginas": max(1, -(-total // por_pagina)),
        "evaluaciones": datos,
        "aviso": ("Contiene direcciones y coordenadas de predios: dato personal "
                  "bajo la Ley 1581 de 2012. No publicar sin agregar."),
    })


@router.get("/evaluaciones.geojson")
def evaluaciones_geojson(x_api_token: str = Header(default=""),
                         municipio: str = Query("", max_length=120),
                         barrio: str = Query("", max_length=120),
                         desde: date | None = None, hasta: date | None = None,
                         clasificacion: int | None = Query(None, ge=1, le=3),
                         pagina: int = Query(1, ge=1),
                         por_pagina: int = Query(MAX_PAGINA, ge=1, le=MAX_PAGINA)):
    cred = autenticar(x_api_token)
    _, datos = _detalle(cred, municipio, barrio, desde, hasta,
                        clasificacion, pagina, por_pagina)
    rasgos = [{"type": "Feature",
               "geometry": {"type": "Point", "coordinates": [d["lon"], d["lat"]]},
               "properties": {k: v for k, v in d.items() if k not in ("lon", "lat")}}
              for d in datos if d["lon"] is not None]
    return sin_cache({"type": "FeatureCollection", "features": rasgos})


# -------------------------------------------------------------------- ayuda
@router.get("/")
def indice(x_api_token: str = Header(default="")):
    """Qué puede hacer ESTA credencial. Evita adivinar leyendo documentación."""
    nombre, alcance, municipios = autenticar(x_api_token)
    return sin_cache({
        "credencial": nombre,
        "alcance": alcance,
        "municipios": municipios or "todos",
        "rutas": {
            "/api/v1/consolidado": "agregado por sector, con umbral de anonimato",
            "/api/v1/consolidado.geojson": "lo mismo como capa de puntos",
            "/api/v1/evaluaciones": ("detalle paginado" if alcance == "detalle"
                                     else "no disponible para esta credencial"),
            "/api/v1/evaluaciones.geojson": ("detalle como capa" if alcance == "detalle"
                                             else "no disponible para esta credencial"),
        },
        "filtros": ["municipio", "barrio", "desde", "hasta", "clasificacion"],
        "autenticacion": "cabecera X-API-Token",
    })
