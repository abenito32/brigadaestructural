#!/usr/bin/env python3
"""Regenera municipios.py desde los datos abiertos del DANE.

  python3 herramientas/actualizar_municipios.py

La DIVIPOLA cambia poco —un municipio nuevo cada varios años— así que esto se
corre a mano cuando haga falta, no en cada despliegue. Después hay que correr
build_catalogo.py, que es quien lo mete en la app.

Fuente: dataset gdxc-w37w de datos.gov.co (Departamentos y municipios de
Colombia). Se guarda el resultado en el repositorio para que la app se pueda
construir sin conexión y para que quede registrado con qué versión se firmó.
"""
import datetime
import json
import pathlib
import subprocess
import sys
import urllib.request

URL = "https://www.datos.gov.co/resource/gdxc-w37w.json?$limit=1500"
RAIZ = pathlib.Path(__file__).resolve().parent.parent
SALIDA = RAIZ / "municipios.py"

# Partículas que van en minúscula: el origen viene todo en mayúsculas y
# "San José Del Palmar" se lee como un error de quien lo escribió.
MINUS = {"de", "del", "la", "las", "los", "y", "el", "e"}


def titulo(s: str) -> str:
    partes = s.lower().split()
    return " ".join(p if i and p in MINUS else p[:1].upper() + p[1:]
                    for i, p in enumerate(partes))


def descargar() -> list:
    """urllib primero; si el Python de turno no tiene los certificados del
    sistema —pasa en macOS con la instalación de python.org— se cae a curl en vez
    de pedirle a nadie que desactive la verificación de TLS."""
    try:
        with urllib.request.urlopen(URL, timeout=60) as r:
            return json.load(r)
    except Exception as e:
        print(f"urllib no pudo ({e.__class__.__name__}), intentando con curl…")
        salida = subprocess.run(["curl", "-sS", "--max-time", "60", URL],
                                capture_output=True, check=True).stdout
        return json.loads(salida)


def main() -> None:
    datos = descargar()
    if len(datos) < 1000:
        sys.exit(f"Solo llegaron {len(datos)} municipios: el origen cambió, revise "
                 "antes de sobrescribir la lista buena.")

    deptos, mun = {}, []
    for f in datos:
        deptos[f["cod_dpto"]] = titulo(f["dpto"])
        mun.append("%s|%s|%s|%s" % (
            f["cod_mpio"], titulo(f["nom_mpio"]),
            round(float(f["latitud"].replace(",", ".")), 4),
            round(float(f["longitud"].replace(",", ".")), 4)))
    mun.sort(key=lambda x: x.split("|")[1])

    SALIDA.write_text(PLANTILLA % (
        datetime.date.today().isoformat(),
        json.dumps(deptos, ensure_ascii=False, indent=4),
        len(mun),
        "\n".join("    %r," % m for m in mun)))
    print(f"{SALIDA.name}: {len(mun)} municipios, {len(deptos)} departamentos "
          f"({SALIDA.stat().st_size // 1024} KB)")
    print("Ahora corra: python3 build_catalogo.py")


PLANTILLA = '''"""División político-administrativa de Colombia (DIVIPOLA del DANE).

Generado por herramientas/actualizar_municipios.py desde el portal de datos
abiertos (dataset gdxc-w37w de datos.gov.co), %s.

Sirve para dos cosas en la app: escribir el municipio sin teclearlo entero —y que
quede siempre con la misma grafía, que es lo que permite consolidar por sector— y
centrar el mapa cuando todavía no hay lectura de GPS.

Se guarda el código DANE, no solo el nombre: es la llave con la que cualquier
entidad cruza contra sus propios datos, y hay municipios homónimos en
departamentos distintos que el nombre solo no distingue.

Cada línea es "codigo|nombre|lat|lon". El departamento sale de los dos primeros
dígitos del código, para no repetirlo mil veces.
"""

DEPARTAMENTOS = %s

# %d municipios, ordenados por nombre para que la app no tenga que ordenarlos al
# arrancar.
MUNICIPIOS = [
%s
]
'''


if __name__ == "__main__":
    main()
