#!/usr/bin/env python3
"""Escribe el catálogo del V2F dentro de index.html.

  python3 build_catalogo.py           # regenera
  python3 build_catalogo.py --revisar # solo comprueba que esté al día (CI, o antes de desplegar)

La app es un solo archivo autocontenido que tiene que arrancar sin señal, así que
el catálogo no se descarga en tiempo de ejecución: se inyecta acá, entre
marcadores, y `v2f.py` sigue siendo la única fuente. No hay bundler; esto es un
comando que se corre a mano cuando el catálogo cambia, como el manual y la
presentación.

El código generado es ES5 (`var`, sin arrow functions) para no romper el estilo
del archivo ni los teléfonos viejos que son la razón de ese estilo.
"""
import json
import pathlib
import sys

import v2f

RAIZ = pathlib.Path(__file__).resolve().parent
DESTINO = RAIZ / "index.html"
INICIO = "/* V2F:catalogo:inicio */"
FIN = "/* V2F:catalogo:fin */"


def bloque() -> str:
    cat = v2f.para_la_app()
    lineas = [INICIO,
              "/* Generado por build_catalogo.py desde v2f.py. NO editar a mano:",
              "   el próximo generador lo sobrescribe. Cambie v2f.py y vuelva a correrlo. */"]
    for nombre, valor in cat.items():
        # Sin sort_keys: los grupos del formulario (concreto, mampostería, acero…)
        # van en el orden en que están impresos en el papel, no en alfabético.
        # Quien lleva años usando el V2F busca la casilla donde siempre estuvo.
        lineas.append("var V2F_%s=%s;" % (nombre, json.dumps(valor, ensure_ascii=False)))
    # Alias cortos: el resto del archivo ya los usa con estos nombres.
    lineas += [
        'var TIT=["Sin evaluar",V2F_HABITABILIDAD["1"],V2F_HABITABILIDAD["2"],'
        'V2F_HABITABILIDAD["3"],V2F_HABITABILIDAD["4"]];',
        'var SUB=["Complete el nivel de daño",V2F_SUBTITULO["1"],V2F_SUBTITULO["2"],'
        'V2F_SUBTITULO["3"],V2F_SUBTITULO["4"]];',
        FIN]
    return "\n".join(lineas)


def main() -> None:
    html = DESTINO.read_text()
    if INICIO not in html or FIN not in html:
        sys.exit(f"Faltan los marcadores {INICIO} … {FIN} en {DESTINO.name}")
    antes, resto = html.split(INICIO, 1)
    _, despues = resto.split(FIN, 1)
    nuevo = antes + bloque() + despues

    if "--revisar" in sys.argv:
        if nuevo != html:
            sys.exit("El catálogo de index.html NO está al día. Corra: "
                     "python3 build_catalogo.py")
        print("catálogo al día")
        return

    if nuevo == html:
        print("sin cambios")
        return
    DESTINO.write_text(nuevo)
    print(f"{DESTINO.name}: catálogo actualizado ({len(bloque())} bytes)")


if __name__ == "__main__":
    main()
