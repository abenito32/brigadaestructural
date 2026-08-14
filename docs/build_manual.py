#!/usr/bin/env python3
"""Compila un documento HTML de docs/ a PDF con Chrome headless.

  python3 docs/build_manual.py                    # manual.html -> manual-brigada.pdf
  python3 docs/build_manual.py guia-coordinador   # guia-coordinador.html -> ...pdf

Chrome porque es la unica forma de tener control real de la maquetacion impresa
(saltos de pagina, @page, colores) sin arrastrar una cadena de dependencias que
alguien tendria que instalar para reconstruir un PDF.
"""
import pathlib
import shutil
import subprocess
import sys

RAIZ = pathlib.Path(__file__).resolve().parent
# Nombre del documento sin extension. El manual completo sigue siendo el defecto,
# para no romper a quien ya corre esto sin argumentos.
DOCS = {"manual": ("manual.html", "manual-brigada.pdf"),
        "guia-coordinador": ("guia-coordinador.html", "guia-coordinador.pdf"),
        "no-se-pierde": ("no-se-pierde.html", "no-se-pierde.pdf")}

CANDIDATOS = [
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
    "google-chrome", "chromium", "chromium-browser",
]


def buscar_chrome() -> str:
    for c in CANDIDATOS:
        if pathlib.Path(c).exists() or shutil.which(c):
            return c
    sys.exit("No se encontró Chrome ni Chromium. Instale uno de los dos.")


def main() -> None:
    cual = sys.argv[1] if len(sys.argv) > 1 else "manual"
    if cual not in DOCS:
        sys.exit(f"No conozco «{cual}». Opciones: {', '.join(DOCS)}")
    fuente, salida = (RAIZ / n for n in DOCS[cual])
    if not fuente.exists():
        sys.exit(f"Falta {fuente}")
    chrome = buscar_chrome()
    subprocess.run([
        chrome,
        "--headless",
        "--disable-gpu",
        "--no-pdf-header-footer",       # los encabezados los pone el documento
        "--print-to-pdf-no-header",     # nombre antiguo del mismo flag
        f"--print-to-pdf={salida}",
        fuente.as_uri(),
    ], check=True, capture_output=True)
    kb = salida.stat().st_size / 1024
    print(f"{salida}  ({kb:.0f} KB)")


if __name__ == "__main__":
    main()
