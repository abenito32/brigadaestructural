#!/usr/bin/env python3
"""Compila docs/manual.html a PDF con Chrome headless.

  python3 docs/build_manual.py

Chrome porque es la unica forma de tener control real de la maquetacion impresa
(saltos de pagina, @page, colores) sin arrastrar una cadena de dependencias que
alguien tendria que instalar para reconstruir un PDF.
"""
import pathlib
import shutil
import subprocess
import sys

RAIZ = pathlib.Path(__file__).resolve().parent
FUENTE = RAIZ / "manual.html"
SALIDA = RAIZ / "manual-brigada.pdf"

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
    if not FUENTE.exists():
        sys.exit(f"Falta {FUENTE}")
    chrome = buscar_chrome()
    subprocess.run([
        chrome,
        "--headless",
        "--disable-gpu",
        "--no-pdf-header-footer",       # los encabezados los pone el documento
        "--print-to-pdf-no-header",     # nombre antiguo del mismo flag
        f"--print-to-pdf={SALIDA}",
        FUENTE.as_uri(),
    ], check=True, capture_output=True)
    kb = SALIDA.stat().st_size / 1024
    print(f"{SALIDA}  ({kb:.0f} KB)")


if __name__ == "__main__":
    main()
