#!/usr/bin/env python3
# Brigada · Evaluación estructural en campo
# Copyright (C) 2026 Rollout Comercio e Servicios Limitada / Andrés Benito Revollo Vélez
# Software libre bajo GNU AGPL v3.
"""Genera la tarjeta en PDF que se le entrega a una brigada.

  pip install segno
  python3 herramientas/tarjeta_brigada.py "Nombre de la brigada" <token> [endpoint]

Lleva dos códigos QR: uno abre la aplicación, el otro contiene el token para no
tener que teclear cuarenta y ocho caracteres en un teléfono, que es donde se
equivoca cualquiera.

OJO: el archivo que sale ES UNA CREDENCIAL. Con ese token, cualquier teléfono
puede enviar evaluaciones a nombre de esa brigada. Va a la persona que coordina,
por un canal que usted controle, y no a un grupo. Si se filtra, se reemite desde
el panel y el anterior deja de servir en el acto.

El PDF no se versiona en el repositorio: se genera y se entrega.
"""
import html
import pathlib
import shutil
import subprocess
import sys
import tempfile

try:
    import segno
except ImportError:
    sys.exit("Falta segno: pip install segno")

RAIZ = pathlib.Path(__file__).resolve().parent.parent
APP = "https://brigadaestructural.co/app/"
ENDPOINT = "https://brigadaestructural.co/api/evaluaciones"

CANDIDATOS_CHROME = [
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
    "google-chrome", "chromium", "chromium-browser",
]


def qr(datos: str, escala: int = 4) -> str:
    """SVG en línea. Corrección de errores alta: la tarjeta se va a imprimir,
    doblar y fotografiar, y un QR con manchas tiene que seguir leyéndose."""
    import io
    buf = io.BytesIO()      # segno escribe bytes, no texto
    segno.make(datos, error="h").save(buf, kind="svg", scale=escala, border=2,
                                      svgclass=None, lineclass=None, xmldecl=False,
                                      svgns=True, dark="#0F172A")
    return buf.getvalue().decode()


def en_bloques(token: str, n: int = 8) -> str:
    return " ".join(token[i:i + n] for i in range(0, len(token), n))


PLANTILLA = """<!doctype html><html lang="es-CO"><head><meta charset="utf-8">
<title>Credencial · {nombre}</title>
<style>
@page {{ size: A5; margin: 0; }}
:root{{ --tinta:#0F172A; --tinta2:#475569; --tenue:#5E6E82; --linea:#E2E8F0;
  --azul:#0369A1; --azul-osc:#075985; --azul-tinte:#E0F2FE; --papel:#F1F5F9;
  --rojo:#7F1D1D; --rojo-tinte:#FEF2F2; }}
*{{ box-sizing:border-box; }}
body{{ margin:0; width:148mm; height:210mm; padding:11mm 12mm;
  font:10pt/1.45 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
  color:var(--tinta); display:flex; flex-direction:column; }}
.cab{{ display:flex; align-items:flex-start; gap:6mm; border-bottom:2.5pt solid var(--azul);
  padding-bottom:3.5mm; }}
.cab h1{{ margin:0; font-size:11pt; letter-spacing:.16em; text-transform:uppercase;
  color:var(--azul); font-weight:800; }}
.cab p{{ margin:1mm 0 0; font-size:9pt; color:var(--tinta2); }}
.marca{{ margin-left:auto; text-align:right; font-size:8.5pt; color:var(--tenue); }}
.marca b{{ display:block; font-size:11pt; color:var(--tinta); letter-spacing:-.01em; }}

.nombre{{ margin:6mm 0 1mm; font-size:20pt; font-weight:800; letter-spacing:-.02em;
  line-height:1.15; }}
.rot{{ font-size:8pt; letter-spacing:.13em; text-transform:uppercase; color:var(--tenue);
  font-weight:700; margin:0 0 1.5mm; }}

.fila{{ display:flex; gap:6mm; align-items:flex-start; margin-top:4mm; }}
.qr{{ flex:none; text-align:center; width:34mm; }}
.qr svg{{ width:32mm; height:32mm; display:block; }}
.qr span{{ display:block; font-size:7.5pt; color:var(--tinta2); margin-top:1mm;
  line-height:1.3; }}

.token{{ font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:12.5pt;
  font-weight:600; letter-spacing:.04em; word-break:break-all; line-height:1.5;
  background:var(--papel); border:1pt dashed #94A3B8; border-radius:2mm;
  padding:3mm 3.5mm; }}
.servidor{{ font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:8.5pt;
  color:var(--tinta2); overflow-wrap:anywhere; margin-top:1.5mm; }}

ol{{ margin:2mm 0 0; padding-left:5mm; }}
li{{ margin-bottom:1.6mm; }}
.aviso{{ margin-top:auto; background:var(--rojo-tinte); border:0.8pt solid #FECACA;
  border-left:3pt solid var(--rojo); border-radius:2mm; padding:3mm 3.5mm; font-size:8.5pt;
  line-height:1.45; }}
/* Solo el PRIMER b es el título del aviso. Sin el `:first-child`, cualquier
   énfasis dentro del texto se volvía un bloque en mayúsculas y partía la frase. */
.aviso > b:first-child{{ display:block; font-size:8pt; letter-spacing:.09em;
  text-transform:uppercase; color:var(--rojo); margin-bottom:1mm; }}
.pie{{ margin-top:3mm; font-size:7.5pt; color:var(--tenue); text-align:center;
  line-height:1.5; }}
</style></head><body>

<div class="cab">
  <div>
    <h1>Credencial de brigada</h1>
    <p>Para configurar los teléfonos que van a evaluar</p>
  </div>
  <div class="marca"><b>Brigada</b>Evaluación estructural<br>en campo</div>
</div>

<p class="rot" style="margin-top:6mm">Brigada</p>
<div class="nombre">{nombre}</div>

<div class="fila">
  <div class="qr">{qr_app}<span>Escanee para<br>abrir la app</span></div>
  <div style="flex:1">
    <p class="rot">Cómo se configura</p>
    <ol>
      <li>Abra la app y elija <b>«Agregar a pantalla de inicio»</b>. Así funciona sin señal.</li>
      <li>Vaya a <b>Ajustes</b> y escriba su nombre y su matrícula profesional.</li>
      <li>Pegue el <b>token</b> de abajo. El servidor <b>ya viene puesto</b>.</li>
      <li>Toque <b>«Probar conexión»</b> con señal, <b>antes</b> de salir a terreno.</li>
    </ol>
  </div>
</div>

<div class="fila">
  <div class="qr">{qr_token}<span>Escanee para<br>copiar el token</span></div>
  <div style="flex:1">
    <p class="rot">Token de la brigada</p>
    <div class="token">{token_bloques}</div>
    <p style="font-size:8pt;color:var(--tinta2);margin:1.5mm 0 0">Escríbalo
      <b>seguido, sin espacios</b>. Los bloques son solo para leerlo.</p>
    <p class="rot" style="margin-top:3mm">Servidor</p>
    <div class="servidor">{endpoint}</div>
  </div>
</div>

<div class="aviso">
  <b>Esto es una credencial, no un instructivo</b>
  Con este token, cualquier teléfono puede enviar evaluaciones a nombre de
  <b>{nombre}</b>. Entréguelo a quien coordina, por un canal que usted controle, y
  no en un grupo. Si se filtra, se reemite desde el panel y el anterior deja de
  servir en el acto. El token identifica a la brigada, <b>no a la persona</b>: quien
  firma cada evaluación es quien pone su matrícula.
</div>

<div class="pie">
  Triaje estructural preliminar · La habilitación definitiva es competencia de UNGRD,
  Defensa Civil, bomberos y alcaldías.<br>
  Desarrollada con Amor por Andrés Benito Revollo Vélez · Rollout Comercio e Servicios
  Limitada · AGPL v3
</div>
</body></html>"""


def main() -> None:
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    nombre, token = sys.argv[1], sys.argv[2].strip()
    endpoint = sys.argv[3] if len(sys.argv) > 3 else ENDPOINT

    pagina = PLANTILLA.format(
        nombre=html.escape(nombre),
        token_bloques=html.escape(en_bloques(token)),
        endpoint=html.escape(endpoint),
        qr_app=qr(APP), qr_token=qr(token))

    chrome = next((c for c in CANDIDATOS_CHROME
                   if pathlib.Path(c).exists() or shutil.which(c)), None)
    if not chrome:
        sys.exit("No se encontró Chrome ni Chromium.")

    seguro = "".join(ch if ch.isalnum() else "-" for ch in nombre.lower()).strip("-")
    salida = RAIZ / "docs" / f"credencial-{seguro}.pdf"
    with tempfile.TemporaryDirectory() as tmp:
        fuente = pathlib.Path(tmp) / "tarjeta.html"
        fuente.write_text(pagina)
        subprocess.run([chrome, "--headless", "--disable-gpu", "--no-pdf-header-footer",
                        f"--print-to-pdf={salida}", fuente.as_uri()],
                       check=True, capture_output=True)
    print(f"{salida}  ({salida.stat().st_size // 1024} KB)")
    print("Es una credencial: entréguela por un canal que usted controle.")


if __name__ == "__main__":
    main()
