# Brigada · Evaluación estructural en campo
# Copyright (C) 2026 Rollout Comercio e Servicios Limitada / Andrés Benito Revollo Vélez
#
# Este programa es software libre bajo la Licencia Pública General Affero de GNU,
# versión 3 o posterior. Vea <https://www.gnu.org/licenses/>.
"""
Panel de administración: brigadas, inspectores y estado de los reportes.

Se monta sobre la misma app del receptor y se sirve en /admin.

Acceso: una sola clave de administrador, guardada como hash scrypt en
BRIGADA_ADMIN_HASH. Se define con:  admin_brigadas.py clave
Sin esa variable el panel no se monta: no existe un modo "sin clave".

Lo que se ve acá incluye direcciones y coordenadas, que son dato personal
(Ley 1581 de 2012). El panel es para coordinación de brigada, no para difusión:
lo que sale hacia autoridades es la vista consolidado_publico, agregada por sector.
"""
import base64
import hashlib
import json
import pathlib
from typing import NamedTuple
import hmac
import os
import secrets
import time

import v2f   # nombres y escala de la habitabilidad
from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import (HTMLResponse, JSONResponse, RedirectResponse,
                               Response)
from jinja2 import Environment

CLAVE_HASH = os.getenv("BRIGADA_ADMIN_HASH", "")
# Mismo umbral que la API de consulta: un solo numero, un solo lugar.
K_ANONIMATO = 5
# El correo de contacto sale del entorno, no del codigo: este archivo esta en un
# repositorio publico y una direccion ahi se rastrea en dias. Solo se muestra en
# el panel, que ademas lleva noindex.
CONTACTO = os.getenv("BRIGADA_CONTACTO", "")
DURACION_SESION = 8 * 3600          # una jornada
MAX_INTENTOS = 8                    # por IP, en la ventana de abajo
VENTANA_INTENTOS = 600

router = APIRouter()
env = Environment(autoescape=True)  # autoescape: los datos vienen de campo
# Leaflet se sirve desde el propio servidor: el panel tiene que funcionar sin
# depender de un CDN, igual que la aplicacion de campo.
VENDOR = pathlib.Path(os.getenv("BRIGADA_VENDOR", "/opt/brigadas/vendor"))
intentos: dict[str, list[float]] = {}


# ---------------------------------------------------------------- credenciales
def hash_clave(clave: str, sal: bytes | None = None) -> str:
    sal = sal or secrets.token_bytes(16)
    dk = hashlib.scrypt(clave.encode(), salt=sal, n=2**14, r=8, p=1, dklen=32)
    return "scrypt$" + base64.b64encode(sal).decode() + "$" + base64.b64encode(dk).decode()


def verificar_clave(clave: str, esperado: str) -> bool:
    """Comparación en tiempo constante contra un hash scrypt guardado."""
    try:
        _, sal_b64, _ = esperado.split("$")
    except ValueError:
        return False
    return hmac.compare_digest(hash_clave(clave, base64.b64decode(sal_b64)), esperado)


def clave_correcta(clave: str) -> bool:
    """La clave maestra del administrador, que vive en el entorno."""
    return bool(CLAVE_HASH) and verificar_clave(clave, CLAVE_HASH)


def _llave() -> bytes:
    """La firma de sesión deriva del hash de la clave: cambiarla cierra las sesiones."""
    return hashlib.sha256(("sesion:" + CLAVE_HASH).encode()).digest()


class Sesion(NamedTuple):
    rol: str              # "admin" | "coordinador"
    brigada: str | None   # None para admin: ve todo
    usuario: str


def firmar(vence: int, rol: str, brigada: str | None, usuario: str) -> str:
    """El rol y la brigada viajan DENTRO de la firma. Si fueran un parámetro
    aparte, cualquiera cambiaría 'coordinador' por 'admin' en su propia cookie."""
    cuerpo = "|".join([str(vence), rol, brigada or "", usuario]).encode()
    firma = hmac.new(_llave(), cuerpo, hashlib.sha256).digest()
    # Se concatena sin separador: sha256 mide SIEMPRE 32 bytes, así que al leer
    # se corta por longitud. Con un separador de un byte —un punto, por ejemplo—
    # la firma podía contenerlo y el corte caía en el lugar equivocado: una de
    # cada ocho sesiones nacía rota, al azar.
    return base64.urlsafe_b64encode(cuerpo + firma).decode()


def leer_sesion(cookie: str | None) -> Sesion | None:
    if not cookie:
        return None
    try:
        crudo = base64.urlsafe_b64decode(cookie.encode())
        cuerpo, firma = crudo[:-32], crudo[-32:]      # sha256: 32 bytes exactos
        if not hmac.compare_digest(hmac.new(_llave(), cuerpo, hashlib.sha256).digest(), firma):
            return None
        vence, rol, brigada, usuario = cuerpo.decode().split("|", 3)
        if int(vence) <= time.time() or rol not in ("admin", "coordinador"):
            return None
        # Un coordinador sin brigada no existe: sería un admin encubierto.
        if rol == "coordinador" and not brigada:
            return None
        return Sesion(rol, brigada or None, usuario)
    except Exception:
        return None


def exigir(req: Request) -> Sesion:
    ses = leer_sesion(req.cookies.get("brigada_admin"))
    if ses is None:
        raise HTTPException(303, headers={"Location": "/admin/entrar"})
    # La cookie va firmada, pero la firma no caduca cuando se revoca a alguien.
    # Sin esta comprobación, dar de baja a un coordinador —o a su brigada— lo
    # dejaba dentro hasta ocho horas. Es una consulta por petición, y el panel
    # tiene un puñado de usuarios: el precio correcto por revocar de verdad.
    if ses.rol == "coordinador":
        vigente = consulta("""SELECT 1 FROM coordinador c JOIN brigada b ON b.nombre = c.brigada
                               WHERE c.usuario = %s AND c.brigada = %s
                                 AND c.activo AND b.activa""",
                           (ses.usuario, ses.brigada))
        if not vigente:
            raise HTTPException(303, headers={"Location": "/admin/entrar"})
    return ses


def exigir_admin(req: Request) -> Sesion:
    """Para lo que administra el sistema: brigadas, solicitudes, credenciales.
    Se comprueba en el servidor, no escondiendo el enlace del menú."""
    ses = exigir(req)
    if ses.rol != "admin":
        raise HTTPException(403, "Esta sección es solo para la administración del sistema")
    return ses


def ip_real(req: Request) -> str:
    """Detras de nginx, req.client.host es siempre el proxy: sin esto TODOS los
    intentos caen en el mismo cubo y ocho fallos de cualquiera dejan afuera a
    todo el mundo. X-Real-IP lo pone nginx con $remote_addr, no el cliente."""
    return req.headers.get("x-real-ip") or (req.client.host if req.client else "?")


def limitar(ip: str) -> bool:
    """Frena la fuerza bruta contra la clave. Devuelve True si hay que rechazar."""
    ahora = time.time()
    hist = [t for t in intentos.get(ip, []) if ahora - t < VENTANA_INTENTOS]
    intentos[ip] = hist
    return len(hist) >= MAX_INTENTOS


# ---------------------------------------------------------------------- diseño
BASE = """<!doctype html>
<html lang="es-CO"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<!-- Ni siquiera la pantalla de entrada debe aparecer en un buscador. -->
<meta name="robots" content="noindex,nofollow">
<title>{{ titulo }} · Administración Brigada</title>
<style>
:root{--papel:#F1F5F9;--carta:#fff;--tinta:#0F172A;--tinta2:#475569;--tenue:#5E6E82;
 --borde:#CBD5E1;--linea:#E2E8F0;--azul:#0369A1;--azul-osc:#075985;--azul-tinte:#E0F2FE;
 --verde:#15803D;--ambar:#B45309;--ambar-fondo:#EAB308;--ambar-tinta:#422006;
 --naranja:#C2410C;--rojo:#7F1D1D;
 --rojo-tinte:#FEF2F2;--r:8px;--r-l:12px;--sombra:0 1px 2px rgba(15,23,42,.05),0 1px 3px rgba(15,23,42,.08)}
*{box-sizing:border-box}html{color-scheme:light}
body{margin:0;background:var(--papel);color:var(--tinta);font:16px/1.5 ui-sans-serif,system-ui,
 -apple-system,"Segoe UI",Roboto,sans-serif}
.top{background:var(--carta);border-bottom:1px solid var(--linea);position:sticky;top:0;z-index:9}
.top-in,.wrap{max-width:1100px;margin:0 auto;padding:0 18px}
.top-in{display:flex;align-items:center;gap:18px;padding-top:12px;padding-bottom:0;flex-wrap:wrap}
.marca{font-weight:700;letter-spacing:-.01em}.marca span{color:var(--azul)}
.nav{display:flex;gap:2px;margin-left:auto;flex-wrap:wrap}
.nav a{padding:11px 13px;text-decoration:none;color:var(--tinta2);font-weight:600;font-size:14px;
 border-bottom:2.5px solid transparent;margin-bottom:-1px}
.nav a.on{color:var(--azul);border-bottom-color:var(--azul)}
.nav a:hover{color:var(--tinta)}
.salir{font-size:13px;color:var(--tenue);text-decoration:underline;padding:11px 0 11px 8px}
.wrap{padding-top:20px;padding-bottom:56px}
h1{font-size:22px;margin:0 0 4px;letter-spacing:-.02em}
.sub{color:var(--tinta2);font-size:14px;margin:0 0 18px}
.tarjeta{background:var(--carta);border:1px solid var(--linea);border-radius:var(--r-l);
 padding:18px;box-shadow:var(--sombra);margin-bottom:16px}
.rotulo{font-size:11px;font-weight:700;letter-spacing:.09em;text-transform:uppercase;
 color:var(--tenue);margin:0 0 14px}
.cifras{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:16px}
.cifra{background:var(--carta);border:1px solid var(--linea);border-radius:var(--r-l);padding:15px 16px;
 box-shadow:var(--sombra)}
.cifra b{display:block;font-size:30px;font-weight:800;letter-spacing:-.03em;font-variant-numeric:tabular-nums}
.cifra span{font-size:12px;color:var(--tinta2);font-weight:600}
.cifra.c1 b{color:var(--verde)}.cifra.c2 b{color:var(--ambar)}
.cifra.c3 b{color:var(--naranja)}.cifra.c4 b{color:var(--rojo)}
.cifra.alerta{border-color:#FECACA;background:var(--rojo-tinte)}
table{width:100%;border-collapse:collapse;font-size:14px}
th{text-align:left;font-size:11px;letter-spacing:.07em;text-transform:uppercase;color:var(--tenue);
 padding:0 10px 9px;font-weight:700;white-space:nowrap}
td{padding:11px 10px;border-top:1px solid var(--linea);vertical-align:top}
tbody tr:hover{background:var(--papel)}
.num{font-variant-numeric:tabular-nums}
.pastilla{display:inline-block;padding:3px 9px;border-radius:999px;font-size:12px;font-weight:700;
 white-space:nowrap}
.p1{background:#DCFCE7;color:#14532D}.p2{background:#FEF3C7;color:var(--ambar-tinta)}
.p3{background:#FFEDD5;color:#7C2D12}.p4{background:#FEE2E2;color:#7F1D1D}
.pi{background:var(--azul-tinte);color:var(--azul-osc)}.pn{background:#F1F5F9;color:var(--tinta2)}
.palerta{background:#FEE2E2;color:#7F1D1D}
label{display:block;margin-bottom:13px}
label>span{display:block;font-size:13px;font-weight:600;color:var(--tinta2);margin-bottom:5px}
input,select{width:100%;padding:11px 12px;font:inherit;border:1px solid var(--borde);
 border-radius:var(--r);background:var(--carta);color:var(--tinta);min-height:46px}
input:focus,select:focus{outline:3px solid var(--azul);outline-offset:-1px;border-color:var(--azul)}
/* Las casillas y los radios no son campos de texto: sin esto heredan el ancho
   completo y los 46px de alto y salen como un recuadro vacío enorme. */
input[type=checkbox],input[type=radio]{width:auto;min-height:0;padding:0;
 margin:0 8px 0 0;accent-color:var(--azul);flex:none}
label.acepto{display:flex;align-items:flex-start;gap:2px;max-width:640px}
label.acepto>span{display:inline;font-weight:400;font-size:14px;margin:0;color:var(--tinta2)}
.btn{display:inline-block;border:1px solid var(--borde);background:var(--carta);color:var(--tinta);
 font:inherit;font-weight:600;font-size:15px;padding:12px 18px;border-radius:var(--r);cursor:pointer;
 text-decoration:none;box-shadow:var(--sombra)}
.btn:hover{background:var(--papel)}
.btn-p{background:var(--azul);color:#fff;border-color:var(--azul)}
.btn-p:hover{background:var(--azul-osc)}
.btn-r{color:var(--rojo);border-color:#FECACA;background:var(--rojo-tinte);font-size:13px;padding:7px 12px}
/* Faltaba: los botones del modal y del formulario catastral la usaban desde que
   se añadió la ficha, y sin ella salían del tamaño de un botón principal. */
.btn-s{font-size:13px;padding:8px 13px;min-height:0}
.btn-r:hover{background:#FEE2E2}
.fila{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;align-items:end}
.nota{font-size:13px;color:var(--tinta2);line-height:1.55;margin:10px 0 0}
.aviso{border:1px solid #FECACA;border-left:4px solid var(--rojo);background:var(--rojo-tinte);
 border-radius:var(--r);padding:13px 15px;font-size:14px;margin-bottom:16px}
.ok{border:1px solid #BBF7D0;border-left:4px solid var(--verde);background:#F0FDF4;
 border-radius:var(--r);padding:13px 15px;font-size:14px;margin-bottom:16px}
.token{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:15px;background:var(--carta);
 border:1px dashed var(--borde);border-radius:var(--r);padding:11px 13px;margin:10px 0;
 word-break:break-all;user-select:all}
.oculto{display:none!important}
.vacio{color:var(--tinta2);padding:30px 0;text-align:center}
.desplaza{overflow-x:auto}
.pag{display:flex;gap:9px;align-items:center;margin-top:16px;font-size:14px;color:var(--tinta2)}
.entrar{max-width:380px;margin:12vh auto;padding:0 18px}
.credito{margin:34px 0 0;font-size:13px;color:var(--tenue);text-align:center;line-height:1.6}
.credito a{color:var(--tenue)}
@media (max-width:640px){.top-in{gap:8px}.nav{width:100%;margin-left:0}}
</style></head><body>
{% if sesion %}
<header class="top"><div class="top-in">
  <div class="marca">Brigada <span>/</span> {{ "administración" if rol == "admin" else brigada }}</div>
  <nav class="nav">
    <a href="/admin" class="{{ 'on' if pag=='inicio' }}">Resumen</a>
    <a href="/admin/mapa" class="{{ 'on' if pag=='mapa' }}">Mapa</a>
    <a href="/admin/evolucion" class="{{ 'on' if pag=='evolucion' }}">Evolución</a>
    <a href="/admin/reportes" class="{{ 'on' if pag=='reportes' }}">Reportes</a>
    <a href="/admin/exportar" class="{{ 'on' if pag=='exportar' }}">Exportar</a>
    <a href="/admin/rojos" class="{{ 'on' if pag=='rojos' }}">Revisión</a>
    {% if rol == 'admin' %}<a href="/admin/brigadas" class="{{ 'on' if pag=='brigadas' }}">Brigadas</a>{% endif %}
    <a href="/admin/inspectores" class="{{ 'on' if pag=='inspectores' }}">Inspectores</a>
    {% if rol == 'admin' %}<a href="/admin/solicitudes" class="{{ 'on' if pag=='solicitudes' }}">Solicitudes</a>{% endif %}
    <a href="/admin/salir" class="salir">Salir{% if rol == 'coordinador' %} · {{ quien }}{% endif %}</a>
  </nav>
</div></header>
{% endif %}
<main class="{{ 'entrar' if not sesion else 'wrap' }}">{{ cuerpo }}
<p class="credito">Desarrollada con Amor por Andrés Benito Revollo Vélez ·
  Rollout Comercio e Servicios Limitada<br>
  {% if contacto %}<a href="mailto:{{ contacto }}">{{ contacto }}</a> · {% endif %}
  <a href="https://github.com/abenito32/brigadaestructural" rel="noopener">AGPL v3</a></p>
</main>
</body></html>"""


def pagina(titulo, cuerpo_html, pag="", sesion=True, ses=None):
    from markupsafe import Markup
    return HTMLResponse(env.from_string(BASE).render(
        titulo=titulo, cuerpo=Markup(cuerpo_html), pag=pag, sesion=sesion,
        contacto=CONTACTO,
        rol=(ses.rol if ses else "admin"),
        brigada=(ses.brigada if ses else None),
        quien=(ses.usuario if ses else "")))


def render(plantilla, **ctx):
    return env.from_string(plantilla).render(**ctx)


def consulta(sql, args=()):
    import api_brigadas
    with api_brigadas.pool.connection(timeout=api_brigadas.ESPERA_POOL) as con, con.cursor() as cur:
        cur.execute(sql, args)
        return cur.fetchall() if cur.description else []


# ---------------------------------------------------------------- el modal
# Una sola pieza, compartida por Reportes, Rojos y el mapa: si el detalle de una
# evaluación se dibujara en tres sitios distintos, tarde o temprano dirían cosas
# distintas sobre el mismo predio.
MODAL_HTML = """
<dialog id="ficha">
  <div class="ficha-cab">
    <div>
      <span id="f-chip" class="pastilla">—</span>
      <strong id="f-id" class="num"></strong>
      <span id="f-rev" class="pastilla pn oculto"></span>
      <span id="f-vig" class="pastilla pn oculto">reemplazada</span>
    </div>
    <div style="margin-left:auto;display:flex;gap:8px">
      <a class="btn btn-s" id="f-hist" href="#">Historia del predio</a>
      <button class="btn btn-s" id="f-html">Exportar HTML</button>
      <button class="btn btn-s" id="f-json">JSON con fotos</button>
      <button class="btn btn-s" id="f-cerrar" aria-label="Cerrar">Cerrar</button>
    </div>
  </div>
  <div class="ficha-cuerpo" id="f-cuerpo"></div>
</dialog>

<style>
#ficha{border:0;border-radius:var(--r-l);padding:0;max-width:900px;width:94vw;
  box-shadow:0 12px 40px rgba(15,23,42,.28)}
#ficha::backdrop{background:rgba(15,23,42,.55)}
.ficha-cab{display:flex;gap:12px;align-items:center;padding:16px 20px;
  border-bottom:1px solid var(--linea);position:sticky;top:0;background:var(--carta);
  flex-wrap:wrap}
.ficha-cuerpo{padding:20px;max-height:74vh;overflow-y:auto}
.ficha-cuerpo h4{margin:18px 0 8px;font-size:12px;letter-spacing:.09em;
  text-transform:uppercase;color:var(--tenue)}
.ficha-cuerpo h4:first-child{margin-top:0}
.ficha-cuerpo table{width:100%;font-size:14px}
.ficha-cuerpo td:first-child{width:34%;color:var(--tinta2)}
.fotos-ficha{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:12px}
.foto-marco{position:relative;border:1px solid var(--linea);border-radius:var(--r);
  overflow:hidden;background:var(--papel)}
.foto-marco img{width:100%;display:block}
/* La marca va sobre la imagen, no dentro del archivo: el original guardado sigue
   siendo la evidencia intacta, y aun así una captura de pantalla sale trazable. */
.foto-marca{position:absolute;left:0;right:0;bottom:0;padding:6px 9px;
  background:rgba(15,23,42,.72);color:#fff;font-size:11px;line-height:1.35;
  font-family:ui-monospace,Menlo,monospace;word-break:break-all}
.escala-mini{display:flex;gap:4px;flex-wrap:wrap}
.escala-mini span{padding:2px 8px;border-radius:4px;font-size:12px;font-weight:600}
.reserva-aviso{font-size:12px;color:var(--tinta2);background:var(--papel);
  border-left:3px solid var(--azul);border-radius:4px;padding:8px 11px;margin:0 0 10px}
</style>

<script>
(function(){
  "use strict";
  var dlg = document.getElementById("ficha");
  if (!dlg) return;
  var NIV = ["N/A","Leve","Moderado","Severo"];          // escala de daño, 0 a 3
  var HAB = __HAB__;                                     // habitabilidad, 1 a 4
  var PARC = __PARC__;
  var CAT = __CAT__;                                     // catálogo del V2F
  var COLOR_NIV = ["#EEF2F6","#DCFCE7","#FEF3C7","#FEE2E2"];
  var TINTA_NIV = ["#475569","#14532D","#422006","#7F1D1D"];
  var CATEG = {portantes:"Elementos portantes", horizontal:"Vigas y entrepisos",
               nostruct:"Muros divisorios y fachada", terreno:"Terreno y entorno"};
  var BAND = {colapso:"Colapso total o parcial", inclina:"Inclinación visible",
              acero:"Acero expuesto o pandeado", pasante:"Grietas pasantes",
              vecino:"Riesgo externo", acceso:"Elementos sobre el acceso"};
  var actual = null;

  function esc(t){ var d=document.createElement("div"); d.textContent = t==null?"":t; return d.innerHTML; }
  function fecha(s){ return s ? s.replace("T"," ").slice(0,16) : "—"; }

  function filas(pares){
    return "<table>" + pares.filter(function(p){ return p[1]; })
      .map(function(p){ return "<tr><td>"+esc(p[0])+"</td><td>"+p[1]+"</td></tr>"; })
      .join("") + "</table>";
  }

  function cuerpo(e, fotosHtml){
    var d = e.danos || {}, b = e.banderas || {};
    var niveles = Object.keys(CATEG).map(function(k){
      var v = d[k] || 0;
      return '<span style="background:'+COLOR_NIV[v]+';color:'+TINTA_NIV[v]+'">'
           + esc(CATEG[k]) + ": " + NIV[v] + "</span>";
    }).join("");
    var marcadas = Object.keys(BAND).filter(function(k){ return b[k]; })
      .map(function(k){ return "<li>"+esc(BAND[k])+"</li>"; }).join("");

    var html = "<h4>Dónde</h4>" + filas([
      ["Dirección", esc(e.direccion)],
      ["Municipio y barrio", esc([e.municipio, e.barrio].filter(Boolean).join(" · "))],
      ["Coordenadas", e.lat!=null ? e.lat.toFixed(5)+", "+e.lon.toFixed(5)
        + (e.precision_m ? " (±"+e.precision_m+" m)" : "") : ""],
    ]);
    html += "<h4>Edificación</h4>" + filas([
      ["Sistema constructivo", esc(e.sistema)], ["Uso", esc(e.uso)],
      ["Pisos", e.pisos], ["Ocupantes", e.ocupantes],
    ]);
    html += "<h4>Daño observado</h4><div class='escala-mini'>" + niveles + "</div>";
    if (marcadas) html += "<h4>Condiciones que obligan cierre</h4><ul>" + marcadas + "</ul>";
    html += "<h4>Quién firma</h4>" + filas([
      ["Inspector", esc(e.inspector)],
      ["Matrícula", e.firma_tipo === "matricula"
        ? esc(e.matricula) + (e.matricula_verificada ? "" :
            ' <span class="pastilla palerta">fuera del registro</span>')
        : '<span class="pastilla palerta">Firmada sin matrícula</span>'],
      ["Documento", esc(e.documento)],
      ["Profesión", esc(e.profesion)],
      ["Brigada", esc(e.brigada_token || e.brigada)],
      ["Evaluada", fecha(e.ts)], ["Recibida", fecha(e.recibido_en)],
    ]);
    if (e.clasificacion_auto != null && e.clasificacion !== e.clasificacion_auto)
      html += "<h4>Clasificación modificada por el inspector</h4>" + filas([
        ["Calculada", HAB[e.clasificacion_auto]], ["Firmada", HAB[e.clasificacion]],
        ["Motivo", esc(e.justificacion)]]);
    if (e.modo === "completo" || e.v2f_estado || e.v2f_estructurales) {
      html += "<h4>Formulario V2F</h4>" + filas([
        ["Tipo de inspección", CAT.TIPO_INSPECCION[e.tipo_inspeccion]],
        ["Sistema estructural", cod(e.v2f_estructura, "sistema", CAT.SISTEMA_ESTRUCTURAL)],
        ["Tipo de entrepiso", cod(e.v2f_estructura, "entrepiso", CAT.TIPO_ENTREPISO)],
        ["Período de construcción", cod(e.v2f_estructura, "periodo", CAT.PERIODO_CONSTRUCCION)],
        ["Uso (V2F)", cod(e.v2f_estructura, "uso", CAT.USO)],
        ["Uso de la planta baja", cod(e.v2f_estructura, "uso_planta_baja", CAT.USO)],
        ["Código catastral", esc(e.cod_catastral) +
          (e.catastral_origen === "panel" ? " <em>(completado desde el panel)</em>" : "")],
        ["Nivel de mayor daño", e.nivel_mayor_dano],
        ["Área afectada", e.area_afectada_pct != null ? e.area_afectada_pct + " %" : ""],
      ]);
      html += bloquePreguntas("A · Estado general", e.v2f_estado, CAT.ESTADO_GENERAL);
      html += bloquePreguntas("B · Problemas geotécnicos", e.v2f_geotecnicos, CAT.GEOTECNICOS);
      html += bloqueEscala("C · Daños no estructurales", e.v2f_no_estructurales);
      html += bloqueGrilla("D · Daños estructurales", e.v2f_estructurales);
      html += bloquePreguntas("E · Problemas del entorno", e.v2f_entorno, CAT.ENTORNO);
      html += bloqueLibre("Condiciones pre-existentes", e.v2f_preexistentes, CAT.PREEXISTENTES);
      html += bloqueMarcadas("Recomendaciones y medidas", e.v2f_recomendaciones);
      html += bloqueLlaves("Ocupación", e.v2f_ocupacion, {
        habitada:"¿Habitada?", ocupantes:"Ocupantes",
        unidades:"Unidades existentes", unidades_no_hab:"Unidades no habitables"});
      html += bloqueLlaves("Comisión", e.v2f_comision, {
        codigo_lider:"Código del líder", evaluadores:"Nº de evaluadores", otro:"Otro inspector"});
    }
    if (e.bloques_faltantes && e.bloques_faltantes.length)
      html += '<h4>Bloques sin datos</h4><p class="reserva-aviso">' +
        e.bloques_faltantes.map(function(k){ return esc(k + " · " + PARC[k]); }).join("<br>") +
        "<br><em>Un bloque en blanco no significa «sin daño»: significa que nadie lo miró. " +
        "El V2F sale marcado como inspección parcial.</em></p>";
    if (e.reservado && Object.keys(e.reservado).length) {
      var rr = e.reservado;
      html += '<h4>Reservado · datos personales de terceros</h4>' +
        '<p class="reserva-aviso">Ley 1581 de 2012. No aparece en el listado, ni en el ' +
        'CSV, ni en la API de consulta. Sale del panel solo dentro del V2F que se ' +
        'entrega a la autoridad.</p>' + filas([
        ["¿Hubo muertos o heridos?", {1:"No",2:"Sí",3:"No se sabe"}[rr.hubo_victimas]],
        ["Personas fallecidas", rr.fallecidos != null ? String(rr.fallecidos) : ""],
        ["Heridos", rr.heridos != null ? String(rr.heridos) : ""],
        ["Afectados", rr.afectados != null ? String(rr.afectados) : ""],
        ["Persona de contacto", esc(rr.contacto_nombre)],
        ["Teléfono", esc(rr.contacto_telefono)], ["Correo", esc(rr.contacto_correo)],
      ]);
    }
    if (e.parciales) {
      var pk = ["A","B","C","D","E"], pp = "";
      for (var j = 0; j < pk.length; j++)
        pp += "<tr><td>" + pk[j] + " · " + esc(PARC[pk[j]]) + "</td><td>"
            + esc(HAB[e.parciales[pk[j]]] || "—")
            + (e.parcial_manda === pk[j] ? " <strong>← manda</strong>" : "") + "</td></tr>";
      html += "<h4>Clasificación por bloque (V2F)</h4><table>" + pp + "</table>";
    }
    if (e.revision_estado) html += "<h4>Segunda revisión</h4>" + filas([
      ["Estado", esc(e.revision_estado)], ["Revisó", esc(e.revision_matricula)],
      ["Cuándo", fecha(e.revision_en)], ["Motivo", esc(e.revision_motivo)]]);
    if (e.observaciones) html += "<h4>Observaciones</h4><p>" + esc(e.observaciones) + "</p>";
    if (fotosHtml) html += "<h4>Registro fotográfico</h4><div class='fotos-ficha'>"
      + fotosHtml + "</div>";
    return html;
  }

  function cod(blq, k, catalogo){
    var v = blq && blq[k];
    return v == null ? "" : esc((catalogo && catalogo[v]) || ("código " + v + " (desconocido)"));
  }
  function bloquePreguntas(titulo, datos, defs){
    if (!datos) return "";
    var f = defs.map(function(q){
      return [q.rotulo, datos[q.k] == null ? "" : esc(q.opciones[datos[q.k]] ||
              ("código " + datos[q.k]))];
    });
    return "<h4>" + esc(titulo) + "</h4>" + filas(f);
  }
  function bloqueEscala(titulo, datos){
    if (!datos) return "";
    var f = Object.keys(datos).sort(function(a,b){return a-b}).map(function(k){
      return [(CAT.NO_ESTRUCTURALES[k] || ("ítem " + k)),
              esc(CAT.GRADO_DANO[datos[k]] || datos[k])];
    });
    return "<h4>" + esc(titulo) + "</h4>" + filas(f);
  }
  function bloqueGrilla(titulo, datos){
    if (!datos) return "";
    var h = "<h4>" + esc(titulo) + '</h4><table><tr><td></td>';
    var grados = Object.keys(CAT.GRADO_DANO).sort(function(a,b){return a-b});
    grados.forEach(function(g){ h += "<td><strong>" + esc(CAT.GRADO_DANO[g]) + "</strong></td>"; });
    h += "</tr>";
    Object.keys(datos).sort(function(a,b){return a-b}).forEach(function(it){
      h += "<tr><td>" + esc(CAT.ESTRUCTURALES[it] || it) + "</td>";
      grados.forEach(function(g){ h += "<td>" + (datos[it][g] || 0) + " %</td>"; });
      h += "</tr>";
    });
    return h + "</table>";
  }
  function bloqueLibre(titulo, datos, defs){
    if (!datos) return "";
    var f = defs.filter(function(q){ return datos[q.k] != null; })
                .map(function(q){ return [q.rotulo, esc(q.opciones[datos[q.k]] || datos[q.k])]; });
    return f.length ? "<h4>" + esc(titulo) + "</h4>" + filas(f) : "";
  }
  function bloqueMarcadas(titulo, datos){
    if (!datos) return "";
    var partes = [];
    [["visita", CAT.VISITA_ESPECIALIZADA, "Visita especializada"],
     ["intervencion", CAT.INTERVENCION, "Intervención de"],
     ["medidas", CAT.MEDIDAS_SEGURIDAD, "Medidas de seguridad"]].forEach(function(t){
      var d = datos[t[0]];
      if (!d) return;
      var l = Object.keys(d).filter(function(k){ return d[k]; })
                .map(function(k){ return esc(t[1][k] || k); });
      if (l.length) partes.push([t[2], l.join("<br>")]);
    });
    if (datos.lugares) partes.push(["Lugares", esc(datos.lugares)]);
    return partes.length ? "<h4>" + esc(titulo) + "</h4>" + filas(partes) : "";
  }
  function bloqueLlaves(titulo, datos, rotulos){
    if (!datos) return "";
    var f = Object.keys(rotulos).filter(function(k){ return datos[k] != null && datos[k] !== ""; })
      .map(function(k){
        var v = datos[k];
        if (k === "habitada") v = {1:"Sí",2:"No"}[v] || v;
        return [rotulos[k], esc(v)];
      });
    return f.length ? "<h4>" + esc(titulo) + "</h4>" + filas(f) : "";
  }

  function marca(e, i){
    return esc(e.id_local || e.id) + " · foto " + (i+1) + "<br>" + esc(e.id);
  }

  function abrir(id){
    fetch("/admin/evaluacion/" + encodeURIComponent(id) + ".json", {cache:"no-store"})
      .then(function(r){ if(!r.ok) throw 0; return r.json(); })
      .then(function(e){
        actual = e;
        document.getElementById("f-id").textContent = e.id_local || e.id;
        var chip = document.getElementById("f-chip");
        chip.className = "pastilla p" + e.clasificacion_efectiva;
        chip.textContent = e.nombre_clas;
        var rev = document.getElementById("f-rev");
        rev.classList.toggle("oculto", !e.revision_estado);
        rev.textContent = e.revision_estado || "";
        // Una evaluación reemplazada sigue existiendo y sigue firmada; lo que no
        // hace es contar. Quien la abre tiene que verlo de entrada.
        document.getElementById("f-vig").classList.toggle("oculto", e.vigente !== false);
        var fotos = "";
        for (var i = 0; i < e.fotos; i++)
          fotos += '<figure class="foto-marco" style="margin:0">'
                 + '<img loading="lazy" alt="Fotografía ' + (i+1) + ' de la evaluación" src="/admin/foto/'
                 + encodeURIComponent(e.id) + '/' + i + '">'
                 + '<figcaption class="foto-marca">' + marca(e, i) + '</figcaption></figure>';
        document.getElementById("f-cuerpo").innerHTML = cuerpo(e, fotos);
        document.getElementById("f-hist").href = "/admin/historia/" +
          encodeURIComponent(e.id);
        dlg.showModal();
      })
      .catch(function(){ alert("No se pudo abrir esa evaluación."); });
  }
  window.abrirFicha = abrir;

  document.getElementById("f-cerrar").onclick = function(){ dlg.close(); };

  function bajar(nombre, texto, tipo){
    var u = URL.createObjectURL(new Blob([texto], {type:tipo}));
    var a = document.createElement("a"); a.href = u; a.download = nombre; a.click();
    setTimeout(function(){ URL.revokeObjectURL(u); }, 2000);
  }

  // Las fotos se incrustan en base64: el archivo exportado se abre sin conexión
  // y sin sesión, que es lo que hace falta para adjuntarlo a un correo.
  function conFotos(e){
    var tareas = [];
    for (var i = 0; i < e.fotos; i++)
      tareas.push(fetch("/admin/foto/"+encodeURIComponent(e.id)+"/"+i)
        .then(function(r){ return r.blob(); })
        .then(function(b){ return new Promise(function(res){
          var fr = new FileReader(); fr.onload = function(){ res(fr.result); };
          fr.readAsDataURL(b); }); }));
    return Promise.all(tareas);
  }

  document.getElementById("f-html").onclick = function(){
    if (!actual) return;
    var e = actual;
    conFotos(e).then(function(datos){
      var fotos = datos.map(function(src, i){
        return '<figure class="foto-marco" style="margin:0"><img src="'+src+'">'
             + '<figcaption class="foto-marca">' + marca(e, i) + '</figcaption></figure>';
      }).join("");
      var css = document.querySelector("style").textContent
              + document.querySelectorAll("style")[1].textContent;
      var doc = "<!DOCTYPE html><html lang=es-CO><head><meta charset=utf-8>"
        + "<title>Evaluación " + esc(e.id_local || e.id) + "</title><style>" + css
        + "body{padding:28px;max-width:860px;margin:0 auto}"
        + "@media print{.foto-marca{background:rgba(15,23,42,.72)!important;"
        + "-webkit-print-color-adjust:exact;print-color-adjust:exact}}</style></head><body>"
        + "<h1 style='font-size:22px;margin:0 0 4px'>Evaluación estructural "
        + esc(e.id_local || e.id) + "</h1>"
        + "<p class=sub style='margin:0 0 6px'><span class='pastilla p"
        + e.clasificacion_efectiva + "'>" + esc(e.nombre_clas) + "</span></p>"
        + "<p class=nota style='margin:0 0 18px'>Identificador del servidor: " + esc(e.id) + "</p>"
        + cuerpo(e, fotos)
        + "<p class=nota style='margin-top:24px;border-top:1px solid #E2E8F0;padding-top:12px'>"
        + "Triaje preliminar. La habilitación definitiva de una edificación es competencia "
        + "de UNGRD, Defensa Civil, bomberos y las alcaldías. Contiene datos personales "
        + "(Ley 1581 de 2012): no difundir.</p></body></html>";
      bajar("evaluacion-" + (e.id_local || e.id) + ".html", doc, "text/html;charset=utf-8");
    });
  };

  document.getElementById("f-json").onclick = function(){
    if (!actual) return;
    var e = actual;
    conFotos(e).then(function(datos){
      var copia = JSON.parse(JSON.stringify(e));
      copia.fotos = datos;
      bajar("evaluacion-" + (e.id_local || e.id) + ".json",
            JSON.stringify(copia, null, 1), "application/json");
    });
  };
})();
</script>
""".replace(
    # Catálogos del V2F resueltos al importar: el modal se inserta en tres
    # pantallas y no tiene sentido que las tres pasen el mismo diccionario.
    "__HAB__", json.dumps({str(k): v["nombre"] for k, v in v2f.HABITABILIDAD.items()},
                          ensure_ascii=False)
).replace("__PARC__", json.dumps(v2f.PARCIALES, ensure_ascii=False)
).replace("__CAT__", json.dumps(v2f.para_la_app(), ensure_ascii=False))


# ---------------------------------------------------------------------- entrar
ENTRAR = """
<h1>Administración</h1>
<p class="sub">Panel de coordinación de brigadas.</p>
{% if error %}<div class="aviso">{{ error }}</div>{% endif %}
<div class="tarjeta">
<form method="post" action="/admin/entrar">
  <label><span>Usuario</span>
    <input name="usuario" autocomplete="username" autofocus
           placeholder="Déjelo vacío si es la administración del sistema"></label>
  <label><span>Clave</span>
    <input type="password" name="clave" autocomplete="current-password" required></label>
  <button class="btn btn-p" style="width:100%">Entrar</button>
</form>
</div>
<p class="nota">Los inspectores no entran acá: su matrícula es una firma, no una cuenta.
Este panel es solo para quien coordina.</p>
"""


@router.get("/admin/entrar", response_class=HTMLResponse)
def entrar_form(req: Request):
    if leer_sesion(req.cookies.get("brigada_admin")):
        return RedirectResponse("/admin", 303)
    return pagina("Entrar", render(ENTRAR, error=None), sesion=False)


def autenticar_coordinador(usuario: str, clave: str):
    """Devuelve (brigada, nombre) o None. Solo coordinadores activos, y solo si
    su brigada sigue activa: revocar la brigada cierra también su coordinación."""
    filas = consulta("""SELECT c.brigada, c.nombre, c.clave_hash
                          FROM coordinador c JOIN brigada b ON b.nombre = c.brigada
                         WHERE c.usuario = %s AND c.activo AND b.activa""", (usuario,))
    if not filas:
        return None
    brigada, nombre, hash_guardado = filas[0]
    if not verificar_clave(clave, hash_guardado):
        return None
    consulta("UPDATE coordinador SET ultimo_acceso = now() WHERE usuario = %s", (usuario,))
    return brigada, nombre


@router.post("/admin/entrar")
def entrar(req: Request, clave: str = Form(...), usuario: str = Form("")):
    ip = ip_real(req)
    if limitar(ip):
        return pagina("Entrar", render(ENTRAR,
            error="Demasiados intentos. Espere diez minutos."), sesion=False)

    usuario = usuario.strip()
    if usuario:
        cred = autenticar_coordinador(usuario, clave)
        # Un solo mensaje para usuario inexistente y clave incorrecta: distinguirlos
        # permitiría averiguar qué usuarios existen.
        if not cred:
            intentos.setdefault(ip, []).append(time.time())
            return pagina("Entrar", render(ENTRAR, error="Usuario o clave incorrectos."),
                          sesion=False)
        rol, brigada, quien = "coordinador", cred[0], usuario
    else:
        if not clave_correcta(clave):
            intentos.setdefault(ip, []).append(time.time())
            return pagina("Entrar", render(ENTRAR, error="Clave incorrecta."), sesion=False)
        rol, brigada, quien = "admin", None, "administración"

    intentos.pop(ip, None)
    r = RedirectResponse("/admin", 303)
    r.set_cookie("brigada_admin",
                 firmar(int(time.time()) + DURACION_SESION, rol, brigada, quien),
                 max_age=DURACION_SESION, httponly=True, secure=True, samesite="strict")
    return r


@router.get("/admin/salir")
def salir():
    r = RedirectResponse("/admin/entrar", 303)
    r.delete_cookie("brigada_admin")
    return r


# ---------------------------------------------------------------------- resumen
INICIO = """
<h1>Resumen</h1>
<p class="sub">Estado de lo que han enviado las brigadas.</p>
<div class="cifras">
  <div class="cifra"><b class="num">{{ t.total }}</b><span>Evaluaciones recibidas</span></div>
  <div class="cifra c4"><b class="num">{{ t.peligro_colapso }}</b>
    <span>Peligro de colapso</span></div>
  <div class="cifra c3"><b class="num">{{ t.no_habitables }}</b><span>No habitables</span></div>
  <div class="cifra c2"><b class="num">{{ t.uso_restringido }}</b><span>Uso restringido</span></div>
  <div class="cifra c1"><b class="num">{{ t.habitables }}</b><span>Habitables</span></div>
  <div class="cifra {{ 'alerta' if t.sin_verificar }}"><b class="num">{{ t.sin_verificar }}</b>
    <span>Firmas fuera del registro</span></div>
  <a class="cifra" href="/admin/catastral" style="text-decoration:none;color:inherit">
    <b class="num">{{ t.sin_catastral }}</b><span>Sin código catastral →</span></a>
</div>
{% if rol == 'admin' and not d.ok %}
<div class="aviso"><strong>Disco:</strong> quedan {{ d.libre_gb }} GB libres
({{ d.usado_pct }}% usado). Si se llena, el servidor deja de recibir evaluaciones.
Revise si alguna brigada está enviando de más y, si hace falta, revoque su token.</div>
{% endif %}
{% if rol == 'admin' and (not r.ok or not r.reciente) %}
<div class="aviso"><strong>Respaldo:</strong> {{ r.mensaje or "sin información" }}.
{% if r.horas is defined %}Último intento hace {{ r.horas }} horas.{% endif %}
Mientras esto siga así, una pérdida del disco se lleva el levantamiento completo.</div>
{% elif rol == 'admin' %}
<div class="ok"><strong>Respaldo al día.</strong> Hace {{ r.horas }} horas · {{ r.mensaje }}{% if not r.cifrado %}
 · <strong>sin cifrar</strong>{% endif %}{% if not r.remoto %} · <strong>solo en este servidor</strong>{% endif %}.</div>
{% endif %}
{% if t.rojos_pendientes %}
<div class="{{ 'aviso' if t.rojos_vencidos else 'nota-caja' }}">
  <strong>{{ t.rojos_pendientes }} rojos</strong> esperan segunda revisión{% if t.rojos_vencidos %},
  y {{ t.rojos_vencidos }} ya pasaron su plazo{% endif %}.
  <a href="/admin/rojos">Revisarlos</a>.</div>
{% endif %}
{% if t.sin_verificar %}
<div class="aviso"><strong>{{ t.sin_verificar }} evaluaciones</strong> las firmó una matrícula que no
está en el registro. Se aceptaron para no perder trabajo de campo, pero hay que revisarlas antes de
consolidar. <a href="/admin/reportes?verificada=no">Verlas</a>.</div>
{% endif %}

<div class="tarjeta">
  <p class="rotulo">Por brigada</p>
  <div class="desplaza"><table>
  <thead><tr><th>Brigada</th><th>Evaluadas</th><th>Peligro de colapso</th>
    <th>No habitables</th><th>Uso restringido</th><th>Habitables</th>
    <th>Sin verificar</th><th>Última</th></tr></thead><tbody>
  {% for f in por_brigada %}<tr>
    <td>{{ f[0] or "— sin atribuir (token heredado)" }}</td>
    <td class="num">{{ f[1] }}</td><td class="num">{{ f[2] }}</td><td class="num">{{ f[3] }}</td>
    <td class="num">{{ f[4] }}</td><td class="num">{{ f[5] }}</td>
    <td class="num">{% if f[6] %}<span class="pastilla palerta">{{ f[6] }}</span>{% else %}0{% endif %}</td>
    <td class="num">{{ f[7].strftime("%Y-%m-%d %H:%M") if f[7] else "—" }}</td>
  </tr>{% else %}<tr><td colspan="8" class="vacio">Todavía no hay evaluaciones.</td></tr>{% endfor %}
  </tbody></table></div>
</div>

<div class="tarjeta">
  <p class="rotulo">Por sector · lo que se entrega a las autoridades</p>
  <div class="desplaza"><table>
  <thead><tr><th>Municipio</th><th>Barrio o vereda</th><th>Evaluadas</th>
    <th>Peligro de colapso</th><th>No habitables</th><th>Uso restringido</th>
    <th>Habitables</th></tr></thead><tbody>
  {% for f in consolidado %}<tr>
    <td>{{ f[0] or "—" }}</td><td>{{ f[1] or "—" }}</td><td class="num">{{ f[2] }}</td>
    <td class="num">{{ f[3] }}</td><td class="num">{{ f[4] }}</td><td class="num">{{ f[5] }}</td>
    <td class="num">{{ f[6] }}</td>
  </tr>{% else %}<tr><td colspan="7" class="vacio">Ningún sector llega todavía al mínimo de
    5 registros.</td></tr>{% endfor %}
  </tbody></table></div>
  <p class="nota">Esta es la vista <code>consolidado_publico</code>: agregada por sector y con
  k-anonimato de 5 registros. Los sectores con menos no aparecen, a propósito — con dos o tres
  evaluaciones, "el barrio" identifica el predio (Ley 1581 de 2012).</p>
</div>
"""


@router.get("/admin", response_class=HTMLResponse)
def inicio(req: Request):
    ses = exigir(req)
    w, wa = filtro_alcance(req)
    (total, colapso, nohab, restr, hab, sinv, sincat, rpend, rvenc), = consulta(f"""
        SELECT count(*), count(*) FILTER (WHERE clasificacion=4),
               count(*) FILTER (WHERE clasificacion=3),
               count(*) FILTER (WHERE clasificacion=2),
               count(*) FILTER (WHERE clasificacion=1),
               count(*) FILTER (WHERE NOT matricula_verificada),
               count(*) FILTER (WHERE cod_catastral IS NULL),
               count(*) FILTER (WHERE revision_estado = 'pendiente'),
               count(*) FILTER (WHERE revision_estado = 'pendiente'
                                  AND revision_vence < now())
          FROM evaluacion_brigada WHERE {w} AND vigente""", tuple(wa))
    por_brigada = consulta(f"""
        SELECT brigada_token, count(*), count(*) FILTER (WHERE clasificacion_efectiva=4),
               count(*) FILTER (WHERE clasificacion_efectiva=3),
               count(*) FILTER (WHERE clasificacion_efectiva=2),
               count(*) FILTER (WHERE clasificacion_efectiva=1),
               count(*) FILTER (WHERE NOT matricula_verificada), max(recibido_en)
          FROM evaluacion_brigada WHERE {w} AND vigente
         GROUP BY brigada_token ORDER BY count(*) DESC""", tuple(wa))
    # El consolidado por sector se recalcula con el alcance aplicado: la vista
    # consolidado_publico no distingue brigadas, y servirla tal cual le mostraria
    # a un coordinador los sectores de las demas.
    consolidado = [f[:7] for f in sectores(req)]
    t = {"total": total, "peligro_colapso": colapso, "no_habitables": nohab,
         "uso_restringido": restr, "habitables": hab,
         "sin_verificar": sinv, "sin_catastral": sincat,
         "rojos_pendientes": rpend, "rojos_vencidos": rvenc}
    import api_brigadas
    # El estado del servidor es cosa de quien lo administra, no de una brigada.
    salud = ({"r": api_brigadas.estado_respaldo(), "d": api_brigadas.estado_disco()}
             if ses.rol == "admin" else {"r": {"ok": True, "reciente": True, "horas": 0,
                                               "mensaje": "", "cifrado": True, "remoto": True},
                                         "d": {"ok": True}})
    return pagina("Resumen", render(INICIO, t=t, por_brigada=por_brigada,
                                    consolidado=consolidado, rol=ses.rol,
                                    r=salud["r"], d=salud["d"]), "inicio", ses=ses)


# --------------------------------------------------------------------- reportes
REPORTES = """
<h1>Reportes recibidos</h1>
<p class="sub">{{ total }} evaluaciones{{ " con los filtros aplicados" if filtrando else "" }}.</p>

<div class="tarjeta">
<form method="get" class="fila">
  {% if brigadas %}<label><span>Brigada</span><select name="brigada">
    <option value="">Todas</option>
    {% for b in brigadas %}<option value="{{ b }}" {{ 'selected' if b==f.brigada }}>{{ b }}</option>{% endfor %}
  </select></label>{% endif %}
  <label><span>Clasificación</span><select name="clas">
    <option value="">Todas</option>
    <option value="4" {{ 'selected' if f.clas=='4' }}>Peligro de colapso</option>
    <option value="3" {{ 'selected' if f.clas=='3' }}>No habitable</option>
    <option value="2" {{ 'selected' if f.clas=='2' }}>Uso restringido</option>
    <option value="1" {{ 'selected' if f.clas=='1' }}>Habitable</option>
  </select></label>
  <label><span>Municipio</span><input name="municipio" value="{{ f.municipio }}"></label>
  <label><span>Firma</span><select name="verificada">
    <option value="">Todas</option>
    <option value="no" {{ 'selected' if f.verificada=='no' }}>Fuera del registro</option>
    <option value="si" {{ 'selected' if f.verificada=='si' }}>Verificada</option>
  </select></label>
  <button class="btn btn-p">Filtrar</button>
</form>
</div>

<div class="tarjeta">
<div class="desplaza"><table>
<thead><tr><th>ID</th><th>Fecha</th><th>Clasificación</th><th>Dirección</th><th>Sector</th>
  <th>Firma</th><th>Brigada</th><th>Fotos</th></tr></thead><tbody>
{% for e in filas %}<tr onclick="abrirFicha('{{ e.id }}')" style="cursor:pointer"
   tabindex="0" onkeydown="if(event.key==='Enter')abrirFicha('{{ e.id }}')"
   title="Abrir la evaluación completa">
  <td class="num">{{ e.id_local or "—" }}<br>
      <span class="nota" title="Identificador canónico del servidor">{{ e.id[:10] }}…</span></td>
  <td class="num">{{ e.ts.strftime("%Y-%m-%d %H:%M") }}</td>
  <td><span class="pastilla p{{ e.clas }}">{{ e.nombre_clas }}</span>
      {% if e.modificada %}<br><span class="pastilla pn" title="{{ e.justificacion }}">modificada</span>{% endif %}</td>
  <td>{{ e.direccion or "—" }}{% if e.geo %}<br><span class="nota">{{ e.geo }}</span>{% endif %}</td>
  <td>{{ e.municipio or "—" }}{{ " · " + e.barrio if e.barrio }}</td>
  <td>{{ e.inspector or "—" }}<br><span class="pastilla {{ 'pi' if (e.verificada and e.firma_tipo == 'matricula') else 'palerta' }}">
      {% if e.firma_tipo == 'matricula' %}{{ e.matricula }}{{ "" if e.verificada else " · sin registrar" }}
      {% else %}doc. {{ e.documento }} · sin matrícula{% endif %}</span></td>
  <td>{{ e.brigada_token or "—" }}</td>
  <td class="num">{{ e.fotos }}</td>
</tr>{% else %}<tr><td colspan="8" class="vacio">Nada que mostrar con esos filtros.</td></tr>{% endfor %}
</tbody></table></div>
<div class="pag">
  {% if pagina_n > 1 %}<a class="btn" href="?{{ qs }}&pag={{ pagina_n-1 }}">Anteriores</a>{% endif %}
  <span>Página {{ pagina_n }} de {{ paginas }}</span>
  {% if pagina_n < paginas %}<a class="btn" href="?{{ qs }}&pag={{ pagina_n+1 }}">Siguientes</a>{% endif %}
</div>
</div>
<p class="nota">Toque una fila para abrir la evaluación completa, con sus fotos, y
exportarla.</p>
""" + MODAL_HTML + """
<p class="nota">Esta pantalla muestra dirección y coordenadas, que son dato personal
(Ley 1581 de 2012). Sirve para coordinar la brigada; lo que se entrega a las autoridades
es el consolidado por sector del Resumen, nunca este listado.</p>
"""
# Los nombres salen del catálogo del V2F: una sola fuente para el papel, el panel
# y la API. El color quedó en la interfaz, que es donde ayuda.
NOMBRE_CLAS = {k: v["nombre"] for k, v in v2f.HABITABILIDAD.items()}
POR_PAGINA = 50


@router.get("/admin/reportes", response_class=HTMLResponse)
def reportes(req: Request, brigada: str = "", clas: str = "", municipio: str = "",
             verificada: str = "", pag: int = 1):
    ses = exigir(req)
    w, wa = filtro_alcance(req)
    donde, args = [w], list(wa)
    # Un coordinador no puede pedir otra brigada por parametro: su alcance ya
    # esta en el WHERE y este filtro solo puede estrecharlo, nunca ampliarlo.
    if brigada and ses.rol == "admin":
        donde.append("brigada_token = %s"); args.append(brigada)
    if clas in ("1", "2", "3"):
        donde.append("clasificacion = %s"); args.append(int(clas))
    if municipio:
        donde.append("municipio ILIKE %s"); args.append(f"%{municipio}%")
    if verificada == "no":
        donde.append("NOT matricula_verificada")
    elif verificada == "si":
        donde.append("matricula_verificada")
    w = " AND ".join(donde)

    (total,), = consulta(f"SELECT count(*) FROM evaluacion_brigada WHERE {w}", tuple(args))
    paginas = max(1, -(-total // POR_PAGINA))
    pag = min(max(1, pag), paginas)
    crudas = consulta(f"""
        SELECT id, ts, clasificacion, clasificacion_auto, justificacion, direccion, municipio,
               barrio, inspector, matricula, matricula_verificada, firma_tipo,
               documento, profesion, brigada_token,
               coalesce(jsonb_array_length(fotos),0), ST_Y(geom), ST_X(geom), id_local
          FROM evaluacion_brigada WHERE {w}
         ORDER BY ts DESC LIMIT %s OFFSET %s""",
        tuple(args) + (POR_PAGINA, (pag - 1) * POR_PAGINA))
    filas = [{
        "id": r[0], "ts": r[1], "clas": r[2], "nombre_clas": NOMBRE_CLAS.get(r[2], "?"),
        "modificada": r[3] is not None and r[2] != r[3], "justificacion": r[4] or "",
        "direccion": r[5], "municipio": r[6], "barrio": r[7], "inspector": r[8],
        "matricula": r[9], "verificada": r[10], "firma_tipo": r[11],
        "documento": r[12], "profesion": r[13],
        "brigada_token": r[14], "fotos": r[15],
        "geo": (f"{r[16]:.5f}, {r[17]:.5f}" if r[16] is not None else ""),
        "id_local": r[18],
    } for r in crudas]
    brigadas = ([b for (b,) in consulta("SELECT nombre FROM brigada ORDER BY nombre")]
                if ses.rol == "admin" else [])
    qs = f"brigada={brigada}&clas={clas}&municipio={municipio}&verificada={verificada}"
    f = {"brigada": brigada, "clas": clas, "municipio": municipio, "verificada": verificada}
    return pagina("Reportes", render(REPORTES, filas=filas, total=total, brigadas=brigadas,
                                     f=f, filtrando=any(f.values()), pagina_n=pag,
                                     paginas=paginas, qs=qs), "reportes", ses=ses)


# --------------------------------------------------------------------- brigadas
BRIGADAS = """
<h1>Brigadas</h1>
<p class="sub">Cada brigada tiene un token. Ese token es lo que atribuye cada evaluación.</p>
{% if clave_nueva %}
<div class="ok"><strong>Coordinador «{{ usuario_nuevo }}» creado.</strong> Esta es su clave,
y esta es la única vez que se muestra: la base guarda solo su hash.
<div class="token">{{ clave_nueva }}</div>
Entra en esta misma dirección poniendo <strong>{{ usuario_nuevo }}</strong> en Usuario.
Entréguesela por un canal razonable, no por un grupo.</div>
{% endif %}
{% if token_nuevo %}
<div class="ok"><strong>Token de «{{ nombre_nuevo }}».</strong> Esta es la única vez que se
muestra: la base guarda solo su sha256. Si acaba de reemitirlo, el anterior dejó de servir
y hay que reconfigurar los teléfonos de esa brigada.
<div class="token">{{ token_nuevo }}</div>
Entrégueselo ahora a quien coordina esa brigada. Si se pierde, hay que emitir uno nuevo.</div>
{% endif %}
{% if error %}<div class="aviso">{{ error }}</div>{% endif %}

<div class="tarjeta">
  <p class="rotulo">Registrar una brigada</p>
  <form method="post" action="/admin/brigadas" class="fila">
    <label><span>Nombre</span><input name="nombre" required placeholder="Universidad Nacional"></label>
    <label><span>Contacto</span><input name="contacto" placeholder="coord@unal.edu.co"></label>
    <button class="btn btn-p">Registrar y generar token</button>
  </form>
</div>

<div class="tarjeta">
<div class="desplaza"><table>
<thead><tr><th>Brigada</th><th>Estado</th><th>Quién puede firmar</th><th>Contacto</th>
  <th>Inspectores</th><th>Evaluaciones</th><th>Desde</th><th></th></tr></thead><tbody>
{% for b in filas %}<tr>
  <td><strong>{{ b[0] }}</strong></td>
  <td><span class="pastilla {{ 'pi' if b[1] else 'pn' }}">{{ "Activa" if b[1] else "Revocada" }}</span></td>
  <td>
    <form method="post" action="/admin/brigadas/firma" style="display:flex;gap:8px;align-items:center"
      onsubmit="return confirm({{ ('Permitir que en ' ~ b[0] ~ ' firme quien no tiene matrícula? Quedará registrado en cada evaluación con su documento y su profesión.') | tojson if b[6] else ('Exigir matrícula en ' ~ b[0] ~ '? Los teléfonos sin matrícula dejarán de poder guardar.') | tojson }})">
      <input type="hidden" name="nombre" value="{{ b[0] }}">
      <input type="hidden" name="exige" value="{{ '0' if b[6] else '1' }}">
      <span class="pastilla {{ 'pi' if b[6] else 'palerta' }}">
        {{ "Solo con matrícula" if b[6] else "También sin matrícula" }}</span>
      <button class="btn btn-s">Cambiar</button>
    </form>
    {% if b[7] %}<span class="nota" style="margin:0">{{ b[7] }} firmadas sin matrícula</span>{% endif %}
  </td>
  <td>{{ b[2] or "—" }}</td><td class="num">{{ b[3] }}</td><td class="num">{{ b[4] }}</td>
  <td class="num">{{ b[5] }}</td>
  <td>{% if b[1] %}<div style="display:flex;gap:8px;flex-wrap:wrap">
      <form method="post" action="/admin/brigadas/reemitir"
        onsubmit="return confirm('Emitir un token nuevo para {{ b[0] }}? El actual deja de servir y hay que reconfigurar sus teléfonos.')">
        <input type="hidden" name="nombre" value="{{ b[0] }}">
        <button class="btn btn-r" style="color:var(--azul);border-color:var(--borde);background:var(--carta)">
          Reemitir token</button></form>
      <form method="post" action="/admin/brigadas/baja"
        onsubmit="return confirm('Revocar el token de {{ b[0] }}? Sus teléfonos dejan de sincronizar de inmediato.')">
        <input type="hidden" name="nombre" value="{{ b[0] }}">
        <button class="btn btn-r">Revocar token</button></form>
      </div>{% endif %}</td>
</tr>{% else %}<tr><td colspan="8" class="vacio">No hay brigadas registradas.</td></tr>{% endfor %}
</tbody></table></div>
</div>

{% if filas %}
<div class="tarjeta">
  <p class="rotulo">Quién coordina cada brigada</p>
  <p class="nota" style="margin:0 0 16px">Un coordinador entra en esta misma dirección
    llenando el campo <strong>Usuario</strong>, y ve <strong>solo su brigada</strong>:
    su resumen, su mapa, sus reportes, sus rojos y sus inspectores. No puede emitir
    tokens, ver otras brigadas ni el estado del servidor.</p>

  {% for b in filas if b[1] %}
  <div style="border-top:1px solid var(--linea);padding-top:14px;margin-top:14px">
    <p style="font-weight:600;margin:0 0 8px">{{ b[0] }}</p>
    {% for c in coordinadores.get(b[0], []) %}
      <div style="display:flex;gap:12px;align-items:center;margin-bottom:8px">
        <span class="pastilla {{ 'pi' if c.activo else 'pn' }}">{{ c.usuario }}</span>
        <span style="font-size:14px;color:var(--tinta2)">{{ c.nombre }}</span>
        {% if c.activo %}
        <form method="post" action="/admin/coordinadores/baja" style="margin-left:auto"
              onsubmit="return confirm('Dar de baja a {{ c.usuario }}? Su sesión se cierra en el acto.')">
          <input type="hidden" name="usuario" value="{{ c.usuario }}">
          <button class="btn btn-r">Dar de baja</button></form>
        {% endif %}
      </div>
    {% else %}
      <p class="nota" style="margin:0 0 8px">Todavía nadie coordina esta brigada.</p>
    {% endfor %}
    <form method="post" action="/admin/coordinadores" class="fila" style="margin-top:10px">
      <input type="hidden" name="brigada" value="{{ b[0] }}">
      <label><span>Usuario</span><input name="usuario" required placeholder="coord.unal"></label>
      <label><span>Nombre</span><input name="nombre" required placeholder="Ana Ruiz"></label>
      <button class="btn">Crear coordinador</button>
    </form>
  </div>
  {% endfor %}
</div>
{% endif %}
<p class="nota">Revocar corta el token en el acto, pero no borra nada: las evaluaciones que esa
brigada ya envió siguen en la base y siguen atribuidas a ella.</p>
"""


def _coordinadores_por_brigada():
    filas = consulta("""SELECT brigada, usuario, nombre, activo
                          FROM coordinador ORDER BY activo DESC, usuario""")
    por = {}
    for brigada, usuario, nombre, activo in filas:
        por.setdefault(brigada, []).append({"usuario": usuario, "nombre": nombre,
                                            "activo": activo})
    return por


def _brigadas_filas():
    return consulta("""
        SELECT b.nombre, b.activa, b.contacto,
               (SELECT count(*) FROM inspector i WHERE i.brigada=b.nombre AND i.vigente),
               (SELECT count(*) FROM evaluacion_brigada e WHERE e.brigada_token=b.nombre),
               b.creada_en::date, b.exige_matricula,
               (SELECT count(*) FROM evaluacion_brigada e
                 WHERE e.brigada_token=b.nombre AND e.firma_tipo <> 'matricula')
          FROM brigada b ORDER BY b.activa DESC, b.nombre""")


def _pantalla_brigadas(ses, *, token=None, nombre=None, clave=None, usuario=None, error=None):
    return pagina("Brigadas", render(BRIGADAS, filas=_brigadas_filas(),
                                     coordinadores=_coordinadores_por_brigada(),
                                     token_nuevo=token, nombre_nuevo=nombre,
                                     clave_nueva=clave, usuario_nuevo=usuario,
                                     error=error), "brigadas", ses=ses)


@router.get("/admin/brigadas", response_class=HTMLResponse)
def brigadas_ver(req: Request):
    ses = exigir_admin(req)
    return _pantalla_brigadas(ses)


@router.post("/admin/brigadas", response_class=HTMLResponse)
def brigadas_alta(req: Request, nombre: str = Form(...), contacto: str = Form("")):
    ses = exigir_admin(req)
    import api_brigadas
    nombre, contacto = nombre.strip(), contacto.strip() or None
    token = secrets.token_hex(24)
    error = None
    try:
        consulta("INSERT INTO brigada (nombre, token_hash, contacto) VALUES (%s,%s,%s)",
                 (nombre, api_brigadas.sha(token), contacto))
    except Exception:
        token, error = None, f"Ya existe una brigada llamada «{nombre}»."
    return _pantalla_brigadas(ses, token=token, nombre=nombre, error=error)


@router.post("/admin/brigadas/firma", response_class=HTMLResponse)
def brigadas_firma(req: Request, nombre: str = Form(...), exige: str = Form(...)):
    """Si esta brigada admite que firme quien no tiene matrícula.

    Es una decisión de quien administra la brigada, no del sistema: las
    comisiones reales no siempre son de ingenieros matriculados, y rechazar en el
    servidor deja el trabajo de esa jornada encerrado en un teléfono. Lo que el
    sistema sí garantiza es que quede registrado evaluación por evaluación —con
    documento y profesión— y que la segunda revisión de un desalojo siga siendo
    de alguien del registro.
    """
    ses = exigir_admin(req)
    consulta("UPDATE brigada SET exige_matricula = %s WHERE nombre = %s",
             (exige == "1", nombre))
    return _pantalla_brigadas(ses)


@router.post("/admin/brigadas/reemitir", response_class=HTMLResponse)
def brigadas_reemitir(req: Request, nombre: str = Form(...)):
    """El token se muestra una sola vez; si se perdió, se emite otro. El anterior
    deja de servir en el acto: hay que reconfigurar los teléfonos de esa brigada."""
    ses = exigir_admin(req)
    import api_brigadas
    token = secrets.token_hex(24)
    hecho = consulta("""UPDATE brigada SET token_hash = %s
                         WHERE nombre = %s AND activa RETURNING nombre""",
                     (api_brigadas.sha(token), nombre))
    if not hecho:
        return _pantalla_brigadas(ses, error="Esa brigada no existe o está revocada.")
    return _pantalla_brigadas(ses, token=token, nombre=nombre)


@router.post("/admin/brigadas/baja")
def brigadas_baja(req: Request, nombre: str = Form(...)):
    exigir_admin(req)
    consulta("UPDATE brigada SET activa=false WHERE nombre=%s", (nombre,))
    return RedirectResponse("/admin/brigadas", 303)


# ------------------------------------------------------------------ inspectores
INSPECTORES = """
<h1>Inspectores</h1>
<p class="sub">Quién puede firmar. No tienen cuenta ni clave: la matrícula es la firma.</p>
{% if error %}<div class="aviso">{{ error }}</div>{% endif %}
{% if aviso %}<div class="ok">{{ aviso }}</div>{% endif %}

<div class="tarjeta">
  <p class="rotulo">Registrar un inspector</p>
  <form method="post" action="/admin/inspectores" class="fila">
    <label><span>Matrícula profesional</span><input name="matricula" required placeholder="25101-COPNIA"></label>
    <label><span>Nombre completo</span><input name="nombre" required></label>
    <label><span>Brigada</span><select name="brigada" required>
      {% for b in brigadas %}<option value="{{ b }}">{{ b }}</option>{% endfor %}
    </select></label>
    <label><span>Matrícula verificada ante COPNIA</span><select name="copnia">
      <option value="">Todavía no</option><option value="si">Sí, verificada</option>
    </select></label>
    <button class="btn btn-p">Registrar</button>
  </form>
  {% if not brigadas %}<p class="nota">Registre primero una brigada.</p>{% endif %}
</div>

<div class="tarjeta">
<div class="desplaza"><table>
<thead><tr><th>Matrícula</th><th>Nombre</th><th>Brigada</th><th>Estado</th><th>COPNIA</th>
  <th>Evaluaciones</th><th></th></tr></thead><tbody>
{% for i in filas %}<tr>
  <td class="num"><strong>{{ i[0] }}</strong></td><td>{{ i[1] }}</td><td>{{ i[2] or "—" }}</td>
  <td><span class="pastilla {{ 'pi' if i[3] else 'pn' }}">{{ "Vigente" if i[3] else "De baja" }}</span></td>
  <td>{% if i[4] %}<span class="pastilla pi">Verificada</span>{% else %}
      <span class="pastilla pn">Sin verificar</span>{% endif %}</td>
  <td class="num">{{ i[5] }}</td>
  <td>{% if i[3] %}<form method="post" action="/admin/inspectores/baja"
      onsubmit="return confirm('Dar de baja a {{ i[1] }}? Lo que ya firmó no cambia.')">
      <input type="hidden" name="matricula" value="{{ i[0] }}">
      <button class="btn btn-r">Dar de baja</button></form>{% endif %}</td>
</tr>{% else %}<tr><td colspan="7" class="vacio">No hay inspectores registrados.</td></tr>{% endfor %}
</tbody></table></div>
</div>
<p class="nota">Una evaluación firmada por alguien fuera del registro <strong>no se rechaza</strong>:
entra marcada y queda en la cola de revisión. Perder trabajo de campo en una emergencia es peor que
aceptarlo pendiente. Al registrar a esa persona, sus evaluaciones anteriores se reconcilian solas.</p>
"""


def _inspectores_filas(req: Request):
    w, wa = filtro_alcance(req, "i.brigada")
    return consulta(f"""
        SELECT i.matricula, i.nombre, i.brigada, i.vigente, i.verificada_copnia,
               (SELECT count(*) FROM evaluacion_brigada e WHERE e.matricula=i.matricula)
          FROM inspector i WHERE {w}
         ORDER BY i.vigente DESC, i.brigada, i.nombre""", tuple(wa))


def _brigadas_activas(req: Request):
    """Un coordinador solo puede dar de alta gente en SU brigada."""
    b = alcance_brigada(req)
    if b:
        return [b]
    return [x for (x,) in consulta("SELECT nombre FROM brigada WHERE activa ORDER BY nombre")]


@router.get("/admin/inspectores", response_class=HTMLResponse)
def inspectores_ver(req: Request):
    ses = exigir(req)
    return pagina("Inspectores", render(INSPECTORES, filas=_inspectores_filas(req),
                                        brigadas=_brigadas_activas(req), error=None, aviso=None),
                  "inspectores", ses=ses)


@router.post("/admin/inspectores", response_class=HTMLResponse)
def inspectores_alta(req: Request, matricula: str = Form(...), nombre: str = Form(...),
                     brigada: str = Form(...), copnia: str = Form("")):
    ses = exigir(req)
    # La brigada no se acepta como viene: se fuerza a la del alcance.
    permitidas = _brigadas_activas(req)
    if brigada not in permitidas:
        return pagina("Inspectores",
                      render(INSPECTORES, filas=_inspectores_filas(req), brigadas=permitidas,
                             error="No puede registrar inspectores en esa brigada.", aviso=None),
                      "inspectores", ses=ses)
    matricula, nombre = matricula.strip(), nombre.strip()
    consulta("""INSERT INTO inspector (matricula, nombre, brigada, verificada_copnia)
                VALUES (%s,%s,%s,%s)
                ON CONFLICT (matricula) DO UPDATE
                  SET nombre=EXCLUDED.nombre, brigada=EXCLUDED.brigada,
                      verificada_copnia=EXCLUDED.verificada_copnia, vigente=true""",
             (matricula, nombre, brigada, copnia == "si"))
    # Reconcilia lo que esa persona ya había enviado antes de estar en el registro.
    n = consulta("""UPDATE evaluacion_brigada SET matricula_verificada=true
                     WHERE matricula=%s AND NOT matricula_verificada RETURNING id""", (matricula,))
    aviso = f"Inspector {matricula} ({nombre}) registrado en «{brigada}»."
    if n:
        aviso += f" Se reconciliaron {len(n)} evaluaciones suyas que estaban sin verificar."
    return pagina("Inspectores", render(INSPECTORES, filas=_inspectores_filas(req),
                                        brigadas=_brigadas_activas(req), error=None, aviso=aviso),
                  "inspectores", ses=ses)


@router.post("/admin/inspectores/baja")
def inspectores_baja(req: Request, matricula: str = Form(...)):
    exigir(req)
    consulta("UPDATE inspector SET vigente=false WHERE matricula=%s", (matricula,))
    return RedirectResponse("/admin/inspectores", 303)


# ------------------------------------------------------------------ solicitudes
SOLICITUDES = """
<h1>Solicitudes de información</h1>
<p class="sub">Lo que llega por el formulario de la página pública.</p>
<div class="tarjeta">
<div class="desplaza"><table>
<thead><tr><th>Recibida</th><th>Quién</th><th>Entidad</th><th>Contacto</th>
  <th>Mensaje</th><th></th></tr></thead><tbody>
{% for s in filas %}<tr>
  <td class="num">{{ s[1].strftime("%Y-%m-%d %H:%M") }}</td>
  <td>{{ s[2] }}</td><td>{{ s[3] }}</td>
  <td><a href="mailto:{{ s[4] }}">{{ s[4] }}</a>{% if s[5] %}<br>{{ s[5] }}{% endif %}</td>
  <td>{{ s[6] or "—" }}</td>
  <td>{% if s[7] %}<span class="pastilla pn">Atendida</span>{% else %}
    <form method="post" action="/admin/solicitudes/atender">
      <input type="hidden" name="id" value="{{ s[0] }}">
      <button class="btn btn-r" style="color:var(--azul);border-color:var(--borde);background:var(--carta)">
        Marcar atendida</button></form>{% endif %}</td>
</tr>{% else %}<tr><td colspan="6" class="vacio">Todavía no hay solicitudes.</td></tr>{% endfor %}
</tbody></table></div>
</div>
<p class="nota">Estos son datos personales de un funcionario, entregados con autorización
para una finalidad concreta: responder su solicitud. No se usan para nada más, y quien
lo pida tiene derecho a que se eliminen (Ley 1581 de 2012).</p>
"""


@router.get("/admin/solicitudes", response_class=HTMLResponse)
def solicitudes(req: Request):
    exigir_admin(req)
    filas = consulta("""SELECT id, recibido_en, nombre, entidad, correo, telefono,
                               mensaje, atendido
                          FROM contacto ORDER BY atendido, recibido_en DESC LIMIT 200""")
    return pagina("Solicitudes", render(SOLICITUDES, filas=filas), "solicitudes")


@router.post("/admin/solicitudes/atender")
def solicitud_atender(req: Request, id: int = Form(...)):
    exigir_admin(req)
    consulta("UPDATE contacto SET atendido = true WHERE id = %s", (id,))
    return RedirectResponse("/admin/solicitudes", 303)


# ------------------------------------------------------------ doble revisión
ROJOS = """
<h1>Pendientes de segunda revisión</h1>
<p class="sub">No habitable y peligro de colapso ordenan desalojar. Antes de
consolidarlos, otro inspector registrado tiene que mirarlos. El peligro de colapso va
primero: no solo vacía el edificio, también compromete la vía y a los vecinos.</p>

{% if error %}<div class="aviso">{{ error }}</div>{% endif %}
{% if aviso %}<div class="ok">{{ aviso }}</div>{% endif %}

{% if not inspectores %}
<div class="aviso">No hay inspectores vigentes en el registro, así que no hay quién
revise. Registre al menos uno en <a href="/admin/inspectores">Inspectores</a>.</div>
{% endif %}

{% for r in filas %}
<div class="tarjeta" style="{{ 'border-color:#FECACA' if r.vencido }}">
  <div style="display:flex;gap:14px;align-items:baseline;flex-wrap:wrap">
    <span class="pastilla p{{ r.clas }}">{{ r.nombre_clas|upper }}</span>
    <strong>{{ r.id_local or r.id }}</strong>
    <span class="nota" style="margin:0">{{ r.ts.strftime("%Y-%m-%d %H:%M") }}</span>
    {% if r.vencido %}
      <span class="pastilla palerta">Atrasado {{ r.horas }} h</span>
    {% else %}
      <span class="pastilla pi">Vence en {{ -r.horas }} h</span>
    {% endif %}
  </div>

  <table style="margin-top:14px">
    <tr><td style="width:22%"><strong>Dónde</strong></td>
        <td>{{ r.direccion or "—" }}{% if r.municipio %} · {{ r.municipio }}{% endif %}
            {% if r.barrio %} · {{ r.barrio }}{% endif %}</td></tr>
    <tr><td><strong>Quién firmó</strong></td>
        <td>{{ r.inspector or "—" }} · matrícula {{ r.matricula }}
            {% if r.brigada_token %}<br><span class="nota" style="margin:0">{{ r.brigada_token }}</span>{% endif %}</td></tr>
    {% if r.justificacion %}<tr><td><strong>Cambió el semáforo</strong></td>
        <td>{{ r.justificacion }}</td></tr>{% endif %}
    {% if r.observaciones %}<tr><td><strong>Observaciones</strong></td>
        <td>{{ r.observaciones }}</td></tr>{% endif %}
  </table>

  {% if r.fotos %}
  <div class="fotos-ficha" style="margin-top:14px">
    {% for i in range(r.fotos) %}
      <figure class="foto-marco" style="margin:0">
        <img loading="lazy" src="/admin/foto/{{ r.id }}/{{ i }}"
             alt="Fotografía {{ i + 1 }} de la evaluación {{ r.id_local or r.id }}">
        <figcaption class="foto-marca">{{ r.id_local or r.id }} · foto {{ i + 1 }}<br>{{ r.id }}</figcaption>
      </figure>
    {% endfor %}
  </div>
  {% else %}
  <p class="nota">Esta evaluación se guardó sin fotografías.</p>
  {% endif %}
  <p class="nota"><a href="#" onclick="abrirFicha('{{ r.id }}');return false">Ver la
    evaluación completa</a> — con el detalle del daño y la opción de exportarla.</p>

  <form method="post" action="/admin/rojos/revisar" style="margin-top:16px"
        onsubmit="return confirm('¿Registrar esta revisión? Queda con la matrícula de quien revisa.')">
    <input type="hidden" name="id" value="{{ r.id }}">
    <div class="fila">
      <label><span>Quién revisa</span><select name="matricula" required>
        <option value="">Seleccione</option>
        {% for i in inspectores %}
          {# Quien firmó no puede revisarse a sí mismo: si no, no hay segunda mirada. #}
          {% if i[0] != r.matricula %}<option value="{{ i[0] }}">{{ i[1] }} · {{ i[0] }}</option>{% endif %}
        {% endfor %}
      </select></label>
      <label><span>Resultado</span><select name="resultado" required>
        <option value="confirmado">Confirmar la clasificación</option>
        {% if r.clas == 4 %}<option value="3">Revocar → No habitable</option>{% endif %}
        <option value="2">Revocar → Uso restringido</option>
        <option value="1">Revocar → Habitable</option>
      </select></label>
      <label><span>Motivo</span><input name="motivo" placeholder="Criterio técnico"></label>
      <button class="btn btn-p">Registrar revisión</button>
    </div>
  </form>
</div>
{% else %}
<div class="tarjeta"><p class="vacio" style="margin:0">No hay evaluaciones esperando
  segunda revisión.</p></div>
{% endfor %}

<p class="nota">Revocar no borra nada: la clasificación firmada queda tal cual y se
guarda aparte quién revisó, cuándo y por qué. Lo que cambia es la clasificación
efectiva, que es la que usan el consolidado y la API.</p>
<p class="nota">El vencimiento no degrada nada. Un peligro de colapso atrasado sigue
siendo peligro de colapso: solo aparece marcado, para que nadie lo dé por revisado sin
estarlo. Un temporizador no puede rebajar un desalojo.</p>
""" + MODAL_HTML + """
"""


def _rojos(req: Request):
    w, wa = filtro_alcance(req)
    crudas = consulta(f"""SELECT id, id_local, ts, matricula, inspector, brigada_token,
                                direccion, municipio, barrio, observaciones,
                                justificacion, vencido, horas_de_atraso, clasificacion,
                                (SELECT coalesce(jsonb_array_length(e.fotos), 0)
                                   FROM evaluacion_brigada e WHERE e.id = rojos_pendientes.id)
                           FROM rojos_pendientes WHERE {w} LIMIT 100""", tuple(wa))
    return [{"id": r[0], "id_local": r[1], "ts": r[2], "matricula": r[3],
             "inspector": r[4], "brigada_token": r[5], "direccion": r[6],
             "municipio": r[7], "barrio": r[8], "observaciones": r[9],
             "justificacion": r[10], "vencido": r[11],
             "horas": round(r[12]) if r[12] is not None else 0,
             "clas": r[13], "nombre_clas": NOMBRE_CLAS.get(r[13], "?"),
             "fotos": r[14]} for r in crudas]


def _inspectores_vigentes(req: Request):
    w, wa = filtro_alcance(req, "brigada")
    return consulta(f"SELECT matricula, nombre FROM inspector "
                    f"WHERE vigente AND {w} ORDER BY nombre", tuple(wa))


@router.get("/admin/rojos", response_class=HTMLResponse)
def rojos(req: Request):
    ses = exigir(req)
    return pagina("Segunda revisión", render(ROJOS, filas=_rojos(req),
                                  inspectores=_inspectores_vigentes(req),
                                  error=None, aviso=None), "rojos", ses=ses)


@router.post("/admin/rojos/revisar", response_class=HTMLResponse)
def rojos_revisar(req: Request, id: str = Form(...), matricula: str = Form(...),
                  resultado: str = Form(...), motivo: str = Form("")):
    ses = exigir(req)
    error = aviso = None
    w, wa = filtro_alcance(req)
    # El alcance va en el WHERE: sin esto, un coordinador podria revisar el rojo
    # de otra brigada mandando su id a mano.
    firmo = consulta(f"SELECT matricula FROM evaluacion_brigada WHERE id = %s AND {w}",
                     (id, *wa))
    if not firmo:
        error = "Esa evaluación no existe o no pertenece a su brigada."
    elif firmo[0][0] == matricula:
        # Cinturón además del tirante: la lista ya excluye al firmante, pero esto
        # es lo que impide que alguien lo fuerce desde fuera del formulario.
        error = "Quien firmó no puede revisar su propia evaluación."
    elif resultado != "confirmado" and not motivo.strip():
        error = "Revocar una clasificación exige escribir el motivo."
    else:
        nueva = None if resultado == "confirmado" else int(resultado)
        consulta("""UPDATE evaluacion_brigada
                       SET revision_estado = %s, revision_matricula = %s,
                           revision_en = now(), revision_clasificacion = %s,
                           revision_motivo = %s
                     WHERE id = %s AND revision_estado = 'pendiente'""",
                 ("confirmado" if nueva is None else "revocado", matricula,
                  nueva, motivo.strip() or None, id))
        aviso = ("Clasificación confirmada." if nueva is None else
                 f"Revocada a «{NOMBRE_CLAS[nueva].lower()}». La clasificación firmada "
                 "queda registrada igual.")
    return pagina("Segunda revisión", render(ROJOS, filas=_rojos(req),
                                  inspectores=_inspectores_vigentes(req),
                                  error=error, aviso=aviso), "rojos", ses=ses)


# ------------------------------------------------------------------- el mapa
# Rampa secuencial de un solo tono para el % de rojas. Validada: monotona en
# luminosidad, saltos visibles entre pasos, y el extremo claro se despega del
# blanco de la tarjeta (2,25:1). No se toca sin volver a validarla.
RAMPA_ROJAS = ["#F19393", "#E56A6A", "#D13A3A", "#A81A1A", "#751010"]
CORTES_ROJAS = [0.10, 0.25, 0.50, 0.75]   # % de rojas que separa cada paso

# Teselas del mapa base. Configurable para que una entidad pueda apuntar a su
# propio servidor o al geoportal municipal en vez de a un tercero.
TESELAS = os.getenv("BRIGADA_TESELAS", "https://tile.openstreetmap.org/{z}/{x}/{y}.png")
TESELAS_CREDITO = os.getenv(
    "BRIGADA_TESELAS_CREDITO",
    '&copy; colaboradores de <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a>')

# Ortofoto y rótulos para las vistas satélite e híbrida. Después de un sismo la
# imagen aérea es la referencia que la gente reconoce —techos, patios, manzanas—
# mucho antes que el callejero.
#
# Pedir teselas revela a ese proveedor qué zona se está mirando, igual que ya
# ocurre con OpenStreetMap. No viaja ningún dato de las evaluaciones: los puntos
# se dibujan en el navegador sobre la imagen. Aun así, una entidad que no quiera
# depender de un tercero apunta estas variables a su propio geoportal.
TESELAS_SAT = os.getenv(
    "BRIGADA_TESELAS_SAT",
    "https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/"
    "MapServer/tile/{z}/{y}/{x}")
TESELAS_ROTULOS = os.getenv(
    "BRIGADA_TESELAS_ROTULOS",
    "https://server.arcgisonline.com/ArcGIS/rest/services/Reference/"
    "World_Boundaries_and_Places/MapServer/tile/{z}/{y}/{x}")
TESELAS_SAT_CREDITO = os.getenv(
    "BRIGADA_TESELAS_SAT_CREDITO",
    "Imágenes &copy; Esri, Maxar, Earthstar Geographics")


def alcance_brigada(req: Request) -> str | None:
    """Qué brigada puede ver quien está mirando. None = todas (administrador).

    Es el único punto donde se decide el alcance: cada consulta del panel lo
    consulta a través de `filtro_alcance()`."""
    return exigir(req).brigada


def filtro_alcance(req: Request, columna: str = "brigada_token"):
    """Devuelve (fragmento_sql, args) para intercalar en cualquier WHERE."""
    b = alcance_brigada(req)
    return (f"{columna} = %s", [b]) if b else ("1=1", [])


def sectores(req: Request, brigada: str | None = None):
    """Agregado por sector, con el mismo umbral de anonimato del consolidado."""
    alcance = alcance_brigada(req) or brigada
    donde, args = "1=1", []
    if alcance:
        donde, args = "brigada_token = %s", [alcance]
    return consulta(f"""
        SELECT municipio, barrio, count(*),
               count(*) FILTER (WHERE clasificacion_efectiva = 4),
               count(*) FILTER (WHERE clasificacion_efectiva = 3),
               count(*) FILTER (WHERE clasificacion_efectiva = 2),
               count(*) FILTER (WHERE clasificacion_efectiva = 1),
               count(*) FILTER (WHERE revision_estado = 'pendiente'),
               ST_X(ST_Centroid(ST_Collect(geom))), ST_Y(ST_Centroid(ST_Collect(geom))),
               max(recibido_en)
          FROM evaluacion_brigada
         WHERE {donde} AND vigente
         GROUP BY municipio, barrio
        HAVING count(*) >= %s
         ORDER BY count(*) DESC""", tuple(args) + (K_ANONIMATO,))


@router.get("/admin/individual.geojson")
def individual_geojson(req: Request, brigada: str = ""):
    """Un punto por evaluación, con su dirección. Es dato personal, así que vive
    detrás de la sesión y del alcance de brigada, y NO se expone por la API de
    consulta: ahí el umbral de anonimato sigue mandando."""
    ses = exigir(req)
    w, wa = filtro_alcance(req)
    args = list(wa)
    if brigada and ses.rol == "admin":
        w += " AND brigada_token = %s"; args.append(brigada)
    filas = consulta(f"""
        SELECT id, id_local, clasificacion_efectiva, direccion, barrio,
               revision_estado, coalesce(jsonb_array_length(fotos), 0),
               ST_X(geom), ST_Y(geom)
          FROM evaluacion_brigada
         WHERE {w} AND geom IS NOT NULL AND vigente
         ORDER BY ts DESC LIMIT 2000""", tuple(args))
    return JSONResponse({"type": "FeatureCollection", "features": [
        {"type": "Feature",
         "geometry": {"type": "Point", "coordinates": [f[7], f[8]]},
         "properties": {"id": f[0], "id_local": f[1], "clas": f[2],
                        "direccion": f[3], "barrio": f[4],
                        "sin_revisar": f[5] == "pendiente", "fotos": f[6]}}
        for f in filas]}, headers={"Cache-Control": "no-store"})


@router.get("/admin/mapa.geojson")
def mapa_geojson(req: Request, brigada: str = ""):
    ses = exigir(req)
    if ses.rol != "admin":
        brigada = ""      # su alcance ya lo pone sectores(); el parametro se ignora
    rasgos = []
    for m, b, n, colapso, nohab, restr, hab, sinrev, lon, lat, ultima in sectores(
            req, brigada or None):
        if lon is None:
            continue
        rasgos.append({
            "type": "Feature",
            "geometry": {"type": "Point", "coordinates": [lon, lat]},
            # `desalojos` es 3 y 4 juntos: es lo que pinta el color del círculo,
            # porque para leer un sector de un vistazo lo que importa es cuánta
            # gente quedó fuera de su casa, no en cuál de los dos niveles.
            "properties": {"municipio": m or "—", "barrio": b or "—", "evaluadas": n,
                           "peligro_colapso": colapso, "no_habitables": nohab,
                           "uso_restringido": restr, "habitables": hab,
                           "desalojos": colapso + nohab,
                           "sin_revisar": sinrev,
                           "ultima": ultima.strftime("%Y-%m-%d %H:%M") if ultima else None},
        })
    return JSONResponse({"type": "FeatureCollection", "features": rasgos},
                        headers={"Cache-Control": "no-store"})


MAPA = """
<h1>Mapa del consolidado</h1>
<p class="sub">Un círculo por sector. El tamaño es cuántas evaluaciones tiene; el color,
qué proporción de ellas quedó sin poder habitarse.</p>

{% if brigadas|length > 1 %}
<div class="tarjeta">
  <form method="get" class="fila">
    <label><span>Brigada</span><select name="brigada" onchange="this.form.submit()">
      <option value="">Todas</option>
      {% for b in brigadas %}<option value="{{ b }}" {{ 'selected' if b==sel }}>{{ b }}</option>{% endfor %}
    </select></label>
  </form>
</div>
{% endif %}

{% if not filas %}
<div class="tarjeta"><p class="vacio" style="margin:0">Todavía no hay ningún sector con
  {{ k }} evaluaciones o más. Los sectores con menos no se muestran, para que el barrio
  no identifique el predio.</p></div>
{% else %}
<div class="tarjeta" style="padding:14px 16px;display:flex;gap:16px;align-items:center;flex-wrap:wrap">
  <label class="acepto" style="margin:0">
    <input type="checkbox" id="capa-individual">
    <span><strong>Ver los reportes individuales</strong> — un punto por evaluación,
      con su dirección. Toque uno para abrir la ficha con sus fotos.</span>
  </label>
  <span id="aviso-individual" class="pastilla palerta oculto" style="margin-left:auto">
    Mostrando datos personales</span>
</div>

<div class="tarjeta" style="padding:0;overflow:hidden">
  <div id="mapa" style="height:520px;background:var(--papel)"></div>
</div>

<div class="tarjeta">
  <p class="rotulo">Cómo leerlo</p>
  <div style="display:flex;gap:34px;flex-wrap:wrap;align-items:flex-start">
    <div>
      <p style="font-size:12px;font-weight:700;color:var(--tinta2);margin:0 0 8px">
        Proporción sin habitar</p>
      <div style="display:flex;align-items:center;gap:0">
        {% for c in rampa %}<span style="width:44px;height:14px;background:{{ c }}"></span>{% endfor %}
      </div>
      <div style="display:flex;justify-content:space-between;width:220px;font-size:11px;
                  color:var(--tenue);margin-top:4px"><span>0 %</span><span>100 %</span></div>
    </div>
    <div>
      <p style="font-size:12px;font-weight:700;color:var(--tinta2);margin:0 0 8px">
        Tamaño = evaluaciones</p>
      <svg width="150" height="58" role="img" aria-label="Círculos de referencia: 5, 25 y 100 evaluaciones">
        <circle cx="16"  cy="34" r="8"  fill="none" stroke="#94A3B8" stroke-width="1.5"/>
        <circle cx="56"  cy="28" r="14" fill="none" stroke="#94A3B8" stroke-width="1.5"/>
        <circle cx="112" cy="23" r="19" fill="none" stroke="#94A3B8" stroke-width="1.5"/>
        <text x="16"  y="56" font-size="10" fill="#5E6E82" text-anchor="middle">5</text>
        <text x="56"  y="56" font-size="10" fill="#5E6E82" text-anchor="middle">25</text>
        <text x="112" y="56" font-size="10" fill="#5E6E82" text-anchor="middle">100</text>
      </svg>
    </div>
    <div>
      <p style="font-size:12px;font-weight:700;color:var(--tinta2);margin:0 0 8px">
        Sin segunda revisión</p>
      <svg width="60" height="40" role="img" aria-label="Círculo con anillo azul">
        <circle cx="26" cy="20" r="13" fill="#D13A3A" stroke="#0369A1" stroke-width="3.5"/>
      </svg>
      <p class="nota" style="margin:0;max-width:190px">El anillo marca los sectores con
        desalojos sin segunda firma. Nunca es solo el color: también salen en la tabla.</p>
    </div>
  </div>
</div>

<div class="tarjeta">
  <p class="rotulo">Los mismos datos, en tabla</p>
  <div class="desplaza"><table>
    <thead><tr><th>Municipio</th><th>Barrio</th><th>Evaluadas</th>
      <th>Peligro de colapso</th><th>No habitables</th><th>Uso restringido</th>
      <th>Habitables</th><th>Sin revisar</th><th>Última</th></tr></thead>
    <tbody>
    {% for f in filas %}<tr>
      <td>{{ f[0] or "—" }}</td><td>{{ f[1] or "—" }}</td>
      <td class="num">{{ f[2] }}</td>
      <td class="num">{% if f[3] %}<span class="pastilla p4">{{ f[3] }}</span>{% else %}0{% endif %}</td>
      <td class="num">{{ f[4] }}</td><td class="num">{{ f[5] }}</td><td class="num">{{ f[6] }}</td>
      <td class="num">{% if f[7] %}<span class="pastilla palerta">{{ f[7] }}</span>{% else %}0{% endif %}</td>
      <td class="num">{{ f[10].strftime("%Y-%m-%d %H:%M") if f[10] else "—" }}</td>
    </tr>{% endfor %}
    </tbody>
  </table></div>
</div>

""" + MODAL_HTML + """
<p class="nota">Solo aparecen los sectores con {{ k }} evaluaciones o más. Con dos o tres
registros, decir «el barrio X tiene una roja» equivale a señalar la casa con el dedo
(Ley 1581 de 2012). El centro de cada círculo es el centroide del sector, no un predio.</p>

<link rel="stylesheet" href="/admin/vendor/leaflet.css">
<script src="/admin/vendor/leaflet.js"></script>
<script>
(function(){
  "use strict";
  var RAMPA = {{ rampa|tojson }}, CORTES = {{ cortes|tojson }};
  // El color mide desalojos: no habitables y peligro de colapso juntos. Separar
  // los dos en la rampa haría falsa precisión sobre un centroide de sector.
  function color(desalojos, total){
    var p = total ? desalojos / total : 0;
    for (var i = 0; i < CORTES.length; i++) if (p < CORTES[i]) return RAMPA[i];
    return RAMPA[RAMPA.length - 1];
  }
  // El área es proporcional al conteo, no el radio: si el radio creciera con n,
  // un sector con el doble de evaluaciones se vería cuatro veces más grande.
  function radio(n){ return Math.max(7, Math.min(30, 3.6 * Math.sqrt(n))); }

  var mapa = L.map("mapa", {scrollWheelZoom: false});

  // Tres bases: callejero, ortofoto y la híbrida (ortofoto + rótulos encima).
  // La híbrida instancia su propia capa de imagen porque una misma tileLayer no
  // puede pertenecer a dos bases a la vez.
  function ortofoto(){
    return L.tileLayer({{ satelite|tojson }},
      {maxZoom: 19, attribution: {{ credito_sat|tojson }}});
  }
  var BASES = {
    "Callejero": L.tileLayer({{ teselas|tojson }},
      {maxZoom: 19, attribution: {{ credito|tojson }}}),
    "Satélite": ortofoto(),
    "Híbrida": L.layerGroup([ortofoto(), L.tileLayer({{ rotulos|tojson }},
      {maxZoom: 19, attribution: {{ credito_sat|tojson }}})])
  };
  // La elección se recuerda: quien trabaja sobre ortofoto no quiere volver a
  // elegirla cada vez que entra al mapa.
  var guardada = null;
  try { guardada = localStorage.getItem("brg_capa_base"); } catch (e) {}
  (BASES[guardada] || BASES["Callejero"]).addTo(mapa);
  // Desplegado y no en icono: el icono de Leaflet es una imagen que no está
  // vendorizada, y además tres nombres visibles se eligen de un toque.
  L.control.layers(BASES, null, {position: "topright", collapsed: false}).addTo(mapa);
  mapa.on("baselayerchange", function(ev){
    try { localStorage.setItem("brg_capa_base", ev.name); } catch (e) {}
  });

  fetch("/admin/mapa.geojson{{ ('?brigada=' + sel) if sel else '' }}", {cache: "no-store"})
    .then(function(r){ return r.json(); })
    .then(function(g){
      if (!g.features.length) return;
      var capa = L.geoJSON(g, {
        pointToLayer: function(f, latlng){
          var p = f.properties;
          return L.circleMarker(latlng, {
            radius: radio(p.evaluadas),
            fillColor: color(p.desalojos, p.evaluadas),
            fillOpacity: 0.85,
            // Anillo azul = rojos sin revisar. El azul es de la interfaz y no
            // pertenece al semáforo, así que no se confunde con un estado de daño.
            color: p.sin_revisar ? "#0369A1" : "#FFFFFF",
            weight: p.sin_revisar ? 3.5 : 2
          });
        },
        onEachFeature: function(f, capa){
          var p = f.properties;
          capa.bindPopup(
            "<strong>" + p.barrio + "</strong><br>" + p.municipio +
            "<br><br><strong>" + p.evaluadas + "</strong> evaluaciones<br>" +
            (p.peligro_colapso ? p.peligro_colapso + " en peligro de colapso<br>" : "") +
            p.no_habitables + " no habitables · " + p.uso_restringido +
            " uso restringido · " + p.habitables + " habitables" +
            (p.sin_revisar ? "<br><strong>" + p.sin_revisar +
             " sin segunda revisión</strong>" : "") +
            (p.ultima ? "<br><small>última: " + p.ultima + "</small>" : ""));
          capa.bindTooltip(p.barrio + " · " + p.evaluadas);
        }
      }).addTo(mapa);
      mapa.fitBounds(capa.getBounds(), {padding: [40, 40], maxZoom: 14});
      preparaIndividual(capa);
    })
    .catch(function(){
      document.getElementById("mapa").innerHTML =
        '<p style="padding:24px;color:#475569">No se pudo cargar la capa. ' +
        'Los mismos datos están en la tabla de abajo.</p>';
    });

  // Segunda capa: un punto por evaluación. Se carga solo si alguien la pide, y
  // el aviso deja claro que a partir de ahí hay direcciones en pantalla.
    // Del catálogo del V2F: el mismo color que usa la app de campo.
  var CLAS_COLOR = {{ clas_color|tojson }};
  function preparaIndividual(capaAgregada){
    var casilla = document.getElementById("capa-individual");
    var aviso = document.getElementById("aviso-individual");
    if (!casilla) return;
    var capa = null;
    casilla.addEventListener("change", function(){
      aviso.classList.toggle("oculto", !casilla.checked);
      if (!casilla.checked){ if (capa) mapa.removeLayer(capa); mapa.addLayer(capaAgregada); return; }
      mapa.removeLayer(capaAgregada);
      if (capa){ mapa.addLayer(capa); return; }
      fetch("/admin/individual.geojson{{ ('?brigada=' + sel) if sel else '' }}",
            {cache:"no-store"})
        .then(function(r){ return r.json(); })
        .then(function(g){
          capa = L.geoJSON(g, {
            pointToLayer: function(f, ll){
              var p = f.properties;
              return L.circleMarker(ll, {radius: 7,
                fillColor: CLAS_COLOR[p.clas] || "#94A3B8", fillOpacity: .9,
                color: p.sin_revisar ? "#0369A1" : "#FFFFFF",
                weight: p.sin_revisar ? 3 : 1.5});
            },
            onEachFeature: function(f, c){
              var p = f.properties;
              c.bindTooltip((p.id_local || "") + " · " + (p.direccion || p.barrio || ""));
              c.on("click", function(){ window.abrirFicha(p.id); });
            }
          }).addTo(mapa);
        });
    });
  }
})();
</script>
{% endif %}
"""


@router.get("/admin/mapa", response_class=HTMLResponse)
def mapa(req: Request, brigada: str = ""):
    ses = exigir(req)
    if ses.rol != "admin":
        brigada = ""
    filas = sectores(req, brigada or None)
    brigadas = ([b for (b,) in consulta("SELECT nombre FROM brigada ORDER BY nombre")]
                if ses.rol == "admin" else [])
    return pagina("Mapa", render(MAPA, filas=filas, brigadas=brigadas, sel=brigada,
                                 rampa=RAMPA_ROJAS, cortes=CORTES_ROJAS, k=K_ANONIMATO,
                                 teselas=TESELAS, credito=TESELAS_CREDITO,
                                 satelite=TESELAS_SAT, rotulos=TESELAS_ROTULOS,
                                 credito_sat=TESELAS_SAT_CREDITO,
                                 clas_color=v2f.COLOR), "mapa", ses=ses)


@router.get("/admin/vendor/{archivo}")
def vendor(req: Request, archivo: str):
    """Sirve Leaflet desde el propio servidor. Sin sesión a propósito: son archivos
    de librería, no datos, y exigir cookie complicaría el cacheo del navegador."""
    if archivo not in ("leaflet.js", "leaflet.css"):
        raise HTTPException(404, "No existe")
    ruta = VENDOR / archivo
    if not ruta.is_file():
        raise HTTPException(404, "Falta el archivo de la librería en el servidor")
    tipo = "text/css" if archivo.endswith(".css") else "application/javascript"
    return Response(ruta.read_bytes(), media_type=tipo,
                    headers={"Cache-Control": "public, max-age=604800, immutable"})


# --------------------------------------------------- panel sin clave configurada
# Sin BRIGADA_ADMIN_HASH no se monta el panel, y hasta ahora eso daba un
# {"detail":"Not Found"} en JSON: indistinguible de una URL mal escrita o de un
# despliegue roto. Quien administra merece saber que le falta un paso, no adivinar.
router_sin_clave = APIRouter()

SIN_CLAVE = """
<h1>El panel todavía no tiene clave</h1>
<p class="sub">No es un error del servidor: falta configurarlo.</p>
<div class="tarjeta">
  <p>Las rutas del panel solo existen cuando hay una clave de administrador definida.
     Es deliberado: así no queda una pantalla de acceso expuesta con una clave por
     defecto que alguien olvide cambiar.</p>
  <p style="margin-bottom:0">Para habilitarlo, en el servidor:</p>
  <pre style="background:var(--papel);border:1px solid var(--linea);border-radius:8px;
              padding:14px 16px;font-size:13px;overflow-x:auto"><code>sudo /opt/brigadas/venv/bin/python /opt/brigadas/admin_brigadas.py clave
# pega la línea BRIGADA_ADMIN_HASH=... en /etc/brigadas.env
sudo systemctl restart brigadas-api</code></pre>
  <p class="nota">Pide la clave por teclado y nunca la acepta como argumento: ahí
     quedaría en el historial del shell y en la lista de procesos.</p>
</div>
<p class="nota">El resto del sistema no depende de esto. La aplicación de campo sigue
recibiendo evaluaciones con normalidad.</p>
"""


@router_sin_clave.api_route("/admin", methods=["GET", "POST"], response_class=HTMLResponse)
@router_sin_clave.api_route("/admin/{resto:path}", methods=["GET", "POST"],
                            response_class=HTMLResponse)
def panel_sin_clave(req: Request, resto: str = ""):
    r = pagina("Sin configurar", render(SIN_CLAVE), sesion=False)
    r.status_code = 503        # no es "no existe": es "no está listo todavía"
    return r


# ------------------------------------------------- coordinadores desde el panel
@router.post("/admin/coordinadores", response_class=HTMLResponse)
def coordinadores_alta(req: Request, brigada: str = Form(...), usuario: str = Form(...),
                       nombre: str = Form(...)):
    ses = exigir_admin(req)
    usuario, nombre = usuario.strip().lower(), nombre.strip()
    if not usuario or " " in usuario:
        return _pantalla_brigadas(ses, error="El usuario no puede llevar espacios.")
    if not consulta("SELECT 1 FROM brigada WHERE nombre = %s AND activa", (brigada,)):
        return _pantalla_brigadas(ses, error="Esa brigada no existe o está revocada.")
    if consulta("SELECT 1 FROM coordinador WHERE usuario = %s AND activo", (usuario,)):
        return _pantalla_brigadas(ses, error=f"Ya existe un coordinador «{usuario}».")

    # La clave se genera acá y se muestra una sola vez, igual que el token de
    # brigada: así no depende de que quien administra elija una buena, y no queda
    # escrita en ningún formulario que alguien pueda tener abierto.
    clave = "-".join(secrets.token_hex(3) for _ in range(3))
    consulta("""INSERT INTO coordinador (usuario, brigada, nombre, clave_hash)
                VALUES (%s,%s,%s,%s)
                ON CONFLICT (usuario) DO UPDATE
                  SET brigada=EXCLUDED.brigada, nombre=EXCLUDED.nombre,
                      clave_hash=EXCLUDED.clave_hash, activo=true""",
             (usuario, brigada, nombre, hash_clave(clave)))
    return _pantalla_brigadas(ses, clave=clave, usuario=usuario)


@router.post("/admin/coordinadores/baja")
def coordinadores_baja(req: Request, usuario: str = Form(...)):
    exigir_admin(req)
    consulta("UPDATE coordinador SET activo = false WHERE usuario = %s", (usuario,))
    return RedirectResponse("/admin/brigadas", 303)


# ------------------------------------------------------------------- las fotos
# Se sirven por (evaluación, índice), NUNCA por nombre de archivo: el cliente no
# elige rutas, así que no hay forma de pedir algo fuera del directorio de fotos.
# Y van con el alcance de brigada aplicado: un coordinador solo ve las suyas.
@router.get("/admin/foto/{ident}/{n}")
def foto(req: Request, ident: str, n: int):
    exigir(req)
    w, wa = filtro_alcance(req)
    fila = consulta(f"SELECT fotos FROM evaluacion_brigada WHERE id = %s AND {w}",
                    (ident, *wa))
    if not fila or not fila[0][0] or n < 0 or n >= len(fila[0][0]):
        raise HTTPException(404, "No existe esa foto")

    import api_brigadas
    ruta = pathlib.Path(fila[0][0][n]).resolve()
    # Cinturón: aunque la ruta salga de la base, se comprueba que caiga dentro
    # del directorio de fotos antes de leer nada del disco.
    if not ruta.is_file() or api_brigadas.FOTOS.resolve() not in ruta.parents:
        raise HTTPException(404, "El archivo ya no está")
    return Response(ruta.read_bytes(), media_type="image/jpeg",
                    # Dato personal: no se queda en cachés intermedias.
                    headers={"Cache-Control": "private, no-store"})


def _evaluacion(req: Request, ident: str):
    """Una evaluación completa, con su alcance aplicado. None si no le pertenece."""
    w, wa = filtro_alcance(req)
    filas = consulta(f"""
        SELECT id, id_local, ts, recibido_en, matricula, inspector, brigada,
               brigada_token, matricula_verificada, firma_tipo, documento, profesion,
               direccion, municipio, barrio,
               sistema, uso, pisos, ocupantes, danos, banderas, clasificacion,
               clasificacion_auto, motivo_auto, justificacion, observaciones,
               coalesce(jsonb_array_length(fotos), 0), ST_Y(geom), ST_X(geom),
               precision_m, revision_estado, revision_matricula, revision_en,
               revision_clasificacion, revision_motivo, clasificacion_efectiva,
               escala, parciales, parcial_manda,
               reemplazada_por, vigente, reemplazo_usuario, reemplazo_en,
               departamento, cod_dane, origen_punto,
               modo, tipo_inspeccion, cod_catastral, catastral_origen, localidad,
               nivel_mayor_dano, area_afectada_pct, bloques_faltantes,
               v2f_estructura, v2f_estado, v2f_geotecnicos, v2f_no_estructurales,
               v2f_no_estructurales_pct, v2f_estructurales, v2f_entorno,
               v2f_preexistentes, v2f_recomendaciones, v2f_ocupacion, v2f_comision,
               dano_global,
               -- Datos personales de un tercero. Esta es la ÚNICA consulta del
               -- panel que los selecciona: en el listado, el CSV y la API no
               -- existen. Ver el bloque «Compartimento reservado» en esquema.sql.
               reservado
          FROM evaluacion_brigada WHERE id = %s AND {w}""", (ident, *wa))
    if not filas:
        return None
    campos = ["id", "id_local", "ts", "recibido_en", "matricula", "inspector",
              "brigada", "brigada_token", "matricula_verificada",
              "firma_tipo", "documento", "profesion", "direccion",
              "municipio", "barrio", "sistema", "uso", "pisos", "ocupantes",
              "danos", "banderas", "clasificacion", "clasificacion_auto",
              "motivo_auto", "justificacion", "observaciones", "fotos", "lat",
              "lon", "precision_m", "revision_estado", "revision_matricula",
              "revision_en", "revision_clasificacion", "revision_motivo",
              "clasificacion_efectiva", "escala", "parciales", "parcial_manda",
              "reemplazada_por", "vigente", "reemplazo_usuario", "reemplazo_en",
              "departamento", "cod_dane", "origen_punto",
              "modo", "tipo_inspeccion", "cod_catastral", "catastral_origen",
              "localidad", "nivel_mayor_dano", "area_afectada_pct",
              "bloques_faltantes",
              "v2f_estructura", "v2f_estado", "v2f_geotecnicos",
              "v2f_no_estructurales", "v2f_no_estructurales_pct",
              "v2f_estructurales", "v2f_entorno",
              "v2f_preexistentes", "v2f_recomendaciones", "v2f_ocupacion",
              "v2f_comision", "dano_global", "reservado"]
    return dict(zip(campos, filas[0], strict=True))


@router.get("/admin/evaluacion/{ident}.json")
def evaluacion_json(req: Request, ident: str):
    """Lo que consume el modal de Reportes y el globo del mapa."""
    exigir(req)
    e = _evaluacion(req, ident)
    if e is None:
        raise HTTPException(404, "No existe o no pertenece a su brigada")
    for k in ("ts", "recibido_en", "revision_en", "reemplazo_en"):
        e[k] = e[k].isoformat() if e[k] else None
    e["nombre_clas"] = NOMBRE_CLAS.get(e["clasificacion_efectiva"], "?")
    return JSONResponse(e, headers={"Cache-Control": "no-store"})


# ------------------------------------------------------- evolución de la operación
# Ritmo, cobertura y cumplimiento. A propósito NO hay conteo por inspector: medir a
# una persona por cuántas evaluaciones firmó premia la prisa, y en este trabajo la
# prisa es exactamente el riesgo. Lo que se mide es la operación.
#
# Los colores salen del catálogo del V2F, que es el mismo que usa la app de campo.
# La paleta de cuatro está validada con el script: el color nunca va solo, siempre
# con el número y la palabra, porque amarillo, naranja y rojo no se separan bajo
# daltonismo por más que se elijan bien.
ALTO_BARRA = 140       # px del área de dibujo; las etiquetas van debajo
COLOR_CLAS = v2f.COLOR      # del catálogo del V2F: un solo sitio para el color

TABLERO_HTML = """
<h1>Evolución de la operación</h1>
<p class="sub">Cómo avanza el levantamiento, qué sectores llevan horas sin actividad
y qué queda por resolver.</p>

<div class="cifras">
  <div class="cifra"><b class="num">{{ t.total }}</b><span>Evaluaciones</span></div>
  <div class="cifra"><b class="num">{{ t.dias }}</b><span>Días con actividad</span></div>
  <div class="cifra"><b class="num">{{ t.sectores }}</b><span>Sectores trabajados</span></div>
  <div class="cifra {{ 'alerta' if t.rojos_vencidos }}"><b class="num">{{ t.rojos_pend }}</b>
    <span>Desalojos sin segunda revisión</span></div>
  <div class="cifra {{ 'alerta' if t.sin_registro }}"><b class="num">{{ t.sin_registro }}</b>
    <span>Firmas fuera del registro</span></div>
</div>

{% if not serie %}
<div class="tarjeta"><p class="vacio" style="margin:0">Todavía no hay evaluaciones
  que mostrar.</p></div>
{% else %}

<div class="tarjeta">
  <p class="rotulo">Ritmo · evaluaciones recibidas por día</p>
  <div class="desplaza"><div class="barras">
    {% for d in serie %}
    <div class="barra-col">
      <span class="barra-val num">{{ d.total }}</span>
      <div class="barra-pila" style="height:{{ d.alto }}px"
           title="{{ d.fecha }} · {{ d.colapso }} en peligro de colapso, {{ d.no_hab }} no habitables, {{ d.restr }} uso restringido, {{ d.hab }} habitables">
        {% for seg in d.segmentos %}
        <div style="height:{{ seg.alto }}px;background:{{ seg.color }}"></div>
        {% endfor %}
      </div>
      <span class="barra-eti">{{ d.etiqueta }}</span>
    </div>
    {% endfor %}
  </div></div>
  <div class="leyenda">
    <span><i style="background:#7F1D1D"></i>Peligro de colapso</span>
    <span><i style="background:#C2410C"></i>No habitables</span>
    <span><i style="background:#EAB308"></i>Uso restringido</span>
    <span><i style="background:#15803D"></i>Habitables</span>
    <span style="color:var(--tenue)">Clasificación ya revisada, no la original.</span>
  </div>
  <details class="detalle">
    <summary>Ver los mismos datos en tabla</summary>
    <div class="desplaza"><table>
      <thead><tr><th>Día</th><th>Peligro de colapso</th><th>No habitables</th>
        <th>Uso restringido</th><th>Habitables</th><th>Total</th></tr></thead>
      <tbody>{% for d in serie|reverse %}<tr><td class="num">{{ d.fecha }}</td>
        <td class="num">{{ d.colapso }}</td><td class="num">{{ d.no_hab }}</td>
        <td class="num">{{ d.restr }}</td><td class="num">{{ d.hab }}</td>
        <td class="num">{{ d.total }}</td></tr>{% endfor %}</tbody>
    </table></div>
  </details>
</div>

<div class="tarjeta">
  <p class="rotulo">Cobertura · dónde se trabajó y cuándo fue la última vez</p>
  <div class="desplaza"><table>
    <thead><tr><th>Municipio</th><th>Barrio</th><th>Evaluadas</th><th>Desalojos</th>
      <th>Última evaluación</th><th>Sin actividad</th></tr></thead>
    <tbody>
    {% for c in cobertura %}<tr>
      <td>{{ c.municipio or "—" }}</td><td>{{ c.barrio or "—" }}</td>
      <td class="num">{{ c.evaluadas }}</td>
      <td class="num">{% if c.desalojos %}<span class="pastilla p3">{{ c.desalojos }}</span>{% else %}0{% endif %}</td>
      <td class="num">{{ c.ultima }}</td>
      <td class="num">{% if c.horas >= 24 %}<span class="pastilla palerta">{{ c.horas }} h</span>
        {% else %}{{ c.horas }} h{% endif %}</td>
    </tr>{% endfor %}
    </tbody></table></div>
  <p class="nota">El sistema no sabe qué había que cubrir —no hay un plan cargado—, así
    que no puede decir qué falta. Lo que sí muestra es dónde se trabajó y cuánto hace
    que nadie vuelve.</p>
</div>

{% if por_brigada|length > 1 %}
<div class="tarjeta">
  <p class="rotulo">Por brigada</p>
  <div class="desplaza"><table>
    <thead><tr><th>Brigada</th><th>Evaluaciones</th><th>Sectores</th><th>Firmas distintas</th>
      <th>Sin segunda revisión</th><th>Última actividad</th></tr></thead>
    <tbody>
    {% for b in por_brigada %}<tr>
      <td>{{ b.nombre }}</td>
      <td class="num">{{ b.total }}</td><td class="num">{{ b.sectores }}</td>
      <td class="num">{{ b.matriculas }}</td>
      <td class="num">{% if b.pendientes %}<span class="pastilla palerta">{{ b.pendientes }}</span>
        {% else %}0{% endif %}</td>
      <td class="num">{{ b.ultima }}</td>
    </tr>{% endfor %}
    </tbody></table></div>
</div>
{% endif %}

<div class="tarjeta">
  <p class="rotulo">Cumplimiento · lo que queda por resolver</p>
  <table>
    <tr><td style="width:58%">Desalojos esperando segunda revisión</td>
      <td class="num">{{ t.rojos_pend }}{% if t.rojos_vencidos %}
        <span class="pastilla palerta">{{ t.rojos_vencidos }} fuera de plazo</span>{% endif %}</td></tr>
    <tr><td>Demora media en la segunda revisión</td><td class="num">{{ t.demora or "—" }}</td></tr>
    <tr><td>Evaluaciones firmadas por matrícula fuera del registro</td>
      <td class="num">{{ t.sin_registro }}</td></tr>
    <tr><td>Evaluaciones sin coordenada</td><td class="num">{{ t.sin_geo }}</td></tr>
    <tr><td>Evaluaciones sin fotografía</td><td class="num">{{ t.sin_foto }}</td></tr>
  </table>
  <p class="nota">No hay conteo por inspector, a propósito: medir a alguien por cuántas
    evaluaciones firmó premia la prisa en un trabajo donde la prisa es el riesgo.</p>
</div>
{% endif %}

<style>
.barras{display:flex;gap:10px;align-items:flex-end;justify-content:flex-start;padding:4px 2px 0}
/* max-width para que con un solo día la barra quede a la izquierda y no flotando
   en el centro de una columna del ancho de la tarjeta. */
.barra-col{display:flex;flex-direction:column;align-items:center;gap:5px;
  flex:1 1 36px;min-width:36px;max-width:72px}
.barra-pila{width:100%;max-width:44px;display:flex;flex-direction:column-reverse;
  gap:2px;border-radius:4px;overflow:hidden}
.barra-val{font-size:12px;font-weight:700;color:var(--tinta2);font-variant-numeric:tabular-nums}
.barra-eti{font-size:11px;color:var(--tenue);white-space:nowrap}
.leyenda{display:flex;gap:18px;align-items:center;flex-wrap:wrap;margin-top:16px;font-size:12px;
  color:var(--tinta2)}
.leyenda i{display:inline-block;width:11px;height:11px;border-radius:2px;margin-right:6px;
  vertical-align:-1px}
.detalle{margin-top:14px;font-size:13px}
.detalle summary{cursor:pointer;color:var(--azul);font-weight:600}
.detalle table{margin-top:10px}
</style>
"""


def _segmentos(dia: dict, alto: int) -> list:
    """Reparte la altura en píxeles entre las tres clases.

    Se calcula en el servidor y no con `flex`, para que el último segmento absorba
    el redondeo y la pila mida exactamente lo que dice la barra.
    """
    segs, usado = [], 0
    presentes = [(c, dia[k]) for c, k in
                 ((4, "colapso"), (3, "no_hab"), (2, "restr"), (1, "hab")) if dia[k]]
    for i, (clas, n) in enumerate(presentes):
        parte = (alto - usado if i == len(presentes) - 1
                 else max(2, round(alto * n / dia["total"])))
        usado += parte
        segs.append({"color": COLOR_CLAS[clas], "alto": max(2, parte)})
    return segs


@router.get("/admin/evolucion", response_class=HTMLResponse)
def evolucion(req: Request):
    ses = exigir(req)
    w, wa = filtro_alcance(req)

    (total, dias, sectores, rojos_pend, rojos_venc, sin_reg, sin_geo, sin_foto,
     demora), = consulta(f"""
        SELECT count(*), count(DISTINCT ts::date), count(DISTINCT (municipio, barrio)),
               count(*) FILTER (WHERE revision_estado = 'pendiente'),
               count(*) FILTER (WHERE revision_estado = 'pendiente'
                                  AND revision_vence < now()),
               count(*) FILTER (WHERE NOT matricula_verificada),
               count(*) FILTER (WHERE geom IS NULL),
               count(*) FILTER (WHERE coalesce(jsonb_array_length(fotos), 0) = 0),
               round((avg(extract(epoch FROM (revision_en - recibido_en)) / 3600.0)
                      FILTER (WHERE revision_en IS NOT NULL))::numeric, 1)
          FROM evaluacion_brigada WHERE {w} AND vigente""", tuple(wa))

    crudas = consulta(f"""
        SELECT ts::date, count(*),
               count(*) FILTER (WHERE clasificacion_efectiva = 4),
               count(*) FILTER (WHERE clasificacion_efectiva = 3),
               count(*) FILTER (WHERE clasificacion_efectiva = 2),
               count(*) FILTER (WHERE clasificacion_efectiva = 1)
          FROM evaluacion_brigada WHERE {w} AND vigente
         GROUP BY 1 ORDER BY 1 DESC LIMIT 21""", tuple(wa))
    serie = [{"fecha": f[0].isoformat(), "etiqueta": f[0].strftime("%d/%m"),
              "total": f[1], "colapso": f[2], "no_hab": f[3], "restr": f[4], "hab": f[5]}
             for f in reversed(crudas)]
    maximo = max((d["total"] for d in serie), default=1)
    for d in serie:
        d["alto"] = max(4, round(ALTO_BARRA * d["total"] / maximo))
        d["segmentos"] = _segmentos(d, d["alto"])

    cobertura = [{"municipio": f[0], "barrio": f[1], "evaluadas": f[2], "desalojos": f[3],
                  "ultima": f[4].strftime("%Y-%m-%d %H:%M"), "horas": round(f[5])}
                 for f in consulta(f"""
        SELECT municipio, barrio, count(*),
               count(*) FILTER (WHERE clasificacion_efectiva >= 3),
               max(recibido_en),
               extract(epoch FROM (now() - max(recibido_en))) / 3600.0
          FROM evaluacion_brigada WHERE {w} AND vigente
         GROUP BY municipio, barrio ORDER BY max(recibido_en) DESC""", tuple(wa))]

    por_brigada = [{"nombre": f[0] or "— sin atribuir", "total": f[1], "sectores": f[2],
                    "matriculas": f[3], "pendientes": f[4],
                    "ultima": f[5].strftime("%Y-%m-%d %H:%M")}
                   for f in consulta(f"""
        SELECT brigada_token, count(*), count(DISTINCT (municipio, barrio)),
               count(DISTINCT matricula),
               count(*) FILTER (WHERE revision_estado = 'pendiente'),
               max(recibido_en)
          FROM evaluacion_brigada WHERE {w} AND vigente
         GROUP BY brigada_token ORDER BY count(*) DESC""", tuple(wa))]

    t = {"total": total, "dias": dias, "sectores": sectores, "rojos_pend": rojos_pend,
         "rojos_vencidos": rojos_venc, "sin_registro": sin_reg, "sin_geo": sin_geo,
         "sin_foto": sin_foto, "demora": f"{demora} h" if demora is not None else None}
    return pagina("Evolución",
                  render(TABLERO_HTML, t=t, serie=serie, cobertura=cobertura,
                         por_brigada=por_brigada),
                  "evolucion", ses=ses)


# ------------------------------------------------------- catastral pendiente
# El código catastral casi nunca se sabe de memoria frente al predio, así que en
# campo es opcional y se completa acá: escritorio, conexión y pantalla grande.
# Queda registrado que lo puso el panel y no quien estaba parado en la puerta —
# no es lo mismo leerlo de un recibo que deducirlo cruzando una dirección.
CATASTRAL_HTML = """
<h1>Predios sin código catastral</h1>
<p class="sub">Sin el código, la exportación no se puede cruzar contra el catastro
distrital. Los desalojos van primero.</p>

{% if aviso %}<div class="ok">{{ aviso }}</div>{% endif %}
{% if error %}<div class="aviso">{{ error }}</div>{% endif %}

{% if not filas %}
<div class="tarjeta"><p class="vacio" style="margin:0">Todas las evaluaciones tienen
  código catastral.</p></div>
{% else %}
<div class="tarjeta">
  <div class="desplaza"><table>
    <thead><tr><th>Evaluación</th><th>Dónde</th><th>Clasificación</th>
      <th>Código catastral</th></tr></thead>
    <tbody>
    {% for f in filas %}<tr>
      <td><a href="#" onclick="abrirFicha('{{ f.id }}');return false">{{ f.id_local or f.id }}</a>
        <br><span class="nota" style="margin:0">{{ f.recibido.strftime("%Y-%m-%d %H:%M") }}</span></td>
      <td>{{ f.direccion or "—" }}
        {% if f.barrio %}<br><span class="nota" style="margin:0">{{ f.municipio }} · {{ f.barrio }}</span>{% endif %}
        {% if f.lat %}<br><a class="nota" target="_blank" rel="noopener"
           href="https://www.openstreetmap.org/?mlat={{ f.lat }}&mlon={{ f.lon }}#map=19/{{ f.lat }}/{{ f.lon }}"
           >ver la coordenada</a>{% endif %}</td>
      <td><span class="pastilla p{{ f.clas }}">{{ f.nombre_clas }}</span></td>
      <td>
        <form method="post" action="/admin/catastral" style="display:flex;gap:6px;align-items:end">
          <input type="hidden" name="id" value="{{ f.id }}">
          <label style="margin:0"><span style="font-size:11px">Localidad</span>
            <input name="localidad" value="{{ f.localidad or '' }}" style="min-width:110px"></label>
          <label style="margin:0"><span style="font-size:11px">Código</span>
            <input name="cod" required inputmode="numeric" style="min-width:170px"></label>
          <button class="btn btn-s">Guardar</button>
        </form></td>
    </tr>{% endfor %}
    </tbody></table></div>
</div>
{% endif %}
""" + MODAL_HTML


def _sin_catastral(req: Request):
    w, wa = filtro_alcance(req)
    return [{"id": f[0], "id_local": f[1], "recibido": f[3], "direccion": f[5],
             "municipio": f[6], "barrio": f[7], "clas": f[8],
             "nombre_clas": NOMBRE_CLAS.get(f[8], "?"), "lat": f[9], "lon": f[10],
             "localidad": None}
            for f in consulta(f"""SELECT id, id_local, ts, recibido_en, brigada_token,
                                         direccion, municipio, barrio,
                                         clasificacion_efectiva, lat, lon
                                    FROM pendientes_de_catastral
                                   WHERE {w} LIMIT 100""", tuple(wa))]


@router.get("/admin/catastral", response_class=HTMLResponse)
def catastral(req: Request):
    ses = exigir(req)
    return pagina("Catastral", render(CATASTRAL_HTML, filas=_sin_catastral(req),
                                      aviso=None, error=None), "catastral", ses=ses)


@router.post("/admin/catastral", response_class=HTMLResponse)
def catastral_guardar(req: Request, id: str = Form(...), cod: str = Form(...),
                      localidad: str = Form("")):
    ses = exigir(req)
    aviso = error = None
    # El alcance va en el WHERE: sin esto, un coordinador podría escribir sobre la
    # evaluación de otra brigada mandando su id a mano.
    w, wa = filtro_alcance(req)
    cod = cod.strip()
    if not cod:
        error = "El código catastral no puede ir vacío."
    else:
        hecho = consulta(f"""UPDATE evaluacion_brigada
                                SET cod_catastral = %s, catastral_origen = 'panel',
                                    localidad = coalesce(nullif(%s,''), localidad)
                              WHERE id = %s AND {w} AND cod_catastral IS NULL
                          RETURNING id_local""", (cod, localidad.strip(), id, *wa))
        aviso = (f"Código catastral guardado en {hecho[0][0] or id}." if hecho else
                 None)
        if not hecho:
            error = "Esa evaluación no existe, no es de su brigada, o ya tenía código."
    return pagina("Catastral", render(CATASTRAL_HTML, filas=_sin_catastral(req),
                                      aviso=aviso, error=error), "catastral", ses=ses)


# ═════════════════════════════════════════════ exportación al formulario V2F
#
# Una columna por casilla, con los códigos del IDIGER. Es lo que se entrega para
# que lo carguen en su sistema; el PDF quedaría como respaldo legible y la ficha
# HTML ya cumple ese papel.
#
# Acá SÍ va el compartimento reservado: este archivo es el documento que va a la
# autoridad, y sin la persona de contacto ni el efecto en los ocupantes el V2F
# está incompleto. Lo descarga una persona con sesión, dentro del alcance de su
# brigada, y la respuesta lo dice en el encabezado. Por la API de consulta, que
# es una credencial de máquina, ese bloque NO viaja.
CAMPOS_EXPORTA = """
        SELECT id, id_local, ts, recibido_en, matricula, inspector, brigada,
               brigada_token, matricula_verificada, firma_tipo, documento, profesion,
               direccion, municipio, barrio,
               localidad, cod_catastral, tipo_inspeccion, modo, escala,
               departamento, cod_dane, origen_punto,
               pisos, ocupantes, danos, banderas,
               clasificacion, clasificacion_efectiva, justificacion, observaciones,
               parciales, bloques_faltantes, nivel_mayor_dano, area_afectada_pct,
               revision_estado, revision_matricula,
               v2f_estructura, v2f_estado, v2f_geotecnicos, v2f_no_estructurales,
               v2f_no_estructurales_pct, v2f_estructurales, v2f_entorno,
               v2f_preexistentes, v2f_recomendaciones, v2f_ocupacion, v2f_comision,
               dano_global, reservado,
               ST_Y(geom), ST_X(geom)
          FROM evaluacion_brigada"""
NOMBRES_EXPORTA = [
    "id", "id_local", "ts", "recibido_en", "matricula", "inspector", "brigada",
    "brigada_token", "matricula_verificada", "firma_tipo", "documento", "profesion",
    "direccion", "municipio", "barrio",
    "localidad", "cod_catastral", "tipo_inspeccion", "modo", "escala",
    "departamento", "cod_dane", "origen_punto",
    "pisos", "ocupantes", "danos", "banderas",
    "clasificacion", "clasificacion_efectiva", "justificacion", "observaciones",
    "parciales", "bloques_faltantes", "nivel_mayor_dano", "area_afectada_pct",
    "revision_estado", "revision_matricula",
    "v2f_estructura", "v2f_estado", "v2f_geotecnicos", "v2f_no_estructurales",
    "v2f_no_estructurales_pct", "v2f_estructurales", "v2f_entorno",
    "v2f_preexistentes", "v2f_recomendaciones", "v2f_ocupacion", "v2f_comision",
    "dano_global", "reservado",
    "lat", "lon"]


def _para_exportar(req: Request, desde: str = "", hasta: str = "", clas: str = ""):
    w, wa = filtro_alcance(req)
    donde, args = [w], list(wa)
    if desde:
        donde.append("ts >= %s::date"); args.append(desde)
    if hasta:
        donde.append("ts < (%s::date + 1)"); args.append(hasta)
    if clas in ("1", "2", "3", "4"):
        donde.append("clasificacion_efectiva = %s"); args.append(int(clas))
    filas = consulta(f"{CAMPOS_EXPORTA} WHERE {' AND '.join(donde)} "
                     f"ORDER BY recibido_en", tuple(args))
    return [dict(zip(NOMBRES_EXPORTA, f, strict=True)) for f in filas]


def _csv_v2f(filas: list, con_reservado: bool) -> str:
    import csv
    import io
    salida = io.StringIO()
    escritor = csv.DictWriter(salida, fieldnames=v2f.columnas_v2f(con_reservado),
                              extrasaction="ignore", lineterminator="\r\n")
    escritor.writeheader()
    for e in filas:
        escritor.writerow({k: ("" if v is None else v)
                           for k, v in v2f.fila_v2f(e, con_reservado).items()})
    # BOM: sin él, Excel en Windows abre las tildes rotas y alguien acaba
    # "arreglando" el archivo a mano antes de entregarlo.
    return "﻿" + salida.getvalue()


@router.get("/admin/v2f.csv")
def exportar_csv(req: Request, desde: str = "", hasta: str = "", clas: str = ""):
    ses = exigir(req)
    filas = _para_exportar(req, desde, hasta, clas)
    cuerpo = _csv_v2f(filas, con_reservado=True)
    marca = (ses.brigada or "todas").replace(" ", "-").lower()
    return Response(cuerpo, media_type="text/csv; charset=utf-8", headers={
        "Content-Disposition": f'attachment; filename="v2f-{marca}.csv"',
        "Cache-Control": "private, no-store"})


@router.get("/admin/v2f.json")
def exportar_json(req: Request, desde: str = "", hasta: str = "", clas: str = ""):
    exigir(req)
    filas = _para_exportar(req, desde, hasta, clas)
    return JSONResponse({
        "formulario": "V2F-IDIGER",
        "columnas": v2f.columnas_v2f(True),
        "aviso": ("Contiene datos personales de terceros (Ley 1581 de 2012): "
                  "persona de contacto y efecto en los ocupantes. Se entrega a la "
                  "autoridad competente, no se difunde."),
        "evaluaciones": [v2f.fila_v2f(e, con_reservado=True) for e in filas],
    }, headers={"Cache-Control": "private, no-store"})


EXPORTA_HTML = """
<h1>Exportar al formulario V2F</h1>
<p class="sub">Una columna por casilla del formulario del IDIGER, con sus códigos:
el sistema estructural sale como <code>21</code>, no como «mampostería». Quien lo
recibe conoce el V2F, no nuestro modelo de datos.</p>

<div class="tarjeta">
  <form method="get" class="fila" id="fExp">
    <label><span>Desde</span><input type="date" name="desde" value="{{ f.desde }}"></label>
    <label><span>Hasta</span><input type="date" name="hasta" value="{{ f.hasta }}"></label>
    <label><span>Clasificación</span><select name="clas">
      <option value="">Todas</option>
      <option value="4" {{ 'selected' if f.clas=='4' }}>Peligro de colapso</option>
      <option value="3" {{ 'selected' if f.clas=='3' }}>No habitable</option>
      <option value="2" {{ 'selected' if f.clas=='2' }}>Uso restringido</option>
      <option value="1" {{ 'selected' if f.clas=='1' }}>Habitable</option>
    </select></label>
    <button class="btn">Ver cuántas</button>
  </form>
  <p class="nota"><strong>{{ total }}</strong> evaluaciones con ese filtro
    {% if completas is not none %}· {{ completas }} con el formulario completo,
    {{ total - completas }} solo con triaje{% endif %}.</p>
  <div class="fila" style="margin-top:12px">
    <a class="btn btn-p" href="/admin/v2f.csv?{{ qs }}">Descargar CSV</a>
    <a class="btn" href="/admin/v2f.json?{{ qs }}">Descargar JSON</a>
  </div>
</div>

<div class="tarjeta">
  <p class="rotulo">Qué lleva y qué no</p>
  <table>
    <tr><td style="width:38%"><strong>Casillas del formulario</strong></td>
      <td>Las {{ n_columnas }} columnas van en el orden del papel y con los códigos
        del IDIGER. Lo que no se llenó sale <em>vacío</em>, nunca en cero: un cero
        afirma que alguien lo miró.</td></tr>
    <tr><td><strong>Evaluaciones de triaje</strong></td>
      <td>La grilla de porcentajes del bloque D va en blanco —nadie contó los
        elementos— y lo observado con la escala corta baja escrito en comentarios.
        La columna <code>modo</code> lo dice y <code>bloques_sin_datos</code>
        enumera lo que quedó sin mirar.</td></tr>
    <tr><td><strong>Datos personales de terceros</strong></td>
      <td>Persona de contacto y efecto en los ocupantes <strong>sí van</strong>:
        este archivo es el documento que va a la autoridad y sin ellos el V2F está
        incompleto. Por la API de consulta no viajan.</td></tr>
    <tr><td><strong>Alcance</strong></td>
      <td>{% if rol == 'coordinador' %}Solo las evaluaciones de su brigada.{% else %}
        Todas las brigadas.{% endif %}</td></tr>
  </table>
  <p class="nota">Contiene direcciones, coordenadas y datos personales (Ley 1581 de
    2012). Va a la entidad competente por un canal que usted controle; no es un
    archivo para un grupo de mensajería.</p>
</div>
"""


@router.get("/admin/exportar", response_class=HTMLResponse)
def exportar(req: Request, desde: str = "", hasta: str = "", clas: str = ""):
    ses = exigir(req)
    filas = _para_exportar(req, desde, hasta, clas)
    from urllib.parse import urlencode
    qs = urlencode({k: v for k, v in
                    (("desde", desde), ("hasta", hasta), ("clas", clas)) if v})
    return pagina("Exportar", render(
        EXPORTA_HTML, f={"desde": desde, "hasta": hasta, "clas": clas},
        total=len(filas), completas=sum(1 for e in filas if e["modo"] == "completo"),
        n_columnas=len(v2f.columnas_v2f(True)), qs=qs, rol=ses.rol), "exportar", ses=ses)


# ═══════════════════════════════════════════════════════ historia del predio
#
# Dos evaluaciones son «del mismo predio» si están cerca. No hay más señal: el
# código catastral casi nunca llega desde el campo y el número del formulario
# anterior tampoco.
#
# Por eso la cercanía SOLO AGRUPA PARA MOSTRAR. Declarar que una evaluación
# reemplaza a otra exige señalar cuál, con la dirección y la foto de las dos a la
# vista. Con precisión de ±18 m —normal en campo— en una manzana densa caben tres
# o cuatro predios dentro del radio; enlazar solo retiraría del consolidado el
# rojo del edificio de al lado.
RADIO_CERCANIA = int(os.getenv("BRIGADA_RADIO_PREDIO", "25"))   # metros


def _cercanas(req: Request, ident: str):
    """Evaluaciones dentro del radio, sin contar la propia. Con el alcance puesto."""
    w, wa = filtro_alcance(req)
    return consulta(f"""
        SELECT o.id, o.id_local, o.ts, o.direccion, o.barrio, o.municipio,
               o.clasificacion_efectiva, o.matricula, o.inspector,
               coalesce(jsonb_array_length(o.fotos), 0),
               round(ST_Distance(o.geom::geography, e.geom::geography)::numeric, 1),
               o.reemplazada_por, o.revision_estado, o.vigente
          FROM evaluacion_brigada e
          JOIN evaluacion_brigada o
            ON o.id <> e.id
           AND ST_DWithin(o.geom::geography, e.geom::geography, %s)
         WHERE e.id = %s AND {w.replace('brigada_token', 'o.brigada_token')}
         ORDER BY o.ts DESC LIMIT 20""", (RADIO_CERCANIA, ident, *wa))


HISTORIA_HTML = """
<h1>Historia de este predio</h1>
<p class="sub">Evaluaciones a menos de {{ radio }} m. Están agrupadas por cercanía,
no por identidad: el sistema no sabe si son el mismo edificio, y por eso no decide
solo.</p>

{% if aviso %}<div class="ok">{{ aviso }}</div>{% endif %}
{% if error %}<div class="aviso">{{ error }}</div>{% endif %}

<div class="tarjeta" style="border-color:var(--azul)">
  <p class="rotulo">Esta evaluación</p>
  {{ tarjeta(act, true) }}
</div>

{% if not filas %}
<div class="tarjeta"><p class="vacio" style="margin:0">No hay otras evaluaciones
  a menos de {{ radio }} m de esta.</p></div>
{% else %}
<p class="sub" style="margin-top:22px"><strong>{{ filas|length }}</strong>
  {{ "evaluación" if filas|length == 1 else "evaluaciones" }} cerca. Compare la
  dirección y la fotografía antes de declarar nada.</p>

{% for r in filas %}
<div class="tarjeta {{ 'reemplazada' if not r.vigente }}">
  {{ tarjeta(r, false) }}
  <div class="fila" style="margin-top:12px">
    {% if r.reemplazada_por == act.id %}
      <form method="post" action="/admin/historia/deshacer">
        <input type="hidden" name="id" value="{{ act.id }}">
        <input type="hidden" name="vieja" value="{{ r.id }}">
        <button class="btn btn-r">Deshacer el reemplazo</button>
      </form>
      <p class="nota" style="margin:0">Esta evaluación la declaró reemplazada
        {{ r.reemplazo_usuario or "—" }}{% if r.reemplazo_en %} el
        {{ r.reemplazo_en.strftime("%Y-%m-%d %H:%M") }}{% endif %}.</p>
    {% elif not r.vigente %}
      <p class="nota" style="margin:0">Ya fue reemplazada por otra evaluación.</p>
    {% elif r.ts > act.ts %}
      <p class="nota" style="margin:0">Es <strong>posterior</strong> a la que está
        mirando: si son el mismo predio, el reemplazo se declara desde aquella.</p>
    {% else %}
      <form method="post" action="/admin/historia/reemplazar"
            onsubmit="return confirm('¿Son el mismo predio?\\n\\nLa evaluación anterior dejará de contar en el consolidado, el mapa y las colas. Se puede deshacer.')">
        <input type="hidden" name="id" value="{{ act.id }}">
        <input type="hidden" name="vieja" value="{{ r.id }}">
        <button class="btn">Es el mismo predio: esta reemplaza a aquella</button>
      </form>
    {% endif %}
  </div>
</div>
{% endfor %}
{% endif %}

<p class="nota">Declarar un reemplazo no borra nada: la evaluación anterior sigue
en los listados y en la exportación, porque esa inspección ocurrió y está firmada.
Lo que deja de hacer es contar dos veces el mismo predio.</p>
{% if act.clas >= 3 %}
<p class="nota">Una evaluación que ordenaba desalojo solo sale de la cola de segunda
revisión si quien firmó la nueva es <strong>otra matrícula</strong>. Si es la misma
persona, la segunda mirada sigue pendiente: volver al predio uno mismo no es que
otro lo revise.</p>
{% endif %}

<style>
.tarjeta.reemplazada{opacity:.7;border-style:dashed}
.hist-cab{display:flex;gap:12px;align-items:baseline;flex-wrap:wrap;margin-bottom:10px}
.hist-fotos{display:flex;gap:8px;margin-top:10px;flex-wrap:wrap}
.hist-fotos img{width:120px;height:90px;object-fit:cover;border-radius:var(--r);
  border:1px solid var(--linea)}
</style>
"""

TARJETA_HIST = """
{% macro tarjeta(r, actual) %}
  <div class="hist-cab">
    <span class="pastilla p{{ r.clas }}">{{ r.nombre_clas }}</span>
    <strong>{{ r.id_local or r.id }}</strong>
    <span class="nota" style="margin:0">{{ r.ts.strftime("%Y-%m-%d %H:%M") }}</span>
    {% if not actual %}<span class="pastilla pi">a {{ r.metros }} m</span>{% endif %}
    {% if not r.vigente %}<span class="pastilla pn">reemplazada</span>{% endif %}
    {% if r.revision_estado == 'pendiente' %}
      <span class="pastilla palerta">sin segunda revisión</span>{% endif %}
  </div>
  <table>
    <tr><td style="width:22%"><strong>Dónde</strong></td>
      <td>{{ r.direccion or "—" }}{% if r.barrio %} · {{ r.barrio }}{% endif %}</td></tr>
    <tr><td><strong>Quién firmó</strong></td>
      <td>{{ r.inspector or "—" }} · matrícula {{ r.matricula }}</td></tr>
  </table>
  {% if r.fotos %}
  <div class="hist-fotos">
    {% for i in range(r.fotos) %}
      <img loading="lazy" src="/admin/foto/{{ r.id }}/{{ i }}"
           alt="Fotografía {{ i + 1 }} de {{ r.id_local or r.id }}">
    {% endfor %}
  </div>
  {% else %}<p class="nota">Sin fotografías.</p>{% endif %}
{% endmacro %}
"""


def _fila_hist(f):
    return {"id": f[0], "id_local": f[1], "ts": f[2], "direccion": f[3],
            "barrio": f[4], "municipio": f[5], "clas": f[6],
            "nombre_clas": NOMBRE_CLAS.get(f[6], "?"), "matricula": f[7],
            "inspector": f[8], "fotos": f[9], "metros": f[10],
            "reemplazada_por": f[11], "revision_estado": f[12], "vigente": f[13]}


def _historia(req: Request, ident: str, aviso=None, error=None):
    ses = exigir(req)
    w, wa = filtro_alcance(req)
    prop = consulta(f"""
        SELECT id, id_local, ts, direccion, barrio, municipio,
               clasificacion_efectiva, matricula, inspector,
               coalesce(jsonb_array_length(fotos), 0), 0, reemplazada_por,
               revision_estado, vigente, reemplazo_usuario, reemplazo_en
          FROM evaluacion_brigada WHERE id = %s AND {w}""", (ident, *wa))
    if not prop:
        raise HTTPException(404, "No existe o no pertenece a su brigada")
    act = _fila_hist(prop[0])
    filas = []
    for f in _cercanas(req, ident):
        d = _fila_hist(f)
        crudo = consulta("""SELECT reemplazo_usuario, reemplazo_en
                              FROM evaluacion_brigada WHERE id = %s""", (d["id"],))
        d["reemplazo_usuario"], d["reemplazo_en"] = crudo[0] if crudo else (None, None)
        filas.append(d)
    cuerpo = render(TARJETA_HIST + HISTORIA_HTML, act=act, filas=filas,
                    radio=RADIO_CERCANIA, aviso=aviso, error=error)
    return pagina("Historia del predio", cuerpo, "reportes", ses=ses)


@router.get("/admin/historia/{ident}", response_class=HTMLResponse)
def historia(req: Request, ident: str):
    return _historia(req, ident)


@router.post("/admin/historia/reemplazar", response_class=HTMLResponse)
def historia_reemplazar(req: Request, id: str = Form(...), vieja: str = Form(...)):
    ses = exigir(req)
    w, wa = filtro_alcance(req)
    aviso = error = None
    # Las dos tienen que estar dentro del alcance de quien declara: sin esto, un
    # coordinador podría retirar del consolidado el rojo de otra brigada mandando
    # su id a mano.
    par = consulta(f"""SELECT n.matricula, n.clasificacion_efectiva, n.ts,
                              v.matricula, v.clasificacion_efectiva, v.ts,
                              v.revision_estado, v.reemplazada_por
                         FROM evaluacion_brigada n, evaluacion_brigada v
                        WHERE n.id = %s AND v.id = %s
                          AND {w.replace('brigada_token', 'n.brigada_token')}
                          AND {w.replace('brigada_token', 'v.brigada_token')}""",
                   (id, vieja, *wa, *wa))
    if not par:
        return _historia(req, id,
                         error="Alguna de las dos evaluaciones no existe o no es "
                               "de su brigada.")
    mat_n, clas_n, ts_n, mat_v, clas_v, ts_v, rev_v, ya = par[0]

    if ya:
        error = "Esa evaluación ya figura reemplazada por otra."
    elif ts_n <= ts_v:
        error = ("La evaluación que reemplaza tiene que ser posterior. Declárelo "
                 "desde la más reciente de las dos.")
    # Quien firmó no puede revisar lo suyo, y volver al predio uno mismo tampoco
    # es que otro lo revise. Si la misma matrícula rebaja su propio desalojo
    # pendiente de segunda mirada, el reemplazo sería esa revisión por la puerta
    # de atrás. Si la nueva es igual o más grave no hay tal atajo: entra en la
    # cola por su cuenta.
    elif (rev_v == "pendiente" and clas_v and clas_v >= 3
          and mat_n == mat_v and (clas_n or 0) < clas_v):
        error = ("No se puede: la anterior ordenaba desalojo, sigue esperando "
                 "segunda revisión, y la nueva la firmó la misma matrícula con una "
                 "clasificación menos grave. Eso sería revisar lo propio. Registre "
                 "primero la segunda revisión, o que evalúe otro inspector.")
    else:
        consulta("""UPDATE evaluacion_brigada
                       SET reemplazada_por = %s, reemplazo_en = now(),
                           reemplazo_usuario = %s
                     WHERE id = %s AND reemplazada_por IS NULL""",
                 (id, ses.usuario, vieja))
        aviso = ("Reemplazo declarado. La anterior sigue en los listados y en la "
                 "exportación, pero deja de contar en el consolidado, el mapa y "
                 "las colas.")
    return _historia(req, id, aviso=aviso, error=error)


@router.post("/admin/historia/deshacer", response_class=HTMLResponse)
def historia_deshacer(req: Request, id: str = Form(...), vieja: str = Form(...)):
    exigir(req)
    w, wa = filtro_alcance(req)
    consulta(f"""UPDATE evaluacion_brigada
                    SET reemplazada_por = NULL, reemplazo_en = NULL,
                        reemplazo_usuario = NULL
                  WHERE id = %s AND reemplazada_por = %s AND {w}""",
             (vieja, id, *wa))
    return _historia(req, id, aviso="Reemplazo deshecho. Las dos vuelven a contar.")
