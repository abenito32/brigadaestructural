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
import pathlib
from typing import NamedTuple
import hmac
import os
import secrets
import time

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
    return base64.urlsafe_b64encode(cuerpo + b"." + firma).decode()


def leer_sesion(cookie: str | None) -> Sesion | None:
    if not cookie:
        return None
    try:
        crudo = base64.urlsafe_b64decode(cookie.encode())
        cuerpo, firma = crudo.rsplit(b".", 1)
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
 --verde:#15803D;--ambar:#B45309;--ambar-fondo:#FACC15;--ambar-tinta:#422006;--rojo:#B91C1C;
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
.cifra.c1 b{color:var(--verde)}.cifra.c2 b{color:var(--ambar)}.cifra.c3 b{color:var(--rojo)}
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
.p3{background:#FEE2E2;color:#7F1D1D}
.pi{background:var(--azul-tinte);color:var(--azul-osc)}.pn{background:#F1F5F9;color:var(--tinta2)}
.palerta{background:#FEE2E2;color:#7F1D1D}
label{display:block;margin-bottom:13px}
label>span{display:block;font-size:13px;font-weight:600;color:var(--tinta2);margin-bottom:5px}
input,select{width:100%;padding:11px 12px;font:inherit;border:1px solid var(--borde);
 border-radius:var(--r);background:var(--carta);color:var(--tinta);min-height:46px}
input:focus,select:focus{outline:3px solid var(--azul);outline-offset:-1px;border-color:var(--azul)}
.btn{display:inline-block;border:1px solid var(--borde);background:var(--carta);color:var(--tinta);
 font:inherit;font-weight:600;font-size:15px;padding:12px 18px;border-radius:var(--r);cursor:pointer;
 text-decoration:none;box-shadow:var(--sombra)}
.btn:hover{background:var(--papel)}
.btn-p{background:var(--azul);color:#fff;border-color:var(--azul)}
.btn-p:hover{background:var(--azul-osc)}
.btn-r{color:var(--rojo);border-color:#FECACA;background:var(--rojo-tinte);font-size:13px;padding:7px 12px}
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
    <a href="/admin/reportes" class="{{ 'on' if pag=='reportes' }}">Reportes</a>
    <a href="/admin/rojos" class="{{ 'on' if pag=='rojos' }}">Rojos</a>
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
  <div class="cifra c3"><b class="num">{{ t.rojas }}</b><span>Rojas · inseguro</span></div>
  <div class="cifra c2"><b class="num">{{ t.amarillas }}</b><span>Amarillas · uso restringido</span></div>
  <div class="cifra c1"><b class="num">{{ t.verdes }}</b><span>Verdes · habitable</span></div>
  <div class="cifra {{ 'alerta' if t.sin_verificar }}"><b class="num">{{ t.sin_verificar }}</b>
    <span>Firmas fuera del registro</span></div>
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
  <thead><tr><th>Brigada</th><th>Evaluadas</th><th>Rojas</th><th>Amarillas</th><th>Verdes</th>
    <th>Sin verificar</th><th>Última</th></tr></thead><tbody>
  {% for f in por_brigada %}<tr>
    <td>{{ f[0] or "— sin atribuir (token heredado)" }}</td>
    <td class="num">{{ f[1] }}</td><td class="num">{{ f[2] }}</td><td class="num">{{ f[3] }}</td>
    <td class="num">{{ f[4] }}</td>
    <td class="num">{% if f[5] %}<span class="pastilla palerta">{{ f[5] }}</span>{% else %}0{% endif %}</td>
    <td class="num">{{ f[6].strftime("%Y-%m-%d %H:%M") if f[6] else "—" }}</td>
  </tr>{% else %}<tr><td colspan="7" class="vacio">Todavía no hay evaluaciones.</td></tr>{% endfor %}
  </tbody></table></div>
</div>

<div class="tarjeta">
  <p class="rotulo">Por sector · lo que se entrega a las autoridades</p>
  <div class="desplaza"><table>
  <thead><tr><th>Municipio</th><th>Barrio o vereda</th><th>Evaluadas</th><th>Rojas</th>
    <th>Amarillas</th><th>Verdes</th></tr></thead><tbody>
  {% for f in consolidado %}<tr>
    <td>{{ f[0] or "—" }}</td><td>{{ f[1] or "—" }}</td><td class="num">{{ f[2] }}</td>
    <td class="num">{{ f[3] }}</td><td class="num">{{ f[4] }}</td><td class="num">{{ f[5] }}</td>
  </tr>{% else %}<tr><td colspan="6" class="vacio">Ningún sector llega todavía al mínimo de
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
    (total, rojas, amarillas, verdes, sinv, rpend, rvenc), = consulta(f"""
        SELECT count(*), count(*) FILTER (WHERE clasificacion=3),
               count(*) FILTER (WHERE clasificacion=2),
               count(*) FILTER (WHERE clasificacion=1),
               count(*) FILTER (WHERE NOT matricula_verificada),
               count(*) FILTER (WHERE revision_estado = 'pendiente'),
               count(*) FILTER (WHERE revision_estado = 'pendiente'
                                  AND revision_vence < now())
          FROM evaluacion_brigada WHERE {w}""", tuple(wa))
    por_brigada = consulta(f"""
        SELECT brigada_token, count(*), count(*) FILTER (WHERE clasificacion_efectiva=3),
               count(*) FILTER (WHERE clasificacion_efectiva=2),
               count(*) FILTER (WHERE clasificacion_efectiva=1),
               count(*) FILTER (WHERE NOT matricula_verificada), max(recibido_en)
          FROM evaluacion_brigada WHERE {w}
         GROUP BY brigada_token ORDER BY count(*) DESC""", tuple(wa))
    # El consolidado por sector se recalcula con el alcance aplicado: la vista
    # consolidado_publico no distingue brigadas, y servirla tal cual le mostraria
    # a un coordinador los sectores de las demas.
    consolidado = [(f[0], f[1], f[2], f[3], f[4], f[5]) for f in sectores(req)]
    t = {"total": total, "rojas": rojas, "amarillas": amarillas, "verdes": verdes,
         "sin_verificar": sinv, "rojos_pendientes": rpend, "rojos_vencidos": rvenc}
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
    <option value="3" {{ 'selected' if f.clas=='3' }}>Rojo</option>
    <option value="2" {{ 'selected' if f.clas=='2' }}>Amarillo</option>
    <option value="1" {{ 'selected' if f.clas=='1' }}>Verde</option>
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
{% for e in filas %}<tr>
  <td class="num">{{ e.id_local or "—" }}<br>
      <span class="nota" title="Identificador canónico del servidor">{{ e.id[:10] }}…</span></td>
  <td class="num">{{ e.ts.strftime("%Y-%m-%d %H:%M") }}</td>
  <td><span class="pastilla p{{ e.clas }}">{{ e.nombre_clas }}</span>
      {% if e.modificada %}<br><span class="pastilla pn" title="{{ e.justificacion }}">modificada</span>{% endif %}</td>
  <td>{{ e.direccion or "—" }}{% if e.geo %}<br><span class="nota">{{ e.geo }}</span>{% endif %}</td>
  <td>{{ e.municipio or "—" }}{{ " · " + e.barrio if e.barrio }}</td>
  <td>{{ e.inspector or "—" }}<br><span class="pastilla {{ 'pi' if e.verificada else 'palerta' }}">
      {{ e.matricula }}{{ "" if e.verificada else " · sin registrar" }}</span></td>
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
<p class="nota">Esta pantalla muestra dirección y coordenadas, que son dato personal
(Ley 1581 de 2012). Sirve para coordinar la brigada; lo que se entrega a las autoridades
es el consolidado por sector del Resumen, nunca este listado.</p>
"""
NOMBRE_CLAS = {1: "Verde", 2: "Amarillo", 3: "Rojo"}
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
               barrio, inspector, matricula, matricula_verificada, brigada_token,
               coalesce(jsonb_array_length(fotos),0), ST_Y(geom), ST_X(geom), id_local
          FROM evaluacion_brigada WHERE {w}
         ORDER BY ts DESC LIMIT %s OFFSET %s""",
        tuple(args) + (POR_PAGINA, (pag - 1) * POR_PAGINA))
    filas = [{
        "id": r[0], "ts": r[1], "clas": r[2], "nombre_clas": NOMBRE_CLAS.get(r[2], "?"),
        "modificada": r[3] is not None and r[2] != r[3], "justificacion": r[4] or "",
        "direccion": r[5], "municipio": r[6], "barrio": r[7], "inspector": r[8],
        "matricula": r[9], "verificada": r[10], "brigada_token": r[11], "fotos": r[12],
        "geo": (f"{r[13]:.5f}, {r[14]:.5f}" if r[13] is not None else ""),
        "id_local": r[15],
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
{% if token_nuevo %}
<div class="ok"><strong>Brigada «{{ nombre_nuevo }}» registrada.</strong> Este es su token, y esta
es la única vez que se muestra: la base guarda solo su sha256.
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
<thead><tr><th>Brigada</th><th>Estado</th><th>Contacto</th><th>Inspectores</th><th>Evaluaciones</th>
  <th>Desde</th><th></th></tr></thead><tbody>
{% for b in filas %}<tr>
  <td><strong>{{ b[0] }}</strong></td>
  <td><span class="pastilla {{ 'pi' if b[1] else 'pn' }}">{{ "Activa" if b[1] else "Revocada" }}</span></td>
  <td>{{ b[2] or "—" }}</td><td class="num">{{ b[3] }}</td><td class="num">{{ b[4] }}</td>
  <td class="num">{{ b[5] }}</td>
  <td>{% if b[1] %}<form method="post" action="/admin/brigadas/baja"
      onsubmit="return confirm('Revocar el token de {{ b[0] }}? Sus teléfonos dejan de sincronizar de inmediato.')">
      <input type="hidden" name="nombre" value="{{ b[0] }}">
      <button class="btn btn-r">Revocar token</button></form>{% endif %}</td>
</tr>{% else %}<tr><td colspan="7" class="vacio">No hay brigadas registradas.</td></tr>{% endfor %}
</tbody></table></div>
</div>
<p class="nota">Revocar corta el token en el acto, pero no borra nada: las evaluaciones que esa
brigada ya envió siguen en la base y siguen atribuidas a ella.</p>
"""


def _brigadas_filas():
    return consulta("""
        SELECT b.nombre, b.activa, b.contacto,
               (SELECT count(*) FROM inspector i WHERE i.brigada=b.nombre AND i.vigente),
               (SELECT count(*) FROM evaluacion_brigada e WHERE e.brigada_token=b.nombre),
               b.creada_en::date
          FROM brigada b ORDER BY b.activa DESC, b.nombre""")


@router.get("/admin/brigadas", response_class=HTMLResponse)
def brigadas_ver(req: Request):
    exigir_admin(req)
    return pagina("Brigadas", render(BRIGADAS, filas=_brigadas_filas(),
                                     token_nuevo=None, nombre_nuevo=None, error=None), "brigadas")


@router.post("/admin/brigadas", response_class=HTMLResponse)
def brigadas_alta(req: Request, nombre: str = Form(...), contacto: str = Form("")):
    exigir_admin(req)
    import api_brigadas
    nombre, contacto = nombre.strip(), contacto.strip() or None
    token = secrets.token_hex(24)
    error = None
    try:
        consulta("INSERT INTO brigada (nombre, token_hash, contacto) VALUES (%s,%s,%s)",
                 (nombre, api_brigadas.sha(token), contacto))
    except Exception:
        token, error = None, f"Ya existe una brigada llamada «{nombre}»."
    return pagina("Brigadas", render(BRIGADAS, filas=_brigadas_filas(), token_nuevo=token,
                                     nombre_nuevo=nombre, error=error), "brigadas")


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
<h1>Rojos pendientes de segunda revisión</h1>
<p class="sub">Un rojo ordena no habitar una edificación. Antes de consolidarlo,
otro inspector registrado tiene que mirarlo.</p>

{% if error %}<div class="aviso">{{ error }}</div>{% endif %}
{% if aviso %}<div class="ok">{{ aviso }}</div>{% endif %}

{% if not inspectores %}
<div class="aviso">No hay inspectores vigentes en el registro, así que no hay quién
revise. Registre al menos uno en <a href="/admin/inspectores">Inspectores</a>.</div>
{% endif %}

{% for r in filas %}
<div class="tarjeta" style="{{ 'border-color:#FECACA' if r.vencido }}">
  <div style="display:flex;gap:14px;align-items:baseline;flex-wrap:wrap">
    <span class="pastilla p3">ROJO</span>
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
        <option value="confirmado">Confirmar el rojo</option>
        <option value="2">Revocar → Amarillo</option>
        <option value="1">Revocar → Verde</option>
      </select></label>
      <label><span>Motivo</span><input name="motivo" placeholder="Criterio técnico"></label>
      <button class="btn btn-p">Registrar revisión</button>
    </div>
  </form>
</div>
{% else %}
<div class="tarjeta"><p class="vacio" style="margin:0">No hay rojos esperando revisión.</p></div>
{% endfor %}

<p class="nota">Revocar no borra nada: la clasificación firmada queda tal cual y se
guarda aparte quién revisó, cuándo y por qué. Lo que cambia es la clasificación
efectiva, que es la que usan el consolidado y la API.</p>
<p class="nota">El vencimiento no degrada el rojo. Un rojo atrasado sigue siendo rojo:
solo aparece marcado para que nadie lo dé por revisado sin estarlo.</p>
"""


def _rojos(req: Request):
    w, wa = filtro_alcance(req)
    crudas = consulta(f"""SELECT id, id_local, ts, matricula, inspector, brigada_token,
                                direccion, municipio, barrio, observaciones,
                                justificacion, vencido, horas_de_atraso
                           FROM rojos_pendientes WHERE {w} LIMIT 100""", tuple(wa))
    return [{"id": r[0], "id_local": r[1], "ts": r[2], "matricula": r[3],
             "inspector": r[4], "brigada_token": r[5], "direccion": r[6],
             "municipio": r[7], "barrio": r[8], "observaciones": r[9],
             "justificacion": r[10], "vencido": r[11],
             "horas": round(r[12]) if r[12] is not None else 0} for r in crudas]


def _inspectores_vigentes(req: Request):
    w, wa = filtro_alcance(req, "brigada")
    return consulta(f"SELECT matricula, nombre FROM inspector "
                    f"WHERE vigente AND {w} ORDER BY nombre", tuple(wa))


@router.get("/admin/rojos", response_class=HTMLResponse)
def rojos(req: Request):
    ses = exigir(req)
    return pagina("Rojos", render(ROJOS, filas=_rojos(req),
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
        error = "Revocar un rojo exige escribir el motivo."
    else:
        nueva = None if resultado == "confirmado" else int(resultado)
        consulta("""UPDATE evaluacion_brigada
                       SET revision_estado = %s, revision_matricula = %s,
                           revision_en = now(), revision_clasificacion = %s,
                           revision_motivo = %s
                     WHERE id = %s AND revision_estado = 'pendiente'""",
                 ("confirmado" if nueva is None else "revocado", matricula,
                  nueva, motivo.strip() or None, id))
        aviso = ("Rojo confirmado." if nueva is None else
                 f"Rojo revocado a {NOMBRE_CLAS[nueva].lower()}. La clasificación firmada "
                 "queda registrada igual.")
    return pagina("Rojos", render(ROJOS, filas=_rojos(req),
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
               count(*) FILTER (WHERE clasificacion_efectiva = 3),
               count(*) FILTER (WHERE clasificacion_efectiva = 2),
               count(*) FILTER (WHERE clasificacion_efectiva = 1),
               count(*) FILTER (WHERE revision_estado = 'pendiente'),
               ST_X(ST_Centroid(ST_Collect(geom))), ST_Y(ST_Centroid(ST_Collect(geom))),
               max(recibido_en)
          FROM evaluacion_brigada
         WHERE {donde}
         GROUP BY municipio, barrio
        HAVING count(*) >= %s
         ORDER BY count(*) DESC""", tuple(args) + (K_ANONIMATO,))


@router.get("/admin/mapa.geojson")
def mapa_geojson(req: Request, brigada: str = ""):
    ses = exigir(req)
    if ses.rol != "admin":
        brigada = ""      # su alcance ya lo pone sectores(); el parametro se ignora
    rasgos = []
    for m, b, n, rojas, ama, ver, sinrev, lon, lat, ultima in sectores(req, brigada or None):
        if lon is None:
            continue
        rasgos.append({
            "type": "Feature",
            "geometry": {"type": "Point", "coordinates": [lon, lat]},
            "properties": {"municipio": m or "—", "barrio": b or "—", "evaluadas": n,
                           "rojas": rojas, "amarillas": ama, "verdes": ver,
                           "sin_revisar": sinrev,
                           "ultima": ultima.strftime("%Y-%m-%d %H:%M") if ultima else None},
        })
    return JSONResponse({"type": "FeatureCollection", "features": rasgos},
                        headers={"Cache-Control": "no-store"})


MAPA = """
<h1>Mapa del consolidado</h1>
<p class="sub">Un círculo por sector. El tamaño es cuántas evaluaciones tiene; el color,
qué proporción de ellas quedó en rojo.</p>

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
<div class="tarjeta" style="padding:0;overflow:hidden">
  <div id="mapa" style="height:520px;background:var(--papel)"></div>
</div>

<div class="tarjeta">
  <p class="rotulo">Cómo leerlo</p>
  <div style="display:flex;gap:34px;flex-wrap:wrap;align-items:flex-start">
    <div>
      <p style="font-size:12px;font-weight:700;color:var(--tinta2);margin:0 0 8px">
        Proporción en rojo</p>
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
        Rojos sin segunda revisión</p>
      <svg width="60" height="40" role="img" aria-label="Círculo con anillo azul">
        <circle cx="26" cy="20" r="13" fill="#D13A3A" stroke="#0369A1" stroke-width="3.5"/>
      </svg>
      <p class="nota" style="margin:0;max-width:190px">El anillo marca los sectores con
        rojos pendientes. Nunca es solo el color: también salen en la tabla.</p>
    </div>
  </div>
</div>

<div class="tarjeta">
  <p class="rotulo">Los mismos datos, en tabla</p>
  <div class="desplaza"><table>
    <thead><tr><th>Municipio</th><th>Barrio</th><th>Evaluadas</th><th>Rojas</th>
      <th>Amarillas</th><th>Verdes</th><th>Sin revisar</th><th>Última</th></tr></thead>
    <tbody>
    {% for f in filas %}<tr>
      <td>{{ f[0] or "—" }}</td><td>{{ f[1] or "—" }}</td>
      <td class="num">{{ f[2] }}</td>
      <td class="num">{{ f[3] }}</td><td class="num">{{ f[4] }}</td><td class="num">{{ f[5] }}</td>
      <td class="num">{% if f[6] %}<span class="pastilla palerta">{{ f[6] }}</span>{% else %}0{% endif %}</td>
      <td class="num">{{ f[9].strftime("%Y-%m-%d %H:%M") if f[9] else "—" }}</td>
    </tr>{% endfor %}
    </tbody>
  </table></div>
</div>

<p class="nota">Solo aparecen los sectores con {{ k }} evaluaciones o más. Con dos o tres
registros, decir «el barrio X tiene una roja» equivale a señalar la casa con el dedo
(Ley 1581 de 2012). El centro de cada círculo es el centroide del sector, no un predio.</p>

<link rel="stylesheet" href="/admin/vendor/leaflet.css">
<script src="/admin/vendor/leaflet.js"></script>
<script>
(function(){
  "use strict";
  var RAMPA = {{ rampa|tojson }}, CORTES = {{ cortes|tojson }};
  function color(rojas, total){
    var p = total ? rojas / total : 0;
    for (var i = 0; i < CORTES.length; i++) if (p < CORTES[i]) return RAMPA[i];
    return RAMPA[RAMPA.length - 1];
  }
  // El área es proporcional al conteo, no el radio: si el radio creciera con n,
  // un sector con el doble de evaluaciones se vería cuatro veces más grande.
  function radio(n){ return Math.max(7, Math.min(30, 3.6 * Math.sqrt(n))); }

  var mapa = L.map("mapa", {scrollWheelZoom: false});
  L.tileLayer({{ teselas|tojson }}, {maxZoom: 19, attribution: {{ credito|tojson }}}).addTo(mapa);

  fetch("/admin/mapa.geojson{{ ('?brigada=' + sel) if sel else '' }}", {cache: "no-store"})
    .then(function(r){ return r.json(); })
    .then(function(g){
      if (!g.features.length) return;
      var capa = L.geoJSON(g, {
        pointToLayer: function(f, latlng){
          var p = f.properties;
          return L.circleMarker(latlng, {
            radius: radio(p.evaluadas),
            fillColor: color(p.rojas, p.evaluadas),
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
            p.rojas + " rojas · " + p.amarillas + " amarillas · " + p.verdes + " verdes" +
            (p.sin_revisar ? "<br><strong>" + p.sin_revisar + " rojos sin revisar</strong>" : "") +
            (p.ultima ? "<br><small>última: " + p.ultima + "</small>" : ""));
          capa.bindTooltip(p.barrio + " · " + p.evaluadas);
        }
      }).addTo(mapa);
      mapa.fitBounds(capa.getBounds(), {padding: [40, 40], maxZoom: 14});
    })
    .catch(function(){
      document.getElementById("mapa").innerHTML =
        '<p style="padding:24px;color:#475569">No se pudo cargar la capa. ' +
        'Los mismos datos están en la tabla de abajo.</p>';
    });
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
                                 teselas=TESELAS, credito=TESELAS_CREDITO), "mapa", ses=ses)


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
