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
import hmac
import os
import secrets
import time

from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from jinja2 import Environment

CLAVE_HASH = os.getenv("BRIGADA_ADMIN_HASH", "")
DURACION_SESION = 8 * 3600          # una jornada
MAX_INTENTOS = 8                    # por IP, en la ventana de abajo
VENTANA_INTENTOS = 600

router = APIRouter()
env = Environment(autoescape=True)  # autoescape: los datos vienen de campo
intentos: dict[str, list[float]] = {}


# ---------------------------------------------------------------- credenciales
def hash_clave(clave: str, sal: bytes | None = None) -> str:
    sal = sal or secrets.token_bytes(16)
    dk = hashlib.scrypt(clave.encode(), salt=sal, n=2**14, r=8, p=1, dklen=32)
    return "scrypt$" + base64.b64encode(sal).decode() + "$" + base64.b64encode(dk).decode()


def clave_correcta(clave: str) -> bool:
    try:
        _, sal_b64, _ = CLAVE_HASH.split("$")
        esperado = CLAVE_HASH
    except ValueError:
        return False
    # compare_digest: comparación en tiempo constante, no revela la clave por timing
    return hmac.compare_digest(hash_clave(clave, base64.b64decode(sal_b64)), esperado)


def _llave() -> bytes:
    """La firma de sesión deriva del hash de la clave: cambiarla cierra las sesiones."""
    return hashlib.sha256(("sesion:" + CLAVE_HASH).encode()).digest()


def firmar(vence: int) -> str:
    cuerpo = str(vence).encode()
    firma = hmac.new(_llave(), cuerpo, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(cuerpo + b"." + firma).decode()


def sesion_valida(cookie: str | None) -> bool:
    if not cookie:
        return False
    try:
        crudo = base64.urlsafe_b64decode(cookie.encode())
        cuerpo, firma = crudo.rsplit(b".", 1)
        if not hmac.compare_digest(hmac.new(_llave(), cuerpo, hashlib.sha256).digest(), firma):
            return False
        return int(cuerpo) > time.time()
    except Exception:
        return False


def exigir(req: Request):
    if not sesion_valida(req.cookies.get("brigada_admin")):
        raise HTTPException(303, headers={"Location": "/admin/entrar"})


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
@media (max-width:640px){.top-in{gap:8px}.nav{width:100%;margin-left:0}}
</style></head><body>
{% if sesion %}
<header class="top"><div class="top-in">
  <div class="marca">Brigada <span>/</span> administración</div>
  <nav class="nav">
    <a href="/admin" class="{{ 'on' if pag=='inicio' }}">Resumen</a>
    <a href="/admin/reportes" class="{{ 'on' if pag=='reportes' }}">Reportes</a>
    <a href="/admin/brigadas" class="{{ 'on' if pag=='brigadas' }}">Brigadas</a>
    <a href="/admin/inspectores" class="{{ 'on' if pag=='inspectores' }}">Inspectores</a>
    <a href="/admin/salir" class="salir">Salir</a>
  </nav>
</div></header>
{% endif %}
<main class="{{ 'entrar' if not sesion else 'wrap' }}">{{ cuerpo }}</main>
</body></html>"""


def pagina(titulo, cuerpo_html, pag="", sesion=True):
    from markupsafe import Markup
    return HTMLResponse(env.from_string(BASE).render(
        titulo=titulo, cuerpo=Markup(cuerpo_html), pag=pag, sesion=sesion))


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
  <label><span>Clave de administrador</span>
    <input type="password" name="clave" autocomplete="current-password" autofocus required></label>
  <button class="btn btn-p" style="width:100%">Entrar</button>
</form>
</div>
<p class="nota">Los inspectores no entran acá: su matrícula es una firma, no una cuenta.
Este panel es solo para quien coordina.</p>
"""


@router.get("/admin/entrar", response_class=HTMLResponse)
def entrar_form(req: Request):
    if sesion_valida(req.cookies.get("brigada_admin")):
        return RedirectResponse("/admin", 303)
    return pagina("Entrar", render(ENTRAR, error=None), sesion=False)


@router.post("/admin/entrar")
def entrar(req: Request, clave: str = Form(...)):
    ip = req.client.host if req.client else "?"
    if limitar(ip):
        return pagina("Entrar", render(ENTRAR,
            error="Demasiados intentos. Espere diez minutos."), sesion=False)
    if not clave_correcta(clave):
        intentos.setdefault(ip, []).append(time.time())
        return pagina("Entrar", render(ENTRAR, error="Clave incorrecta."), sesion=False)
    intentos.pop(ip, None)
    r = RedirectResponse("/admin", 303)
    r.set_cookie("brigada_admin", firmar(int(time.time()) + DURACION_SESION),
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
    exigir(req)
    (total, rojas, amarillas, verdes, sinv), = consulta("""
        SELECT count(*), count(*) FILTER (WHERE clasificacion=3),
               count(*) FILTER (WHERE clasificacion=2),
               count(*) FILTER (WHERE clasificacion=1),
               count(*) FILTER (WHERE NOT matricula_verificada)
          FROM evaluacion_brigada""")
    por_brigada = consulta("""
        SELECT brigada_token, count(*), count(*) FILTER (WHERE clasificacion=3),
               count(*) FILTER (WHERE clasificacion=2), count(*) FILTER (WHERE clasificacion=1),
               count(*) FILTER (WHERE NOT matricula_verificada), max(recibido_en)
          FROM evaluacion_brigada GROUP BY brigada_token ORDER BY count(*) DESC""")
    consolidado = consulta("""SELECT municipio, barrio, evaluadas, rojas, amarillas, verdes
                                FROM consolidado_publico ORDER BY evaluadas DESC""")
    t = {"total": total, "rojas": rojas, "amarillas": amarillas, "verdes": verdes,
         "sin_verificar": sinv}
    return pagina("Resumen", render(INICIO, t=t, por_brigada=por_brigada,
                                    consolidado=consolidado), "inicio")


# --------------------------------------------------------------------- reportes
REPORTES = """
<h1>Reportes recibidos</h1>
<p class="sub">{{ total }} evaluaciones{{ " con los filtros aplicados" if filtrando else "" }}.</p>

<div class="tarjeta">
<form method="get" class="fila">
  <label><span>Brigada</span><select name="brigada">
    <option value="">Todas</option>
    {% for b in brigadas %}<option value="{{ b }}" {{ 'selected' if b==f.brigada }}>{{ b }}</option>{% endfor %}
  </select></label>
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
  <td class="num">{{ e.id }}</td>
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
    exigir(req)
    donde, args = ["1=1"], []
    if brigada:
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
               coalesce(jsonb_array_length(fotos),0), ST_Y(geom), ST_X(geom)
          FROM evaluacion_brigada WHERE {w}
         ORDER BY ts DESC LIMIT %s OFFSET %s""",
        tuple(args) + (POR_PAGINA, (pag - 1) * POR_PAGINA))
    filas = [{
        "id": r[0], "ts": r[1], "clas": r[2], "nombre_clas": NOMBRE_CLAS.get(r[2], "?"),
        "modificada": r[3] is not None and r[2] != r[3], "justificacion": r[4] or "",
        "direccion": r[5], "municipio": r[6], "barrio": r[7], "inspector": r[8],
        "matricula": r[9], "verificada": r[10], "brigada_token": r[11], "fotos": r[12],
        "geo": (f"{r[13]:.5f}, {r[14]:.5f}" if r[13] is not None else ""),
    } for r in crudas]
    brigadas = [b for (b,) in consulta("SELECT nombre FROM brigada ORDER BY nombre")]
    qs = f"brigada={brigada}&clas={clas}&municipio={municipio}&verificada={verificada}"
    f = {"brigada": brigada, "clas": clas, "municipio": municipio, "verificada": verificada}
    return pagina("Reportes", render(REPORTES, filas=filas, total=total, brigadas=brigadas,
                                     f=f, filtrando=any(f.values()), pagina_n=pag,
                                     paginas=paginas, qs=qs), "reportes")


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
    exigir(req)
    return pagina("Brigadas", render(BRIGADAS, filas=_brigadas_filas(),
                                     token_nuevo=None, nombre_nuevo=None, error=None), "brigadas")


@router.post("/admin/brigadas", response_class=HTMLResponse)
def brigadas_alta(req: Request, nombre: str = Form(...), contacto: str = Form("")):
    exigir(req)
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
    exigir(req)
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


def _inspectores_filas():
    return consulta("""
        SELECT i.matricula, i.nombre, i.brigada, i.vigente, i.verificada_copnia,
               (SELECT count(*) FROM evaluacion_brigada e WHERE e.matricula=i.matricula)
          FROM inspector i ORDER BY i.vigente DESC, i.brigada, i.nombre""")


def _brigadas_activas():
    return [b for (b,) in consulta("SELECT nombre FROM brigada WHERE activa ORDER BY nombre")]


@router.get("/admin/inspectores", response_class=HTMLResponse)
def inspectores_ver(req: Request):
    exigir(req)
    return pagina("Inspectores", render(INSPECTORES, filas=_inspectores_filas(),
                                        brigadas=_brigadas_activas(), error=None, aviso=None),
                  "inspectores")


@router.post("/admin/inspectores", response_class=HTMLResponse)
def inspectores_alta(req: Request, matricula: str = Form(...), nombre: str = Form(...),
                     brigada: str = Form(...), copnia: str = Form("")):
    exigir(req)
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
    return pagina("Inspectores", render(INSPECTORES, filas=_inspectores_filas(),
                                        brigadas=_brigadas_activas(), error=None, aviso=aviso),
                  "inspectores")


@router.post("/admin/inspectores/baja")
def inspectores_baja(req: Request, matricula: str = Form(...)):
    exigir(req)
    consulta("UPDATE inspector SET vigente=false WHERE matricula=%s", (matricula,))
    return RedirectResponse("/admin/inspectores", 303)
