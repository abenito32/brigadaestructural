#!/usr/bin/env python3
# Brigada · Evaluación estructural en campo
# Copyright (C) 2026 Rollout Comercio e Servicios Limitada / Andrés Benito Revollo Vélez
#
# Este programa es software libre: usted puede redistribuirlo y/o modificarlo bajo
# los términos de la Licencia Pública General Affero de GNU publicada por la Free
# Software Foundation, en su versión 3 o (a su elección) cualquier versión posterior.
#
# Se distribuye con la esperanza de que sea útil, pero SIN NINGUNA GARANTÍA. Vea
# <https://www.gnu.org/licenses/> para más detalle.
"""
Registro de brigadas e inspectores.

  sudo -u brigadas BRIGADA_DSN="$(grep BRIGADA_DSN /etc/brigadas.env | cut -d= -f2-)" \\
       /opt/brigadas/venv/bin/python /opt/brigadas/admin_brigadas.py <orden>

Ordenes:
  brigada-alta   <nombre> [contacto]   genera el token y lo muestra UNA vez
  brigada-baja   <nombre>              la desactiva; sus evaluaciones quedan
  brigada-adoptar <nombre> <token>     registra un token que ya está en uso
  brigadas                             lista

  inspector-alta <matricula> <nombre> <brigada> [--copnia]
  inspector-baja <matricula>           baja lógica; nunca se borra quien firmó
  inspectores    [brigada]             lista

  consumidor-alta <nombre> [consolidado|detalle] [municipios,coma] [contacto]
  consumidor-baja <nombre>             revoca su token de consulta
  consumidores                         lista

  rojos                                rojos sin segunda revisión
  sin-verificar  [n]                   evaluaciones firmadas por gente no registrada
  clave                                define la clave del panel /admin
"""
import hashlib
import os
import secrets
import sys

import psycopg

DSN = os.getenv("BRIGADA_DSN", "")


def sha(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def con():
    if not DSN:
        salir("Falta BRIGADA_DSN en el entorno.")
    return psycopg.connect(DSN)


def salir(msg, cod=1):
    print(msg, file=sys.stderr)
    sys.exit(cod)


def tabla(filas, cab):
    if not filas:
        print("  (vacío)")
        return
    anchos = [max(len(str(f[i])) for f in [cab] + filas) for i in range(len(cab))]
    print("  " + "  ".join(str(c).ljust(anchos[i]) for i, c in enumerate(cab)))
    print("  " + "  ".join("-" * a for a in anchos))
    for f in filas:
        print("  " + "  ".join(str(v).ljust(anchos[i]) for i, v in enumerate(f)))


def brigada_alta(nombre, contacto=None):
    token = secrets.token_hex(24)
    with con() as c, c.cursor() as cur:
        try:
            cur.execute(
                "INSERT INTO brigada (nombre, token_hash, contacto) VALUES (%s,%s,%s)",
                (nombre, sha(token), contacto),
            )
        except psycopg.errors.UniqueViolation:
            salir(f"Ya existe una brigada llamada {nombre!r}.")
    print(f"Brigada '{nombre}' registrada.\n")
    print(f"  TOKEN: {token}\n")
    print("Este token no se puede recuperar: la base guarda solo su sha256.")
    print("Entrégueselo a la brigada ahora; si se pierde, hay que emitir otro.")


def brigada_adoptar(nombre, token):
    """Para los tokens que ya están en teléfonos: los mete al registro sin rotarlos."""
    with con() as c, c.cursor() as cur:
        try:
            cur.execute(
                "INSERT INTO brigada (nombre, token_hash) VALUES (%s,%s)",
                (nombre, sha(token)),
            )
        except psycopg.errors.UniqueViolation:
            salir("Ese nombre o ese token ya están registrados.")
    print(f"Brigada '{nombre}' adoptó un token existente. Los teléfonos ya "
          "configurados siguen funcionando, y ahora sus envíos quedan atribuidos.")


def brigada_baja(nombre):
    with con() as c, c.cursor() as cur:
        cur.execute("UPDATE brigada SET activa=false WHERE nombre=%s", (nombre,))
        if not cur.rowcount:
            salir(f"No existe la brigada {nombre!r}.")
        cur.execute("SELECT count(*) FROM evaluacion_brigada WHERE brigada_token=%s", (nombre,))
        n = cur.fetchone()[0]
    print(f"Brigada '{nombre}' desactivada. Su token deja de servir de inmediato.")
    print(f"Sus {n} evaluaciones quedan en la base y siguen atribuidas a ella.")


def brigadas():
    with con() as c, c.cursor() as cur:
        cur.execute("""SELECT b.nombre, b.activa, coalesce(b.contacto,'—'),
                              (SELECT count(*) FROM inspector i
                                WHERE i.brigada=b.nombre AND i.vigente),
                              (SELECT count(*) FROM evaluacion_brigada e
                                WHERE e.brigada_token=b.nombre),
                              b.creada_en::date
                         FROM brigada b ORDER BY b.nombre""")
        tabla(cur.fetchall(), ("BRIGADA", "ACTIVA", "CONTACTO", "INSPECT.", "EVALS", "DESDE"))


def inspector_alta(matricula, nombre, brigada, copnia=False):
    with con() as c, c.cursor() as cur:
        cur.execute("SELECT 1 FROM brigada WHERE nombre=%s", (brigada,))
        if not cur.fetchone():
            salir(f"No existe la brigada {brigada!r}. Regístrela primero con brigada-alta.")
        cur.execute(
            """INSERT INTO inspector (matricula, nombre, brigada, verificada_copnia)
               VALUES (%s,%s,%s,%s)
               ON CONFLICT (matricula) DO UPDATE
                 SET nombre=EXCLUDED.nombre, brigada=EXCLUDED.brigada,
                     verificada_copnia=EXCLUDED.verificada_copnia, vigente=true""",
            (matricula, nombre, brigada, copnia),
        )
        # Las evaluaciones que ya firmó pasan a verificadas: llegaron marcadas
        # solo porque el registro iba atrasado, no porque hubiera algo mal.
        cur.execute(
            "UPDATE evaluacion_brigada SET matricula_verificada=true "
            "WHERE matricula=%s AND NOT matricula_verificada",
            (matricula,),
        )
        n = cur.rowcount
    print(f"Inspector {matricula} ({nombre}) registrado en '{brigada}'"
          + (" con matrícula verificada ante COPNIA." if copnia else "."))
    if n:
        print(f"Se reconciliaron {n} evaluaciones suyas que estaban sin verificar.")


def inspector_baja(matricula):
    with con() as c, c.cursor() as cur:
        cur.execute("UPDATE inspector SET vigente=false WHERE matricula=%s", (matricula,))
        if not cur.rowcount:
            salir(f"No existe la matrícula {matricula!r}.")
    print(f"Inspector {matricula} dado de baja. Sus evaluaciones anteriores no cambian: "
          "lo que firmó, firmado está.")


def inspectores(brigada=None):
    with con() as c, c.cursor() as cur:
        cur.execute("""SELECT i.matricula, i.nombre, coalesce(i.brigada,'—'), i.vigente,
                              i.verificada_copnia,
                              (SELECT count(*) FROM evaluacion_brigada e
                                WHERE e.matricula=i.matricula)
                         FROM inspector i
                        -- El ::text es obligatorio: sin el, Postgres no infiere
                        -- el tipo del parametro cuando se lista sin filtrar.
                        WHERE (%s::text IS NULL OR i.brigada=%s)
                        ORDER BY i.brigada, i.nombre""", (brigada, brigada))
        tabla(cur.fetchall(), ("MATRÍCULA", "NOMBRE", "BRIGADA", "VIGENTE", "COPNIA", "EVALS"))


def sin_verificar(n=20):
    with con() as c, c.cursor() as cur:
        cur.execute("SELECT id, matricula, inspector, brigada_declarada, "
                    "brigada_autenticada, clasificacion FROM pendientes_de_verificacion "
                    "LIMIT %s", (int(n),))
        filas = cur.fetchall()
        cur.execute("SELECT count(*) FROM evaluacion_brigada WHERE NOT matricula_verificada")
        total = cur.fetchone()[0]
    print(f"{total} evaluaciones firmadas por matrículas fuera del registro "
          "(los rojos primero):\n")
    tabla(filas, ("ID", "MATRÍCULA", "FIRMA", "DECLARADA", "AUTENTICADA", "CLAS"))


def consumidor_alta(nombre, alcance="consolidado", municipios=None, contacto=None):
    """Credencial de SOLO LECTURA para la API de consulta."""
    if alcance not in ("consolidado", "detalle"):
        salir("El alcance debe ser 'consolidado' o 'detalle'.")
    lista = [m.strip() for m in municipios.split(",") if m.strip()] if municipios else None
    token = secrets.token_hex(24)
    with con() as c, c.cursor() as cur:
        try:
            cur.execute("""INSERT INTO consumidor (nombre, token_hash, alcance,
                                                   municipios, contacto)
                           VALUES (%s,%s,%s,%s,%s)""",
                        (nombre, sha(token), alcance, lista, contacto))
        except psycopg.errors.UniqueViolation:
            salir(f"Ya existe un consumidor llamado {nombre!r}.")
    print(f"Consumidor '{nombre}' registrado · alcance {alcance} · "
          f"municipios: {', '.join(lista) if lista else 'todos'}\n")
    print(f"  TOKEN: {token}\n")
    print("Se envía en la cabecera X-API-Token. No se puede recuperar: la base")
    print("guarda solo su sha256.")
    if alcance == "detalle":
        print("\nOJO: alcance 'detalle' entrega direcciones y coordenadas de predios.")
        print("Es dato personal (Ley 1581 de 2012): entréguelo solo a la entidad")
        print("dueña de esos datos y con una finalidad declarada por escrito.")


def consumidor_baja(nombre):
    with con() as c, c.cursor() as cur:
        cur.execute("UPDATE consumidor SET activo=false WHERE nombre=%s", (nombre,))
        if not cur.rowcount:
            salir(f"No existe el consumidor {nombre!r}.")
    print(f"Consumidor '{nombre}' revocado. Su token deja de servir de inmediato.")


def consumidores():
    with con() as c, c.cursor() as cur:
        cur.execute("""SELECT nombre, alcance,
                              coalesce(array_to_string(municipios, ', '), 'todos'),
                              activo, consultas,
                              coalesce(ultimo_uso::date::text, 'nunca')
                         FROM consumidor ORDER BY activo DESC, nombre""")
        tabla(cur.fetchall(),
              ("CONSUMIDOR", "ALCANCE", "MUNICIPIOS", "ACTIVO", "CONSULTAS", "ÚLTIMO USO"))


def rojos():
    with con() as c, c.cursor() as cur:
        cur.execute("""SELECT coalesce(id_local, id), matricula,
                              coalesce(direccion,'—'), coalesce(municipio,'—'),
                              CASE WHEN vencido THEN 'ATRASADO ' || horas_de_atraso || ' h'
                                   ELSE 'en plazo' END
                         FROM rojos_pendientes LIMIT 50""")
        filas = cur.fetchall()
        cur.execute("SELECT count(*) FROM evaluacion_brigada WHERE revision_estado='pendiente'")
        total = cur.fetchone()[0]
    print(f"{total} rojos esperan segunda revisión (los atrasados primero):\n")
    tabla(filas, ("EVALUACIÓN", "FIRMÓ", "DIRECCIÓN", "MUNICIPIO", "PLAZO"))
    print("\nLa revisión se registra desde el panel: exige elegir quién revisa, y")
    print("quien firmó no puede revisarse a sí mismo.")


def clave():
    """Pide la clave y devuelve la línea para /etc/brigadas.env.

    No escribe el archivo a propósito: quien administra el servidor decide qué
    guarda en él, y así la clave nunca pasa por un argumento de línea de comandos
    (donde quedaría en el historial y en la lista de procesos).
    """
    import getpass
    import admin_web
    c1 = getpass.getpass("Clave nueva del panel: ")
    if len(c1) < 12:
        salir("Muy corta: use al menos 12 caracteres.")
    if c1 != getpass.getpass("Repítala: "):
        salir("No coinciden.")
    print("\nAgregue esta línea a /etc/brigadas.env y reinicie brigadas-api:\n")
    print("BRIGADA_ADMIN_HASH=" + admin_web.hash_clave(c1) + "\n")
    print("Cambiar la clave cierra todas las sesiones abiertas del panel.")


ORDENES = {
    "clave": clave, "rojos": rojos,
    "consumidor-alta": consumidor_alta, "consumidor-baja": consumidor_baja,
    "consumidores": consumidores,
    "brigada-alta": brigada_alta, "brigada-baja": brigada_baja,
    "brigada-adoptar": brigada_adoptar, "brigadas": brigadas,
    "inspector-alta": inspector_alta, "inspector-baja": inspector_baja,
    "inspectores": inspectores, "sin-verificar": sin_verificar,
}

if __name__ == "__main__":
    args = sys.argv[1:]
    if not args or args[0] not in ORDENES:
        print(__doc__)
        sys.exit(0 if not args else 1)
    orden, resto = args[0], args[1:]
    kw = {}
    if "--copnia" in resto:
        resto.remove("--copnia")
        kw["copnia"] = True
    try:
        ORDENES[orden](*resto, **kw)
    except TypeError:
        salir(f"Argumentos incorrectos para '{orden}'. Vea la ayuda sin argumentos.")
