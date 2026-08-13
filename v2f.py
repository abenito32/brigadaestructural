"""Catálogo y regla de clasificación del formulario V2F del IDIGER.

Fuente única de los códigos del «Formulario para inspección de edificaciones
después de un sismo» (IDIGER, sobre el formulario de la AIS de 2002). Lo usan:

  · `api_brigadas.py`  para validar lo que llega de campo,
  · el exportador      para escribir cada casilla con SU código y no con el
                       nuestro (sistema estructural = 21, no "mamposteria"),
  · `build_catalogo.py` que lo inyecta dentro de `index.html`, porque la app es
                       un solo archivo autocontenido y no hay bundler.

Los números NO son nuestros y no se renumeran: son los que el IDIGER imprime en
el papel y con los que cruza contra su sistema. Si el instituto publica otra
versión del formulario, se cambia acá y se vuelve a correr el generador.
"""
from __future__ import annotations

# --------------------------------------------------------------- habitabilidad
#
# Cuatro niveles, no tres. Nuestro «rojo» viejo mezclaba dos decisiones que el
# formulario separa: no entrar a esta edificación (3) y esta edificación puede
# caerse sobre la calle (4). La segunda acordona la vía y evacúa vecinos.
HABITABILIDAD = {
    1: {"nombre": "Habitable", "color_v2f": "Verde", "sub": "Puede ocuparse"},
    2: {"nombre": "Uso restringido", "color_v2f": "Amarillo",
        "sub": "Ocupación limitada"},
    3: {"nombre": "No habitable", "color_v2f": "Naranja",
        "sub": "No ingresar · evacuar"},
    4: {"nombre": "Peligro de colapso", "color_v2f": "Rojo",
        "sub": "Evacuar y acordonar el entorno"},
}

# El color no puede ser el único canal: amarillo, naranja y rojo no se separan
# bajo daltonismo (el peor par queda en ΔE 7.0). La escala es ordinal y baja en
# luminosidad de amarillo a rojo, y el número y la palabra acompañan siempre al
# color. Validado con el script, no elegido a ojo.
COLOR = {0: "#64748B", 1: "#15803D", 2: "#EAB308", 3: "#C2410C", 4: "#7F1D1D"}
COLOR_TINTA = {0: "#FFFFFF", 1: "#FFFFFF", 2: "#422006", 3: "#FFFFFF", 4: "#FFFFFF"}

# Techo de cada clasificación parcial. El formulario lo dice sin explicarlo: por
# daños no estructurales o por el entorno se llega a «no habitable», nunca a
# «peligro de colapso» — un antepecho suelto no vuelve inminente el colapso de
# la estructura, aunque sí obligue a cerrar.
TECHO_PARCIAL = {"A": 4, "B": 4, "C": 3, "D": 4, "E": 3}

PARCIALES = {
    "A": "Estado general de la edificación",
    "B": "Problemas geotécnicos",
    "C": "Daños en elementos no estructurales",
    "D": "Daños en elementos estructurales",
    "E": "Problemas del entorno",
}

TIPO_INSPECCION = {1: "Completa", 2: "Parcial", 3: "Exterior solamente"}

# ------------------------------------------------------------------ catálogos
SISTEMA_ESTRUCTURAL = {
    11: "Pórtico de concreto", 12: "Muros estructurales", 13: "Sistemas duales",
    14: "Prefabricados",
    21: "Mampostería confinada", 22: "Mampostería reforzada",
    23: "Mampostería no reforzada (simple)",
    31: "Pórticos arriostrados", 32: "Pórticos no arriostrados",
    33: "Pórticos en celosía",
    41: "Pórticos y paneles en madera",
    42: "Pórticos en madera y paneles en otros materiales",
    51: "Muros en bahareque", 52: "Muros en tapia o adobe",
    60: "Mixta",
    61: "Construida en material precario (sin sistema estructural)",
    70: "Otros",
}
SISTEMA_GRUPO = {
    "Concreto reforzado": [11, 12, 13, 14],
    "Mampostería": [21, 22, 23],
    "Acero": [31, 32, 33],
    "Madera": [41, 42],
    "Bahareque o tapia (adobe)": [51, 52],
    "Otros": [60, 61, 70],
}

TIPO_ENTREPISO = {
    11: "Placa maciza", 12: "Placa aligerada", 13: "Reticular celulado",
    21: "Lámina colaborante (steel deck)", 22: "Vigas", 23: "Cerchas",
    31: "Vigas en madera", 32: "Cerchas en madera",
    40: "Mixta", 50: "Otros",
}
ENTREPISO_GRUPO = {
    "Concreto reforzado": [11, 12, 13],
    "Acero": [21, 22, 23],
    "Madera": [31, 32],
    "Otros": [40, 50],
}

PERIODO_CONSTRUCCION = {
    1: "Antes de 1960", 2: "1960 a 1985", 3: "1986 a 1999",
    4: "2000 a 2011", 5: "A partir de 2012",
}

USO = {
    1: "Residencial", 2: "Comercial", 3: "Educacional", 4: "Salud",
    5: "Hotelero", 6: "Oficinas", 7: "Industrial", 8: "Institucional",
    9: "Bodegas", 10: "Estacionamientos", 11: "Otros",
}

# ------------------------------------------- bloque A · estado general (1 a 3)
COLAPSO = {1: "No", 2: "Parcial", 3: "Total"}
SI_NO_ND = {1: "No", 2: "Sí", 3: "No se pudo determinar"}
ESTADO_GENERAL = {
    1: {"rotulo": "Colapso", "opciones": COLAPSO},
    2: {"rotulo": "Desviación o inclinación de la edificación o de algún entrepiso",
        "opciones": SI_NO_ND},
    3: {"rotulo": "Falla o asentamiento de la cimentación", "opciones": SI_NO_ND},
}

# ------------------------------------------ bloque B · geotécnicos (4 a 6)
GEOTECNICOS = {
    4: {"rotulo": "Falla en talud o movimientos en masa que afecte la edificación",
        "opciones": {1: "No", 2: "Puntual", 3: "General"}},
    5: {"rotulo": "Asentamiento, subsidencia o licuación que afecte la edificación",
        "opciones": {1: "No", 2: "Puntual", 3: "General"}},
    6: {"rotulo": "Grietas en el terreno circundante",
        "opciones": {1: "No", 2: "Incipientes", 3: "Generalizadas"}},
}

# ------------------------------- bloque C · arquitectónicos (7 a 17), escala 1 a 5
GRADO_DANO = {1: "Ninguno", 2: "Leve", 3: "Moderado", 4: "Fuerte", 5: "Severo"}
NO_ESTRUCTURALES = {
    7: "Muros de fachadas o antepechos",
    8: "Vidrios exteriores",
    9: "Acabados exteriores (incluyendo antenas, letreros o similares)",
    10: "Muros divisorios o particiones",
    11: "Balcones",
    12: "Cielo rasos o luminarias",
    13: "Cubierta",
    14: "Escaleras",
    15: "Instalaciones: acueducto, red sanitaria, energía, gas",
    16: "Ductos de ventilación",
    17: "Tanques elevados",
}

# ------------------ bloque D · estructurales (18 a 21), % que suma 100 por fila
ESTRUCTURALES = {
    18: "Columnas o muros portantes",
    19: "Vigas",
    20: "Nudos o puntos de conexión",
    21: "Entrepisos",
}

# ------------------------------------------- bloque E · entorno (22 y 23)
ENTORNO = {
    22: {"rotulo": "Edificio o infraestructura vecina crítica que pueda caer y "
                   "afectar la estabilidad", "opciones": SI_NO_ND},
    23: {"rotulo": "Evento adverso inminente que puede afectar la habitabilidad",
         "opciones": {1: "No", 2: "Sí"}},
}

# Repreguntas. La guía distingue niveles que el formulario impreso no separa: en
# la Tabla 2 el código «2» de colapso cae en «no habitable» y en «peligro de
# colapso» a la vez, y lo que decide está en la columna de comentarios. Se
# pregunta solo cuando hace falta, y sin respuesta se toma el nivel más grave.
REPREGUNTAS = [
    {"blq": "estado", "si": "colapso", "vale": 2, "k": "colapso_mayor_50",
     "rotulo": "¿El colapso supera el 50 % del área, o la parte colapsada "
               "sobrecarga el resto?"},
    {"blq": "estado", "si": "desviacion", "vale": 2, "k": "desviacion_notable",
     "rotulo": "¿La inclinación es notable / la edificación alcanzó estados últimos?"},
    {"blq": "estado", "si": "cimentacion", "vale": 2, "k": "cimentacion_global",
     "rotulo": "¿La falla de cimentación afecta la estabilidad global?"},
    {"blq": "geotecnicos", "si": "grietas", "vale": 3, "k": "grietas_reactivacion",
     "rotulo": "¿El potencial de reactivación es inminente o muy probable?"},
    {"blq": "entorno", "si": "vecina", "vale": 2, "k": "vecina_grave",
     "rotulo": "¿La vecina crítica impide habitar esta edificación?"},
    {"blq": "entorno", "si": "evento", "vale": 2, "k": "evento_grave",
     "rotulo": "¿El evento adverso impide habitar, o solo restringe el uso?"},
]
SI_NO = {1: "Sí", 2: "No"}

# ------------------------------------------------ recomendaciones y seguridad
VISITA_ESPECIALIZADA = {1: "Estructurales", 2: "Geotécnicos", 3: "Servicios públicos"}
INTERVENCION = {
    1: "Alcaldía Local / Control físico", 2: "Policía · Ejército",
    3: "Tránsito", 4: "Bomberos y entidades de rescate",
}
MEDIDAS_SEGURIDAD = {
    1: "Restringir paso de peatones",
    2: "Restringir tráfico vehicular",
    3: "Apuntalar",
    4: "Remover elementos en peligro de caer o no estructurales afectados",
    5: "Evacuar parcialmente la edificación y restringir acceso",
    6: "Evacuar totalmente la edificación y restringir acceso",
    7: "Evacuar edificaciones vecinas y restringir acceso",
    8: "Desconectar energía",
    9: "Desconectar gas",
    10: "Desconectar agua",
    11: "Manejo de sustancias peligrosas",
    12: "Cubrir con plástico el talud",
    13: "Control de aguas de escorrentía sobre talud",
    14: "Estabilizar en pie de ladera (barreras)",
}

# ------------------------------------------------- condiciones pre-existentes
BUENA_REGULAR_MALA = {1: "Buena", 2: "Regular", 3: "Mala"}
PREEXISTENTES = {
    "calidad_construccion": ("Calidad de la construcción", BUENA_REGULAR_MALA),
    "posicion_manzana": ("Posición de la edificación en la manzana",
                         {1: "Esquina", 2: "Intermedia", 3: "Libre por un costado",
                          4: "Libre por dos costados"}),
    "config_planta": ("Configuración en planta", BUENA_REGULAR_MALA),
    "config_altura": ("Configuración en altura", BUENA_REGULAR_MALA),
    "config_estructural": ("Configuración estructural", BUENA_REGULAR_MALA),
    "tipo_suelo": ("Tipo de suelo", {1: "Duro", 2: "Medio", 3: "Blando",
                                     4: "No se pudo determinar"}),
    "tipo_cimentacion": ("Tipo de cimentación", {1: "Superficial", 2: "Profunda",
                                                 3: "No se pudo determinar"}),
    "calidad_cimentacion": ("Calidad de la cimentación",
                            {1: "Buena", 2: "Regular", 3: "Mala",
                             4: "No se pudo determinar"}),
    "topografia": ("Condiciones topográficas",
                   {1: "Plano", 2: "Cresta", 3: "Ladera", 4: "Pie de ladera",
                    5: "Valle", 6: "Borde de canal, río o lago"}),
    "tipo_cubierta": ("Tipo de cubierta", {1: "Maciza", 2: "Liviana"}),
    "amarre_cubierta": ("Condiciones de amarre de la cubierta", BUENA_REGULAR_MALA),
    "columna_corta": ("Efecto de columna corta", {1: "Sí", 2: "No"}),
    "continuidad": ("Continuidad en columnas y vigas", {1: "Sí", 2: "No"}),
    "anclaje_no_estr": ("Evidencia de anclaje de elementos no estructurales",
                        {1: "Sí", 2: "No", 3: "No se sabe"}),
    "danos_previos": ("Indicios de daños por sismos anteriores",
                      {1: "Sí", 2: "No", 3: "No se sabe"}),
    "reparacion": ("Hubo reparación", {1: "Total", 2: "Parcial", 3: "Ninguna",
                                       4: "No se pudo determinar"}),
    "reforzamiento": ("Se ha llevado a cabo reforzamiento estructural",
                      {1: "Total", 2: "Parcial", 3: "Ninguna",
                       4: "No se pudo determinar"}),
}

# --------------------------------------------------- ocupantes y ocupación
#
# Estos campos y la persona de contacto son datos personales de un tercero
# (Ley 1581 de 2012): se capturan porque el formulario los pide y porque hay a
# quién llamar antes de volver al predio, pero viven en compartimento reservado.
# No salen en el listado, ni en el CSV, ni por la API de consulta, ni en el
# consolidado. Solo en la ficha individual, dentro del alcance de esa brigada, y
# en el V2F exportado, que es el documento que va a la autoridad.
RESERVADO = ("contacto_nombre", "contacto_telefono", "contacto_correo",
             "fallecidos", "heridos", "afectados")


# --------------------------------------------------------------- la regla A–E
#
# El formulario en papel no calcula: el inspector escribe las cinco parciales y
# la global. Acá se calculan, y la global es la más crítica de las cinco, que es
# lo que manda el V2F. El inspector puede cambiar la GLOBAL con justificación
# obligatoria; las parciales no se tocan sueltas, para no entregar un formulario
# que se contradice consigo mismo.
#
# Los umbrales de abajo son NUESTROS, derivados de la lógica ATC-20/AIS. El
# formulario no los publica porque allí decide una persona. Están acá, en un solo
# lugar y por escrito, justamente para poder discutirlos con un ingeniero.

def _tope(parcial: str, valor: int) -> int:
    return min(valor, TECHO_PARCIAL[parcial])


def clasificar_triaje(danos: dict, banderas: dict) -> dict:
    """Las cinco parciales a partir del formulario corto (escala 0–3 y banderas).

    En triaje nadie contó elementos, así que el bloque D no puede salir de un
    porcentaje: sale de lo observado. Se mantiene exactamente el resultado que
    daba la regla de tres niveles, con una sola diferencia deliberada — colapso,
    inclinación y núcleo de columna triturado ahora llegan a 4 en vez de quedarse
    en 3. Ese era justamente el caso que la escala vieja no sabía decir.
    """
    d = {k: int(danos.get(k) or 0) for k in ("portantes", "horizontal",
                                             "nostruct", "terreno")}
    b = {k: bool(banderas.get(k)) for k in ("colapso", "inclina", "acero",
                                            "pasante", "vecino", "acceso")}
    p, por = {}, {}

    if b["colapso"]:
        p["A"], por["A"] = 4, "Colapso total o parcial de algún nivel"
    elif b["inclina"]:
        p["A"], por["A"] = 4, "Inclinación o desplome visible de la edificación"
    else:
        p["A"], por["A"] = 1, "Sin colapso ni desplome visible"

    if d["terreno"] == 3:
        p["B"], por["B"] = 3, "Daño severo en el terreno de soporte"
    elif d["terreno"] == 2:
        p["B"], por["B"] = 2, "Daño moderado en el terreno"
    else:
        p["B"], por["B"] = 1, "Sin problema geotécnico observado"

    # OJO · umbral heredado, pendiente de revisar con un ingeniero.
    # La regla de tres niveles daba «uso restringido» ante daño severo en muros
    # divisorios o fachada, y «habitable» ante daño moderado. Se conserva tal cual:
    # mover el límite entre verde y amarillo es una decisión profesional, no un
    # efecto secundario de cambiar la escala. La discusión de fondo es que un
    # antepecho suelto mata a quien pasa por el andén aunque la estructura esté
    # intacta — pero esa conversación se tiene con quien firma, no acá.
    if b["acceso"]:
        p["C"], por["C"] = 3, "Elementos pesados sueltos sobre el acceso o la vía"
    elif d["nostruct"] == 3:
        p["C"], por["C"] = 2, "Daño severo en muros divisorios o fachada"
    else:
        p["C"], por["C"] = 1, "Sin daño no estructural que restrinja el uso"

    if b["acero"]:
        p["D"], por["D"] = 4, "Núcleo de columna triturado, acero expuesto o pandeado"
    elif d["portantes"] == 3 or d["horizontal"] == 3:
        p["D"], por["D"] = 3, "Daño severo en elementos portantes o entrepisos"
    elif b["pasante"]:
        p["D"], por["D"] = 3, "Grietas pasantes o anchas en muros portantes"
    elif d["portantes"] == 2 or d["horizontal"] == 2:
        p["D"], por["D"] = 2, "Daño moderado en la estructura"
    else:
        p["D"], por["D"] = 1, "Sin daño estructural relevante"

    if b["vecino"]:
        p["E"], por["E"] = 3, "Riesgo externo: vecino inestable, talud o deslizamiento"
    else:
        p["E"], por["E"] = 1, "Entorno sin amenaza observada"

    return _global(p, por, sin_datos=(not any(d.values()) and not any(b.values())))


def _global(p: dict, por: dict, *, sin_datos: bool = False) -> dict:
    """La global es la más crítica de las que SE PUDIERON calcular.

    Un bloque sin datos vale None y no entra en el máximo. No vale 1: decir
    «habitable» de lo que nadie miró es la mentira que este sistema no puede
    permitirse. Los bloques faltantes viajan aparte para que el formulario salga
    marcado como inspección parcial y el panel diga cuáles son.
    """
    p = {k: (None if v is None else _tope(k, v)) for k, v in p.items()}
    faltan = [k for k in "ABCDE" if p.get(k) is None]
    if sin_datos or all(p.get(k) is None for k in "ABCDE"):
        return {"v": 0, "por": "Complete el nivel de daño", "parciales": p,
                "manda": None, "faltan": faltan, "motivos": por}
    hay = [k for k in "ABCDE" if p.get(k) is not None]
    manda = max(hay, key=lambda k: (p[k], -"ABCDE".index(k)))
    return {"v": p[manda], "por": por[manda], "parciales": p, "manda": manda,
            "faltan": faltan, "motivos": por}


# ------------------------------------------------- la regla del formulario largo
#
# Los umbrales de acá NO son nuestros: salen de la «Guía Técnica para la
# Inspección de Edificaciones Después de un Sismo» (IDIGER–AIS, 4ª edición,
# 2018), que es el documento que acompaña al formulario V2F. Cada tabla lleva su
# número y su página para poder volver a la fuente.
#
# Antes de tener la guía, acá había un umbral único del 30 % inventado por
# nosotros. Al comparar contra las tablas se quedaba corto en 11 de 15 casos del
# bloque D, siempre hacia el lado peligroso: daño moderado en el 70 % de las
# columnas daba «uso restringido» cuando la guía dice «peligro de colapso».
#
# En los valores de frontera se adopta el criterio más conservador: la guía
# escribe rangos que se solapan («≤ 30 %» y «30 – 100 %») y no dice cuál manda
# en el punto exacto. Ante la duda, el nivel más grave.

# Tabla 4 (pág. 39) · daño arquitectónico, no estructural → parcial C.
# Nivel 1..5 = ninguno, leve, moderado, fuerte, severo. C nunca llega a 4: por un
# antepecho no se declara inminente el colapso de la estructura.
def _tabla_4(nivel: int, pct: float) -> int:
    if nivel <= 2:                      # ninguno o leve, hasta el 100 %
        return 1
    if nivel == 3:                      # moderado
        return 1 if pct < 30 else 2
    return 2 if pct < 60 else 3         # fuerte o severo


# Tabla 7 (pág. 51) · daño estructural → parcial D.
def _tabla_7(nivel: int, pct: float) -> int:
    if nivel <= 1:
        return 1
    if nivel == 2:                      # leve
        return 1 if pct < 30 else 2
    if nivel == 3:                      # moderado
        return 2 if pct < 30 else (3 if pct < 60 else 4)
    if nivel == 4:                      # fuerte
        return 2 if pct < 10 else (3 if pct < 30 else 4)
    return 2 if pct < 5 else (3 if pct < 15 else 4)      # severo


# Tabla 6 (pág. 50) · elementos cuyo daño severo satura el daño global.
# «La calificación con daño severo de ciertos elementos "esenciales" puede
# comprometer toda la edificación», dice la guía. Lo escribe como advertencia,
# no como regla; acá se aplica como regla porque el inspector siempre puede
# bajar la global con justificación, y al revés no.
SATURAN = {
    11: (18, 20), 12: (18, 20), 13: (18, 20), 14: (18, 20),   # concreto: columnas, nudos
    21: (18,), 22: (18,), 23: (18,),                          # mampostería: muros de carga
    31: (18, 20), 32: (18, 20), 33: (18, 20),                 # acero: columnas, conexiones
    41: (18, 20), 42: (18, 20),                               # madera: columnas, conexiones
    51: (18,), 52: (18,),                                     # bahareque y tapia: muros
}


def _tope(parcial: str, valor: int) -> int:
    return min(valor, TECHO_PARCIAL[parcial])


def _max_con_motivo(candidatos):
    """De [(valor, motivo)], el peor. None si no hay ninguno."""
    reales = [c for c in candidatos if c[0] is not None]
    if not reales:
        return None, None
    return max(reales, key=lambda c: c[0])


def clasificar_completo(bloques: dict) -> dict:
    """Las cinco parciales a partir de los bloques del formulario largo.

    `bloques` trae lo que llenó el inspector; lo que no está, no se inventa.
    """
    p, por = {}, {}
    g = lambda blq, k: (bloques.get(blq) or {}).get(k)      # noqa: E731

    # A · estado general — Tabla 2, pág. 27 ----------------------------------
    #
    # La tabla no basta por sí sola: para «colapso parcial» el código del
    # formulario es el mismo (2) tanto en «no habitable» como en «peligro de
    # colapso», y lo que decide está en la columna de comentarios — si supera el
    # 50 % del área o si la parte colapsada sobrecarga el resto. Por eso hay una
    # repregunta. Sin responderla se toma el nivel más grave.
    edo = bloques.get("estado") or {}
    if edo:
        cand = []
        if edo.get("colapso") == 3:
            cand.append((4, "Colapso total"))
        elif edo.get("colapso") == 2:
            grave = edo.get("colapso_mayor_50") != 2      # 1 sí, 2 no, ausente = sí
            cand.append((4, "Colapso parcial superior al 50 % o que sobrecarga el resto")
                        if grave else
                        (3, "Colapso parcial inferior al 50 %, sin sobrecargar el resto"))
        if edo.get("desviacion") == 2:
            grave = edo.get("desviacion_notable") != 2
            cand.append((4, "Inclinación notable: la edificación alcanzó estados últimos")
                        if grave else (3, "Desviación o inclinación de la edificación"))
        elif edo.get("desviacion") == 3:
            cand.append((3, "No se pudo determinar si hay desviación o inclinación"))
        if edo.get("cimentacion") == 2:
            grave = edo.get("cimentacion_global") != 2
            cand.append((4, "Falla de cimentación que afecta la estabilidad global")
                        if grave else (3, "Falla o asentamiento puntual de la cimentación"))
        elif edo.get("cimentacion") == 3:
            cand.append((3, "Existen dudas sobre posibles fallas de la cimentación"))
        v, m = _max_con_motivo(cand)
        p["A"], por["A"] = (v or 1), (m or "Sin colapso, inclinación ni falla de cimentación")
    else:
        p["A"], por["A"] = None, None

    # B · geotécnicos — Tabla 3, pág. 30 -------------------------------------
    geo = bloques.get("geotecnicos") or {}
    if geo:
        cand = []
        if geo.get("talud") == 3: cand.append((4, "Falla general en talud o movimiento en masa"))
        elif geo.get("talud") == 2: cand.append((3, "Falla puntual en talud que afecta la edificación"))
        if geo.get("asentamiento") == 3: cand.append((4, "Asentamiento, subsidencia o licuación general"))
        elif geo.get("asentamiento") == 2: cand.append((3, "Asentamiento, subsidencia o licuación puntual"))
        if geo.get("grietas") == 3:
            # La tabla admite 3 ó 4 según el potencial de reactivación.
            grave = geo.get("grietas_reactivacion") == 1
            cand.append((4, "Grietas generalizadas con reactivación inminente") if grave
                        else (3, "Grietas generalizadas en el terreno circundante"))
        elif geo.get("grietas") == 2:
            cand.append((2, "Grietas incipientes en el terreno circundante"))
        v, m = _max_con_motivo(cand)
        p["B"], por["B"] = (v or 1), (m or "Sin problema geotécnico observado")
    else:
        p["B"], por["B"] = None, None

    # C · no estructurales — Tabla 4, pág. 39 --------------------------------
    ne = {int(k): v for k, v in (bloques.get("no_estructurales") or {}).items() if v}
    pcts = {int(k): v for k, v in (bloques.get("no_estructurales_pct") or {}).items()}
    if ne:
        cand = []
        for item, nivel in ne.items():
            pct = float(pcts.get(item) or 100)   # sin porcentaje, la extensión es total
            r = _tabla_4(int(nivel), pct)
            if r > 1:
                cand.append((r, "%s · %s en el %.0f %% del área"
                             % (NO_ESTRUCTURALES.get(item, "elemento"),
                                GRADO_DANO.get(int(nivel), "?").lower(), pct)))
        v, m = _max_con_motivo(cand)
        p["C"], por["C"] = (v or 1), (m or "Sin daño no estructural que restrinja el uso")
    else:
        p["C"], por["C"] = None, None

    # D · estructurales — Tabla 7, pág. 51, con la saturación de la Tabla 6 ---
    grid = bloques.get("estructurales") or {}
    filas = {int(k): v for k, v in grid.items() if isinstance(v, dict) and any(v.values())}
    if filas:
        sistema = (bloques.get("estructura") or {}).get("sistema")
        esenciales = SATURAN.get(int(sistema), ()) if sistema else ()
        cand = []
        for elem, pct_por_nivel in filas.items():
            nom = ESTRUCTURALES.get(elem, "elemento").lower()
            for nivel in (2, 3, 4, 5):
                pct = float(pct_por_nivel.get(str(nivel), pct_por_nivel.get(nivel)) or 0)
                if pct <= 0:
                    continue
                cand.append((_tabla_7(nivel, pct),
                             "%.0f %% de %s con daño %s"
                             % (pct, nom, GRADO_DANO[nivel].lower())))
            sev = float(pct_por_nivel.get("5", pct_por_nivel.get(5)) or 0)
            if sev > 0 and elem in esenciales:
                cand.append((4, "Daño severo en %s, elemento esencial del sistema "
                                "estructural: satura el daño global" % nom))
        v, m = _max_con_motivo(cand)
        p["D"], por["D"] = (v or 1), (m or "Sin daño estructural relevante")
    else:
        p["D"], por["D"] = None, None

    # E · entorno — Tabla 8, pág. 52 -----------------------------------------
    ent = bloques.get("entorno") or {}
    if ent:
        cand = []
        if ent.get("vecina") == 2:
            grave = ent.get("vecina_grave") != 2
            cand.append((3, "Edificación o infraestructura vecina crítica que puede caer")
                        if grave else (2, "Vecina con riesgo acotado"))
        elif ent.get("vecina") == 3:
            cand.append((3, "No se pudo determinar el riesgo de la edificación vecina"))
        if ent.get("evento") == 2:
            grave = ent.get("evento_grave") != 2
            cand.append((3, "Evento adverso inminente que impide habitar")
                        if grave else (2, "Evento adverso que permite uso restringido"))
        v, m = _max_con_motivo(cand)
        p["E"], por["E"] = (v or 1), (m or "Entorno sin amenaza observada")
    else:
        p["E"], por["E"] = None, None

    return _global(p, por)


# Tabla 10 (pág. 54) · el porcentaje de área afectada de toda la edificación,
# que el formulario pide aparte, tiene su propia escala de daño. Y la Tabla 9
# (pág. 53) la traduce a habitabilidad. NO reemplaza a las cinco parciales —el
# V2F dice que la global es la más conservadora de A a E— pero sirve de contraste:
# si el inspector estima 70 % de área afectada y las parciales dan «uso
# restringido», hay algo que revisar antes de firmar.
DANO_GLOBAL = {1: "Ninguno", 2: "Leve", 3: "Moderado", 4: "Fuerte", 5: "Severo",
               6: "Colapso total"}
DANO_A_HABITABILIDAD = {1: 1, 2: 1, 3: 2, 4: 3, 5: 4, 6: 4}


def dano_global(pct_area: float | None) -> int | None:
    """Clasificación global del daño según el % de área afectada (Tabla 10)."""
    if pct_area is None:
        return None
    p = float(pct_area)
    if p <= 0: return 1
    if p >= 100: return 6
    if p < 10: return 2
    if p < 30: return 3
    if p < 60: return 4
    return 5


def clasificar(danos: dict, banderas: dict, bloques: dict | None = None) -> dict:
    """Punto único de entrada: usa los bloques largos si los hay, si no el triaje.

    Cuando hay las dos cosas —el inspector llenó el formulario completo sobre una
    evaluación que empezó como triaje— mandan los bloques largos, pero un bloque
    que quedó vacío se rellena con lo que sí dijo el triaje. Así completar el
    formulario nunca hace desaparecer una observación ya hecha.
    """
    corto = clasificar_triaje(danos, banderas)
    if not bloques:
        return corto
    largo = clasificar_completo(bloques)
    # Si el formulario corto está vacío no aporta nada: sus cinco parciales en 1
    # significan «no se marcó daño», no «se miró y no había». Rellenar con eso un
    # bloque que el formulario largo dejó sin datos convertiría el silencio en un
    # «habitable» — precisamente lo que no se puede firmar.
    hay_triaje = corto["v"] != 0
    p, por = {}, {}
    for k in "ABCDE":
        if largo["parciales"].get(k) is not None:
            p[k], por[k] = largo["parciales"][k], largo["motivos"][k]
        elif hay_triaje:
            p[k], por[k] = corto["parciales"].get(k), corto["motivos"].get(k)
        else:
            p[k], por[k] = None, None
    return _global(p, por)


# Qué catálogo valida cada clave de cada bloque. Lo que no está acá no se valida
# porque es texto libre o un número (metros de frente, número de ocupantes).
CATALOGOS = {
    ("estructura", "sistema"): SISTEMA_ESTRUCTURAL,
    ("estructura", "entrepiso"): TIPO_ENTREPISO,
    ("estructura", "periodo"): PERIODO_CONSTRUCCION,
    ("estructura", "uso"): USO,
    ("estructura", "uso_planta_baja"): USO,
    ("estado", "colapso"): COLAPSO,
    ("estado", "desviacion"): SI_NO_ND,
    ("estado", "cimentacion"): SI_NO_ND,
    ("geotecnicos", "talud"): GEOTECNICOS[4]["opciones"],
    ("geotecnicos", "asentamiento"): GEOTECNICOS[5]["opciones"],
    ("geotecnicos", "grietas"): GEOTECNICOS[6]["opciones"],
    ("entorno", "vecina"): ENTORNO[22]["opciones"],
    ("entorno", "evento"): ENTORNO[23]["opciones"],
}
CATALOGOS.update({(r["blq"], r["k"]): SI_NO for r in REPREGUNTAS})


def codigos_desconocidos(bloques: dict) -> list[str]:
    """Códigos que este catálogo no reconoce.

    NO sirve para rechazar. Un código desconocido significa que el teléfono y el
    servidor tienen versiones distintas del formulario, y ese es exactamente el
    caso en el que rechazar deja una jornada de campo encerrada en un bolsillo.
    Sirve para avisar en el log y para que el panel lo muestre sin traducir.
    """
    raros = []
    for (blq, clave), catalogo in CATALOGOS.items():
        v = (bloques.get(blq) or {}).get(clave)
        if v not in (None, "") and int(v) not in catalogo:
            raros.append(f"{blq}.{clave}={v}")
    for clave, valor in (bloques.get("no_estructurales") or {}).items():
        if valor and int(valor) not in GRADO_DANO:
            raros.append(f"no_estructurales.{clave}={valor}")
        if int(clave) not in NO_ESTRUCTURALES:
            raros.append(f"no_estructurales: ítem {clave} no existe")
    for clave in (bloques.get("estructurales") or {}):
        if int(clave) not in ESTRUCTURALES:
            raros.append(f"estructurales: ítem {clave} no existe")
    return raros


def nombre(valor: int) -> str:
    return HABITABILIDAD.get(valor, {}).get("nombre", "Sin evaluar")


# --------------------------------------------------------- lo que genera la app
#
# Lo que necesita el teléfono para pintar el formulario y clasificar igual que el
# servidor. Se inyecta en index.html con `build_catalogo.py`; no se descarga en
# tiempo de ejecución, porque la app tiene que arrancar sin señal.


def _preguntas(defs: dict, claves: dict) -> list:
    """Normaliza un bloque a [{k, n, rotulo, opciones}] para que el teléfono solo
    tenga que pintar, sin conocer la forma interna de cada catálogo."""
    return [{"k": claves[n], "n": n, "rotulo": d["rotulo"],
             "opciones": {str(c): t for c, t in d["opciones"].items()}}
            for n, d in defs.items()]


def para_la_app() -> dict:
    """Lo que necesita el teléfono para pintar el formulario y clasificar igual
    que el servidor. Se inyecta en index.html con `build_catalogo.py`; no se
    descarga en tiempo de ejecución, porque la app tiene que arrancar sin señal."""
    txt = lambda d: {str(k): v for k, v in d.items()}      # noqa: E731
    return {
        "HABITABILIDAD": {k: v["nombre"] for k, v in HABITABILIDAD.items()},
        "SUBTITULO": {k: v["sub"] for k, v in HABITABILIDAD.items()},
        "COLOR": COLOR,
        "COLOR_TINTA": COLOR_TINTA,
        "TECHO_PARCIAL": TECHO_PARCIAL,
        "PARCIALES": PARCIALES,
        "SISTEMA_ESTRUCTURAL": SISTEMA_ESTRUCTURAL,
        "SISTEMA_GRUPO": SISTEMA_GRUPO,
        "TIPO_ENTREPISO": TIPO_ENTREPISO,
        "ENTREPISO_GRUPO": ENTREPISO_GRUPO,
        "PERIODO_CONSTRUCCION": PERIODO_CONSTRUCCION,
        "USO": USO,
        "TIPO_INSPECCION": TIPO_INSPECCION,
        "GRADO_DANO": txt(GRADO_DANO),
        "REPREGUNTAS": REPREGUNTAS,
        "SATURAN": {str(k): list(v) for k, v in SATURAN.items()},
        "DANO_GLOBAL": txt(DANO_GLOBAL),
        "NO_ESTRUCTURALES": txt(NO_ESTRUCTURALES),
        "ESTRUCTURALES": txt(ESTRUCTURALES),
        "ESTADO_GENERAL": _preguntas(ESTADO_GENERAL,
                                     {1: "colapso", 2: "desviacion", 3: "cimentacion"}),
        "GEOTECNICOS": _preguntas(GEOTECNICOS,
                                  {4: "talud", 5: "asentamiento", 6: "grietas"}),
        "ENTORNO": _preguntas(ENTORNO, {22: "vecina", 23: "evento"}),
        "PREEXISTENTES": [{"k": k, "rotulo": r, "opciones": txt(o)}
                          for k, (r, o) in PREEXISTENTES.items()],
        "VISITA_ESPECIALIZADA": txt(VISITA_ESPECIALIZADA),
        "INTERVENCION": txt(INTERVENCION),
        "MEDIDAS_SEGURIDAD": txt(MEDIDAS_SEGURIDAD),
    }


# ═══════════════════════════════════════════════════════ exportación del V2F
#
# Una columna por casilla del formulario, con SUS códigos: sistema estructural
# sale como 21, no como "mamposteria". Quien recibe el archivo conoce el V2F, no
# nuestro modelo de datos, y no tiene por qué cargar con un diccionario de
# traducción para leerlo. El orden de las columnas es el orden del papel.
#
# Al final, y solo al final, van las columnas que el V2F no tiene y nosotros sí:
# el identificador del servidor, la escala con la que se firmó, los bloques que
# quedaron sin llenar. Sin ellas el archivo miente por omisión — un formulario
# que no dice que está incompleto se lee como completo.

# Las casillas de recomendaciones se aplanan a una columna booleana cada una,
# porque en el papel son casillas independientes, no una lista.
_MEDIDAS_COL = {
    1: "medida_restringir_peatones", 2: "medida_restringir_vehiculos",
    3: "medida_apuntalar", 4: "medida_remover_elementos",
    5: "medida_evacuar_parcial", 6: "medida_evacuar_total",
    7: "medida_evacuar_vecinas", 8: "medida_desconectar_energia",
    9: "medida_desconectar_gas", 10: "medida_desconectar_agua",
    11: "medida_sustancias_peligrosas", 12: "medida_cubrir_talud",
    13: "medida_control_escorrentia", 14: "medida_estabilizar_ladera",
}
_VISITA_COL = {1: "visita_estructural", 2: "visita_geotecnica", 3: "visita_servicios"}
_INTERV_COL = {1: "interv_alcaldia", 2: "interv_policia", 3: "interv_transito",
               4: "interv_bomberos"}


def columnas_v2f(con_reservado: bool = False) -> list[str]:
    """El encabezado, en el orden del formulario. Es el contrato del archivo."""
    c = ["form_numero", "departamento", "cod_dane", "localidad", "cod_catastral",
         "tipo_inspeccion", "direccion", "municipio", "barrio",
         "uso_edificacion", "uso_planta_baja", "pisos", "sotanos", "frente_m", "fondo_m",
         "sistema_estructural", "tipo_entrepiso", "periodo_construccion",
         "p1_colapso", "p2_desviacion", "p3_cimentacion", "clas_A",
         "p4_talud", "p5_asentamiento", "p6_grietas", "clas_B"]
    for n in NO_ESTRUCTURALES:
        c += [f"p{n}_no_estructural", f"p{n}_pct"]
    c += ["clas_C"]
    c += ["nivel_mayor_dano"]
    for n in ESTRUCTURALES:
        c += [f"p{n}_{g}" for g in ("ninguno", "leve", "moderado", "fuerte", "severo")]
    c += ["clas_D", "p22_vecina", "p23_evento", "clas_E",
          "clas_global", "area_afectada_pct", "dano_global"]
    c += list(_VISITA_COL.values()) + list(_INTERV_COL.values())
    c += list(_MEDIDAS_COL.values()) + ["medidas_lugares"]
    c += list(PREEXISTENTES)
    c += ["habitada", "ocupantes", "unidades", "unidades_no_habitables"]
    if con_reservado:
        c += ["hubo_victimas", "fallecidos", "heridos", "afectados",
              "contacto_nombre", "contacto_telefono", "contacto_correo"]
    c += ["observaciones", "codigo_lider", "nombre_lider", "matricula_lider",
          "evaluadores", "otro_inspector", "fecha_inspeccion"]
    # Lo que el V2F no tiene y sin lo cual el archivo se leería mal.
    c += ["id_servidor", "brigada", "modo", "escala", "bloques_sin_datos",
          "clasificacion_firmada", "clasificacion_efectiva", "revision_estado",
          "revision_matricula", "justificacion", "matricula_verificada",
          "lat", "lon", "origen_punto", "recibido_en"]
    # Repreguntas: no son casillas del formulario impreso, son la precisión que
    # la guía pide en su columna de comentarios y el papel no captura.
    c += [r["k"] for r in REPREGUNTAS]
    return c


# Etiquetas de la escala corta, para poder decirlo en palabras en el V2F.
_ESCALA_CORTA = {0: "sin daño", 1: "leve", 2: "moderado", 3: "severo"}
_CATEGORIAS_CORTAS = {
    "portantes": "elementos portantes", "horizontal": "vigas y entrepisos",
    "nostruct": "muros divisorios y fachada", "terreno": "terreno y entorno",
}
_BANDERAS_CORTAS = {
    "colapso": "colapso total o parcial", "inclina": "inclinación visible",
    "acero": "acero expuesto o pandeado", "pasante": "grietas pasantes",
    "vecino": "riesgo externo", "acceso": "elementos sobre el acceso",
}


def _comentarios(e: dict) -> str:
    """Los comentarios del V2F, más lo observado en triaje si la grilla va vacía.

    Se acordó que un triaje deja la grilla del bloque D en blanco: un porcentaje
    ahí dice «conté los elementos», y en triaje nadie los contó. Pero lo que sí
    se observó no se puede perder, así que baja acá en palabras.
    """
    texto = (e.get("observaciones") or "").strip()
    if e.get("modo") == "completo" and (e.get("v2f_estructurales") or {}):
        return texto
    d, b = e.get("danos") or {}, e.get("banderas") or {}
    if not d and not b:
        return texto
    partes = ["%s: %s" % (n, _ESCALA_CORTA.get(int(d.get(k) or 0), "?"))
              for k, n in _CATEGORIAS_CORTAS.items() if k in d]
    marcadas = [n for k, n in _BANDERAS_CORTAS.items() if b.get(k)]
    linea = ("Evaluación de triaje (escala 0-3), sin conteo de elementos. "
             + " · ".join(partes))
    if marcadas:
        linea += ". Condiciones que obligan cierre: " + ", ".join(marcadas) + "."
    return (texto + "\n\n" + linea).strip() if texto else linea


def fila_v2f(e: dict, con_reservado: bool = False) -> dict:
    """Una evaluación, aplanada a las casillas del formulario.

    `e` es la fila de la base tal como la lee el panel. Lo que no se llenó sale
    vacío: nunca un cero ni un «1». Un cero en la casilla de un daño afirma que
    alguien lo miró, y en un documento que firma un ingeniero esa diferencia es
    justamente la que importa.
    """
    b = lambda k: e.get(k) or {}                                    # noqa: E731
    est, edo = b("v2f_estructura"), b("v2f_estado")
    geo, ent = b("v2f_geotecnicos"), b("v2f_entorno")
    ne, gr = b("v2f_no_estructurales"), b("v2f_estructurales")
    pre, rec = b("v2f_preexistentes"), b("v2f_recomendaciones")
    ocu, com = b("v2f_ocupacion"), b("v2f_comision")
    par, res = b("parciales"), b("reservado")
    ts = e.get("ts")

    f = {
        "form_numero": e.get("id_local") or e.get("id"),
        "departamento": e.get("departamento"), "cod_dane": e.get("cod_dane"),
        "localidad": e.get("localidad"),
        "cod_catastral": e.get("cod_catastral"),
        "tipo_inspeccion": e.get("tipo_inspeccion"),
        "direccion": e.get("direccion"), "municipio": e.get("municipio"),
        "barrio": e.get("barrio"),
        "uso_edificacion": est.get("uso"), "uso_planta_baja": est.get("uso_planta_baja"),
        "pisos": e.get("pisos"), "sotanos": est.get("sotanos"),
        "frente_m": est.get("frente"), "fondo_m": est.get("fondo"),
        "sistema_estructural": est.get("sistema"),
        "tipo_entrepiso": est.get("entrepiso"),
        "periodo_construccion": est.get("periodo"),
        "p1_colapso": edo.get("colapso"), "p2_desviacion": edo.get("desviacion"),
        "p3_cimentacion": edo.get("cimentacion"), "clas_A": par.get("A"),
        "p4_talud": geo.get("talud"), "p5_asentamiento": geo.get("asentamiento"),
        "p6_grietas": geo.get("grietas"), "clas_B": par.get("B"),
        "clas_C": par.get("C"), "nivel_mayor_dano": e.get("nivel_mayor_dano"),
        "clas_D": par.get("D"),
        "p22_vecina": ent.get("vecina"), "p23_evento": ent.get("evento"),
        "clas_E": par.get("E"),
        "clas_global": e.get("clasificacion_efectiva"),
        "area_afectada_pct": e.get("area_afectada_pct"),
        # Tabla 10: la casilla «clasificación del daño» del formulario.
        "dano_global": e.get("dano_global"),
        "medidas_lugares": rec.get("lugares"),
        "habitada": ocu.get("habitada"), "ocupantes": ocu.get("ocupantes") or e.get("ocupantes"),
        "unidades": ocu.get("unidades"), "unidades_no_habitables": ocu.get("unidades_no_hab"),
        "observaciones": _comentarios(e),
        "codigo_lider": com.get("codigo_lider"), "nombre_lider": e.get("inspector"),
        "matricula_lider": e.get("matricula"), "evaluadores": com.get("evaluadores"),
        "otro_inspector": com.get("otro"),
        "fecha_inspeccion": ts.isoformat() if hasattr(ts, "isoformat") else ts,
        "id_servidor": e.get("id"), "brigada": e.get("brigada_token"),
        "modo": e.get("modo"), "escala": e.get("escala"),
        "bloques_sin_datos": "|".join(e.get("bloques_faltantes") or []),
        "clasificacion_firmada": e.get("clasificacion"),
        "clasificacion_efectiva": e.get("clasificacion_efectiva"),
        "revision_estado": e.get("revision_estado"),
        "revision_matricula": e.get("revision_matricula"),
        "justificacion": e.get("justificacion"),
        "matricula_verificada": e.get("matricula_verificada"),
        "lat": e.get("lat"), "lon": e.get("lon"),
        "origen_punto": e.get("origen_punto"),
        "recibido_en": (e["recibido_en"].isoformat()
                        if hasattr(e.get("recibido_en"), "isoformat") else e.get("recibido_en")),
    }
    nep = e.get("v2f_no_estructurales_pct") or {}
    for n in NO_ESTRUCTURALES:
        f[f"p{n}_no_estructural"] = ne.get(str(n), ne.get(n))
        f[f"p{n}_pct"] = nep.get(str(n), nep.get(n))
    for n in ESTRUCTURALES:
        fila = gr.get(str(n)) or gr.get(n) or {}
        for i, g in enumerate(("ninguno", "leve", "moderado", "fuerte", "severo"), start=1):
            f[f"p{n}_{g}"] = fila.get(str(i), fila.get(i))
    for cod, col in _VISITA_COL.items():
        f[col] = 1 if (rec.get("visita") or {}).get(str(cod)) else None
    for cod, col in _INTERV_COL.items():
        f[col] = 1 if (rec.get("intervencion") or {}).get(str(cod)) else None
    for cod, col in _MEDIDAS_COL.items():
        f[col] = 1 if (rec.get("medidas") or {}).get(str(cod)) else None
    for k in PREEXISTENTES:
        f[k] = pre.get(k)
    for r in REPREGUNTAS:
        f[r["k"]] = (e.get("v2f_" + r["blq"]) or {}).get(r["k"])
    if con_reservado:
        f.update({
            "hubo_victimas": res.get("hubo_victimas"),
            "fallecidos": res.get("fallecidos"), "heridos": res.get("heridos"),
            "afectados": res.get("afectados"),
            "contacto_nombre": res.get("contacto_nombre"),
            "contacto_telefono": res.get("contacto_telefono"),
            "contacto_correo": res.get("contacto_correo"),
        })
    return {k: f.get(k) for k in columnas_v2f(con_reservado)}
