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
# Umbrales NUESTROS otra vez: el V2F imprime las casillas pero no publica la
# regla, porque en el papel decide una persona. Están acá, juntos y por escrito,
# para poder discutirlos con un ingeniero en vez de deducirlos del código.
#
# La escala de daño del V2F tiene cinco grados y la nuestra de triaje tiene
# cuatro. Se alinean así: ninguno=ninguno, leve=leve, moderado=moderado, y
# nuestro «severo» equivale al «fuerte» del V2F. El «severo» del V2F queda por
# encima de lo que la escala corta sabe expresar, y por eso puede cerrar una
# edificación donde el triaje solo la restringía.
UMBRAL_D = 30      # % de elementos en un grado que hace saltar el nivel


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

    # A · estado general -----------------------------------------------------
    colapso, desv, cim = g("estado", "colapso"), g("estado", "desviacion"), g("estado", "cimentacion")
    if colapso or desv or cim:
        cand = []
        if colapso == 3: cand.append((4, "Colapso total"))
        elif colapso == 2: cand.append((4, "Colapso parcial"))
        if desv == 2: cand.append((4, "Desviación o inclinación de la edificación"))
        elif desv == 3: cand.append((2, "No se pudo determinar si hay desviación"))
        if cim == 2: cand.append((3, "Falla o asentamiento de la cimentación"))
        elif cim == 3: cand.append((2, "No se pudo determinar el estado de la cimentación"))
        v, m = _max_con_motivo(cand)
        p["A"], por["A"] = (v or 1), (m or "Sin colapso, desviación ni falla de cimentación")
    else:
        p["A"], por["A"] = None, None

    # B · geotécnicos --------------------------------------------------------
    talud, asent, grietas = g("geotecnicos", "talud"), g("geotecnicos", "asentamiento"), g("geotecnicos", "grietas")
    if talud or asent or grietas:
        cand = []
        if talud == 3: cand.append((4, "Falla general en talud o movimiento en masa"))
        elif talud == 2: cand.append((3, "Falla puntual en talud"))
        if asent == 3: cand.append((4, "Asentamiento, subsidencia o licuación generalizada"))
        elif asent == 2: cand.append((3, "Asentamiento, subsidencia o licuación puntual"))
        if grietas == 3: cand.append((3, "Grietas generalizadas en el terreno circundante"))
        elif grietas == 2: cand.append((2, "Grietas incipientes en el terreno circundante"))
        v, m = _max_con_motivo(cand)
        p["B"], por["B"] = (v or 1), (m or "Sin problema geotécnico observado")
    else:
        p["B"], por["B"] = None, None

    # C · no estructurales (ítems 7 a 17, escala 1 a 5) -----------------------
    ne = {int(k): v for k, v in (bloques.get("no_estructurales") or {}).items()
          if v}
    if ne:
        peor = max(ne.values())
        cual = NO_ESTRUCTURALES.get(max(ne, key=lambda k: ne[k]), "")
        if peor >= 5:
            p["C"], por["C"] = 3, f"Daño severo · {cual.lower()}"
        elif peor == 4:
            p["C"], por["C"] = 2, f"Daño fuerte · {cual.lower()}"
        else:
            p["C"], por["C"] = 1, "Sin daño no estructural que restrinja el uso"
    else:
        p["C"], por["C"] = None, None

    # D · estructurales (porcentajes por elemento en el piso de mayor daño) ---
    grid = bloques.get("estructurales") or {}
    filas = {int(k): v for k, v in grid.items() if isinstance(v, dict) and any(v.values())}
    if filas:
        cand = []
        for elem, pct in filas.items():
            sev = float(pct.get("5") or pct.get(5) or 0)
            fue = float(pct.get("4") or pct.get(4) or 0)
            mod = float(pct.get("3") or pct.get(3) or 0)
            nom = ESTRUCTURALES.get(elem, "elemento").lower()
            if sev >= UMBRAL_D: cand.append((4, f"{sev:.0f}% de {nom} con daño severo"))
            elif sev > 0: cand.append((3, f"{sev:.0f}% de {nom} con daño severo"))
            elif fue >= UMBRAL_D: cand.append((3, f"{fue:.0f}% de {nom} con daño fuerte"))
            elif fue > 0: cand.append((2, f"{fue:.0f}% de {nom} con daño fuerte"))
            elif mod >= UMBRAL_D: cand.append((2, f"{mod:.0f}% de {nom} con daño moderado"))
        v, m = _max_con_motivo(cand)
        p["D"], por["D"] = (v or 1), (m or "Sin daño estructural relevante")
    else:
        p["D"], por["D"] = None, None

    # E · entorno ------------------------------------------------------------
    vecina, evento = g("entorno", "vecina"), g("entorno", "evento")
    if vecina or evento:
        cand = []
        if vecina == 2: cand.append((3, "Edificación o infraestructura vecina crítica"))
        elif vecina == 3: cand.append((2, "No se pudo determinar el riesgo de la vecina"))
        if evento == 2: cand.append((3, "Evento adverso inminente"))
        v, m = _max_con_motivo(cand)
        p["E"], por["E"] = (v or 1), (m or "Entorno sin amenaza observada")
    else:
        p["E"], por["E"] = None, None

    return _global(p, por)


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
        "UMBRAL_D": UMBRAL_D,
        "SISTEMA_ESTRUCTURAL": SISTEMA_ESTRUCTURAL,
        "SISTEMA_GRUPO": SISTEMA_GRUPO,
        "TIPO_ENTREPISO": TIPO_ENTREPISO,
        "ENTREPISO_GRUPO": ENTREPISO_GRUPO,
        "PERIODO_CONSTRUCCION": PERIODO_CONSTRUCCION,
        "USO": USO,
        "TIPO_INSPECCION": TIPO_INSPECCION,
        "GRADO_DANO": txt(GRADO_DANO),
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
