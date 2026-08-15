-- Brigada · Evaluación estructural en campo
-- Copyright (C) 2026 Rollout Comercio e Servicios Limitada / Andrés Benito Revollo Vélez
-- 
-- Este programa es software libre: usted puede redistribuirlo y/o
-- modificarlo bajo los términos de la Licencia Pública General Affero
-- de GNU publicada por la Free Software Foundation, en su versión 3 o
-- (a su elección) cualquier versión posterior.
-- 
-- Se distribuye con la esperanza de que sea útil, pero SIN NINGUNA
-- GARANTÍA; ni siquiera la garantía implícita de COMERCIABILIDAD o
-- IDONEIDAD PARA UN PROPÓSITO PARTICULAR. Vea la Licencia para más detalle.
-- 
-- Debería haber recibido una copia junto con este programa. Si no,
-- vea <https://www.gnu.org/licenses/>.

-- Esquema de la base de Brigadas (PostgreSQL 16 + PostGIS 3.4).
-- Idempotente: se puede volver a correr sin romper nada.
--   docker exec -i brigadas-db psql -U brigadas -d brigadas < esquema.sql

CREATE EXTENSION IF NOT EXISTS postgis;

CREATE TABLE IF NOT EXISTS evaluacion_brigada (
  id              text PRIMARY KEY,          -- ULID asignado por el servidor (ver mas abajo)
  ts              timestamptz NOT NULL,      -- cuando se llenó en campo
  recibido_en     timestamptz NOT NULL DEFAULT now(),  -- cuando sincronizó
  matricula       text NOT NULL,             -- quien firma; sin esto no se acepta
  inspector       text,
  brigada         text,
  geom            geometry(Point,4326),      -- puede ser NULL: se georreferencia después
  precision_m     int,
  direccion       text,
  municipio       text,
  barrio          text,
  sistema         text,
  uso             text,
  pisos           int,
  ocupantes       int,
  danos           jsonb,                     -- {portantes,horizontal,nostruct,terreno}: 0..3
  banderas        jsonb,                     -- condiciones de cierre, booleanas
  clasificacion   smallint NOT NULL,  -- habitabilidad firmada; ver la escala mas abajo
  clasificacion_auto smallint,               -- lo que calculó la regla
  motivo_auto     text,                      -- por qué lo calculó así
  justificacion   text,                      -- obligatorio si difiere del automático
  observaciones   text,
  fotos           jsonb                      -- rutas en disco, nunca base64
);

CREATE INDEX IF NOT EXISTS evaluacion_brigada_geom_idx   ON evaluacion_brigada USING gist (geom);
CREATE INDEX IF NOT EXISTS evaluacion_brigada_sector_idx ON evaluacion_brigada (municipio, barrio);
CREATE INDEX IF NOT EXISTS evaluacion_brigada_clasif_idx ON evaluacion_brigada (clasificacion);

-- ---------------------------------------------------------------------------
-- Cuatro niveles de habitabilidad (formulario V2F del IDIGER)
-- ---------------------------------------------------------------------------
--
--   1 Habitable · 2 Uso restringido · 3 No habitable · 4 Peligro de colapso
--
-- La escala de tres mezclaba dos decisiones distintas dentro del rojo: no entrar
-- a esta edificacion, y esta edificacion puede caerse sobre la calle. La segunda
-- acordona la via y evacua vecinos; no es el mismo acto.
--
-- Lo ya firmado NO se reescribe. Un rojo de la escala vieja queda en 3, que es
-- lo que decia su texto ("inseguro, no ingresar"); nadie sube a 4 de forma
-- retroactiva, porque 4 es un dictamen que ningun ingeniero firmo. `escala`
-- registra con cual se firmo cada fila, para que dentro de un año se pueda
-- distinguir "descarto el peligro de colapso" de "ni siquiera se lo preguntaron".
ALTER TABLE evaluacion_brigada ADD COLUMN IF NOT EXISTS escala smallint NOT NULL DEFAULT 3
  CHECK (escala IN (3,4));

ALTER TABLE evaluacion_brigada DROP CONSTRAINT IF EXISTS evaluacion_brigada_clasificacion_check;
ALTER TABLE evaluacion_brigada ADD CONSTRAINT evaluacion_brigada_clasificacion_check
  CHECK (clasificacion BETWEEN 1 AND escala);

-- Las cinco parciales A-E del V2F, tal como se calcularon. Se guardan porque el
-- formulario las imprime y porque son la explicacion de la global: sin ellas,
-- "3" es un numero sin defensa.
ALTER TABLE evaluacion_brigada ADD COLUMN IF NOT EXISTS parciales jsonb;
ALTER TABLE evaluacion_brigada ADD COLUMN IF NOT EXISTS parcial_manda text
  CHECK (parcial_manda IN ('A','B','C','D','E'));

-- ---------------------------------------------------------------------------
-- Formulario V2F completo
-- ---------------------------------------------------------------------------
--
-- El modo `triaje` llena el nucleo en cuatro minutos y produce una habitabilidad
-- valida con un V2F parcial. El modo `completo` habilita los bloques restantes y
-- produce un V2F entregable. Es el mismo modelo: `modo` dice cual se uso.
--
-- Los bloques van como jsonb y no como cien columnas a proposito. Las claves son
-- los numeros de casilla del formulario, que es la unica numeracion que importa
-- acá; lo que se consulta de verdad (la clasificacion, el sector, la fecha) ya
-- tiene columna propia desde antes.
ALTER TABLE evaluacion_brigada ADD COLUMN IF NOT EXISTS modo text NOT NULL DEFAULT 'triaje'
  CHECK (modo IN ('triaje','completo'));
ALTER TABLE evaluacion_brigada ADD COLUMN IF NOT EXISTS tipo_inspeccion smallint
  CHECK (tipo_inspeccion BETWEEN 1 AND 3);   -- completa / parcial / exterior

-- Identificacion catastral. Opcional en campo —casi nadie la sabe de memoria— y
-- completable despues desde el panel, que es trabajo de escritorio con conexion.
-- `catastral_origen` dice quien la puso: no es lo mismo leerla de un recibo en la
-- puerta que deducirla cruzando una direccion.
ALTER TABLE evaluacion_brigada ADD COLUMN IF NOT EXISTS cod_catastral text;
ALTER TABLE evaluacion_brigada ADD COLUMN IF NOT EXISTS catastral_origen text
  CHECK (catastral_origen IN ('campo','panel'));
ALTER TABLE evaluacion_brigada ADD COLUMN IF NOT EXISTS localidad text;
CREATE INDEX IF NOT EXISTS evaluacion_brigada_catastral_idx
  ON evaluacion_brigada (cod_catastral) WHERE cod_catastral IS NOT NULL;

-- Un jsonb por bloque del formulario. Los que quedan NULL son los que nadie
-- lleno, y salen listados en `bloques_faltantes`: un bloque vacio NO vale
-- "sin daño".
ALTER TABLE evaluacion_brigada ADD COLUMN IF NOT EXISTS v2f_estructura jsonb;
  -- sistema estructural, entrepiso, periodo, usos, pisos, sotanos, frente, fondo
ALTER TABLE evaluacion_brigada ADD COLUMN IF NOT EXISTS v2f_estado jsonb;
  -- bloque A: colapso, desviacion, cimentacion
ALTER TABLE evaluacion_brigada ADD COLUMN IF NOT EXISTS v2f_geotecnicos jsonb;
  -- bloque B: talud, asentamiento, grietas
ALTER TABLE evaluacion_brigada ADD COLUMN IF NOT EXISTS v2f_no_estructurales jsonb;
  -- bloque C: items 7 a 17, escala 1 a 5
ALTER TABLE evaluacion_brigada ADD COLUMN IF NOT EXISTS v2f_no_estructurales_pct jsonb;
  -- % de area afectada por item del bloque C. La Tabla 4 de la guia 2018
  -- clasifica por grado Y extension, pero el formulario impreso solo tiene
  -- casilla para el grado.
ALTER TABLE evaluacion_brigada ADD COLUMN IF NOT EXISTS v2f_estructurales jsonb;
  -- bloque D: items 18 a 21, % por grado que suma 100 en el piso de mayor daño
ALTER TABLE evaluacion_brigada ADD COLUMN IF NOT EXISTS v2f_entorno jsonb;
  -- bloque E: vecina critica, evento inminente
ALTER TABLE evaluacion_brigada ADD COLUMN IF NOT EXISTS v2f_preexistentes jsonb;
ALTER TABLE evaluacion_brigada ADD COLUMN IF NOT EXISTS v2f_recomendaciones jsonb;
ALTER TABLE evaluacion_brigada ADD COLUMN IF NOT EXISTS v2f_ocupacion jsonb;
  -- unidades existentes / no habitables, si esta habitada, nº de ocupantes
ALTER TABLE evaluacion_brigada ADD COLUMN IF NOT EXISTS v2f_comision jsonb;
  -- codigo del lider, nº de evaluadores, otro inspector
ALTER TABLE evaluacion_brigada ADD COLUMN IF NOT EXISTS nivel_mayor_dano smallint;
ALTER TABLE evaluacion_brigada ADD COLUMN IF NOT EXISTS area_afectada_pct smallint
  CHECK (area_afectada_pct BETWEEN 0 AND 100);
ALTER TABLE evaluacion_brigada ADD COLUMN IF NOT EXISTS bloques_faltantes text[];

-- Clasificacion global del dano (Tabla 10, pag. 54) derivada del % de area
-- afectada, y la habitabilidad que le corresponde (Tabla 9, pag. 53). NO
-- reemplaza a las cinco parciales: el V2F dice que la global es la mas
-- conservadora de A a E. Sirve de contraste — si el inspector estima 70 % de
-- area afectada y las parciales dan "uso restringido", hay algo que revisar.
ALTER TABLE evaluacion_brigada ADD COLUMN IF NOT EXISTS dano_global smallint
  CHECK (dano_global BETWEEN 1 AND 6);

-- Municipio segun la DIVIPOLA del DANE. El nombre escrito a mano produce
-- "Bogota", "BOGOTÁ" y "Bogotá, D.C." como tres sectores distintos, y el umbral
-- de anonimato del consolidado los cuenta por separado: tres grupos de cuatro
-- registros no llegan al minimo, uno de doce si. El codigo es ademas la llave
-- con la que cualquier entidad cruza contra sus propios datos.
ALTER TABLE evaluacion_brigada ADD COLUMN IF NOT EXISTS departamento text;
ALTER TABLE evaluacion_brigada ADD COLUMN IF NOT EXISTS cod_dane text;
CREATE INDEX IF NOT EXISTS evaluacion_brigada_dane_idx
  ON evaluacion_brigada (cod_dane) WHERE cod_dane IS NOT NULL;

-- De donde salio la coordenada. Un punto señalado a mano sobre el mapa no tiene
-- "precision en metros": esa cifra describe una medicion del GPS, y ponersela a
-- algo que alguien apunto con el dedo seria inventar una exactitud que nadie
-- midio. El agrupamiento por cercania del predio se apoya en esta distincion.
ALTER TABLE evaluacion_brigada ADD COLUMN IF NOT EXISTS origen_punto text
  CHECK (origen_punto IN ('gps','mapa','panel'));

-- ---------------------------------------------------------------------------
-- Historia del predio
-- ---------------------------------------------------------------------------
--
-- El V2F pregunta "¿existe una clasificacion previa? ¿cual?": contempla que un
-- predio se vuelva a evaluar. Nosotros no teniamos forma de decir que dos
-- evaluaciones son de la misma edificacion.
--
-- Se agrupan por cercania geografica, y el agrupamiento SOLO MUESTRA. Para
-- declarar que una evaluacion reemplaza a otra hay que señalar cual, con su
-- direccion y su foto a la vista. Nunca se enlaza solo: con precision de ±18 m
-- —normal en campo— en una manzana densa caben tres o cuatro predios dentro del
-- radio, y un enlace equivocado retiraria del consolidado el rojo del edificio
-- de al lado.
ALTER TABLE evaluacion_brigada ADD COLUMN IF NOT EXISTS reemplazada_por text
  REFERENCES evaluacion_brigada(id);
ALTER TABLE evaluacion_brigada ADD COLUMN IF NOT EXISTS reemplazo_en timestamptz;
ALTER TABLE evaluacion_brigada ADD COLUMN IF NOT EXISTS reemplazo_usuario text;

-- Una evaluacion no puede reemplazarse a si misma.
ALTER TABLE evaluacion_brigada DROP CONSTRAINT IF EXISTS evaluacion_brigada_reemplazo_check;
ALTER TABLE evaluacion_brigada ADD CONSTRAINT evaluacion_brigada_reemplazo_check
  CHECK (reemplazada_por IS DISTINCT FROM id);

-- `vigente` es lo que se cuenta. Una evaluacion reemplazada NO se borra ni se
-- oculta: sigue en los listados y en la exportacion, porque esa inspeccion
-- ocurrio y esta firmada. Lo que deja de hacer es contar dos veces el mismo
-- predio en el consolidado, en el mapa y en las colas.
ALTER TABLE evaluacion_brigada ADD COLUMN IF NOT EXISTS vigente boolean
  GENERATED ALWAYS AS (reemplazada_por IS NULL) STORED;
CREATE INDEX IF NOT EXISTS evaluacion_brigada_vigente_idx
  ON evaluacion_brigada (vigente) WHERE vigente;

-- ---------------------------------------------------------------------------
-- Compartimento reservado
-- ---------------------------------------------------------------------------
--
-- Persona de contacto (nombre, telefono, correo) y efecto en los ocupantes
-- (fallecidos, heridos, afectados). Son datos personales de un TERCERO, no del
-- inspector: Ley 1581 de 2012.
--
-- Va en UNA columna aparte y no repartido entre las demas, para que no depender
-- de que alguien se acuerde de excluir seis claves cada vez que escribe una
-- consulta. Quien no seleccione esta columna no puede filtrarlos por accidente.
--
--   listado, CSV, API de consulta, consolidado  ->  NUNCA
--   ficha individual, dentro del alcance de su brigada, y V2F exportado -> SI
ALTER TABLE evaluacion_brigada ADD COLUMN IF NOT EXISTS reservado jsonb;

COMMENT ON COLUMN evaluacion_brigada.reservado IS
  'Datos personales de terceros (Ley 1581/2012). No exponer fuera de la ficha '
  'individual ni del V2F exportado. Ver el bloque "Compartimento reservado" en esquema.sql.';

-- La vista `pendientes_de_catastral` vivia aca, y no podia: usa `id_local` y
-- `clasificacion_efectiva`, dos columnas que se agregan mas abajo con ALTER.
-- En una base ya existente daba igual —las columnas ya estaban— pero crear una
-- base DESDE CERO fallaba en esta linea, que es justo lo que hace el comando de
-- instalacion documentado. Las vistas van todas juntas, despues de la ultima
-- columna de la que dependen.

-- ---------------------------------------------------------------------------
-- Registro de brigadas e inspectores
-- ---------------------------------------------------------------------------

-- Una fila por brigada autorizada a sincronizar. El token NUNCA se guarda en
-- claro: se guarda su sha256. Si la base se filtra, los tokens no se filtran.
CREATE TABLE IF NOT EXISTS brigada (
  nombre      text PRIMARY KEY,
  token_hash  text NOT NULL UNIQUE,
  contacto    text,
  activa      boolean NOT NULL DEFAULT true,
  creada_en   timestamptz NOT NULL DEFAULT now()
);

-- Si esta brigada admite que firme quien no tiene matricula profesional.
--
-- Por defecto NO: la Ley 400/97 y la NSR-10 reservan el dictamen de habitabilidad
-- a quien tiene matricula, y ese fue el criterio del sistema desde el principio.
-- Pero las comisiones reales no siempre son de ingenieros matriculados —el
-- instrumento del PNUD para el sismo de agosto de 2026 pide "profesion" como
-- texto libre y ni siquiera menciona la matricula—, y rechazar en el servidor
-- deja el trabajo de esa jornada encerrado en un telefono.
--
-- La decision es de quien administra la brigada, y queda registrada evaluacion
-- por evaluacion: lo que NO se puede es que el sistema afirme que todo lo que
-- contiene lo firmo un matriculado cuando no es asi.
ALTER TABLE brigada ADD COLUMN IF NOT EXISTS exige_matricula boolean NOT NULL DEFAULT true;

-- Quién puede firmar. `vigente` es la baja lógica: nunca se borra un inspector
-- que ya firmó evaluaciones, porque su matrícula es parte del registro legal.
CREATE TABLE IF NOT EXISTS inspector (
  matricula          text PRIMARY KEY,
  nombre             text NOT NULL,
  brigada            text REFERENCES brigada(nombre),
  vigente            boolean NOT NULL DEFAULT true,
  verificada_copnia  boolean NOT NULL DEFAULT false,
  registrado_en      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS inspector_brigada_idx ON inspector (brigada);

-- Atribución: con qué credencial entró cada evaluación y si quien firmó estaba
-- registrado. Aditivas y con default, para no romper lo que ya está grabado.
ALTER TABLE evaluacion_brigada
  ADD COLUMN IF NOT EXISTS brigada_token text REFERENCES brigada(nombre);
ALTER TABLE evaluacion_brigada
  ADD COLUMN IF NOT EXISTS matricula_verificada boolean NOT NULL DEFAULT false;
CREATE INDEX IF NOT EXISTS evaluacion_brigada_token_idx ON evaluacion_brigada (brigada_token);

-- Identidad canónica asignada por el servidor.
--
-- El id que genera el teléfono (BRG-AAAAMMDD-NNN) se numera contra el total de
-- registros de ESE teléfono, así que dos brigadas emiten el mismo el mismo día.
-- Con ese id como clave primaria, la segunda evaluación chocaba contra el
-- ON CONFLICT, se descartaba en silencio y el teléfono la daba por enviada:
-- se perdía trabajo de campo, rojos incluidos, sin que nadie se enterara.
--
-- Ahora `id` es un ULID del servidor y el id del teléfono baja a `id_local`,
-- que solo sirve como llave de idempotencia dentro de su propia brigada.
ALTER TABLE evaluacion_brigada ADD COLUMN IF NOT EXISTS id_local text;
UPDATE evaluacion_brigada SET id_local = id WHERE id_local IS NULL;

-- Columna generada porque en SQL dos NULL no son iguales: sin esto, los envíos
-- con token heredado (brigada_token NULL) escaparían del índice único y
-- reintentar sí duplicaría.
ALTER TABLE evaluacion_brigada ADD COLUMN IF NOT EXISTS origen text
  GENERATED ALWAYS AS (coalesce(brigada_token, '(sin atribuir)')) STORED;

CREATE UNIQUE INDEX IF NOT EXISTS evaluacion_brigada_idem_idx
  ON evaluacion_brigada (origen, id_local);
CREATE INDEX IF NOT EXISTS evaluacion_brigada_id_local_idx
  ON evaluacion_brigada (id_local);

-- Con que se identifica quien firmo. 'matricula' es el caso normal; 'documento'
-- solo aparece si la brigada lo admite, y entonces se exigen documento Y
-- profesion. Anonimo, nunca.
ALTER TABLE evaluacion_brigada ADD COLUMN IF NOT EXISTS firma_tipo text NOT NULL
  DEFAULT 'matricula' CHECK (firma_tipo IN ('matricula','documento'));
ALTER TABLE evaluacion_brigada ADD COLUMN IF NOT EXISTS documento text;
ALTER TABLE evaluacion_brigada ADD COLUMN IF NOT EXISTS profesion text;

-- La columna `matricula` era NOT NULL. Esa garantia se cambia por otra mas
-- exacta: siempre hay UNA identidad, sea matricula o documento. Lo que no puede
-- haber es una evaluacion sin firmante.
ALTER TABLE evaluacion_brigada ALTER COLUMN matricula DROP NOT NULL;
ALTER TABLE evaluacion_brigada DROP CONSTRAINT IF EXISTS evaluacion_brigada_firmante_check;
ALTER TABLE evaluacion_brigada ADD CONSTRAINT evaluacion_brigada_firmante_check
  CHECK (matricula IS NOT NULL OR documento IS NOT NULL);

CREATE INDEX IF NOT EXISTS evaluacion_brigada_firma_idx
  ON evaluacion_brigada (firma_tipo) WHERE firma_tipo <> 'matricula';

-- ---------------------------------------------------------------------------
-- Doble revisión de los rojos
-- ---------------------------------------------------------------------------
--
-- Un rojo ordena no habitar una edificación. Que dependa del criterio de una sola
-- persona, tomado en veinte minutos y con réplicas de fondo, es mucho pedirle a
-- cualquiera. Por eso cada rojo entra en estado 'pendiente' y necesita que un
-- segundo inspector registrado lo mire.
--
-- Dos reglas que no se pueden relajar:
--   · El vencimiento NO degrada nada. Un rojo vencido sigue siendo rojo; solo se
--     vuelve visible como atrasado. Un temporizador no puede rebajar un desalojo.
--   · La firma original no se borra. La revisión es otro acto profesional, con su
--     propia matrícula y su motivo, y ambos quedan en el registro.
ALTER TABLE evaluacion_brigada
  ADD COLUMN IF NOT EXISTS revision_estado text
    CHECK (revision_estado IN ('pendiente','confirmado','revocado'));
ALTER TABLE evaluacion_brigada ADD COLUMN IF NOT EXISTS revision_vence timestamptz;
ALTER TABLE evaluacion_brigada ADD COLUMN IF NOT EXISTS revision_matricula text;
ALTER TABLE evaluacion_brigada ADD COLUMN IF NOT EXISTS revision_en timestamptz;
ALTER TABLE evaluacion_brigada DROP CONSTRAINT IF EXISTS
  evaluacion_brigada_revision_clasificacion_check;
ALTER TABLE evaluacion_brigada ADD COLUMN IF NOT EXISTS revision_clasificacion smallint;
ALTER TABLE evaluacion_brigada ADD CONSTRAINT evaluacion_brigada_revision_clasificacion_check
  CHECK (revision_clasificacion BETWEEN 1 AND 4);
ALTER TABLE evaluacion_brigada ADD COLUMN IF NOT EXISTS revision_motivo text;

-- Lo que vale operativamente. La columna `clasificacion` sigue siendo lo que
-- firmó quien evaluó, intacta; esta es la que hay que usar para consolidar.
ALTER TABLE evaluacion_brigada ADD COLUMN IF NOT EXISTS clasificacion_efectiva smallint
  GENERATED ALWAYS AS (coalesce(revision_clasificacion, clasificacion)) STORED;

CREATE INDEX IF NOT EXISTS evaluacion_brigada_revision_idx
  ON evaluacion_brigada (revision_estado, revision_vence);

-- Lo que ordena desalojo y todavia no tiene segunda mirada. Entran 3 y 4: los
-- dos vacian un edificio. El 4 va primero porque ademas compromete la via y a
-- los vecinos, y trae su propio plazo, mas corto.
-- Cola de trabajo del panel: lo que llego sin codigo catastral. Sin el, la
-- exportacion no se puede cruzar contra el catastro distrital.
DROP VIEW IF EXISTS pendientes_de_catastral;
CREATE VIEW pendientes_de_catastral AS
SELECT id, id_local, ts, recibido_en, brigada_token, direccion, municipio, barrio,
       clasificacion_efectiva, ST_Y(geom) AS lat, ST_X(geom) AS lon
  FROM evaluacion_brigada
 WHERE cod_catastral IS NULL AND vigente
 ORDER BY clasificacion_efectiva DESC, recibido_en DESC;

DROP VIEW IF EXISTS rojos_pendientes;
CREATE VIEW rojos_pendientes AS
SELECT id, id_local, ts, recibido_en, matricula, inspector, brigada_token,
       direccion, municipio, barrio, observaciones, justificacion,
       clasificacion, revision_vence,
       (revision_vence < now())                       AS vencido,
       round(extract(epoch FROM (now() - revision_vence)) / 3600.0, 1) AS horas_de_atraso
  FROM evaluacion_brigada
 WHERE revision_estado = 'pendiente' AND vigente
 ORDER BY clasificacion DESC, revision_vence;

-- Cola de revisión: quién firmó sin estar en el registro. No se rechaza en campo
-- —perder una evaluación es peor que aceptarla marcada— pero no puede pasar
-- inadvertido al consolidar.
DROP VIEW IF EXISTS pendientes_de_verificacion;
CREATE VIEW pendientes_de_verificacion AS
SELECT e.id, e.ts, e.matricula, e.inspector, e.brigada AS brigada_declarada,
       e.brigada_token AS brigada_autenticada, e.clasificacion,
       e.municipio, e.barrio
FROM evaluacion_brigada e
WHERE (NOT e.matricula_verificada OR e.firma_tipo <> 'matricula') AND e.vigente
ORDER BY e.clasificacion DESC, e.ts DESC;   -- los rojos primero

-- Quién coordina una brigada. Distinto del administrador del sistema: el
-- coordinador de una universidad necesita ver SU operación, no emitir tokens ni
-- leer los predios que levantó otra brigada. Con una sola clave para todo, darle
-- acceso a un coordinador externo era entregarle el sistema entero.
--
-- Los inspectores siguen sin tener cuenta: su matrícula es una firma, no un
-- acceso. Quien inicia sesión es quien coordina.
CREATE TABLE IF NOT EXISTS coordinador (
  usuario       text PRIMARY KEY,
  brigada       text NOT NULL REFERENCES brigada(nombre),
  nombre        text NOT NULL,
  clave_hash    text NOT NULL,
  activo        boolean NOT NULL DEFAULT true,
  creado_en     timestamptz NOT NULL DEFAULT now(),
  ultimo_acceso timestamptz
);
CREATE INDEX IF NOT EXISTS coordinador_brigada_idx ON coordinador (brigada);

-- Quién puede LEER por la API de consulta. Deliberadamente separado de `brigada`:
-- una brigada escribe evaluaciones desde un teléfono; un consumidor lee desde el
-- sistema de una alcaldía. Mezclar ambos en una sola credencial haría que filtrar
-- el token de un geoportal permitiera escribir evaluaciones falsas.
CREATE TABLE IF NOT EXISTS consumidor (
  nombre      text PRIMARY KEY,
  token_hash  text NOT NULL UNIQUE,
  -- 'consolidado' = solo agregados por sector, sin dato personal.
  -- 'detalle'     = direcciones y coordenadas. Solo para la entidad dueña de los
  --                 datos, y con finalidad declarada (Ley 1581 de 2012).
  alcance     text NOT NULL DEFAULT 'consolidado'
              CHECK (alcance IN ('consolidado','detalle')),
  municipios  text[],          -- NULL = todos; si no, solo esos
  contacto    text,
  activo      boolean NOT NULL DEFAULT true,
  creado_en   timestamptz NOT NULL DEFAULT now(),
  ultimo_uso  timestamptz,
  consultas   bigint NOT NULL DEFAULT 0
);

-- Solicitudes de información desde la página pública. Son datos personales de
-- un funcionario (Ley 1581 de 2012): se piden con autorización explícita, con
-- una finalidad declarada —responder esa solicitud— y nada más.
CREATE TABLE IF NOT EXISTS contacto (
  id         bigserial PRIMARY KEY,
  recibido_en timestamptz NOT NULL DEFAULT now(),
  nombre     text NOT NULL,
  entidad    text NOT NULL,
  correo     text NOT NULL,
  telefono   text,
  mensaje    text,
  atendido   boolean NOT NULL DEFAULT false
);

-- Lo único que sale hacia las autoridades: agregado por sector, sin predio ni
-- dirección (Ley 1581 de 2012), con umbral mínimo de registros por sector.
-- DROP + CREATE y no CREATE OR REPLACE: reemplazar una vista solo admite AGREGAR
-- columnas al final, y acá se insertó una en medio. Es idempotente igual.
DROP VIEW IF EXISTS consolidado_publico;
CREATE VIEW consolidado_publico AS
SELECT municipio, barrio,
       count(*)                                  AS evaluadas,
       -- Efectiva, no la firmada: si un segundo inspector revocó un rojo, el
       -- consolidado tiene que reflejar la realidad revisada.
       -- Los nombres son los del formulario y de la resolucion, no los del
       -- semaforo: el color vive en la interfaz, donde ayuda. Se renombro con
       -- cero credenciales de consulta emitidas, que era el momento de hacerlo.
       count(*) FILTER (WHERE clasificacion_efectiva = 1) AS habitables,
       count(*) FILTER (WHERE clasificacion_efectiva = 2) AS uso_restringido,
       count(*) FILTER (WHERE clasificacion_efectiva = 3) AS no_habitables,
       count(*) FILTER (WHERE clasificacion_efectiva = 4) AS peligro_colapso,
       count(*) FILTER (WHERE revision_estado = 'pendiente') AS sin_segunda_revision,
       ST_Centroid(ST_Collect(geom))             AS centro
FROM evaluacion_brigada
WHERE vigente          -- un predio reevaluado cuenta una vez, no dos
GROUP BY municipio, barrio
HAVING count(*) >= 5;   -- k-anonimato: no publicar sectores con muy pocos registros


-- ===========================================================================
-- Despacho: rutas de inspección
-- ===========================================================================
--
-- Hasta acá el sistema sabía qué SE EVALUÓ, pero no qué HABÍA QUE EVALUAR, así
-- que no podía decir qué faltaba: la pantalla de evolución lo confesaba por
-- escrito. Una ruta es ese plan.
--
-- Se asigna a UNA matrícula y no a la brigada entera. La matrícula sigue sin ser
-- una credencial —no hay cuenta de inspector— y por eso no autoriza nada: quien
-- autoriza es el token de brigada. La matrícula solo delimita a quién le toca
-- qué, dentro de una organización que ya comparte el token.
--
-- Una ruta es una LISTA DE DIRECCIONES de predios TODAVÍA NO VISITADOS: es el
-- dato personal más caducable del sistema (Ley 1581 de 2012). Por eso `vence_en`
-- no es decoración: es la orden de borrado que viaja al teléfono, y el teléfono
-- la obedece por su propio reloj, sin esperar confirmación del servidor. Si
-- dependiera del servidor, un teléfono sin señal se quedaría con la lista para
-- siempre, que es justo el escenario del que hay que protegerse.

CREATE TABLE IF NOT EXISTS ruta (
  id            text PRIMARY KEY,                 -- ULID del servidor, como evaluacion_brigada
  nombre        text NOT NULL,
  brigada       text NOT NULL REFERENCES brigada(nombre),
  matricula     text NOT NULL REFERENCES inspector(matricula),
  -- Cómo se armó. No cambia la forma de las visitas: cambia de dónde salieron,
  -- que es lo que hay que poder defender seis meses después.
  armado        text NOT NULL DEFAULT 'manual'
                CHECK (armado IN ('manual','area','revisita','csv')),
  -- El sector dibujado en el mapa (modo 'area'). MultiPolygon y no Polygon
  -- porque un sector real se dibuja en dos pedazos, con una quebrada en medio,
  -- más veces de las que uno quisiera.
  area          geometry(MultiPolygon,4326),
  jornada       date NOT NULL DEFAULT current_date,
  estado        text NOT NULL DEFAULT 'borrador'
                CHECK (estado IN ('borrador','despachada','cerrada','anulada')),
  -- Sube en CADA cambio de la ruta o de sus visitas. El teléfono compara para
  -- no volver a bajar direcciones que ya tiene.
  version       int  NOT NULL DEFAULT 1,
  notas         text,
  creada_en     timestamptz NOT NULL DEFAULT now(),
  creada_por    text NOT NULL,                    -- coordinador.usuario, o 'admin'
  despachada_en timestamptz,
  descargada_en timestamptz,                      -- primera bajada de un teléfono
  cerrada_en    timestamptz,
  vence_en      timestamptz NOT NULL
);

ALTER TABLE ruta ADD COLUMN IF NOT EXISTS version int NOT NULL DEFAULT 1;

ALTER TABLE ruta DROP CONSTRAINT IF EXISTS ruta_area_check;
ALTER TABLE ruta ADD CONSTRAINT ruta_area_check
  CHECK (armado <> 'area' OR area IS NOT NULL);

ALTER TABLE ruta DROP CONSTRAINT IF EXISTS ruta_vence_check;
ALTER TABLE ruta ADD CONSTRAINT ruta_vence_check
  CHECK (vence_en > creada_en);

CREATE INDEX IF NOT EXISTS ruta_brigada_idx ON ruta (brigada, estado, jornada DESC);
CREATE INDEX IF NOT EXISTS ruta_bajada_idx  ON ruta (brigada, matricula, estado);
CREATE INDEX IF NOT EXISTS ruta_area_idx    ON ruta USING gist (area);


-- Una parada. Lo que el teléfono muestra como "siguiente predio" y lo que el
-- panel cuenta como pendiente o hecha.
CREATE TABLE IF NOT EXISTS visita (
  id                text PRIMARY KEY,             -- ULID del servidor
  -- Sin ON DELETE CASCADE a propósito: las rutas NO se borran, se anulan. Un
  -- DELETE de mantenimiento debe fallar ruidosamente y no llevarse por delante
  -- visitas cerradas, que son el rastro de auditoría de un despacho.
  ruta              text NOT NULL REFERENCES ruta(id),
  -- Sin UNIQUE (ruta, orden): reordenar con un único obliga a pasar por estados
  -- intermedios en colisión, y el orden de una ruta es una sugerencia de
  -- recorrido, no una llave.
  orden             int  NOT NULL DEFAULT 0,
  direccion         text,
  municipio         text,
  barrio            text,
  localidad         text,
  cod_dane          text,                         -- llave estable del municipio
  cod_catastral     text,
  geom              geometry(Point,4326),
  referencia        text,                         -- "portón azul, al lado de la panadería"
  -- Modo revisita: qué evaluación se va a volver a mirar.
  evaluacion_previa text REFERENCES evaluacion_brigada(id),
  motivo            text CHECK (motivo IN
                      ('nueva','rojo_pendiente','sin_catastral','sin_coordenada','otra')),
  estado            text NOT NULL DEFAULT 'pendiente'
                    CHECK (estado IN ('pendiente','hecha','no_realizada','cancelada')),
  motivo_cierre     text CHECK (motivo_cierre IN
                      ('nadie','no_existe','rechazo','inaccesible','otra')),
  -- La evaluación que la cerró. La llena el SERVIDOR tras validar que la visita
  -- es de esta brigada; nunca es lo que afirmó el teléfono sin comprobar.
  evaluacion        text REFERENCES evaluacion_brigada(id),
  cerrada_en        timestamptz,
  nota_cierre       text,
  creada_en         timestamptz NOT NULL DEFAULT now()
);

-- Una visita tiene que poder encontrarse. Sin dirección, sin punto y sin
-- evaluación previa es un renglón en blanco que alguien va a tener que ir a
-- buscar a la calle.
ALTER TABLE visita DROP CONSTRAINT IF EXISTS visita_ubicable_check;
ALTER TABLE visita ADD CONSTRAINT visita_ubicable_check
  CHECK (direccion IS NOT NULL OR geom IS NOT NULL OR evaluacion_previa IS NOT NULL);

-- Tener evaluación implica hecha. Al revés NO: un coordinador puede marcar una
-- visita como hecha porque el inspector se lo reportó, y eso vale menos que una
-- evaluación firmada pero no es mentira.
ALTER TABLE visita DROP CONSTRAINT IF EXISTS visita_evaluacion_check;
ALTER TABLE visita ADD CONSTRAINT visita_evaluacion_check
  CHECK (evaluacion IS NULL OR estado = 'hecha');

ALTER TABLE visita DROP CONSTRAINT IF EXISTS visita_cierre_check;
ALTER TABLE visita ADD CONSTRAINT visita_cierre_check
  CHECK (estado = 'pendiente' OR cerrada_en IS NOT NULL);

ALTER TABLE visita DROP CONSTRAINT IF EXISTS visita_motivo_check;
ALTER TABLE visita ADD CONSTRAINT visita_motivo_check
  CHECK (estado = 'no_realizada' OR motivo_cierre IS NULL);

-- Una evaluación cierra UNA visita. Si el mismo predio se despachó dos veces por
-- error, la segunda queda pendiente y sale en el panel como lo que es —trabajo
-- duplicado— en vez de contarse dos veces como cobertura.
CREATE UNIQUE INDEX IF NOT EXISTS visita_evaluacion_idx
  ON visita (evaluacion) WHERE evaluacion IS NOT NULL;

CREATE INDEX IF NOT EXISTS visita_ruta_idx   ON visita (ruta, orden);
CREATE INDEX IF NOT EXISTS visita_estado_idx ON visita (estado) WHERE estado = 'pendiente';
CREATE INDEX IF NOT EXISTS visita_geom_idx   ON visita USING gist (geom);
CREATE INDEX IF NOT EXISTS visita_previa_idx ON visita (evaluacion_previa)
  WHERE evaluacion_previa IS NOT NULL;


-- Lo que el teléfono AFIRMÓ estar cerrando. Deliberadamente SIN foreign key.
--
-- Con FK, un id de visita vencido, anulado o de otra brigada convertiría una
-- evaluación perfectamente válida en un error de inserción, o sea en un 503, o
-- sea en una jornada atrapada en un teléfono. Es el mismo criterio que ya rige
-- para la matrícula fuera del registro: se acepta y se marca.
--
-- El enlace de verdad, el validado, vive en visita.evaluacion. Acá queda lo
-- declarado, para poder ver la diferencia. Es el mismo par que ya existe entre
-- `brigada` (declarada) y `brigada_token` (autenticada).
ALTER TABLE evaluacion_brigada ADD COLUMN IF NOT EXISTS visita_declarada text;
CREATE INDEX IF NOT EXISTS evaluacion_brigada_visita_idx
  ON evaluacion_brigada (visita_declarada) WHERE visita_declarada IS NOT NULL;


-- Cobertura por ruta: lo único que convierte "se hicieron 40 evaluaciones" en
-- "faltan 12". Se calcula acá y no en Python para que el panel, la exportación y
-- cualquier consulta futura cuenten lo mismo.
DROP VIEW IF EXISTS cobertura_ruta;
CREATE VIEW cobertura_ruta AS
SELECT r.id, r.nombre, r.brigada, r.matricula,
       i.nombre  AS inspector,
       i.vigente AS matricula_vigente,
       r.armado, r.estado, r.jornada, r.version, r.notas,
       r.creada_en, r.creada_por, r.despachada_en, r.descargada_en,
       r.cerrada_en, r.vence_en,
       (r.area IS NOT NULL) AS con_area,
       (r.estado = 'despachada' AND r.vence_en < now()) AS vencida,
       -- count(v.id) y NO count(*): con LEFT JOIN, una ruta sin visitas produce
       -- una fila con v.* en NULL y count(*) contaría 1. Una ruta recién creada
       -- diría que tiene una visita que no existe.
       count(v.id)                                        AS visitas,
       count(*) FILTER (WHERE v.estado = 'pendiente')     AS pendientes,
       count(*) FILTER (WHERE v.estado = 'hecha')         AS hechas,
       count(*) FILTER (WHERE v.estado = 'no_realizada')  AS no_realizadas,
       count(*) FILTER (WHERE v.estado = 'cancelada')     AS canceladas,
       count(*) FILTER (WHERE v.evaluacion IS NOT NULL)   AS con_evaluacion,
       round(100.0 * count(*) FILTER (WHERE v.estado <> 'pendiente')
             / nullif(count(v.id), 0))                    AS avance_pct,
       max(v.cerrada_en)                                  AS ultimo_cierre
FROM ruta r
LEFT JOIN visita v    ON v.ruta = r.id
LEFT JOIN inspector i ON i.matricula = r.matricula
GROUP BY r.id, i.nombre, i.vigente;

-- Lo que se levantó sin estar en ninguna ruta. NO es un reproche: en una
-- emergencia se evalúa lo que aparece en el camino, y eso es trabajo bueno. Es
-- una cifra APARTE para que el avance del plan no se infle con predios que el
-- plan nunca pidió.
--
-- OJO al consultarla: incluye TODO lo histórico anterior al despacho. Sin acotar
-- por fecha es un número enorme y sin significado.
DROP VIEW IF EXISTS evaluaciones_fuera_de_plan;
CREATE VIEW evaluaciones_fuera_de_plan AS
SELECT e.id, e.id_local, e.ts, e.recibido_en, e.brigada_token, e.matricula,
       e.municipio, e.barrio, e.direccion, e.clasificacion_efectiva,
       -- Si viene llena, el teléfono creyó estar cerrando una visita y el
       -- servidor no la aceptó: id vencido, de otra brigada, o ya cerrada.
       e.visita_declarada
FROM evaluacion_brigada e
WHERE e.vigente
  AND NOT EXISTS (SELECT 1 FROM visita v WHERE v.evaluacion = e.id);

-- Visitas de rutas ya vencidas que nadie cerró. La cola de trabajo del
-- coordinador al día siguiente: o se reasignan, o se cancelan con motivo.
DROP VIEW IF EXISTS visitas_vencidas;
CREATE VIEW visitas_vencidas AS
SELECT v.id, v.ruta, r.nombre AS ruta_nombre, r.brigada, r.matricula, r.jornada,
       v.orden, v.direccion, v.municipio, v.barrio, v.motivo,
       v.evaluacion_previa, r.vence_en,
       round(extract(epoch FROM (now() - r.vence_en)) / 3600.0, 1) AS horas_vencida
FROM visita v
JOIN ruta r ON r.id = v.ruta
WHERE v.estado = 'pendiente'
  AND r.estado = 'despachada'
  AND r.vence_en < now()
ORDER BY r.vence_en;


-- ===========================================================================
-- Reporte ciudadano
-- ===========================================================================
--
-- La única entrada al sistema que NO firma un profesional. Quien reporta es la
-- persona que vive en el inmueble, sin matrícula y sin cuenta.
--
-- Todo lo que sigue existe para sostener una frontera: esto es un INSUMO para
-- decidir a dónde mandar una brigada, y NUNCA una evaluación. No produce
-- clasificación, no alimenta `evaluacion_brigada`, no entra en
-- `consolidado_publico` y no sale en ninguna exportación a autoridades. Lo que
-- se entrega sigue saliendo solo de lo que firmó un ingeniero en sitio.
--
-- Se acota por EVENTO a propósito. El subdominio existe los 365 días del año y
-- la mayoría de esos días no hay sismo: un formulario abierto sin nadie leyendo
-- del otro lado recoge reportes que le hacen creer a una persona que ya hizo lo
-- que tenía que hacer. Sin evento activo la guía se muestra y el formulario no.

CREATE TABLE IF NOT EXISTS evento (
  id            text PRIMARY KEY,                 -- ULID del servidor
  nombre        text NOT NULL,                    -- "Sismo del 10 de agosto de 2026"
  descripcion   text,
  ocurrido_en   timestamptz NOT NULL,
  estado        text NOT NULL DEFAULT 'borrador'
                CHECK (estado IN ('borrador','activo','cerrado')),
  -- Al cerrarlo se purgan los datos de contacto de sus reportes. La fecha queda
  -- como constancia de que la purga corrió.
  cerrado_en    timestamptz,
  purgado_en    timestamptz,
  creado_en     timestamptz NOT NULL DEFAULT now(),
  creado_por    text NOT NULL,                    -- 'admin'; los eventos no los declara un coordinador
  -- Cupo de disco para las fotos de ESTE evento. Un canal público de subida de
  -- imágenes llena un disco más rápido de lo que uno cree, y es el mismo disco
  -- del que dependen las evaluaciones firmadas: el tope va por evento y no solo
  -- por petición.
  cupo_fotos_mb int NOT NULL DEFAULT 2048,
  -- Lo consumido, contado en la misma transacción que inserta el reporte. Medir
  -- el directorio en cada petición sería un recorrido de disco por reporte; y
  -- estimarlo dejaría el tope como una sugerencia.
  fotos_bytes   bigint NOT NULL DEFAULT 0
);
ALTER TABLE evento ADD COLUMN IF NOT EXISTS fotos_bytes bigint NOT NULL DEFAULT 0;

-- Solo un evento activo a la vez. Con dos, un reporte no sabría a cuál pertenece
-- y la página no sabría cuál guía mostrar.
CREATE UNIQUE INDEX IF NOT EXISTS evento_activo_idx
  ON evento ((estado)) WHERE estado = 'activo';


-- Dónde está abierto el formulario, y a quién se manda a la gente de ahí.
--
-- La lista es corta a propósito: son los municipios afectados de UN evento, no
-- los 1.122 del país. Ese es justamente el motivo de que el directorio de
-- autoridades sea mantenible — un directorio nacional permanente nadie lo
-- actualiza, y un teléfono muerto en plena emergencia es peor que ninguno.
CREATE TABLE IF NOT EXISTS evento_municipio (
  evento        text NOT NULL REFERENCES evento(id) ON DELETE CASCADE,
  cod_dane      text NOT NULL,                    -- DIVIPOLA; llave estable del municipio
  municipio     text NOT NULL,                    -- grafía del catálogo, para mostrar
  gravedad      text CHECK (gravedad IN ('leve','moderada','grave','critica')),
  -- El contacto local. Se muestra SOLO si alguien lo verificó, y con la fecha a
  -- la vista: quien lea la página tiene que poder juzgar qué tan viejo es el
  -- dato antes de marcar. Sin verificar, la guía dice qué buscar y no a quién
  -- llamar; la línea nacional se muestra siempre y no vive acá.
  entidad       text,
  telefono      text,
  verificado_en date,
  verificado_por text,
  notas         text,
  PRIMARY KEY (evento, cod_dane)
);

-- Un contacto sin fecha de verificación no se puede mostrar, así que tampoco se
-- puede guardar a medias: o está completo o no está.
ALTER TABLE evento_municipio DROP CONSTRAINT IF EXISTS evento_municipio_contacto_check;
ALTER TABLE evento_municipio ADD CONSTRAINT evento_municipio_contacto_check
  CHECK ((entidad IS NULL AND telefono IS NULL AND verificado_en IS NULL)
      OR (entidad IS NOT NULL AND telefono IS NOT NULL AND verificado_en IS NOT NULL));


CREATE TABLE IF NOT EXISTS reporte_ciudadano (
  id            text PRIMARY KEY,                 -- ULID del servidor
  -- El folio que se le da a la persona: RC-AAAAMMDD-NNNN. Es para que pueda
  -- referirse a su reporte, NO para consultarlo: no hay endpoint que lo devuelva.
  -- Un folio consultable convierte una tanda de folios adivinados en una lista
  -- de casas dañadas y vacías.
  folio         text NOT NULL UNIQUE,
  evento        text NOT NULL REFERENCES evento(id),
  recibido_en   timestamptz NOT NULL DEFAULT now(),

  -- Ubicación. El municipio lo ELIGE la persona de un catálogo; no se deduce de
  -- la coordenada. Los centroides del DANE ponen una casa de Suba en Cota y una
  -- de Bosa en Soacha, y acá el municipio decide a qué autoridad se manda a
  -- alguien: no puede salir de una aproximación.
  cod_dane      text NOT NULL,
  municipio     text NOT NULL,
  direccion     text NOT NULL,
  barrio        text,
  -- El punto, SOLO si la persona dijo estar frente al inmueble. Es la corrección
  -- al error de origen del módulo: después de un sismo la gente evacuó, y un GPS
  -- tomado sin preguntar registra el albergue donde está parada, no la casa
  -- dañada. Un racimo de reportes alrededor de un albergue no lo detecta nadie.
  geom          geometry(Point,4326),
  precision_m   int,
  en_sitio      boolean NOT NULL DEFAULT false,

  -- Las respuestas. Siete que deciden algo (tres escalan, dos arman el patrón de
  -- cuadra, dos dan contexto) y lo demás opcional. Cada pregunta de más es gente
  -- que abandona a mitad, y quien llena esto está asustado y con el teléfono en
  -- las últimas.
  respuestas    jsonb NOT NULL,
  relato        text,                             -- "¿quiere agregar algo más?"
  fotos         text[] NOT NULL DEFAULT '{}',     -- rutas en disco, nunca base64

  -- Compartimento reservado, igual que el de `evaluacion_brigada`: el teléfono
  -- de quien reporta. Fuera del CSV, del GeoJSON y del consolidado. Se BORRA al
  -- cerrar el evento —la lista de "casa dañada + dueño" deja de existir sola—,
  -- y por eso el reporte tiene que sobrevivir sin él: nada acá depende de que
  -- esta columna tenga contenido.
  reservado     jsonb,

  -- Triaje del panel. `escalado` lo pone el servidor por reglas simples sobre
  -- las respuestas: inclinación, colapso parcial u olor a gas. NO es una
  -- clasificación de habitabilidad y no se le muestra jamás a quien reporta.
  escalado      boolean NOT NULL DEFAULT false,
  motivo_escalado text,
  estado        text NOT NULL DEFAULT 'nuevo'
                CHECK (estado IN ('nuevo','en_ruta','descartado','duplicado')),
  visita        text REFERENCES visita(id),       -- si se convirtió en parada de una ruta
  revisado_por  text,
  revisado_en   timestamptz,
  nota_interna  text
);

COMMENT ON TABLE reporte_ciudadano IS
  'Insumo para decidir a dónde ir. NO es una evaluación: no produce clasificación '
  'de habitabilidad ni entra en consolidado_publico. Ver el bloque "Reporte '
  'ciudadano" en esquema.sql.';
COMMENT ON COLUMN reporte_ciudadano.reservado IS
  'Datos de contacto de quien reporta (Ley 1581/2012). No exponer fuera de la '
  'ficha individual. Se purga al cerrar el evento.';

CREATE INDEX IF NOT EXISTS reporte_ciudadano_evento_idx
  ON reporte_ciudadano (evento, estado, recibido_en DESC);
CREATE INDEX IF NOT EXISTS reporte_ciudadano_mun_idx
  ON reporte_ciudadano (evento, cod_dane);
CREATE INDEX IF NOT EXISTS reporte_ciudadano_geom_idx
  ON reporte_ciudadano USING gist (geom);
CREATE INDEX IF NOT EXISTS reporte_ciudadano_escalado_idx
  ON reporte_ciudadano (evento, recibido_en DESC) WHERE escalado;


-- El quinto modo de armar una ruta. Los cuatro anteriores salían de decisiones
-- del coordinador; este sale de lo que reportó la gente.
ALTER TABLE ruta DROP CONSTRAINT IF EXISTS ruta_armado_check;
ALTER TABLE ruta ADD CONSTRAINT ruta_armado_check
  CHECK (armado IN ('manual','area','revisita','csv','ciudadano'));


-- La cola del panel, ya agrupada. El valor no está en los reportes sueltos: está
-- en que diecinueve casas contiguas digan lo mismo, que es lo que separa el
-- movimiento del suelo —o de un edificio vecino— del daño aislado. Un humano no
-- ve eso en una lista de 472 filas.
--
-- Se agrupa por barrio dentro de municipio y no por distancia: el barrio es lo
-- que la gente escribe y lo que una brigada usa para caminar. Sin barrio cae en
-- '(sin barrio)', que es su propio racimo y no se mezcla con nadie.
DROP VIEW IF EXISTS racimos_ciudadanos;
CREATE VIEW racimos_ciudadanos AS
SELECT evento, cod_dane, municipio,
       coalesce(nullif(btrim(barrio),''), '(sin barrio)') AS sector,
       count(*)                                             AS reportes,
       count(*) FILTER (WHERE escalado)                     AS escalados,
       count(*) FILTER (WHERE estado = 'nuevo')             AS sin_revisar,
       count(*) FILTER (WHERE estado = 'en_ruta')           AS en_ruta,
       -- Las dos señales que hacen el patrón de cuadra. Juntas y en varias casas
       -- contiguas dicen algo que ninguna casa sola dice.
       count(*) FILTER (WHERE respuestas->>'puertas' = 'si')       AS puertas_trabadas,
       count(*) FILTER (WHERE respuestas->>'grietas_nuevas' = 'si') AS grietas_nuevas,
       min(recibido_en)                                     AS primero,
       max(recibido_en)                                     AS ultimo,
       -- Para centrar el mapa. Solo con los que se tomaron en sitio: promediar
       -- puntos de albergues correría el racimo a otro lado de la ciudad.
       avg(ST_Y(geom)) FILTER (WHERE en_sitio)              AS lat,
       avg(ST_X(geom)) FILTER (WHERE en_sitio)              AS lon
FROM reporte_ciudadano
WHERE estado <> 'descartado'
GROUP BY evento, cod_dane, municipio, sector;
