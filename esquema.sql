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

-- Cola de trabajo del panel: lo que llego sin codigo catastral. Sin el, la
-- exportacion no se puede cruzar contra el catastro distrital.
DROP VIEW IF EXISTS pendientes_de_catastral;
CREATE VIEW pendientes_de_catastral AS
SELECT id, id_local, ts, recibido_en, brigada_token, direccion, municipio, barrio,
       clasificacion_efectiva, ST_Y(geom) AS lat, ST_X(geom) AS lon
  FROM evaluacion_brigada
 WHERE cod_catastral IS NULL AND vigente
 ORDER BY clasificacion_efectiva DESC, recibido_en DESC;

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
WHERE NOT e.matricula_verificada AND e.vigente
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
