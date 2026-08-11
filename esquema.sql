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
  id              text PRIMARY KEY,          -- BRG-AAAAMMDD-NNN, generado en el telefono
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
  clasificacion   smallint NOT NULL CHECK (clasificacion IN (1,2,3)),  -- 1 verde 2 amarillo 3 rojo
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

-- Cola de revisión: quién firmó sin estar en el registro. No se rechaza en campo
-- —perder una evaluación es peor que aceptarla marcada— pero no puede pasar
-- inadvertido al consolidar.
CREATE OR REPLACE VIEW pendientes_de_verificacion AS
SELECT e.id, e.ts, e.matricula, e.inspector, e.brigada AS brigada_declarada,
       e.brigada_token AS brigada_autenticada, e.clasificacion,
       e.municipio, e.barrio
FROM evaluacion_brigada e
WHERE NOT e.matricula_verificada
ORDER BY e.clasificacion DESC, e.ts DESC;   -- los rojos primero

-- Lo único que sale hacia las autoridades: agregado por sector, sin predio ni
-- dirección (Ley 1581 de 2012), con umbral mínimo de registros por sector.
CREATE OR REPLACE VIEW consolidado_publico AS
SELECT municipio, barrio,
       count(*)                                  AS evaluadas,
       count(*) FILTER (WHERE clasificacion = 3) AS rojas,
       count(*) FILTER (WHERE clasificacion = 2) AS amarillas,
       count(*) FILTER (WHERE clasificacion = 1) AS verdes,
       ST_Centroid(ST_Collect(geom))             AS centro
FROM evaluacion_brigada
GROUP BY municipio, barrio
HAVING count(*) >= 5;   -- k-anonimato: no publicar sectores con muy pocos registros
