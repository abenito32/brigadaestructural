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
