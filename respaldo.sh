#!/usr/bin/env bash
# Brigada · Evaluación estructural en campo
# Copyright (C) 2026 Rollout Comercio e Servicios Limitada / Andrés Benito Revollo Vélez
# Software libre bajo GNU AGPL v3.
#
# Respaldo de la base y de las fotos.
#
#   sudo /opt/brigadas/respaldo.sh
#
# Lo dispara brigadas-respaldo.timer una vez al día. Deja el resultado en un
# archivo de estado que /api/salud y el panel leen: sin MTA en el servidor, la
# forma de enterarse de que el respaldo dejó de correr es verlo en pantalla.
#
# Variables (en /etc/brigadas.env):
#   BRIGADA_RESPALDO_DIR      dónde se guardan          (por defecto /var/backups/brigadas)
#   BRIGADA_RESPALDO_CLAVE    passphrase de cifrado     (vacío = sin cifrar, solo local)
#   BRIGADA_RESPALDO_DIAS     retención                 (por defecto 14)
#   BRIGADA_RESPALDO_REMOTO   destino rsync externo     (vacío = solo local)
set -uo pipefail

ENV_FILE=/etc/brigadas.env
ESTADO=/var/lib/brigadas/respaldo-estado.json
CONTENEDOR=brigadas-db

# NO se hace `source` del archivo de entorno: es un EnvironmentFile de systemd,
# que no expande nada, y varios valores llevan `$` (el hash scrypt de la clave del
# panel, entre otros). Con `source` bash intentaría expandirlos y reventaría.
leer() { [ -r "$ENV_FILE" ] && sed -n "s/^$1=//p" "$ENV_FILE" | tail -1 || true; }

DESTINO="$(leer BRIGADA_RESPALDO_DIR)";   DESTINO="${DESTINO:-/var/backups/brigadas}"
CLAVE="$(leer BRIGADA_RESPALDO_CLAVE)"
DIAS="$(leer BRIGADA_RESPALDO_DIAS)";     DIAS="${DIAS:-14}"
REMOTO="$(leer BRIGADA_RESPALDO_REMOTO)"
SELLO="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
FECHA="$(date -u +%Y%m%d-%H%M)"

fallos_previos() { [ -r "$ESTADO" ] && grep -o '"fallos_consecutivos":[0-9]*' "$ESTADO" | cut -d: -f2 || echo 0; }

escribir_estado() {   # ok|mensaje|bytes_base|bytes_fotos
  local ok="$1" msg="$2" bb="${3:-0}" bf="${4:-0}" fallos
  if [ "$ok" = "true" ]; then fallos=0; else fallos=$(( $(fallos_previos) + 1 )); fi
  mkdir -p "$(dirname "$ESTADO")"
  cat > "$ESTADO" <<EOF
{"ok":$ok,"ts":"$SELLO","mensaje":"$msg","bytes_base":$bb,"bytes_fotos":$bf,
 "cifrado":$([ -n "$CLAVE" ] && echo true || echo false),
 "remoto":$([ -n "$REMOTO" ] && echo true || echo false),
 "retencion_dias":$DIAS,"fallos_consecutivos":$fallos}
EOF
  chmod 644 "$ESTADO"
  if [ "$ok" != "true" ]; then
    logger -t brigadas-respaldo -p daemon.err "FALLO: $msg (consecutivos: $fallos)"
    # Dos fallos seguidos ya no es un tropiezo: es que el respaldo dejó de correr.
    [ "$fallos" -ge 2 ] && logger -t brigadas-respaldo -p daemon.crit \
      "El respaldo lleva $fallos fallos seguidos. NO HAY COPIA RECIENTE."
  else
    logger -t brigadas-respaldo -p daemon.info "OK ($msg)"
  fi
}

abortar() { escribir_estado false "$1"; echo "respaldo: $1" >&2; exit 1; }

# Cifrar es opcional para una copia local, pero obligatorio si sale del servidor:
# el dump lleva direcciones y coordenadas de predios (Ley 1581 de 2012).
[ -n "$REMOTO" ] && [ -z "$CLAVE" ] && \
  abortar "hay destino remoto pero no hay BRIGADA_RESPALDO_CLAVE: no se envía sin cifrar"

mkdir -p "$DESTINO" && chmod 700 "$DESTINO" || abortar "no se pudo crear $DESTINO"
docker inspect -f '{{.State.Running}}' "$CONTENEDOR" 2>/dev/null | grep -q true \
  || abortar "el contenedor $CONTENEDOR no está corriendo"

# ---------------------------------------------------------------- base de datos
BASE="$DESTINO/brigadas-$FECHA.sql.gz"
# El pipe completo tiene que fallar si falla pg_dump, no solo si falla gzip.
if ! docker exec "$CONTENEDOR" pg_dump -U brigadas --clean --if-exists brigadas \
     | gzip -9 > "$BASE"; then
  rm -f "$BASE"; abortar "pg_dump falló"
fi
[ -s "$BASE" ] || { rm -f "$BASE"; abortar "el dump salió vacío"; }
# Un .gz que no descomprime no es un respaldo. Se verifica siempre, no se asume.
gzip -t "$BASE" || { rm -f "$BASE"; abortar "el dump comprimido está corrupto"; }

if [ -n "$CLAVE" ]; then
  if ! gpg --batch --yes --quiet --symmetric --cipher-algo AES256 \
       --passphrase "$CLAVE" --output "$BASE.gpg" "$BASE"; then
    rm -f "$BASE" "$BASE.gpg"; abortar "gpg falló al cifrar la base"
  fi
  rm -f "$BASE"; BASE="$BASE.gpg"
fi
chmod 600 "$BASE"
BYTES_BASE=$(stat -c%s "$BASE")

# ---------------------------------------------------------------------- fotos
FOTOS="$DESTINO/fotos-$FECHA.tar.gz"
BYTES_FOTOS=0
if [ -d /var/lib/brigadas/fotos ]; then
  if ! tar czf "$FOTOS" -C /var/lib/brigadas fotos; then
    rm -f "$FOTOS"; abortar "falló el empaquetado de fotos"
  fi
  if [ -n "$CLAVE" ]; then
    gpg --batch --yes --quiet --symmetric --cipher-algo AES256 \
        --passphrase "$CLAVE" --output "$FOTOS.gpg" "$FOTOS" \
      && { rm -f "$FOTOS"; FOTOS="$FOTOS.gpg"; } \
      || { rm -f "$FOTOS" "$FOTOS.gpg"; abortar "gpg falló al cifrar las fotos"; }
  fi
  chmod 600 "$FOTOS"
  BYTES_FOTOS=$(stat -c%s "$FOTOS")
fi

# --------------------------------------------------------------- copia externa
# Un respaldo en el mismo disco protege de un DELETE accidental o de una
# corrupción, pero NO de perder el disco, que es la amenaza que importa.
if [ -n "$REMOTO" ]; then
  rsync -a --timeout=120 "$BASE" "$FOTOS" "$REMOTO/" \
    || abortar "el respaldo local quedó bien pero rsync al destino externo falló"
fi

# ------------------------------------------------------------------- retención
find "$DESTINO" -maxdepth 1 -type f -name 'brigadas-*' -mtime +"$DIAS" -delete
find "$DESTINO" -maxdepth 1 -type f -name 'fotos-*'    -mtime +"$DIAS" -delete

RESUMEN="base $(numfmt --to=iec "$BYTES_BASE"), fotos $(numfmt --to=iec "$BYTES_FOTOS")"
[ -n "$REMOTO" ] && RESUMEN="$RESUMEN, copiado afuera"
[ -z "$CLAVE" ] && RESUMEN="$RESUMEN, SIN CIFRAR"
escribir_estado true "$RESUMEN" "$BYTES_BASE" "$BYTES_FOTOS"
echo "respaldo OK · $RESUMEN"
