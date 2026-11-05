#!/usr/bin/env bash
# deploy.sh — Publica index.html en scan.bancobase.com
#
# Uso (desde /home/slunam/ScannerBaseSite):
#   ./deploy.sh              publica el index.html de esta carpeta
#   ./deploy.sh --rollback   restaura el último respaldo
#
# Origen:  la misma carpeta donde vive este script
# Destino: /var/www/ScannerBaseSite (DocumentRoot de Apache)

set -euo pipefail

SRC_DIR="$(cd "$(dirname "$0")" && pwd)"
SRC="$SRC_DIR/index.html"
DEST_DIR="/var/www/ScannerBaseSite"
DEST="$DEST_DIR/index.html"
BACKUP_DIR="/var/tmp/ScannerBaseSite-backups"
KEEP=10   # respaldos que se conservan

publicar_archivo() {
    # Copia a un temporal en el mismo directorio y luego renombra:
    # el cambio es atómico (nadie ve un archivo a medio copiar).
    sudo install -o root -g root -m 644 "$1" "$DEST.tmp"
    sudo mv -f "$DEST.tmp" "$DEST"
    sudo restorecon "$DEST"
}

verificar() {
    local esperado actual http
    esperado=$(sudo md5sum "$1" | cut -d' ' -f1)
    actual=$(sudo md5sum "$DEST" | cut -d' ' -f1)
    if [[ "$esperado" != "$actual" ]]; then
        echo "ERROR: el archivo publicado no coincide con el origen."
        exit 1
    fi
    http=$(curl -s -o /dev/null -w '%{http_code}' \
        --resolve scan.bancobase.com:443:127.0.0.1 https://scan.bancobase.com/ || true)
    echo "OK: publicado (md5 $actual). Respuesta del sitio: HTTP $http"
    echo "Si el navegador muestra la versión anterior, recarga con Ctrl+F5."
}

# ---------- Rollback ----------
if [[ "${1:-}" == "--rollback" ]]; then
    ULTIMO=$(sudo ls -1t "$BACKUP_DIR"/index.html.* 2>/dev/null | head -1 || true)
    if [[ -z "$ULTIMO" ]]; then
        echo "ERROR: no hay respaldos en $BACKUP_DIR"
        exit 1
    fi
    echo "Restaurando $ULTIMO"
    publicar_archivo "$ULTIMO"
    verificar "$ULTIMO"
    exit 0
fi

# ---------- Validaciones ----------
if [[ ! -f "$SRC" ]]; then
    echo "ERROR: no existe $SRC"
    exit 1
fi
if ! grep -qi '<html' "$SRC"; then
    echo "ERROR: $SRC no parece un archivo HTML. No se publica."
    exit 1
fi
if sudo cmp -s "$SRC" "$DEST"; then
    echo "Sin cambios: ese index.html ya está publicado."
    exit 0
fi

# ---------- Respaldo ----------
sudo mkdir -p "$BACKUP_DIR"
if sudo test -f "$DEST"; then
    TS=$(date +%F_%H%M%S)
    sudo cp -a "$DEST" "$BACKUP_DIR/index.html.$TS"
    echo "Respaldo: $BACKUP_DIR/index.html.$TS"
fi
# Conserva solo los últimos $KEEP respaldos
sudo ls -1t "$BACKUP_DIR"/index.html.* 2>/dev/null \
    | tail -n +$((KEEP + 1)) | xargs -r sudo rm -f || true

# ---------- Publicar ----------
publicar_archivo "$SRC"
verificar "$SRC"
