#!/usr/bin/env bash
# install_dc.sh — instala una instancia del descubridor de certificados en
# este servidor (un servidor = un Datacenter).
#
# Requiere sesión gráfica accesible por RDP/VNC (Tkinter necesita un
# display X). Si este servidor todavía no la tiene, corre PRIMERO:
#   sudo ./setup_remote_desktop.sh
# (deja XFCE + xrdp listos para conectarte con el Escritorio Remoto de
# Windows). Este script (install_dc.sh) no necesita sesión gráfica para
# correr — solo la GUI resultante la necesita para mostrarse.
#
# Todas las dependencias (Tkinter a nivel sistema, cryptography y pyjks a
# nivel Python — incluido el compilador C que pyjks a veces necesita) se
# revisan e instalan solas, sin banderas. run.sh (el lanzador que este
# script genera) repite un chequeo rápido de las dependencias Python cada
# vez que se abre el programa: si ya están, el chequeo es instantáneo; si
# falta algo, se instala sola en ese momento.
#
# Este script también arma dc_profile.json de forma interactiva si no
# existe todavía: busca plantillas en ./profiles, o pregunta el nombre del
# Datacenter y los rangos a escanear y lo genera él mismo.
#
# Uso:
#   ./install_dc.sh                          # instala en ./venv junto al script
#   ./install_dc.sh --rdp-user=certdisco     # crea el ícono de escritorio para ESE usuario
#                                             # (necesario si corres este script como root/sudo
#                                             # o como un usuario distinto al que hará login por
#                                             # RDP/VNC — de lo contrario el ícono termina en el
#                                             # home equivocado, o ni se crea)
#
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

RDP_USER=""
for arg in "$@"; do
  [[ "$arg" == --rdp-user=* ]] && RDP_USER="${arg#--rdp-user=}"
done

echo "== 1/5 · Revisando Python 3 =="
if ! command -v python3 >/dev/null 2>&1; then
  echo "ERROR: no se encontró python3. Instálalo primero (paquete 'python3' de tu distro) y vuelve a correr este script." >&2
  exit 1
fi
python3 --version

echo "== 2/5 · Revisando Tkinter (lo necesita la interfaz gráfica) =="
if ! python3 -c "import tkinter" >/dev/null 2>&1; then
  echo "Tkinter no está instalado. Intentando instalarlo…"
  if command -v apt-get >/dev/null 2>&1; then
    sudo apt-get update -qq && sudo apt-get install -y python3-tk
  elif command -v dnf >/dev/null 2>&1; then
    sudo dnf install -y python3-tkinter
  elif command -v yum >/dev/null 2>&1; then
    sudo yum install -y python3-tkinter
  elif command -v zypper >/dev/null 2>&1; then
    sudo zypper install -y python3-tk
  else
    echo "ERROR: no reconozco el gestor de paquetes de este sistema." >&2
    echo "Instala manualmente el paquete de Tkinter para Python 3 y vuelve a correr este script." >&2
    exit 1
  fi
fi
python3 -c "import tkinter; print('Tkinter OK, versión Tcl/Tk', tkinter.TclVersion)"

echo "== 3/5 · Creando entorno virtual (./venv) =="
# --system-site-packages: Tkinter vive en el Python del sistema, no en pip;
# el venv necesita verlo.
if [[ ! -d venv ]]; then
  python3 -m venv --system-site-packages venv
fi
source venv/bin/activate

echo "== 4/5 · Instalando dependencias Python =="
pip install --quiet --upgrade pip
# Obligatoria: el programa no arranca sin ella.
pip install --quiet cryptography

# Opcional: solo habilita la lectura de keystores .jks (scan_files). pyjks
# depende de 'twofish', que a veces necesita compilar código C. Primero se
# intenta normal (rápido, sin tocar el sistema); solo si falla POR FALTA DE
# COMPILADOR se instala uno y se reintenta una vez. Si de plano no se puede
# (sin internet, gestor de paquetes desconocido, etc.) no se detiene la
# instalación — esa fuente simplemente queda desactivada.
PYJKS_LOG="$(mktemp)"
if ! pip install --quiet pyjks >"$PYJKS_LOG" 2>&1; then
  if grep -qiE "gcc|compiler|failed building wheel|error: command" "$PYJKS_LOG"; then
    echo "  pyjks necesita compilar una dependencia y falta un compilador C. Instalando herramientas de compilación…"
    if command -v apt-get >/dev/null 2>&1; then
      sudo apt-get update -qq && sudo apt-get install -y build-essential || true
    elif command -v dnf >/dev/null 2>&1; then
      sudo dnf groupinstall -y "Development Tools" || sudo dnf install -y gcc gcc-c++ make || true
    elif command -v yum >/dev/null 2>&1; then
      sudo yum groupinstall -y "Development Tools" || sudo yum install -y gcc gcc-c++ make || true
    elif command -v zypper >/dev/null 2>&1; then
      sudo zypper install -y -t pattern devel_basis || sudo zypper install -y gcc gcc-c++ make || true
    else
      echo "  No reconozco el gestor de paquetes de este sistema; instala un compilador C manualmente si quieres soporte .jks."
    fi
    pip install --quiet pyjks || echo "  Aviso: sigue sin poder instalarse pyjks (soporte .jks); se omitirá esa fuente por ahora."
  else
    echo "  Aviso: no se pudo instalar pyjks (soporte .jks); se omitirá esa fuente por ahora."
  fi
fi
rm -f "$PYJKS_LOG"
deactivate

echo "== 5/5 · Configuración del Datacenter (dc_profile.json) =="

# Crea/reescribe dc_profile.json con dc_name/targets dados y el resto de
# campos en sus valores por defecto (mismo esquema que profiles/*.example.json).
write_dc_profile() {
  python3 - "$1" "$2" << 'PYEOF'
import json, sys
dc_name, targets = sys.argv[1], sys.argv[2]
profile = {
    "_nota": "Generado por install_dc.sh. Edita cualquier campo a mano si lo necesitas.",
    "dc_name": dc_name,
    "targets": targets,
    "ports": "443,8443,9443,25,587,465,143,993,110,995,21,389,636,5432,3306",
    "starttls": "auto",
    "exclude": "",
    "concurrency": 300,
    "timeout": 3.0,
    "check_trust": False,
    "resolve_ptr": True,
    "check_revocation": False,
    "sni": "",
    "files": "",
    "schedule_minutes": 1440,
    "autostart": False,
}
json.dump(profile, open("dc_profile.json", "w"), indent=2, ensure_ascii=False)
print(f"  dc_profile.json escrito: {dc_name}  ->  targets: {targets}")
PYEOF
}

show_dc_profile() {
  python3 - << 'PYEOF'
import json
p = json.load(open("dc_profile.json"))
print(f"  Perfil actual: {p.get('dc_name','(sin nombre)')}  ->  targets: {p.get('targets','(vacío)')}")
PYEOF
}

if [[ -f dc_profile.json ]]; then
  show_dc_profile
elif [[ -t 0 ]]; then
  # Sesión interactiva y todavía no hay dc_profile.json: lo armamos aquí mismo.
  mapfile -t TEMPLATES < <(ls profiles/*.json 2>/dev/null || true)
  CHOSEN=""
  if [[ ${#TEMPLATES[@]} -gt 0 ]]; then
    echo "  Encontré estas plantillas en ./profiles:"
    for i in "${!TEMPLATES[@]}"; do
      echo "    $((i+1))) ${TEMPLATES[$i]}"
    done
    echo "    0) Ninguna — crear un perfil nuevo desde cero"
    read -rp "  ¿Cuál corresponde a ESTE servidor? [1]: " sel
    sel="${sel:-1}"
    [[ "$sel" =~ ^[0-9]+$ ]] || sel=1
    if [[ "$sel" != "0" && -n "${TEMPLATES[$((sel-1))]:-}" ]]; then
      CHOSEN="${TEMPLATES[$((sel-1))]}"
      cp "$CHOSEN" dc_profile.json
      echo "  Copiado: $CHOSEN -> dc_profile.json"
    fi
  fi
  if [[ -z "$CHOSEN" ]]; then
    echo "  Vamos a crear dc_profile.json para este servidor."
    read -rp "  Nombre de este Datacenter (p.ej. DC1): " dc_name
    read -rp "  Rangos a escanear, coma-separados (p.ej. 10.10.0.0/16,10.11.0.0/16): " targets
    write_dc_profile "$dc_name" "$targets"
  fi
  show_dc_profile
  read -rp "  ¿Correcto? [S/n]: " ok
  if [[ "$ok" =~ ^[nN] ]]; then
    read -rp "  Nombre de este Datacenter: " dc_name
    read -rp "  Rangos a escanear, coma-separados: " targets
    write_dc_profile "$dc_name" "$targets"
  fi
else
  echo "AVISO: no hay dc_profile.json en $(pwd), y esta sesión no es interactiva."
  echo "  Cópialo/edítalo manualmente:"
  echo "    cp profiles/<perfil de este DC>.json dc_profile.json"
  echo "  y edita 'targets' con los rangos reales de este Datacenter antes de arrancar."
fi

# Lanzador: activa el venv, se asegura de tener sus dependencias (chequeo
# rápido — solo instala si de verdad falta algo) y abre la GUI.
cat > run.sh << 'EOF'
#!/usr/bin/env bash
cd "$(dirname "${BASH_SOURCE[0]}")"
source venv/bin/activate

# --- Autochequeo de dependencias --------------------------------------- #
# Se corre cada vez que se abre el programa (doble clic en el ícono o
# ./run.sh). El import de un paquete ya instalado tarda milisegundos, así
# que si todo está en orden esto no se nota. Si falta algo, se instala
# solo (silenciosamente para las obligatorias; con aviso si falla una
# opcional) y luego arranca la GUI normalmente.
python3 - << 'PYEOF'
import importlib, subprocess, sys

# import_name -> (paquete de pip, obligatoria?)
DEPS = {
    "cryptography": ("cryptography", True),   # sin esto el programa no arranca
    "jks":          ("pyjks",       False),   # solo habilita lectura de .jks
}

def instalado(mod):
    try:
        importlib.import_module(mod)
        return True
    except ImportError:
        return False

faltantes = {mod: info for mod, info in DEPS.items() if not instalado(mod)}
if not faltantes:
    sys.exit(0)  # todo presente — no se llama a pip, arranque sin demora

for mod, (paquete, obligatoria) in faltantes.items():
    print(f"[deps] Falta '{paquete}', instalando…")
    r = subprocess.run([sys.executable, "-m", "pip", "install", "--quiet", paquete])
    if r.returncode != 0:
        msg = f"[deps] No se pudo instalar '{paquete}'."
        if obligatoria:
            sys.exit(msg + " El programa no puede arrancar sin ella. "
                      "Revisa la conexión a internet de este servidor e intenta de nuevo.")
        else:
            print(msg + " Se continúa sin soporte para esa fuente opcional.")
PYEOF
[[ $? -ne 0 ]] && exit 1

python3 cert_discovery_gui.py
EOF
chmod +x run.sh

# Icono de escritorio (doble clic) para el operador que entra por VNC/RDP —
# mismo espíritu que abrir el cliente de Venafi.
#
# OJO: $HOME es el home de quien EJECUTA este script, que no necesariamente
# es el usuario que hará RDP (p.ej. si corres install_dc.sh como root justo
# después de setup_remote_desktop.sh, o por SSH con otro usuario). Si no se
# pasó --rdp-user=, usamos $SUDO_USER (si corriste con sudo) o el usuario
# actual como mejor esfuerzo — pero lo correcto es pasar --rdp-user=<mismo
# usuario que usaste en setup_remote_desktop.sh>.
if [[ -z "$RDP_USER" ]]; then
  RDP_USER="${SUDO_USER:-$(id -un)}"
fi

DESKTOP_USER_HOME=$(getent passwd "$RDP_USER" 2>/dev/null | cut -d: -f6) || true
if [[ -z "$DESKTOP_USER_HOME" ]]; then
  echo "AVISO: no encontré al usuario '$RDP_USER' (getent passwd); omito el ícono de escritorio."
  echo "  Créalo luego con: ./install_dc.sh --rdp-user=<usuario-que-hará-RDP>"
else
  DESKTOP_DIR="$DESKTOP_USER_HOME/Desktop"
  # XFCE solo crea ~/Desktop la primera vez que alguien abre sesión gráfica
  # ahí. Si este script corre ANTES de ese primer login (lo normal, ya que
  # install_dc.sh no necesita sesión gráfica para correr), el directorio
  # todavía no existe — antes eso hacía que el ícono se omitiera en silencio.
  mkdir -p "$DESKTOP_DIR"
  cat > "$DESKTOP_DIR/Descubrimiento-Certificados.desktop" << EOF
[Desktop Entry]
Type=Application
Name=Descubrimiento de Certificados
Comment=SecDevOps · Banco Base
Exec=$(pwd)/run.sh
Path=$(pwd)
Terminal=false
Categories=Utility;
EOF
  chmod +x "$DESKTOP_DIR/Descubrimiento-Certificados.desktop"
  if [[ "$(id -un)" == "root" ]]; then
    chown -R "$RDP_USER":"$RDP_USER" "$DESKTOP_USER_HOME/Desktop" 2>/dev/null || true
  fi
  echo "  Ícono de escritorio creado para '$RDP_USER' en $DESKTOP_DIR"
fi

echo
if [[ -f dc_profile.json ]]; then
  echo "Listo. Para arrancar:"
  echo "  ./run.sh"
else
  echo "Listo, pero falta configurar este Datacenter:"
  echo "  cp profiles/<perfil de este DC>.json dc_profile.json   (o créalo a mano)"
  echo "  y edita 'targets' con los rangos reales antes de arrancar con ./run.sh"
fi
echo "  (o doble clic en el ícono del escritorio, si tienes sesión gráfica por VNC/RDP)"
echo "Si el ícono no apareció donde esperabas, vuelve a correr con:"
echo "   ./install_dc.sh --rdp-user=<usuario con el que entras por RDP>"
