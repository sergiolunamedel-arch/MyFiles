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
# nivel Python) se revisan e instalan solas — no hace falta pasar ninguna
# bandera para "activarlas". Además, run.sh (el lanzador que este script
# genera) repite un chequeo rápido cada vez que se abre el programa: si ya
# están instaladas, el chequeo es prácticamente instantáneo; si falta algo
# (p.ej. se reinstaló el venv a mano), se instala sola en ese momento.
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
# Opcional: solo habilita la lectura de keystores .jks (scan_files). Se
# intenta siempre, pero si falla (p.ej. sin internet en este momento) no se
# detiene la instalación — simplemente esa fuente queda desactivada, y
# run.sh lo volverá a intentar solo cada vez que abras el programa.
pip install --quiet pyjks || echo "  Aviso: no se pudo instalar pyjks (soporte .jks); se omitirá esa fuente por ahora."
deactivate

echo "== 5/5 · Verificando perfil de Datacenter =="
if [[ ! -f dc_profile.json ]]; then
  echo "AVISO: no hay dc_profile.json en $(pwd)."
  echo "  Copia el perfil que corresponde a ESTE servidor, por ejemplo:"
  echo "    cp profiles/dc1_profile.example.json dc_profile.json"
  echo "  y edita 'targets' con los rangos reales de este Datacenter antes de arrancar."
else
  python3 - << 'PYEOF'
import json
p = json.load(open("dc_profile.json"))
print(f"  Perfil encontrado: {p.get('dc_name','(sin nombre)')}  ->  targets: {p.get('targets','(vacío)')}")
PYEOF
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
echo "Listo. Para arrancar:"
echo "  1) Si no lo hiciste ya: cp profiles/<perfil de este DC>.json dc_profile.json  (y edita 'targets')"
echo "  2) ./run.sh"
echo "     (o doble clic en el ícono del escritorio, si tienes sesión gráfica por VNC/RDP)"
echo "  Si el ícono no apareció donde esperabas, vuelve a correr con:"
echo "     ./install_dc.sh --rdp-user=<usuario con el que entras por RDP>"
