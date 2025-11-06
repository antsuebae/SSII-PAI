#!/usr/bin/env bash
# pc_hardening_interactive.sh
# Script interactivo (endpoint) para PAI-3:
#  - Ejecuta Lynis (quick) con timeout
#  - Lee SIEMPRE el Hardening Index (0-100) de forma fiable (lynis-report.dat)
#  - Muestra un menú de mejoras aplicables y aplica las seleccionadas
#  - Repite Lynis y muestra el Hardening Index final
#
# Uso:
#   chmod +x pc_hardening_interactive.sh
#   sudo ./pc_hardening_interactive.sh
#
set -euo pipefail

TIMEOUT_SECONDS="${TIMEOUT_SECONDS:-180}"   # Ajustable: TIMEOUT_SECONDS=240 sudo ./pc_hardening_interactive.sh
WORKDIR="$(pwd)/pc_hardening_outputs"
mkdir -p "$WORKDIR"
RUN_ID="$(date +%Y%m%d_%H%M%S)"
LYNIS_BIN="$(command -v lynis || true)"

trap 'echo; echo "[!] Escaneo interrumpido por el usuario. Pasando al menú de mejoras...";' INT

check_prereqs() {
  if [[ -z "$LYNIS_BIN" ]]; then
    echo "ERROR: Lynis no está instalado. Instálalo con:"
    echo "  sudo apt update && sudo apt install -y lynis"
    exit 1
  fi
}

backup_file() {
  local f="$1"
  if [[ -f "$f" ]]; then
    sudo cp -a "$f" "${f}.bak.${RUN_ID}"
    echo "Backup: ${f} -> ${f}.bak.${RUN_ID}"
  fi
}

# Lee el índice desde el texto y, de forma fiable, desde /var/log/lynis-report.dat
parse_hardening_index() {
  local out_txt="$1"
  local idx line

  # 1) Preferencia: fichero oficial de datos
  if sudo test -r /var/log/lynis-report.dat; then
    idx="$(sudo awk -F= '/^hardening_index=/{v=$2} END{if (v!="" ) print v;}' /var/log/lynis-report.dat 2>/dev/null || true)"
    if [[ -n "$idx" ]]; then
      echo "$idx"; return 0
    fi
  fi

  # 2) Respaldo: parseo robusto del texto
  line="$(grep -iE '^[[:space:]]*Hardening index[[:space:]]*:' "$out_txt" 2>/dev/null | tail -n1 || true)"
  if [[ -n "$line" ]]; then
    idx="$(echo "$line" | sed -n 's/.*Hardening index[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p' | head -n1 || true)"
    if [[ -n "$idx" ]]; then
      echo "$idx"; return 0
    fi
    idx="$(echo "$line" | sed -n 's/.*\[\([0-9][0-9]*\)\].*/\1/p' | head -n1 || true)"
    if [[ -n "$idx" ]]; then
      echo "$idx"; return 0
    fi
  fi

  echo "N/A"
}

run_lynis_quick() {
  local tag="$1"
  local out="$WORKDIR/lynis_${tag}_${RUN_ID}.txt"
  echo "=== Ejecutando Lynis (quick) con timeout ${TIMEOUT_SECONDS}s... ==="
  echo "(Puedes ajustar con: TIMEOUT_SECONDS=240 sudo ./pc_hardening_interactive.sh)"
  set +e
  if [[ $EUID -ne 0 ]]; then
    timeout --preserve-status "${TIMEOUT_SECONDS}" sudo "$LYNIS_BIN" audit system --quick --no-colors 2>&1 | tee "$out"
    rc=${PIPESTATUS[0]}
  else
    timeout --preserve-status "${TIMEOUT_SECONDS}" "$LYNIS_BIN" audit system --quick --no-colors 2>&1 | tee "$out"
    rc=${PIPESTATUS[0]}
  fi
  set -e

  case "$rc" in
    0)   echo "[OK] Lynis finalizado." ;;
    124) echo "[!] Timeout (${TIMEOUT_SECONDS}s). Continuamos igualmente." ;;
    130) echo "[!] Interrumpido con Ctrl-C. Continuamos igualmente." ;;
    *)   echo "[!] Lynis terminó con código $rc. Continuamos igualmente." ;;
  esac

  local hi
  hi="$(parse_hardening_index "$out")"
  if [[ "$hi" != "N/A" ]]; then
    echo ">>> Hardening index (${tag}): ${hi}"
  else
    echo ">>> No se pudo extraer el Hardening index (${tag})."
  fi
  echo "Informe guardado en: $out"
  echo
  echo "$out"
}

improve_password_policy() {
  echo
  echo "Mejora: Políticas de contraseñas (libpam-pwquality + ageing)."
  read -r -p "¿Aplicar? [y/N]: " ans
  [[ ! "$ans" =~ ^[Yy]$ ]] && { echo "Omitido."; return; }
  sudo apt update
  sudo apt install -y libpam-pwquality || true

  backup_file /etc/login.defs
  sudo cp /etc/login.defs /etc/login.defs.orig."${RUN_ID}" 2>/dev/null || true
  sudo sed -i -E '/^PASS_MAX_DAYS/s/.*/PASS_MAX_DAYS\t90/' /etc/login.defs || sudo sh -c 'echo "PASS_MAX_DAYS\t90" >> /etc/login.defs'
  sudo sed -i -E '/^PASS_MIN_DAYS/s/.*/PASS_MIN_DAYS\t7/' /etc/login.defs || sudo sh -c 'echo "PASS_MIN_DAYS\t7" >> /etc/login.defs'
  sudo sed -i -E '/^PASS_WARN_AGE/s/.*/PASS_WARN_AGE\t14/' /etc/login.defs || sudo sh -c 'echo "PASS_WARN_AGE\t14" >> /etc/login.defs'
  if grep -q '^UMASK' /etc/login.defs 2>/dev/null; then
    sudo sed -i -E 's/^UMASK.*/UMASK 027/' /etc/login.defs
  else
    sudo sh -c 'echo "UMASK 027" >> /etc/login.defs'
  fi

  backup_file /etc/pam.d/common-password
  if ! grep -q 'pam_pwquality.so' /etc/pam.d/common-password 2>/dev/null; then
    sudo bash -c 'echo "password    requisite           pam_pwquality.so retry=3 minlen=12 difok=4" >> /etc/pam.d/common-password'
    echo "Añadido pam_pwquality a /etc/pam.d/common-password"
  else
    echo "pam_pwquality ya estaba configurado."
  fi
}

improve_ufw() {
  echo
  echo "Mejora: Configurar y activar UFW (firewall)."
  read -r -p "¿Aplicar? [y/N]: " ans
  [[ ! "$ans" =~ ^[Yy]$ ]] && { echo "Omitido."; return; }
  sudo apt update
  sudo apt install -y ufw || true
  sudo ufw default deny incoming
  sudo ufw default allow outgoing
  if ss -tln | grep -q ':22 '; then
    sudo ufw allow 22/tcp
    echo "Regla: Allow 22/tcp (SSH)"
  fi
  sudo ufw --force enable
  sudo ufw status verbose
}

improve_banners() {
  echo
  echo "Mejora: Añadir banner legal en /etc/issue y /etc/issue.net"
  read -r -p "¿Aplicar? [y/N]: " ans
  [[ ! "$ans" =~ ^[Yy]$ ]] && { echo "Omitido."; return; }
  local msg="Acceso restringido. Actividad monitorizada. Solo usuarios autorizados."
  backup_file /etc/issue
  backup_file /etc/issue.net
  echo "$msg" | sudo tee /etc/issue >/dev/null
  echo "$msg" | sudo tee /etc/issue.net >/dev/null
}

improve_block_usb() {
  echo
  echo "Mejora: Bloquear módulos usb_storage y firewire_ohci (puede requerir reinicio)."
  read -r -p "¿Aplicar? [y/N]: " ans
  [[ ! "$ans" =~ ^[Yy]$ ]] && { echo "Omitido."; return; }
  local f1="/etc/modprobe.d/blacklist-usb.conf"
  local f2="/etc/modprobe.d/blacklist-firewire.conf"
  backup_file "$f1"
  backup_file "$f2"
  echo "blacklist usb_storage" | sudo tee "$f1" >/dev/null
  echo "blacklist firewire_ohci" | sudo tee "$f2" >/dev/null
  echo "Actualizando initramfs..."
  sudo update-initramfs -u || true
}

improve_umask() {
  echo
  echo "Mejora: Establecer UMASK 027 en /etc/login.defs"
  read -r -p "¿Aplicar? [y/N]: " ans
  [[ ! "$ans" =~ ^[Yy]$ ]] && { echo "Omitido."; return; }
  backup_file /etc/login.defs
  if grep -q '^UMASK' /etc/login.defs 2>/dev/null; then
    sudo sed -i -E 's/^UMASK.*/UMASK 027/' /etc/login.defs
  else
    sudo sh -c 'echo "UMASK 027" >> /etc/login.defs'
  fi
}

improve_update() {
  echo
  echo "Mejora: Actualizar sistema (apt update && apt upgrade -y)"
  read -r -p "¿Aplicar? [y/N]: " ans
  [[ ! "$ans" =~ ^[Yy]$ ]] && { echo "Omitido."; return; }
  sudo apt update
  sudo apt upgrade -y
}

menu_and_apply() {
  cat <<'MENU'
Selecciona qué mejoras aplicar (números separados por espacios) o ENTER para saltar:
 1) Políticas de contraseñas (libpam-pwquality + aging)
 2) Firewall UFW (deny incoming, allow outgoing, enable)
 3) Banners legales (/etc/issue, /etc/issue.net)
 4) Bloquear usb_storage / firewire modules
 5) UMASK 027
 6) Actualizar sistema (apt upgrade -y)
 7) Aplicar TODO lo anterior
 0) Salir sin aplicar nada
MENU
  echo
  read -r -p "Tu selección: " selection
  [[ -z "${selection// }" ]] && { echo "Sin cambios."; return; }
  [[ "$selection" == "0" ]] && { echo "Sin cambios."; return; }
  if [[ "$selection" == "7" ]]; then
    improve_password_policy || true
    improve_ufw || true
    improve_banners || true
    improve_block_usb || true
    improve_umask || true
    improve_update || true
    return
  fi
  for tok in $selection; do
    case "$tok" in
      1) improve_password_policy ;;
      2) improve_ufw ;;
      3) improve_banners ;;
      4) improve_block_usb ;;
      5) improve_umask ;;
      6) improve_update ;;
      *) echo "Opción desconocida: $tok" ;;
    esac
  done
}

main() {
  clear
  echo "=========================================="
  echo "  PAI-3: Script interactivo de hardening"
  echo "=========================================="
  check_prereqs

  echo
  echo "1) Escaneo inicial Lynis (con timeout):"
  INITIAL_REPORT="$(run_lynis_quick inicial || true)"
  echo "Informe inicial: ${INITIAL_REPORT:-'(no disponible)'}"

  echo
  echo "2) Selección de mejoras a aplicar"
  menu_and_apply

  echo
  echo "3) Re-ejecutando Lynis tras aplicar mejoras (con timeout):"
  FINAL_REPORT="$(run_lynis_quick final || true)"
  echo "Informe final: ${FINAL_REPORT:-'(no disponible)'}"

  echo
  echo "Listo. Informes en: $WORKDIR"
  echo "Sugerencia: exporta TIMEOUT_SECONDS=240 si tu máquina es lenta."
}

main "$@"
