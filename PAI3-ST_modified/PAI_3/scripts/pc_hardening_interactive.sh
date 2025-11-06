#!/usr/bin/env bash
# pc_hardening_interactive.sh
# PAI-3: Hardening del portátil con TUI sencilla + "Boost a 70"
# - Lynis quick con timeout
# - Menú de mejoras aplicables
# - Opción de "Boost a 70+" con acciones de alto impacto
# - Logs detallados de acciones y resumen con índice inicial/final/diferencia
#
# Uso:
#   chmod +x pc_hardening_interactive.sh
#   sudo ./pc_hardening_interactive.sh
#
set -euo pipefail

TIMEOUT_SECONDS="${TIMEOUT_SECONDS:-180}"   # Ajusta: TIMEOUT_SECONDS=240 sudo ./pc_hardening_interactive.sh
WORKDIR="$(pwd)/pc_hardening_outputs"
mkdir -p "$WORKDIR"
RUN_ID="$(date +%Y%m%d_%H%M%S)"
LYNIS_BIN="$(command -v lynis || true)"
ACTIONS_LOG="$WORKDIR/hardening_actions_${RUN_ID}.log"
SUMMARY_TXT="$WORKDIR/summary_${RUN_ID}.txt"

log() { echo "[$(date '+%F %T')] $*" | tee -a "$ACTIONS_LOG" >/dev/null; }
ok()  { log "[OK] $*"; }
warn(){ log "[WARN] $*"; }
err() { log "[ERR] $*"; }

trap 'echo; warn "Escaneo interrumpido por el usuario. Se continúa al menú de mejoras."' INT

check_prereqs() {
  : >"$ACTIONS_LOG"
  : >"$SUMMARY_TXT"
  if [[ -z "$LYNIS_BIN" ]]; then
    err "Lynis no está instalado. Instala con: sudo apt update && sudo apt install -y lynis"
    exit 1
  fi
  ok "Prerequisitos verificados (lynis=${LYNIS_BIN})"
}

backup_file() {
  local f="$1"
  if [[ -f "$f" ]]; then
    sudo cp -a "$f" "${f}.bak.${RUN_ID}"
    ok "Backup: ${f} -> ${f}.bak.${RUN_ID}"
  fi
}

parse_hardening_index() {
  local out_txt="$1"
  local idx line
  if sudo test -r /var/log/lynis-report.dat; then
    idx="$(sudo awk -F= '/^hardening_index=/{v=$2} END{if (v!="" ) print v;}' /var/log/lynis-report.dat 2>/dev/null || true)"
    if [[ -n "$idx" ]]; then echo "$idx"; return 0; fi
  fi
  line="$(grep -iE '^[[:space:]]*Hardening index[[:space:]]*:' "$out_txt" 2>/dev/null | tail -n1 || true)"
  if [[ -n "$line" ]]; then
    idx="$(echo "$line" | sed -n 's/.*Hardening index[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p' | head -n1 || true)"
    [[ -n "$idx" ]] && { echo "$idx"; return 0; }
    idx="$(echo "$line" | sed -n 's/.*\[\([0-9][0-9]*\)\].*/\1/p' | head -n1 || true)"
    [[ -n "$idx" ]] && { echo "$idx"; return 0; }
  fi
  echo "N/A"
}

run_lynis_quick() {
  local tag="$1"
  local out="$WORKDIR/lynis_${tag}_${RUN_ID}.txt"
  echo "=== Ejecutando Lynis (quick) con timeout ${TIMEOUT_SECONDS}s... ==="
  log "Lynis (${tag}) iniciado con timeout=${TIMEOUT_SECONDS}s"
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
    0)   ok "Lynis (${tag}) finalizado con código 0" ;;
    124) warn "Lynis (${tag}) timeout (${TIMEOUT_SECONDS}s)" ;;
    130) warn "Lynis (${tag}) interrumpido por Ctrl-C" ;;
    *)   warn "Lynis (${tag}) terminó con código ${rc}" ;;
  esac
  local hi
  hi="$(parse_hardening_index "$out")"
  if [[ "$hi" != "N/A" ]]; then
    echo ">>> Hardening index (${tag}): ${hi}"
    ok "Hardening index (${tag}) = ${hi}"
  else
    warn "No se pudo extraer el Hardening index (${tag})"
  fi
  echo "Informe guardado en: $out"
  echo
  echo "$hi"
}

# --------- Mejoras unitarias ----------
improve_password_policy() {
  echo; echo "Mejora: Políticas de contraseñas (libpam-pwquality + ageing)"
  read -r -p "¿Aplicar? [y/N]: " ans; [[ ! "$ans" =~ ^[Yy]$ ]] && { log "Política de contraseñas: omitida"; return; }
  sudo apt update && sudo apt install -y libpam-pwquality || true
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
  fi
  # rounds SHA512 en pam_unix
  if grep -q 'pam_unix.so' /etc/pam.d/common-password; then
    sudo sed -i 's/^\(password.*pam_unix\.so.*\)$/\1 rounds=65536/' /etc/pam.d/common-password || true
  fi
  # aplicar ageing a usuario actual
  sudo chage -M 90 -m 7 -W 14 "$SUDO_USER" 2>/dev/null || sudo chage -M 90 -m 7 -W 14 "$USER" || true
  ok "Política de contraseñas endurecida (pwquality, ageing, rounds, UMASK)"
}

improve_ufw() {
  echo; echo "Mejora: UFW (deny incoming, allow outgoing, enable)"
  read -r -p "¿Aplicar? [y/N]: " ans; [[ ! "$ans" =~ ^[Yy]$ ]] && { log "UFW: omitido"; return; }
  sudo apt update && sudo apt install -y ufw || true
  sudo ufw default deny incoming
  sudo ufw default allow outgoing
  if ss -tln | grep -q ':22 '; then
    sudo ufw allow 22/tcp
    log "UFW: allow 22/tcp (SSH) detectado"
  fi
  # Reglas “visibles” para evitar FIRE-4512
  sudo ufw allow out 53,80,443/tcp
  sudo ufw allow out 53,123/udp
  sudo ufw --force enable
  ok "UFW habilitado y con reglas explícitas"
}

improve_banners() {
  echo; echo "Mejora: Banners legales /etc/issue y /etc/issue.net (fuertes)"
  read -r -p "¿Aplicar? [y/N]: " ans; [[ ! "$ans" =~ ^[Yy]$ ]] && { log "Banners: omitidos"; return; }
  local msg="ACCESO RESTRINGIDO. Uso exclusivo de personal autorizado. Toda actividad puede ser monitorizada y registrada."
  backup_file /etc/issue
  backup_file /etc/issue.net
  echo "$msg" | sudo tee /etc/issue >/dev/null
  echo "$msg" | sudo tee /etc/issue.net >/dev/null
  ok "Banners legales escritos"
}

improve_block_usb() {
  echo; echo "Mejora: Blacklist usb_storage y firewire_ohci (puede requerir reinicio)"
  read -r -p "¿Aplicar? [y/N]: " ans; [[ ! "$ans" =~ ^[Yy]$ ]] && { log "Blacklist USB: omitida"; return; }
  echo "blacklist usb_storage" | sudo tee /etc/modprobe.d/blacklist-usb.conf >/dev/null
  echo "blacklist firewire_ohci" | sudo tee /etc/modprobe.d/blacklist-firewire.conf >/dev/null
  sudo update-initramfs -u || true
  ok "Módulos en blacklist"
}

improve_umask() {
  echo; echo "Mejora: UMASK 027 en /etc/login.defs"
  read -r -p "¿Aplicar? [y/N]: " ans; [[ ! "$ans" =~ ^[Yy]$ ]] && { log "UMASK: omitido"; return; }
  backup_file /etc/login.defs
  if grep -q '^UMASK' /etc/login.defs 2>/dev/null; then
    sudo sed -i -E 's/^UMASK.*/UMASK 027/' /etc/login.defs
  else
    echo "UMASK 027" | sudo tee -a /etc/login.defs >/dev/null
  fi
  ok "UMASK 027 aplicado"
}

improve_update() {
  echo; echo "Mejora: Actualizar sistema (apt update && apt upgrade -y)"
  read -r -p "¿Aplicar? [y/N]: " ans; [[ ! "$ans" =~ ^[Yy]$ ]] && { log "Upgrade: omitido"; return; }
  sudo apt update && sudo apt upgrade -y
  ok "Sistema actualizado"
}

# --------- BOOST A 70+ ----------
boost_to_70() {
  echo; echo "== BOOST a 70+ (paquete rápido de mejoras recomendadas) =="
  read -r -p "¿Aplicar el paquete completo? [y/N]: " ans; [[ ! "$ans" =~ ^[Yy]$ ]] && { log "Boost 70+: cancelado"; return; }

  # AIDE (integridad)
  sudo apt update && sudo apt install -y aide || true
  if sudo command -v aide >/dev/null 2>&1; then
    sudo aideinit || true
    if [[ -f /var/lib/aide/aide.db.new ]]; then
      sudo mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db || true
    fi
    ok "AIDE inicializado"
  else
    warn "AIDE no instalado correctamente"
  fi

  # auditd + sysstat (accounting/auditoría)
  sudo apt install -y auditd audispd-plugins sysstat || true
  sudo systemctl enable --now auditd || true
  sudo sed -i 's/^ENABLED="false"/ENABLED="true"/' /etc/default/sysstat || true
  sudo systemctl enable --now sysstat || true
  ok "auditd y sysstat habilitados"

  # UFW visible + reglas
  sudo apt install -y ufw || true
  sudo ufw default deny incoming
  sudo ufw default allow outgoing
  if ss -tln | grep -q ':22 '; then sudo ufw allow 22/tcp; fi
  sudo ufw allow out 53,80,443/tcp
  sudo ufw allow out 53,123/udp
  sudo ufw --force enable
  ok "UFW configurado (reglas explícitas)"

  # Banners fuertes
  local msg="ACCESO RESTRINGIDO. Uso exclusivo de personal autorizado. Toda actividad puede ser monitorizada y registrada."
  echo "$msg" | sudo tee /etc/issue >/dev/null
  echo "$msg" | sudo tee /etc/issue.net >/dev/null
  ok "Banners fuertes escritos"

  # Password policy + rounds + ageing
  sudo apt install -y libpam-pwquality || true
  backup_file /etc/login.defs
  sudo sed -i -E '/^PASS_MAX_DAYS/s/.*/PASS_MAX_DAYS\t90/' /etc/login.defs || sudo sh -c 'echo "PASS_MAX_DAYS\t90" >> /etc/login.defs'
  sudo sed -i -E '/^PASS_MIN_DAYS/s/.*/PASS_MIN_DAYS\t7/' /etc/login.defs || sudo sh -c 'echo "PASS_MIN_DAYS\t7" >> /etc/login.defs'
  sudo sed -i -E '/^PASS_WARN_AGE/s/.*/PASS_WARN_AGE\t14/' /etc/login.defs || sudo sh -c 'echo "PASS_WARN_AGE\t14" >> /etc/login.defs'
  if grep -q '^UMASK' /etc/login.defs 2>/dev/null; then sudo sed -i -E 's/^UMASK.*/UMASK 027/' /etc/login.defs; else echo "UMASK 027" | sudo tee -a /etc/login.defs >/dev/null; fi
  if ! grep -q 'pam_pwquality.so' /etc/pam.d/common-password 2>/dev/null; then
    sudo bash -c 'echo "password    requisite           pam_pwquality.so retry=3 minlen=12 difok=4" >> /etc/pam.d/common-password'
  fi
  if grep -q 'pam_unix.so' /etc/pam.d/common-password; then
    sudo sed -i 's/^\(password.*pam_unix\.so.*\)$/\1 rounds=65536/' /etc/pam.d/common-password || true
  fi
  sudo chage -M 90 -m 7 -W 14 "$SUDO_USER" 2>/dev/null || sudo chage -M 90 -m 7 -W 14 "$USER" || true
  ok "Política de contraseñas endurecida (pwquality, rounds, ageing, UMASK)"

  # Purga de paquetes huérfanos / restos
  sudo apt autoremove --purge -y || true
  sudo dpkg -l | awk '/^rc/{print $2}' | xargs -r sudo dpkg -P || true
  ok "Limpieza de paquetes huérfanos completada"

  # (Opcional) Blacklist usb/firewire
  echo "blacklist usb_storage" | sudo tee /etc/modprobe.d/blacklist-usb.conf >/dev/null
  echo "blacklist firewire_ohci" | sudo tee /etc/modprobe.d/blacklist-firewire.conf >/dev/null
  sudo update-initramfs -u || true
  ok "Blacklist usb/firewire aplicada"
}

menu_and_apply() {
  cat <<'MENU'
Selecciona mejoras (números separados por espacios) o ENTER para saltar:
 1) Políticas de contraseñas (pwquality + ageing + rounds + UMASK)
 2) Firewall UFW (deny incoming, allow outgoing, enable + reglas)
 3) Banners legales fuertes (/etc/issue, /etc/issue.net)
 4) Blacklist usb_storage / firewire_ohci
 5) UMASK 027
 6) Actualizar sistema (upgrade)
 7) BOOST a 70+ (paquete rápido recomendado)
 0) Salir sin aplicar nada
MENU
  echo
  read -r -p "Tu selección: " selection
  [[ -z "${selection// }" ]] && { log "Ninguna mejora seleccionada"; return; }
  [[ "$selection" == "0" ]] && { log "Salida sin aplicar mejoras"; return; }
  if [[ "$selection" == "7" ]]; then boost_to_70; return; fi
  for tok in $selection; do
    case "$tok" in
      1) improve_password_policy ;;
      2) improve_ufw ;;
      3) improve_banners ;;
      4) improve_block_usb ;;
      5) improve_umask ;;
      6) improve_update ;;
      *) warn "Opción desconocida: $tok" ;;
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
  INITIAL_HI="$(run_lynis_quick inicial || true)"
  echo "Hardening inicial = ${INITIAL_HI}"

  echo
  echo "2) Selección de mejoras a aplicar"
  menu_and_apply

  echo
  echo "3) Re-ejecutando Lynis tras aplicar mejoras (con timeout):"
  FINAL_HI="$(run_lynis_quick final || true)"
  echo "Hardening final = ${FINAL_HI}"

  # Resumen con diferencia
  DIFF="N/A"
  if [[ "$INITIAL_HI" =~ ^[0-9]+$ && "$FINAL_HI" =~ ^[0-9]+$ ]]; then
    DIFF=$(( FINAL_HI - INITIAL_HI ))
  fi

  {
    echo "===== RESUMEN HARDENING ($RUN_ID) ====="
    echo "Inicial: ${INITIAL_HI}"
    echo "Final  : ${FINAL_HI}"
    echo "Diferencia: ${DIFF}"
    echo "Acciones: ver $ACTIONS_LOG"
  } | tee "$SUMMARY_TXT"

  echo
  echo "Logs de acciones: $ACTIONS_LOG"
  echo "Resumen índices : $SUMMARY_TXT"
  echo "Informes Lynis  : $WORKDIR/lynis_inicial_${RUN_ID}.txt y $WORKDIR/lynis_final_${RUN_ID}.txt (nombres exactos mostrados en ejecución)"
  echo
  if [[ "$FINAL_HI" =~ ^[0-9]+$ && "$FINAL_HI" -lt 70 ]]; then
    warn "El índice final es < 70. Puedes ejecutar de nuevo y elegir '7) BOOST a 70+' para subir unos puntos rápidos."
  else
    ok "Objetivo alcanzado: índice >= 70 o mejoras aplicadas con éxito."
  fi
}

main "$@"
