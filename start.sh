
#!/usr/bin/env bash
set -Eeuo pipefail

# SSH Hardening + Fail2ban
# Debian / Ubuntu / RHEL / Rocky Linux / AlmaLinux

if [[ $EUID -ne 0 ]]; then
    echo "Ошибка: запусти скрипт от root: sudo bash $0"
    exit 1
fi

if ! command -v systemctl >/dev/null 2>&1; then
    echo "Ошибка: systemd не обнаружен. Скрипт рассчитан на systemd."
    exit 1
fi

if ! command -v sshd >/dev/null 2>&1; then
    echo "Ошибка: sshd не найден. Сначала установи OpenSSH Server."
    exit 1
fi

SSHD_CONFIG="/etc/ssh/sshd_config"
BACKUP="${SSHD_CONFIG}.backup.$(date +%Y%m%d_%H%M%S)"
JAIL_CONFIG="/etc/fail2ban/jail.d/sshd-hardening.local"

if [[ ! -f "$SSHD_CONFIG" ]]; then
    echo "Ошибка: конфигурация $SSHD_CONFIG не найдена."
    exit 1
fi

# Определяем имя службы SSH
if systemctl list-unit-files ssh.service --no-legend 2>/dev/null |
    grep -q '^ssh\.service'; then
    SSH_SERVICE="ssh"
elif systemctl list-unit-files sshd.service --no-legend 2>/dev/null |
    grep -q '^sshd\.service'; then
    SSH_SERVICE="sshd"
else
    echo "Ошибка: служба SSH не найдена."
    exit 1
fi

echo "======================================"
echo "       SSH HARDENING + FAIL2BAN"
echo "======================================"

# Выбор порта

while true; do
    read -r -p "Введи новый SSH-порт (1-65535): " SSH_PORT

    # Проверяем, что введены только цифры
    if [[ ! "$SSH_PORT" =~ ^[0-9]{1,5}$ ]]; then
        echo "Ошибка: введи число от 1 до 65535."
        continue
    fi

    # Убираем ведущие нули
    SSH_PORT=$((10#$SSH_PORT))

    if (( SSH_PORT < 1 || SSH_PORT > 65535 )); then
        echo "Ошибка: порт должен быть от 1 до 65535."
        continue
    fi

    # Проверяем, не занят ли порт
    if ss -H -lnt 2>/dev/null |
        awk '{print $4}' |
        grep -Eq "(:|\])${SSH_PORT}$"; then
        echo "Ошибка: порт $SSH_PORT уже занят."
        continue
    fi

    break
done


echo
echo "[1/6] Создаю резервную копию..."
cp -a "$SSHD_CONFIG" "$BACKUP"
echo "Резервная копия: $BACKUP"

# Сохраняем дополнительные настройки SSH, если они есть.
DROPIN_DIR="/etc/ssh/sshd_config.d"
if [[ -d "$DROPIN_DIR" ]]; then
    DROPIN_BACKUP="${BACKUP}.dropins"
    mkdir -p "$DROPIN_BACKUP"
    cp -a "$DROPIN_DIR/." "$DROPIN_BACKUP/"
    echo "Копия дополнительных конфигураций: $DROPIN_BACKUP"
fi

# Открываем порт в известных системных firewall.
echo
echo "[2/6] Проверяю firewall..."

if command -v ufw >/dev/null 2>&1 &&
   ufw status 2>/dev/null | grep -q "Status: active"; then
    ufw allow "${SSH_PORT}/tcp" || {
        echo "Ошибка настройки UFW. Старый SSH-порт оставлен без изменений."
        exit 1
    }
    echo "UFW: разрешён TCP-порт $SSH_PORT"
elif command -v firewall-cmd >/dev/null 2>&1 &&
     firewall-cmd --state >/dev/null 2>&1; then
    firewall-cmd --add-port="${SSH_PORT}/tcp" &&
    firewall-cmd --permanent --add-port="${SSH_PORT}/tcp" || {
        echo "Ошибка настройки firewalld."
        exit 1
    }
    echo "firewalld: разрешён TCP-порт $SSH_PORT"
else
    echo "UFW/firewalld не активен или не обнаружен."
    echo "При необходимости открой порт в другом firewall."
fi

# Удаляем ранее добавленный нами блок, если скрипт запускается повторно.
TEMP_CONFIG="$(mktemp)"
trap 'rm -f "$TEMP_CONFIG"' EXIT

awk '
    /^# BEGIN SSH-HARDENING MANAGED BLOCK$/ { skip=1; next }
    /^# END SSH-HARDENING MANAGED BLOCK$/ { skip=0; next }
    !skip { print }
' "$SSHD_CONFIG" > "$TEMP_CONFIG"

# Убираем глобальные директивы Port и парольной аутентификации
# из основного файла, чтобы старые значения не мешали.
sed -i -E \
    '/^[[:space:]]*(Port|PasswordAuthentication|KbdInteractiveAuthentication|ChallengeResponseAuthentication)[[:space:]]+/Id' \
    "$TEMP_CONFIG"

# Блок помещается перед Include, чтобы иметь приоритет
# над обычными настройками в подключаемых файлах.
{
    cat <<EOF
# BEGIN SSH-HARDENING MANAGED BLOCK
Port $SSH_PORT
PasswordAuthentication no
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
# END SSH-HARDENING MANAGED BLOCK

EOF
    cat "$TEMP_CONFIG"
} > "${SSHD_CONFIG}.new"

install -o root -g root -m 600 "${SSHD_CONFIG}.new" "$SSHD_CONFIG"
rm -f "${SSHD_CONFIG}.new"

echo
echo "[3/6] Проверяю конфигурацию SSH..."

if ! sshd -t; then
    echo "Ошибка конфигурации! Восстанавливаю основной файл."
    cp -a "$BACKUP" "$SSHD_CONFIG"
    echo "Основной файл восстановлен. Перезапуск SSH отменён."
    exit 1
fi

# Проверяем итоговые параметры, включая Include-файлы.
EFFECTIVE_CONFIG="$(sshd -T 2>/dev/null)" || {
    cp -a "$BACKUP" "$SSHD_CONFIG"
    echo "Не удалось проверить итоговые настройки SSH."
    exit 1
}

if ! grep -qx "port $SSH_PORT" <<< "$EFFECTIVE_CONFIG" ||
   ! grep -qx "passwordauthentication no" <<< "$EFFECTIVE_CONFIG" ||
   ! grep -qx "kbdinteractiveauthentication no" <<< "$EFFECTIVE_CONFIG"; then
    cp -a "$BACKUP" "$SSHD_CONFIG"
    echo "Ошибка: итоговые настройки отличаются от ожидаемых."
    echo "Основной файл восстановлен. SSH не перезапускался."
    echo "Проверь Include-файлы и настройки Match."
    exit 1
fi

echo "Проверка sshd -t пройдена."

echo
echo "[4/6] Устанавливаю Fail2ban..."

if command -v apt-get >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y fail2ban
elif command -v dnf >/dev/null 2>&1; then
    dnf install -y fail2ban
elif command -v yum >/dev/null 2>&1; then
    yum install -y fail2ban
else
    echo "Ошибка: не найден apt-get, dnf или yum."
    exit 1
fi

echo
echo "[5/6] Настраиваю Fail2ban..."

mkdir -p /etc/fail2ban/jail.d

cat > "$JAIL_CONFIG" <<EOF
[sshd]
enabled = true
port = $SSH_PORT
filter = sshd
backend = systemd
maxretry = 5
findtime = 10m
bantime = 1h
EOF

if ! fail2ban-client -t; then
    echo "Ошибка конфигурации Fail2ban."
    echo "См. файл $JAIL_CONFIG"
    exit 1
fi

systemctl enable --now fail2ban
systemctl restart fail2ban

echo
echo "[6/6] Перезапускаю SSH..."

if ! systemctl reload "$SSH_SERVICE"; then
    echo "Reload не удался, пробую restart..."
    if ! systemctl restart "$SSH_SERVICE"; then
        echo "ОШИБКА: SSH не удалось перезапустить!"
        echo "Текущая сессия может оставаться активной."
        echo "Восстанови конфигурацию из $BACKUP"
        exit 1
    fi
fi

if ! systemctl is-active --quiet "$SSH_SERVICE"; then
    echo "Ошибка: служба SSH не активна."
    echo "Проверь журнал: journalctl -u $SSH_SERVICE -n 50"
    exit 1
fi

echo
echo "======================================"
echo "              ОТЧЁТ"
echo "======================================"
echo "[OK] SSH-порт: $SSH_PORT"
echo "[OK] PasswordAuthentication: no"
echo "[OK] KbdInteractiveAuthentication: no"
echo "[OK] SSH-служба: $(systemctl is-active "$SSH_SERVICE")"
echo "[OK] Fail2ban: $(systemctl is-active fail2ban)"
echo "[OK] Резервная копия: $BACKUP"
echo
echo "Статус Fail2ban:"
fail2ban-client status sshd || true

echo
echo "Проверь подключение в НОВОМ терминале:"
echo "ssh -p $SSH_PORT USER@SERVER_IP"
echo
echo "Убедись, что вход по ключу работает, прежде чем"
echo "закрывать текущую SSH-сессию."
echo "Старые правила firewall автоматически не удалялись."
echo "======================================"
