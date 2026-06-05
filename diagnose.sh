#!/bin/bash

# Диагностика 3x-ui / Xray Reality
# Запускать на сервере!

echo "=== Диагностика Xray/3x-ui ==="
echo ""

# 1. Проверка времени
echo "1. Проверка времени на сервере:"
date
TIMEDATE=$(date +%s)
echo "Текущий unix timestamp: $TIMEDATE"
echo "Рекомендуется синхронизация с NTP"
timedatectl status 2>/dev/null || echo "timedatectl не установлен"
echo ""

# 2. Проверка, слушает ли Xray порты
echo "2. Прослушиваемые порты Xray:"
sudo ss -tlnp | grep -E 'xray|443|80|8443' || echo "Xray не слушает порты или не запущен"
echo ""

# 3. Проверка логов Xray (последние 20 строк)
echo "3. Последние логи Xray:"
if systemctl list-units --full -all | grep -q xray; then
    sudo journalctl -u xray -n 20 --no-pager
else
    echo "Служба xray не найдена в systemd, проверяю лог файл панели..."
    tail -20 /var/log/xray/error.log 2>/dev/null || echo "Логи xray не найдены"
fi
echo ""

# 4. Проверка блокировки исходящего трафика на 443 (google.com)
echo "4. Проверка доступа к google.com:443 с сервера:"
timeout 3 curl -vI https://www.google.com 2>&1 | head -10
if [ $? -ne 0 ]; then
    echo "ВНИМАНИЕ: Сервер не может подключиться к google.com на 443 порт"
    echo "Это может означать блокировку исходящего 443 (или проблемы с сетью)"
fi
echo ""

# 5. Проверка публичного IP сервера
echo "5. Ваш публичный IP (как видят снаружи):"
curl -s ifconfig.me || curl -s icanhazip.com || echo "Не удалось определить"
echo ""

# 6. Проверка конфигурации Xray Reality (если найдем)
echo "6. Поиск конфига Reality в Xray:"
CONFIG_PATH=$(sudo find /etc -name "config.json" 2>/dev/null | grep -E "xray|3-ui" | head -1)
if [ -n "$CONFIG_PATH" ]; then
    echo "Конфиг найден: $CONFIG_PATH"
    echo "Параметры shortId и pbk:"
    sudo grep -A5 -B5 '"realitySettings"' $CONFIG_PATH 2>/dev/null | grep -E 'shortId|publicKey|fingerprint' | head -5
else
    echo "Конфиг xray.json не найден в стандартных путях"
fi
echo ""

# 7. Проверка свободной памяти и перезагрузка демона
echo "7. Состояние службы Xray:"
sudo systemctl status xray --no-pager -l | head -10
echo ""

echo "=== Рекомендации ==="
echo "- Если время отличается >1 минуты -> выполните: sudo timedatectl set-ntp true"
echo "- Если google.com не пингуется на 443 порт -> IP сервера забанен (меняйте сервер)"
echo "- В логах ошибки 'dial tcp' или 'timeout' -> пробуйте сменить sni на dl.google.com или cloudflare.com"
echo "- Временно отключите firewall на сервере: sudo ufw disable (если включен)"
echo ""
echo "Хотите перезапустить Xray? (y/n): "
read -r RESTART
if [ "$RESTART" = "y" ]; then
    sudo systemctl restart xray
    echo "Xray перезапущен. Проверьте через 10 секунд, работает ли VPN."
    sleep 10
    sudo systemctl status xray --no-pager
fi
