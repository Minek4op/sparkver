import os
import re
import random
import time
import threading
import sqlite3
import secrets
import hmac
from flask import Flask, request, jsonify
from werkzeug.middleware.proxy_fix import ProxyFix
import requests
from dotenv import load_dotenv
from functools import wraps

load_dotenv()
app = Flask(__name__)

# Ограничиваем размер тела запроса (защита от примитивного payload-flood DoS)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024  # 16 KB более чем достаточно для этих эндпоинтов

# --- ИСПРАВЛЕНИЕ ДЛЯ NGINX ---
# x_for=1 означает, что доверяем РОВНО ОДНОМУ хопу X-Forwarded-For.
# ВАЖНО: процесс Flask/Gunicorn НЕ должен быть доступен напрямую из интернета —
# иначе атакующий сможет сам подставить X-Forwarded-For и обойти IP-лимиты.
# Закройте порт Flask файрволом снаружи, доступ — только от nginx/localhost.
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)

# --- КОНФИГУРАЦИЯ БЕЗОПАСНОСТИ ---
# ВСЕ секреты теперь только из переменных окружения — ничего не хардкодим в коде/репозитории.
RESEND_API_KEY = os.getenv('RESEND_API_KEY')
TURNSTILE_SECRET_KEY = os.getenv('TURNSTILE_SECRET_KEY')
APP_SECRET = os.getenv('APP_SECRET')

if not RESEND_API_KEY or not TURNSTILE_SECRET_KEY or not APP_SECRET:
    raise RuntimeError(
        "Не заданы переменные окружения RESEND_API_KEY / TURNSTILE_SECRET_KEY / APP_SECRET. "
        "Добавьте их в .env перед запуском (старый хардкоженый APP_SECRET можно "
        "перенести туда же, но лучше сгенерировать новый, например: python -c "
        "\"import secrets; print(secrets.token_hex(32))\")."
    )

EMAIL_RE = re.compile(r'^[^@\s]{1,128}@[^@\s]{1,128}\.[^@\s]{2,24}$')
CODE_RE = re.compile(r'^\d{4}$')

# =====================================================================
# НАСТРОЙКА БАЗЫ ДАННЫХ SQLITE
# =====================================================================
def get_db_connection():
    conn = sqlite3.connect('spark_messenger.db', timeout=10)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Создает таблицы при первом запуске, если их еще нет"""
    conn = get_db_connection()
    try:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS verification_codes (
                email TEXT PRIMARY KEY,
                code TEXT NOT NULL,
                expires_at INTEGER NOT NULL
            )
        ''')

        conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                email TEXT PRIMARY KEY,
                auth_token TEXT,
                created_at INTEGER
            )
        ''')

        conn.execute('''
            CREATE TABLE IF NOT EXISTS rate_limits (
                email TEXT,
                timestamp INTEGER
            )
        ''')

        conn.execute('''
            CREATE TABLE IF NOT EXISTS blocked_emails (
                email TEXT PRIMARY KEY,
                blocked_until INTEGER
            )
        ''')

        conn.execute('''
            CREATE TABLE IF NOT EXISTS ip_rate_limits (
                ip TEXT,
                timestamp INTEGER
            )
        ''')

        conn.execute('''
            CREATE TABLE IF NOT EXISTS blocked_attempts (
                email TEXT PRIMARY KEY,
                attempt_count INTEGER DEFAULT 0,
                blocked_until INTEGER DEFAULT 0
            )
        ''')

        conn.commit()
    finally:
        conn.close()

init_db()
# =====================================================================


def make_json_response(data, status_code):
    response = jsonify(data)
    response.headers["Content-Type"] = "application/json; charset=utf-8"
    return response, status_code


def limit_requests(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        ip = request.remote_addr
        now = int(time.time())
        conn = get_db_connection()
        try:
            # Лёгкая авто-очистка старых логов (шанс 5%, чтобы БД не разрасталась)
            if random.random() < 0.05:
                conn.execute('DELETE FROM ip_rate_limits WHERE timestamp <= ?', (now - 120,))
                conn.execute('DELETE FROM rate_limits WHERE timestamp <= ?', (now - 900,))
                conn.execute('DELETE FROM blocked_emails WHERE blocked_until <= ?', (now,))
                conn.execute('DELETE FROM blocked_attempts WHERE blocked_until > 0 AND blocked_until <= ?', (now,))
                conn.commit()

            recent_reqs = conn.execute(
                'SELECT COUNT(*) as count FROM ip_rate_limits WHERE ip = ? AND timestamp > ?',
                (ip, now - 120)
            ).fetchone()['count']

            if recent_reqs >= 5:
                print(f">>> RATE LIMIT: Блокировка запроса по IP от {ip}")
                return make_json_response({"message": "Слишком много запросов. Подождите 2 минуты."}, 429)

            conn.execute('INSERT INTO ip_rate_limits (ip, timestamp) VALUES (?, ?)', (ip, now))
            conn.commit()
        finally:
            conn.close()

        return f(*args, **kwargs)
    return decorated_function


def require_auth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        provided = request.headers.get('X-Spark-Auth', '')
        # Сравнение за константное время — защита от timing-атак на секрет
        if not hmac.compare_digest(provided, APP_SECRET):
            print(f">>> AUTH ERROR: Неверный ключ доступа от {request.remote_addr}")
            return make_json_response({"message": "Access Denied"}, 401)
        return f(*args, **kwargs)
    return decorated_function


def send_email_async(email, code, headers, payload):
    try:
        print(f">>> [ФОН] Начинается отправка письма на {email}...")
        resend_resp = requests.post("https://api.resend.com/emails", headers=headers, json=payload, timeout=10)

        if resend_resp.status_code in [200, 201, 202]:
            print(f">>> [ФОН] УСПЕШНО: Письмо для {email} отправлено.")
        else:
            print(f">>> [ФОН] ОШИБКА RESEND ДЛЯ {email}: {resend_resp.text}")
    except Exception as e:
        print(f">>> [ФОН] КРИТИЧЕСКАЯ ОШИБКА ПОТОКА ОТПРАВКИ: {str(e)}")


# =====================================================================
# ЭНДПОИНТ 1: ОТПРАВКА КОДА
# =====================================================================
@app.route('/send-verification-code', methods=['POST'])
@require_auth
@limit_requests
def send_verification_code():
    try:
        data = request.get_json(silent=True)
        if not data:
            return make_json_response({"message": "Пустой JSON запрос"}, 400)

        email = (data.get('email') or '').strip().lower()
        captcha_token = data.get('captcha_token')

        if not email or not EMAIL_RE.match(email):
            return make_json_response({"message": "Некорректный email"}, 400)

        now = int(time.time())

        # 1. ЖЕСТКАЯ ПРОВЕРКА НА БЛОКИРОВКУ ПОЧТЫ В БД
        conn = get_db_connection()
        try:
            block_record = conn.execute('SELECT blocked_until FROM blocked_emails WHERE email = ?', (email,)).fetchone()

            if block_record:
                if now < block_record['blocked_until']:
                    remaining_seconds = block_record['blocked_until'] - now
                    print(f">>> EMAIL BLOCKED: Попытка отправки на заблокированную почту {email}. Осталось {remaining_seconds} сек.")
                    return make_json_response({"message": "Превышен лимит отправки кодов"}, 429)
                else:
                    conn.execute('DELETE FROM blocked_emails WHERE email = ?', (email,))
                    conn.execute('DELETE FROM rate_limits WHERE email = ?', (email,))
                    conn.commit()
        finally:
            conn.close()  # закрываем перед долгим запросом к Turnstile

        if not captcha_token:
            print(f">>> CAPTCHA ERROR: Токен капчи отсутствует для {email}")
            return make_json_response({"message": "Капча не пройдена"}, 403)

        # 2. ПРОВЕРКА КАПЧИ В CLOUDFLARE TURNSTILE
        turnstile_url = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
        turnstile_resp = requests.post(turnstile_url, data={
            "secret": TURNSTILE_SECRET_KEY,
            "response": captcha_token,
            "remoteip": request.remote_addr
        }, timeout=5)
        turnstile_result = turnstile_resp.json()

        if not turnstile_result.get("success"):
            print(f">>> CAPTCHA FAILED: Невалидный токен капчи для {email}. Ответ: {turnstile_result}")
            return make_json_response({"message": "Капча не пройдена"}, 403)

        # 3. ПОДСЧЕТ ОТПРАВОК И ВЫДАЧА БЛОКИРОВКИ НА 15 МИНУТ
        conn = get_db_connection()
        try:
            recent_attempts = conn.execute(
                'SELECT COUNT(*) as count FROM rate_limits WHERE email = ? AND timestamp > ?',
                (email, now - 900)
            ).fetchone()['count']

            if recent_attempts >= 1:
                conn.execute('''
                    INSERT INTO blocked_emails (email, blocked_until)
                    VALUES (?, ?)
                    ON CONFLICT(email) DO UPDATE SET blocked_until=excluded.blocked_until
                ''', (email, now + 900))
                conn.commit()
                print(f">>> EMAIL RATE LIMIT: Превышен лимит! Почта {email} ЖЕСТКО заблокирована на 15 минут.")
                return make_json_response({"message": "Превышен лимит отправки кодов"}, 429)

            conn.execute('INSERT INTO rate_limits (email, timestamp) VALUES (?, ?)', (email, now))

            # 4. ГЕНЕРАЦИЯ КОДА — криптографически стойким генератором (не random.randint!)
            code = str(1000 + secrets.randbelow(9000))
            expires_at = now + 600  # 10 минут

            conn.execute('''
                INSERT INTO verification_codes (email, code, expires_at)
                VALUES (?, ?, ?)
                ON CONFLICT(email) DO UPDATE SET
                code=excluded.code, expires_at=excluded.expires_at
            ''', (email, code, expires_at))

            conn.execute('DELETE FROM blocked_attempts WHERE email = ?', (email,))

            conn.commit()
        finally:
            conn.close()

        print(f"\n>>> ИНИЦИАЛИЗАЦИЯ ОТПРАВКИ: {email} (Код: {code})")

        headers = {
            "Authorization": f"Bearer {RESEND_API_KEY}",
            "Content-Type": "application/json"
        }

        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <style>
                body {{ font-family: -apple-system, sans-serif; background-color: #f9f9f9; padding: 20px; }}
                .card {{ background: #ffffff; max-width: 450px; margin: 0 auto; padding: 40px; border-radius: 16px; box-shadow: 0 4px 20px rgba(0,0,0,0.08); border: 1px solid #eee; }}
                .logo {{ color: #000000; font-size: 28px; font-weight: 200; letter-spacing: 4px; text-align: center; margin-bottom: 30px; }}
                .code-box {{ background: #f0f0f0; padding: 20px; text-align: center; font-size: 36px; font-weight: bold; letter-spacing: 8px; color: #000; border-radius: 12px; margin: 25px 0; }}
                .info {{ font-size: 14px; color: #666; line-height: 1.5; text-align: center; }}
                .footer {{ font-size: 11px; color: #aaa; text-align: center; margin-top: 30px; border-top: 1px solid #eee; padding-top: 20px; }}
            </style>
        </head>
        <body>
            <div class="card">
                <div class="logo">SPARK</div>
                <p style="text-align: center; font-weight: 500;">Подтверждение входа</p>
                <div class="code-box">{code}</div>
                <div class="info">
                    Введите этот код в приложении для завершения авторизации.<br>
                    Код действителен в течение 10 минут.
                </div>
                <div class="footer">Если вы не запрашивали этот код, просто проигнорируйте письмо.</div>
            </div>
        </body>
        </html>
        """

        payload = {
            "from": "Spark Messenger <auth@sparkmessenger.ru>",
            "to": [email],
            "subject": "Код подтверждения Spark",
            "html": html_content
        }

        email_thread = threading.Thread(
            target=send_email_async,
            args=(email, code, headers, payload)
        )
        email_thread.start()

        return make_json_response({"message": "Code sent"}, 200)

    except Exception as e:
        # Внутренние детали логируем только на сервере, клиенту — обобщённое сообщение
        print(f">>> ОШИБКА СЕРВЕРА: {str(e)}")
        return make_json_response({"message": "Server Error"}, 500)


# =====================================================================
# ЭНДПОИНТ 2: ПРОВЕРКА КОДА И ВЫДАЧА ТОКЕНА
# =====================================================================
@app.route('/verify-code', methods=['POST'])
@require_auth
@limit_requests
def verify_code():
    try:
        data = request.get_json(silent=True)
        if not data:
            return make_json_response({"message": "Пустой JSON запрос"}, 400)

        email = (data.get('email') or '').strip().lower()
        code = (data.get('code') or '').strip()

        if not email or not EMAIL_RE.match(email) or not CODE_RE.match(code):
            return make_json_response({"message": "Некорректные данные"}, 400)

        now = int(time.time())
        conn = get_db_connection()
        try:
            # 1. ПРОВЕРКА БЛОКИРОВКИ ОТ BRUTE FORCE
            attempt_record = conn.execute('SELECT attempt_count, blocked_until FROM blocked_attempts WHERE email = ?', (email,)).fetchone()

            if attempt_record and attempt_record['blocked_until'] > now:
                remaining = attempt_record['blocked_until'] - now
                print(f">>> BRUTE FORCE BLOCK: Почта {email} заблокирована. Осталось {remaining} сек.")
                return make_json_response({"message": "Слишком много неверных попыток. Доступ закрыт на 15 минут."}, 429)

            # 2. Ищем код в БАЗЕ ДАННЫХ
            row = conn.execute('SELECT code, expires_at FROM verification_codes WHERE email = ?', (email,)).fetchone()

            if not row:
                print(f">>> VERIFY ERROR: Код для {email} не найден")
                return make_json_response({"message": "Код не найден или устарел"}, 404)

            # 3. Проверяем срок годности
            if now > row["expires_at"]:
                conn.execute('DELETE FROM verification_codes WHERE email = ?', (email,))
                conn.commit()
                print(f">>> VERIFY ERROR: Время кода для {email} истекло")
                return make_json_response({"message": "Время действия кода истекло"}, 400)

            # 4. Сверяем сам код за константное время
            if not hmac.compare_digest(row["code"], code):
                new_count = (attempt_record['attempt_count'] + 1) if attempt_record else 1
                blocked_until = (now + 900) if new_count >= 5 else 0

                conn.execute('''
                    INSERT INTO blocked_attempts (email, attempt_count, blocked_until)
                    VALUES (?, ?, ?)
                    ON CONFLICT(email) DO UPDATE SET
                    attempt_count = excluded.attempt_count,
                    blocked_until = excluded.blocked_until
                ''', (email, new_count, blocked_until))
                conn.commit()

                print(f">>> VERIFY ERROR: Неверный код для {email} (Попытка {new_count}/5)")

                if new_count >= 5:
                    return make_json_response({"message": "Слишком много неверных попыток. Доступ закрыт на 15 минут."}, 429)
                else:
                    return make_json_response({"message": "Неверный код"}, 401)

            # 5. КОД ВЕРНЫЙ! Генерируем токен
            print(f">>> УСПЕШНАЯ АВТОРИЗАЦИЯ: {email}")

            auth_token = secrets.token_hex(32)

            conn.execute('DELETE FROM verification_codes WHERE email = ?', (email,))
            conn.execute('DELETE FROM blocked_attempts WHERE email = ?', (email,))

            conn.execute('''
                INSERT INTO users (email, auth_token, created_at)
                VALUES (?, ?, ?)
                ON CONFLICT(email) DO UPDATE SET
                auth_token=excluded.auth_token
            ''', (email, auth_token, now))

            conn.execute('DELETE FROM rate_limits WHERE email = ?', (email,))
            conn.execute('DELETE FROM blocked_emails WHERE email = ?', (email,))

            conn.commit()

            return make_json_response({
                "message": "Код верный",
                "token": auth_token
            }, 200)
        finally:
            conn.close()

    except Exception as e:
        print(f">>> ОШИБКА СЕРВЕРА (verify): {str(e)}")
        return make_json_response({"message": "Server Error"}, 500)


# =====================================================================
# ЭНДПОИНТ 3: АННУЛИРОВАНИЕ КОДА (ПРИ НАЖАТИИ "НАЗАД")
# =====================================================================
@app.route('/invalidate-code', methods=['POST'])
@require_auth
@limit_requests
def invalidate_code():
    try:
        data = request.get_json(silent=True)
        if not data:
            return make_json_response({"message": "Пустой JSON запрос"}, 400)

        email = (data.get('email') or '').strip().lower()

        if email and EMAIL_RE.match(email):
            conn = get_db_connection()
            try:
                conn.execute('DELETE FROM verification_codes WHERE email = ?', (email,))
                conn.commit()
            finally:
                conn.close()
            print(f">>> КОД АННУЛИРОВАН: Пользователь {email} вышел с экрана верификации")

        return make_json_response({"message": "OK"}, 200)

    except Exception as e:
        print(f">>> ОШИБКА СЕРВЕРА (invalidate): {str(e)}")
        return make_json_response({"message": "Server Error"}, 500)


if __name__ == '__main__':
    # Только для локальной разработки. В продакшене запускайте через Gunicorn/uWSGI
    # за nginx, не через встроенный сервер Flask, и без debug=True.
    app.run(host='0.0.0.0', port=5000, debug=False)
