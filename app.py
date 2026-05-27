import os
import random
import time
import threading  # Для асинхронности
from flask import Flask, request, jsonify
import requests
from dotenv import load_dotenv
from functools import wraps

load_dotenv()
app = Flask(__name__)

# --- КОНФИГУРАЦИЯ БЕЗОПАСНОСТИ ---
RESEND_API_KEY = os.getenv('RESEND_API_KEY')
TURNSTILE_SECRET_KEY = os.getenv('TURNSTILE_SECRET_KEY')  # Секретный ключ из Cloudflare
APP_SECRET = "Qx9zP2wL4mN7bV1sK5hJ8rT3yX6gZ0" 

request_history = {}
email_history = {}  # История запросов по Email: { email: [timestamps] }
verification_codes = {} # Хранилище кодов: { email: {"code": "1234", "expires_at": 169...} }

def make_json_response(data, status_code):
    response = jsonify(data)
    response.headers["Content-Type"] = "application/json; charset=utf-8"
    return response, status_code

def limit_requests(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        ip = request.remote_addr
        now = time.time()
        
        if ip in request_history:
            request_history[ip] = [t for t in request_history[ip] if now - t < 120]
        else:
            request_history[ip] = []
            
        if len(request_history[ip]) >= 3:
            print(f">>> RATE LIMIT: Блокировка запроса по IP от {ip}")
            return make_json_response({"message": "Слишком много запросов. Подождите 2 минуты."}, 429)
            
        request_history[ip].append(now)
        return f(*args, **kwargs)
    return decorated_function

def require_auth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.headers.get('X-Spark-Auth') != APP_SECRET:
            print(f">>> AUTH ERROR: Неверный ключ доступа от {request.remote_addr}")
            return make_json_response({"message": "Access Denied"}, 401)
        return f(*args, **kwargs)
    return decorated_function

# --- АСИНХРОННАЯ ФУНКЦИЯ ОТПРАВКИ ПИСЬМА ---
def send_email_async(email, code, headers, payload):
    """Выполняется параллельно и не блокирует основной поток Flask"""
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
        data = request.get_json()
        if not data:
            return make_json_response({"message": "Пустой JSON запрос"}, 400)
            
        email = data.get('email')
        captcha_token = data.get('captcha_token')
        
        if not email:
            return make_json_response({"message": "Email не указан"}, 400)
            
        if not captcha_token:
            print(f">>> CAPTCHA ERROR: Токен капчи отсутствует для {email}")
            return make_json_response({"message": "Капча не пройдена"}, 403)

        # 1. ПРОВЕРКА КАПЧИ В CLOUDFLARE TURNSTILE
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

        # 2. ПРОВЕРКА ЛИМИТОВ ПО EMAIL
        now = int(time.time())
        if email in email_history:
            email_history[email] = [t for t in email_history[email] if now - t < 900]
        else:
            email_history[email] = []
            
        if len(email_history[email]) >= 2:
            print(f">>> EMAIL RATE LIMIT: Блокировка отправки на {email}")
            return make_json_response({"message": "Превышен лимит отправки кодов"}, 429)

        email_history[email].append(now)

        # 3. ГЕНЕРАЦИЯ И СОХРАНЕНИЕ КОДА
        code = str(random.randint(1000, 9999))
        expires_at = now + 600 # 10 минут
        verification_codes[email] = {"code": code, "expires_at": expires_at}

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

        # ЗАПУСК ФОНОВОГО ПОТОКА ДЛЯ RESEND
        email_thread = threading.Thread(
            target=send_email_async, 
            args=(email, code, headers, payload)
        )
        email_thread.start()

        return make_json_response({"message": "Code sent"}, 200)

    except Exception as e:
        print(f">>> ОШИБКА СЕРВЕРА: {str(e)}")
        return make_json_response({"message": "Server Error", "error": str(e)}, 500)

# =====================================================================
# ЭНДПОИНТ 2: ПРОВЕРКА КОДА (НОВЫЙ)
# =====================================================================
@app.route('/verify-code', methods=['POST'])
@require_auth
def verify_code():
    try:
        data = request.get_json()
        if not data:
            return make_json_response({"message": "Пустой JSON запрос"}, 400)
            
        email = data.get('email')
        code = data.get('code')
        
        if not email or not code:
            return make_json_response({"message": "Email или код не указаны"}, 400)

        # 1. Проверяем, запрашивался ли код для этого email
        if email not in verification_codes:
            print(f">>> VERIFY ERROR: Код для {email} не найден")
            return make_json_response({"message": "Код не найден или устарел"}, 404)

        record = verification_codes[email]
        now = int(time.time())

        # 2. Проверяем срок годности кода (10 минут)
        if now > record["expires_at"]:
            del verification_codes[email]
            print(f">>> VERIFY ERROR: Время кода для {email} истекло")
            return make_json_response({"message": "Время действия кода истекло"}, 400)

        # 3. Сверяем сам код
        if record["code"] != code:
            print(f">>> VERIFY ERROR: Неверный код для {email}")
            return make_json_response({"message": "Неверный код"}, 400)

        # 4. Код верный!
        print(f">>> УСПЕШНАЯ АВТОРИЗАЦИЯ: {email}")
        del verification_codes[email] # Удаляем, чтобы не зашли второй раз по старому коду
        
        return make_json_response({"message": "Код верный"}, 200)

    except Exception as e:
        print(f">>> ОШИБКА СЕРВЕРА (verify): {str(e)}")
        return make_json_response({"message": "Server Error", "error": str(e)}, 500)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
