import os
import random
import time
from flask import Flask, request, jsonify
import requests
from dotenv import load_dotenv
from functools import wraps

# Загружаем переменные из .env
load_dotenv()

app = Flask(__name__)

# --- КОНФИГУРАЦИЯ БЕЗОПАСНОСТИ ---
RESEND_API_KEY = os.getenv('RESEND_API_KEY')
# ТОТ ЖЕ КЛЮЧ, ЧТО В ПРИЛОЖЕНИИ
APP_SECRET = "Qx9zP2wL4mN7bV1sK5hJ8rT3yX6gZ0" 

# История запросов для защиты от спама: { ip: [timestamps] }
request_history = {}

def make_json_response(data, status_code):
    """Вспомогательная функция для генерации четкого JSON-ответа с заголовками для Cloudflare"""
    response = jsonify(data)
    response.headers["Content-Type"] = "application/json; charset=utf-8"
    return response, status_code

def limit_requests(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        ip = request.remote_addr
        now = time.time()
        
        # Очищаем старые записи (старше 2 минут)
        if ip in request_history:
            request_history[ip] = [t for t in request_history[ip] if now - t < 120]
        else:
            request_history[ip] = []
            
        # Лимит: не более 3 запросов за 2 минуты с одного IP
        if len(request_history[ip]) >= 3:
            print(f">>> RATE LIMIT: Блокировка запроса от {ip}")
            return make_json_response({"message": "Слишком много запросов. Подождите 2 минуты."}, 429)
            
        request_history[ip].append(now)
        return f(*args, **kwargs)
    return decorated_function

def require_auth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Проверяем секретный заголовок из Android приложения
        if request.headers.get('X-Spark-Auth') != APP_SECRET:
            print(f">>> AUTH ERROR: Неверный ключ доступа от {request.remote_addr}")
            return make_json_response({"message": "Access Denied"}, 401)
        return f(*args, **kwargs)
    return decorated_function

# Временное хранилище кодов (email: {code, expires})
verification_codes = {}

@app.route('/send-verification-code', methods=['POST'])
@require_auth
@limit_requests
def send_verification_code():
    try:
        data = request.get_json()
        if not data:
            return make_json_response({"message": "Пустой JSON запрос"}, 400)
            
        email = data.get('email')
        
        if not email:
            return make_json_response({"message": "Email не указан"}, 400)

        # Генерация 4-значного кода
        code = str(random.randint(1000, 9999))
        
        # Срок действия 10 минут
        expires_at = int(time.time()) + 600
        verification_codes[email] = {"code": code, "expires_at": expires_at}

        print(f"\n>>> ОТПРАВКА КОДА: {email}")
        
        headers = {
            "Authorization": f"Bearer {RESEND_API_KEY}",
            "Content-Type": "application/json"
        }

        # Красивое и строгое письмо
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

        resend_resp = requests.post("https://api.resend.com/emails", headers=headers, json=payload)
        
        if resend_resp.status_code in [200, 201, 202]:
            print(f">>> УСПЕШНО: Письмо отправлено.")
            return make_json_response({"message": "Code sent"}, 200)
        else:
            print(f">>> ОШИБКА RESEND: {resend_resp.text}")
            return make_json_response({"message": "Resend Error", "details": resend_resp.text}, resend_resp.status_code)

    except Exception as e:
        print(f">>> ОШИБКА СЕРВЕРА: {str(e)}")
        return make_json_response({"message": "Server Error", "error": str(e)}, 500)

if __name__ == '__main__':
    # Слушаем на всех интерфейсах (0.0.0.0) и порту 8443, куда проксирует Cloudflare
    app.run(host='0.0.0.0', port=8443)
