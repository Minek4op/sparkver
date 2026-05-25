import os
import random
import time
from flask import Flask, request, jsonify
import requests
from dotenv import load_dotenv

# Загружаем переменные окружения из .env файла
load_dotenv()

app = Flask(__name__)

RESEND_API_KEY = os.getenv('RESEND_API_KEY')
if not RESEND_API_KEY:
    print("Ошибка: RESEND_API_KEY не установлен в .env файле.")
    exit(1)

# Временное хранилище для кодов подтверждения (в реальном приложении используй базу данных)
# { "email": {"code": "1234", "expires_at": 1678886400} }
verification_codes = {}

@app.route('/send-verification-code', methods=['POST'])
def send_verification_code():
    data = request.get_json()
    email = data.get('email')

    if not email:
        return jsonify({"message": "Email не предоставлен"}), 400

    # Генерация 4-значного кода
    code = str(random.randint(1000, 9999))
    
    # Установка срока действия кода (10 минут)
    expires_at = int(time.time()) + (10 * 60) # 10 минут в секундах

    verification_codes[email] = {"code": code, "expires_at": expires_at}
    print(f"Сгенерирован код {code} для {email}, истекает в {time.ctime(expires_at)}")

    headers = {
        "Authorization": f"Bearer {RESEND_API_KEY}",
        "Content-Type": "application/json"
    }

    # Строгое и красивое оформление письма
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>Код подтверждения Spark Messenger</title>
        <style>
            body {{
                font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
                line-height: 1.6;
                color: #333333;
                background-color: #f4f4f4;
                margin: 0;
                padding: 0;
            }}
            .container {{
                max-width: 600px;
                margin: 30px auto;
                background-color: #ffffff;
                padding: 40px;
                border-radius: 8px;
                box-shadow: 0 4px 12px rgba(0, 0, 0, 0.05);
                border: 1px solid #eaeaec;
            }}
            .header {{
                text-align: center;
                margin-bottom: 30px;
                border-bottom: 1px solid #eeeeee;
                padding-bottom: 20px;
            }}
            .header h1 {{
                color: #007bff; /* Примерный цвет бренда, можно изменить */
                font-size: 28px;
                margin: 0;
            }}
            .content {{
                text-align: center;
            }}
            .content p {{
                font-size: 16px;
                margin-bottom: 20px;
            }}
            .code-box {{
                background-color: #e0f2f7; /* Легкий фон для кода */
                border: 1px dashed #a7d9ed;
                padding: 15px 25px;
                margin: 25px auto;
                font-size: 32px;
                font-weight: bold;
                letter-spacing: 5px;
                color: #007bff;
                display: inline-block;
                border-radius: 6px;
            }}
            .footer {{
                text-align: center;
                margin-top: 40px;
                font-size: 12px;
                color: #999999;
                border-top: 1px solid #eeeeee;
                padding-top: 20px;
            }}
            .footer p {{
                margin: 5px 0;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>Spark Messenger</h1>
            </div>
            <div class="content">
                <p>Здравствуйте!</p>
                <p>Ваш код подтверждения для Spark Messenger:</p>
                <div class="code-box">
                    <strong>{code}</strong>
                </div>
                <p>Этот код действителен в течение 10 минут. Если вы не запрашивали этот код, пожалуйста, проигнорируйте это письмо.</p>
                <p>С уважением,<br>Команда Spark Messenger</p>
            </div>
            <div class="footer">
                <p>Это автоматическое письмо. Пожалуйста, не отвечайте на него.</p>
                <p>&copy; {time.strftime("%Y")} Spark Messenger. Все права защищены.</p>
            </div>
        </div>
    </body>
    </html>
    """

    payload = {
        "from": "auth@sparkmessenger.ru",
        "to": [email],
        "subject": "Код подтверждения для Spark Messenger",
        "html": html_content
    }

    try:
        resend_response = requests.post("https://api.resend.com/emails", headers=headers, json=payload)
        resend_response.raise_for_status() # Вызовет исключение для HTTP ошибок (4xx или 5xx)
        print(f"Письмо успешно отправлено Resend для {email}. ID: {resend_response.json().get('id')}")
        return jsonify({"message": "Код подтверждения отправлен", "email": email}), 200
    except requests.exceptions.RequestException as e:
        print(f"Ошибка при отправке письма через Resend для {email}: {e}")
        return jsonify({"message": "Не удалось отправить код подтверждения", "error": str(e)}), 500

if __name__ == '__main__':
    # Flask будет слушать на всех доступных IP-адресах на порту 5000
    # В продакшене используй Gunicorn/Nginx для запуска приложения
    app.run(host='0.0.0.0', port=5000)