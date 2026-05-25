import os
import random
import time
from flask import Flask, request, jsonify
import requests
from dotenv import load_dotenv

# Загружаем переменные из .env
load_dotenv()

app = Flask(__name__)

RESEND_API_KEY = os.getenv('RESEND_API_KEY')
if not RESEND_API_KEY:
    print("!!! ОШИБКА: API ключ не найден в .env файле")
    exit(1)

# Хранилище кодов (в памяти)
verification_codes = {}

@app.route('/send-verification-code', methods=['POST'])
def send_verification_code():
    try:
        data = request.get_json()
        email = data.get('email')
        
        if not email:
            return jsonify({"message": "Email не указан"}), 400

        # Генерация кода
        code = str(random.randint(1000, 9999))
        verification_codes[email] = {
            "code": code,
            "expires_at": int(time.time()) + 600  # 10 минут
        }

        headers = {
            "Authorization": f"Bearer {RESEND_API_KEY}",
            "Content-Type": "application/json"
        }

        payload = {
            "from": "Spark Messenger <auth@sparkmessenger.ru>",
            "to": [email],
            "subject": "Код подтверждения Spark",
            "html": f"""
                <div style="font-family: sans-serif; max-width: 500px; margin: auto; padding: 20px; border: 1px solid #eee; border-radius: 10px;">
                    <h2 style="color: #007bff; text-align: center;">Spark Messenger</h2>
                    <p>Ваш код подтверждения:</p>
                    <div style="background: #f8f9fa; padding: 20px; text-align: center; font-size: 30px; font-weight: bold; letter-spacing: 5px; color: #007bff; border-radius: 8px;">
                        {code}
                    </div>
                    <p style="font-size: 12px; color: #777; margin-top: 20px;">Код действителен 10 минут. Если вы не запрашивали его, просто удалите это письмо.</p>
                </div>
            """
        }

        print(f"\n>>> ПОПЫТКА ОТПРАВКИ: {email}")
        
        # Делаем запрос к Resend
        response = requests.post("https://api.resend.com/emails", headers=headers, json=payload)
        
        # ЛОГИ ДЛЯ ДИАГНОСТИКИ (СМОТРИ ИХ В ТЕРМИНАЛЕ)
        print(f">>> СТАТУС RESEND: {response.status_code}")
        print(f">>> ОТВЕТ RESEND: {response.text}")

        if response.status_code in [200, 201, 202]:
            print(f">>> УСПЕХ: Код {code} отправлен.")
            return jsonify({"message": "Success", "id": response.json().get('id')}), 200
        else:
            print(f">>> ОШИБКА: Resend отклонил запрос.")
            return jsonify({"message": "Resend Error", "details": response.text}), response.status_code

    except Exception as e:
        print(f">>> КРИТИЧЕСКАЯ ОШИБКА: {str(e)}")
        return jsonify({"message": "Server Error", "error": str(e)}), 500

if __name__ == '__main__':
    print("--- Spark Auth Server Started on Port 5000 ---")
    app.run(host='0.0.0.0', port=5000)
