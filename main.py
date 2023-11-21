import json
import requests
import telebot
import hashlib
from requests.exceptions import RequestException
from urllib3.exceptions import InsecureRequestWarning
from Constant.data import TOKEN, CHAT_ID

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

BASE_URL = "https://{ip}:{port}"
LOGIN_ENDPOINT = '/auth/login'
STATUS_ENDPOINT = '/api/node/status'

bot = telebot.TeleBot(TOKEN)

def hash_password(password):
    hasher = hashlib.sha256()
    hasher.update(password.encode('utf-8'))
    hashed_password = hasher.hexdigest()
    return hashed_password


def login_request(password, ip, port='8080'):
    url = BASE_URL.format(ip=ip, port=port)
    headers = {
        'Connection': 'keep-alive',
        'Content-Type': 'application/json',
    }
    json_data = {
        'password': f'{hash_password(password)}',
    }
    try:
        response = requests.post(f'{url}{LOGIN_ENDPOINT}', headers=headers, json=json_data, verify=False)
        return response.json().get('accessToken')
    except RequestException as e:
        print(f"Error occurred while sending request to server: {e}")
        return None


def status_request(password, ip, port='8080'):
    url = BASE_URL.format(ip=ip, port=port)
    access_token = login_request(password, ip, port)
    if not access_token:
        return  # Exit if login fails

    headers = {
        'Connection': 'keep-alive',
        'X-Api-Token': f'{access_token}',
    }
    try:
        response = requests.get(f'{url}{STATUS_ENDPOINT}', headers=headers, verify=False)
        response.raise_for_status()
        print(response.status_code)
        bot.send_message(chat_id=CHAT_ID, text=response.status_code)
    except RequestException as e:
        print(f"Error during status request: {e}")


if __name__ == "__main__":
    with open('db.json', 'r') as file:
        data = json.load(file)

    for user, nodes in data.items():
        for node, info in nodes.items():
            status_request(info['password'], info['ip'], info['name'])
