import json
import requests
import hashlib
from requests.exceptions import RequestException
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


def hash_password(password):
    hasher = hashlib.sha256()
    hasher.update(password.encode('utf-8'))
    hashed_password = hasher.hexdigest()
    return hashed_password


def login_request(password, ip, port='8080'):
    headers = {
        'Connection': 'keep-alive',
        'Content-Type': 'application/json',
    }
    json_data = {
        'password': f'{hash_password(password)}',
    }
    try:
        response = requests.post(f'https://{ip}:{port}/auth/login', headers=headers, json=json_data, verify=False)
        return response.json().get('accessToken')
    except RequestException as e:
        print("Error occurred while sending request to server")
        return None


def status_request(password, ip, port='8080'):
    access_token = login_request(password, ip, port)
    if not access_token:
        return  # Exit if login fails

    headers = {
        'Connection': 'keep-alive',
        'X-Api-Token': f'{access_token}',
    }
    try:
        response = requests.get(f'https://{ip}:{port}/api/node/status', headers=headers, verify=False)
        response.raise_for_status()  # Raises HTTPError for bad responses
        print(response.status_code)
    except RequestException as e:
        print(f"Error during status request: {e}")


if __name__ == "__main__":
    with open('db.json', 'r') as file:
        data = json.load(file)

    for user, nodes in data.items():
        for node, info in nodes.items():
            status_request(info['password'], info['ip'])
