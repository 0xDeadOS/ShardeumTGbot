import json
import requests
import hashlib

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

    response = requests.post(f'https://{ip}:{port}/auth/login', headers=headers, json=json_data, verify=False)

    return response.json().get('accessToken')


def status_request(password, ip, port='8080'):
    headers = {
        'Connection': 'keep-alive',
        'X-Api-Token': f'{login_request(password, ip)}',
    }

    response = requests.get(f'https://{ip}:{port}/api/node/status', headers=headers, verify=False)
    print(response.status_code)


if __name__ == "__main__":
    with open('db.json', 'r') as file:
        data = json.load(file)
    for user, nodes in data.items():
        for node, info in nodes.items():
            status_request(info['password'], info['ip'])
