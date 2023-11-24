import asyncio
import aiohttp
import requests
import json
import hashlib
from Constant.data import TOKEN, CHAT_ID, BASE_URL, STATUS_ENDPOINT, LOGIN_ENDPOINT

from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


async def req(session, password, ip, name, port='8080'):
    print(name)
    url = BASE_URL.format(ip=ip, port=port)
    hasher = hashlib.sha256()
    hasher.update(password.encode('utf-8'))
    hashed_password = hasher.hexdigest()
    async with session.post(f"{url}{LOGIN_ENDPOINT}", json={
        "password": hashed_password
    }) as resp:
        data = await resp.json()
        token = data["accessToken"]
    async with session.get(f"{url}{STATUS_ENDPOINT}", headers={
        "X-Api-Token": token
    }) as resp:
        print(f"Status code for {name}: {resp.status}")
    return resp.status


async def main():
    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as session:
        tasks = []
        with open("db.json") as f:
            data = json.load(f)
        for user, nodes in data.items():
            for node, info in nodes.items():
                tasks.append(asyncio.ensure_future(req(session, info['password'], info['ip'], info['name'])))

        response = await asyncio.gather(*tasks)
        print(response)


if __name__ == '__main__':
    asyncio.run(main())
