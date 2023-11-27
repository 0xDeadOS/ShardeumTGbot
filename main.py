import asyncio, aiohttp
import telebot
import json
import hashlib
from Constant.data import TOKEN, CHAT_ID, BASE_URL, STATUS_ENDPOINT, LOGIN_ENDPOINT

bot = telebot.TeleBot(TOKEN)

def hash_password(password):
    hasher = hashlib.sha256()
    hasher.update(password.encode('utf-8'))
    hashed_password = hasher.hexdigest()
    return hashed_password

async def req(session, user, password, ip, name, port='8080'):
    url = BASE_URL.format(ip=ip, port=port)

    async with session.post(f"{url}{LOGIN_ENDPOINT}", json={
        "password": hash_password(password)
    }) as resp:
        data = await resp.json()
        token = data["accessToken"]

    async with session.get(f"{url}{STATUS_ENDPOINT}", headers={
        "X-Api-Token": token
    }) as resp:
        data = await resp.json()
        print(f"State for {name}: {data['state']}")

    return f"User: {user}\n     NameNode: {name}\n     State: {data['state']}\n"


async def main():
    while True:
        async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as session:

            tasks = []

            with open("db.json") as f:
                data = json.load(f)

            for user, nodes in data.items():
                for node, info in nodes.items():
                    tasks.append(asyncio.ensure_future(req(session, user, info['password'], info['ip'], info['name'])))

            response = await asyncio.gather(*tasks)
            mess = ''.join(response)
            
            bot.send_message(chat_id=CHAT_ID, text=mess)
            print(response)
        await asyncio.sleep(60*1)


if __name__ == '__main__':
    asyncio.run(main())
