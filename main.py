import aiohttp
import asyncio
import hashlib
import json
import telebot
from loguru import logger
from Constant.data import TOKEN, CHAT_ID, BASE_URL, STATUS_ENDPOINT, LOGIN_ENDPOINT

bot = telebot.TeleBot(TOKEN)

@bot.message_handler(commands=['start'])
def start(message):
    bot.send_message(chat_id=message.chat.id, text="Hello, I'm Shardeum TG bot")
    asyncio.run(check())

def hash_password(password):
    hasher = hashlib.sha256()
    hasher.update(password.encode('utf-8'))
    return hasher.hexdigest()

async def login_request(session, url, user, password, name):
    try:
        async with session.post(f"{url}{LOGIN_ENDPOINT}", json={
            "password": hash_password(password)
        }) as resp:
            if resp.status != 200:
                return None
            data = await resp.json()
            return True, data["accessToken"]
    except Exception as e:
        logger.error(f"Error for {user} | {name}")
        logger.error(e)

        return False, e
    
async def status_request(session, url, token, name):
    async with session.get(f"{url}{STATUS_ENDPOINT}", headers={
        "X-Api-Token": token
    }) as resp:
        if resp.status != 200:
            return None
        return await resp.json()

async def req(session, user, password, ip, name, port='8080') -> str:
    url = BASE_URL.format(ip=ip, port=port)
    token = await login_request(session, url, user, password, name)
    if not token:
        return f"Error for {user} | {name}"
    data = await status_request(session, url, token, name)
    if not data:
        return f"Error for {user} | {name}\n     "
    
    return f"{user} | {name}\n     State: <b>{data['state']}</b>"


async def check():
    with open("db.json") as f:
        data = json.load(f)
        async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as session:
            tasks = []
            for user, nodes in data.items():
                tasks.extend(
                    asyncio.ensure_future(
                        req(
                            session,
                            user,
                            info['password'],
                            info['ip'],
                            info['name'],
                        )
                    )
                    for node, info in nodes.items()
                )
        bot.send_message(chat_id=CHAT_ID, parse_mode='HTML', text='\n'.join(await asyncio.gather(*tasks)))


if __name__ == '__main__':
    bot.polling(none_stop=True)
