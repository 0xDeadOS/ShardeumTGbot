import asyncio
import telebot
from Constant.data import TOKEN, CHAT_ID, BASE_URL, STATUS_ENDPOINT, LOGIN_ENDPOINT

bot = telebot.TeleBot(TOKEN)

async def foo():
    print("Start foo")
    await asyncio.sleep(2)
    print("End foo")

async def bar():
    print("Start bar")
    await asyncio.sleep(1)
    print("End bar")
    
@bot.message_handler(commands=['start'])
async def start(message):
    await message.reply("Hello!")
    
    
async def main():
    task1 = asyncio.create_task(foo())
    task2 = asyncio.create_task(bar())

    await task1
    await task2


if __name__ == "__main__":
    asyncio.run(main(),bot.polling(none_stop=True))