import requests

BOT_TOKEN = "7854538488:AAE6zXA3LdjUrE8ZwC0ubAJ84PkOk_AERsY"
CHAT_ID = "-1002672470858"
MESSAGE = "✅ Deploy sa GitHub-a uspešno izvršen!"

url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
data = {"chat_id": CHAT_ID, "text": MESSAGE}
requests.post(url, data=data)
