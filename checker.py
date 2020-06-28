import requests

s = requests.Session()
s.proxies = {
 "http": "http://localhost:8000",
 "https": "http://localhost:8001",
}

r = s.get("https://ya.ru")
r = s.get("https://ya.ru")

open('test.html', 'wb').write(r.content)

print(r.content)
