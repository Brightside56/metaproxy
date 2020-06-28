import requests

s = requests.Session()
s.proxies = {
 "http": "http://192.168.100.21:8000",
 "https": "http://192.168.100.21:8000",
}

r = s.get("https://ya.ru")
r = s.get("https://ya.ru")

open('test.html', 'wb').write(r.content)

print(r.content)
