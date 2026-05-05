import requests

session = requests.Session()
res = session.post('http://127.0.0.1:8080/login', data={'username': 'admin', 'password': 'password123'})
print("Login Status:", res.status_code)

res2 = session.get('http://127.0.0.1:8080/live-instances')
print("Live Instances Status:", res2.status_code)
if res2.status_code != 200:
    print(res2.text[:500])

res3 = session.get('http://127.0.0.1:8080/ai-analysis')
print("AI Analysis Status:", res3.status_code)
if res3.status_code != 200:
    print(res3.text[:500])
