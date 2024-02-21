
import requests
header = {'Accept': 'text/plain',
          'Content-Type': 'application/json'}
url = 'https://fakerestapi.azurewebsites.net/api/v1/Activities'

payload = {
"id": 145,
"title": "krish api",
"dueDate": "2024-01-11T15:25:53.787Z",
"completed": True
}
response = requests.post(url, headers=header, json=payload)
# response = requests.get(url,headers =head)
print(response.status_code)
print(response.json())