import requests
from selenium_practice import webdriver
url="https://gorest.co.in/public/v2/users"

head ={
"Authorization": "Bearer 2efa6623397eba86362013ae3d95650c66990fd3af9f78021ec489d6ffd424f2"
}

body ={"name":"Malik","email":"malik@pacocha-sipes.example","gender":"female","status":"active"}

result = requests.get(url,headers=head)
assert result.status_code ==200
print(result.json())
# print(result.text)


result = requests.post(url,headers=head,json=body)
print(result.status_code)
print(result.json())
value=result.json()['id']
print(value)
assert result.status_code ==201
# import pdb; pdb.set_trace()
result = requests.get(url+'/'+str(value),headers=head)
assert result.status_code ==200
print(result.json())
