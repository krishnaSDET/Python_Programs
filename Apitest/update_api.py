import requests

token ="Bearer 18f72383e867e8a56f94f4b3b45b70f7d352bd08049438b1cae99220f3fd8cef"

url ="https://gorest.co.in/public/v2/users/6006996"


head ={
"Authorization": "Bearer 2efa6623397eba86362013ae3d95650c66990fd3af9f78021ec489d6ffd424f2"
}
result = requests.get(url,headers=head)
assert result.status_code ==200
print(result.json())
# {"name":"Allasani Peddana", "email":"allasani.peddana@15ce.com", "status":"active"}'
# body ={"name":"Malik","email":"malik@pacocha-sipes.example","gender":"female","status":"active"}
body ={"gender":"female","status":"active"}
result = requests.put(url,headers=head,json=body)
print( result.status_code)
print(result.json())