import requests

token ="Bearer 18f72383e867e8a56f94f4b3b45b70f7d352bd08049438b1cae99220f3fd8cef"

url ="https://gorest.co.in/public/v2/users/6006996"

url1 ="https://gorest.co.in/public/v2/users"
head ={
"Authorization": "Bearer 2efa6623397eba86362013ae3d95650c66990fd3af9f78021ec489d6ffd424f2"
}
body={"name":"Tenali Ramakrishna", "gender":"male", "email":"ramakrishna@15e.com", "status":"active"}

# curl -i -H "Accept:application/json" -H "Content-Type:application/json" -H "Authorization: Bearer ACCESS-TOKEN" -XPOST "https://gorest.co.in/public/v2/users" -d '{"name":"Tenali Ramakrishna", "gender":"male", "email":"tenali.ramakrishna@15ce.com", "status":"active"}'

s = requests.Session()
s.headers.update(head)
# s.prepare_request()

r = s.post(url1,json=body)
print(f'Status Code: {r.status_code}, Content: {r.json()}')