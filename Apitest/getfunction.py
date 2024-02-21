import requests

token ="Bearer 18f72383e867e8a56f94f4b3b45b70f7d352bd08049438b1cae99220f3fd8cef"

url ="https://simple-grocery-store-api.glitch.me/orders"
url1 ="https://simple-grocery-store-api.glitch.me/carts"
head ={
    'Authorization': token
}

bodycarts ={
   "created": True,
   "cartId": "ZFe4yhG5qNhmuNyrbLWa4"
}
body ={
    "cartId": "LgIYy5oEED406e1YJPn_Z",
    "customerName": "John Doe"
}

# cartId': 'LgIYy5oEED406e1YJPn_Z
parms = {
    'category' :'candy',
    'result' : 4
}
# result = requests.post(url, headers=head, json=body)
result = requests.get(url, headers=head)
# result = requests.get(url1+'/LgIYy5oEED406e1YJPn_Z')
print(result.status_code)
# assert result.status_code ==200
id_value = result.json()

print(result.json())
# print(id_value[0]['id'])

