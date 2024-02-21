import requests
head ={'Accept':'text/plain'}
url="https://fakerestapi.azurewebsites.net/api/v1/Activities"
response = requests.get(url,headers =head)
print(response.status_code)