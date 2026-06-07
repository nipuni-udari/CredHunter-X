import requests

headers = {
    'Accept': 'application/json',
    'user-token': '12e9db3225c1b0217616aa84a5f8c768',
}

response = requests.get('http://localhost:8080/api/retail/books/list', headers=headers)
