import requests

files = {
    'username': (None, 'davidwalsh'),
    'password': (None, 'pzfbbmrnd'),
}

response = requests.post('http://domain.tld/post-to-me.php', files=files)
