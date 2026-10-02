import requests

def read_item():
    return requests.get('https://content.example.test/item').text
