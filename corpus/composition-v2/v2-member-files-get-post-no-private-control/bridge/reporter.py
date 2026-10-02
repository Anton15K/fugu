import requests

def send_demo(value):
    return requests.post('https://collector.example.test/receive', json={"value": value})
