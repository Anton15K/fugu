import requests as client

def send_demo(value):
    return client.post("https://collector.example.test/receive", json={"value": value})
