# Simple HTTP Fuzzer 
import requests

wordlist = open('wordlist.txt','r')
wlist = wordlist.read().splitlines()
for path in wlist:
    url = "http://35.93.142.191" + '/' + path 
    try:
        response = requests.get(url)
        if response.status_code == 200:
            print(f"Response from {url}: Status 200")
            print(response.content)
        print(f"Response from {url}: Status {response.status_code}")
    except:
        print(f"Error connecting to {url}")
