# Simple HTTP Fuzzer 
import requests
import threading
wordlist = open('wordlist.txt','r')
wlist = wordlist.read().splitlines()

def Requested(url) :
    response = requests.get(url)
    if response.status_code == 200:
        print(f"Response from {url}")
        print(response.content)
  
threads = []

for path in wlist:
    url = "http://35.93.142.191" + '/' + path 
    thread = threading.Thread(target=Requested,args=[url])  
    thread.start()
    threads.append(thread)

for thread in threads :
    thread.join()
