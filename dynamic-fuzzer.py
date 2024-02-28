import requests
import argparse
from threading import Thread

def Fuffa(url):
    try:
        response = requests.get(url, verify=False)
        if response.status_code == 200:
            print(url + " is valid")
        else:
            print(url + str(response.status_code))    
    except KeyboardInterrupt:
        exit(0)
    except requests.exceptions.RequestException as e:
        print("Error:", e)

if __name__ == "__main__":
    threads = []
        
    parser = argparse.ArgumentParser(description='Fuffa Dynamic Fuzzer')
    parser.add_argument('-w', '--wordlist', help='Path to the wordlist')
    parser.add_argument('-u', '--url', help='Target URL')
    args = parser.parse_args()
    
    with open(args.wordlist, 'r') as file:
        wordlist = file.readlines()
        for value in wordlist:
            target = str(args.url).replace("Fuffa", value.strip())                   
            thread = Thread(target=Fuffa, args=[target])  
            threads.append(thread)
            thread.start()

    for thread in threads:
        thread.join()
