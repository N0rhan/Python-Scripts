from hashlib import sha512
import bs4
import requests 

request = requests.get('http://challenges.ringzer0team.com:10013/')
soup = bs4.BeautifulSoup(request.content , 'html.parser')
div=soup.find("div").get_text()

message=div.replace("----- BEGIN MESSAGE -----" , '')
message= message.replace("----- END MESSAGE -----" , '')
message = message.strip()
print(message)
hash = sha512(message.encode()).hexdigest() 
print(hash)
url = 'http://challenges.ringzer0team.com:10013/?r='+ hash
response = requests.post(url)
print(response.content)