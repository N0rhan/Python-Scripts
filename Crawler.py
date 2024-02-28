import bs4
import requests

url_set = set()

def link_parser(base_url):
    request = requests.get(base_url)
    bs = bs4.BeautifulSoup(request.content, "lxml")
    links = bs.find_all("a")
    for link in links:
        href = link.get("href")
        if href is not None and href not in url_set and "#" not in href and "javascript:" not in href:
            url_set.add(href)

def sub_urls(url_set):
    for url in url_set:
        request = requests.get(url)
        status_code = request.status_code
        if status_code == 200: 
            bs = bs4.BeautifulSoup(request.text, "lxml")
            sub_links = bs.find_all("a")
            for link in sub_links:
                href = link.get("href")
                if href is not None and href not in url_set and "#" not in href and "javascript:" not in href:
                    print(f"Link: {url}\n\t==> {href}")
        else:
            print(f"Failed to fetch {url}. Status code: {status_code}")

base_url = "https://www.kali.org/"
link_parser(base_url)
sub_urls(url_set)
