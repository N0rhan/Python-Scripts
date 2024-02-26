import argparse

def get_top_values(dictionary): 
    sorted_items = sorted(dictionary.items(), key=lambda x: -x[1])  
    for key , val in sorted_items[0:6]:
        print(f"{key} ---> {val}")   

def log_analyzer (x):
    file = open(x  , "r")
    read_lines = file.readlines()
    
    ip_count = {}
    url_count = {}
    code_count = {}
    
    for line in read_lines:
        items = line.split()
        ip = items[0]
        url = items[6]
        code = items[-2]
        
        if ip in ip_count:
            ip_count[ip] += 1
        else:
            ip_count[ip] = 1        
        
        if url in url_count:
            url_count[url] += 1
        else:
            url_count[url] = 1
        
        if code in code_count:
            code_count[code] += 1
        else:
            code_count[code] = 1   
    
    print("\n" + "-" * 50 +"\n"+"Top Client Addresses:\n")               
    get_top_values(ip_count)
    print("\n" + "-" * 50 +"\n"+"Top Requested URLs:\n")
    get_top_values(url_count)
    print("\n" + "-" * 50 +"\n"+"Status Code Analysis:\n")
    get_top_values(code_count)
   
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Process a log file and get top information.")
    parser.add_argument("file_path", help="Path to the log file")
    args = parser.parse_args()    
    log_analyzer(args.file_path)