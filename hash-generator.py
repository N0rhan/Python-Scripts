import hashlib

text = input("Enter text...")
algo = input("Enter Hash Algorithem...")
algo = algo.lower().replace(" " ,"")

def find_hash(text , algo) :
    if algo == "md5":
       hash = hashlib.md5(text.encode()).hexdigest()
       print("MD5 Hash:" + hash)
    elif algo == "sha1":
       hash = hashlib.sha1(text.encode()).hexdigest()
       print("SHA1 Hash: " + hash)
    elif algo == "sha256" :
        hash = hashlib.sha256(text.encode()).hexdigest()
        print("SHA256 Hash: " + hash)
    elif algo == "sha512" :
        hash = hashlib.sha512(text.encode()).hexdigest()  
        print("SHA512 Hash: " + hash)
    else:
        print("invalid hash!\nChoose a hash algorithm (md5, sha1, sha256, sha512)")

find_hash(text , algo)
