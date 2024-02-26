import hashlib
import glob
import datetime
import time

def wait(T):
    time.sleep(T)
        

dll_files = glob.glob(r"C:\Windows\System32\*.dll")
dll_dict = {}
for file in dll_files:
    read_file = open(file, 'rb') 
    file_contents = read_file.read()
    stored_hash = hashlib.md5(file_contents).hexdigest()
    dll_dict[file] = dll_dict.get(file, stored_hash) 
changes = False

wait(60)

warnings_file = open("D:/security/BlueCourses/Python/warnings.txt", "a") 
for file, stored_hash in dll_dict.items():
    read_file = open(file, 'rb') 
    file_contents = read_file.read()
    file_hash = hashlib.md5(file_contents).hexdigest()
    if file_hash != stored_hash:
        warnings_file.write(f"Checking date: {datetime.datetime.now()}\n{file} has changed.\n")
        changes = True

if not changes:
    warnings_file = open("D:/security/BlueCourses/Python/warnings.txt", "a") 
    warnings_file.write(f"Checking date: {datetime.datetime.now()}\nNo changes were detected.\n")

print("DLL checking completed.")
