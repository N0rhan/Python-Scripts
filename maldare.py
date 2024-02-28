#Basic malware signature detector
import os
from hashlib import md5
from datetime import datetime
import pefile
import lief
import argparse

def getsampleinfo(file_path):
    sample = os.stat(file_path)
    print("Sample General information: \n" + "-" * 50)
    
    filename = os.path.basename(file_path)
    file_extension = os.path.splitext(file_path)[1]
    print(f"File name: \t\t {filename}")
    print(f"File type: \t\t{file_extension}")
    print(f"File Size: \t\t{sample.st_size} bytes")
    
    created_time = sample.st_ctime
    accessed_time = sample.st_atime
    modified_time = sample.st_mtime
    
    print(f"File created at: \t{datetime.fromtimestamp(created_time)}")
    print(f"File accessed at: \t{datetime.fromtimestamp(accessed_time)}")
    print(f"File modified at: \t{datetime.fromtimestamp(modified_time)}")    
    with open(file_path, mode="rb") as file:
        content = file.read()
        md5_hash = md5(content).hexdigest()
        print(f"MD5 Hash: \t\t{md5_hash}")

def getpeheaderinfo(file_path):
    print(f"\n\nPE information \n " + "-" * 50)
    PE = pefile.PE(file_path)
    
    print(f"Machine Type:\t\t {hex(PE.FILE_HEADER.Machine)}")
    print(f"Subsystem Type:\t\t{hex(PE.OPTIONAL_HEADER.Subsystem)}")
    
    print(f"This file ran for first time at\t {datetime.fromtimestamp(PE.FILE_HEADER.TimeDateStamp)}")
    print(f"Image Base: \t\t {hex(PE.OPTIONAL_HEADER.ImageBase)}")
    
    print(f"Number of Sections:\t\t {PE.FILE_HEADER.NumberOfSections}")   
    print(f"Address Of Entry Point {PE.OPTIONAL_HEADER.AddressOfEntryPoint}")
    
    PE.parse_data_directories()
    print(f"Imported Functions: ")
    for entry in PE.DIRECTORY_ENTRY_IMPORT:
        print(f"\t\tDLL: {entry.dll}")
        for imp in entry.imports:
            print(f"\tFunction: {imp.name}")  
    print(f"DLL characteristics {PE.OPTIONAL_HEADER.DllCharacteristics}")
    
    print("\nManifest:\n ")
    try:
        binary = lief.parse(file_path)
        if binary.resources_manager.has_manifest:
            print(binary.resources_manager.manifest)
        else:
            print("No Manifest FOUND...")
    except lief.not_found as e:
        print(f"Error: {e}")

def malware_signature(file_path):
    PE = pefile.PE(file_path)
    API_list = ["SetWindowsHookEx", "GetAsyncKeyState", "GetKeyState", "CreateRemoteThread", "RegCreateKeyEx", "BitBlt", "CreateCompatibleDC"]
    REG_Key = ["software\\microsoft\\windows\\currentversion\\run",
               "software\\microsoft\\windows\\currentversion\\runonce",
               "software\\microsoft\\windows\\currentversion\\policies\\explorer\\run", 
               "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders"]

    for section in PE.sections:
        section_name = section.Name.decode('utf-8')
        section_content = section.get_data()
        
        for api in API_list:
            if api.encode('utf-8') in section_content:
                print(f"Highly Suspicious API call: {api}")

        for reg_key in REG_Key:
            if reg_key.encode('utf-8') in section_content:
                print(f"Highly Suspicious Key Modification: {reg_key}")

def main():
    parser = argparse.ArgumentParser(description="Sample Analysis Script")
    parser.add_argument('sample_path', help="Path to the sample file")
    parser.add_argument('-i', '--info', action='store_true', help="Get general information about the sample")
    parser.add_argument('-p', '--header', action='store_true', help="Get PE header information")
    parser.add_argument('-s', '--signature', action='store_true', help="Search for Malware signature")

    args = parser.parse_args()

    if args.info:
        getsampleinfo(args.sample_path)
    if args.header:
        getpeheaderinfo(args.sample_path)
    if args.signature:
        malware_signature(args.sample_path)
if __name__ == "__main__":
    main()
