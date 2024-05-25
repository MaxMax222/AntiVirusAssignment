import os
import requests
import threading as th
import time
import concurrent.futures

# get all of the file paths in a given path of a directory
def get_all_files(folder):
    all_files = []

    for data in os.listdir(folder):
        path = os.path.join(folder, data)

        if os.path.isdir(path):
            all_files.extend(get_all_files(path))
        else:
            all_files.append(path)

    return all_files

# upload a file to VirusTotal and retrive the id of the file after upload
def get_file_id(file_path):
    url = "https://www.virustotal.com/api/v3/files"
    api_key = 'ccc7a97f2f98b70f337c62eb56f65bc2b66b41105b3e8e7203d8394f2b24bbbb'
    
    files = {
        "file": (os.path.basename(file_path), open(file_path, 'rb'))
    }
    
    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }
    
    response = requests.post(url, headers=headers, files=files)
    responseJSN = response.json()
    id = responseJSN['data']['id']

    return id

# get report of an uploaded file by the id of the file
def get_report_by_id(id):
    url = f'https://www.virustotal.com/api/v3/analyses/{id}'
    api_key = 'ccc7a97f2f98b70f337c62eb56f65bc2b66b41105b3e8e7203d8394f2b24bbbb'
    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }

    # wait for the until the report is finished 
    while True:
        response = requests.get(url=url, headers=headers)
        response_jsn = response.json()
        
        # Check the analysis status
        status = response_jsn.get('data', {}).get('attributes', {}).get('status', 'queued')
        
        if status == 'completed':
            break
        else:
            print(f'Analysis status: {status}. Waiting for 10 seconds before checking again...')
            time.sleep(10)
    
    return response_jsn


folder = input('enter path to folder: ->')

all_files_paths = get_all_files(folder)

files_path_reports = {}

# create a thread for each file in the folder for efficency
with concurrent.futures.ThreadPoolExecutor(max_workers=len(all_files_paths)) as executor:
    for file_path in all_files_paths:
        future = executor.submit(get_report_by_id, get_file_id(file_path=file_path))
        files_path_reports[os.path.basename(file_path)] = future.result()

# determine which files are safe and which are not
for k,v in files_path_reports.items():
    safe_cnt = 0
    mali_cnt = 0
    print('\n')
    for av, result in v.get('data').get('attributes').get('results').items():
        if result in ['malicious', 'suspicious']:
            mali_cnt+=1
        else:
            safe_cnt += 1
    
    if safe_cnt > mali_cnt:
        print(f'{k} is a safe file')
    else:
        print(f'{k} is a malicious file')