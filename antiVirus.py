import os
import requests
import threading as th
import time
import concurrent.futures

# Get all of the file paths in a given directory
def get_all_files(folder):
    all_files = []

    for data in os.listdir(folder):
        path = os.path.join(folder, data)

        if os.path.isdir(path):
            all_files.extend(get_all_files(path))
        else:
            all_files.append(path)

    return all_files

# Upload a file to VirusTotal and retrieve the ID of the file after upload
def get_file_id(file_path, api_key):
    url = "https://www.virustotal.com/api/v3/files"
    
    with open(file_path, 'rb') as file:
        files = {
            "file": (os.path.basename(file_path), file)
        }
        
        headers = {
            "accept": "application/json",
            "x-apikey": api_key
        }
        
        response = requests.post(url, headers=headers, files=files)
        response.raise_for_status()  # Raise an exception for HTTP errors
        responseJSN = response.json()
        return responseJSN['data']['id']

# Get the report of an uploaded file by the ID of the file
def get_report_by_id(file_id, api_key):
    url = f'https://www.virustotal.com/api/v3/analyses/{file_id}'
    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }

    while True:
        response = requests.get(url=url, headers=headers)
        response.raise_for_status()  # Raise an exception for HTTP errors
        response_jsn = response.json()
        
        # Check the analysis status
        status = response_jsn.get('data', {}).get('attributes', {}).get('status', 'queued')
        
        if status == 'completed':
            break
        else:
            print(f'Analysis status: {status}. Waiting for 10 seconds before checking again...')
            time.sleep(10)
    
    return response_jsn

def process_file(file_path, api_key):
    try:
        file_id = get_file_id(file_path, api_key)
        report = get_report_by_id(file_id, api_key)
        return os.path.basename(file_path), report
    except requests.RequestException as e:
        print(f'Error processing file {file_path}: {e}')
        return os.path.basename(file_path), None

def main():
    folder = input('Enter path to folder: ->')
    api_key = os.getenv('VIRUSTOTAL_API_KEY')  # Load API key from environment variable

    all_files_paths = get_all_files(folder)

    files_path_reports = {}

    # Create a thread pool for concurrent processing
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(len(all_files_paths), 10)) as executor:
        futures = [executor.submit(process_file, file_path, api_key) for file_path in all_files_paths]
        
        for future in concurrent.futures.as_completed(futures):
            file_name, report = future.result()
            if report:
                files_path_reports[file_name] = report

    # Determine which files are safe and which are not
    for file_name, report in files_path_reports.items():
        safe_cnt = 0
        mali_cnt = 0
        print('\n')
        for av, result in report.get('data', {}).get('attributes', {}).get('results', {}).items():
            if result in ['malicious', 'suspicious']:
                mali_cnt += 1
            else:
                safe_cnt += 1
        
        if safe_cnt > mali_cnt:
            print(f'{file_name} is a safe file')
        else:
            print(f'{file_name} is a malicious file')

if __name__ == "__main__":
    main()
