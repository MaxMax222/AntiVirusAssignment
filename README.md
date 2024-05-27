
# VirusTotal File Scanner

This script scans all files in a specified directory for malware using the VirusTotal API. It uploads each file to VirusTotal, retrieves the analysis report, and determines if the file is safe or malicious based on the analysis results.

## Requirements

- Python 3.x
- `requests` library

You can install the `requests` library using pip:

```sh
pip install requests
```

## Setup

1. **VirusTotal API Key**: You need a VirusTotal API key to use this script. You can obtain one by signing up on the [VirusTotal website](https://www.virustotal.com/gui/join-us).

2. **Environment Variable**: Set the VirusTotal API key as an environment variable named `VIRUSTOTAL_API_KEY`.

   - On Windows:
     ```sh
     set VIRUSTOTAL_API_KEY=your_api_key_here
     ```

   - On macOS/Linux:
     ```sh
     export VIRUSTOTAL_API_KEY=your_api_key_here
     ```

## Usage

1. Save the script to a file, e.g., `virus_total_scanner.py`.
2. Run the script from the command line:
   ```sh
   python virus_total_scanner.py
   ```

3. When prompted, enter the path to the directory containing the files you want to scan.

## How It Works

1. **File Retrieval**: The script retrieves all file paths from the specified directory and its subdirectories.

2. **File Upload**: Each file is uploaded to VirusTotal using the `/files` endpoint. The script retrieves the file ID after a successful upload.

3. **Analysis Report**: The script continuously checks the analysis status of each file using the `/analyses/{id}` endpoint until the analysis is complete.

4. **Report Evaluation**: After retrieving the analysis report, the script evaluates the results. If the number of safe detections is greater than the number of malicious/suspicious detections, the file is considered safe; otherwise, it is considered malicious.

## Output

The script prints the analysis results for each file, indicating whether the file is safe or malicious based on the analysis report.

## Example

```sh
Enter path to folder: ->/path/to/your/folder

Analysis status: queued. Waiting for 10 seconds before checking again...
Analysis status: completed.

file1.txt is a safe file

file2.exe is a malicious file
```

## Error Handling

If an error occurs during the file upload or analysis retrieval process, the script prints an error message with the file path and the error details.

## Contributing

Contributions are welcome! If you find any issues or have suggestions for improvement, please create an issue or submit a pull request.

## License

This project is licensed under the MIT License. See the LICENSE file for details.
