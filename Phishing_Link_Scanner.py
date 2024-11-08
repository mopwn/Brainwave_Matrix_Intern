import requests
import os
import base64

#Make sure you have a VirusTotal API key and set it in your environment variables as VIRUSTOTAL_API_KEY.
API_KEY = os.environ['VIRUSTOTAL_API_KEY']

url = 'https://www.virustotal.com/api/v3/urls'
headers = {
    "accept": "application/json",
    "x-apikey": API_KEY,
    "content-type": "application/x-www-form-urlencoded"
}

def submit_url_for_scan(target_url):
    #Submit a URL for scanning if it hasn't been scanned recently.
    data = {'url': target_url}
    response = requests.post(url, headers=headers, data=data)
    if response.status_code == 200:
        scan_info = response.json()
        print("URL submitted for scanning.")
        return scan_info
    else:
        print(f"Failed to submit URL. Status Code: {response.status_code}")
        return response.json()


def url_scan(target_url):
    # URL needs to be in base64 format for VirusTotal API
    url_id = base64.urlsafe_b64encode(target_url.encode()).decode().strip("=")
    response = requests.get(f'https://www.virustotal.com/api/v3/urls/{url_id}', headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Failed to retrieve scan result. Status Code: {response.status_code}")
        return response.json()


# Prompt user for the target URL
target_url = input("Enter the URL to scan: ")



result = url_scan(target_url)

if 'error' in result:
    print("URL not found in recent scans. Submitting for a new scan.")
    result = submit_url_for_scan(target_url)

print(result)
