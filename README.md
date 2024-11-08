# Brainwave_Matrix_Intern
This Python script interacts with the VirusTotal API to check the security status of a given URL

import requests
import os


API_KEY = os.environ['VIRUSTOTAL_API_KEY']

url = 'https://www.virustotal.com/api/v3/urls'
headers = {
    "accept": "application/json",
    "x-apikey": API_KEY,
    "content-type": "application/x-www-form-urlencoded"
}



def url_scan(target_url):
    # URL needs to be in base64 format for VirusTotal API
    import base64
    url_id = base64.urlsafe_b64encode(target_url.encode()).decode().strip("=")
    response = requests.get(f'https://www.virustotal.com/api/v3/urls/{url_id}', headers=headers)
    return response.json()


# Prompt user for the target URL
target_url = input("Enter the URL to scan: ")

result = url_scan(target_url)
print(result)

