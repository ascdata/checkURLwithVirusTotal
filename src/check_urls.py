import requests
import csv
import time

API_KEY = "API-KEY"
API_URL = "https://www.virustotal.com/api/v3/urls"

headers = {
    "x-apikey": API_KEY,
    "Content-Type": "application/x-www-form-urlencoded"
}

def scan_url(url):
    response = requests.post(API_URL, headers=headers, data={"url": url})
    print(f"[scan_url] Status: {response.status_code}, URL: {url}")
    if response.status_code == 200:
        return response.json()["data"]["id"]
    print(f"[scan_url] Fehlerhafte Antwort: {response.text}")
    return None

def get_analysis(report_id):
    response = requests.get(f"{API_URL}/{report_id}", headers=headers)
    print(f"[get_analysis] Status: {response.status_code}, Report-ID: {report_id}")
    if response.status_code == 200:
        return response.json()["data"]["attributes"]["last_analysis_stats"]
    print(f"[get_analysis] Fehlerhafte Antwort: {response.text}")
    return None


with open("C:/Users/NB-Alex/IdeaProjects/checkURLwithVirusTotal/src/Web-Base-Links-29-03.csv", newline="") as csvfile:
    reader = csv.reader(csvfile)
    next(reader)  # Überspringt die Kopfzeile
    for _, url in reader:
        report_id = scan_url(url)
        if report_id:
            time.sleep(15)  # API-Limit beachten
            result = get_analysis(report_id)
            print(f"{url}: {result}")
