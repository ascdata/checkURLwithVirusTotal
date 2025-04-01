import requests
import csv
import time
import base64
import os

# --- VirusTotal API configuration ---
try:
    with open("apikey.txt", "r") as f:
        API_KEY = f.read().strip()
except FileNotFoundError:
    raise RuntimeError("API key file not found. Please create 'apikey.txt'.")

API_URL = "https://www.virustotal.com/api/v3/urls"

# Set up headers with API key for all requests
headers = {
    "x-apikey": API_KEY,
    "Content-Type": "application/x-www-form-urlencoded"
}

# --- Submit a URL to VirusTotal for scanning ---
def scan_url(url):
    response = requests.post(API_URL, headers=headers, data={"url": url})
    print(f"[scan_url] Status: {response.status_code}, URL: {url}")

    # Return True if submission was successful
    if response.status_code == 200:
        return True

    # Print error if submission failed
    print(f"[scan_url] Error response: {response.text}")
    return False

# --- Retrieve the analysis result for a submitted URL using its base64-encoded ID ---
def get_analysis_by_url(url, retries=3, wait_seconds=15):
    # Remove protocol and encode the URL to URL-safe base64 (without padding)
    url_no_proto = url.replace("https://", "").replace("http://", "")
    url_id = base64.urlsafe_b64encode(url_no_proto.encode()).decode().strip("=")

    # Try multiple times if the result is not yet available
    for attempt in range(1, retries + 1):
        response = requests.get(f"{API_URL}/{url_id}", headers=headers)
        print(f"[get_analysis] Attempt {attempt}, Status: {response.status_code}, Encoded URL ID: {url_id}")

        if response.status_code == 200:
            # Return the result if successful
            return response.json()["data"]["attributes"]["last_analysis_stats"]
        elif response.status_code == 404:
            # If result not yet available, wait and retry
            print("[get_analysis] Not found yet, retrying...")
            time.sleep(wait_seconds)
        else:
            # Stop retrying on unexpected error
            print(f"[get_analysis] Error response: {response.text}")
            break

    return None  # All retries failed

# --- File paths for input and output ---
input_file = "C:/Users/NB-Alex/IdeaProjects/checkURLwithVirusTotal/src/Web-Base-Links-29-03.csv"
results_file = "C:/Users/NB-Alex/IdeaProjects/checkURLwithVirusTotal/src/scan_results.csv"
failed_file = "C:/Users/NB-Alex/IdeaProjects/checkURLwithVirusTotal/src/failed_scans.csv"

# --- Load already scanned URLs from previous runs ---
scanned_urls = set()
if os.path.exists(results_file):
    with open(results_file, newline="") as f:
        reader = csv.reader(f)
        next(reader)  # Skip header
        for row in reader:
            if row and row[0]:
                scanned_urls.add(row[0].strip())

# --- Create output files with header if they do not exist yet ---
if not os.path.exists(results_file):
    with open(results_file, mode="w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["url", "harmless", "suspicious", "malicious", "undetected"])

if not os.path.exists(failed_file):
    with open(failed_file, mode="w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["url", "reason"])

# --- Start processing the input file ---
with open(results_file, mode="a", newline="") as results_out, \
        open(failed_file, mode="a", newline="") as failed_out, \
        open(input_file, newline="") as csvfile:

    result_writer = csv.writer(results_out)
    failed_writer = csv.writer(failed_out)
    reader = csv.reader(csvfile)
    next(reader)  # Skip CSV header row

    for row in reader:
        if not row:
            continue

        # Get the URL (supporting both 1-column or 2-column CSVs)
        url = row[0] if len(row) == 1 else row[1]
        url = url.strip()

        # Skip URL if it was already processed
        if url in scanned_urls:
            print(f"Skipping already scanned URL: {url}")
            continue

        print(f"\nProcessing URL: {url}")
        success = scan_url(url)

        if success:
            # Wait before analysis to allow VirusTotal to process the scan
            time.sleep(15)
            result = get_analysis_by_url(url)

            if result:
                print(f"Analysis for {url}: harmless={result['harmless']}, "
                      f"suspicious={result['suspicious']}, "
                      f"malicious={result['malicious']}, "
                      f"undetected={result['undetected']}")
                result_writer.writerow([
                    url,
                    result['harmless'],
                    result['suspicious'],
                    result['malicious'],
                    result['undetected']
                ])
            else:
                print(f"No analysis result for {url}")
                failed_writer.writerow([url, "No analysis result"])
        else:
            print(f"Scan failed for {url}")
            failed_writer.writerow([url, "Scan request failed"])
