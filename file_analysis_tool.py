import os
import time
import requests
import hashlib
import argparse
import json


# Configuration file path to store API keys
CONFIG_FILE = os.path.expanduser("~/.file_analysis_tool_config")


# ------------------------------- #
# Utility Functions for API Keys #
# ------------------------------- #

def save_api_key(service, api_key):
    """Saves the API key for a given service into a configuration file."""
    config = load_config()
    config[service] = api_key
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f)
    print(f"{service.capitalize()} API key saved for future use.")


def load_api_key(service):
    """Loads the API key for a given service from the configuration file."""
    config = load_config()
    return config.get(service)


def load_config():
    """Loads the configuration file, creating it if it does not exist."""
    if not os.path.exists(CONFIG_FILE):
        return {}
    with open(CONFIG_FILE, "r") as f:
        return json.load(f)


# --------------------------- #
# File Hash Calculation       #
# --------------------------- #

def calculate_file_hash(path):
    """Calculates the SHA256 hash of the given file."""
    try:
        sha256_hash = hashlib.sha256()
        with open(path, "rb") as f:
            # Read file in chunks of 4KB to handle large files efficiently
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except FileNotFoundError:
        raise FileNotFoundError(f"Error: File '{path}' not found.")
    except Exception as e:
        raise RuntimeError(f"Error: {e}")


# --------------------------- #
# VirusTotal API Interaction  #
# --------------------------- #

def query_virustotal(api_key, file_hash, path=None):
    """
    Queries VirusTotal for a file hash. If the file hash is not found, uploads the file for analysis.
    """
    headers = {"x-apikey": api_key}
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"

    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    elif response.status_code == 404 and path:
        print("File not found in VirusTotal. Uploading for analysis...")
        return upload_to_virustotal(api_key, path)
    else:
        raise RuntimeError(f"VirusTotal error: {response.status_code} - {response.text}")


def upload_to_virustotal(api_key, path):
    """
    Uploads a file to VirusTotal for analysis if its hash is not already in the database.
    """
    url = 'https://www.virustotal.com/api/v3/files'
    headers = {"x-apikey": api_key}
    try:
        with open(path, 'rb') as f:
            files = {'file': (path, f)}
            response = requests.post(url, headers=headers, files=files)
        if response.status_code == 200:
            analysis_id = response.json().get('data', {}).get('id')
            return fetch_virustotal_analysis(api_key, analysis_id)
        else:
            raise RuntimeError(f"Error uploading file: {response.status_code} - {response.text}")
    except Exception as e:
        raise RuntimeError(f"Error: {e}")


def fetch_virustotal_analysis(api_key, analysis_id):
    """
    Waits for the completion of VirusTotal analysis and fetches the result using the analysis ID.
    """
    url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    headers = {"x-apikey": api_key}

    while True:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            status = data.get('data', {}).get('attributes', {}).get('status')
            if status == 'completed':
                file_hash = data.get('meta', {}).get('file_info', {}).get('sha256')
                return query_virustotal(api_key, file_hash)
            else:
                print("Analysis in progress, waiting 30 seconds...")
                time.sleep(30)
        else:
            raise RuntimeError(f"Error fetching analysis: {response.status_code} - {response.text}")


def parse_virustotal_result(data):
    """
    Parses the VirusTotal API response to summarize results such as total engines, malicious detections, etc.
    """
    attributes = data.get("data", {}).get("attributes", {})
    last_analysis_results = attributes.get("last_analysis_results", {})

    summary = {
        "Total Engines": len(last_analysis_results),
        "Malicious": sum(
            1 for engine in last_analysis_results.values() if engine.get("category") == "malicious"
        ),
        "Harmless": sum(
            1 for engine in last_analysis_results.values() if engine.get("category") == "harmless"
        ),
        "Suspicious": sum(
            1 for engine in last_analysis_results.values() if engine.get("category") == "suspicious"
        ),
        "Undetected": sum(
            1 for engine in last_analysis_results.values() if engine.get("category") == "undetected"
        ),
        "Details": [
            {
                "Engine": engine_data.get("engine_name", "Unknown"),
                "Category": engine_data.get("category", "Unknown"),
                "Result": engine_data.get("result", "N/A"),
            }
            for engine_data in last_analysis_results.values()
        ],
    }
    return summary


# ------------------------------- #
# MalwareBazaar API Interaction   #
# ------------------------------- #

def query_malwarebazaar(file_hash):
    """Queries MalwareBazaar for file hash information."""
    url = 'https://mb-api.abuse.ch/api/v1/'
    data = {'query': 'get_info', 'hash': file_hash}

    response = requests.post(url, data=data)
    if response.status_code == 200:
        return response.json()
    else:
        raise RuntimeError(f"MalwareBazaar error: {response.status_code} - {response.text}")


def parse_malwarebazaar_result(data):
    """
    Parses the MalwareBazaar API response to extract details about the file, such as signature and tags.
    """
    query_status = data.get('query_status')
    if query_status == 'ok':
        malware_info = data.get('data', [])[0]
        return {
            'SHA256 Hash': malware_info.get('sha256_hash'),
            'MD5 Hash': malware_info.get('md5_hash'),
            'File Type': malware_info.get('file_type'),
            'File Name': malware_info.get('file_name'),
            'Signature': malware_info.get('signature'),
            'First Seen': malware_info.get('first_seen'),
            'Tags': ', '.join(malware_info.get('tags', [])),
            'Download URL': malware_info.get('malware_download_url'),
        }
    elif query_status == 'hash_not_found':
        return {"info": "Hash not found in MalwareBazaar database. This may indicate the file is benign."}
    else:
        raise RuntimeError(f"MalwareBazaar error: {query_status}")


# ------------------------------- #
# Result Display                 #
# ------------------------------- #

def display_results(title, summary):
    """Displays the results in a clean, readable format."""
    print(f"\n{'-' * 10} {title} {'-' * 10}")

    if isinstance(summary, dict):
        for key, value in summary.items():
            if key == "Details":
                print("\nMalicious Detections:")
                malicious_details = [
                    detail for detail in value if detail["Category"] == "malicious"
                ]
                if malicious_details:
                    for detail in malicious_details:
                        print(
                            f"- {detail['Engine']}: {detail['Result'] or 'No specific name'}"
                        )
                else:
                    print("No malicious detections found.")
            else:
                print(f"{key}: {value}")


# ------------------------------- #
# Main Function                  #
# ------------------------------- #

def main():
    parser = argparse.ArgumentParser(description="Automated File/Hash Analysis Tool")
    parser.add_argument("-f", "--file", required=True, help="Path to the file")
    parser.add_argument("-k", "--apikey", help="VirusTotal API key")
    parser.add_argument("--save-keys", action="store_true", help="Save provided API keys for future use")
    parser.add_argument("--tools", nargs="+", choices=['virustotal', 'malwarebazaar'], default=['virustotal'], help="Tools to use (virustotal, malwarebazaar)")
    args = parser.parse_args()

    try:
        # Step 1: Calculate file hash
        file_hash = calculate_file_hash(args.file)
        print(f"Calculated File Hash: {file_hash}")

        # Step 2: VirusTotal Analysis
        vt_api_key = args.apikey or load_api_key("virustotal")
        if not vt_api_key:
            raise RuntimeError("VirusTotal API key is required but not provided.")
        if args.save_keys and args.apikey:
            save_api_key("virustotal", args.apikey)

        if 'virustotal' in args.tools:
            print("\nQuerying VirusTotal...")
            vt_data = query_virustotal(vt_api_key, file_hash, path=args.file)
            vt_result = parse_virustotal_result(vt_data)
            display_results("VirusTotal Results", vt_result)

        # Step 3: MalwareBazaar Analysis
        if 'malwarebazaar' in args.tools:
            print("\nQuerying MalwareBazaar...")
            mb_data = query_malwarebazaar(file_hash)
            mb_result = parse_malwarebazaar_result(mb_data)
            display_results("MalwareBazaar Results", mb_result)

    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    main()
