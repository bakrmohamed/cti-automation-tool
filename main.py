import os
import csv
import time
import ipaddress
from pathlib import Path
import requests

BASE_DIR = Path(__file__).resolve().parent
ENDPOINT = "https://api.abuseipdb.com/api/v2/check"
THRESHOLD = 50

def check_setup():
    env_path = BASE_DIR / ".env"
    if not env_path.exists():
        print("[*] .env file not found. Let's create one.")
        api_key = input("Enter your AbuseIPDB API key: ").strip()
        with env_path.open("w", encoding="utf-8") as f:
            f.write(f"ABUSEIPDB_API_KEY={api_key}\n")
        print("[+] Saved .env successfully.")

    ips_path = BASE_DIR / "ips_to_check.txt"
    if not ips_path.exists():
        print("[*] ips_to_check.txt not found. Let's create it.")
        raw_ips = input("Enter IPs separated by space: ").strip()
        ips = raw_ips.split() if raw_ips else ["8.8.8.8"]
        with ips_path.open("w", encoding="utf-8") as f:
            for ip in ips:
                f.write(f"{ip}\n")
        print("[+] ips_to_check.txt created successfully.")

def load_env():
    config = {}
    env_path = BASE_DIR / ".env"
    if env_path.exists():
        with env_path.open("r", encoding="utf-8") as f:
            for line in f:
                if "=" in line and not line.startswith("#"):
                    k, v = line.strip().split("=", 1)
                    config[k.strip()] = v.strip().strip('"\'')
    return config

def check_ip(ip, api_key):
    headers = {"Accept": "application/json", "Key": api_key}
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    
    for _ in range(3):
        try:
            res = requests.get(ENDPOINT, headers=headers, params=params, timeout=10)
            if res.status_code == 200:
                data = res.json().get("data", {})
                return {
                    "IP": ip,
                    "Abuse_Score": data.get("abuseConfidenceScore", 0),
                    "Country": data.get("countryCode", "NA"),
                    "Usage_Type": data.get("usageType", "Unknown")
                }
            elif res.status_code == 429:
                print("[!] Rate limit hit, waiting 15 seconds...")
                time.sleep(15)
                continue
            else:
                print(f"[!] Error status {res.status_code} for IP {ip}")
                return None
        except Exception as err:
            print(f"[x] Connection error on {ip}: {err}")
            time.sleep(2)
    return None

def main():
    print("=== CTI IP Scanner Tool ===")
    check_setup()
    
    config = load_env()
    api_key = config.get("ABUSEIPDB_API_KEY", "")
    if not api_key:
        print("[x] API key is missing.")
        return

    ips_path = BASE_DIR / "ips_to_check.txt"
    report_path = BASE_DIR / "security_report.csv"
    
    with ips_path.open("r", encoding="utf-8") as f:
        ips = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    results = []
    fields = ["IP", "Abuse_Score", "Country", "Usage_Type", "Verdict", "Error"]
    
    print(f"\n[*] Starting scan for {len(ips)} IPs...\n")
    
    for ip in ips:
        print(f"[*] Checking IP: {ip}")
        try:
            ip = str(ipaddress.ip_address(ip))
        except ValueError:
            print(f"[!] Invalid IP format: {ip}")
            results.append({"IP": ip, "Verdict": "Invalid", "Error": "Bad IP format"})
            continue

        info = check_ip(ip, api_key)
        if info:
            info["Verdict"] = "Review" if info["Abuse_Score"] > THRESHOLD else "Safe"
            results.append(info)
        else:
            results.append({"IP": ip, "Verdict": "Error", "Error": "API request failed"})
        
        time.sleep(1)

    with report_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(results)
        
    print(f"\n[+] Scan finished. Report saved to {report_path.name}")

if __name__ == "__main__":
    main()
