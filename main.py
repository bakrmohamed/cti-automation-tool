import csv
import ipaddress
import os
import time
from pathlib import Path
from typing import Any, Dict, Optional

import requests


BASE_DIR = Path(__file__).resolve().parent
ABUSEIPDB_ENDPOINT = "https://api.abuseipdb.com/api/v2/check"
REQUEST_TIMEOUT = (5, 15)
MAX_ATTEMPTS = 3
ABUSE_THRESHOLD = 50


def setup_configuration():
    """إذا لم يكن ملف .env موجوداً، اطلب من المستخدم إدخال البيانات تفاعلياً"""
    env_path = BASE_DIR / ".env"
    if not load_env_file().get("ABUSEIPDB_API_KEY", "").strip():
        print("\n[!] Setup Wizard: No configuration found.")
        api_key = input("[?] Enter your AbuseIPDB API Key: ").strip()
        if not api_key:
            print("[!] An API key is required to run the scan.")
            return

        tg_token = input("[?] Enter your Telegram Bot Token (or press Enter to skip): ").strip()
        tg_chat = input("[?] Enter your Telegram Chat ID (or press Enter to skip): ").strip() if tg_token else ""

        with env_path.open("w", encoding="utf-8") as f:
            f.write(f"ABUSEIPDB_API_KEY={api_key}\n")
            f.write(f"TELEGRAM_BOT_TOKEN={tg_token}\n")
            f.write(f"TELEGRAM_CHAT_ID={tg_chat}\n")
        print("[+] Configuration saved successfully to .env!\n")


def setup_ip_list():
    """إذا لم يكن ملف الـ IPs موجوداً، اطلب من المستخدم إدخالها"""
    input_file = BASE_DIR / "ips_to_check.txt"
    if not input_file.exists():
        print("\n[!] Input file 'ips_to_check.txt' not found.")
        print("Please enter the IPs you want to check (separated by spaces or enter one by one).")
        raw_ips = input("[?] Enter IPs (e.g. 8.8.8.8 1.1.1.1): ").strip()
        
        ip_array = raw_ips.split() if raw_ips else ["8.8.8.8", "1.1.1.1"]
        
        with input_file.open("w", encoding="utf-8") as f:
            for ip in ip_array:
                f.write(f"{ip}\n")
        print(f"[+] Created '{input_file}' with your entered IPs.\n")


def load_env_file():
    """قراءة يدوية لملف .env بدون الحاجة لمكتبة python-dotenv إضافية لتكون الأداة أسرع"""
    env_vars = {}
    env_path = BASE_DIR / ".env"
    if env_path.exists():
        with env_path.open("r", encoding="utf-8-sig") as f:
            for line in f:
                line = line.strip()
                if "=" in line and not line.startswith("#"):
                    key, value = line.split("=", 1)
                    env_vars[key.strip()] = value.strip().strip("\"'")
    env_vars.update({key: value for key, value in os.environ.items() if value})
    return env_vars


def query_abuseipdb(ip: str, api_key: str) -> Optional[Dict[str, Any]]:
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    headers = {"Accept": "application/json", "Key": api_key}

    for attempt in range(MAX_ATTEMPTS):
        try:
            res = requests.get(
                ABUSEIPDB_ENDPOINT,
                headers=headers,
                params=params,
                timeout=REQUEST_TIMEOUT,
            )
        except requests.exceptions.RequestException as err:
            if attempt < MAX_ATTEMPTS - 1:
                time.sleep(2 ** attempt)
                continue
            print(f"[x] Request failed for {ip}: {err.__class__.__name__}")
            return None

        if res.status_code == 200:
            try:
                response_data = res.json()
            except ValueError:
                print(f"[!] Invalid JSON response from AbuseIPDB for {ip}.")
                return None
            info = response_data.get("data") if isinstance(response_data, dict) else None
            if not isinstance(info, dict):
                print(f"[!] Unexpected response format from AbuseIPDB for {ip}.")
                return None
            try:
                abuse_score = int(info["abuseConfidenceScore"])
            except (KeyError, TypeError, ValueError):
                print(f"[!] AbuseIPDB response has no valid score for {ip}.")
                return None
            if not 0 <= abuse_score <= 100:
                print(f"[!] AbuseIPDB returned an out-of-range score for {ip}.")
                return None
            return {
                "IP": ip,
                "Abuse_Score": abuse_score,
                "Country": info.get("countryCode") or "XX",
                "Usage_Type": info.get("usageType") or "Unknown",
            }

        if res.status_code == 429 or 500 <= res.status_code < 600:
            if attempt < MAX_ATTEMPTS - 1:
                retry_after = res.headers.get("Retry-After", "")
                try:
                    delay = min(max(int(retry_after), 1), 30)
                except ValueError:
                    delay = 2 ** attempt
                time.sleep(delay)
                continue

        print(
            f"[!] AbuseIPDB returned status {res.status_code} for {ip}: "
            f"{res.text[:200]}"
        )
        return None

    return None


def push_telegram_alert(data: Dict[str, Any], token: str, chat_id: str) -> bool:
    if not token or not chat_id:
        return False

    text = (
        f"SOC Alert: High Risk IP\n\n"
        f"IP: {data['IP']}\n"
        f"Score: {data['Abuse_Score']}%\n"
        f"Country: {data['Country']}\n"
        f"Type: {data['Usage_Type']}"
    )

    api_url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = {"chat_id": chat_id, "text": text}

    try:
        response = requests.post(api_url, json=payload, timeout=REQUEST_TIMEOUT)
    except requests.exceptions.RequestException as err:
        print(f"[!] Telegram alert request failed: {err.__class__.__name__}.")
        return False

    if not response.ok:
        print(f"[!] Telegram returned status {response.status_code}: {response.text[:200]}")
        return False
    try:
        telegram_result = response.json()
    except ValueError:
        print("[!] Telegram returned an invalid JSON response.")
        return False
    if not isinstance(telegram_result, dict) or not telegram_result.get("ok", False):
        print("[!] Telegram did not accept the alert.")
        return False
    return True


def main():
    print("=" * 45)
    print("   🛡️ Automated CTI Tool for SOC Analysts   ")
    print("=" * 45)
    
    # 1. فحص وضبط ملف الإعدادات والـ API Keys تفاعلياً
    setup_configuration()
    
    # 2. فحص وضبط ملف الـ IPs تفاعلياً
    setup_ip_list()
    
    env = load_env_file()
    api_key = env.get("ABUSEIPDB_API_KEY", "").strip()
    tg_token = env.get("TELEGRAM_BOT_TOKEN", "").strip()
    tg_chat = env.get("TELEGRAM_CHAT_ID", "").strip()

    if not api_key:
        print("[x] ABUSEIPDB_API_KEY is missing. Add it to .env or set it as an environment variable.")
        return
    
    source_file = BASE_DIR / "ips_to_check.txt"
    report_file = BASE_DIR / "security_report.csv"
    
    with source_file.open("r", encoding="utf-8") as file:
        ips = [
            line.strip()
            for line in file
            if line.strip() and not line.lstrip().startswith("#")
        ]

    scanned_data = []
    fields = ["IP", "Abuse_Score", "Country", "Usage_Type", "Verdict", "Error"]
    invalid_count = 0
    failed_count = 0
    alert_count = 0

    print(f"\n[*] Starting scan on {len(ips)} IP(s)...\n")
    
    for ip in ips:
        print(f"[*] Analyzing: {ip}...")
        try:
            ip = str(ipaddress.ip_address(ip))
        except ValueError:
            print(f"[!] Invalid IP address: {ip}")
            invalid_count += 1
            scanned_data.append({
                "IP": ip,
                "Verdict": "Invalid",
                "Error": "Invalid IP address",
            })
            continue

        result = query_abuseipdb(ip, api_key)
        
        if result:
            result["Verdict"] = "Review" if result["Abuse_Score"] > ABUSE_THRESHOLD else "No alert"
            scanned_data.append(result)
            
            if result["Abuse_Score"] > ABUSE_THRESHOLD:
                alert_count += 1
                push_telegram_alert(result, tg_token, tg_chat)
        else:
            failed_count += 1
            scanned_data.append({
                "IP": ip,
                "Verdict": "Error",
                "Error": "AbuseIPDB request failed; see console output",
            })
        
    with report_file.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=fields)
        writer.writeheader()
        writer.writerows(scanned_data)

    print(
        f"\n[+] Scan completed. Results: {len(scanned_data)}, "
        f"invalid IPs: {invalid_count}, failed lookups: {failed_count}, "
        f"high-risk IPs: {alert_count}."
    )
    print(f"[+] Report generated: '{report_file}'.")

if __name__ == "__main__":
    main()
