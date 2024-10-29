import requests
from tqdm import tqdm
import time

domain = "google.com"
RED = "\033[91m"
GREEN = "\033[92m"
RESET = "\033[0m"

def check_spamhaus(domain):
    spamhaus_url = f"https://check.spamhaus.org/listed/{domain}"
    response = requests.get(spamhaus_url)
    if "is listed" not in response.text:
        return 50, "Spamhaus: Domain is not blacklisted."
    else:
        return 0, "Spamhaus: Domain is blacklisted."

def check_talos(domain):
    talos_url = f"https://talosintelligence.com/sb_api/query_lookup?query_type=domain&query_entry={domain}"
    response = requests.get(talos_url)
    if "Neutral" in response.text:
        return 50, "Cisco Talos: Domain has a neutral reputation."
    elif "Unclassified" in response.text:
        return 25, "Cisco Talos: Domain is unclassified."
    else:
        return 10, "Cisco Talos: Domain may have a flagged reputation."

def check_virustotal(domain, api_key):
    vt_url = "https://www.virustotal.com/vtapi/v2/domain/report"
    params = {'apikey': api_key, 'domain': domain}
    response = requests.get(vt_url, params=params).json()
    if response.get("positives", 0) > 0:
        return 10, "VirusTotal: Domain has been flagged."
    else:
        return 50, "VirusTotal: Domain is clean."

def check_abuseipdb(domain, api_key):
    abuse_url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        'Key': api_key,
        'Accept': 'application/json'
    }
    params = {'ipAddress': domain}
    response = requests.get(abuse_url, headers=headers, params=params).json()
    if response.get("data", {}).get("abuseConfidenceScore", 0) > 0:
        return 10, "AbuseIPDB: Domain has abuse reports."
    else:
        return 50, "AbuseIPDB: Domain is clean."

def check_sucuri(domain):
    sucuri_url = f"https://sitecheck.sucuri.net/api/scan/{domain}"
    response = requests.get(sucuri_url).json()
    if response.get("status") == "error":
        return 0, "Sucuri: Unable to retrieve information."
    elif response.get("data", {}).get("is_blacklisted"):
        return 0, "Sucuri: Domain is blacklisted."
    else:
        return 50, "Sucuri: Domain is clean."

def check_fortiguard(domain):
    fortiguard_url = f"https://fortiguard.com/webfilter?q={domain}"
    response = requests.get(fortiguard_url)
    if "This domain is categorized as Malicious Websites" in response.text:
        return 10, "FortiGuard: Domain is categorized as malicious."
    else:
        return 50, "FortiGuard: Domain is not flagged."

def check_trendmicro(domain):
    trendmicro_url = f"https://global.sitesafety.trendmicro.com/result.php?url={domain}"
    response = requests.get(trendmicro_url)
    if "Dangerous" in response.text or "Highly Suspicious" in response.text:
        return 10, "Trend Micro: Domain is flagged."
    else:
        return 50, "Trend Micro: Domain is not flagged."

def check_openphish(domain):
    openphish_url = "https://openphish.com/feed.txt"
    response = requests.get(openphish_url)
    if domain in response.text:
        return 10, "OpenPhish: Domain is flagged as a phishing site."
    else:
        return 50, "OpenPhish: Domain is not flagged."

virus_total_api_key = "2c78a6e08525b151076dbb4f2dd3add43152b723384b9a3948293779cd8ce88c"
abuseipdb_api_key = "3370a7e621783f95e7b2dde4dc8d83319fb124472ffad9fc7dc5678ef390dc2a35c83255f25f6d30"

checks = [
    ("Spamhaus", lambda: check_spamhaus(domain)),
    ("Cisco Talos", lambda: check_talos(domain)),
    ("VirusTotal", lambda: check_virustotal(domain, virus_total_api_key)),
    ("AbuseIPDB", lambda: check_abuseipdb(domain, abuseipdb_api_key)),
    ("Sucuri", lambda: check_sucuri(domain)),
    ("FortiGuard", lambda: check_fortiguard(domain)),
    ("Trend Micro", lambda: check_trendmicro(domain)),
    ("OpenPhish", lambda: check_openphish(domain))
]

total_score = 0
report = []
flagged = False 

# loading
for name, func in tqdm(checks, desc="Checking domain reputation", ascii=True, ncols=75):
    score, message = func()
    total_score += score
    report.append((name, message))
    if score < 50:  
        flagged = True
    time.sleep(0.5)

average_score = total_score / len(checks)

if flagged:
    print("\nDetailed Report:")
    print("\n --------------------------------------------------")
    print(f"Overall Domain Reputation Score: {average_score}%")
    print("\n --------------------------------------------------")
    for name, message in report:
        if "not blacklisted" in message or "not flagged" in message or "not malicious" in message or "Domain is clean" in message:
           print(f"{GREEN}- {name}: {message}{RESET}")
        else:
            print(f"{RED}- {name}: {message}{RESET}")
