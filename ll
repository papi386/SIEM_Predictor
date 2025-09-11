import requests
import time
import sys
import ipaddress
import re
import math
import pandas as pd
import urllib.parse
from datetime import datetime, timedelta

# ==============================
# CONFIG
# ==============================
QRADAR_HOST = "PUT_HOST"
API_TOKEN = "PUT_API_TOKEN"
API_VERSION = "16.0"
OFFENSE_ID_CIBLE = PUT_OFFENSE_ID
SEARCH_WINDOW_MINUTES = 10

# ==============================
# HELPERS
# ==============================
def get_qradar_headers():
    return {"SEC": API_TOKEN, "Version": API_VERSION, "Accept": "application/json"}

def get_offense_details(offense_id):
    url = f"{QRADAR_HOST}/api/siem/offenses/{offense_id}"
    try:
        r = requests.get(url, headers=get_qradar_headers(), verify=False, timeout=60)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        print(f"[!] Could not fetch offense {offense_id}: {e}")
        return None

def run_aql_query(aql_query):
    headers = get_qradar_headers()
    search_endpoint = f"{QRADAR_HOST}/api/ariel/searches"
    try:
        r = requests.post(search_endpoint, headers=headers, params={"query_expression": aql_query}, verify=False, timeout=60)
        r.raise_for_status()
        search_id = r.json().get("search_id")
        if not search_id:
            return None

        status_endpoint = f"{search_endpoint}/{search_id}"
        for _ in range(30):
            time.sleep(2)
            status_r = requests.get(status_endpoint, headers=headers, verify=False, timeout=60)
            status_r.raise_for_status()
            if status_r.json().get("status") == "COMPLETED":
                results_r = requests.get(f"{status_endpoint}/results", headers=headers, verify=False, timeout=60)
                results_r.raise_for_status()
                return results_r.json()
        return None
    except Exception as e:
        print(f"[!] AQL query failed: {e}")
        return None

# ==============================
# FEATURE EXTRACTION
# ==============================
URL_REGEX = re.compile(r"(https?://[^\s\"'<>]+)", re.IGNORECASE)
IP_REGEX = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")

def shannon_entropy(s):
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    probs = [v / len(s) for v in freq.values()]
    return -sum(p * math.log2(p) for p in probs)

def _extract_domain(url):
    try:
        parsed = urllib.parse.urlparse(url)
        netloc = parsed.netloc or parsed.path
        netloc = netloc.split(":")[0]
        if netloc.startswith("www."):
            netloc = netloc[4:]
        return netloc.lower()
    except:
        return url.lower()

def _get_src_ip(event):
    for k in ["src_ip", "sourceip", "srcip", "source_ip", "sourceIP"]:
        if k in event and event[k]:
            return event[k]
    payload = event.get("payload_text", "")
    m = IP_REGEX.search(payload)
    return m.group(0) if m else None

def _get_src_country(event):
    for k in ["srccountry", "src_country", "sourcecountry", "srcCountry"]:
        if k in event and event[k]:
            return event[k]
    return None

def _ip_to_network(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
        if ip.version == 4:
            net = ipaddress.ip_network(f"{ip_str}/24", strict=False)
        else:
            net = ipaddress.ip_network(f"{ip_str}/64", strict=False)
        return str(net)
    except:
        return None

def extract_features(events):
    urls, domains, ips, src_ips = set(), set(), set(), set()
    url_lengths, domain_entropies = [], []
    countries = set()

    for ev in events:
        payload = ev.get("payload_text", "") or ""

        # src_ip
        sip = _get_src_ip(ev)
        if sip:
            src_ips.add(sip)
            ips.add(sip)

        # srccountry
        sc = _get_src_country(ev)
        if sc:
            countries.add(sc)

        # find extra IPs in payload
        for ip in IP_REGEX.findall(payload):
            ips.add(ip)

        # extract URLs
        for url in URL_REGEX.findall(payload):
            url = url.rstrip(".,;:)\"]'")
            urls.add(url)
            url_lengths.append(len(url))
            dom = _extract_domain(url)
            if dom:
                domains.add(dom)
                domain_entropies.append(shannon_entropy(dom))

    # multiple IP ranges?
    networks = set()
    for ip in src_ips:
        n = _ip_to_network(ip)
        if n:
            networks.add(n)
    has_multiple_ip_ranges = len(networks) > 1

    return {
        "num_domains": len(domains),
        "num_ips": len(ips),
        "num_urls": len(urls),
        "avg_domain_entropy": sum(domain_entropies) / len(domain_entropies) if domain_entropies else 0,
        "avg_length_of_urls": sum(url_lengths) / len(url_lengths) if url_lengths else 0,
        "unique_ip_countries": ",".join(sorted(countries)) if countries else "N/A",
        "has_multiple_ip_ranges": has_multiple_ip_ranges,
    }

# ==============================
# MAIN
# ==============================
if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    offense = get_offense_details(OFFENSE_ID_CIBLE)
    if not offense:
        sys.exit(0)

    description = offense.get("description", "N/A").strip()
    start_time_ms = offense.get("start_time")
    offense_source_ip = offense.get("offense_source")

    print("=" * 80)
    print(f"Investigation Offense #{OFFENSE_ID_CIBLE}: {description[:80]}")
    print("=" * 80)

    if not (offense_source_ip and start_time_ms):
        print("[!] Missing IP or start time")
        sys.exit(0)

    start_time = datetime.fromtimestamp(start_time_ms / 1000)
    search_start = (start_time - timedelta(minutes=SEARCH_WINDOW_MINUTES / 2)).strftime("%Y-%m-%d %H:%M:%S")
    search_end = (start_time + timedelta(minutes=SEARCH_WINDOW_MINUTES / 2)).strftime("%Y-%m-%d %H:%M:%S")

    # query events
    aql = (f"SELECT UTF8(payload) as payload_text, sourceip as src_ip, "
           f"srccountry as srccountry FROM events "
           f"WHERE sourceip='{offense_source_ip}' OR destinationip='{offense_source_ip}' "
           f"START '{search_start}' STOP '{search_end}'")
    results = run_aql_query(aql)

    if results and "events" in results and results["events"]:
        features = extract_features(results["events"])
        print("Extracted Features:", features)

        df = pd.DataFrame([features])
        out_name = f"offense_{OFFENSE_ID_CIBLE}_features.csv"
        df.to_csv(out_name, index=False)
        print(f"[+] Saved features to {out_name}")
    else:
        print("[!] No events found in this window.")
