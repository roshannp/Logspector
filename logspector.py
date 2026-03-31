import argparse
import re
import requests
import time
import ipaddress
import whois
import pandas as pd
from urllib.parse import urlparse

STANDARD_PORTS = {20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3389, 5985}
SUSPICIOUS_PORTS = {22, 21, 3389, 5985}
INTERNAL_RANGES = [
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16")
]

def is_non_standard_port(port):
    try:
        return int(port) not in STANDARD_PORTS
    except:
        return False

def is_internal_ip(ip):
    try:
        ip_obj = ipaddress.IPv4Address(ip)
        return any(ip_obj in net for net in INTERNAL_RANGES)
    except ValueError:
        return False

def enrich_ip(ip):
    try:
        r = requests.get(f"https://ipinfo.io/{ip}/json")
        if r.status_code == 200:
            return r.json()
    except Exception as e:
        return {"error": str(e)}

def enrich_hash_virustotal(hash_value, api_key):
    try:
        headers = {"x-apikey": api_key}
        url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            score = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return score
        else:
            return {"error": f"VT status {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}

def enrich_domain_whois(domain):
    try:
        domain_info = whois.whois(domain)
        return {
            "registrar": domain_info.registrar,
            "creation_date": str(domain_info.creation_date),
            "expiration_date": str(domain_info.expiration_date),
            "name_servers": domain_info.name_servers
        }
    except Exception as e:
        return {"error": str(e)}

def extract_indicators(file_path):
    hashes, urls, domains, ips = set(), set(), set(), set()
    binaries = set()
    suspicious_access = []

    hash_pattern = re.compile(r'\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b')
    url_pattern = re.compile(r'https?://[^\s"\'>]+')
    ip_port_pattern = re.compile(r'(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})')
    binary_path_pattern = re.compile(r'([a-zA-Z]:[\\\/][\w\-\\\/\.]+?\.(exe|dll|bat|cmd|ps1|scr|vbs|msi|bin))', re.IGNORECASE)

    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            # Extract IP:Port pairs
            pairs = ip_port_pattern.findall(line)
            for i, (ip1, port1) in enumerate(pairs):
                if is_non_standard_port(port1):
                    ips.add(f"{ip1}:{port1}")
                for j, (ip2, port2) in enumerate(pairs):
                    if i != j and is_internal_ip(ip2) and not is_internal_ip(ip1):
                        if int(port2) in SUSPICIOUS_PORTS:
                            suspicious_access.append({
                                "external_ip": ip1,
                                "internal_ip": ip2,
                                "port": port2,
                                "log_line": line.strip()
                            })
            # Extract URLs and domains
            for url in url_pattern.findall(line):
                parsed = urlparse(url)
                if parsed.port and is_non_standard_port(parsed.port):
                    urls.add(url)
                    if parsed.hostname:
                        domains.add(parsed.hostname)

            # Extract hashes
            if any(pat in line for pat in [":", "http"]):
                hashes.update(hash_pattern.findall(line))

            # Extract binaries
            for binary_path in binary_path_pattern.findall(line):
                binaries.add(binary_path[0])

    return {
        'hashes': list(hashes),
        'urls': list(urls),
        'domains': list(domains),
        'ips': list(ips),
        'binaries': list(binaries),
        'suspicious_access': suspicious_access
    }

def run_logspector(file_path, vt_key):
    indicators = extract_indicators(file_path)
    enriched_data = []

    for ip in indicators["ips"]:
        clean_ip = ip.split(":")[0]
        enrichment = enrich_ip(clean_ip)
        enriched_data.append({
            "type": "ip",
            "value": ip,
            "details": enrichment
        })

    for h in indicators["hashes"]:
        vt_result = enrich_hash_virustotal(h, vt_key)
        enriched_data.append({
            "type": "hash",
            "value": h,
            "details": vt_result
        })
        time.sleep(15)  # Respect VT rate limits

    for url in indicators["urls"]:
        enriched_data.append({
            "type": "url",
            "value": url,
            "details": {}
        })

    for domain in indicators["domains"]:
        whois_result = enrich_domain_whois(domain)
        enriched_data.append({
            "type": "domain",
            "value": domain,
            "details": whois_result
        })

    for binary in indicators["binaries"]:
        enriched_data.append({
            "type": "binary",
            "value": binary,
            "details": {}
        })

    enriched_df = pd.DataFrame(enriched_data)
    suspicious_df = pd.DataFrame(indicators["suspicious_access"])

    enriched_df.to_csv("logspector_enriched_indicators.csv", index=False)
    suspicious_df.to_csv("logspector_suspicious_access.csv", index=False)

    print("\n✅ Logspector finished. Output files created:")
    print(" - logspector_enriched_indicators.csv")
    print(" - logspector_suspicious_access.csv")

def main():
    banner = """
    🔍 Logspector – CLI

    This tool does the following:
    --------------------------------------------------
    ✅ Extracts IOCs: hashes, domains, URLs, IPs, binary paths
    ✅ Detects external access to internal IPs over sensitive ports
    ✅ Enriches with IPinfo, VirusTotal, WHOIS
    ✅ Outputs two CSVs: enriched indicators and suspicious access
    --------------------------------------------------
    """
    print(banner)

    parser = argparse.ArgumentParser(description="Logspector CLI")
    parser.add_argument("logfile", help="Path to the log file to analyze")
    parser.add_argument("--vtkey", required=True, help="VirusTotal API key for hash enrichment")
    args = parser.parse_args()

    run_logspector(args.logfile, args.vtkey)

if __name__ == "__main__":
    main()
