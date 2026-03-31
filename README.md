# Logspector

CLI tool for extracting, detecting, and enriching security-relevant artifacts from log files.

## Features

- **IOC Extraction**: Hashes (MD5/SHA1/SHA256), IP:Port pairs, domains, URLs, binary paths
- **Suspicious Access Detection**: External IPs hitting internal hosts on sensitive ports (SSH, FTP, RDP, WinRM)
- **Enrichment**: IPinfo (GeoIP/ASN), VirusTotal (hash reputation), WHOIS (domain registration)

## Installation

```bash
python3 -m venv logspector-env
source logspector-env/bin/activate
pip install requests python-whois pandas
```

## Usage

```bash
python logspector.py <logfile> --vtkey <VIRUSTOTAL_API_KEY>
```

### Example

```bash
python logspector.py sample_splunk_mixed.log --vtkey abc123...
```

## Output

| File | Description |
|------|-------------|
| `logspector_enriched_indicators.csv` | All extracted IOCs with enrichment data |
| `logspector_suspicious_access.csv` | External-to-internal access on sensitive ports |

## Detection Logic

**Sensitive ports monitored**: 21 (FTP), 22 (SSH), 3389 (RDP), 5985 (WinRM)

**Internal IP ranges**: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`

## Requirements

- Python 3.x
- VirusTotal API key (free tier works, but rate-limited)
```
