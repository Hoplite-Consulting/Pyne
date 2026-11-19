"""
KEV Enrichment Module for Pyne

Enriches Nessus vulnerability data with VulnCheck/CISA KEV information.
"""

import json
import re
import urllib.request
from datetime import datetime
import os
from pathlib import Path

# VulnCheck KEV API (preferred)
VULNCHECK_KEV_URL = "https://api.vulncheck.com/v3/backup/vulncheck-kev"
VULNCHECK_CACHE_FILE = "/tmp/vulncheck_kev_cache.json"

# CISA KEV catalog URL (fallback)
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CISA_KEV_CACHE_FILE = "/tmp/cisa_kev_cache.json"

KEV_CACHE_MAX_AGE = 86400  # 24 hours in seconds


def read_kev_config(config_path: str) -> str:
    """Read VulnCheck API key from KEV.conf file."""
    # Try .local version first (not in git)
    local_config = config_path.replace('.conf', '.conf.local')

    for path in [local_config, config_path]:
        try:
            with open(path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line.startswith('VULNCHECK_API_KEY='):
                        api_key = line.split('=', 1)[1].strip()
                        # Remove quotes if present
                        api_key = api_key.strip('"').strip("'")
                        if api_key and api_key != '' and not api_key.startswith('your_'):
                            return api_key
        except Exception:
            continue

    # Check environment variable
    return os.environ.get('VULNCHECK_API_KEY')


def download_vulncheck_kev(api_key: str) -> tuple:
    """Download VulnCheck KEV data using API key."""
    try:
        req = urllib.request.Request(VULNCHECK_KEV_URL)
        req.add_header('Authorization', f'Bearer {api_key}')
        req.add_header('Accept', 'application/json')

        with urllib.request.urlopen(req, timeout=30) as response:
            data = json.loads(response.read().decode())

        # Cache the data
        with open(VULNCHECK_CACHE_FILE, 'w') as f:
            json.dump(data, f)

        vuln_count = len(data.get('data', []))
        return data, 'vulncheck', vuln_count

    except urllib.error.HTTPError as e:
        if e.code == 401:
            print(f"[!] VulnCheck API authentication failed (check API key in config/KEV.conf)")
        else:
            print(f"[!] VulnCheck API error: HTTP {e.code}")
        return None, None, 0

    except Exception as e:
        print(f"[!] Warning: Failed to download VulnCheck KEV: {e}")
        return None, None, 0


def download_cisa_kev() -> tuple:
    """Download CISA KEV catalog (fallback)."""
    try:
        with urllib.request.urlopen(CISA_KEV_URL, timeout=30) as response:
            data = json.loads(response.read().decode())

        # Cache the data
        with open(CISA_KEV_CACHE_FILE, 'w') as f:
            json.dump(data, f)

        return data, 'cisa', data.get('count', 0)

    except Exception as e:
        print(f"[!] Warning: Failed to download CISA KEV: {e}")
        return None, None, 0


def get_kev_catalog(config_path: str) -> tuple:
    """Get KEV catalog, using cache if recent enough."""
    api_key = read_kev_config(config_path)

    # Try VulnCheck first if API key is available
    if api_key:
        # Check cache
        if os.path.exists(VULNCHECK_CACHE_FILE):
            cache_age = datetime.now().timestamp() - os.path.getmtime(VULNCHECK_CACHE_FILE)
            if cache_age < KEV_CACHE_MAX_AGE:
                print(f"[*] Using cached VulnCheck KEV (age: {cache_age/3600:.1f}h)")
                with open(VULNCHECK_CACHE_FILE, 'r') as f:
                    data = json.load(f)
                    return data, 'vulncheck', len(data.get('data', []))

        # Download fresh data
        print("[*] Downloading VulnCheck KEV catalog...")
        data, source, count = download_vulncheck_kev(api_key)
        if data:
            return data, source, count

        print("[!] VulnCheck API failed, falling back to CISA KEV...")

    else:
        print("[*] No VulnCheck API key found, using CISA KEV")
        print("    Tip: Add API key to pyne/config/KEV.conf for comprehensive data")

    # Fall back to CISA KEV
    if os.path.exists(CISA_KEV_CACHE_FILE):
        cache_age = datetime.now().timestamp() - os.path.getmtime(CISA_KEV_CACHE_FILE)
        if cache_age < KEV_CACHE_MAX_AGE:
            print(f"[*] Using cached CISA KEV (age: {cache_age/3600:.1f}h)")
            with open(CISA_KEV_CACHE_FILE, 'r') as f:
                data = json.load(f)
                return data, 'cisa', data.get('count', 0)

    print("[*] Downloading CISA KEV catalog...")
    data, source, count = download_cisa_kev()
    if data:
        return data, source, count

    # Try to use any cached version as last resort
    if os.path.exists(VULNCHECK_CACHE_FILE):
        print("[*] Using stale VulnCheck cache as fallback...")
        with open(VULNCHECK_CACHE_FILE, 'r') as f:
            data = json.load(f)
            return data, 'vulncheck', len(data.get('data', []))

    if os.path.exists(CISA_KEV_CACHE_FILE):
        print("[*] Using stale CISA cache as fallback...")
        with open(CISA_KEV_CACHE_FILE, 'r') as f:
            data = json.load(f)
            return data, 'cisa', data.get('count', 0)

    print("[!] ERROR: No KEV data available")
    return None, None, 0


def build_vulncheck_lookup(kev_data: dict) -> dict:
    """Build CVE -> KEV details lookup from VulnCheck format."""
    lookup = {}

    for vuln in kev_data.get('data', []):
        cve_id = vuln.get('cve', '').upper()
        if not cve_id:
            continue

        lookup[cve_id] = {
            'dateAdded': vuln.get('date_added', ''),
            'vulnerabilityName': vuln.get('name', ''),
            'requiredAction': vuln.get('required_action', ''),
            'dueDate': vuln.get('due_date', ''),
            'notes': vuln.get('notes', ''),
            'source': vuln.get('source', 'VulnCheck'),
            'knownRansomware': vuln.get('known_ransomware_campaign_use', False),
        }

    return lookup


def build_cisa_lookup(kev_data: dict) -> dict:
    """Build CVE -> KEV details lookup from CISA format."""
    lookup = {}

    for vuln in kev_data.get('vulnerabilities', []):
        cve_id = vuln.get('cveID', '').upper()
        if not cve_id:
            continue

        lookup[cve_id] = {
            'dateAdded': vuln.get('dateAdded', ''),
            'vulnerabilityName': vuln.get('vulnerabilityName', ''),
            'requiredAction': vuln.get('requiredAction', ''),
            'dueDate': vuln.get('dueDate', ''),
            'notes': vuln.get('notes', ''),
            'source': 'CISA',
            'knownRansomware': vuln.get('knownRansomwareCampaignUse', 'Unknown') == 'Known',
        }

    return lookup


def extract_cves_from_text(text: str) -> list:
    """Extract CVE identifiers from text."""
    if not text or not isinstance(text, str):
        return []

    # Match CVE-YYYY-NNNNN+ format (case insensitive)
    cve_pattern = re.compile(r'CVE-\d{4}-\d+', re.IGNORECASE)
    cves = cve_pattern.findall(text)

    # Normalize to uppercase and deduplicate
    return list(set(cve.upper() for cve in cves))


def enrich_finding_with_kev(finding: dict, kev_lookup: dict) -> dict:
    """Enrich a single finding with KEV data."""
    # Extract CVEs from the 'cve' field if present
    cve_list = []
    if 'cve' in finding and finding['cve']:
        cve_list = extract_cves_from_text(finding['cve'])

    # Also check plugin name and description
    if 'pluginName' in finding:
        cve_list.extend(extract_cves_from_text(finding['pluginName']))
    if 'description' in finding:
        cve_list.extend(extract_cves_from_text(finding['description']))

    # Deduplicate
    cve_list = list(set(cve_list))

    # Check if any CVE is in KEV
    kev_matches = []
    for cve in cve_list:
        if cve in kev_lookup:
            kev_matches.append((cve, kev_lookup[cve]))

    # Add KEV fields to finding
    if not kev_matches:
        finding['in_kev'] = 'No'
        finding['kev_date_added'] = ''
        finding['kev_vulnerability_name'] = ''
        finding['kev_required_action'] = ''
        finding['kev_due_date'] = ''
        finding['kev_source'] = ''
        finding['kev_ransomware_use'] = ''
        finding['kev_notes'] = ''
    elif len(kev_matches) == 1:
        cve, details = kev_matches[0]
        finding['in_kev'] = 'Yes'
        finding['kev_date_added'] = details['dateAdded']
        finding['kev_vulnerability_name'] = details['vulnerabilityName']
        finding['kev_required_action'] = details['requiredAction']
        finding['kev_due_date'] = details['dueDate']
        finding['kev_source'] = details['source']
        finding['kev_ransomware_use'] = 'Yes' if details['knownRansomware'] else 'No'
        finding['kev_notes'] = details['notes']
    else:
        # Multiple KEV matches
        ransomware_any = any(d['knownRansomware'] for _, d in kev_matches)

        finding['in_kev'] = f'Yes ({len(kev_matches)} CVEs)'
        finding['kev_date_added'] = ' | '.join([d['dateAdded'] for _, d in kev_matches])
        finding['kev_vulnerability_name'] = ' | '.join([f"{c}: {d['vulnerabilityName']}" for c, d in kev_matches])
        finding['kev_required_action'] = ' | '.join([d['requiredAction'] for _, d in kev_matches])
        finding['kev_due_date'] = ' | '.join([d['dueDate'] for _, d in kev_matches])
        finding['kev_source'] = ' | '.join([d['source'] for _, d in kev_matches])
        finding['kev_ransomware_use'] = 'Yes' if ransomware_any else 'No'
        finding['kev_notes'] = ' | '.join([d['notes'] for _, d in kev_matches if d['notes']])

    return finding


def enrich_reports_with_kev(reports: list, config_path: str) -> tuple:
    """Enrich all reports with KEV data."""
    print("\n[*] KEV Enrichment Starting...")

    # Get KEV catalog
    kev_data, source, count = get_kev_catalog(config_path)

    if not kev_data:
        print("[!] ERROR: Could not load KEV data, skipping enrichment")
        return reports, 0, 0

    print(f"[+] Loaded {count} KEV entries from {source.upper()}")

    # Build lookup dictionary
    if source == 'vulncheck':
        kev_lookup = build_vulncheck_lookup(kev_data)
    else:
        kev_lookup = build_cisa_lookup(kev_data)

    # Enrich each finding
    kev_matches = 0
    ransomware_matches = 0

    for report in reports:
        enrich_finding_with_kev(report, kev_lookup)

        if report.get('in_kev', 'No').startswith('Yes'):
            kev_matches += 1
            if report.get('kev_ransomware_use') == 'Yes':
                ransomware_matches += 1

    print(f"[+] KEV Enrichment Complete!")
    print(f"    Total findings: {len(reports)}")
    print(f"    KEV matches: {kev_matches} ({kev_matches/len(reports)*100:.1f}%)")
    if ransomware_matches > 0:
        print(f"    ⚠️  Ransomware-linked: {ransomware_matches}")
    print(f"    Data source: {source.upper()}\n")

    return reports, kev_matches, ransomware_matches
