# Pyne

A .nessus file parser that converts Nessus scan results to CSV format.

## Installation

```bash
pip3 install -r requirements.txt
pip3 install -e .
```

## Usage

```bash
# Parse single .nessus file
python3 -m pyne scan.nessus

# Parse multiple files into separate CSVs
python3 -m pyne scan1.nessus scan2.nessus scan3.nessus

# Combine multiple scans into one CSV
python3 -m pyne scan1.nessus scan2.nessus -o combined.csv
```

## Flags

- `-o, --out FILE` - Single output file (combines all scans)
- `-C, --Category` - Add category to each finding
- `-U, --UID` - Add unique ID to each finding
- `-k, --KEV` - **NEW:** Enrich with Known Exploited Vulnerabilities data
- `-s, --sort` - Sort keys alphabetically
- `-F, --Force` - Force file write (overwrite existing)
- `-v, --verbose` - Verbose error messaging

## KEV Enrichment (New Feature)

The `-k/--KEV` flag enriches scan results with [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) data and optionally [VulnCheck KEV](https://vulncheck.com/kev) for more comprehensive coverage.

```bash
# Basic KEV enrichment (uses free CISA KEV catalog)
python3 -m pyne scan.nessus -k

# With all features
python3 -m pyne scan.nessus -k -C -U -o output.csv
```

### What KEV Enrichment Adds

When using `-k`, these columns are automatically added to the CSV:

| Column | Description |
|--------|-------------|
| `in_kev` | Yes/No - Is this CVE actively exploited? |
| `kev_date_added` | Date added to KEV catalog |
| `kev_vulnerability_name` | KEV catalog description |
| `kev_required_action` | CISA remediation guidance |
| `kev_due_date` | Federal agency deadline |
| `kev_source` | Data source (CISA or VulnCheck) |
| `kev_ransomware_use` | Known ransomware campaign usage |
| `kev_notes` | Additional context |

**Note:** KEV columns are only added when `-k` flag is used. Without `-k`, output is identical to previous versions.

### VulnCheck API (Optional)

For more comprehensive KEV data (~500 additional CVEs beyond CISA), configure a VulnCheck API key:

```bash
# Option 1: Config file (create local copy)
echo "VULNCHECK_API_KEY=your_key_here" > pyne/config/KEV.conf.local

# Option 2: Environment variable
export VULNCHECK_API_KEY="your_key_here"
```

Get a free API key at: https://vulncheck.com

Without an API key, Pyne automatically falls back to the free CISA KEV catalog (~1,700+ vulnerabilities).

### Example Output

```bash
$ python3 -m pyne internal_scan.nessus -k -o report.csv

[*] Downloading CISA KEV catalog...
[+] Loaded 1,786 KEV entries from CISA

Reading Report... internal_scan.nessus
[*] KEV Enrichment Starting...
[+] KEV Enrichment Complete!
    Total findings: 523
    KEV matches: 47 (9.0%)
    ⚠️  Ransomware-linked: 12

Writing to file... report.csv
```

## Column Customization

Edit `pyne/config/SORT.conf` to control which columns appear and their order in CSV output:

```bash
# Remove a column: delete the line or comment with #
# Reorder columns: move lines up/down (top = leftmost in CSV)
nano pyne/config/SORT.conf
```

## Compatibility

- **Python 3.8+** (tested up to Python 3.14)
- Uses `pathlib.Path` instead of deprecated `pkg_resources` for Python 3.14+ compatibility

## Credits

Original Pyne by [Hoplite Consulting](https://github.com/Hoplite-Consulting/Pyne)

## License

See LICENSE file
