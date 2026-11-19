# Pyne

Nessus parser written in Python with config files for easy setup and usage.

Written by [Oliver Scotten](https://www.github.com/oliv10).

### Requirements
- Python 3.10.4 or greater

### Configuration
- HOST.conf - Data about Host Device
- REPORT.conf - Data about Findings
- SORT.conf - Order in which data is shown in output CSV file

If making changes to the configuration files, make sure to re-install the application using pip to make sure the new configurations are applied.

### Usage
- Install requirements
```
pip3 install .
```

Run the command ```pyne``` anywhere!

```
usage: pyne [-h] [-o OUT] [-s] [-v] [-F] [-C] [-U] [-k] nessusFiles [nessusFiles ...]

 ______                   
(_____ \                  
 _____) )   _ ____   ____ 
|  ____/ | | |  _ \ / _  )
| |    | |_| | | | ( (/ / 
|_|     \__  |_| |_|\____)
       (____/             

Pyne
2.1.0

     Pyne is a .nessus file parser.

     It can be used in two different ways.
     It can create multiple CSV output files for every .nessus file input, or it can create one CSV output file from all the .nessus files.

     This is specified through the '-o/--out' flag.
     Without using this flag every .nessus file will have an output of the same name and location as the original with .csv appended to the end.
     With this flag all the .nessus files will be combined into one CSV output at your desired name and location.

     The '-C/--Category' flag will add a category to each finding based on Hoplite Consultings standards.
     The '-k/--KEV' flag will enrich findings with Known Exploited Vulnerabilities (KEV) data from CISA/VulnCheck.
     

positional arguments:
  nessusFiles        .nessus file or files or directory of nessus files

options:
  -h, --help         show this help message and exit
  -o OUT, --out OUT  single output file location
  -s, --sort         sort keys alphabetically
  -v, --verbose      verbose error messaging
  -F, --Force        force file write
  -C, --Category     add category to each finding
  -U, --UID          add unique id to each finding
  -k, --KEV          enrich with Known Exploited Vulnerabilities (KEV) data
```

### KEV Enrichment

The `-k/--KEV` flag enriches scan results with [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) data and optionally [VulnCheck KEV](https://vulncheck.com/kev) for more comprehensive coverage.

**What it adds:**

When using `-k`, eight columns are added to the CSV output:
- `in_kev` - Yes/No indicating if any CVE in the finding is actively exploited
- `kev_date_added` - Date added to KEV catalog
- `kev_vulnerability_name` - KEV catalog description
- `kev_required_action` - CISA remediation guidance
- `kev_due_date` - Federal agency deadline
- `kev_source` - Data source (CISA or VulnCheck)
- `kev_ransomware_use` - Known ransomware campaign usage
- `kev_notes` - Additional context

**Note:** KEV columns are only added when `-k` flag is used. Without `-k`, output is identical to previous versions.

**VulnCheck API (Optional):**

For more comprehensive KEV data, configure a VulnCheck API key:

```bash
# Option 1: Config file (create local copy)
echo "VULNCHECK_API_KEY=your_key_here" > pyne/config/KEV.conf.local

# Option 2: Environment variable
export VULNCHECK_API_KEY="your_key_here"
```

Get a free API key at: https://vulncheck.com

Without an API key, Pyne automatically falls back to the free CISA KEV catalog.

**Example:**

```bash
$ pyne internal_scan.nessus -k -o report.csv

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
