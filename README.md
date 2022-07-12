# Pyne

Nessus parser written in Python with config files for easy setup and usage.

Written by [Oliver Scotten](https://www.github.com/oliv10).

### Requirements
- Python 3.10.4 or greater

### Configuration
- HOST.conf - Data about Host Device
- REPORT.conf - Data about Findings
- SORT.conf - Order in which data is shown in output CSV file

### Usage
- Install requirements
```
pip3 install -r requirements.txt
```

```
usage: pyne.py [-h] [-w] [-s] [-f] [-v] [-S] nessusFiles [nessusFiles ...]

Pyne 1.1.1

positional arguments:
nessusFiles

options:
-h, --help         show this help message and exit
-w , --writeFile   path to write file
-s, --sort         sort keys alphabetically
-f, --force        force overwrite of file
-v, --verbose
-S, --SlowMode
```