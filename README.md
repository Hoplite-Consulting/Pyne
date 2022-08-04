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
usage: pyne.py [-h] [-s] [-f] [-U] [-S] nessusFiles [nessusFiles ...] writeFile

 ______                   
(_____ \                  
 _____) )   _ ____   ____ 
|  ____/ | | |  _ \ / _  )
| |    | |_| | | | ( (/ / 
|_|     \__  |_| |_|\____)
       (____/             

Pyne 1.1.8

positional arguments:
  nessusFiles     nessus file
  writeFile       path to write file

options:
  -h, --help      show this help message and exit
  -s, --sort      sort keys alphabetically
  -f, --force     force overwrite of write file
  -U, --UID       add unique id to each finding
  -S, --SlowMode  run slowly
```
