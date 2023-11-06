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
pip3 install .
```

Run the command ```pyne``` anywhere!

```
usage: pyne [-h] [-o OUT] [-s] [-v] [-F] [-C] [-U] nessusFiles [nessusFiles ...]

 ______                   
(_____ \                  
 _____) )   _ ____   ____ 
|  ____/ | | |  _ \ / _  )
| |    | |_| | | | ( (/ / 
|_|     \__  |_| |_|\____)
       (____/             

Pyne
2.0.3

     Pyne is a .nessus file parser.

     It can be used in two different ways.
     It can create multiple CSV output files for every .nessus file input, or it can create one CSV output file from all the .nessus files.

     This is specified through the '-o/--out' flag.
     Without using this flag every .nessus file will have an output of the same name and location as the original with .csv appended to the end.
     With this flag all the .nessus files will be combined into one CSV output at your desired name and location.

     The '-C/--Category' flag will add a category to each finding based on Hoplite Consultings standards.
     

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
```