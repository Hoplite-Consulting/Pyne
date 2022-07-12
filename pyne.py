#!/bin/python3

from csv import DictWriter
from src import *
import argparse
import xml.etree.ElementTree as ET
from alive_progress import alive_bar, alive_it
import time
from os.path import exists

# Get Default REPORT.conf
try:
    VARS = []
    with open("config/REPORT.conf", "r") as f:
        lines = f.readlines()
    for l in lines:
        if l[0] == '#':
            continue
        elif l == '':
                continue
        else:
            VARS.append(l.strip())
except:
    print("Failed to read default VARS...")
    VARS = ["description", "solution", "plugin_type", "plugin_output", "cve", "cvss_base_score"]
    print("Using Builtin List:", VARS)

def main(args):
    reports = []
    for file in args.nessusFiles:
        try:
            scan = ET.parse(file)
        except:
            print("Unable to open file ", file)
            continue
        bar = alive_it(scan.getroot().findall('./Report/ReportHost'), title="Reading Reports...")
        for reportHost in bar:
            if args.SlowMode:
                time.sleep(.01)
            # get host data here
            repItems = utils.getReportItems(reportHost, VARS)
            for report in repItems:
                report["filename"] = file.split("/")[-1] # Add Filename to Report
                reports.append(report)
    
    # Get Default SORT.conf
    try:
        keys = []
        with open("config/SORT.conf", "r") as f:
            lines = f.readlines()
        for l in lines:
            if l[0] == '#':
                continue
            elif l == '':
                continue
            else:
                keys.append(l.strip())
    except:
        print("Failed to read default keys...")
        keys = ["pluginID", "pluginName", "description", "solution", "name", "protocol", "port"]
        print("Using Builtin List:", keys)

    for rep in reports:
        for key in rep.keys():
            if key not in keys:
                keys.append(key)
    if args.sort:
        keys.sort()

    if args.writeFile:
        if exists(args.writeFile):
            while True:
                if args.force:
                    break
                i = input("Overwrite (y/n): ")
                if i.lower() == "y":
                    pass
                    break
                elif i.lower() == "n":
                    print("Exiting")
                    exit()
        with open(args.writeFile, "w") as f:
            writer = DictWriter(f, keys)
            writer.writeheader()
            bar = alive_it(reports, title="Writing to file...")
            for rep in bar:
                if args.SlowMode:
                    time.sleep(0.01)
                writer.writerow(rep)

if __name__ == "__main__":

    __version__ = "1.0.2"

    parser = argparse.ArgumentParser(description=f"Pyne {__version__}")
    parser.add_argument('nessusFiles', type=str, nargs='+')
    parser.add_argument('-w', '--writeFile', metavar='', help='path to write file')
    parser.add_argument('-s', '--sort', action='store_true', help='sort keys alphabetically')
    parser.add_argument('-f', '--force', action='store_true', help='force overwrite of file')
    parser.add_argument('-v', '--verbose', action='store_true')
    parser.add_argument('-S', '--SlowMode', action='store_true')
    args = parser.parse_args()

    main(args)