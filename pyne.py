#!/bin/python3

from csv import DictWriter
from src import *
import argparse
import xml.etree.ElementTree as ET
from alive_progress import alive_it
import time
from os.path import exists

# Get Default REPORT.conf
VARS = utils.readConfig("config/REPORT.conf")

# Get Default HOST.conf
HOST = utils.readConfig("config/HOST.conf")

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
            repHost = utils.getHostItems(reportHost, HOST)
            repItems = utils.getReportItems(reportHost, VARS)
            for report in repItems:
                report["filename"] = file.split("/")[-1] # Add Filename to Report
                reports.append(report | repHost)
    
    # Get Default SORT.conf
    keys = utils.readConfig("config/SORT.conf")

    # Add all Missing Keys
    for rep in reports:
        for key in rep.keys():
            if key not in keys:
                keys.append(key)
    if args.sort:
        keys.sort()

    # Save to File
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

    __version__ = "1.1.2"

    parser = argparse.ArgumentParser(description=f"Pyne {__version__}")
    parser.add_argument('nessusFiles', type=str, nargs='+', help='nessus file')
    parser.add_argument('writeFile', help='path to write file')
    parser.add_argument('-s', '--sort', action='store_true', help='sort keys alphabetically')
    parser.add_argument('-f', '--force', action='store_true', help='force overwrite of write file')
    parser.add_argument('-v', '--verbose', action='store_true')
    parser.add_argument('-S', '--SlowMode', action='store_true')
    args = parser.parse_args()

    main(args)