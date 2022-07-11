#!/bin/python3

from csv import DictWriter
from src import *
import argparse
import xml.etree.ElementTree as ET
from alive_progress import alive_bar, alive_it
import time
from os.path import exists


try:
    VARS = []
    with open("config/defaultVARS.conf", "r") as f:
        lines = f.readlines()
    for l in lines:
        VARS.append(l.strip())
except:
    print("Failed to read default VARS.")
    VARS = ["risk_factor", "description", "solution", "plugin_type", "plugin_output", "cve", "see_also", "cvss_base_score", "exploit_available", "metasploit_name"]
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
            repItems = utils.getReportItems(reportHost, VARS)
            for report in repItems:
                report["filename"] = file.split("/")[-1] # Add Filename to Report
                reports.append(report)
    
    try:
        keys = []
        with open("config/defaultKeys.conf", "r") as f:
            lines = f.readlines()
        for l in lines:
            keys.append(l.strip())
    except:
        print("Failed to read default keys.")
        keys = ["pluginID", "pluginName", "severity", "risk_factor", "description", "solution", "name", "hostname", "plugin_type", "protocol", "port", "plugin_output", "cve", "see_also", "cvss_base_score", "exploit_available", "metasploit_name"]
        print("Using Default List:", keys)

    for rep in reports:
        for key in rep.keys():
            if key not in keys:
                keys.append(key)
    if args.sort:
        keys.sort()

    if args.writeFile:
        if exists(args.writeFile):
            while True:
                if args.overWrite:
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

    __version__ = "1.0.0"

    parser = argparse.ArgumentParser(description=f"Pyne Parse {__version__}")
    parser.add_argument('nessusFiles', type=str, nargs='+')
    parser.add_argument('-w', '--writeFile', metavar='', help='path to write file')
    parser.add_argument('-s', '--sort', action='store_true', help='sort keys alphabetically')
    parser.add_argument('-v', '--verbose', action='store_true')
    parser.add_argument('-o', '--overWrite', action='store_true')
    parser.add_argument('-S', '--SlowMode', action='store_true')
    args = parser.parse_args()

    main(args)