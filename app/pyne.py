from utils import readConfig, getHostItems, getHeaderItems, getCategory
import argparse
import xml.etree.ElementTree as ET
from platypus import *
from os.path import exists
from csv import DictWriter
from alive_progress import alive_it
import pyfiglet

HEADER_CONFIG = readConfig("config/HEADER.conf")
HOST_CONFIG = readConfig("config/HOST.conf")

def parseNessusFile(filePath: str, args):

     # Initial Sort Config Reset for Each Report
     SORT_CONFIG = readConfig("config/SORT.conf")

     # Empty Reports List
     reports = []

     # Try to Parse XML Element Tree
     try:
          rawParse = ET.parse(filePath)
     except Exception as err:
          print(f"Failed to Parse Nessus File: {filePath}")
          if args.verbose:
               print(err)
          if args.Application:
               platypusAlert("Failed to Parse Nessus File", filePath)
          return False
     
     # Process Report Data from Nessus File
     bar = alive_it(rawParse.getroot().findall('./Report/ReportHost'), title=f"Reading Reports... {filePath}")
     for reportHost in bar:
          repHost = getHostItems(reportHost, HOST_CONFIG)
          repHeaders = getHeaderItems(reportHost, HEADER_CONFIG)
          for header in repHeaders:
               if args.CATEGORY:
                    report["category"] = getCategory(report['pluginName'], report['solution'], report['severity'])
               if args.UID:
                    try:
                         report["uid"] = report["pluginID"] + "-" + report["port"] + "-" + repHost["host-fqdn"]
                    except KeyError:
                         report["uid"] = report["pluginID"] + "-" + report["port"] + "-" + repHost["host-ip"]
                         print("[WARNING] No host-fqdn found for", repHost["host-ip"], "Using host-ip, this may not be consistent if comparing multiple scans.")
               reports.append(header | repHost)
     
     # Add Any Missing Keys
     for report in reports:
          for key in report.keys():
               if key not in SORT_CONFIG:
                    SORT_CONFIG.append(key)
     
     # Sort if Argument Present
     if args.sort:
          SORT_CONFIG.sort()
     
     # Check is OutFile Already Exists
     try:
          if exists(f"{filePath}.csv"):
               raise FileExistsError
     except FileExistsError as err:
          print(f"Output File Already Exists: {filePath}.csv")
          if args.verbose:
               print(err)
          if args.Application:
               platypusAlert("Output File Already Exists", f"{filePath}.csv")
          return False

     # Write to OutFile
     with open(f"{filePath}.csv", "w") as outFile:
          writer = DictWriter(outFile, SORT_CONFIG)
          writer.writeheader()
          bar = alive_it(reports, title=f"Writing to file... {filePath}")
          for report in bar:
               writer.writerow(report)
     
     return True

if __name__ == "__main__":

     __version__ = "2.0.0"
     NAME = "Pyne"
     TITLE = pyfiglet.figlet_format(NAME, font="stop") + f"\n{NAME}\n{__version__}"

     PARSER = argparse.ArgumentParser(description=f"{TITLE}", formatter_class=argparse.RawTextHelpFormatter)

     PARSER.add_argument('nessusFiles', type=str, nargs='+', help='nessus file')
     PARSER.add_argument('-s', '--sort', action='store_true', help='sort keys alphabetically')
     PARSER.add_argument('-v', '--verbose', action='store_true', help='verbose error messaging')
     PARSER.add_argument('-C', '--CATEGORY', action='store_true', help='add category to each finding')
     PARSER.add_argument('-U', '--UID', action='store_true', help='add unique id to each finding')
     PARSER.add_argument('-A', '--Application', action='store_true', help='application mode extended output')

     args = PARSER.parse_args()

     for nessusFile in args.nessusFiles:
          try:
               parseNessusFile(nessusFile, args)
          except Exception as err:
               print(f"Unable to Parse File: {nessusFile}")
               if args.verbose:
                    print(err)
               if args.Application:
                    platypusAlert("Unable to Parse File", nessusFile)
          if args.Application:
               platypusNotification("Parse Completed", f"Output Saved to {nessusFile}.csv")