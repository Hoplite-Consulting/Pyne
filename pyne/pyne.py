#!/usr/bin/python3

from .utils import readConfig, getHostItems, getHeaderItems, getCategory, saveCSVFile, getFileType
import argparse
import xml.etree.ElementTree as ET
from .platypus import *
from alive_progress import alive_it
import pyfiglet
import pkg_resources
import time

HEADER_PATH = pkg_resources.resource_filename("pyne.config", "HEADER.conf")
HOST_PATH = pkg_resources.resource_filename("pyne.config", "HOST.conf")

HEADER_CONFIG = readConfig(HEADER_PATH)
HOST_CONFIG = readConfig(HOST_PATH)

def parseNessusFile(filePath: str, args) -> list:

     # # Initial Sort Config Reset for Each Report
     # SORT_CONFIG = readConfig("./config/SORT.conf")

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
     bar = alive_it(rawParse.getroot().findall('./Report/ReportHost'), title=f"Reading Report... {filePath}")
     for reportHost in bar:
          if args.Slow:
                time.sleep(.01)
          repHost = getHostItems(reportHost, HOST_CONFIG)
          repHeaders = getHeaderItems(reportHost, HEADER_CONFIG)
          for header in repHeaders:
               if args.out != None:
                    header["origin-filename"] = filePath.split("/")[-1] # Add Filename to Report
               if args.Category:
                    header["category"] = getCategory(header['pluginName'], header['solution'], header['severity'])
               if args.UID:
                    try:
                         header["uid"] = header["pluginID"] + "-" + header["port"] + "-" + repHost["host-fqdn"]
                    except KeyError:
                         header["uid"] = header["pluginID"] + "-" + header["port"] + "-" + repHost["host-ip"]
                         print("[WARNING] No host-fqdn found for", repHost["host-ip"], "Using host-ip, this may not be consistent if comparing multiple scans.")
               reports.append(header | repHost)
     
     return reports

def main(nessusFiles, args):

     reportsList = []

     for nessusFile in nessusFiles:
          try:
               nessusReport = parseNessusFile(nessusFile, args)

               # Multi File Output
               if args.out == None:
                    path = nessusFile + ".csv"
                    saveCSVFile(nessusReport, path, args)
                    if args.Application:
                         platypusNotification("Parse Completed", f"Output Saved to {path}")

               # Single File Output
               if args.out != None:
                    for i in nessusReport:
                         reportsList.append(i)

          except Exception as err:
               print(f"Unable to Parse File: {nessusFile}")
               if args.verbose:
                    print(err)
               if args.Application:
                    platypusAlert("Unable to Parse File", nessusFile)
     
     if args.out != None:
          saveCSVFile(reportsList, args.out, args)
          if args.Application:
               platypusNotification("Parse Completed", f"Output Saved to {args.out}")

     if args.Application:
          platypusNotification("Parse Complete", "All Nessus files have been parsed.")

def setup():

     __version__ = "2.0.4"
     NAME = "Pyne"
     DESC = """
     Pyne is a .nessus file parser.

     It can be used in two different ways.
     It can create multiple CSV output files for every .nessus file input, or it can create one CSV output file from all the .nessus files.

     This is specified through the '-o/--out' flag.
     Without using this flag every .nessus file will have an output of the same name and location as the original with .csv appended to the end.
     With this flag all the .nessus files will be combined into one CSV output at your desired name and location.

     The '-C/--Category' flag will add a category to each finding based on Hoplite Consultings standards.
     """
     TITLE = pyfiglet.figlet_format(NAME, font="stop") + f"\n{NAME}\n{__version__}\n{DESC}"

     PARSER = argparse.ArgumentParser(description=f"{TITLE}", formatter_class=argparse.RawTextHelpFormatter)

     PARSER.add_argument('nessusFiles', type=str, nargs='+', help='.nessus file or files or directory of nessus files')
     PARSER.add_argument('-o', '--out', type=str, help='single output file location')
     PARSER.add_argument('-s', '--sort', action='store_true', help='sort keys alphabetically')
     PARSER.add_argument('-v', '--verbose', action='store_true', help='verbose error messaging')
     PARSER.add_argument('-F', '--Force', action='store_true', help='force file write')
     PARSER.add_argument('-C', '--Category', action='store_true', help='add category to each finding')
     PARSER.add_argument('-U', '--UID', action='store_true', help='add unique id to each finding')
     PARSER.add_argument('-A', '--Application', action='store_true', help=argparse.SUPPRESS) # This flag is used in a compiled application version to give notifications to the user.
     PARSER.add_argument('-S', '--Slow', action='store_true', help=argparse.SUPPRESS) # Runs the program slowly so you can watch the flashy loading bar.

     parsedArguments = PARSER.parse_args()

     # Make sure there are only .nessus files being parsed.
     nessusFiles = getFileType(parsedArguments.nessusFiles, ".nessus", parsedArguments)

     # Parse the files.
     main(nessusFiles, parsedArguments)

if __name__ == "__main__":
     setup()