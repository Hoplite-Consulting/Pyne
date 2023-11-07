from xml.etree.ElementTree import Element
import fnmatch
from os.path import exists, splitext
from csv import DictWriter
from .platypus import *
from alive_progress import alive_it
import pkg_resources
import time

SORT_PATH = pkg_resources.resource_filename("pyne.config", "SORT.conf")

def readConfig(PATH: str) -> list:
    """_summary_

    Args:
        PATH (str): Path of Config File

    Returns:
        list: List of Config File Options
    """
    DEF_HOST = ["operating-system", "host-ip", "host-fqdn"]
    DEF_SORT = ["pluginID", "pluginName", "description", "solution", "name", "protocol", "port"]
    DEF_REPORT = ["description", "solution", "plugin_type", "plugin_output", "cve", "cvss_base_score"]

    try:
        VAR = []
        with open(PATH, "r") as f:
            lines = f.readlines()
        for l in lines:
            if l[0] == '#':
                continue
            elif l.strip() == '':
                continue
            else:
                VAR.append(l.strip())
    except:
        print(f"Failed to read config file {PATH}...")
        if "HOST" in PATH:
            print("Using Default List:", DEF_HOST)
            VAR = DEF_HOST
        elif "SORT" in PATH:
            print("Using Default List:", DEF_SORT)
            VAR = DEF_SORT
        elif "REPORT" in PATH:
            print("Using Default List:", DEF_REPORT)
            VAR = DEF_REPORT
    
    return VAR

def getHostItems(elmnt: Element, elmntList: list) -> dict:
    retDict = {}
    for item in elmnt.findall("./HostProperties"):
        for i in item.findall("./tag"):
            if i.attrib['name'] in elmntList:
                retDict[i.attrib['name']] = i.text
            else:
                continue
    return retDict

def getHeaderItems(elmnt: Element, elmntList: list) -> list[dict]:
    retList = []
    for item in elmnt.findall("./ReportItem"):
        appDict = elmnt.attrib | item.attrib
        for var in elmntList:
            try:
                appDict[var] = item.find(f"./{var}").text[:30000] # Character Limit becasue Excel is lame...
            except:
                pass
        retList.append(appDict)
    return retList

def getCategory(title: str, solution: str, severity: str) -> str:

    TITLE = title.lower()
    SOLUTION = solution.lower()
    SEVERITY = int(severity)

    if SEVERITY == 0:
        return "Informational"

    try:
        ms_patch = fnmatch.filter(TITLE.split(" "), "ms??-???")[0]
    except:
        try:
            ms_patch = fnmatch.filter(TITLE.split(":"), "ms??-???")[0]
        except:
            ms_patch = "MS??-???"

    if "unsupported version" in TITLE:
        return "Unsupported Application"
    elif "unsupported" in TITLE:
        return "Unsupported Operating System"
    elif ms_patch in TITLE or "bluekeep" in TITLE or "sigrid" in TITLE or "petitpotam" in TITLE or "smbv1" in TITLE:
        return "Missing Microsoft Patches"
    elif "<" in TITLE or "upgrade" in SOLUTION or "update" in SOLUTION:
        return "Missing Patches and Updates"
    elif "unprivileged" in TITLE or "unauthenticated" in TITLE or "unprotected" in TITLE or "nfs" in TITLE:
        return "Insecure Access Controls"
    elif "ssl" in TITLE or "tls" in TITLE:
        return "Insecure SSL/TLS Configurations or Services"
    else:
        return "Insecure Configurations or Services"
    
def saveCSVFile(reports: list, filePath: str, args) -> bool:

    # Initial Sort Config Reset for Each Report
    SORT_CONFIG = readConfig(SORT_PATH)

    # Add Any Missing Keys
    for report in reports:
         for key in report.keys():
              if key not in SORT_CONFIG:
                   SORT_CONFIG.append(key)
    
    # Sort if Argument Present
    if args.sort:
         SORT_CONFIG.sort()
    
    # Check is OutFile Already Exists
    if not args.Force:
        try:
            if exists(f"{filePath}"):
                raise FileExistsError
        except FileExistsError as err:
            print(f"Output File Already Exists: {filePath}")
            if args.verbose:
                print(err)
            if args.Application:
                platypusAlert("Output File Already Exists", f"{filePath}")
            return False

    # Write to OutFile
    with open(f"{filePath}", "w") as outFile:
         writer = DictWriter(outFile, SORT_CONFIG)
         writer.writeheader()
         bar = alive_it(reports, title=f"Writing to file... {filePath}")
         for report in bar:
              if args.Slow:
                time.sleep(.001)
              writer.writerow(report)

    return True

def getFileType(files: list, type: str, args) -> list:
    nessusFiles = []
    for file in files:
        fileType = splitext(file)[1]
        if fileType == type:
            nessusFiles.append(file)
    return nessusFiles