from xml.etree.ElementTree import Element

def getReportItems(elmnt: Element, elmntList: list) -> list[dict]:
    retList = []
    for item in elmnt.findall("./ReportItem"):
        appDict = elmnt.attrib | item.attrib
        for var in elmntList:
            try:
                appDict[var] = item.find(f"./{var}").text[:32600] # Character Limit becasue Excel is lame...
            except:
                pass
        retList.append(appDict)
    return retList

def getHostItems(elmnt: Element, elmntList: list) -> dict:
    retDict = {}
    for item in elmnt.findall("./HostProperties"):
        for i in item.findall("./tag"):
            if i.attrib['name'] in elmntList:
                retDict[i.attrib['name']] = i.text
            else:
                continue
    # return retDict | elmnt.attrib
    return retDict

def readConfig(PATH: str) -> list:
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