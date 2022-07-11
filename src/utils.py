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