from xml.dom import NamespaceErr
import lxml.etree as le
from dojo.models import Endpoint, Finding

__author__ = 'patriknordlen'


class NmapXMLParser(object):
    def __init__(self, file, test):
        parser = le.XMLParser(resolve_entities=False)
        nscan = le.parse(file, parser)
        root = nscan.getroot()

        if 'nmaprun' not in root.tag:
            raise NamespaceErr("This doesn't seem to be a valid Nmap xml file.")
        dupes = {}
        hostInfo = ""

        for host in root.iter("host"):
            ip = host.find("address[@addrtype='ipv4']").attrib['addr']
            fqdn = host.find("hostnames/hostname[@type='PTR']").attrib['name'] if host.find("hostnames/hostname[@type='PTR']") is not None else None

            for os in root.iter("os"):
                if ip is not None:
                    hostInfo += "IP Address: %s\n" % ip
                if fqdn is not None:
                    fqdn += "FQDN: %s\n" % ip
                if os.find('osmatch') is not None:
                    if 'name' in os.find('osmatch').attrib:
                        hostInfo += "Host OS: %s\n" % os.find('osmatch').attrib['name']
                    if 'accuracy' in os.find('osmatch').attrib:
                        hostInfo += "Accuracy: {0}%\n".format(os.find('osmatch').attrib['accuracy'])

                hostInfo += "\n"

            for portelem in host.xpath("ports/port[state/@state='open']"):
                port = portelem.attrib['portid']
                protocol = portelem.attrib['protocol']

                title = "Open port: %s/%s" % (port, protocol)
                description = hostInfo
                description += "Port: %s\n" % (port)
                serviceinfo = ""

                if portelem.find('service') is not None:
                    if 'product' in portelem.find('service').attrib:
                        serviceinfo += "Product: %s\n" % portelem.find('service').attrib['product']

                    if 'version' in portelem.find('service').attrib:
                        serviceinfo += "Version: %s\n" % portelem.find('service').attrib['version']

                    if 'extrainfo' in portelem.find('service').attrib:
                        serviceinfo += "Extra Info: %s\n" % portelem.find('service').attrib['extrainfo']

                    description += serviceinfo

                description += '\n\n'

                severity = "Info"

                dupe_key = port

                if dupe_key in dupes:
                    find = dupes[dupe_key]
                    if description is not None:
                        find.description += description
                else:
                    find = Finding(title=title,
                                    test=test,
                                    active=False,
                                    verified=False,
                                    description=description,
                                    severity=severity,
                                    numerical_severity=Finding.get_numerical_severity(severity))
                    find.unsaved_endpoints = list()
                    dupes[dupe_key] = find

                find.unsaved_endpoints.append(Endpoint(host=ip, fqdn=fqdn, port=port, protocol=protocol))
        self.items = dupes.values()
