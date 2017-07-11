from xml.dom import NamespaceErr
import lxml.etree as le
import os
import csv
import re
from dojo.models import Endpoint, Finding
from pprint import pprint

__author__ = 'patriknordlen'

class NmapXMLParser(object):
    def __init__(self, file, test):
        parser = le.XMLParser(resolve_entities=False)
        nscan = le.parse(file, parser)
        root = nscan.getroot()

        if 'nmaprun' not in root.tag:
            raise NamespaceErr("This doesn't seem to be a valid nmap xml file.")
        dupes = {}
        for host in root.iter("host"):
            ip = host.find("address[@addrtype='ipv4']").attrib['addr']
            fqdn = host.find("hostnames/hostname[@type='PTR']").attrib['name'] if host.find("hostnames/hostname[@type='PTR']") is not None else None

            for portelem in host.xpath("ports/port[state/@state='open']"):
                port = portelem.attrib['portid']
                protocol = portelem.attrib['protocol']

                title = "Open port: %s/%s" % (port, protocol)
                
                description = "%s:%s A service was found to be listening on this port." % (ip, port)

                if portelem.find('service') is not None:
                    if hasattr(portelem.find('service'),'product'):
                        serviceinfo = " (%s%s)" % (portelem.find('service').attrib['product'], " "+portelem.find('service').attrib['version'] if hasattr(portelem.find('service'),'version') else "")
                    else:
                        serviceinfo = ""
                    description += " It was identified as '%s%s'." % (portelem.find('service').attrib['name'], serviceinfo)
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
