from defusedxml.ElementTree import parse
from cpe import CPE

from dojo.models import Endpoint, Finding


class NmapParser(object):

    def get_scan_types(self):
        return ["Nmap Scan"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type  # no custom label for now

    def get_description_for_scan_types(self, scan_type):
        return "XML output (use -oX)"

    def get_findings(self, file, test):
        tree = parse(file)
        root = tree.getroot()
        dupes = dict()
        if 'nmaprun' not in root.tag:
            raise ValueError("This doesn't seem to be a valid Nmap xml file.")

        for host in root.findall("host"):
            host_info = "### Host\n\n"

            ip = host.find("address[@addrtype='ipv4']").attrib['addr']
            if ip is not None:
                host_info += "**IP Address:** %s\n" % ip

            fqdn = host.find("hostnames/hostname[@type='PTR']").attrib['name'] if host.find("hostnames/hostname[@type='PTR']") is not None else None
            if fqdn is not None:
                host_info += "**FQDN:** %s\n" % fqdn

            host_info += "\n\n"

            for os in host.iter("os"):
                for os_match in os.iter("osmatch"):
                    if 'name' in os_match.attrib:
                        host_info += "**Host OS:** %s\n" % os_match.attrib['name']
                    if 'accuracy' in os_match.attrib:
                        host_info += "**Accuracy:** {0}%\n".format(os_match.attrib['accuracy'])

                host_info += "\n\n"

            for port_element in host.findall("ports/port"):
                port = port_element.attrib['portid']
                protocol = port_element.attrib['protocol']
                endpoint = Endpoint(host=ip, fqdn=fqdn, port=port, protocol=protocol)

                # filter on open ports
                if 'open' != port_element.find("state").attrib.get('state'):
                    continue
                title = "Open port: %s/%s" % (port, protocol)
                description = host_info
                description += "**Port/Protocol:** %s/%s\n" % (port, protocol)

                service_info = "\n\n"
                if port_element.find('service') is not None:
                    if 'product' in port_element.find('service').attrib:
                        service_info += "**Product:** %s\n" % port_element.find('service').attrib['product']

                    if 'version' in port_element.find('service').attrib:
                        service_info += "**Version:** %s\n" % port_element.find('service').attrib['version']

                    if 'extrainfo' in port_element.find('service').attrib:
                        service_info += "**Extra Info:** %s\n" % port_element.find('service').attrib['extrainfo']

                    description += service_info

                description += "\n\n"

                # manage some script like https://github.com/vulnersCom/nmap-vulners
                for script_element in port_element.findall('script[@id="vulners"]'):
                    self.manage_vulner_script(test, dupes, script_element, endpoint)

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
                                mitigation="N/A",
                                impact="No impact provided",
                                numerical_severity=Finding.get_numerical_severity(severity))
                    find.unsaved_endpoints = list()
                    dupes[dupe_key] = find

                find.unsaved_endpoints.append(endpoint)
        return list(dupes.values())

    def convert_cvss_score(self, raw_value):
        """According to CVSS official numbers https://nvd.nist.gov/vuln-metrics/cvss
                        None 	0.0
        Low 	0.0-3.9 	Low 	0.1-3.9
        Medium 	4.0-6.9 	Medium 	4.0-6.9
        High 	7.0-10.0 	High 	7.0-8.9
        Critical 	9.0-10.0"""
        val = float(raw_value)
        if val == 0.0:
            return "Info"
        elif val < 4.0:
            return "Low"
        elif val < 7.0:
            return "Medium"
        elif val < 9.0:
            return "High"
        else:
            return "Critical"

    def manage_vulner_script(self, test, dupes, script_element, endpoint):
        for component_element in script_element.findall('table'):
            component_cpe = CPE(component_element.attrib['key'])
            for vuln in component_element.findall('table'):
                description = "### Vulnerability\n\n"
                description += "**CPE**: " + str(component_cpe) + "\n"
                vuln_attributes = dict()
                for elem in vuln.findall('elem'):
                    vuln_attributes[elem.attrib['key'].lower()] = elem.text
                    description += "**" + elem.attrib['key'] + "**: " + elem.text + "\n"
                cve = vuln_attributes['id']
                severity = self.convert_cvss_score(vuln_attributes['cvss'])

                dupe_key = cve
                if dupe_key in dupes:
                    find = dupes[dupe_key]
                    if description is not None:
                        find.description += description
                else:
                    find = Finding(title=cve,
                                    cve=cve,
                                    test=test,
                                    active=False,
                                    verified=False,
                                    description=description,
                                    severity=severity,
                                    mitigation="N/A",
                                    impact="No impact provided",
                                    numerical_severity=Finding.get_numerical_severity(severity),
                                    component_name=component_cpe.get_product()[0] if len(component_cpe.get_product()) > 0 else '',
                                    component_version=component_cpe.get_version()[0] if len(component_cpe.get_version()) > 0 else '',
                                   )
                    find.unsaved_endpoints = list()
                    dupes[dupe_key] = find

                find.unsaved_endpoints.append(endpoint)
