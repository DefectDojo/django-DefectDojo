from xml.dom import NamespaceErr
from defusedxml import ElementTree
import os
import csv
import re
from dojo.models import Endpoint, Finding

__author__ = 'jay7958'


def get_text_severity(severity_id):
    if severity_id == 4:
        return 'Critical'
    elif severity_id == 3:
        return 'High'
    elif severity_id == 2:
        return 'Medium'
    elif severity_id == 1:
        return 'Low'
    else:
        return 'Info'

class NessusCSVParser(object):
    def __init__(self, filename, test):
        content = open(filename.temporary_file_path(), "rb").read().replace("\r", "\n")
        # content = re.sub("\"(.*?)\n(.*?)\"", "\"\1\2\"", content)
        # content = re.sub("(?<=\")\n", "\\\\n", content)
        with open("%s-filtered" % filename.temporary_file_path(), "wb") as out:
            out.write(content)
            out.close()

        with open("%s-filtered" % filename.temporary_file_path(), "rb") as scan_file:
            reader = csv.reader(scan_file,
                                lineterminator="\n",
                                quoting=csv.QUOTE_ALL)
            dupes = {}
            first = True
            for row in reader:
                if first:
                    heading = row
                    first = False
                    continue

                dat = {}
                endpoint = None
                for h in ["severity", "endpoint",
                          "title", "description",
                          "mitigation", "references",
                          "impact", "plugin_output", "port"]:
                    dat[h] = None

                for i, var in enumerate(row):
                    if not var:
                        continue

                    var = re.sub("(\A(\\n)+|(\\n)+\Z|\\r)", "", var)
                    var = re.sub("(\\n)+", "\n", var)

                    if heading[i] == "CVE":
                        if re.search("(CVE|CWE)", var) is None:
                            var = "CVE-%s" % str(var)
                        if dat['references'] is not None:
                            dat['references'] = var + "\n" + dat['references']
                        else:
                            dat['references'] = var + "\n"
                    elif heading[i] == "Risk":
                        if re.match("None", var) or not var:
                            dat['severity'] = "Info"
                        else:
                            dat['severity'] = var
                    elif heading[i] == "Host":
                        dat['endpoint'] = var
                        endpoint = Endpoint(host=var)
                    elif heading[i] == "Port":
                        if var is not "None":
                            if dat['description'] is not None:
                                dat['description'] = "Ports:"
                                + var + "\n" + dat['description']
                            else:
                                dat['description'] = "Ports:" + var + "\n"

                            dat['port'] = var
                            endpoint.host += ":" + var
                        else:
                            dat['port'] = 'n/a'

                    elif heading[i] == "Name":
                        dat['title'] = var
                    elif heading[i] == "Synopsis":
                        dat['description'] = var
                    elif heading[i] == "Description":
                        dat['impact'] = var
                    elif heading[i] == "Solution":
                        dat['mitigation'] = var
                    elif heading[i] == "See Also":
                        if dat['references'] is not None:
                            dat['references'] += var
                        else:
                            dat['references'] = var
                    elif heading[i] == "Plugin Output":
                        dat['plugin_output'] = "\nPlugin output(" + \
                                               dat['endpoint'] + "):" + str(var) + "\n"

                if not dat['severity']:
                    dat['severity'] = "Info"
                if not dat['title']:
                    continue

                dupe_key = dat['severity'] + dat['title']

                if dupe_key in dupes:
                    find = dupes[dupe_key]
                    if dat['plugin_output'] is not None:
                        find.description += dat['plugin_output']
                else:
                    if dat['plugin_output'] is not None:
                        dat['description'] = dat['description'] + \
                                             dat['plugin_output']
                    find = Finding(title=dat['title'],
                                   test=test,
                                   active=False,
                                   verified=False, description=dat['description'],
                                   severity=dat['severity'],
                                   numerical_severity=Finding.get_numerical_severity(dat['severity']),
                                   mitigation=dat['mitigation'] if dat['mitigation'] is not None else 'N/A',
                                   impact=dat['impact'],
                                   references=dat['references'],
                                   url=dat['endpoint'])

                    find.unsaved_endpoints = list()
                    dupes[dupe_key] = find

                if endpoint:
                    find.unsaved_endpoints.append(endpoint)
        os.unlink(filename.temporary_file_path())
        os.unlink("%s-filtered" % filename.temporary_file_path())
        self.items = dupes.values()


class NessusXMLParser(object):
    def __init__(self, file, test):
        nscan = ElementTree.parse(file)
        root = nscan.getroot()

        if 'NessusClientData_v2' not in root.tag:
            raise NamespaceErr('This version of Nessus report is not supported. Please make sure the export is '
                               'formatted using the NessusClientData_v2 schema.')
        dupes = {}
        for report in root.iter("Report"):
            for host in report.iter("ReportHost"):
                ip = host.attrib['name']
                fqdn = host.find(".//HostProperties/tag[@name='host-fqdn']").text if host.find(
                    ".//HostProperties/tag[@name='host-fqdn']") is not None else None

                for item in host.iter("ReportItem"):
                    # if item.attrib["svc_name"] == "general":
                    #     continue

                    port = None
                    if float(item.attrib["port"]) > 0:
                        port = item.attrib["port"]

                    protocol = None
                    if str(item.attrib["protocol"]):
                        protocol = item.attrib["protocol"]

                    description = ""
                    plugin_output = None
                    if item.find("synopsis") is not None:
                        description = item.find("synopsis").text + "\n\n"
                    if item.find("plugin_output") is not None:
                        plugin_output = "Plugin Output: " + ip + (
                            (":" + port) if port is not None else "") + " " + item.find("plugin_output").text + "\n\n"
                        description += plugin_output

                    nessus_severity_id = int(item.attrib["severity"])
                    severity = get_text_severity(nessus_severity_id)

                    impact = item.find("description").text + "\n\n"
                    if item.find("cvss_vector") is not None:
                        impact += "CVSS Vector: " + item.find("cvss_vector").text + "\n"
                    if item.find("cvss_base_score") is not None:
                        impact += "CVSS Base Score: " + item.find("cvss_base_score").text + "\n"
                    if item.find("cvss_temporal_score") is not None:
                        impact += "CVSS Temporal Score: " + item.find("cvss_temporal_score").text + "\n"

                    mitigation = item.find("solution").text if item.find("solution") is not None else "N/A"
                    references = ""
                    for ref in item.iter("see_also"):
                        refs = ref.text.split()
                        for r in refs:
                            references += r + "\n"

                    for xref in item.iter("xref"):
                        references += xref.text + "\n"

                    cwe = None
                    if item.find("cwe") is not None:
                        cwe = item.find("cwe").text
                    title = item.attrib["pluginName"]
                    dupe_key = severity + title

                    if dupe_key in dupes:
                        find = dupes[dupe_key]
                        if plugin_output is not None:
                            find.description += plugin_output
                    else:
                        find = Finding(title=title,
                                       test=test,
                                       active=False,
                                       verified=False,
                                       description=description,
                                       severity=severity,
                                       numerical_severity=Finding.get_numerical_severity(severity),
                                       mitigation=mitigation,
                                       impact=impact,
                                       references=references,
                                       cwe=cwe)
                        find.unsaved_endpoints = list()
                        dupes[dupe_key] = find

                    find.unsaved_endpoints.append(Endpoint(host=ip + (":" + port if port is not None else ""),
                                                           protocol=protocol))
                    if fqdn is not None:
                        find.unsaved_endpoints.append(Endpoint(host=fqdn,
                                                               protocol=protocol))

        self.items = dupes.values()
