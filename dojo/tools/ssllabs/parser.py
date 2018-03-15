__author__ = 'Aaron Weaver'

from dojo.models import Endpoint, Finding
from datetime import datetime
import json

class SSLlabsParser(object):
    def __init__(self, filename, test):
        data = json.load(filename)

        find_date = datetime.now()
        dupes = {}

        for host in data:
            for endpoints in host["endpoints"]:
                categories = ''
                language = ''
                mitigation = ''
                impact = ''
                references = ''
                findingdetail = ''
                title = ''
                group = ''
                status = ''
                port = ''
                hostName = ''
                ipAddress = ''
                protocol = ''

                grade = endpoints["grade"]
                hostName = host["host"]
                port = host["port"]
                ipAddress = endpoints["ipAddress"]
                protocol = host["protocol"]

                title = "TLS Grade '%s' for %s" % (grade, hostName)
                cert = endpoints["details"]["cert"]
                sev = self.getCriticalityRating(grade)
                description = "%s \n\n" % title
                description = "%sCertifcate Subject: %s\n" % (description, cert["subject"])
                description = "%sIssuer Subject: %s\n" % (description, cert["issuerSubject"])
                description = "%sSignature Algorithm: %s\n" % (description, cert["sigAlg"])

                protocol_str = ""
                for protocol_data in endpoints["details"]["protocols"]:
                    protocol_str += protocol_data["name"] + " " + protocol_data["version"] + "\n"

                if protocol_str:
                    description += "\nProtocols:\n" + protocol_str

                description += "\nSuites List:\n\n"
                suite_info = ""
                for suites in endpoints["details"]["suites"]["list"]:
                    suite_info += suites["name"] + "\n"
                    suite_info += "Cipher Strength: " + str(suites["cipherStrength"]) + "\n"
                    if "ecdhBits" in suites:
                        suite_info += "ecdhBits: " + str(suites["ecdhBits"]) + "\n"
                    if "ecdhStrength" in suites:
                        suite_info += "ecdhStrength: " + str(suites["ecdhStrength"])
                    suite_info += "\n\n"

                description += suite_info
                description += "Additional Information:\n\n"

                description += "serverSignature: " + endpoints["details"]["serverSignature"] + "\n"
                description += "prefixDelegation: " + str(endpoints["details"]["prefixDelegation"]) + "\n"
                description += "nonPrefixDelegation: " + str(endpoints["details"]["nonPrefixDelegation"]) + "\n"
                description += "vulnBeast: " + str(endpoints["details"]["vulnBeast"]) + "\n"
                description += "renegSupport: " + str(endpoints["details"]["renegSupport"]) + "\n"
                description += "stsStatus: " + endpoints["details"]["stsStatus"] + "\n"
                description += "stsResponseHeader: " + endpoints["details"]["stsResponseHeader"] + "\n"
                description += "stsPreload: " + str(endpoints["details"]["stsPreload"]) + "\n"
                description += "sessionResumption: " + str(endpoints["details"]["sessionResumption"]) + "\n"
                description += "compressionMethods: " + str(endpoints["details"]["compressionMethods"]) + "\n"
                description += "supportsNpn: " + str(endpoints["details"]["supportsNpn"]) + "\n"
                description += "supportsAlpn: " + str(endpoints["details"]["supportsAlpn"]) + "\n"
                description += "sessionTickets: " + str(endpoints["details"]["sessionTickets"]) + "\n"
                description += "ocspStapling: " + str(endpoints["details"]["ocspStapling"]) + "\n"
                description += "sniRequired: " + str(endpoints["details"]["sniRequired"]) + "\n"
                description += "httpStatusCode: " + str(endpoints["details"]["httpStatusCode"]) + "\n"
                description += "supportsRc4: " + str(endpoints["details"]["supportsRc4"]) + "\n"
                description += "rc4WithModern: " + str(endpoints["details"]["rc4WithModern"]) + "\n"
                description += "forwardSecrecy: " + str(endpoints["details"]["forwardSecrecy"]) + "\n"
                description += "protocolIntolerance: " + str(endpoints["details"]["protocolIntolerance"]) + "\n"
                description += "miscIntolerance: " + str(endpoints["details"]["miscIntolerance"]) + "\n"
                description += "heartbleed: " + str(endpoints["details"]["heartbleed"]) + "\n"
                description += "heartbeat: " + str(endpoints["details"]["heartbeat"]) + "\n"
                description += "openSslCcs: " + str(endpoints["details"]["openSslCcs"]) + "\n"
                description += "openSSLLuckyMinus20: " + str(endpoints["details"]["openSSLLuckyMinus20"]) + "\n"
                description += "poodle: " + str(endpoints["details"]["poodle"]) + "\n"
                description += "poodleTls: " + str(endpoints["details"]["poodleTls"]) + "\n"
                description += "fallbackScsv: " + str(endpoints["details"]["fallbackScsv"]) + "\n"
                description += "freak: " + str(endpoints["details"]["freak"]) + "\n"
                description += "hasSct: " + str(endpoints["details"]["hasSct"]) + "\n"

                cName = ""
                for commonNames in cert["commonNames"]:
                    cName = "%s %s \n" % (cName, commonNames)

                aName = ""
                for altNames in cert["altNames"]:
                    aName = "%s %s \n" % (aName, altNames)

                protoName = ""
                for protocols in endpoints["details"]["protocols"]:
                    protoName = "%s %s %s\n" % (protoName, protocols["name"], protocols["version"])

                dupe_key = hostName + grade

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
                                   severity=sev,
                                   numerical_severity=Finding.get_numerical_severity(sev),
                                   mitigation=mitigation,
                                   impact=impact,
                                   references=references,
                                   url=host,
                                   date=find_date,
                                   dynamic_finding=True)
                    dupes[dupe_key] = find
                    find.unsaved_endpoints = list()

                find.unsaved_endpoints.append(Endpoint(host=ipAddress, fqdn=hostName, port=port, protocol=protocol))

            self.items = dupes.values()

    #Criticality rating
    #Grades: https://github.com/ssllabs/research/wiki/SSL-Server-Rating-Guide
    #A - Info, B - Medium, C - High, D/F/M/T - Critical
    def getCriticalityRating(self, rating):
        criticality = "Info"
        if "A" in rating:
            criticality = "Info"
        elif "B" in rating:
            criticality = "Medium"
        elif "C" in rating:
            criticality = "High"
        elif "D" in rating or "F" in rating or "M" in rating or "T" in rating:
            criticality = "Critical"

        return criticality
