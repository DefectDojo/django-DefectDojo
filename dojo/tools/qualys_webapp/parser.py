#!/usr/bin/env python
#
# -*- coding:utf-8 -*-

import xml
import re
import base64
from dojo.models import Finding, Endpoint
from urllib.parse import urlparse


SEVERITY_MATCH = ['Informational',
                   'Low',
                   'Medium',
                   'High',
                   'Critical']


# Parse 'CWE-XXXX' format to strip just the numbers
def get_cwe(cwe):
    cweSearch = re.search("CWE-([0-9]*)", cwe, re.IGNORECASE)
    if cweSearch:
        return cweSearch.group(1)
    else:
        return 0


# Inputs are a list of endpoints and request/response pairs and doctors
# them to fit their respective model structures and the adds them to a
# newly generated Finding
def attach_extras(endpoints, requests, responses, finding):
    if finding is None:
        finding = Finding()
        finding.unsaved_req_resp = list()
        finding.unsaved_endpoints = list()

    for endpoint in endpoints:
        parsedUrl = urlparse(endpoint)
        protocol = parsedUrl.scheme
        query = parsedUrl.query
        fragment = parsedUrl.fragment
        path = parsedUrl.path
        port = ""  # Set port to empty string by default
        # Split the returned network address into host and
        try:  # If there is port number attached to host address
            host, port = parsedUrl.netloc.split(':')
        except:  # there's no port attached to address
            host = parsedUrl.netloc

        finding.unsaved_endpoints.append(Endpoint(
                    host=host, port=port,
                    path=path,
                    protocol=protocol,
                    query=query, fragment=fragment))

    for i in range(0, len(requests)):
        if requests[i] != '' or responses[i] != '':
            finding.unsaved_req_resp.append({"req": requests[i], "resp": responses[i]})

    return finding


# Build a request string by checking for all possible field that could be
# found in the this section of the report
def get_request(request):
    if request is not None:
        header = ''
        header += str(request.findtext('METHOD')) + ': '
        header += str(request.findtext('URL')) + '\n'
        headers = request.find('HEADERS')
        if headers is not None:
            for head in headers.iter('HEADER'):
                header += str(head.findtext('key')) + ': '
                header += str(head.findtext('value')) + '\n'
        return str(header)
    return ''


# Build a response string by decrypting the value in the response
def get_response(response):
    if response is not None:
        enc_resp = str(response.findtext('CONTENTS'))
        resp = base64.b64decode(enc_resp).decode('utf-8')
        return resp
    return ''


# Retrieve request and response pairs and return a list of requests
# and a list of responses from a single vulnerability
def get_request_response(payloads):
    requests = []
    responses = []
    for payload in payloads.iter('PAYLOAD'):
        requests.append(str(get_request(payload.find('REQUEST'))))
        responses.append(str(get_response(payload.find('RESPONSE'))))
    return [requests, responses]


# Traverse and retreive any information in the VULNERABILITY_LIST
# section of the report. This includes all endpoints and request/response pairs
def get_vulnerabilities(vulnerabilities):
    findings = {}
    # Iterate through all vulnerabilites to pull necessary info
    for vuln in vulnerabilities:
        urls = []
        requests = response = ''
        qid = int(vuln.findtext('QID'))
        urls.append(str(vuln.findtext('URL')))
        access_path = vuln.find('ACCESS_PATH')
        if access_path is not None:
            urls += [url.text for url in access_path.iter('URL')]
        payloads = vuln.find('PAYLOADS')
        if payloads is not None:
            req_resps = get_request_response(payloads)

        finding = findings.get(qid, None)
        findings[qid] = attach_extras(urls, req_resps[0], req_resps[1], finding)
    return findings


# Retrieve information from a single glossary entry such as description,
# severity, title, impact, mitigation, and CWE
def get_glossary_item(glossary, finding):
    title = str(glossary.findtext('TITLE'))
    if title is not None:
        finding.title = title
    severity = int(glossary.findtext('SEVERITY'))
    if severity is not None:
        finding.severity = SEVERITY_MATCH[severity - 1]
    description = str(glossary.findtext('DESCRIPTION'))
    if description is not None:
        finding.description = description
    impact = str(glossary.findtext('IMPACT'))
    if impact is not None:
        finding.impact = impact
    solution = str(glossary.findtext('SOLUTION'))
    if solution is not None:
        finding.mitigation = solution
    cwe = str(glossary.findtext('CWE'))
    if cwe is not None:
        finding.cwe = int(get_cwe(cwe))
    return finding


# Retrieve information from a single information gathered entry
def get_info_item(info_gathered, finding):
    data = str(info_gathered.findtext('DATA'))
    if data is not None:
        finding.description += '\n\n' + data
    return finding


# Create finding items for all vulnerabilities in the report
def get_items(vulnerabilities, info_gathered, glossary):
    ig_qid_list = [int(ig.findtext('QID')) for ig in info_gathered]
    g_qid_list = [int(g.findtext('QID')) for g in glossary]

    # This dict has findings mapped by QID to remove any duplicates
    findings = get_vulnerabilities(vulnerabilities)

    for qid, finding in findings.items():
        if qid in g_qid_list:
            index = g_qid_list.index(qid)
            findings[qid] = get_glossary_item(glossary[index], finding)
        if qid in ig_qid_list:
            index = ig_qid_list.index(qid)
            findings[qid] = get_info_item(glossary[index], finding)

    return findings


def qualys_webapp_parser(qualys_xml_file, test):
    if qualys_xml_file is None:
        return []

    tree = xml.etree.ElementTree.parse(qualys_xml_file)
    vulnerabilities = tree.findall('./RESULTS/VULNERABILITY_LIST/VULNERABILITY')
    info_gathered = tree.findall('./RESULTS/INFORMATION_GATHERED_LIST/INFORMATION_GATHERED')
    glossary = tree.findall('./GLOSSARY/QID_LIST/QID')

    items = list(get_items(vulnerabilities, info_gathered, glossary).values())

    return items


class QualysWebAppParser(object):
    def __init__(self, file, test):
        self.items = qualys_webapp_parser(file, test)
