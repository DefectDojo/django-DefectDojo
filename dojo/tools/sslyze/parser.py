import json
from dojo.models import Endpoint, Finding

WEAK_PROTOCOLS = [
    "ssl_2_0_cipher_suites",
    "ssl_3_0_cipher_suites",
    "tls_1_0_cipher_suites",
    "tls_1_1_cipher_suites"
]


class SSLyzeJSONParser(object):

    def __init__(self, json_output, test):
        self.items = []

        if json_output is None:
            return

        tree = self.parse_json(json_output)

        if tree:
            self.items = [data for data in self.get_items(tree, test)]

    def parse_json(self, json_output):
        try:
            data = json_output.read()
            try:
                tree = json.loads(str(data, 'utf-8'))
            except:
                tree = json.loads(data)
        except:
            raise Exception("Invalid format")

        return tree

    def get_items(self, tree, test):
        items = []

        for node in tree['server_scan_results']:
            endpoint = get_endpoint(node)
            if 'scan_commands_results' in node:
                scr_node = node['scan_commands_results']
                item = get_heartbleed(scr_node, test, endpoint)
                if item:
                    items.append(item)
                item = get_ccs(scr_node, test, endpoint)
                if item:
                    items.append(item)
                item = get_secure_renegotiation(scr_node, test, endpoint)
                if item:
                    items.append(item)
                item = get_ssl2(scr_node, test, endpoint)
                if item:
                    items.append(item)
                item = get_ssl3(scr_node, test, endpoint)
                if item:
                    items.append(item)
                item = get_tls10(scr_node, test, endpoint)
                if item:
                    items.append(item)
                item = get_tls11(scr_node, test, endpoint)
                if item:
                    items.append(item)

        return list(items)


def get_heartbleed(node, test, endpoint):
    if 'heartbleed' in node:
        hb_node = node['heartbleed']
        vulnerable = False
        if 'is_vulnerable_to_heartbleed' in hb_node:
            vulnerable = hb_node['is_vulnerable_to_heartbleed']
        if vulnerable:
            title = get_url(endpoint) + ' - Heartbleed'
            description = get_url(endpoint) + ' is vulnerable to heartbleed'
            cve = 'CVE-2014-0160'
            return get_finding(title, description, cve, test, endpoint)
    return None

def get_ccs(node, test, endpoint):
    if 'openssl_ccs_injection' in node:
        ccs_node = node['openssl_ccs_injection']
        vulnerable = False
        if 'is_vulnerable_to_ccs_injection' in ccs_node:
            vulnerable = ccs_node['is_vulnerable_to_ccs_injection']
        if vulnerable:
            title = get_url(endpoint) + ' - CCS injection'
            description = get_url(endpoint) + ' is vulnerable to OpenSSL CCS injection'
            cve = 'CVE-2014-0224'
            return get_finding(title, description, cve, test, endpoint)
    return None

def get_secure_renegotiation(node, test, endpoint):
    if 'session_renegotiation' in node:
        sr_node = node['session_renegotiation']
        vulnerable = False
        if 'supports_secure_renegotiation' in sr_node:
            vulnerable = not sr_node['supports_secure_renegotiation']
        if vulnerable:
            title = get_url(endpoint) + ' - Secure session renegotiation'
            description = get_url(endpoint) + ' does not support secure session renegotiation'
            return get_finding(title, description, None, test, endpoint)
    return None

def get_ssl2(node, test, endpoint):
    if 'ssl_2_0_cipher_suites' in node:
        ssl2_node = node['ssl_2_0_cipher_suites']
        if 'accepted_cipher_suites' in ssl2_node and len(ssl2_node['accepted_cipher_suites']) > 0:
            title = get_url(endpoint) + ' - SSL 2.0'
            description = get_url(endpoint) + ' accepts SSL 2.0 connections'
            return get_finding(title, description, None, test, endpoint)
    return None

def get_ssl3(node, test, endpoint):
    if 'ssl_3_0_cipher_suites' in node:
        ssl3_node = node['ssl_3_0_cipher_suites']
        if 'accepted_cipher_suites' in ssl3_node and len(ssl3_node['accepted_cipher_suites']) > 0:
            title = get_url(endpoint) + ' - SSL 3.0'
            description = get_url(endpoint) + ' accepts SSL 3.0 connections'
            return get_finding(title, description, None, test, endpoint)
    return None

def get_tls10(node, test, endpoint):
    if 'tls_1_0_cipher_suites' in node:
        tls10_node = node['tls_1_0_cipher_suites']
        if 'accepted_cipher_suites' in tls10_node and len(tls10_node['accepted_cipher_suites']) > 0:
            title = get_url(endpoint) + ' - TLS 1.0'
            description = get_url(endpoint) + ' accepts TLS 1.0 connections'
            return get_finding(title, description, None, test, endpoint)
    return None

def get_tls11(node, test, endpoint):
    if 'tls_1_1_cipher_suites' in node:
        tls11_node = node['tls_1_1_cipher_suites']
        if 'accepted_cipher_suites' in tls11_node and len(tls11_node['accepted_cipher_suites']) > 0:
            title = get_url(endpoint) + ' - TLS 1.1'
            description = get_url(endpoint) + ' accepts TLS 1.1 connections'
            return get_finding(title, description, None, test, endpoint)
    return None

def get_finding(title, description, cve, test, endpoint):
    severity = 'Medium'
    finding = Finding(
        title=title,
        test=test,
        cve=cve,
        active=False,
        verified=False,
        description=description,
        severity=severity,
        numerical_severity=Finding.get_numerical_severity(severity),
        dynamic_finding=False,
        static_finding=True)
    if endpoint is not None:
        finding.unsaved_endpoints = list()
        finding.unsaved_endpoints.append(endpoint)
    return finding

def get_url(endpoint):
    url = 'unkown host'
    if endpoint is not None:
        if endpoint.host is not None:
            url = endpoint.host
        if endpoint.port is not None:
            url = url + ':' + str(endpoint.port)
    return url

def get_endpoint(node):
    hostname = None
    if 'server_info' in node:
        si_node = node['server_info']
        if 'server_location' in si_node:
            sl_node = si_node['server_location']
            if 'hostname' in sl_node:
                hostname = sl_node['hostname']
            if 'port' in sl_node:
                port = sl_node['port']

    if hostname is not None:
        return Endpoint(
            host=hostname,
            port=port)
    else:
        print("No endpoint found")
        return None
