import json

from dojo.models import Endpoint, Finding

# FIXME discuss this list as maintenance subject
# Recommended cipher suites according to German BSI as of 2020
TLS12_RECOMMENDED_CIPHERS = [
    'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256',
    'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384',
    'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
    'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
    'TLS_ECDHE_ECDSA_WITH_AES_128_CCM',
    'TLS_ECDHE_ECDSA_WITH_AES_256_CCM',
    'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256',
    'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384',
    'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
    'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
    'TLS_DHE_DSS_WITH_AES_128_CBC_SHA256',
    'TLS_DHE_DSS_WITH_AES_256_CBC_',
    'TLS_DHE_DSS_WITH_AES_128_GCM_SHA256',
    'TLS_DHE_DSS_WITH_AES_256_GCM_SHA384',
    'TLS_DHE_RSA_WITH_AES_128_CBC_SHA256',
    'TLS_DHE_RSA_WITH_AES_256_CBC_SHA256',
    'TLS_DHE_RSA_WITH_AES_128_GCM_SHA256',
    'TLS_DHE_RSA_WITH_AES_256_GCM_SHA384',
    'TLS_DHE_RSA_WITH_AES_128_CCM',
    'TLS_DHE_RSA_WITH_AES_256_CCM',
    'TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256',
    'TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384',
    'TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256',
    'TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384',
    'TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256',
    'TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384',
    'TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256',
    'TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384',
    'TLS_DH_DSS_WITH_AES_128_CBC_SHA256',
    'TLS_DH_DSS_WITH_AES_256_CBC_SHA256',
    'TLS_DH_DSS_WITH_AES_128_GCM_SHA256',
    'TLS_DH_DSS_WITH_AES_256_GCM_SHA384',
    'TLS_DH_RSA_WITH_AES_128_CBC_SHA256',
    'TLS_DH_RSA_WITH_AES_256_CBC_SHA256',
    'TLS_DH_RSA_WITH_AES_128_GCM_SHA256',
    'TLS_DH_RSA_WITH_AES_256_GCM_SHA384',
    'TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256',
    'TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384',
    'TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256',
    'TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384',
    'TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256',
    'TLS_DHE_PSK_WITH_AES_128_CBC_SHA256',
    'TLS_DHE_PSK_WITH_AES_256_CBC_SHA384',
    'TLS_DHE_PSK_WITH_AES_128_GCM_SHA256',
    'TLS_DHE_PSK_WITH_AES_256_GCM_SHA384',
    'TLS_DHE_PSK_WITH_AES_128_CCM',
    'TLS_DHE_PSK_WITH_AES_256_CCM',
    'TLS_RSA_PSK_WITH_AES_128_CBC_SHA256',
    'TLS_RSA_PSK_WITH_AES_256_CBC_SHA384',
    'TLS_RSA_PSK_WITH_AES_128_GCM_SHA256',
    'TLS_RSA_PSK_WITH_AES_256_GCM_SHA384'
]

TLS13_RECOMMENDED_CIPHERS = [
    'TLS_AES_128_GCM_SHA256',
    'TLS_AES_256_GCM_SHA384',
    'TLS_AES_128_CCM_SHA256'
]

BSI_LINK = 'https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TG02102/BSI-TR-02102-2.pdf?__blob=publicationFile&v=10'
REFERENCES = 'TLS recommendations of German BSI: ' + BSI_LINK


class SSLyzeJSONParser(object):

    def get_findings(self, json_output, test):

        if json_output is None:
            return

        tree = self.parse_json(json_output)

        if tree:
            return self.get_items(tree, test)

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
                item = get_renegotiation(scr_node, test, endpoint)
                if item:
                    items.append(item)
                item = get_weak_protocol('ssl_2_0_cipher_suites', 'SSL 2.0', scr_node, test, endpoint)
                if item:
                    items.append(item)
                item = get_weak_protocol('ssl_3_0_cipher_suites', 'SSL 3.0', scr_node, test, endpoint)
                if item:
                    items.append(item)
                item = get_weak_protocol('tls_1_0_cipher_suites', 'TLS 1.0', scr_node, test, endpoint)
                if item:
                    items.append(item)
                item = get_weak_protocol('tls_1_1_cipher_suites', 'TLS 1.1', scr_node, test, endpoint)
                if item:
                    items.append(item)
                item = get_strong_protocol('tls_1_2_cipher_suites', 'TLS 1.2', TLS12_RECOMMENDED_CIPHERS, scr_node, test, endpoint)
                if item:
                    items.append(item)
                item = get_strong_protocol('tls_1_3_cipher_suites', 'TLS 1.3', TLS13_RECOMMENDED_CIPHERS, scr_node, test, endpoint)
                if item:
                    items.append(item)
                item = get_certificate_information(scr_node, test, endpoint)
                if item:
                    items.append(item)

            elif 'scan_result' in node:
                scr_node = node['scan_result']
                item = get_heartbleed(scr_node, test, endpoint)
                if item:
                    items.append(item)
                item = get_ccs(scr_node, test, endpoint)
                if item:
                    items.append(item)
                item = get_renegotiation(scr_node, test, endpoint)
                if item:
                    items.append(item)
                item = get_weak_protocol('ssl_2_0_cipher_suites', 'SSL 2.0', scr_node, test, endpoint)
                if item:
                    items.append(item)
                item = get_weak_protocol('ssl_3_0_cipher_suites', 'SSL 3.0', scr_node, test, endpoint)
                if item:
                    items.append(item)
                item = get_weak_protocol('tls_1_0_cipher_suites', 'TLS 1.0', scr_node, test, endpoint)
                if item:
                    items.append(item)
                item = get_weak_protocol('tls_1_1_cipher_suites', 'TLS 1.1', scr_node, test, endpoint)
                if item:
                    items.append(item)
                item = get_strong_protocol('tls_1_2_cipher_suites', 'TLS 1.2', TLS12_RECOMMENDED_CIPHERS, scr_node, test, endpoint)
                if item:
                    items.append(item)
                item = get_strong_protocol('tls_1_3_cipher_suites', 'TLS 1.3', TLS13_RECOMMENDED_CIPHERS, scr_node, test, endpoint)
                if item:
                    items.append(item)
                item = get_certificate_information(scr_node, test, endpoint)
                if item:
                    items.append(item)

        return list(items)


def get_heartbleed(node, test, endpoint):
    if 'heartbleed' in node:
        heartbleed = node['heartbleed']
        if heartbleed.get('status') == 'NOT_SCHEDULED':
            return None
        vulnerable = False
        if 'is_vulnerable_to_heartbleed' in heartbleed:
            vulnerable = heartbleed['is_vulnerable_to_heartbleed']
            if vulnerable:
                title = 'Heartbleed'
                description = get_url(endpoint) + ' is vulnerable to heartbleed'
                cve = 'CVE-2014-0160'
                return get_finding(title, description, cve, None, test, endpoint)
        elif 'result' in heartbleed:
            hb_result = heartbleed['result']
            if 'is_vulnerable_to_heartbleed' in hb_result:
                vulnerable = hb_result['is_vulnerable_to_heartbleed']
                if vulnerable:
                    title = 'Heartbleed'
                    description = get_url(endpoint) + ' is vulnerable to heartbleed'
                    cve = 'CVE-2014-0160'
                    return get_finding(title, description, cve, None, test, endpoint)
        return None
    return None


def get_ccs(node, test, endpoint):
    if 'openssl_ccs_injection' in node:
        ccs_injection = node['openssl_ccs_injection']
        vulnerable = False
        if ccs_injection.get('status') == 'NOT_SCHEDULED':
            return None
        if 'is_vulnerable_to_ccs_injection' in ccs_injection:
            vulnerable = ccs_injection['is_vulnerable_to_ccs_injection']
            if vulnerable:
                title = 'CCS injection'
                description = get_url(endpoint) + ' is vulnerable to OpenSSL CCS injection'
                cve = 'CVE-2014-0224'
                return get_finding(title, description, cve, None, test, endpoint)

        elif 'result' in ccs_injection:
            ccs_result = ccs_injection['result']
            if 'is_vulnerable_to_ccs_injection' in ccs_result:
                vulnerable = ccs_result['is_vulnerable_to_ccs_injection']
                if vulnerable:
                    title = 'CCS injection'
                    description = get_url(endpoint) + ' is vulnerable to OpenSSL CCS injection'
                    cve = 'CVE-2014-0224'
                    return get_finding(title, description, cve, None, test, endpoint)
        return None
    return None


def get_renegotiation(node, test, endpoint):
    if 'session_renegotiation' in node:
        renegotiation = node['session_renegotiation']
        if renegotiation.get('status') == 'NOT_SCHEDULED':
            return None
        if 'accepts_client_renegotiation' in renegotiation and 'supports_secure_renegotiation' in renegotiation:
            vulnerable = False
            title = 'Session renegotiation'
            description = get_url(endpoint) + ' has problems with session renegotiation:'
            vulnerable_cr = 'accepts_client_renegotiation' in renegotiation and renegotiation['accepts_client_renegotiation']
            if vulnerable_cr:
                vulnerable = True
                description += '\n - Client renegotiation is accepted'
            vulnerable_sr = 'supports_secure_renegotiation' in renegotiation and not renegotiation['supports_secure_renegotiation']
            if vulnerable_sr:
                vulnerable = True
                description += '\n - Secure session renegotiation is not supported'
            if vulnerable:
                return get_finding(title, description, None, None, test, endpoint)

        elif 'result' in renegotiation:
            reneg_result = renegotiation['result']
            if 'is_vulnerable_to_client_renegotiation_dos' in reneg_result:
                reneg_dos = reneg_result['is_vulnerable_to_client_renegotiation_dos']
                if reneg_dos:
                    title = 'Is vulnerable to client negotiation DoS'
                    description = get_url(endpoint) + ' has problems with session renegotiation:'
                    return get_finding(title, description, None, None, test, endpoint)
            if 'supports_secure_renegotiation' in reneg_result:
                reneg_secure = reneg_result['supports_secure_renegotiation']
                if not reneg_secure:
                    title = 'Does not support secure negotiations'
                    description = get_url(endpoint) + ' has problems with session renegotiation:'
                    return get_finding(title, description, None, None, test, endpoint)
        return None
    return None


def get_weak_protocol(cipher, text, node, test, endpoint):
    if cipher in node:
        weak_node = node[cipher]
        if weak_node.get('status') == 'NOT_SCHEDULED':
            return None
        if 'accepted_cipher_suites' in weak_node and len(weak_node['accepted_cipher_suites']) > 0:
            title = text + ' not recommended'
            description = get_url(endpoint) + ' accepts ' + text + ' connections'
            return get_finding(title, description, None, REFERENCES, test, endpoint)
        elif 'result' in weak_node:
            weak_node_result = weak_node['result']
            if 'accepted_cipher_suites' in weak_node_result and len(weak_node_result['accepted_cipher_suites']) > 0:
                title = text + ' not recommended'
                description = get_url(endpoint) + ' accepts ' + text + ' connections'
                return get_finding(title, description, None, REFERENCES, test, endpoint)
        return None
    return None


def get_strong_protocol(cipher, text, suites, node, test, endpoint):
    if cipher in node:
        strong_node = node[cipher]
        if strong_node.get('status') == 'NOT_SCHEDULED':
            return None

        if 'accepted_cipher_suites' in strong_node and len(strong_node['accepted_cipher_suites']) > 0:
            unrecommended_cipher_found = False
            title = 'Unrecommended cipher suites for ' + text
            description = get_url(endpoint) + ' accepts unrecommended cipher suites for ' + text + ':'
            for cipher_node in strong_node['accepted_cipher_suites']:
                if 'cipher_suite' in cipher_node:
                    cs_node = cipher_node['cipher_suite']
                    if 'name' in cs_node and not cs_node['name'] in suites:
                        unrecommended_cipher_found = True
                        description += '\n - ' + cs_node['name']
            if unrecommended_cipher_found:
                return get_finding(title, description, None, REFERENCES, test, endpoint)

        elif 'result' in strong_node:
            strong_node_result = strong_node['result']
            unrecommended_cipher_found = False
            if 'accepted_cipher_suites' in strong_node_result and len(strong_node_result['accepted_cipher_suites']) > 0:
                title = 'Unrecommended cipher suites for ' + text
                description = get_url(endpoint) + ' accepts unrecommended cipher suites for ' + text + ':'
                for strong_node_result_cyphers in strong_node_result['accepted_cipher_suites']:
                    if 'cipher_suite' in strong_node_result_cyphers:
                        cs_node = strong_node_result_cyphers['cipher_suite']
                        if 'name' in cs_node and not cs_node['name'] in suites:
                            unrecommended_cipher_found = True
                            description += '\n - ' + cs_node['name']
                if unrecommended_cipher_found:
                    return get_finding(title, description, None, REFERENCES, test, endpoint)
        return None
    return None


def get_certificate_information(node, test, endpoint):
    if 'certificate_info' in node:
        ci_node = node['certificate_info']
        if ci_node.get('status') == 'NOT_SCHEDULED':
            return None
        if 'certificate_deployments' in ci_node:
            for cd_node in ci_node['certificate_deployments']:
                title = 'Problems in certificate deployments'
                description = get_url(endpoint) + ' has problems in certificate deployments:'
                vulnerable = False
                if 'leaf_certificate_subject_matches_hostname' in cd_node:
                    if not cd_node['leaf_certificate_subject_matches_hostname']:
                        vulnerable = True
                        description += '\n - Certificate subject does not match hostname'
                for pvr_node in cd_node['path_validation_results']:
                    if 'openssl_error_string' in pvr_node and pvr_node['openssl_error_string'] is not None:
                        vulnerable = True
                        name = None
                        version = None
                        if 'trust_store' in pvr_node:
                            ts_node = pvr_node['trust_store']
                            if 'name' in ts_node:
                                name = ts_node['name']
                            if 'version' in ts_node:
                                version = ts_node['version']
                        description += '\n - ' + pvr_node['openssl_error_string']
                        if name is not None:
                            description += ' for trust store ' + name
                        if version is not None:
                            description += ', version ' + version
                if vulnerable:
                    return get_finding(title, description, None, None, test, endpoint)

        elif 'result' in ci_node:
            ci_node_result = ci_node['result']
            if 'certificate_deployments' in ci_node_result:
                for cd_node in ci_node_result['certificate_deployments']:
                    title = 'Problems in certificate deployments'
                    description = get_url(endpoint) + ' has problems in certificate deployments:'
                    vulnerable = False
                    if 'leaf_certificate_subject_matches_hostname' in cd_node:
                        if not cd_node['leaf_certificate_subject_matches_hostname']:
                            vulnerable = True
                            description += '\n - Certificate subject does not match hostname'
                    for pvr_node in cd_node['path_validation_results']:
                        if 'openssl_error_string' in pvr_node and pvr_node['openssl_error_string'] is not None:
                            vulnerable = True
                            name = None
                            version = None
                            if 'trust_store' in pvr_node:
                                ts_node = pvr_node['trust_store']
                                if 'name' in ts_node:
                                    name = ts_node['name']
                                if 'version' in ts_node:
                                    version = ts_node['version']
                            description += '\n - ' + pvr_node['openssl_error_string']
                            if name is not None:
                                description += ' for trust store ' + name
                            if version is not None:
                                description += ', version ' + version
                    if vulnerable:
                        return get_finding(title, description, None, None, test, endpoint)
        return None
    return None


def get_finding(title, description, cve, references, test, endpoint):
    title += ' (' + get_url(endpoint) + ')'
    severity = 'Medium'
    finding = Finding(
        title=title,
        test=test,
        cve=cve,
        description=description,
        severity=severity,
        references=references,
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

    elif 'server_location' in node:
        si_node = node['server_location']
        if 'hostname' in si_node:
            hostname = si_node['hostname']
        if 'port' in si_node:
            port = si_node['port']
    if hostname is not None:
        return Endpoint(
            host=hostname,
            port=port)
    else:
        return None
