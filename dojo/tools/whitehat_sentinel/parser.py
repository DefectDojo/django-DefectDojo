__author__ = 'Chris Fort'

import json
import logging
import re
from typing import Union, List
from urllib.parse import urlparse


from dojo.models import Finding, Endpoint

logger = logging.getLogger(__name__)


class WhiteHatSentinelParser(object):
    """
    A class to parse WhiteHat Sentinel vulns from the WhiteHat Sentinel API vuln?query_site=[
    SITE_ID]&format=json&display_attack_vectors=all&display_custom_risk=1&display_risk=1&display_description=custom
    """

    def get_scan_types(self):
        return ["WhiteHat Sentinel"]

    def get_label_for_scan_types(self, scan_type):
        return "WhiteHat Sentinel"

    def get_description_for_scan_types(self, scan_type):
        return "WhiteHat Sentinel output from api/vuln/query_site can be imported in JSON format."

    def get_findings(self, file, test):

        # Exit if file is not provided
        if file is None:
            return []

        # Load the contents of the JSON file into a dictionary
        data = file.read()

        try:
            findings_collection = json.loads(str(data, 'utf-8'))
        except:
            findings_collection = json.loads(data)

        # Exit if file is an empty JSON dictionary
        if not findings_collection.keys():
            return list()

        # Make sure the findings key exists in the dictionary and that it is not null or an empty list
        # If it is null or an empty list then exit
        if 'collection' not in findings_collection or not findings_collection['collection']:
            return list()

        # Start with an empty list of findings
        dojo_findings = []

        # Loop through each vuln from WhiteHat
        for whitehat_vuln in findings_collection['collection']:
            # Convert a WhiteHat Vuln with Attack Vectors to a list of DefectDojo findings
            dojo_finding = self._convert_whitehat_sentinel_vuln_to_dojo_finding(whitehat_vuln, test)

            # Append DefectDojo findings to list
            dojo_findings.append(dojo_finding)
        return dojo_findings

    def _convert_whitehat_severity_id_to_dojo_severity(self, whitehat_severity_id: int) -> Union[str, None]:
        """
        Converts a WhiteHat Sentinel numerical severity to a DefectDojo severity.
        :param whitehat_severity_id: The WhiteHat Severity ID
        :return A DefectDojo severity if a mapping can be found; otherwise a null value is returned
        """
        severities = ['Informational', 'Informational', 'Low', 'Medium', 'High', 'Critical', 'Critical']

        try:
            return severities[int(whitehat_severity_id)]
        except IndexError:
            return None

    def _parse_cwe_from_tags(self, whitehat_sentinel_tags) -> str:

        for tag in whitehat_sentinel_tags:
            if tag.startswith('CWE-'):
                return tag.split('-')[1]

    def _parse_description(self, whitehat_sentinel_description: str):
        """
        Converts the HTML description to a DefectDojo-friendly format
        :param whitehat_sentinel_description: The description section of the WhiteHat Sentinel JSON
        :returns: A dict with description and reference link
        """

        description_ref = {'description': '', 'reference_link': ''}

        reference_heading_regex = '<h\d>References<\/h\d>'
        description_chunks = re.split(reference_heading_regex, whitehat_sentinel_description['description'])

        description = description_chunks[0]

        description_ref['description'] = self.__remove_paragraph_tags(description)

        if len(description_chunks) > 1:
            description_ref['reference_link'] = self.__get_href_url(description_chunks[1])

        return description_ref

    def _parse_mitigation(self, whitehat_sentinel_solution: str) -> str:
        """
        :param whitehat_sentinel_solution:
        :returns:
        """

        solution_ref = dict()

        reference_heading_regex = '<h\d>References<\/h\d>'

        solution_chunks = re.split(reference_heading_regex, whitehat_sentinel_solution)

        solution_ref['solution'] = self.__remove_paragraph_tags(solution_chunks[0])

        if len(solution_chunks) > 1:
            solution_ref['reference_link'] = self.__get_href_url(solution_chunks[1])


    def _parse_references(self, whitehat_sentinel_description: str) -> str:
        """

        """
        pass

    def __get_href_url(self, text_to_search):
        return re.search(r'(<a href=")(https://\S+)">', text_to_search)

    def __remove_paragraph_tags(self, text):

        return re.sub(r'<p>|</p>', '', text)


    def _convert_attack_vectors_to_endpoints(self, attack_vectors: List['str']) -> List['Endpoint']:

        endpoints_list = []

        for attack_vector in attack_vectors:
            try:
                url = attack_vector['url']
                parsed_url = urlparse(url)
                protocol = parsed_url.scheme
                query = parsed_url.query
                fragment = parsed_url.fragment
                path = parsed_url.path
                port = ""
                try:
                    host, port = parsed_url.netloc.split(':')
                except ValueError:
                    host = parsed_url.netloc

                endpoints_list.append(Endpoint(host = host,
                                               port = port,
                                               path = path,
                                               protocol = protocol,
                                               query = query,
                                               fragment = fragment)
                                      )
            except:
                url = None

        return endpoints_list

    def _parse_solution(self, whitehat_sentinel_vuln_solution):
        """
        Manually converts the solution HTML to Markdown to avoid importing yet-another-library.
        """

        solution_html = whitehat_sentinel_vuln_solution['solution']

        solution_text = re.sub(r'<.+>','',solution_html)

        solution_text = solution_text.split('References')[0]

        if whitehat_sentinel_vuln_solution.get('solution_prepend'):
            solution_text = f"{solution_text}" \
                            f"\n {whitehat_sentinel_vuln_solution.get('solution_prepend')}"

        return solution_text

    def _convert_whitehat_sentinel_vuln_to_dojo_finding(self, whitehat_sentinel_vuln, test):
        """
        Converts a WhiteHat Sentinel vuln to a DefectDojo finding

        :param whitehat_sentinel_vuln:
        :param test: The test that the DefectDojo finding should be associated to
        :return: A DefectDojo Finding model
        """

        # Out of scope is considered Active because the issue is valid, just not for the asset in question.
        active = whitehat_sentinel_vuln.get('status') in ('open', 'out of scope')

        date_created = whitehat_sentinel_vuln['found'].split('T')[0]

        mitigated_ts = whitehat_sentinel_vuln.get('closed'.split('T')[0], None)

        cwe = self._parse_cwe_from_tags(whitehat_sentinel_vuln['attack_vectors'][0]['scanner_tags'])

        description_ref = self._parse_description(whitehat_sentinel_vuln['description'])

        description = description_ref['description']
        references = description_ref['reference_link']

        steps = whitehat_sentinel_vuln['description'].get('description_prepend', '')

        solution = self._parse_solution(whitehat_sentinel_vuln['solution'])

        risk_id = whitehat_sentinel_vuln.get('custom_risk') if whitehat_sentinel_vuln.get(
            'custom_risk') else whitehat_sentinel_vuln.get('risk')

        severity = self._convert_whitehat_severity_id_to_dojo_severity(risk_id)

        false_positive = whitehat_sentinel_vuln.get('status') == 'invalid'

        finding = Finding(title = whitehat_sentinel_vuln['class'],
                          test = test,
                          cwe = cwe,
                          active = active,
                          verified = True,
                          description = description,
                          steps_to_reproduce = steps,
                          mitigation = solution,
                          references = references,
                          severity = severity,
                          numerical_severity = Finding.get_numerical_severity(severity),
                          false_p = false_positive,
                          date = date_created,
                          is_Mitigated = whitehat_sentinel_vuln.get('mitigated', False),
                          mitigated = mitigated_ts,
                          last_reviewed = whitehat_sentinel_vuln.get('lastRetested', None),
                          dynamic_finding = True,
                          created = date_created,
                          unique_id_from_tool = whitehat_sentinel_vuln['id'],
                          url = whitehat_sentinel_vuln.get('')
                          )

        # Get Endpoints from Attack Vectors
        endpoints = self._convert_attack_vectors_to_endpoints(whitehat_sentinel_vuln['attack_vectors'])

        finding.unsaved_endpoints = endpoints

        return finding
