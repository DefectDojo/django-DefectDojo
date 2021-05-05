import json
import logging
import re
from typing import Union, List
from urllib.parse import urlparse

from dojo.models import Finding, Endpoint


class WhiteHatSentinelParser(object):
    """
    A class to parse WhiteHat Sentinel vulns from the WhiteHat Sentinel API vuln?query_site=[
    SITE_ID]&format=json&display_attack_vectors=all&display_custom_risk=1&display_risk=1&display_description=custom
    """

    _LOGGER = logging.getLogger(__name__)

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

        findings_collection = json.load(file)

        if not findings_collection.keys():
            return list()

        # Make sure the findings key exists in the dictionary and that it is not null or an empty list
        if 'collection' not in findings_collection.keys() or not findings_collection['collection']:
            raise ValueError('collection key not present or there were not findings present.')

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
        Args:
            whitehat_severity_id: The WhiteHat Severity ID (called risk_id in the API)
        Returns: A DefectDojo severity if a mapping can be found; otherwise a null value is returned
        """
        severities = ['Informational', 'Informational', 'Low', 'Medium', 'High', 'Critical', 'Critical']

        try:
            return severities[int(whitehat_severity_id)]
        except IndexError:
            return None

    def _parse_cwe_from_tags(self, whitehat_sentinel_tags) -> str:
        """
        Some Vulns include the CWE ID as a tag. This is used to pull it out of that list and return only the ID.
        Args:
            whitehat_sentinel_tags: The Tags list from the WhiteHat vuln
        Returns: The first CWE ID in the list, if it exists
        """
        for tag in whitehat_sentinel_tags:
            if tag.startswith('CWE-'):
                return tag.split('-')[1]

    def _parse_description(self, whitehat_sentinel_description: dict):
        """
        Manually converts the HTML description to a DefectDojo-friendly format.
        Args:
            whitehat_sentinel_description: The description section of the WhiteHat Sentinel vulnerability dict
        Returns: A dict with description and reference link
        """

        description_ref = {'description': '', 'reference_link': ''}

        # The references section is always between <h2> or <strong> tags
        reference_heading_regex = '<.+>References<.+>'

        description_chunks = re.split(reference_heading_regex, whitehat_sentinel_description['description'])

        description = description_chunks[0]

        description_ref['description'] = self.__remove_paragraph_tags(description)

        if len(description_chunks) > 1:
            description_ref['reference_link'] = self.__get_href_url(description_chunks[1])

        return description_ref

    def _parse_solution(self, whitehat_sentinel_vuln_solution):
        """
        Manually converts the solution HTML to Markdown to avoid importing yet-another-library like Markdownify
        Args:
            whitehat_sentinel_vuln_solution:

        Returns:

        """
        solution_html = whitehat_sentinel_vuln_solution['solution']

        solution_text = re.sub(r'<.+>', '', solution_html)

        solution_text = solution_text.split('References')[0]

        if whitehat_sentinel_vuln_solution.get('solution_prepend'):
            solution_text = f"{solution_text}" \
                            f"\n {whitehat_sentinel_vuln_solution.get('solution_prepend')}"

        return solution_text

    def __get_href_url(self, text_to_search):
        """
        Searches for the anchor targets within a string that includes an anchor tag.
        Args:
            text_to_search: The text string to search for an anchor tag
        Returns:
        """

        links = ''

        for match in re.findall(r'(<a href=")(https://\S+)">', text_to_search):
            links = f'{match[1]}\n{links}'
        return links

    def __remove_paragraph_tags(self, html_string):
        """
        Manually remove <p> tags from HTML strings to avoid importing yet-another-library.
        Args:
            html_string: The HMTL string to remove <p> </p> tags from
        Returns: The original string stipped of paragraph tags
        """

        return re.sub(r'<p>|</p>', '', html_string)

    def _convert_attack_vectors_to_endpoints(self, attack_vectors: List[dict]) -> List['Endpoint']:
        """
        Takes a list of Attack Vectors dictionaries from the WhiteHat vuln API and converts them to Defect Dojo
        Endpoints
        Args:
            attack_vectors: The list of Attack Vector dictionaries
        Returns: A list of Defect Dojo Endpoints
        """

        endpoints_list = []

        # This should be in the Endpoint class should it not?
        for attack_vector in attack_vectors:
            try:
                url = attack_vector['request']['url']
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

                endpoints_list.append(Endpoint(host=host,
                                               port=port,
                                               path=path,
                                               protocol=protocol,
                                               query=query,
                                               fragment=fragment)
                                      )
            except Exception:
                pass

        return endpoints_list

    def _convert_whitehat_sentinel_vuln_to_dojo_finding(self, whitehat_sentinel_vuln, test):
        """
        Converts a WhiteHat Sentinel vuln to a DefectDojo finding

        Args:
            whitehat_sentinel_vuln: The vuln dictionary from WhiteHat Sentinel vuln API
            test: The test ID that the DefectDojo finding should be associated with
        Returns: A DefectDojo Finding object
        """

        date_created = whitehat_sentinel_vuln['found'].split('T')[0]
        mitigated_ts = whitehat_sentinel_vuln.get('closed'.split('T')[0], None)
        cwe = self._parse_cwe_from_tags(whitehat_sentinel_vuln['attack_vectors'][0].get('scanner_tags', []))
        description_ref = self._parse_description(whitehat_sentinel_vuln['description'])
        description = description_ref['description']
        references = description_ref['reference_link']
        steps = whitehat_sentinel_vuln['description'].get('description_prepend', '')
        solution = self._parse_solution(whitehat_sentinel_vuln['solution'])
        risk_id = whitehat_sentinel_vuln.get('custom_risk') if whitehat_sentinel_vuln.get(
            'custom_risk') else whitehat_sentinel_vuln.get('risk')
        severity = self._convert_whitehat_severity_id_to_dojo_severity(risk_id)
        false_positive = whitehat_sentinel_vuln.get('status') == 'invalid'

        # WhiteHat has the following statuses: open, closed, out of scope, accepted, invalid, mitigated.
        # Out of scope is considered active because the vulnerability is valid, just not for the specified WhiteHat
        # Asset. This is often the case when a vulnerability is found in a sister product like an authentication or
        # notification service.
        active = whitehat_sentinel_vuln.get('status') in ('open', 'out of scope')
        is_mitigated = not active

        finding = Finding(title=whitehat_sentinel_vuln['class'],
                          test=test,
                          cwe=cwe,
                          active=active,
                          verified=True,
                          description=description,
                          steps_to_reproduce=steps,
                          mitigation=solution,
                          references=references,
                          severity=severity,
                          false_p=false_positive,
                          date=date_created,
                          is_mitigated=is_mitigated,
                          mitigated=mitigated_ts,
                          last_reviewed=whitehat_sentinel_vuln.get('lastRetested', None),
                          dynamic_finding=True,
                          created=date_created,
                          unique_id_from_tool=whitehat_sentinel_vuln['id']
                          )

        # Get Endpoints from Attack Vectors
        endpoints = self._convert_attack_vectors_to_endpoints(whitehat_sentinel_vuln['attack_vectors'])

        finding.unsaved_endpoints = endpoints

        return finding
