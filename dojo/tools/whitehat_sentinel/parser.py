__author__ = 'Chris Fort'

import json
import logging
import re
from typing import Union

from dojo.models import Finding

logger = logging.getLogger(__name__)


class WhiteHatSentinelParser(object):
	"""
	A class to parse WhiteHat Sentinel vulns from the WhiteHat Sentinel API vuln?query_site=[
	SITE_ID]&format=json&display_attack_vectors=all&display_custom_risk=1&display_risk=1&display_description=custom
	"""

	def get_findings(self, file, test):

		# Exit if file is not provided
		if file is None:
			return list()

		# Load the contents of the JSON file into a dictionary
		data = file.read()
		try:
			vulns_export_dict = json.loads(str(data, 'utf-8'))
		except:
			vulns_export_dict = json.loads(data)

		# Exit if file is an empty JSON dictionary
		if len(vulns_export_dict.keys()) == 0:
			return list()

		# Make sure the findings key exists in the dictionary and that it is not null or an empty list
		# If it is null or an empty list then exit
		if 'collection' not in vulns_export_dict or not vulns_export_dict['collection']:
			return list()

		# Start with an empty list of findings
		items = list()

		# If we have gotten this far then there should be one or more vulns
		# Loop through each vuln from WhiteHat
		for dependency_track_vuln in vulns_export_dict['collection']:
			# Convert a WhiteHat Vuln with Attack Vectors to a list of DefectDojo findings
			dojo_findings = self._convert_whitehat_sentinel_vuln_to_dojo_finding(dependency_track_vuln, test)

			# Extend DefectDojo findings to list
			items.extend(dojo_findings)
		return items

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
				return tag

	def _parse_description(self, whitehat_sentinel_description: str):
		"""
		Converts the HTML description to a DefectDojo-friendly format
		:param whitehat_sentinel_description: The description section of the WhiteHat Sentinel JSON
		:returns: A DefectDojo formatted description string+
		"""

		description_ref = dict()

		reference_heading_regex = '<h\d>References<\/h\d>'
		description_chunks = re.split(reference_heading_regex, whitehat_sentinel_description)

		description = description_chunks[0]

		description_ref['description'] = self.__remove_paragraph_tags(description)

		if len(description_chunks) > 1:
			description_ref['reference_link'] = self.__get_href_url(description_chunks[1])

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


	def _parse_steps_to_reproduce(self, whitehat_sentinel_description: str) -> str:
		"""

		"""
		pass

	def _parse_references(self, whitehat_sentinel_description: str) -> str:
		"""

		"""
		pass

	def __get_href_url(self, text_to_search):
		return re.search(r'(<a href=")(https://\S+)">', text_to_search)

	def __remove_paragraph_tags(self, text):


		return re.sub(r'<p>|</p>', '', text)


	def _convert_whitehat_sentinel_vuln_to_dojo_finding(self, whitehat_sentinel_vuln, test):

		for attack_vector in whitehat_sentinel_vuln['attack_vectors']:

			active = attack_vector.get('state') in ('open', 'out of scope')
			date_created = attack_vector.get('found').split('T')[0]


	def _convert_whitehat_sentinel_vuln_to_dojo_finding(self, whitehat_sentinel_vuln, test):
		"""
		Converts a WhiteHat Sentinel finding to a DefectDojo finding

		:param whitehat_sentinel_vuln:
		:param test: The test that the DefectDojo finding should be associated to
		:return: A DefectDojo Finding model
		"""

		# Out of scope is considered Active because the issue is valid, just not for the asset in question.
		active = whitehat_sentinel_vuln.get('status') in ('open', 'out of scope')

		date_created = whitehat_sentinel_vuln['opened'].split('T')[0]

		mitigated_ts = whitehat_sentinel_vuln.get('closed'.split('T')[0], None)

		cwe = self._parse_cwe_from_tags(whitehat_sentinel_vuln['tags'])

		description = self._parse_description(whitehat_sentinel_vuln.get['description'])

		risk_id = whitehat_sentinel_vuln.get('custom_risk') if whitehat_sentinel_vuln.get(
			'custom_risk') else whitehat_sentinel_vuln.get('risk')

		severity = self._convert_whitehat_severity_id_to_dojo_severity(risk_id)

		false_positive = whitehat_sentinel_vuln.get('status') == 'invalid'

		return Finding(title = whitehat_sentinel_vuln['class'],
		               test = test,
		               cwe = cwe,
		               active = active,
		               verified = True,
		               description = description,
		               severity = severity,
		               numerical_severity = Finding.get_numerical_severity(severity),
		               false_p = false_positive,
		               date = date_created,
		               is_Mitigated = whitehat_sentinel_vuln.get('mitigated', False),
		               mitigated = mitigated_ts,
		               mitigation = '',
		               last_reviewed = whitehat_sentinel_vuln.get('lastRetested', None),
		               dynamic_finding = True,
		               created = date_created,
		               date_found = date_created,
		               unique_id_from_tool = whitehat_sentinel_vuln['id'],
		               url = whitehat_sentinel_vuln.get('')
		               )
