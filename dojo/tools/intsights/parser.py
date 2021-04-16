import json
from urllib.parse import urlparse

from dojo.models import Endpoint, Finding


class IntSightsParser(object):
	"""
	IntSights Threat Intelligence Feed
	"""

	def get_scan_types(self):
		return ["IntSights Scan"]

	def get_label_for_scan_types(self, scan_type):
		return "IntSights Scan"

	def get_description_for_scan_types(self, scan_type):
		return "IntSights report file can be imported in JSON format."

	def get_findings(self, file, test):
		duplicates = dict()
		data = file.read()

		try:
			findings = json.loads(str(data, 'utf-8'))
		except:
			findings = json.loads(data)

		for finding in findings['Findings']:
			unique_id_from_tool = finding['_id']
			title = finding['Details']['Title']
			description = f'{finding["Details"]["Description"]}' \
			              f'\r\n\r\n----' \
			              f'\r\n\r\n**Type**: {finding["Details"]["Type"]}' \
			              f'\r\n**SubType**: {finding["Details"]["SubType"]}' \
			              f'\r\n**Source**: {finding["Details"]["Source"]["URL"]}' \
			              f'\r\n**Source Type**: {finding["Details"]["Source"]["Type"]}' \
			              f'\r\n**Source Network Type**: {finding["Details"]["Source"]["NetworkType"]}' \
			              f'\r\n\r\n----' \
			              f'\r\n**Asset Type**: {finding["Assets"][0]["Type"]}' \
			              f'\r\n\r\n----' \
			              f'\r\n**Takedown Status**: {finding["TakedownStatus"]}'
			severity = finding['Details']['Severity']
			mitigation = "N/A"
			impact = "N/A"
			references = finding["Details"]["Source"]["URL"]
			output = "N/A"
			active = False if finding['Closed']['IsClosed'] else True
			try:
				url = finding["Assets"][0]["Value"]
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
			except:
				url = None

			dupe_key = finding['_id']

			if dupe_key in duplicates:
				finding = duplicates[dupe_key]
				duplicates[dupe_key] = finding
			else:
				duplicates[dupe_key] = True

				finding = Finding(title = title,
				                  test = test,
				                  active = active,
				                  verified = True,
				                  description = description,
				                  severity = severity,
				                  numerical_severity = Finding.get_numerical_severity(severity),
				                  mitigation = mitigation,
				                  impact = impact,
				                  references = references,
				                  static_finding = False,
				                  dynamic_finding = True,
				                  unique_id_from_tool = unique_id_from_tool)
				finding.unsaved_endpoints = list()
				duplicates[dupe_key] = finding

				if url is not None:
					finding.unsaved_endpoints.append(Endpoint(
						host = host, port = port,
						path = path,
						protocol = protocol,
						query = query, fragment = fragment))
		return duplicates.values()
