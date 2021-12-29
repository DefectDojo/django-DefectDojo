import sys
import io
import csv
from datetime import datetime
from dojo.models import Finding


class AzureSecurityCenterRecommendationsParser(object):

    def get_scan_types(self):
        return ["Azure Security Center Recommendations Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Azure Security Center Recommendations Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Import of Microsoft Defender for Cloud (formerly known as Azure Security Center) recommendations in CSV format."

    def get_findings(self, file, test):
        if file.name.lower().endswith('.csv'):
            return self.process_csv(file, test)
        else:
            raise ValueError('Unknown file format')

    def process_csv(self, file, test):
        content = file.read()
        if type(content) is bytes:
            content = content.decode('utf-8')
        csv.field_size_limit(int(sys.maxsize / 10))  # the request/resp are big
        reader = csv.DictReader(io.StringIO(content))

        findings = []

        for row in reader:
            if 'unhealthy' == row.get('state').lower():
                subscription_id = row.get('subscriptionId')
                subscription_name = row.get('subscriptionName')
                resource_group = row.get('resourceGroup')
                resource_type = row.get('resourceType')
                resource_name = row.get('resourceName')
                # resourceId doesn't give additional information and can be ignored
                # resource_id = row.get('resourceId')
                recommendation_id = row.get('recommendationId')
                recommendation_name = row.get('recommendationName')
                recommendation_display_name = row.get('recommendationDisplayName')
                azure_description = row.get('description')
                remediation_steps = row.get('remediationSteps')
                severity = row.get('severity')
                # firstEvaluationDate is where the Security Center was started the first time
                # firstEvaluationDate = row.get('firstEvaluationDate')
                status_change_date = row.get('statusChangeDate')
                controls = row.get('controls')
                azure_portal_recommendation_link = row.get('azurePortalRecommendationLink')
                native_cloud_account_id = row.get('nativeCloudAccountId')

                if resource_name == subscription_id:
                    resource_name = subscription_name

                title = f'{resource_name} - {recommendation_display_name}'

                if controls.startswith('{"'):
                    controls = controls[controls.find('{"') + 2:controls.find('":')]

                description = "**Recommendation:** " + recommendation_display_name + \
                    "\n**Resource Name:** " + resource_name + \
                    "\n**Resource Type:** " + resource_type
                if resource_group:
                    description += "\n**Resource Group:** " + resource_group
                description += "\n**Description:** " + azure_description + \
                    "\n**Controls:** " + controls + \
                    "\n**Subscription:** " + subscription_name + \
                    "\n**Subscription Id:** " + subscription_id
                if native_cloud_account_id:
                    description += "\n**Native Cloud Account Id:** " + native_cloud_account_id

                findings.append(Finding(
                    title=title,
                    cwe=1032,  # Security Configuration Weaknesses
                    test=test,
                    description=description,
                    severity=severity,
                    references=azure_portal_recommendation_link,
                    mitigation=remediation_steps,
                    date=datetime.strptime(status_change_date[0:10], '%Y-%m-%d').date(),
                    vuln_id_from_tool=recommendation_name,
                    unique_id_from_tool=recommendation_id,
                    static_finding=True,
                    dynamic_finding=False,
                ))

        return findings
