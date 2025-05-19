import json
from io import StringIO

from dojo.models import Test
from dojo.tools.prowler.parser import ProwlerParser
from unittests.dojo_test_case import DojoTestCase


class TestProwlerStringIOParser(DojoTestCase):
    def test_empty_csv_parser_stringio(self):
        """Tests that an empty CSV file doesn't generate any findings."""
        file_content = StringIO(
            "ASSESSMENT_START_TIME;ASSESSMENT_END_TIME;ACCOUNT_UID;ACCOUNT_NAME;ACCOUNT_SUBSCRIPTION;ACCOUNT_ORGANIZATION_UID;ACCOUNT_ORGANIZATION_NAME;ACCOUNT_TAGS;FINDING_UID;PROVIDER;CHECK_ID;CHECK_TITLE;CHECK_TYPE;STATUS;STATUS_EXTENDED;MUTED;SERVICE_NAME;SUBSERVICE_NAME;SEVERITY;RESOURCE_TYPE;RESOURCE_UID;RESOURCE_NAME;RESOURCE_DETAILS;RESOURCE_TAGS;PARTITION;REGION;DESCRIPTION;RISK;RELATED_URL;REMEDIATION_RECOMMENDATION_TEXT;REMEDIATION_RECOMMENDATION_URL;REMEDIATION_CODE_NATIVEIAC;REMEDIATION_CODE_TERRAFORM;REMEDIATION_CODE_CLI;REMEDIATION_CODE_OTHER;COMPLIANCE;CATEGORIES;DEPENDS_ON;RELATED_TO;NOTES;PROWLER_VERSION",
        )
        parser = ProwlerParser()
        findings = parser.get_findings(file_content, Test())
        self.assertEqual(0, len(findings))

    def test_aws_csv_parser_stringio(self):
        """Tests that a AWS CSV file with one finding produces correct output."""
        file_content = StringIO("""ASSESSMENT_START_TIME;ASSESSMENT_END_TIME;ACCOUNT_UID;ACCOUNT_NAME;ACCOUNT_SUBSCRIPTION;ACCOUNT_ORGANIZATION_UID;ACCOUNT_ORGANIZATION_NAME;ACCOUNT_TAGS;FINDING_UID;PROVIDER;CHECK_ID;CHECK_TITLE;CHECK_TYPE;STATUS;STATUS_EXTENDED;MUTED;SERVICE_NAME;SUBSERVICE_NAME;SEVERITY;RESOURCE_TYPE;RESOURCE_UID;RESOURCE_NAME;RESOURCE_DETAILS;RESOURCE_TAGS;PARTITION;REGION;DESCRIPTION;RISK;RELATED_URL;REMEDIATION_RECOMMENDATION_TEXT;REMEDIATION_RECOMMENDATION_URL;REMEDIATION_CODE_NATIVEIAC;REMEDIATION_CODE_TERRAFORM;REMEDIATION_CODE_CLI;REMEDIATION_CODE_OTHER;COMPLIANCE;CATEGORIES;DEPENDS_ON;RELATED_TO;NOTES;PROWLER_VERSION
2023-09-27 09:41:37.760834;2023-09-27 09:41:38.065516;123456789012;test-aws;123456789012;;AWS;;74f356f4-e032-42d6-b2cf-1718edc92687;aws;iam_root_hardware_mfa_enabled;Ensure hardware MFA is enabled for the root account;security;FAIL;Hardware MFA is not enabled for the root account.;False;iam;;high;iam-account;123456789012;test-aws;;;;global;The test root account's hardware MFA device is not enabled.;If the root account doesn't have a hardware MFA, alternative mechanisms will be required to gain access to the account in case a password is lost or compromised. Without MFA or alternative mechanisms, it may be difficult or impossible to access the account.;https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_enable_virtual.html;Implement a hardware MFA for the root account;https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_enable_physical.html;;;aws iam enable-mfa-device;;PCI-DSS-3.2.1: 8.3.1, 8.3.2 | CIS-1.4: 1.6 | CIS-1.5: 1.6 | AWS-Foundational-Security-Best-Practices: iam, root-account | KISA-ISMS-P-2023: 2.7.3 | CIS-2.0: 1.6 | KISA-ISMS-P-2023-korean: 2.7.3 | AWS-Well-Architected-Framework-Security-Pillar: SEC01-BP05 | AWS-Account-Security-Onboarding: Prerequisites, MFA requirements for root user | CSA-CCM-4.0: DSP-07, IAM-10 | BSI-CS-C2: 3.3 | IceCat: Rule-2 | CIS-3.0: 1.6 | ENS-RD2022: mp.if.3.aws.iam.7;root-account, security-best-practices, permissions-management, compliance, conditional-access, csf-recovery, nist-id-am-2;;;Recommendation: Implement a hardware MFA device for the root account;1.0.0""")
        parser = ProwlerParser()
        findings = parser.get_findings(file_content, Test())
        self.assertEqual(1, len(findings))

        finding = findings[0]
        self.assertEqual(
            "iam_root_hardware_mfa_enabled: Ensure hardware MFA is enabled for the root account", finding.title,
        )
        self.assertEqual("iam_root_hardware_mfa_enabled", finding.vuln_id_from_tool)
        self.assertEqual("High", finding.severity)
        self.assertTrue(finding.active)
        self.assertIn("AWS", finding.unsaved_tags)
        self.assertIn("iam", finding.unsaved_tags)
        self.assertIn("Status: FAIL", finding.description)

    def test_aws_json_parser_stringio(self):
        """Tests that a AWS JSON file with one finding produces correct output."""
        data = {
            "message": "Hardware MFA is not enabled for the root account",
            "cloud": {
                "account": {"id": "123456789012", "name": "test-aws", "organization": {}},
                "provider": "aws",
                "region": "global",
            },
            "resources": [{"id": "123456789012", "name": "test-aws", "type": "iam-account", "details": {}}],
            "finding_info": {
                "title": "Ensure hardware MFA is enabled for the root account",
                "uid": "74f356f4-e032-42d6-b2cf-1718edc92687",
                "service": "iam",
                "severity": "high",
                "check_id": "iam_root_hardware_mfa_enabled",
            },
            "risk_details": "The test root account's hardware MFA device is not enabled.",
            "status_code": "fail",
            "status_detail": "Hardware MFA is not enabled for the root account.",
            "remediation": {
                "text": "Implement a hardware MFA for the root account",
                "url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_enable_physical.html",
            },
            "compliance": "PCI-DSS-3.2.1: 8.3.1, 8.3.2 | CIS-1.4: 1.6 | CIS-1.5: 1.6",
        }
        file_content = StringIO(json.dumps([data]))
        parser = ProwlerParser()
        findings = parser.get_findings(file_content, Test())
        self.assertEqual(1, len(findings))

        finding = findings[0]
        self.assertEqual("Hardware MFA is not enabled for the root account", finding.title)
        self.assertEqual("iam_root_hardware_mfa_enabled", finding.vuln_id_from_tool)
        self.assertEqual("High", finding.severity)
        self.assertTrue(finding.active)
        self.assertIn("aws", finding.unsaved_tags)
        self.assertIn("Status: fail", finding.description)

    def test_azure_csv_parser_stringio(self):
        """Tests that a Azure CSV file with one finding produces correct output."""
        file_content = StringIO("""ASSESSMENT_START_TIME;ASSESSMENT_END_TIME;ACCOUNT_UID;ACCOUNT_NAME;ACCOUNT_SUBSCRIPTION;ACCOUNT_ORGANIZATION_UID;ACCOUNT_ORGANIZATION_NAME;ACCOUNT_TAGS;FINDING_UID;PROVIDER;CHECK_ID;CHECK_TITLE;CHECK_TYPE;STATUS;STATUS_EXTENDED;MUTED;SERVICE_NAME;SUBSERVICE_NAME;SEVERITY;RESOURCE_TYPE;RESOURCE_UID;RESOURCE_NAME;RESOURCE_DETAILS;RESOURCE_TAGS;PARTITION;REGION;DESCRIPTION;RISK;RELATED_URL;REMEDIATION_RECOMMENDATION_TEXT;REMEDIATION_RECOMMENDATION_URL;REMEDIATION_CODE_NATIVEIAC;REMEDIATION_CODE_TERRAFORM;REMEDIATION_CODE_CLI;REMEDIATION_CODE_OTHER;COMPLIANCE;CATEGORIES;DEPENDS_ON;RELATED_TO;NOTES;PROWLER_VERSION
2025-02-14 14:27:30.710664;2025-02-14 14:27:30.710664;00000000-0000-0000-0000-000000000000;AzureSubscription;00000000-0000-0000-0000-000000000000;00000000-0000-0000-0000-000000000000;AzureTenant;;00000000-0000-0000-0000-000000000000;azure;iam_subscription_roles_owner_no_ad;Ensure Azure Active Directory Administrator Is Configured;;FAIL;Administrator not configured for SQL server testserver.;False;iam;;medium;Microsoft.Sql/servers;/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/testgroup/providers/Microsoft.Sql/servers/testserver;testserver;;sqlserver;global;eastus;Designating Azure AD administrator for SQL Server is recommended;;https://learn.microsoft.com/en-us/azure/azure-sql/database/logins-create-manage;Configure an Azure AD administrator for Azure SQL server;https://learn.microsoft.com/en-us/azure/azure-sql/database/authentication-aad-configure;;terraform code here;azure cli code here;;CIS-1.3.0: 4.3.6;security-best-practices, compliance;;;;1.0.0""")
        parser = ProwlerParser()
        findings = parser.get_findings(file_content, Test())
        self.assertEqual(1, len(findings))

        finding = findings[0]
        self.assertEqual(
            "iam_subscription_roles_owner_no_ad: Ensure Azure Active Directory Administrator Is Configured",
            finding.title,
        )
        self.assertEqual("iam_subscription_roles_owner_no_ad", finding.vuln_id_from_tool)
        self.assertEqual("Medium", finding.severity)
        self.assertTrue(finding.active)
        self.assertIn("AZURE", finding.unsaved_tags)
        self.assertIn("iam", finding.unsaved_tags)

    def test_azure_json_parser_stringio(self):
        """Tests that a Azure JSON file with one finding produces correct output."""
        data = {
            "message": "Administrator not configured for SQL server testserver",
            "cloud": {
                "account": {
                    "id": "00000000-0000-0000-0000-000000000000",
                    "name": "AzureSubscription",
                    "organization": {},
                },
                "provider": "azure",
                "region": "eastus",
            },
            "resources": [
                {
                    "id": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/testgroup/providers/Microsoft.Sql/servers/testserver",
                    "name": "testserver",
                    "type": "Microsoft.Sql/servers",
                    "details": {},
                },
            ],
            "finding_info": {
                "title": "Ensure Azure Active Directory Administrator Is Configured",
                "uid": "00000000-0000-0000-0000-000000000000",
                "service": "iam",
                "severity": "medium",
                "check_id": "iam_subscription_roles_owner_no_ad",
            },
            "risk_details": "Designating Azure AD administrator for SQL Server is recommended",
            "status_code": "fail",
            "status_detail": "Administrator not configured for SQL server testserver.",
            "remediation": {
                "text": "Configure an Azure AD administrator for Azure SQL server",
                "url": "https://learn.microsoft.com/en-us/azure/azure-sql/database/authentication-aad-configure",
            },
            "compliance": "CIS-1.3.0: 4.3.6",
        }
        file_content = StringIO(json.dumps([data]))
        parser = ProwlerParser()
        findings = parser.get_findings(file_content, Test())
        self.assertEqual(1, len(findings))

        finding = findings[0]
        self.assertEqual("Administrator not configured for SQL server testserver", finding.title)
        self.assertEqual("iam_subscription_roles_owner_no_ad", finding.vuln_id_from_tool)
        self.assertEqual("Medium", finding.severity)
        self.assertTrue(finding.active)
        self.assertIn("azure", finding.unsaved_tags)
        self.assertIn("Status: fail", finding.description)

    def test_gcp_csv_parser_stringio(self):
        """Tests that a GCP CSV file with one finding produces correct output."""
        file_content = StringIO("""ASSESSMENT_START_TIME;ASSESSMENT_END_TIME;ACCOUNT_UID;ACCOUNT_NAME;ACCOUNT_SUBSCRIPTION;ACCOUNT_ORGANIZATION_UID;ACCOUNT_ORGANIZATION_NAME;ACCOUNT_TAGS;FINDING_UID;PROVIDER;CHECK_ID;CHECK_TITLE;CHECK_TYPE;STATUS;STATUS_EXTENDED;MUTED;SERVICE_NAME;SUBSERVICE_NAME;SEVERITY;RESOURCE_TYPE;RESOURCE_UID;RESOURCE_NAME;RESOURCE_DETAILS;RESOURCE_TAGS;PARTITION;REGION;DESCRIPTION;RISK;RELATED_URL;REMEDIATION_RECOMMENDATION_TEXT;REMEDIATION_RECOMMENDATION_URL;REMEDIATION_CODE_NATIVEIAC;REMEDIATION_CODE_TERRAFORM;REMEDIATION_CODE_CLI;REMEDIATION_CODE_OTHER;COMPLIANCE;CATEGORIES;DEPENDS_ON;RELATED_TO;NOTES;PROWLER_VERSION
2025-01-01 10:00:00.000000;2025-01-01 10:10:00.000000;123456789012;gcp-project-name;;;;;123456789012-bc-gcp-networking-2-123456789012-456;gcp;bc_gcp_networking_2;Ensure that Firewall Rules do not allow access from 0.0.0.0/0 to Remote Desktop Protocol (RDP);;FAIL;Firewall rule default-allow-rdp allows 0.0.0.0/0 on port RDP.;False;firewall;;high;firewall;projects/gcp-project-name/global/firewalls/default-allow-rdp;default-allow-rdp;;;;global;TCP port 3389 is used for Remote Desktop Protocol. It should not be exposed to the internet.;Unrestricted access to TCP port 3389 from untrusted sources increases risks from external attackers.;https://cloud.google.com/vpc/docs/using-firewalls;Remove any 3389 port firewall rules that have source 0.0.0.0/0 or ::/0 in your VPC Network.;https://cloud.google.com/vpc/docs/using-firewalls;;;gcloud compute firewall-rules update default-allow-rdp --source-ranges=<trusted_source_ips>;https://www.trendmicro.com/cloudoneconformity/knowledge-base/gcp/CloudVPC/unrestricted-rdp-access.html;MITRE-ATTACK: T1190, T1199, T1048, T1498, T1046 | CIS-2.0: 3.7 | ENS-RD2022: mp.com.1.gcp.fw.1 | CIS-3.0: 3.7;internet-exposed;;;;1.0.0""")
        parser = ProwlerParser()
        findings = parser.get_findings(file_content, Test())
        self.assertEqual(1, len(findings))

        finding = findings[0]
        self.assertEqual(
            "bc_gcp_networking_2: Ensure that Firewall Rules do not allow access from 0.0.0.0/0 to Remote Desktop Protocol (RDP)",
            finding.title,
        )
        self.assertEqual("bc_gcp_networking_2", finding.vuln_id_from_tool)
        self.assertEqual("High", finding.severity)
        self.assertTrue(finding.active)
        self.assertIn("GCP", finding.unsaved_tags)
        self.assertIn("firewall", finding.unsaved_tags)

    def test_gcp_json_parser_stringio(self):
        """Tests that a GCP JSON file with one finding produces correct output."""
        data = {
            "message": "Firewall rule default-allow-rdp allows 0.0.0.0/0 on port RDP",
            "cloud": {
                "account": {"id": "123456789012", "name": "gcp-project-name", "organization": {}},
                "provider": "gcp",
                "region": "global",
            },
            "resources": [
                {
                    "id": "projects/gcp-project-name/global/firewalls/default-allow-rdp",
                    "name": "default-allow-rdp",
                    "type": "firewall",
                    "details": {},
                },
            ],
            "finding_info": {
                "title": "Ensure that Firewall Rules do not allow access from 0.0.0.0/0 to Remote Desktop Protocol (RDP)",
                "uid": "123456789012-bc-gcp-networking-2-123456789012-456",
                "service": "firewall",
                "severity": "high",
                "check_id": "bc_gcp_networking_2",
            },
            "risk_details": "TCP port 3389 is used for Remote Desktop Protocol. It should not be exposed to the internet.",
            "status_code": "fail",
            "status_detail": "Firewall rule default-allow-rdp allows 0.0.0.0/0 on port RDP.",
            "remediation": {
                "text": "Remove any 3389 port firewall rules that have source 0.0.0.0/0 or ::/0 in your VPC Network.",
                "url": "https://cloud.google.com/vpc/docs/using-firewalls",
            },
            "compliance": "MITRE-ATTACK: T1190, T1199 | CIS-2.0: 3.7",
        }
        file_content = StringIO(json.dumps([data]))
        parser = ProwlerParser()
        findings = parser.get_findings(file_content, Test())
        self.assertEqual(1, len(findings))

        finding = findings[0]
        self.assertEqual("Firewall rule default-allow-rdp allows 0.0.0.0/0 on port RDP", finding.title)
        self.assertEqual("bc_gcp_networking_2", finding.vuln_id_from_tool)
        self.assertEqual("High", finding.severity)
        self.assertTrue(finding.active)
        self.assertIn("gcp", finding.unsaved_tags)
        self.assertIn("Status: fail", finding.description)

    def test_kubernetes_csv_parser_stringio(self):
        """Tests that a Kubernetes CSV file with one finding produces correct output."""
        file_content = StringIO("""ASSESSMENT_START_TIME;ASSESSMENT_END_TIME;ACCOUNT_UID;ACCOUNT_NAME;ACCOUNT_SUBSCRIPTION;ACCOUNT_ORGANIZATION_UID;ACCOUNT_ORGANIZATION_NAME;ACCOUNT_TAGS;FINDING_UID;PROVIDER;CHECK_ID;CHECK_TITLE;CHECK_TYPE;STATUS;STATUS_EXTENDED;MUTED;SERVICE_NAME;SUBSERVICE_NAME;SEVERITY;RESOURCE_TYPE;RESOURCE_UID;RESOURCE_NAME;RESOURCE_DETAILS;RESOURCE_TAGS;PARTITION;REGION;DESCRIPTION;RISK;RELATED_URL;REMEDIATION_RECOMMENDATION_TEXT;REMEDIATION_RECOMMENDATION_URL;REMEDIATION_CODE_NATIVEIAC;REMEDIATION_CODE_TERRAFORM;REMEDIATION_CODE_CLI;REMEDIATION_CODE_OTHER;COMPLIANCE;CATEGORIES;DEPENDS_ON;RELATED_TO;NOTES;PROWLER_VERSION
2025-02-01 10:00:00.000000;2025-02-01 10:10:00.000000;k8s-cluster;kubernetes;;;;;"k8s-cluster-bc_k8s_pod_security_1-543";kubernetes;bc_k8s_pod_security_1;Ensure that admission control plugin AlwaysPullImages is set;;FAIL;The admission control plugin AlwaysPullImages is not set.;False;cluster-security;;medium;kubernetes-cluster;k8s-cluster;apiserver-01;;;;;"The AlwaysPullImages admission controller forces every new pod to pull the required images every time they are instantiated. In a multitenant or untrusted environment, this reduces the chance for a malicious user to use pre-pulled images.";Without AlwaysPullImages, once an image is pulled to a node, any pod can use it without any authorization check, potentially leading to security risks.;https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/#alwayspullimages;Configure the API server to use the AlwaysPullImages admission control plugin to ensure image security and integrity.;https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers;https://docs.prowler.com/checks/kubernetes/kubernetes-policy-index/ensure-that-the-admission-control-plugin-alwayspullimages-is-set#kubernetes;;--enable-admission-plugins=...,AlwaysPullImages,...;;CIS-1.10: 1.2.11 | CIS-1.8: 1.2.11;cluster-security;;;Enabling AlwaysPullImages can increase network and registry load and decrease container startup speed. It may not be suitable for all environments.;1.0.0""")
        parser = ProwlerParser()
        findings = parser.get_findings(file_content, Test())
        self.assertEqual(1, len(findings))

        finding = findings[0]
        self.assertEqual(
            "bc_k8s_pod_security_1: Ensure that admission control plugin AlwaysPullImages is set", finding.title,
        )
        self.assertEqual("bc_k8s_pod_security_1", finding.vuln_id_from_tool)
        self.assertEqual("Medium", finding.severity)
        self.assertTrue(finding.active)
        self.assertIn("KUBERNETES", finding.unsaved_tags)
        self.assertIn("cluster-security", finding.unsaved_tags)

    def test_kubernetes_json_parser_stringio(self):
        """Tests that a Kubernetes JSON file with one finding produces correct output."""
        data = {
            "message": "The admission control plugin AlwaysPullImages is not set",
            "cloud": {
                "account": {"id": "k8s-cluster", "name": "kubernetes", "organization": {}},
                "provider": "kubernetes",
                "region": "",
            },
            "resources": [{"id": "k8s-cluster", "name": "apiserver-01", "type": "kubernetes-cluster", "details": {}}],
            "finding_info": {
                "title": "Ensure that admission control plugin AlwaysPullImages is set",
                "uid": "k8s-cluster-bc_k8s_pod_security_1-543",
                "service": "cluster-security",
                "severity": "medium",
                "check_id": "bc_k8s_pod_security_1",
            },
            "risk_details": "The AlwaysPullImages admission controller forces every new pod to pull the required images every time they are instantiated. In a multitenant or untrusted environment, this reduces the chance for a malicious user to use pre-pulled images.",
            "status_code": "fail",
            "status_detail": "The admission control plugin AlwaysPullImages is not set.",
            "remediation": {
                "text": "Configure the API server to use the AlwaysPullImages admission control plugin to ensure image security and integrity.",
                "url": "https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers",
            },
            "compliance": "CIS-1.10: 1.2.11 | CIS-1.8: 1.2.11",
        }
        file_content = StringIO(json.dumps([data]))
        parser = ProwlerParser()
        findings = parser.get_findings(file_content, Test())
        self.assertEqual(1, len(findings))

        finding = findings[0]
        self.assertEqual("The admission control plugin AlwaysPullImages is not set", finding.title)
        self.assertEqual("bc_k8s_pod_security_1", finding.vuln_id_from_tool)
        self.assertEqual("Medium", finding.severity)
        self.assertTrue(finding.active)
        self.assertIn("kubernetes", finding.unsaved_tags)
        self.assertIn("Status: fail", finding.description)
