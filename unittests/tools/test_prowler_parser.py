from django.test import TestCase

from dojo.models import Test
from dojo.tools.prowler.parser import ProwlerParser
from unittests.dojo_test_case import get_unit_tests_scans_path


class TestProwlerParser(TestCase):

    def test_prowler_parser_json_with_no_vuln_has_no_findings(self):
        with (get_unit_tests_scans_path("prowler") / "prowler_zero_vul.json").open(encoding="utf-8") as testfile:
            parser = ProwlerParser()
            findings = parser.get_findings(testfile, Test())
            testfile.close()
            self.assertEqual(0, len(findings))

    def test_prowler_parser_csv_with_no_vuln_has_no_findings(self):
        with (get_unit_tests_scans_path("prowler") / "prowler_zero_vul.csv").open(encoding="utf-8") as testfile:
            parser = ProwlerParser()
            findings = parser.get_findings(testfile, Test())
            testfile.close()
            self.assertEqual(0, len(findings))

    def test_prowler_parser_aws_csv_file_with_multiple_vulnerabilities(self):
        with (get_unit_tests_scans_path("prowler") / "example_output_aws.csv").open(encoding="utf-8") as testfile:
            parser = ProwlerParser()
            findings = parser.get_findings(testfile, Test())
            testfile.close()
            self.assertEqual(4, len(findings))
            with self.subTest(i=0):
                description = (
                    "**Cloud Type** : AWS\n\n"
                    "**Description** : Check if IAM Access Analyzer is enabled\n\n"
                    "**Service Name** : accessanalyzer\n\n"
                    "**Status Detail** : IAM Access Analyzer in account <account_uid> is not enabled.\n\n"
                    "**Finding Created Time** : 2025-02-14 14:27:03.913874\n\n"
                    "**Region** : <region>\n\n"
                    "**Notes** : \n\n"
                    "**Related URL** : https://docs.aws.amazon.com/IAM/latest/UserGuide/what-is-access-analyzer.html\n\n"
                    "**Additional URLs** : https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-getting-started.html | https://aws.amazon.com/iam/features/analyze-access/"
                )
                mitigation = (
                    "**Remediation Recommendation** : Enable IAM Access Analyzer for all accounts, create analyzer and take action over it is recommendations (IAM Access Analyzer is available at no additional cost).\n\n"
                    "**Remediation Recommendation URL** : https://docs.aws.amazon.com/IAM/latest/UserGuide/what-is-access-analyzer.html\n\n"
                    "**Remediation Code Native IaC** : \n\n"
                    "**Remediation Code Terraform** : \n\n"
                    "**Remediation Code CLI** : aws accessanalyzer create-analyzer --analyzer-name <NAME> --type <ACCOUNT|ORGANIZATION>\n\n"
                    "**Other Remediation Info** : "
                )
                references = (
                    "CIS-1.4: 1.20\n"
                    "CIS-1.5: 1.20\n"
                    "KISA-ISMS-P-2023: 2.5.6, 2.6.4, 2.8.1, 2.8.2\n"
                    "CIS-2.0: 1.20\n"
                    "KISA-ISMS-P-2023-korean: 2.5.6, 2.6.4, 2.8.1, 2.8.2\n"
                    "AWS-Account-Security-Onboarding: Enabled security services, Create analyzers in each active regions, Verify that events are present in SecurityHub aggregated view\n"
                    "CIS-3.0: 1.20"
                )
                i = 0
                self.assertEqual(findings[i].description, description)
                self.assertEqual(findings[i].mitigation, mitigation)
                self.assertEqual(findings[i].title, "Check if IAM Access Analyzer is enabled")
                self.assertEqual(findings[i].severity, "Low")
                self.assertEqual(findings[i].impact, "AWS IAM Access Analyzer helps you identify the resources in your organization and accounts, such as Amazon S3 buckets or IAM roles, that are shared with an external entity. This lets you identify unintended access to your resources and data, which is a security risk. IAM Access Analyzer uses a form of mathematical analysis called automated reasoning, which applies logic and mathematical inference to determine all possible access paths allowed by a resource policy.")
                self.assertEqual(findings[i].references, references)

            with self.subTest(i=1):
                description = (
                    "**Cloud Type** : AWS\n\n"
                    "**Description** : Maintain current contact details.\n\n"
                    "**Service Name** : account\n\n"
                    "**Status Detail** : Login to the AWS Console. Choose your account name on the top right of the window -> My Account -> Contact Information.\n\n"
                    "**Finding Created Time** : 2025-02-14 14:27:03.913874\n\n"
                    "**Region** : <region>\n\n"
                    "**Notes** : \n\n"
                    "**Additional URLs** : https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-getting-started.html | https://aws.amazon.com/iam/features/analyze-access/"
                )
                mitigation = (
                    "**Remediation Recommendation** : Using the Billing and Cost Management console complete contact details.\n\n"
                    "**Remediation Recommendation URL** : https://docs.aws.amazon.com/accounts/latest/reference/manage-acct-update-contact.html\n\n"
                    "**Remediation Code Native IaC** : \n\n"
                    "**Remediation Code Terraform** : \n\n"
                    "**Remediation Code CLI** : No command available.\n\n"
                    "**Other Remediation Info** : https://docs.prowler.com/checks/aws/iam-policies/iam_18-maintain-contact-details#aws-console"
                )
                references = (
                    "CIS-1.4: 1.1\n"
                    "CIS-1.5: 1.1\n"
                    "KISA-ISMS-P-2023: 2.1.3\n"
                    "CIS-2.0: 1.1\n"
                    "KISA-ISMS-P-2023-korean: 2.1.3\n"
                    "AWS-Well-Architected-Framework-Security-Pillar: SEC03-BP03, SEC10-BP01\n"
                    "AWS-Account-Security-Onboarding: Billing, emergency, security contacts\n"
                    "CIS-3.0: 1.1\n"
                    "ENS-RD2022: op.ext.7.aws.am.1"
                )
                i = 1
                self.assertEqual(findings[i].description, description)
                self.assertEqual(findings[i].mitigation, mitigation)
                self.assertEqual(findings[i].title, "Maintain current contact details.")
                self.assertEqual(findings[i].severity, "Medium")
                self.assertEqual(findings[i].impact, "Ensure contact email and telephone details for AWS accounts are current and map to more than one individual in your organization. An AWS account supports a number of contact details, and AWS will use these to contact the account owner if activity judged to be in breach of Acceptable Use Policy. If an AWS account is observed to be behaving in a prohibited or suspicious manner, AWS will attempt to contact the account owner by email and phone using the contact details listed. If this is unsuccessful and the account behavior needs urgent mitigation, proactive measures may be taken, including throttling of traffic between the account exhibiting suspicious behavior and the AWS API endpoints and the Internet. This will result in impaired service to and from the account in question.")
                self.assertEqual(findings[i].references, references)
            with self.subTest(i=2):
                description = (
                    "**Cloud Type** : AWS\n\n"
                    "**Description** : Maintain different contact details to security, billing and operations.\n\n"
                    "**Service Name** : account\n\n"
                    "**Status Detail** : SECURITY, BILLING and OPERATIONS contacts not found or they are not different between each other and between ROOT contact.\n\n"
                    "**Finding Created Time** : 2025-02-14 14:27:03.913874\n\n"
                    "**Region** : <region>\n\n"
                    "**Notes** : \n\n"
                    "**Related URL** : https://docs.aws.amazon.com/accounts/latest/reference/manage-acct-update-contact.html\n\n"
                    "**Additional URLs** : https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-getting-started.html | https://aws.amazon.com/iam/features/analyze-access/"
                )

                mitigation = (
                    "**Remediation Recommendation** : Using the Billing and Cost Management console complete contact details.\n\n"
                    "**Remediation Recommendation URL** : https://docs.aws.amazon.com/accounts/latest/reference/manage-acct-update-contact.html\n\n"
                    "**Remediation Code Native IaC** : \n\n"
                    "**Remediation Code Terraform** : \n\n"
                    "**Remediation Code CLI** : \n\n"
                    "**Other Remediation Info** : https://docs.prowler.com/checks/aws/iam-policies/iam_18-maintain-contact-details#aws-console"
                )

                references = (
                    "KISA-ISMS-P-2023: 2.1.3\n"
                    "KISA-ISMS-P-2023-korean: 2.1.3"
                )

                i = 2
                self.assertEqual(findings[i].description, description)
                self.assertEqual(findings[i].mitigation, mitigation)
                self.assertEqual(findings[i].title, "Maintain different contact details to security, billing and operations.")
                self.assertEqual(findings[i].severity, "Medium")
                self.assertEqual(findings[i].impact, "Ensure contact email and telephone details for AWS accounts are current and map to more than one individual in your organization. An AWS account supports a number of contact details, and AWS will use these to contact the account owner if activity judged to be in breach of Acceptable Use Policy. If an AWS account is observed to be behaving in a prohibited or suspicious manner, AWS will attempt to contact the account owner by email and phone using the contact details listed. If this is unsuccessful and the account behavior needs urgent mitigation, proactive measures may be taken, including throttling of traffic between the account exhibiting suspicious behavior and the AWS API endpoints and the Internet. This will result in impaired service to and from the account in question.")
                self.assertEqual(findings[i].references, references)
            with self.subTest(i=3):
                description = (
                    "**Cloud Type** : AWS\n\n"
                    "**Description** : Ensure security contact information is registered.\n\n"
                    "**Service Name** : account\n\n"
                    "**Status Detail** : Login to the AWS Console. Choose your account name on the top right of the window -> My Account -> Alternate Contacts -> Security Section.\n\n"
                    "**Finding Created Time** : 2025-02-14 14:27:03.913874\n\n"
                    "**Region** : <region>\n\n"
                    "**Notes** : \n\n"
                    "**Additional URLs** : https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-getting-started.html | https://aws.amazon.com/iam/features/analyze-access/"
                )

                mitigation = (
                    "**Remediation Recommendation** : Go to the My Account section and complete alternate contacts.\n\n"
                    "**Remediation Recommendation URL** : https://docs.aws.amazon.com/accounts/latest/reference/manage-acct-update-contact.html\n\n"
                    "**Remediation Code Native IaC** : \n\n"
                    "**Remediation Code Terraform** : \n\n"
                    "**Remediation Code CLI** : No command available.\n\n"
                    "**Other Remediation Info** : https://docs.prowler.com/checks/aws/iam-policies/iam_19#aws-console"
                )

                references = (
                    "CIS-1.4: 1.2\n"
                    "CIS-1.5: 1.2\n"
                    "AWS-Foundational-Security-Best-Practices: account, acm\n"
                    "KISA-ISMS-P-2023: 2.1.3, 2.2.1\n"
                    "CIS-2.0: 1.2\n"
                    "KISA-ISMS-P-2023-korean: 2.1.3, 2.2.1\n"
                    "AWS-Well-Architected-Framework-Security-Pillar: SEC03-BP03, SEC10-BP01\n"
                    "AWS-Account-Security-Onboarding: Billing, emergency, security contacts\n"
                    "CIS-3.0: 1.2\n"
                    "ENS-RD2022: op.ext.7.aws.am.1"
                )

                i = 3
                self.assertEqual(findings[i].description, description)
                self.assertEqual(findings[i].mitigation, mitigation)
                self.assertEqual(findings[i].title, "Ensure security contact information is registered.")
                self.assertEqual(findings[i].severity, "Medium")
                self.assertEqual(findings[i].impact, "AWS provides customers with the option of specifying the contact information for accounts security team. It is recommended that this information be provided. Specifying security-specific contact information will help ensure that security advisories sent by AWS reach the team in your organization that is best equipped to respond to them.")
                self.assertEqual(findings[i].references, references)

    def test_prowler_parser_azure_csv_file_with_multiple_vulnerabilities(self):
        with (get_unit_tests_scans_path("prowler") / "example_output_azure.csv").open(encoding="utf-8") as testfile:
            parser = ProwlerParser()
            findings = parser.get_findings(testfile, Test())
            testfile.close()
            self.assertEqual(4, len(findings))
            with self.subTest(i=0):
                description = (
                    "**Cloud Type** : AZURE\n\n"
                    "**Description** : Azure Kubernetes Service (AKS) can be configured to use Azure Active Directory (AD) for user authentication. In this configuration, you sign in to an AKS cluster using an Azure AD authentication token. You can also configure Kubernetes role-based access control (Kubernetes RBAC) to limit access to cluster resources based a user's identity or group membership.\n\n"
                    "**Service Name** : aks\n\n"
                    "**Status Detail** : RBAC is enabled for cluster '<resource_name>' in subscription '<account_name>'.\n\n"
                    "**Finding Created Time** : 2025-02-14 14:27:30.710664\n\n"
                    "**Region** : <region>\n\n"
                    "**Notes** : \n\n"
                    "**Related URL** : https://learn.microsoft.com/en-us/azure/aks/azure-ad-rbac?tabs=portal\n\n"
                    "**Additional URLs** : https://learn.microsoft.com/azure/aks/azure-ad-rbac | https://learn.microsoft.com/azure/aks/concepts-identity"
                )

                mitigation = (
                    "**Remediation Recommendation** : \n\n"
                    "**Remediation Recommendation URL** : https://learn.microsoft.com/en-us/security/benchmark/azure/security-controls-v2-privileged-access#pa-7-follow-just-enough-administration-least-privilege-principle\n\n"
                    "**Remediation Code Native IaC** : \n\n"
                    "**Remediation Code Terraform** : https://docs.prowler.com/checks/azure/azure-kubernetes-policies/bc_azr_kubernetes_2#terraform\n\n"
                    "**Remediation Code CLI** : \n\n"
                    "**Other Remediation Info** : https://www.trendmicro.com/cloudoneconformity/knowledge-base/azure/AKS/enable-role-based-access-control-for-kubernetes-service.html#"
                )

                references = (
                    "ENS-RD2022: op.acc.2.az.r1.eid.1"
                )

                i = 0
                self.assertEqual(findings[i].description, description)
                self.assertEqual(findings[i].mitigation, mitigation)
                self.assertEqual(findings[i].title, "Ensure AKS RBAC is enabled")
                self.assertEqual(findings[i].severity, "Medium")
                self.assertEqual(findings[i].impact, "Kubernetes RBAC and AKS help you secure your cluster access and provide only the minimum required permissions to developers and operators.")
                self.assertEqual(findings[i].references, references)
            with self.subTest(i=1):
                description = (
                    "**Cloud Type** : AZURE\n\n"
                    "**Description** : Disable public IP addresses for cluster nodes, so that they only have private IP addresses. Private Nodes are nodes with no public IP addresses.\n\n"
                    "**Service Name** : aks\n\n"
                    "**Status Detail** : Cluster '<resource_name>' was created with private nodes in subscription '<account_name>'\n\n"
                    "**Finding Created Time** : 2025-02-14 14:27:30.710664\n\n"
                    "**Region** : <region>\n\n"
                    "**Notes** : \n\n"
                    "**Related URL** : https://learn.microsoft.com/en-us/azure/aks/private-clusters\n\n"
                    "**Additional URLs** : https://learn.microsoft.com/azure/aks/azure-ad-rbac | https://learn.microsoft.com/azure/aks/concepts-identity"
                )
                mitigation = (
                    "**Remediation Recommendation** : \n\n"
                    "**Remediation Recommendation URL** : https://learn.microsoft.com/en-us/azure/aks/access-private-cluster\n\n"
                    "**Remediation Code Native IaC** : \n\n"
                    "**Remediation Code Terraform** : \n\n"
                    "**Remediation Code CLI** : \n\n"
                    "**Other Remediation Info** : "
                )
                references = (
                    "ENS-RD2022: mp.com.4.r2.az.aks.1\n"
                    "MITRE-ATTACK: T1190, T1530"
                )

                i = 1
                self.assertEqual(findings[i].description, description)
                self.assertEqual(findings[i].mitigation, mitigation)
                self.assertEqual(findings[i].title, "Ensure clusters are created with Private Nodes")
                self.assertEqual(findings[i].severity, "High")
                self.assertEqual(findings[i].impact, "Disabling public IP addresses on cluster nodes restricts access to only internal networks, forcing attackers to obtain local network access before attempting to compromise the underlying Kubernetes hosts.")
                self.assertEqual(findings[i].references, references)
            with self.subTest(i=2):
                description = (
                    "**Cloud Type** : AZURE\n\n"
                    "**Description** : Disable access to the Kubernetes API from outside the node network if it is not required.\n\n"
                    "**Service Name** : aks\n\n"
                    "**Status Detail** : Public access to nodes is enabled for cluster '<resource_name>' in subscription '<account_name>'\n\n"
                    "**Finding Created Time** : 2025-02-14 14:27:30.710664\n\n"
                    "**Region** : <region>\n\n"
                    "**Notes** : \n\n"
                    "**Related URL** : https://learn.microsoft.com/en-us/azure/aks/private-clusters?tabs=azure-portal\n\n"
                    "**Additional URLs** : https://learn.microsoft.com/azure/aks/azure-ad-rbac | https://learn.microsoft.com/azure/aks/concepts-identity"
                )

                mitigation = (
                    "**Remediation Recommendation** : To use a private endpoint, create a new private endpoint in your virtual network then create a link between your virtual network and a new private DNS zone\n\n"
                    "**Remediation Recommendation URL** : https://learn.microsoft.com/en-us/azure/aks/access-private-cluster?tabs=azure-cli\n\n"
                    "**Remediation Code Native IaC** : \n\n"
                    "**Remediation Code Terraform** : \n\n"
                    "**Remediation Code CLI** : az aks update -n <cluster_name> -g <resource_group> --disable-public-fqdn\n\n"
                    "**Other Remediation Info** : "
                )

                references = (
                    "ENS-RD2022: mp.com.4.az.aks.2\n"
                    "MITRE-ATTACK: T1190, T1530"
                )

                i = 2
                self.assertEqual(findings[i].description, description)
                self.assertEqual(findings[i].mitigation, mitigation)
                self.assertEqual(findings[i].title, "Ensure clusters are created with Private Endpoint Enabled and Public Access Disabled")
                self.assertEqual(findings[i].severity, "High")
                self.assertEqual(findings[i].impact, "In a private cluster, the master node has two endpoints, a private and public endpoint. The private endpoint is the internal IP address of the master, behind an internal load balancer in the master's wirtual network. Nodes communicate with the master using the private endpoint. The public endpoint enables the Kubernetes API to be accessed from outside the master's virtual network. Although Kubernetes API requires an authorized token to perform sensitive actions, a vulnerability could potentially expose the Kubernetes publically with unrestricted access. Additionally, an attacker may be able to identify the current cluster and Kubernetes API version and determine whether it is vulnerable to an attack. Unless required, disabling public endpoint will help prevent such threats, and require the attacker to be on the master's virtual network to perform any attack on the Kubernetes API.")
                self.assertEqual(findings[i].references, references)
            with self.subTest(i=3):
                description = (
                    "**Cloud Type** : AZURE\n\n"
                    "**Description** : When you run modern, microservices-based applications in Kubernetes, you often want to control which components can communicate with each other. The principle of least privilege should be applied to how traffic can flow between pods in an Azure Kubernetes Service (AKS) cluster. Let's say you likely want to block traffic directly to back-end applications. The Network Policy feature in Kubernetes lets you define rules for ingress and egress traffic between pods in a cluster.\n\n"
                    "**Service Name** : aks\n\n"
                    "**Status Detail** : Network policy is enabled for cluster '<resource_name>' in subscription '<account_name>'.\n\n"
                    "**Finding Created Time** : 2025-02-14 14:27:30.710664\n\n"
                    "**Region** : <region>\n\n"
                    "**Notes** : Network Policy requires the Network Policy add-on. This add-on is included automatically when a cluster with Network Policy is created, but for an existing cluster, needs to be added prior to enabling Network Policy. Enabling/Disabling Network Policy causes a rolling update of all cluster nodes, similar to performing a cluster upgrade. This operation is long-running and will block other operations on the cluster (including delete) until it has run to completion. If Network Policy is used, a cluster must have at least 2 nodes of type n1-standard-1 or higher. The recommended minimum size cluster to run Network Policy enforcement is 3 n1-standard-1 instances. Enabling Network Policy enforcement consumes additional resources in nodes. Specifically, it increases the memory footprint of the kube-system process by approximately 128MB, and requires approximately 300 millicores of CPU.\n\n"
                    "**Related URL** : https://learn.microsoft.com/en-us/security/benchmark/azure/security-controls-v2-network-security#ns-2-connect-private-networks-together\n\n"
                    "**Additional URLs** : https://learn.microsoft.com/azure/aks/azure-ad-rbac | https://learn.microsoft.com/azure/aks/concepts-identity"
                )

                mitigation = (
                    "**Remediation Recommendation** : \n\n"
                    "**Remediation Recommendation URL** : https://learn.microsoft.com/en-us/azure/aks/use-network-policies\n\n"
                    "**Remediation Code Native IaC** : \n\n"
                    "**Remediation Code Terraform** : https://docs.prowler.com/checks/azure/azure-kubernetes-policies/bc_azr_kubernetes_4#terraform\n\n"
                    "**Remediation Code CLI** : \n\n"
                    "**Other Remediation Info** : "
                )

                references = (
                    "ENS-RD2022: mp.com.4.r2.az.aks.1"
                )

                i = 3
                self.assertEqual(findings[i].description, description)
                self.assertEqual(findings[i].mitigation, mitigation)
                self.assertEqual(findings[i].title, "Ensure Network Policy is Enabled and set as appropriate")
                self.assertEqual(findings[i].severity, "Medium")
                self.assertEqual(findings[i].impact, "All pods in an AKS cluster can send and receive traffic without limitations, by default. To improve security, you can define rules that control the flow of traffic. Back-end applications are often only exposed to required front-end services, for example. Or, database components are only accessible to the application tiers that connect to them. Network Policy is a Kubernetes specification that defines access policies for communication between Pods. Using Network Policies, you define an ordered set of rules to send and receive traffic and apply them to a collection of pods that match one or more label selectors. These network policy rules are defined as YAML manifests. Network policies can be included as part of a wider manifest that also creates a deployment or service.")
                self.assertEqual(findings[i].references, references)

    def test_prowler_parser_gcp_csv_file_with_multiple_vulnerabilities(self):
        with (get_unit_tests_scans_path("prowler") / "example_output_gcp.csv").open(encoding="utf-8") as testfile:
            parser = ProwlerParser()
            findings = parser.get_findings(testfile, Test())
            testfile.close()
            self.assertEqual(2, len(findings))
            with self.subTest(i=0):
                description = (
                    "**Cloud Type** : GCP\n\n"
                    "**Description** : Scan images stored in Google Container Registry (GCR) for vulnerabilities using AR Container Analysis or a third-party provider. This helps identify and mitigate security risks associated with known vulnerabilities in container images.\n\n"
                    "**Service Name** : artifacts\n\n"
                    "**Status Detail** : AR Container Analysis is not enabled in project <account_uid>.\n\n"
                    "**Finding Created Time** : 2025-02-14 14:27:20.697446\n\n"
                    "**Region** : <region>\n\n"
                    "**Notes** : By default, AR Container Analysis is disabled.\n\n"
                    "**Related URL** : https://cloud.google.com/artifact-analysis/docs\n\n"
                    "**Additional URLs** : https://cloud.google.com/api-keys/docs/best-practices | https://cloud.google.com/docs/authentication"
                )

                mitigation = (
                    "**Remediation Recommendation** : Enable vulnerability scanning for images stored in Artifact Registry using AR Container Analysis or a third-party provider.\n\n"
                    "**Remediation Recommendation URL** : https://cloud.google.com/artifact-analysis/docs/container-scanning-overview\n\n"
                    "**Remediation Code Native IaC** : \n\n"
                    "**Remediation Code Terraform** : \n\n"
                    "**Remediation Code CLI** : gcloud services enable containeranalysis.googleapis.com\n\n"
                    "**Other Remediation Info** : "
                )

                references = (
                    "MITRE-ATTACK: T1525\n"
                    "ENS-RD2022: op.exp.4.r4.gcp.log.1, op.mon.3.gcp.scc.1"
                )

                i = 0
                self.assertEqual(findings[i].description, description)
                self.assertEqual(findings[i].mitigation, mitigation)
                self.assertEqual(findings[i].title, "Ensure Image Vulnerability Analysis using AR Container Analysis or a third-party provider")
                self.assertEqual(findings[i].severity, "Medium")
                self.assertEqual(findings[i].impact, "Without image vulnerability scanning, container images stored in Artifact Registry may contain known vulnerabilities, increasing the risk of exploitation by malicious actors.")
                self.assertEqual(findings[i].references, references)
            with self.subTest(i=1):
                description = (
                    "**Cloud Type** : GCP\n\n"
                    "**Description** : GCP `Firewall Rules` are specific to a `VPC Network`. Each rule either `allows` or `denies` traffic when its conditions are met. Its conditions allow users to specify the type of traffic, such as ports and protocols, and the source or destination of the traffic, including IP addresses, subnets, and instances. Firewall rules are defined at the VPC network level and are specific to the network in which they are defined. The rules themselves cannot be shared among networks. Firewall rules only support IPv4 traffic. When specifying a source for an ingress rule or a destination for an egress rule by address, an `IPv4` address or `IPv4 block in CIDR` notation can be used. Generic `(0.0.0.0/0)` incoming traffic from the Internet to a VPC or VM instance using `RDP` on `Port 3389` can be avoided.\n\n"
                    "**Service Name** : networking\n\n"
                    "**Status Detail** : Firewall <resource_name> does not expose port 3389 (RDP) to the internet.\n\n"
                    "**Finding Created Time** : 2025-02-14 14:27:20.697446\n\n"
                    "**Region** : <region>\n\n"
                    "**Notes** : \n\n"
                    "**Additional URLs** : https://cloud.google.com/api-keys/docs | https://cloud.google.com/docs/authentication"
                )

                mitigation = (
                    "**Remediation Recommendation** : Ensure that Google Cloud Virtual Private Cloud (VPC) firewall rules do not allow unrestricted access (i.e. 0.0.0.0/0) on TCP port 3389 in order to restrict Remote Desktop Protocol (RDP) traffic to trusted IP addresses or IP ranges only and reduce the attack surface. TCP port 3389 is used for secure remote GUI login to Windows VM instances by connecting a RDP client application with an RDP server.\n\n"
                    "**Remediation Recommendation URL** : https://cloud.google.com/vpc/docs/using-firewalls\n\n"
                    "**Remediation Code Native IaC** : \n\n"
                    "**Remediation Code Terraform** : https://docs.<account_organization_name>/checks/gcp/google-cloud-networking-policies/bc_gcp_networking_2#terraform\n\n"
                    "**Remediation Code CLI** : https://docs.<account_organization_name>/checks/gcp/google-cloud-networking-policies/bc_gcp_networking_2#cli-command\n\n"
                    "**Other Remediation Info** : https://www.trendmicro.com/cloudoneconformity/knowledge-base/gcp/CloudVPC/unrestricted-rdp-access.html"
                )

                references = (
                    "MITRE-ATTACK: T1190, T1199, T1048, T1498, T1046\n"
                    "CIS-2.0: 3.7\n"
                    "ENS-RD2022: mp.com.1.gcp.fw.1\n"
                    "CIS-3.0: 3.7"
                )

                i = 1
                self.assertEqual(findings[i].description, description)
                self.assertEqual(findings[i].mitigation, mitigation)
                self.assertEqual(findings[i].title, "Ensure That RDP Access Is Restricted From the Internet")
                self.assertEqual(findings[i].severity, "Critical")
                self.assertEqual(findings[i].impact, "Allowing unrestricted Remote Desktop Protocol (RDP) access can increase opportunities for malicious activities such as hacking, Man-In-The-Middle attacks (MITM) and Pass-The-Hash (PTH) attacks.")
                self.assertEqual(findings[i].references, references)

    def test_prowler_parser_kubernetes_csv_file_with_multiple_vulnerabilities(self):
        with (get_unit_tests_scans_path("prowler") / "example_output_kubernetes.csv").open(encoding="utf-8") as testfile:
            parser = ProwlerParser()
            findings = parser.get_findings(testfile, Test())
            testfile.close()
            self.assertEqual(4, len(findings))
            with self.subTest(i=0):
                description = (
                    "**Cloud Type** : KUBERNETES\n\n"
                    "**Description** : This check verifies that the AlwaysPullImages admission control plugin is enabled in the Kubernetes API server. This plugin ensures that every new pod always pulls the required images, enforcing image access control and preventing the use of possibly outdated or altered images.\n\n"
                    "**Service Name** : apiserver\n\n"
                    "**Status Detail** : AlwaysPullImages admission control plugin is not set in pod <resource_uid>\n\n"
                    "**Finding Created Time** : 2025-02-14 14:27:38.533897\n\n"
                    "**Region** : namespace: kube-system\n\n"
                    "**Notes** : Enabling AlwaysPullImages can increase network and registry load and decrease container startup speed. It may not be suitable for all environments.\n\n"
                    "**Related URL** : https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/#alwayspullimages\n\n"
                    "**Additional URLs** : https://kubernetes.io/docs/concepts/containers/images/ | https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/"
                )

                mitigation = (
                    "**Remediation Recommendation** : Configure the API server to use the AlwaysPullImages admission control plugin to ensure image security and integrity.\n\n"
                    "**Remediation Recommendation URL** : https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers\n\n"
                    "**Remediation Code Native IaC** : https://docs.prowler.com/checks/kubernetes/kubernetes-policy-index/ensure-that-the-admission-control-plugin-alwayspullimages-is-set#kubernetes\n\n"
                    "**Remediation Code Terraform** : \n\n"
                    "**Remediation Code CLI** : --enable-admission-plugins=...,AlwaysPullImages,...\n\n"
                    "**Other Remediation Info** : "
                )

                references = (
                    "CIS-1.10: 1.2.11\n"
                    "CIS-1.8: 1.2.11"
                )

                i = 0
                self.assertEqual(findings[i].description, description)
                self.assertEqual(findings[i].mitigation, mitigation)
                self.assertEqual(findings[i].title, "Ensure that the admission control plugin AlwaysPullImages is set")
                self.assertEqual(findings[i].severity, "Medium")
                self.assertEqual(findings[i].impact, "Without AlwaysPullImages, once an image is pulled to a node, any pod can use it without any authorization check, potentially leading to security risks.")
                self.assertEqual(findings[i].references, references)
            with self.subTest(i=1):
                description = (
                    "**Cloud Type** : KUBERNETES\n\n"
                    "**Description** : Disable anonymous requests to the API server. When enabled, requests that are not rejected by other configured authentication methods are treated as anonymous requests, which are then served by the API server. Disallowing anonymous requests strengthens security by ensuring all access is authenticated.\n\n"
                    "**Service Name** : apiserver\n\n"
                    "**Status Detail** : API Server does not have anonymous-auth enabled in pod <resource_uid>\n\n"
                    "**Finding Created Time** : 2025-02-14 14:27:38.533897\n\n"
                    "**Region** : namespace: kube-system\n\n"
                    "**Notes** : While anonymous access can be useful for health checks and discovery, consider the security implications for your specific environment.\n\n"
                    "**Related URL** : https://kubernetes.io/docs/admin/authentication/#anonymous-requests\n\n"
                    "**Additional URLs** : https://kubernetes.io/docs/concepts/containers/images/ | https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/"
                )

                mitigation = (
                    "**Remediation Recommendation** : Ensure the --anonymous-auth argument in the API server is set to false. This will reject all anonymous requests, enforcing authenticated access to the server.\n\n"
                    "**Remediation Recommendation URL** : https://kubernetes.io/docs/reference/command-line-tools-reference/kube-apiserver/\n\n"
                    "**Remediation Code Native IaC** : https://docs.prowler.com/checks/kubernetes/kubernetes-policy-index/ensure-that-the-anonymous-auth-argument-is-set-to-false-1#kubernetes\n\n"
                    "**Remediation Code Terraform** : \n\n"
                    "**Remediation Code CLI** : --anonymous-auth=false\n\n"
                    "**Other Remediation Info** : "
                )

                references = (
                    "CIS-1.10: 1.2.1\n"
                    "CIS-1.8: 1.2.1"
                )

                i = 1
                self.assertEqual(findings[i].description, description)
                self.assertEqual(findings[i].mitigation, mitigation)
                self.assertEqual(findings[i].title, "Ensure that the --anonymous-auth argument is set to false")
                self.assertEqual(findings[i].severity, "High")
                self.assertEqual(findings[i].impact, "Enabling anonymous access to the API server can expose the cluster to unauthorized access and potential security vulnerabilities.")
                self.assertEqual(findings[i].references, references)
            with self.subTest(i=2):
                description = (
                    "**Cloud Type** : KUBERNETES\n\n"
                    "**Description** : This check ensures that the Kubernetes API server is configured with an appropriate audit log retention period. Setting --audit-log-maxage to 30 or as per business requirements helps in maintaining logs for sufficient time to investigate past events.\n\n"
                    "**Service Name** : apiserver\n\n"
                    "**Status Detail** : Audit log max age is not set to 30 or as appropriate in pod <resource_uid>\n\n"
                    "**Finding Created Time** : 2025-02-14 14:27:38.533897\n\n"
                    "**Region** : namespace: kube-system\n\n"
                    "**Notes** : Ensure the audit log retention period is set appropriately to balance between storage constraints and the need for historical data.\n\n"
                    "**Related URL** : https://kubernetes.io/docs/concepts/cluster-administration/audit/\n\n"
                    "**Additional URLs** : https://kubernetes.io/docs/concepts/containers/images/ | https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/"
                )

                mitigation = (
                    "**Remediation Recommendation** : Configure the API server audit log retention period to retain logs for at least 30 days or as per your organization's requirements.\n\n"
                    "**Remediation Recommendation URL** : https://kubernetes.io/docs/reference/command-line-tools-reference/kube-apiserver/\n\n"
                    "**Remediation Code Native IaC** : https://docs.prowler.com/checks/kubernetes/kubernetes-policy-index/ensure-that-the-audit-log-maxage-argument-is-set-to-30-or-as-appropriate#kubernetes\n\n"
                    "**Remediation Code Terraform** : \n\n"
                    "**Remediation Code CLI** : --audit-log-maxage=30\n\n"
                    "**Other Remediation Info** : "
                )

                references = (
                    "CIS-1.10: 1.2.17\n"
                    "CIS-1.8: 1.2.18"
                )

                i = 2
                self.assertEqual(findings[i].description, description)
                self.assertEqual(findings[i].mitigation, mitigation)
                self.assertEqual(findings[i].title, "Ensure that the --audit-log-maxage argument is set to 30 or as appropriate")
                self.assertEqual(findings[i].severity, "Medium")
                self.assertEqual(findings[i].impact, "Without an adequate log retention period, there may be insufficient audit history to investigate and analyze past events or security incidents.")
                self.assertEqual(findings[i].references, references)
            with self.subTest(i=3):
                description = (
                    "**Cloud Type** : KUBERNETES\n\n"
                    "**Description** : This check ensures that the Kubernetes API server is configured with an appropriate number of audit log backups. Setting --audit-log-maxbackup to 10 or as per business requirements helps maintain a sufficient log backup for investigations or analysis.\n\n"
                    "**Service Name** : apiserver\n\n"
                    "**Status Detail** : Audit log max backup is not set to 10 or as appropriate in pod <resource_uid>\n\n"
                    "**Finding Created Time** : 2025-02-14 14:27:38.533897\n\n"
                    "**Region** : namespace: kube-system\n\n"
                    "**Notes** : Ensure the audit log backup retention period is set appropriately to balance between storage constraints and the need for historical data.\n\n"
                    "**Related URL** : https://kubernetes.io/docs/concepts/cluster-administration/audit/\n\n"
                    "**Additional URLs** : https://kubernetes.io/docs/concepts/containers/images/ | https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/"
                )

                mitigation = (
                    "**Remediation Recommendation** : Configure the API server audit log backup retention to 10 or as per your organization's requirements.\n\n"
                    "**Remediation Recommendation URL** : https://kubernetes.io/docs/reference/command-line-tools-reference/kube-apiserver/\n\n"
                    "**Remediation Code Native IaC** : https://docs.prowler.com/checks/kubernetes/kubernetes-policy-index/ensure-that-the-audit-log-maxbackup-argument-is-set-to-10-or-as-appropriate#kubernetes\n\n"
                    "**Remediation Code Terraform** : \n\n"
                    "**Remediation Code CLI** : --audit-log-maxbackup=10\n\n"
                    "**Other Remediation Info** : "
                )

                references = (
                    "CIS-1.10: 1.2.18\n"
                    "CIS-1.8: 1.2.19"
                )

                i = 3
                self.assertEqual(findings[i].description, description)
                self.assertEqual(findings[i].mitigation, mitigation)
                self.assertEqual(findings[i].title, "Ensure that the --audit-log-maxbackup argument is set to 10 or as appropriate")
                self.assertEqual(findings[i].severity, "Medium")
                self.assertEqual(findings[i].impact, "Without an adequate number of audit log backups, there may be insufficient log history to investigate past events or security incidents.")
                self.assertEqual(findings[i].references, references)

    def test_prowler_parser_aws_json_file_with_multiple_vulnerabilities(self):
        with (get_unit_tests_scans_path("prowler") / "example_output_aws.ocsf.json").open(encoding="utf-8") as testfile:
            parser = ProwlerParser()
            findings = parser.get_findings(testfile, Test())
            testfile.close()
            self.assertEqual(3, len(findings))
            with self.subTest(i=0):
                description = (
                    "**Cloud Type** : AWS\n\n"
                    "**Finding Description** : Check if IAM Access Analyzer is enabled\n\n"
                    "**Product Name** : Prowler\n\n"
                    "**Status Detail** : IAM Access Analyzer in account <account_uid> is not enabled.\n\n"
                    "**Finding Created Time** : 2025-02-14T14:27:03.913874\n\n"
                    "**AWS Region** : <region>"
                )

                mitigation = (
                    "**Remediation Description** : Enable IAM Access Analyzer for all accounts, create analyzer and take action over it is recommendations (IAM Access Analyzer is available at no additional cost).\n\n"
                    "**Remediation References** : aws accessanalyzer create-analyzer --analyzer-name <NAME> --type <ACCOUNT|ORGANIZATION>, https://docs.aws.amazon.com/IAM/latest/UserGuide/what-is-access-analyzer.html"
                )

                references = (
                    "**Related URL** : https://docs.aws.amazon.com/IAM/latest/UserGuide/what-is-access-analyzer.html\n\n"
                    "**CIS-1.4** : 1.20\n\n"
                    "**CIS-1.5** : 1.20\n\n"
                    "**KISA-ISMS-P-2023** : 2.5.6, 2.6.4, 2.8.1, 2.8.2\n\n"
                    "**CIS-2.0** : 1.20\n\n"
                    "**KISA-ISMS-P-2023-korean** : 2.5.6, 2.6.4, 2.8.1, 2.8.2\n\n"
                    "**AWS-Account-Security-Onboarding** : Enabled security services, Create analyzers in each active regions, Verify that events are present in SecurityHub aggregated view\n\n"
                    "**CIS-3.0** : 1.20"
                )

                i = 0
                self.assertEqual(findings[i].description, description)
                self.assertEqual(findings[i].mitigation, mitigation)
                self.assertEqual(findings[i].title, "IAM Access Analyzer in account <account_uid> is not enabled.")
                self.assertEqual(findings[i].severity, "Low")
                self.assertEqual(findings[i].impact, "AWS IAM Access Analyzer helps you identify the resources in your organization and accounts, such as Amazon S3 buckets or IAM roles, that are shared with an external entity. This lets you identify unintended access to your resources and data, which is a security risk. IAM Access Analyzer uses a form of mathematical analysis called automated reasoning, which applies logic and mathematical inference to determine all possible access paths allowed by a resource policy.")
                self.assertEqual(findings[i].references, references)
            with self.subTest(i=1):
                description = (
                    "**Cloud Type** : AWS\n\n"
                    "**Finding Description** : Maintain current contact details.\n\n"
                    "**Product Name** : Prowler\n\n"
                    "**Status Detail** : Login to the AWS Console. Choose your account name on the top right of the window -> My Account -> Contact Information.\n\n"
                    "**Finding Created Time** : 2025-02-14T14:27:03.913874\n\n"
                    "**AWS Region** : <region>"
                )

                mitigation = (
                    "**Remediation Description** : Using the Billing and Cost Management console complete contact details.\n\n"
                    "**Remediation References** : No command available., https://docs.prowler.com/checks/aws/iam-policies/iam_18-maintain-contact-details#aws-console, https://docs.aws.amazon.com/accounts/latest/reference/manage-acct-update-contact.html"
                )

                references = (
                    "**Related URL** : \n\n"
                    "**CIS-1.4** : 1.1\n\n"
                    "**CIS-1.5** : 1.1\n\n"
                    "**KISA-ISMS-P-2023** : 2.1.3\n\n"
                    "**CIS-2.0** : 1.1\n\n"
                    "**KISA-ISMS-P-2023-korean** : 2.1.3\n\n"
                    "**AWS-Well-Architected-Framework-Security-Pillar** : SEC03-BP03, SEC10-BP01\n\n"
                    "**AWS-Account-Security-Onboarding** : Billing, emergency, security contacts\n\n"
                    "**CIS-3.0** : 1.1\n\n"
                    "**ENS-RD2022** : op.ext.7.aws.am.1"
                )

                i = 1
                self.assertEqual(findings[i].description, description)
                self.assertEqual(findings[i].mitigation, mitigation)
                self.assertEqual(findings[i].title, "Login to the AWS Console. Choose your account name on the top right of the window -> My Account -> Contact Information.")
                self.assertEqual(findings[i].severity, "Medium")
                self.assertEqual(findings[i].impact, "Ensure contact email and telephone details for AWS accounts are current and map to more than one individual in your organization. An AWS account supports a number of contact details, and AWS will use these to contact the account owner if activity judged to be in breach of Acceptable Use Policy. If an AWS account is observed to be behaving in a prohibited or suspicious manner, AWS will attempt to contact the account owner by email and phone using the contact details listed. If this is unsuccessful and the account behavior needs urgent mitigation, proactive measures may be taken, including throttling of traffic between the account exhibiting suspicious behavior and the AWS API endpoints and the Internet. This will result in impaired service to and from the account in question.")
                self.assertEqual(findings[i].references, references)
            with self.subTest(i=2):
                description = (
                    "**Cloud Type** : AWS\n\n"
                    "**Finding Description** : Maintain different contact details to security, billing and operations.\n\n"
                    "**Product Name** : Prowler\n\n"
                    "**Status Detail** : SECURITY, BILLING and OPERATIONS contacts not found or they are not different between each other and between ROOT contact.\n\n"
                    "**Finding Created Time** : 2025-02-14T14:27:03.913874\n\n"
                    "**AWS Region** : <region>"
                )

                mitigation = (
                    "**Remediation Description** : Using the Billing and Cost Management console complete contact details.\n\n"
                    "**Remediation References** : https://docs.prowler.com/checks/aws/iam-policies/iam_18-maintain-contact-details#aws-console, https://docs.aws.amazon.com/accounts/latest/reference/manage-acct-update-contact.html"
                )

                references = (
                    "**Related URL** : https://docs.aws.amazon.com/accounts/latest/reference/manage-acct-update-contact.html\n\n"
                    "**KISA-ISMS-P-2023** : 2.1.3\n\n"
                    "**KISA-ISMS-P-2023-korean** : 2.1.3"
                )

                i = 2
                self.assertEqual(findings[i].description, description)
                self.assertEqual(findings[i].mitigation, mitigation)
                self.assertEqual(findings[i].title, "SECURITY, BILLING and OPERATIONS contacts not found or they are not different between each other and between ROOT contact.")
                self.assertEqual(findings[i].severity, "Medium")
                self.assertEqual(findings[i].impact, "Ensure contact email and telephone details for AWS accounts are current and map to more than one individual in your organization. An AWS account supports a number of contact details, and AWS will use these to contact the account owner if activity judged to be in breach of Acceptable Use Policy. If an AWS account is observed to be behaving in a prohibited or suspicious manner, AWS will attempt to contact the account owner by email and phone using the contact details listed. If this is unsuccessful and the account behavior needs urgent mitigation, proactive measures may be taken, including throttling of traffic between the account exhibiting suspicious behavior and the AWS API endpoints and the Internet. This will result in impaired service to and from the account in question.")
                self.assertEqual(findings[i].references, references)

    def test_prowler_parser_azure_json_file_with_multiple_vulnerabilities(self):
        with (get_unit_tests_scans_path("prowler") / "example_output_azure.ocsf.json").open(encoding="utf-8") as testfile:
            parser = ProwlerParser()
            findings = parser.get_findings(testfile, Test())
            testfile.close()
            self.assertEqual(3, len(findings))
            with self.subTest(i=0):
                description = (
                    "**Cloud Type** : AZURE\n\n"
                    "**Finding Description** : Application Insights within Azure act as an Application Performance Monitoring solution providing valuable data into how well an application performs and additional information when performing incident response. The types of log data collected include application metrics, telemetry data, and application trace logging data providing organizations with detailed information about application activity and application transactions. Both data sets help organizations adopt a proactive and retroactive means to handle security and performance related metrics within their modern applications.\n\n"
                    "**Product Name** : Prowler\n\n"
                    "**Status Detail** : There are no AppInsight configured in subscription <subscription_name>.\n\n"
                    "**Finding Created Time** : 2025-02-14T14:27:30.710664\n\n"
                    "**AZURE Region** : global"
                )

                mitigation = (
                    "**Remediation Description** : 1. Navigate to Application Insights 2. Under the Basics tab within the PROJECT DETAILS section, select the Subscription 3. Select the Resource group 4. Within the INSTANCE DETAILS, enter a Name 5. Select a Region 6. Next to Resource Mode, select Workspace-based 7. Within the WORKSPACE DETAILS, select the Subscription for the log analytics workspace 8. Select the appropriate Log Analytics Workspace 9. Click Next:Tags > 10. Enter the appropriate Tags as Name, Value pairs. 11. Click Next:Review+Create 12. Click Create.\n\n"
                    "**Remediation References** : az monitor app-insights component create --app <app name> --resource-group <resource group name> --location <location> --kind 'web' --retention-time <INT days to retain logs> --workspace <log analytics workspace ID> -- subscription <subscription ID>, https://www.tenable.com/audits/items/CIS_Microsoft_Azure_Foundations_v2.0.0_L2.audit:8a7a608d180042689ad9d3f16aa359f1"
                )

                references = (
                    "**Related URL** : https://learn.microsoft.com/en-us/azure/azure-monitor/app/app-insights-overview\n\n"
                    "**CIS-2.1** : 5.3.1\n\n"
                    "**ENS-RD2022** : mp.s.4.r1.az.nt.2\n\n"
                    "**CIS-3.0** : 6.3.1\n\n"
                    "**CIS-2.0** : 5.3.1"
                )

                i = 0
                self.assertEqual(findings[i].description, description)
                self.assertEqual(findings[i].mitigation, mitigation)
                self.assertEqual(findings[i].title, "There are no AppInsight configured in subscription <subscription_name>.")
                self.assertEqual(findings[i].severity, "Low")
                self.assertEqual(findings[i].impact, "Configuring Application Insights provides additional data not found elsewhere within Azure as part of a much larger logging and monitoring program within an organization's Information Security practice. The types and contents of these logs will act as both a potential cost saving measure (application performance) and a means to potentially confirm the source of a potential incident (trace logging). Metrics and Telemetry data provide organizations with a proactive approach to cost savings by monitoring an application's performance, while the trace logging data provides necessary details in a reactive incident response scenario by helping organizations identify the potential source of an incident within their application.")
                self.assertEqual(findings[i].references, references)
            with self.subTest(i=1):
                description = (
                    "**Cloud Type** : AZURE\n\n"
                    "**Finding Description** : Microsoft Defender for Cloud emails the subscription owners whenever a high-severity alert is triggered for their subscription. You should provide a security contact email address as an additional email address.\n\n"
                    "**Product Name** : Prowler\n\n"
                    "**Status Detail** : There is not another correct email configured for subscription <subscription_name>.\n\n"
                    "**Finding Created Time** : 2025-02-14T14:27:30.710664\n\n"
                    "**AZURE Region** : global"
                )

                mitigation = (
                    "**Remediation Description** : 1. From Azure Home select the Portal Menu 2. Select Microsoft Defender for Cloud 3. Click on Environment Settings 4. Click on the appropriate Management Group, Subscription, or Workspace 5. Click on Email notifications 6. Enter a valid security contact email address (or multiple addresses separated by commas) in the Additional email addresses field 7. Click Save\n\n"
                    "**Remediation References** : https://docs.prowler.com/checks/azure/azure-general-policies/ensure-that-security-contact-emails-is-set#terraform, https://www.trendmicro.com/cloudoneconformity/knowledge-base/azure/SecurityCenter/security-contact-email.html, https://learn.microsoft.com/en-us/rest/api/defenderforcloud/security-contacts/list?view=rest-defenderforcloud-2020-01-01-preview&tabs=HTTP"
                )

                references = (
                    "**Related URL** : https://docs.microsoft.com/en-us/azure/security-center/security-center-provide-security-contact-details\n\n"
                    "**CIS-2.1** : 2.1.18\n\n"
                    "**ENS-RD2022** : op.mon.3.r3.az.de.1\n\n"
                    "**CIS-3.0** : 3.1.13\n\n"
                    "**CIS-2.0** : 2.1.19"
                )

                i = 1
                self.assertEqual(findings[i].description, description)
                self.assertEqual(findings[i].mitigation, mitigation)
                self.assertEqual(findings[i].title, "There is not another correct email configured for subscription <subscription_name>.")
                self.assertEqual(findings[i].severity, "Medium")
                self.assertEqual(findings[i].impact, "Microsoft Defender for Cloud emails the Subscription Owner to notify them about security alerts. Adding your Security Contact's email address to the 'Additional email addresses' field ensures that your organization's Security Team is included in these alerts. This ensures that the proper people are aware of any potential compromise in order to mitigate the risk in a timely fashion.")
                self.assertEqual(findings[i].references, references)
            with self.subTest(i=2):
                description = (
                    "**Cloud Type** : AZURE\n\n"
                    "**Finding Description** : Ensure That Microsoft Defender for App Services Is Set To 'On' \n\n"
                    "**Product Name** : Prowler\n\n"
                    "**Status Detail** : Defender plan Defender for App Services from subscription <subscription_name> is set to OFF (pricing tier not standard).\n\n"
                    "**Finding Created Time** : 2025-02-14T14:27:30.710664\n\n"
                    "**AZURE Region** : global"
                )

                mitigation = (
                    "**Remediation Description** : By <resource_name>, Microsoft Defender for Cloud is not enabled for your App Service instances. Enabling the Defender security service for App Service instances allows for advanced security defense using threat detection capabilities provided by Microsoft Security Response Center.\n\n"
                    "**Remediation References** : https://docs.prowler.com/checks/azure/azure-general-policies/ensure-that-azure-defender-is-set-to-on-for-app-service#terraform, https://www.trendmicro.com/cloudoneconformity/knowledge-base/azure/SecurityCenter/defender-app-service.html, https://www.trendmicro.com/cloudoneconformity/knowledge-base/azure/SecurityCenter/defender-app-service.html"
                )

                references = (
                    "**Related URL** : \n\n"
                    "**CIS-2.1** : 2.1.2\n\n"
                    "**ENS-RD2022** : mp.s.4.r1.az.nt.3\n\n"
                    "**MITRE-ATTACK** : T1190, T1059, T1204, T1552, T1486, T1499, T1496, T1087\n\n"
                    "**CIS-3.0** : 3.1.6.1"
                )

                i = 2
                self.assertEqual(findings[i].description, description)
                self.assertEqual(findings[i].mitigation, mitigation)
                self.assertEqual(findings[i].title, "Defender plan Defender for App Services from subscription <subscription_name> is set to OFF (pricing tier not standard).")
                self.assertEqual(findings[i].severity, "High")
                self.assertEqual(findings[i].impact, "Turning on Microsoft Defender for App Service enables threat detection for App Service, providing threat intelligence, anomaly detection, and behavior analytics in the Microsoft Defender for Cloud.")
                self.assertEqual(findings[i].references, references)

    def test_prowler_parser_gcp_json_file_with_multiple_vulnerabilities(self):
        with (get_unit_tests_scans_path("prowler") / "example_output_gcp.ocsf.json").open(encoding="utf-8") as testfile:
            parser = ProwlerParser()
            findings = parser.get_findings(testfile, Test())
            testfile.close()
            self.assertEqual(3, len(findings))
            with self.subTest(i=0):
                description = (
                    "**Cloud Type** : GCP\n\n"
                    "**Finding Description** : API Keys should only be used for services in cases where other authentication methods are unavailable. Unused keys with their permissions in tact may still exist within a project. Keys are insecure because they can be viewed publicly, such as from within a browser, or they can be accessed on a device where the key resides. It is recommended to use standard authentication flow instead.\n\n"
                    "**Product Name** : Prowler\n\n"
                    "**Status Detail** : Project <project_id> does not have active API Keys.\n\n"
                    "**Finding Created Time** : 2025-02-14T14:27:20.697446\n\n"
                    "**GCP Region** : global"
                )

                mitigation = (
                    "**Remediation Description** : To avoid the security risk in using API keys, it is recommended to use standard authentication flow instead.\n\n"
                    "**Remediation References** : gcloud alpha services api-keys delete, https://cloud.google.com/docs/authentication/api-keys"
                )

                references = (
                    "**Related URL** : \n\n"
                    "**MITRE-ATTACK** : T1098\n\n"
                    "**CIS-2.0** : 1.12\n\n"
                    "**ENS-RD2022** : op.acc.2.gcp.rbak.1\n\n"
                    "**CIS-3.0** : 1.12"
                )

                i = 0
                self.assertEqual(findings[i].description, description)
                self.assertEqual(findings[i].mitigation, mitigation)
                self.assertEqual(findings[i].title, "Project <project_id> does not have active API Keys.")
                self.assertEqual(findings[i].severity, "Medium")
                self.assertEqual(findings[i].impact, "Security risks involved in using API-Keys appear below: API keys are simple encrypted strings, API keys do not identify the user or the application making the API request, API keys are typically accessible to clients, making it easy to discover and steal an API key.")
                self.assertEqual(findings[i].references, references)
            with self.subTest(i=1):
                description = (
                    "**Cloud Type** : GCP\n\n"
                    "**Finding Description** : Scan images stored in Google Container Registry (GCR) for vulnerabilities using AR Container Analysis or a third-party provider. This helps identify and mitigate security risks associated with known vulnerabilities in container images.\n\n"
                    "**Product Name** : Prowler\n\n"
                    "**Status Detail** : AR Container Analysis is not enabled in project <project_id>.\n\n"
                    "**Finding Created Time** : 2025-02-14T14:27:20.697446\n\n"
                    "**GCP Region** : global"
                )

                mitigation = (
                    "**Remediation Description** : Enable vulnerability scanning for images stored in Artifact Registry using AR Container Analysis or a third-party provider.\n\n"
                    "**Remediation References** : gcloud services enable containeranalysis.googleapis.com, https://cloud.google.com/artifact-analysis/docs/container-scanning-overview"
                )

                references = (
                    "**Related URL** : https://cloud.google.com/artifact-analysis/docs\n\n"
                    "**MITRE-ATTACK** : T1525\n\n"
                    "**ENS-RD2022** : op.exp.4.r4.gcp.log.1, op.mon.3.gcp.scc.1"
                )

                i = 1
                self.assertEqual(findings[i].description, description)
                self.assertEqual(findings[i].mitigation, mitigation)
                self.assertEqual(findings[i].title, "AR Container Analysis is not enabled in project <project_id>.")
                self.assertEqual(findings[i].severity, "Medium")
                self.assertEqual(findings[i].impact, "Without image vulnerability scanning, container images stored in Artifact Registry may contain known vulnerabilities, increasing the risk of exploitation by malicious actors.")
                self.assertEqual(findings[i].references, references)
            with self.subTest(i=2):
                description = (
                    "**Cloud Type** : GCP\n\n"
                    "**Finding Description** : GCP `Firewall Rules` are specific to a `VPC Network`. Each rule either `allows` or `denies` traffic when its conditions are met. Its conditions allow users to specify the type of traffic, such as ports and protocols, and the source or destination of the traffic, including IP addresses, subnets, and instances. Firewall rules are defined at the VPC network level and are specific to the network in which they are defined. The rules themselves cannot be shared among networks. Firewall rules only support IPv4 traffic. When specifying a source for an ingress rule or a destination for an egress rule by address, an `IPv4` address or `IPv4 block in CIDR` notation can be used. Generic `(0.0.0.0/0)` incoming traffic from the Internet to a VPC or VM instance using `RDP` on `Port 3389` can be avoided.\n\n"
                    "**Product Name** : Prowler\n\n"
                    "**Status Detail** : Firewall <resource_id> does exposes port 3389 (RDP) to the internet.\n\n"
                    "**Finding Created Time** : 2025-02-14T14:27:20.697446\n\n"
                    "**GCP Region** : global"
                )

                mitigation = (
                    "**Remediation Description** : Ensure that Google Cloud Virtual Private Cloud (VPC) firewall rules do not allow unrestricted access (i.e. 0.0.0.0/0) on TCP port 3389 in order to restrict Remote Desktop Protocol (RDP) traffic to trusted IP addresses or IP ranges only and reduce the attack surface. TCP port 3389 is used for secure remote GUI login to Windows VM instances by connecting a RDP client application with an RDP server.\n\n"
                    "**Remediation References** : https://docs.prowler.com/checks/gcp/google-cloud-networking-policies/bc_gcp_networking_2#terraform, https://docs.prowler.com/checks/gcp/google-cloud-networking-policies/bc_gcp_networking_2#cli-command, https://www.trendmicro.com/cloudoneconformity/knowledge-base/gcp/CloudVPC/unrestricted-rdp-access.html, https://cloud.google.com/vpc/docs/using-firewalls"
                )

                references = (
                    "**Related URL** : \n\n"
                    "**MITRE-ATTACK** : T1190, T1199, T1048, T1498, T1046\n\n"
                    "**CIS-2.0** : 3.7\n\n"
                    "**ENS-RD2022** : mp.com.1.gcp.fw.1\n\n"
                    "**CIS-3.0** : 3.7"
                )

                i = 2
                self.assertEqual(findings[i].description, description)
                self.assertEqual(findings[i].mitigation, mitigation)
                self.assertEqual(findings[i].title, "Firewall <resource_id> does exposes port 3389 (RDP) to the internet.")
                self.assertEqual(findings[i].severity, "Critical")
                self.assertEqual(findings[i].impact, "Allowing unrestricted Remote Desktop Protocol (RDP) access can increase opportunities for malicious activities such as hacking, Man-In-The-Middle attacks (MITM) and Pass-The-Hash (PTH) attacks.")
                self.assertEqual(findings[i].references, references)

    def test_prowler_parser_kubernetes_json_file_with_multiple_vulnerabilities(self):
        with (get_unit_tests_scans_path("prowler") / "example_output_kubernetes.ocsf.json").open(encoding="utf-8") as testfile:
            parser = ProwlerParser()
            findings = parser.get_findings(testfile, Test())
            testfile.close()
            self.assertEqual(3, len(findings))
            with self.subTest(i=0):
                description = (
                    "**Cloud Type** : KUBERNETES\n\n"
                    "**Finding Description** : This check verifies that the AlwaysPullImages admission control plugin is enabled in the Kubernetes API server. This plugin ensures that every new pod always pulls the required images, enforcing image access control and preventing the use of possibly outdated or altered images.\n\n"
                    "**Product Name** : Prowler\n\n"
                    "**Status Detail** : AlwaysPullImages admission control plugin is not set in pod <pod>.\n\n"
                    "**Finding Created Time** : 2025-02-14T14:27:38.533897\n\n"
                    "**Pod Name** : <pod>\n\n"
                    "**Namespace** : <namespace>"
                )

                mitigation = (
                    "**Remediation Description** : Configure the API server to use the AlwaysPullImages admission control plugin to ensure image security and integrity.\n\n"
                    "**Remediation References** : https://docs.prowler.com/checks/kubernetes/kubernetes-policy-index/ensure-that-the-admission-control-plugin-alwayspullimages-is-set#kubernetes, --enable-admission-plugins=...,AlwaysPullImages,..., https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers"
                )

                references = (
                    "**Related URL** : https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/#alwayspullimages\n\n"
                    "**CIS-1.10** : 1.2.11\n\n"
                    "**CIS-1.8** : 1.2.11"
                )

                i = 0
                self.assertEqual(findings[i].description, description)
                self.assertEqual(findings[i].mitigation, mitigation)
                self.assertEqual(findings[i].title, "AlwaysPullImages admission control plugin is not set in pod <pod>.")
                self.assertEqual(findings[i].severity, "Medium")
                self.assertEqual(findings[i].impact, "Without AlwaysPullImages, once an image is pulled to a node, any pod can use it without any authorization check, potentially leading to security risks.")
                self.assertEqual(findings[i].references, references)
            with self.subTest(i=1):
                description = (
                    "**Cloud Type** : KUBERNETES\n\n"
                    "**Finding Description** : This check ensures that the Kubernetes API server is configured with an appropriate audit log retention period. Setting --audit-log-maxage to 30 or as per business requirements helps in maintaining logs for sufficient time to investigate past events.\n\n"
                    "**Product Name** : Prowler\n\n"
                    "**Status Detail** : Audit log max age is not set to 30 or as appropriate in pod <pod>.\n\n"
                    "**Finding Created Time** : 2025-02-14T14:27:38.533897\n\n"
                    "**Pod Name** : <pod>\n\n"
                    "**Namespace** : <namespace>"
                )

                mitigation = (
                    "**Remediation Description** : Configure the API server audit log retention period to retain logs for at least 30 days or as per your organization's requirements.\n\n"
                    "**Remediation References** : https://docs.prowler.com/checks/kubernetes/kubernetes-policy-index/ensure-that-the-audit-log-maxage-argument-is-set-to-30-or-as-appropriate#kubernetes, --audit-log-maxage=30, https://kubernetes.io/docs/reference/command-line-tools-reference/kube-apiserver/"
                )

                references = (
                    "**Related URL** : https://kubernetes.io/docs/concepts/cluster-administration/audit/\n\n"
                    "**CIS-1.10** : 1.2.17\n\n"
                    "**CIS-1.8** : 1.2.18"
                )

                i = 1
                self.assertEqual(findings[i].description, description)
                self.assertEqual(findings[i].mitigation, mitigation)
                self.assertEqual(findings[i].title, "Audit log max age is not set to 30 or as appropriate in pod <pod>.")
                self.assertEqual(findings[i].severity, "Medium")
                self.assertEqual(findings[i].impact, "Without an adequate log retention period, there may be insufficient audit history to investigate and analyze past events or security incidents.")
                self.assertEqual(findings[i].references, references)
            with self.subTest(i=2):
                description = (
                    "**Cloud Type** : KUBERNETES\n\n"
                    "**Finding Description** : This check ensures that the Kubernetes API server is configured with an appropriate number of audit log backups. Setting --audit-log-maxbackup to 10 or as per business requirements helps maintain a sufficient log backup for investigations or analysis.\n\n"
                    "**Product Name** : Prowler\n\n"
                    "**Status Detail** : Audit log max backup is not set to 10 or as appropriate in pod <pod>.\n\n"
                    "**Finding Created Time** : 2025-02-14T14:27:38.533897\n\n"
                    "**Pod Name** : <pod>\n\n"
                    "**Namespace** : <namespace>\n"
                    "**Cloud Type** : KUBERNETES\n\n"
                    "**Finding Description** : This check ensures that the Kubernetes API server is configured with an appropriate number of audit log backups. Setting --audit-log-maxbackup to 10 or as per business requirements helps maintain a sufficient log backup for investigations or analysis.\n\n"
                    "**Product Name** : Prowler\n\n"
                    "**Status Detail** : Audit log max backup is not set to 10 or as appropriate in pod <pod>.\n\n"
                    "**Finding Created Time** : 2025-02-14T14:27:38.533897\n\n"
                    "**Pod Name** : <pod>\n\n"
                    "**Namespace** : <namespace>"
                )

                mitigation = (
                    "**Remediation Description** : Configure the API server audit log backup retention to 10 or as per your organization's requirements.\n\n"
                    "**Remediation References** : https://docs.prowler.com/checks/kubernetes/kubernetes-policy-index/ensure-that-the-audit-log-maxbackup-argument-is-set-to-10-or-as-appropriate#kubernetes, --audit-log-maxbackup=10, https://kubernetes.io/docs/reference/command-line-tools-reference/kube-apiserver/"
                )

                references = (
                    "**Related URL** : https://kubernetes.io/docs/concepts/cluster-administration/audit/\n\n"
                    "**CIS-1.10** : 1.2.18\n\n"
                    "**CIS-1.8** : 1.2.19"
                )

                i = 2
                self.assertEqual(findings[i].description, description)
                self.assertEqual(findings[i].mitigation, mitigation)
                self.assertEqual(findings[i].title, "Audit log max backup is not set to 10 or as appropriate in pod <pod>.")
                self.assertEqual(findings[i].severity, "Medium")
                self.assertEqual(findings[i].impact, "Without an adequate number of audit log backups, there may be insufficient log history to investigate past events or security incidents.")
                self.assertEqual(findings[i].references, references)
