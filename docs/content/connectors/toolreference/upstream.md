---
title: "Upstream Connectors Tool Reference"
description: "Our list of supported Connector tools, and how to set them up with DefectDojo"
weight: 1
audience: pro
aliases:
  - /connectors/upstream/toolreference/
  - /import_data/pro/connectors/connectors_tool_reference/
  - /en/connecting_your_tools/connectors/connectors_tool_reference
---
<span style="background-color:rgba(242, 86, 29, 0.3)">Note: Upstream Connectors are a DefectDojo Pro-only feature.</span>

When setting up a Connector for a supported tool, you'll need to give DefectDojo specific information related to the tool's API. At a base level, you'll need:

* **Location** \-a field whichgenerallyrefers to your tool's URL in your network,
* **Secret** \- generally an API key.

Some tools will require additional API\-related fields beyond **Location** and **Secret**. They may also require you to make changes on their side to accommodate an incoming Connector from DefectDojo.

Many tools serve one fixed API host. For those, DefectDojo fills in **Location** for you when you add the Connector, so you do not have to copy the URL out of this page. Keep the value you are given. Change it only if your instance uses a different host, such as a self\-hosted deployment or a different region.

![image](images/connectors_tool_reference.png)

Each tool has a different API configuration, and this guide is intended to help you set up the tool's API so that DefectDojo can connect.

Whenever possible, we recommend creating a new 'DefectDojo Bot' account within your Security Tool which will only be used by the Connector. This will help you better differentiate between actions manually taken by your team, and automated actions taken by the Connector.

# **Asset Connectors**

Most Connectors import **findings** from a security tool. **Asset Connectors** work differently: they import your **asset inventory** instead. An Asset Connector enumerates the assets that exist in an external platform (for example, the repositories in a GitLab group) and automatically creates and maintains the matching **Assets** and **Organizations** in DefectDojo. No findings are imported by an Asset Connector.

* **Discover** and **Sync** both reconcile the asset list. New assets appear as `NEW` Records; once mapped (automatically, if auto-mapping is enabled), DefectDojo creates the Asset and groups it under an Organization derived from the tool — for example, the GitLab namespace or the Azure DevOps project.
* If an asset is later removed upstream (for example, a repository is deleted), its mapped Record is flagged `MISSING` on the next Sync so your team can triage it. DefectDojo never silently deletes an Asset.

Azure DevOps, Backstage, Bitbucket, GitHub, GitLab, JSM Assets, and ServiceNow CMDB are Asset Connectors. runZero is primarily an Asset Connector but can optionally import vulnerabilities as findings. All other Connectors listed below import findings.

# **Supported Connectors**

- [AccuKnox](/connectors/toolreference/accuknox/)
- [Action1](/connectors/toolreference/action1/)
- [Acunetix 360](/connectors/toolreference/acunetix_360/)
- [Akamai](/connectors/toolreference/akamai/)
- [Akto](/connectors/toolreference/akto/)
- [Alert Logic](/connectors/toolreference/alert_logic/)
- [Anchore Enterprise](/connectors/toolreference/anchore_enterprise/)
- [AppCheck](/connectors/toolreference/appcheck/)
- [Aqua Security](/connectors/toolreference/aqua_security/)
- [Automox](/connectors/toolreference/automox/)
- [Azure DevOps](/connectors/toolreference/azure_devops/)
- [Backstage](/connectors/toolreference/backstage/)
- [Beagle Security](/connectors/toolreference/beagle_security/)
- [BigID](/connectors/toolreference/bigid/)
- [Black Duck](/connectors/toolreference/black_duck/)
- [Bitbucket](/connectors/toolreference/bitbucket/#upstream-connector)
- [Black Duck Continuous Dynamic](/connectors/toolreference/black_duck_continuous_dynamic/)
- [Bugcrowd](/connectors/toolreference/bugcrowd/)
- [Bright Security](/connectors/toolreference/bright_security/)
- [Burp Suite Enterprise](/connectors/toolreference/burp_suite_enterprise/)
- [Calico Cloud](/connectors/toolreference/calico_cloud/)
- [Censys](/connectors/toolreference/censys/)
- [Checkmarx One](/connectors/toolreference/checkmarx_one/)
- [Chef Automate](/connectors/toolreference/chef_automate/)
- [CI Fuzz](/connectors/toolreference/ci_fuzz/)
- [Cloudflare](/connectors/toolreference/cloudflare/)
- [Cobalt.io](/connectors/toolreference/cobalt_io/)
- [Codacy](/connectors/toolreference/codacy/)
- [Contrast](/connectors/toolreference/contrast/)
- [Coverity](/connectors/toolreference/coverity/)
- [CrowdStrike Falcon](/connectors/toolreference/crowdstrike_falcon/)
- [CyberArk Certificate Manager](/connectors/toolreference/cyberark_certificate_manager/)
- [Cyberwatch](/connectors/toolreference/cyberwatch/)
- [CyCognito](/connectors/toolreference/cycognito/)
- [Datadog](/connectors/toolreference/datadog/)
- [Deepfence ThreatMapper](/connectors/toolreference/deepfence_threatmapper/)
- [DeepSource](/connectors/toolreference/deepsource/)
- [Dependency-Track](/connectors/toolreference/dependency_track/)
- [Detectify](/connectors/toolreference/detectify/)
- [Docker Scout](/connectors/toolreference/docker_scout/)
- [Dragos](/connectors/toolreference/dragos/)
- [Elastic Security](/connectors/toolreference/elastic_security/)
- [Endor Labs](/connectors/toolreference/endor_labs/)
- [Edgescan](/connectors/toolreference/edgescan/)
- [Escape](/connectors/toolreference/escape/)
- [Fairwinds Insights](/connectors/toolreference/fairwinds_insights/)
- [Finite State](/connectors/toolreference/finite_state/)
- [Fleet](/connectors/toolreference/fleet/)
- [Fortify](/connectors/toolreference/fortify/)
- [FOSSA](/connectors/toolreference/fossa/)
- [GitGuardian](/connectors/toolreference/gitguardian/)
- [GitHub](/connectors/toolreference/github/#upstream-connector)
- [GitHub Advanced Security](/connectors/toolreference/github_advanced_security/)
- [GitLab](/connectors/toolreference/gitlab/#upstream-connector)
- [Google Artifact Analysis](/connectors/toolreference/google_artifact_analysis/)
- [Google Cloud SCC](/connectors/toolreference/google_cloud_scc/)
- [Group-IB ASM](/connectors/toolreference/group_ib_asm/)
- [HackerOne](/connectors/toolreference/hackerone/)
- [Halo Security](/connectors/toolreference/halo_security/)
- [Harbor](/connectors/toolreference/harbor/)
- [Have I Been Pwned](/connectors/toolreference/have_i_been_pwned/)
- [HCL AppScan](/connectors/toolreference/hcl_appscan/)
- [HiddenLayer](/connectors/toolreference/hiddenlayer/)
- [Holm Security](/connectors/toolreference/holm_security/)
- [ImmuniWeb](/connectors/toolreference/immuniweb/)
- [InsightCloudSec](/connectors/toolreference/insightcloudsec/)
- [Intigriti](/connectors/toolreference/intigriti/)
- [Intruder](/connectors/toolreference/intruder/)
- [IriusRisk](/connectors/toolreference/iriusrisk/)
- [JFrog XRay](/connectors/toolreference/jfrog_xray/)
- [JSM Assets](/connectors/toolreference/jsm_assets/)
- [Klocwork](/connectors/toolreference/klocwork/)
- [Kubescape](/connectors/toolreference/kubescape/)
- [Mend](/connectors/toolreference/mend/)
- [Lacework / FortiCNAPP](/connectors/toolreference/lacework_forticnapp/)
- [Microsoft Defender](/connectors/toolreference/microsoft_defender/)
- [Microsoft Defender for Cloud](/connectors/toolreference/microsoft_defender_for_cloud/)
- [MobSF](/connectors/toolreference/mobsf/)
- [NetRise](/connectors/toolreference/netrise/)
- [NeuVector](/connectors/toolreference/neuvector/)
- [Nightfall AI](/connectors/toolreference/nightfall_ai/)
- [NowSecure](/connectors/toolreference/nowsecure/)
- [Nozomi Networks](/connectors/toolreference/nozomi_networks/)
- [Nuclei (ProjectDiscovery Cloud)](/connectors/toolreference/nuclei_projectdiscovery_cloud/)
- [OpenVAS / Greenbone](/connectors/toolreference/openvas_greenbone/)
- [Orca Security](/connectors/toolreference/orca_security/)
- [Ostorlab](/connectors/toolreference/ostorlab/)
- [Parasoft DTP](/connectors/toolreference/parasoft_dtp/)
- [Picus Security](/connectors/toolreference/picus_security/)
- [PingCastle](/connectors/toolreference/pingcastle/)
- [Probely](/connectors/toolreference/probely/)
- [Promptfoo](/connectors/toolreference/promptfoo/)
- [Prowler](/connectors/toolreference/prowler/)
- [Qualys](/connectors/toolreference/qualys/)
- [Quay](/connectors/toolreference/quay/)
- [Qwiet AI](/connectors/toolreference/qwiet_ai/)
- [Rapid7 InsightAppSec](/connectors/toolreference/rapid7_insightappsec/)
- [Rapid7 InsightVM](/connectors/toolreference/rapid7_insightvm/)
- [Red Hat Satellite](/connectors/toolreference/red_hat_satellite/)
- [runZero](/connectors/toolreference/runzero/)
- [Scantist](/connectors/toolreference/scantist/)
- [Security Hub](/connectors/toolreference/security_hub/)
- [Semgrep](/connectors/toolreference/semgrep/)
- [ServiceNow CMDB](/connectors/toolreference/servicenow_cmdb/)
- [Shodan](/connectors/toolreference/shodan/)
- [SonarQube](/connectors/toolreference/sonarqube/)
- [Snyk](/connectors/toolreference/snyk/)
- [Socket](/connectors/toolreference/socket/)
- [Sonatype IQ](/connectors/toolreference/sonatype_iq/)
- [SOOS](/connectors/toolreference/soos/)
- [Sysdig Secure](/connectors/toolreference/sysdig_secure/)
- [Tenable.io](/connectors/toolreference/tenable_io/)
- [Tenable Web App Scanning](/connectors/toolreference/tenable_web_app_scanning/)
- [TruffleHog](/connectors/toolreference/trufflehog/)
- [Trustwave Fusion](/connectors/toolreference/trustwave_fusion/)
- [Uptycs](/connectors/toolreference/uptycs/)
- [Vanta](/connectors/toolreference/vanta/)
- [Veracode](/connectors/toolreference/veracode/)
- [Vulnerability Manager Plus](/connectors/toolreference/vulnerability_manager_plus/)
- [Wallarm](/connectors/toolreference/wallarm/)
- [Wazuh](/connectors/toolreference/wazuh/)
- [WebInspect Enterprise](/connectors/toolreference/webinspect_enterprise/)
- [Wiz](/connectors/toolreference/wiz/)
- [YesWeHack](/connectors/toolreference/yeswehack/)
- [Zimperium](/connectors/toolreference/zimperium/)
- [Zora](/connectors/toolreference/zora/)
