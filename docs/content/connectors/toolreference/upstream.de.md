---
title: Referenz zu Upstream-Connector-Tools
description: Unsere Liste der unterstützten Connector-Tools und wie Sie sie mit DefectDojo
  einrichten
weight: 1
audience: pro
aliases:
- /de/connectors/upstream/toolreference/
- /de/import_data/pro/connectors/connectors_tool_reference/
- /de/en/connecting_your_tools/connectors/connectors_tool_reference
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Hinweis: Upstream-Connectors sind eine reine DefectDojo-Pro-Funktion.</span>

Beim Einrichten eines Connectors für ein unterstütztes Tool müssen Sie DefectDojo bestimmte Informationen zur API des Tools mitteilen. Grundsätzlich benötigen Sie:

* **Location** \-ein Feld, das im Allgemeinen auf die URL Ihres Tools in Ihrem Netzwerk verweist,
* **Secret** \- in der Regel ein API-Schlüssel.

Viele Tools stellen genau einen festen API\-Host bereit. Für diese füllt DefectDojo das Feld **Location** beim Anlegen des Connectors automatisch aus. Sie müssen die URL also nicht von dieser Seite kopieren. Behalten Sie den vorgegebenen Wert. Ändern Sie ihn nur, wenn Ihre Instanz einen anderen Host verwendet, zum Beispiel eine selbst gehostete Installation oder eine andere Region.

Manche Tools benötigen über **Location** und **Secret** hinaus weitere API-bezogene Felder. Möglicherweise müssen Sie auch auf der Seite des Tools Änderungen vornehmen, um einen eingehenden Connector von DefectDojo zu ermöglichen.

![image](images/connectors_tool_reference.png)

Jedes Tool hat eine andere API-Konfiguration, und dieser Leitfaden soll Ihnen helfen, die API des Tools so einzurichten, dass DefectDojo eine Verbindung herstellen kann.

Wann immer möglich, empfehlen wir, in Ihrem Sicherheitstool ein neues Konto „DefectDojo Bot" anzulegen, das ausschließlich vom Connector verwendet wird. So können Sie besser zwischen manuell von Ihrem Team ausgeführten Aktionen und automatisierten Aktionen des Connectors unterscheiden.

# **Asset-Connectors**

Die meisten Connectors importieren **Befunde** aus einem Sicherheitstool. **Asset-Connectors** funktionieren anders: Sie importieren stattdessen Ihr **Asset-Inventar**. Ein Asset-Connector zählt die Assets auf, die in einer externen Plattform vorhanden sind (zum Beispiel die Repositories in einer GitLab-Gruppe), und erstellt und pflegt automatisch die entsprechenden **Produkte** (Assets) und **Produkttypen** (Organisationen) in DefectDojo. Ein Asset-Connector importiert keine Befunde.

* **Discover** und **Sync** gleichen beide die Asset-Liste ab. Neue Assets erscheinen als `NEW`-Einträge; sobald sie zugeordnet sind (automatisch, wenn Auto-Mapping aktiviert ist), erstellt DefectDojo das Produkt und ordnet es einem vom Tool abgeleiteten Produkttyp zu — zum Beispiel dem GitLab-Namespace oder dem Azure-DevOps-Projekt.
* Wird ein Asset später upstream entfernt (zum Beispiel ein gelöschtes Repository), wird sein zugeordneter Eintrag beim nächsten Sync als `MISSING` markiert, damit Ihr Team ihn prüfen kann. DefectDojo löscht niemals stillschweigend ein Produkt.

Azure DevOps, Backstage, Bitbucket, GitHub, GitLab, Jira Service Management Assets und ServiceNow CMDB sind Asset-Connectors. runZero ist in erster Linie ein Asset-Connector, kann aber optional auch Schwachstellen als Befunde importieren. Alle anderen unten aufgeführten Connectors importieren Befunde.

# **Unterstützte Connectors**

- [Acunetix 360](/connectors/toolreference/acunetix_360/)
- [Akamai API Security](/connectors/toolreference/akamai/)
- [Anchore](/connectors/toolreference/anchore_enterprise/)
- [AWS Security Hub](/connectors/toolreference/security_hub/)
- [Azure DevOps](/connectors/toolreference/azure_devops/)
- [Backstage](/connectors/toolreference/backstage/)
- [Black Duck](/connectors/toolreference/black_duck/)
- [Bitbucket](/connectors/toolreference/bitbucket/#upstream-connector)
- [Bugcrowd](/connectors/toolreference/bugcrowd/)
- [Bright Security](/connectors/toolreference/bright_security/)
- [BurpSuite](/connectors/toolreference/burp_suite_enterprise/)
- [Censys](/connectors/toolreference/censys/)
- [Checkmarx ONE](/connectors/toolreference/checkmarx_one/)
- [Cloudflare](/connectors/toolreference/cloudflare/)
- [Cobalt.io](/connectors/toolreference/cobalt_io/)
- [Contrast](/connectors/toolreference/contrast/)
- [Coverity](/connectors/toolreference/coverity/)
- [CrowdStrike Falcon](/connectors/toolreference/crowdstrike_falcon/)
- [Deepfence ThreatMapper](/connectors/toolreference/deepfence_threatmapper/)
- [Dependency-Track](/connectors/toolreference/dependency_track/)
- [Docker Scout](/connectors/toolreference/docker_scout/)
- [Endor Labs](/connectors/toolreference/endor_labs/)
- [Edgescan](/connectors/toolreference/edgescan/)
- [Escape](/connectors/toolreference/escape/)
- [Fairwinds Insights](/connectors/toolreference/fairwinds_insights/)
- [Fortify](/connectors/toolreference/fortify/)
- [GitGuardian](/connectors/toolreference/gitguardian/)
- [GitHub](/connectors/toolreference/github/#upstream-connector)
- [GitHub Advanced Security](/connectors/toolreference/github_advanced_security/)
- [GitLab](/connectors/toolreference/gitlab/#upstream-connector)
- [Google Cloud Security Command Center](/connectors/toolreference/google_cloud_scc/)
- [Group-IB ASM](/connectors/toolreference/group_ib_asm/)
- [HackerOne](/connectors/toolreference/hackerone/)
- [Harbor](/connectors/toolreference/harbor/)
- [Have I Been Pwned](/connectors/toolreference/have_i_been_pwned/)
- [HCL AppScan](/connectors/toolreference/hcl_appscan/)
- [Intigriti](/connectors/toolreference/intigriti/)
- [Intruder](/connectors/toolreference/intruder/)
- [IriusRisk](/connectors/toolreference/iriusrisk/)
- [JFrog Xray](/connectors/toolreference/jfrog_xray/)
- [Jira Service Management Assets](/connectors/toolreference/jsm_assets/)
- [Kubescape](/connectors/toolreference/kubescape/)
- [Mend](/connectors/toolreference/mend/)
- [Lacework / FortiCNAPP](/connectors/toolreference/lacework_forticnapp/)
- [Microsoft Defender](/connectors/toolreference/microsoft_defender/)
- [Microsoft Defender for Cloud](/connectors/toolreference/microsoft_defender_for_cloud/)
- [MobSF](/connectors/toolreference/mobsf/)
- [NeuVector](/connectors/toolreference/neuvector/)
- [Nuclei (ProjectDiscovery Cloud)](/connectors/toolreference/nuclei_projectdiscovery_cloud/)
- [OpenVAS / Greenbone](/connectors/toolreference/openvas_greenbone/)
- [Probely](/connectors/toolreference/probely/)
- [Prowler](/connectors/toolreference/prowler/)
- [Qualys](/connectors/toolreference/qualys/)
- [Quay](/connectors/toolreference/quay/)
- [Rapid7 InsightAppSec](/connectors/toolreference/rapid7_insightappsec/)
- [Rapid7 InsightVM](/connectors/toolreference/rapid7_insightvm/)
- [Rapid7 InsightVM - Cloud Instance](/connectors/toolreference/rapid7_insightvm_cloud/)
- [runZero](/connectors/toolreference/runzero/)
- [Semgrep](/connectors/toolreference/semgrep/)
- [ServiceNow CMDB](/connectors/toolreference/servicenow_cmdb/)
- [Shodan](/connectors/toolreference/shodan/)
- [SonarQube](/connectors/toolreference/sonarqube/)
- [Snyk](/connectors/toolreference/snyk/)
- [Socket](/connectors/toolreference/socket/)
- [Sonatype IQ](/connectors/toolreference/sonatype_iq/)
- [Sysdig Secure](/connectors/toolreference/sysdig_secure/)
- [Tenable](/connectors/toolreference/tenable_io/)
- [Tenable Web App Scanning](/connectors/toolreference/tenable_web_app_scanning/)
- [Veracode](/connectors/toolreference/veracode/)
- [Wazuh](/connectors/toolreference/wazuh/)
- [Wiz](/connectors/toolreference/wiz/)
- [YesWeHack](/connectors/toolreference/yeswehack/)
