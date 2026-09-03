---
title: Référence des outils pour les Connecteurs Upstream
description: Notre liste des outils de Connecteur pris en charge, et comment les configurer
  avec DefectDojo
weight: 1
audience: pro
aliases:
- /fr/connectors/upstream/toolreference/
- /fr/import_data/pro/connectors/connectors_tool_reference/
- /fr/en/connecting_your_tools/connectors/connectors_tool_reference
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Remarque : les Connecteurs Upstream sont une fonctionnalité réservée à DefectDojo Pro.</span>

Lors de la configuration d'un Connecteur pour un outil pris en charge, vous devez fournir à DefectDojo des informations spécifiques liées à l'API de l'outil. Au minimum, vous aurez besoin des éléments suivants :

* **Location** \- un champ qui fait généralement référence à l'URL de votre outil sur votre réseau,
* **Secret** \- généralement une clé API.

De nombreux outils exposent un seul hôte d'API fixe. Pour ceux\-là, DefectDojo remplit le champ **Location** lorsque vous ajoutez le connecteur, vous n'avez donc pas à copier l'URL depuis cette page. Conservez la valeur proposée. Ne la modifiez que si votre instance utilise un autre hôte, par exemple une installation auto\-hébergée ou une autre région.

Certains outils nécessiteront des champs supplémentaires liés à l'API, en plus de **Location** et **Secret**. Ils peuvent également nécessiter que vous effectuiez des modifications de leur côté pour prendre en charge un Connecteur entrant depuis DefectDojo.

![image](images/connectors_tool_reference.png)

Chaque outil possède une configuration d'API différente, et ce guide a pour but de vous aider à configurer l'API de l'outil afin que DefectDojo puisse s'y connecter.

Dans la mesure du possible, nous vous recommandons de créer un nouveau compte « DefectDojo Bot » au sein de votre outil de sécurité, qui sera utilisé exclusivement par le Connecteur. Cela vous aidera à mieux distinguer les actions effectuées manuellement par votre équipe des actions automatisées effectuées par le Connecteur.

# **Connecteurs d'actifs**

La plupart des Connecteurs importent des **constatations** depuis un outil de sécurité. Les **Connecteurs d'actifs** fonctionnent différemment : ils importent plutôt votre **inventaire d'actifs**. Un Connecteur d'actifs énumère les actifs qui existent sur une plateforme externe (par exemple, les dépôts d'un groupe GitLab) et crée et maintient automatiquement les **Produits** (Actifs) et **Types de produit** (Organisations) correspondants dans DefectDojo. Aucune constatation n'est importée par un Connecteur d'actifs.

* **Discover** et **Sync** réconcilient tous deux la liste des actifs. Les nouveaux actifs apparaissent comme des Enregistrements `NEW` ; une fois mappés (automatiquement, si le mappage automatique est activé), DefectDojo crée le Produit et le regroupe sous un Type de produit dérivé de l'outil — par exemple, l'espace de noms GitLab ou le projet Azure DevOps.
* Si un actif est ensuite supprimé en amont (par exemple, un dépôt est supprimé), son Enregistrement mappé est marqué `MISSING` lors de la prochaine synchronisation via **Sync**, afin que votre équipe puisse le trier. DefectDojo ne supprime jamais silencieusement un Produit.

Azure DevOps, Backstage, Bitbucket, GitHub, GitLab, Jira Service Management Assets et ServiceNow CMDB sont des Connecteurs d'actifs. runZero est principalement un Connecteur d'actifs, mais peut également importer des vulnérabilités sous forme de constatations. Tous les autres Connecteurs listés ci-dessous importent des constatations.

# **Connecteurs pris en charge**

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
