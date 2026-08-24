---
title: Referencia de herramientas de Conectores Upstream
description: Nuestra lista de herramientas de Conector compatibles y cómo configurarlas
  con DefectDojo
weight: 1
audience: pro
aliases:
- /es/connectors/upstream/toolreference/
- /es/import_data/pro/connectors/connectors_tool_reference/
- /es/en/connecting_your_tools/connectors/connectors_tool_reference
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Nota: los Conectores Upstream son una función exclusiva de DefectDojo Pro.</span>

Al configurar un Conector para una herramienta compatible, deberá proporcionar a DefectDojo información específica relacionada con la API de la herramienta. Como mínimo, necesitará:

* **Location** \-un campo que generalmente hace referencia a la URL de su herramienta dentro de su red,
* **Secret** \- generalmente, una clave de API.

Muchas herramientas usan un único host de API fijo. Para esas, DefectDojo completa el campo **Location** cuando agrega el Conector, así que no necesita copiar la URL de esta página. Conserve el valor que aparece. Cámbielo solo si su instancia usa otro host, por ejemplo una instalación autoalojada o una región distinta.

Algunas herramientas requerirán campos adicionales relacionados con la API además de **Location** y **Secret**. También pueden requerir que realice cambios de su lado para admitir un Conector entrante desde DefectDojo.

![imagen](images/connectors_tool_reference.png)

Cada herramienta tiene una configuración de API diferente, y esta guía está diseñada para ayudarlo a configurar la API de la herramienta para que DefectDojo pueda conectarse.

Siempre que sea posible, recomendamos crear una nueva cuenta 'DefectDojo Bot' dentro de su herramienta de seguridad, que solo será utilizada por el Conector. Esto le ayudará a diferenciar mejor entre las acciones realizadas manualmente por su equipo y las acciones automatizadas realizadas por el Conector.

# **Conectores de activos**

La mayoría de los Conectores importan **hallazgos** desde una herramienta de seguridad. Los **Conectores de activos** funcionan de forma diferente: en su lugar, importan su **inventario de activos**. Un Conector de activos enumera los activos que existen en una plataforma externa (por ejemplo, los repositorios de un grupo de GitLab) y crea y mantiene automáticamente los **Productos** (Activos) y **Tipos de producto** (Organizaciones) correspondientes en DefectDojo. Un Conector de activos no importa hallazgos.

* Tanto **Discover** como **Sync** concilian la lista de activos. Los activos nuevos aparecen como Registros `NEW`; una vez asignados (automáticamente, si la asignación automática está habilitada), DefectDojo crea el Producto y lo agrupa bajo un Tipo de producto derivado de la herramienta — por ejemplo, el namespace de GitLab o el proyecto de Azure DevOps.
* Si más adelante se elimina un activo en el origen (por ejemplo, se elimina un repositorio), su Registro asignado se marca como `MISSING` en la siguiente Sync para que su equipo pueda triarlo. DefectDojo nunca elimina un Producto de forma silenciosa.

Azure DevOps, Backstage, Bitbucket, GitHub, GitLab, Jira Service Management Assets y ServiceNow CMDB son Conectores de activos. runZero es principalmente un Conector de activos, pero opcionalmente puede importar vulnerabilidades como hallazgos. Todos los demás Conectores listados a continuación importan hallazgos.

# **Conectores compatibles**

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
