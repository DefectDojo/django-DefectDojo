---
title: Upstream Connectors ツールリファレンス
description: 対応している Connector ツールの一覧と、DefectDojo でのセットアップ方法
weight: 1
audience: pro
aliases:
- /ja/connectors/upstream/toolreference/
- /ja/import_data/pro/connectors/connectors_tool_reference/
- /ja/en/connecting_your_tools/connectors/connectors_tool_reference
---

<span style="background-color:rgba(242, 86, 29, 0.3)">注: Upstream Connectors は DefectDojo Pro 限定の機能です。</span>

対応ツール向けに Connector をセットアップする際は、そのツールの API に関する特定の情報を DefectDojo に提供する必要があります。基本的には、以下が必要です。

* **Location** \- 通常、ネットワーク内のツールの URL を指すフィールド
* **Secret** \- 通常は API キー

多くのツールは固定の API ホストを 1 つだけ公開します。その場合、コネクタを追加した時点で DefectDojo が **Location** を自動入力するため、このページから URL をコピーする必要はありません。入力済みの値はそのまま使用してください。セルフホスト環境や別リージョンなど、お使いのインスタンスが異なるホストを使う場合にのみ変更してください。

ツールによっては、**Location** と **Secret** 以外にも追加の API 関連フィールドが必要になる場合があります。また、DefectDojo からの Connector 接続を受け入れるために、ツール側での設定変更が必要になることもあります。

![image](images/connectors_tool_reference.png)

ツールごとに API の設定は異なるため、このガイドでは DefectDojo が接続できるように各ツールの API をセットアップする方法を説明します。

可能な限り、Connector 専用に利用する新しい「DefectDojo Bot」アカウントをセキュリティツール内に作成することをお勧めします。これにより、チームが手動で行った操作と Connector による自動操作を区別しやすくなります。

# **Asset Connectors**

ほとんどの Connector はセキュリティツールから**検出事項**をインポートします。**Asset Connectors** はこれとは異なる動作をします。検出事項ではなく**アセットインベントリ**をインポートします。Asset Connector は外部プラットフォームに存在するアセット(例えば GitLab グループ内のリポジトリ)を列挙し、DefectDojo 内に対応する**製品**(アセット)と**製品タイプ**(組織)を自動的に作成・維持します。Asset Connector によって検出事項がインポートされることはありません。

* **Discover** と **Sync** はどちらもアセット一覧を突き合わせます。新しいアセットは `NEW` レコードとして表示され、(自動マッピングが有効な場合は自動的に)マッピングされると、DefectDojo はそのツールから導出された製品タイプ(例えば GitLab の namespace や Azure DevOps のプロジェクト)の下に製品を作成し、グループ化します。
* アセットが後で上流側で削除された場合(例えばリポジトリが削除された場合)、次の Sync 時にマッピング済みのレコードが `MISSING` としてフラグされ、チームがトリアージできるようになります。DefectDojo が製品を無言で削除することはありません。

Azure DevOps、Backstage、Bitbucket、GitHub、GitLab、Jira Service Management Assets、ServiceNow CMDB は Asset Connectors です。runZero は主に Asset Connector ですが、脆弱性を検出事項としてインポートするオプションも備えています。以下に挙げるその他すべての Connector は検出事項をインポートします。

# **Supported Connectors**

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
