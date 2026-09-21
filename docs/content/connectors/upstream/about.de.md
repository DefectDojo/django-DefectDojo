---
title: Upstream-Connectors
description: Verbinden Sie DefectDojo nahtlos mit Ihrer Suite von Sicherheitstools
summary: ''
date: 2023-09-07 16:06:50+02:00
lastmod: 2023-09-07 16:06:50+02:00
draft: false
weight: 0
chapter: true
sidebar:
  collapsed: true
seo:
  title: ''
  description: ''
  canonical: ''
  robots: ''
pro-feature: true
aliases:
- /de/import_data/pro/connectors/about_connectors/
- /de/en/connecting_your_tools/connectors/about_connectors
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Hinweis: Upstream-Connectors sind eine reine DefectDojo-Pro-Funktion.</span>

DefectDojo ermöglicht es Benutzern, ausgefeilte API-Integrationen aufzubauen, und gibt ihnen die volle Kontrolle darüber, wie ihre Schwachstellendaten organisiert werden.

Aber jeder braucht einen Ausgangspunkt, und genau hier kommen Upstream-Connectors ins Spiel. Upstream-Connectors (früher als **API Connectors** bekannt) sind darauf ausgelegt, Ihre Sicherheitstools so schnell wie möglich anzubinden und Daten nach DefectDojo zu importieren.

Wir unterstützen derzeit Upstream-Connectors für die folgenden Tools, weitere sind in Vorbereitung:

* **Acunetix 360**
* **Akamai API Security**
* **Anchore**
* **AWS Security Hub**
* **Azure DevOps**
* **Backstage**
* **Bitbucket**
* **Black Duck**
* **Bright Security**
* **Bugcrowd**
* **BurpSuite**
* **Censys**
* **Checkmarx ONE**
* **Cloudflare**
* **Cobalt.io**
* **Contrast**
* **Coverity**
* **CrowdStrike Falcon**
* **Deepfence ThreatMapper**
* **Dependency-Track**
* **Docker Scout**
* **Edgescan**
* **Endor Labs**
* **Escape**
* **Fairwinds Insights**
* **Fortify**
* **GitGuardian**
* **GitHub**
* **GitHub Advanced Security**
* **GitLab**
* **Google Cloud Security Command Center**
* **Group-IB ASM**
* **HackerOne**
* **Harbor**
* **Have I Been Pwned**
* **HCL AppScan**
* **Intigriti**
* **Intruder**
* **IriusRisk**
* **JFrog Xray**
* **Jira Service Management Assets**
* **Kubescape**
* **Lacework / FortiCNAPP**
* **Mend**
* **Microsoft Defender**
* **Microsoft Defender for Cloud**
* **MobSF**
* **NeuVector**
* **Nuclei (ProjectDiscovery Cloud)**
* **OpenVAS / Greenbone**
* **Probely**
* **Prowler**
* **Qualys**
* **Quay**
* **Rapid7 InsightAppSec**
* **Rapid7 InsightVM**
* **Rapid7 InsightVM - Cloud Instance**
* **runZero**
* **Semgrep**
* **ServiceNow CMDB**
* **Shodan**
* **Snyk**
* **Socket**
* **SonarQube**
* **Sonatype IQ**
* **Sysdig Secure**
* **Tenable**
* **Tenable Web App Scanning**
* **Veracode**
* **Wazuh**
* **Wiz**
* **YesWeHack**

Schritt-für-Schritt-Anleitungen zur Einrichtung für jedes Tool finden Sie in der Referenz [Tool-spezifische Connector-Einrichtung](../../toolreference/upstream/).

Die meisten Connectors importieren **Befunde**. Einige wenige sind **Asset Connectors**, die stattdessen Ihr **Asset-Inventar** importieren — sie bauen und pflegen Ihre Produkt- (Asset-) und Produkttyp- (Organisations-) Hierarchie, statt Befunde zu importieren: **Azure DevOps**, **Backstage**, **Bitbucket**, **GitHub**, **GitLab**, **Jira Service Management Assets** und **ServiceNow CMDB**. (**runZero** ist in erster Linie ein Asset Connector, kann aber optional auch Schwachstellen als Befunde importieren.)

Diese Verbindungen bieten eine Integration mit DefectDojo in API-Geschwindigkeit und können verwendet werden, um Schwachstellendaten aus dem Tool automatisch zu erfassen und zu organisieren.

## Orientierung auf der Connectors-Seite

Connectors werden in zwei Abschnitten aufgeführt, jeweils mit einer Anzahl neben der Überschrift und alphabetisch sortiert:

* **Configured Connectors** — jede Connector-Konfiguration, die auf dieser Instanz existiert. Ein Tool kann mehrfach auftauchen, einmal pro Konfiguration, und jede Kachel trägt den Titel `<Tool> - <label>`, damit sie unterschieden werden können. Teilen sich mehrere Konfigurationen ein Tool, werden sie nach ihrem Label sortiert.
* **Available Connectors** — jedes unterstützte Tool, das Sie noch nicht konfiguriert haben.

Die Zahl neben einer Überschrift ist die Anzahl der aktuell angezeigten Connectors, sie richtet sich also nach dem Suchfeld und dem Typfilter **Asset / Finding** und zeigt nicht immer die Gesamtzahl an. Auf DefectDojo Pro Cloud ist die Kachel **Request Upstream Connector** kein Connector und wird nicht mitgezählt.

Beide Abschnitte verfügen über ein eigenes Suchfeld, das nach dem Tool-Namen sucht.

![Die Connectors-Seite mit einer Anzahl neben jeder Abschnittsüberschrift](images/upstream_counts.png)

Die Seiten [Downstream Connectors](/connectors/downstream/about/) und [Authorization Connectors](/admin/sso/pro__authorization_connectors/) sind auf die gleiche Weise aufgebaut.

## Upstream-Connectors – Schnellstart

Wenn Sie die **Auto-Map**-Einstellungen von DefectDojo verwenden, haben Sie Ihren ersten Connector im Handumdrehen einsatzbereit.

1. Richten Sie einen [Connector](../add_edit/) für ein unterstütztes Tool ein.
2. [Discover](../manage_operations/#discover-operations) Sie die Datenhierarchie Ihres Tools.
3. [Sync](../manage_operations/#sync-operations) Sie die mit Ihrem Tool gefundenen Schwachstellen nach DefectDojo.

Das war's schon! Und denken Sie daran: Auch wenn Sie Ihren Connector auf die 'einfache' Weise erstellen, können Sie die Einrichtung später jederzeit ändern, ohne dabei Ihre Arbeit zu verlieren.

## So funktionieren Upstream-Connectors

Sofern Sie über den API-Schlüssel des Tools verfügen, das Sie verbinden möchten, lässt sich ein Connector in wenigen Minuten hinzufügen. Sobald die Verbindung funktioniert, führt DefectDojo einen **Discover**-Vorgang für die Umgebung Ihres Tools aus, um zu sehen, wie Sie Ihre Scan-Daten organisieren.

Nehmen wir an, Sie haben ein BurpSuite-Tool, das so eingerichtet ist, dass es fünf verschiedene Repositories auf Schwachstellen scannt. Ihr Connector nimmt diese Organisationsstruktur zur Kenntnis und richtet **Records** ein, die Ihnen helfen, diese einzelnen Repositories in die Produkt-/Engagement-/Test-Hierarchie von DefectDojo zu übertragen. Wenn Sie **'Auto-Map Records'** aktiviert haben, lernt DefectDojo diese Struktur automatisch und übernimmt sie.

![image](images/_index.png)

Sobald Ihre **Record**-Zuordnungen eingerichtet sind, beginnt DefectDojo, regelmäßig Scan-Daten zu importieren. Sie werden über alle vom Tool erkannten neuen Schwachstellen auf dem Laufenden gehalten und können sofort mit dem **Befunde**-System von DefectDojo an bestehenden Schwachstellen arbeiten.

Wenn Sie bereit sind, weitere Tools zu DefectDojo hinzuzufügen, können Sie Ihre Import-Zuordnungen problemlos neu anordnen. Mehrere Tools können so eingerichtet werden, dass sie Schwachstellen an dasselbe Ziel importieren, und Sie können Ihr Setup jederzeit umorganisieren, um es besser anzupassen, ohne dabei Arbeit zu verlieren.

## Mein Connector wird nicht unterstützt

### Einen Connector über die Oberfläche anfordern (DefectDojo Pro Cloud)

Auf DefectDojo Pro Cloud können Sie unser Team direkt über die Oberfläche bitten, einen Connector für ein Tool zu entwickeln, das wir noch nicht unterstützen:

1. Gehen Sie zu **Connectors → Upstream Connectors** (für Tools, die Daten *in* DefectDojo importieren). Issue-Tracker und andere ausgehende Integrationen können auf die gleiche Weise unter **Connectors → Downstream Connectors** angefordert werden.
2. Klicken Sie im Abschnitt **Available Connectors** auf **Request a Connector**.
3. Füllen Sie das Anfrageformular aus. Die Felder **Tool / Product Name**, **Tool API Base URL**, **Authentication Type** sowie die Anmeldedaten für diesen Authentifizierungstyp sind alle erforderlich, da unser Team eine erreichbare Adresse und funktionierende Anmeldedaten benötigt, um einen Connector zu entwickeln und zu bestätigen, dass er mit Ihrem Tool funktioniert. Anmeldedaten werden sicher gespeichert. Optional können Sie die Website des Anbieters, einen Link zur API-Dokumentation des Tools und eine Notiz zu Ihrem Anwendungsfall hinzufügen.
4. Klicken Sie auf **Submit Request**. Sie erhalten eine Bestätigung, dass Ihre Anfrage eingegangen ist. Unser Team prüft jede Anfrage, um zu bewerten, ob Unterstützung entwickelt wird — das Absenden einer Anfrage ist keine Garantie dafür, dass der Connector gebaut wird.

Um einen Connector anzufordern, sind **globale Maintainer**-Berechtigungen erforderlich; die Funktion ist **nur auf DefectDojo Pro Cloud** verfügbar — auf selbst gehosteten (On-Premise-)Instanzen erscheint diese Option nicht.

### Manueller Import

Auch ohne Connector kann DefectDojo den manuellen Import für eine Vielzahl von Sicherheitstools übernehmen. Weitere Informationen finden Sie in unserer [Liste unterstützter Tools](/supported_tools) sowie in unserem Leitfaden zum Importieren von Daten.

# **Nächste Schritte**

* Werfen Sie einen Blick auf die Seite **Upstream Connectors**, indem Sie zur **Pro UI** von DefectDojo wechseln und unter der Überschrift **Import** **Connectors \> Upstream Connectors** öffnen.
* Folgen Sie unserem Leitfaden, um [Ihren ersten Upstream-Connector zu erstellen](../add_edit/).
* Sehen Sie sich den Prozess des [Ausführens von Operationen](../manage_operations/) mit Ihren verbundenen Sicherheitstools an und erfahren Sie, wie sie für den Datenimport konfiguriert werden können.
