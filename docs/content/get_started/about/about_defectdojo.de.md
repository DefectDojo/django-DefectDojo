---
title: Über DefectDojo
date: 2021-02-02 20:46:29+01:00
draft: false
type: docs
weight: 1
aliases:
- /de/en/about_defectdojo/about_docs
---

<div class="version-opensource">

![image](images/dashboard.png)

</div>
<div class="version-pro">

![image](images/Introduction_to_Dashboard_Features.png)

</div>


<span style="background-color:rgba(242, 86, 29, 0.3)">DefectDojo, Inc. und Open-Source-Mitwirkende pflegen diese Dokumentation, um sowohl die Community- als auch die Pro-Edition von DefectDojo zu unterstützen.</span>

## Was ist DefectDojo?

DefectDojo ist eine Developer-Security-Operations-Plattform (DevSecOps). DefectDojo vereinfacht DevSecOps, indem es als automatischer Aggregator für Ihre Sicherheitstools fungiert und es Ihnen ermöglicht, Ihre Sicherheitsarbeit einfach zu organisieren und den Sicherheitsstatus Ihrer Organisation an andere Stakeholder zu berichten.

Während die Automatisierung von Sicherheitsprozessen und integrierte Entwicklungspipelines die übergeordneten Ziele von DefectDojo sind, ist diese Software im Kern ein Bug-Tracker für Sicherheitslücken, der Berichte aus vielen Sicherheitstools aufnehmen, organisieren und standardisieren soll.

### Was macht DefectDojo?

DefectDojo verfügt über intelligente Funktionen, um die Ergebnisse Ihrer Sicherheitstools zu verbessern und zu optimieren, darunter die Möglichkeit:

- Sicherheits-Befunde im Kontext zu verfolgen und darüber zu berichten
- SLAs im Kontext durchzusetzen
- Falsch-positive Ergebnisse, Risikoakzeptanzen und andere Triage-Entscheidungen zu verwalten
- Duplikate mithilfe des Deduplizierungsalgorithmus von DefectDojo herauszufiltern
- Sich in externe Projektverfolgungssoftware zu integrieren.
- Metriken/Berichte über Repositories und Entwicklungs-Branches hinweg mittels CI/CD-Integration bereitzustellen.
- Traditionelles Pentest-Management zu koordinieren.
- SLAs für Verfahren zur Behebung von Sicherheitslücken festzulegen und durchzusetzen.
- Risikoakzeptanzen für Sicherheitslücken zu erstellen und zu verfolgen.

Letztendlich ermöglicht Ihnen das Produkt:Engagement-Modell von DefectDojo, Ihre Entwicklungsumgebung zu inventarisieren und neue Sicherheits-Befunde sofort in den richtigen Kontext zu stellen.

---
Hier sind einige Beispiele, wie DefectDojo implementiert werden kann, mit DefectDojo-Mitbegründer und CTO Matt Tesauro:
<iframe width="560" height="315" src="https://www.youtube.com/embed/44vv-KspHBs?si=OwfGHs2VTQ886-FB" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" referrerpolicy="strict-origin-when-cross-origin" allowfullscreen></iframe>

---

## DefectDojo Open-Source

Die Kernfunktionalität von DefectDojo ist in DefectDojo Open-Source verfügbar.

Diese Edition von DefectDojo umfasst:

- Import/Reimport für alle 500+ unterstützten Tools
- REST-API
- Deduplizierungsfunktionen
- Eingeschränkte UI-, Metrik- und Berichtsfunktionen
- Jira-Integrationsfähigkeit

Für Teams, die ein kleineres Volumen an Befunden verwalten, ist DefectDojo Open-Source ein hervorragender Ausgangspunkt.

### Installationsanleitungen

Es gibt einige unterstützte Möglichkeiten, die Open-Source-Edition von DefectDojo zu installieren ([verfügbar auf Github](https://github.com/DefectDojo/django-DefectDojo)):

[Docker Compose](https://github.com/DefectDojo/django-DefectDojo/blob/master/readme-docs/DOCKER.md) ist die einfachste Methode, um das Kernprogramm und die für den Betrieb von DefectDojo erforderlichen Dienste zu installieren.
Unsere [Architektur](/get_started/open_source/architecture/)-Anleitung bietet Ihnen einen Überblick über jeden von DefectDojo verwendeten Dienst und jede Komponente.
[Im Produktivbetrieb ausführen](/get_started/open_source/running-in-production/) listet Systemanforderungen, Performance-Optimierungen und Wartungsprozesse für den Betrieb von DefectDojo auf einem Produktionsserver (mit Docker Compose) auf.

Kubernetes wird auf Open-Source-Ebene nicht vollständig unterstützt, aber diese Anleitung kann als Referenz und Ausgangspunkt dienen, um DefectDojo in eine Kubernetes-Architektur zu integrieren.

Falls bei einer Open-Source-Installation Probleme auftreten, empfehlen wir dringend, Fragen im [OWASP Slack](https://owasp.org/slack/invite) zu stellen. Unsere Community-Mitglieder sind im Kanal #defectdojo aktiv und können Ihnen bei Problemen helfen, auf die Sie stoßen.

## 🟧 DefectDojo Pro-Edition

<iframe width="560" height="315" src="https://www.youtube.com/embed/XUES0mCCGOI?si=2GEnd1iHlLcQE0R3" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" referrerpolicy="strict-origin-when-cross-origin" allowfullscreen></iframe>

DefectDojo, Inc. betreibt eine Pro-Edition dieser Software für kommerzielle Zwecke. Neben einer schlanken, modernen Benutzeroberfläche umfasst DefectDojo Pro:

* [Connectors](/connectors/upstream/about/): sofort einsatzbereite API-Integrationen mit Enterprise-Scannern (wie Checkmarx One, BurpSuite, Semgrep und mehr)
* **Konfigurierbare Importmethoden**: [Universal Parser](/supported_tools/parsers/universal_parser/), [Smart Upload](/import_data/pro/specialized_import/smart_upload/)
* **[CLI-Tools](/import_data/pro/specialized_import/external_tools/)** für die schnelle Integration in Ihre Systeme
* **[Zusätzliche Projektverfolgungs-Integrationen](/connectors/issue_tracking/)**: ServiceNow, Azure DevOps, GitHub und GitLab
* **[Verbesserte Metriken](/metrics_reports/pro_metrics/pro__overview/)** für Executive-Reporting und übergeordnete Analysen
* **[Priorität und Risiko](/asset_modelling/pro_hierarchy/priority_sla/)** zur systemweiten Identifizierung der dringendsten Befunde
* **Premium-Support** und Implementierungsberatung für Ihre Organisation

Die Pro-Edition ist als cloudgehostetes SaaS-Angebot verfügbar und kann auch vor Ort (on-premises) installiert werden.

Weitere Informationen zu DefectDojo Pro finden Sie auf unserer [Preisseite](https://defectdojo.com/pricing).

## Online-Demos

Online-Demos sind sowohl für die Open-Source- als auch für die Pro-Version von DefectDojo verfügbar. Beide können mit den folgenden Zugangsdaten aufgerufen werden:

- Benutzername: `admin`
- Passwort: `1Defectdojo@demo#appsec`

Diese Demos sind mit Beispieldaten gefüllt und werden täglich zurückgesetzt.

### Open-Source-Demo

Ein laufendes Beispiel von DefectDojo (Open-Source-Edition) ist unter [https://demo.defectdojo.org/](https://demo.defectdojo.org/) verfügbar.

### Pro-Demo

Ein laufendes Beispiel von DefectDojo Pro ist unter
[https://pro.demo.defectdojo.com/](https://pro.demo.defectdojo.com/) verfügbar.

## DefectDojo lernen

Ob Sie Pro- oder Open-Source-Nutzer sind, wir bieten zahlreiche Ressourcen, die Ihnen den Einstieg in DefectDojo erleichtern.

* Sehen Sie sich unsere unterstützten [Sicherheitstool-Integrationen](/supported_tools/) an, um DefectDojo in Ihr DevSecOps-Programm einzupassen.
* Unser Team betreibt einen [YouTube-Kanal](https://www.youtube.com/@defectdojo) mit Tutorials, archivierten Office-Hours-Veranstaltungen und weiteren Inhalten. 

## Kontakt zu uns

Um mit dem Team von DefectDojo, Inc. in Kontakt zu treten, können Sie sich jederzeit an [hello@defectdojo.com](mailto:hello@defectdojo.com) wenden.

Wir sind regelmäßig auf [LinkedIn](https://www.linkedin.com/company/33245534) präsent und veranstalten außerdem Online-Präsentationen für AppSec-Fachleute, die live oder auf Abruf angesehen werden können. Über bevorstehende Veranstaltungen erfahren Sie auf unserer [Events-Seite](https://defectdojo.com/events), oder Sie sehen sich vergangene Präsentationen auf unserem [YouTube-Kanal](https://www.youtube.com/@defectdojo) an.

### Sticker

Auf der Suche nach coolen DefectDojo-Laptop-Stickern? Als Dankeschön dafür, dass Sie Teil der DefectDojo-Community sind, können Sie sich anmelden, um kostenlose DefectDojo-Sticker zu erhalten. Weitere Informationen finden Sie unter [diesem Link](https://defectdojo.com/defectdojo-sticker-request).
