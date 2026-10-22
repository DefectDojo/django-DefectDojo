---
title: Häufige Anwendungsfälle
description: Anwendungsfälle und Beispiele
draft: 'false'
weight: 2
chapter: true
aliases:
- /de/en/about_defectdojo/examples_of_use
---

Dieser Artikel basiert auf den Office Hours von DefectDojo, Inc. vom Februar 2025: „Tackling Common Use Cases“.
<iframe width="560" height="315" src="https://www.youtube.com/embed/44vv-KspHBs?si=ilRBlfo-wvX5DPVg" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" referrerpolicy="strict-origin-when-cross-origin" allowfullscreen></iframe>

## Beispiele für Anwendungsfälle

DefectDojo ist so konzipiert, dass es jede Sicherheitsimplementierung bewältigen kann, unabhängig von der Größe Ihres Sicherheitsteams, der Komplexität Ihrer IT oder dem Umfang Ihrer Berichte. Die folgenden Beispiele sollen als Ausgangspunkt für Ihre eigenen Anforderungen dienen, basieren jedoch auf realen Beispielen aus unserer Community und dem DefectDojo Pro-Team.

### Großunternehmen: RBAC und Engagements

„BigCorp“ ist ein großes multinationales Unternehmen mit einem Chief Information Security Officer (CISO) und einer zentralisierten IT-Sicherheitsgruppe, zu der auch AppSec gehört.

Die Sicherheit bei BigCorp ist stark zentralisiert. Bestimmte Aufgaben werden an Business Information Security Officers (BISO) delegiert.

Die wichtigsten Anliegen von BigCorp sind:

- Eine einheitliche Testmethode für alle Geschäftsbereiche der Organisation festlegen und beibehalten
- Compliance-Anforderungen erfüllen und regulatorische Probleme vermeiden

#### Testmodell

BigCorp verarbeitet Sicherheitsdaten aus vielen Quellen:

- CI/CD-Jobs, die automatisch SAST-, SCA- und Secret-Scanning-Tools ausführen
- Penetrationstests durch Drittanbieter für bestimmte Produkte
- PCI-Compliance-Audits für bestimmte Produkte

Jede dieser Berichtskategorien kann durch ein eigenes Engagement abgebildet werden, mit einem separaten Test für jede Art von Scan in DefectDojo.

![image](images/example_product_hierarchy_bigcorp.png)

- Wenn ein Produkt über eine CI/CD-Pipeline verfügt, können alle Ergebnisse dieser Pipeline fortlaufend in ein einziges, offenes Engagement importiert werden. Jedes verwendete Tool erstellt einen eigenen Test innerhalb des CI/CD-Engagements, der kontinuierlich mit neuen Daten aktualisiert werden kann.
(Siehe unseren Leitfaden zu [Reimport](/import_data/import_intro/reimport/))
- Für jeden Penetrationstest kann ein eigenes Engagement erstellt werden, das alle Ergebnisse enthält, z. B. „Q1 Pen Test 2024“, „Q2 Pen Test 2024“ usw.
- BigCorp möchte wahrscheinlich ein eigenes Mock-PCI-Audit durchführen, um auf den Ernstfall vorbereitet zu sein. Die Ergebnisse dieser Audits können ebenfalls als separates Engagement gespeichert werden.

#### RBAC-Modell

- Jeder BISO erhält Lesezugriff (Reader) für jeden Geschäftsbereich (Produkttyp), für den er verantwortlich ist.
- Jeder Produktverantwortliche (Product Owner) erhält Schreibzugriff (Writer) für das Produkt, für das er verantwortlich ist.  Innerhalb ihres Produkts können Product Owner mit DefectDojo interagieren, indem sie Notizen führen, [CI/CD-Pipelines](/import_data/import_scan_files/api_pipeline_modelling/) einrichten, Risikoakzeptanzen erstellen und andere Funktionen nutzen.
- Entwickler bei BigCorp haben überhaupt keinen Zugriff auf DefectDojo und benötigen ihn auch nicht. Der Product Owner kann Jira-Tickets direkt aus DefectDojo heraus erstellen, die alle relevanten Schwachstelleninformationen enthalten.  Die Entwickler nutzen bereits Jira, sodass sie die Behebung nicht anders nachverfolgen müssen als jede andere Entwicklungsaufgabe.

### Eingebettete Systeme: Versionskontrolliertes Reporting

Cyber Robotics ist ein Unternehmen, das Fertigungshardware mit eingebetteten Softwaresystemen verkauft.  Ein Chief Product Officer (CPO) verantwortet dort sowohl das Produkt als auch die Cybersicherheit insgesamt.

Obwohl sie weniger vielfältige Sicherheitsinformationen verwalten müssen als BigCorp, ist es für sie dennoch unerlässlich, ihre Sicherheitsinformationen richtig zu kontextualisieren, damit sie proaktiv auf wichtige Befunde reagieren können.

Wichtige Anliegen von Cyber Robotics:

- Sie haben eine begrenzte Produktlinie, aber **viele** Versionen jedes Produkts, die ordnungsgemäß katalogisiert werden müssen.
- Die Wartung ihrer Produkte ist komplex und die Kosten sind hoch, sodass unnötiger Aufwand vermieden werden muss.

#### Testmodell

Cyber Robotics verfügt über einen standardisierten Testprozess für alle seine eingebetteten Systeme:

- CI/CD-, SAST- und SCA-Tests werden durchgeführt
- Überprüfungen der Sicherheitskontrollen
- Netzwerk-Scans
- Code-Reviews durch Dritte

Da jede Version ihrer Software jedoch isoliert ist, müssen sie zwangsläufig eine große Menge an Daten organisieren, von denen viele nur in einem einzigen Kontext nützlich sind (d. h. der bestimmten Softwareversion, die sie gerade betreiben).

Cyber Robotics kann dieses Problem lösen, indem es Produkttypen verwendet, um eine einzelne Produktlinie darzustellen, und für jede einzelne Version ein separates Produkt anlegt.  So können sie im Detail ermitteln, welche Produkte mit einer bestimmten Schwachstelle verknüpft sind.

![image](images/example_product_hierarchy_robotics.png)

Indem Softwareversionen Produkten und nicht Engagements zugeordnet werden, kann Cyber Robotics bei Bedarf den Zugriff auf eine bestimmte Softwareversion einschränken.  Außendiensttechnikern und Support-Mitarbeitern kann Zugriff auf eine einzelne Softwareversion gewährt werden, ohne ihnen Zugriff auf die gesamte Produktlinie geben zu müssen.

#### RBAC-Modell

Das AppSec-Team verfügt hier über zugewiesene globale Rollen, die den Umfang seiner Interaktion regeln.

- Der CPO verfügt, wie der CISO bei BigCorp, über globalen Lesezugriff (Global Reader) auf DefectDojo.
- Einzelne Product Owner verfügen über globalen Lesezugriff auf jedes Produkt in DefectDojo sowie über Schreibzugriff auf das Produkt, das ihnen gehört.

Auf der Support-Seite:

- Support-Mitarbeitern wird vorübergehend Lesezugriff auf bestimmte Produkte gewährt, für deren Wartung sie zuständig sind, sie haben jedoch keinen Zugriff auf alle DefectDojo-Daten.

### Dynamische IT-Umgebungen und Microservices: Cloud-Services-Unternehmen

Kate's Cloud Service betreibt eine sich schnell verändernde Umgebung, die Kubernetes, Microservices und Automatisierung nutzt.  Kate's Cloud Service hat einen VP of Cloud, der für Cloud-Sicherheitsfragen zuständig ist.  Außerdem gibt es einen CISO, der die angebotene Softwareentwicklung verantwortet, doch in diesem Beispiel konzentrieren wir uns speziell auf ihre Cloud-Sicherheitsanliegen.

Kate's Cloud Service hat sein gesamtes Reporting vollständig automatisiert und erfasst Daten in DefectDojo, sobald Berichte erstellt werden.

Wichtige Anliegen von Kate's Cloud Service:

- Verwaltung der Multi-Tenant-Cloud-Sicherheit, Verhinderung kundenübergreifender Interaktionen bei gleichzeitiger Ermöglichung gemeinsam genutzter Service-Bereitstellung.
- Umgang mit schnellen Änderungen in ihrer Cloud-Umgebung.

#### Tagging gemeinsam genutzter Services

Da Kates Modell viele gemeinsam genutzte Services enthält, die sich auf andere Produkte auswirken können, versieht das Team seine Produkte mit [Tags](/asset_modelling/tags/os__tagging_objects/), um anzuzeigen, welche Cloud-Angebote von diesen Services abhängen.  So können Probleme mit gemeinsam genutzten Services produktübergreifend gefiltert und an die zuständigen Teams gemeldet werden.  Jeder dieser gemeinsam genutzten Services befindet sich in einem eigenen Produkttyp, der sie von den Haupt-Cloud-Angeboten trennt.

![image](images/example_product_hierarchy_microservices.png)

Da das Unternehmen schnell wächst und die Tech Leads häufig wechseln, kann Kate Tags verwenden, um zu verfolgen, welcher Tech Lead aktuell für welches Cloud-Produkt zuständig ist. Dadurch entfällt die Notwendigkeit ständiger manueller Aktualisierungen ihres DefectDojo-Systems. Diese Zuordnungen der Tech Leads werden von einem Dienst außerhalb von DefectDojo verfolgt, der die Import-Pipelines steuern oder die DefectDojo-API aufrufen kann.

Weitere Informationen zum Taggen finden Sie in unserem Leitfaden zu [Tags](/asset_modelling/tags/os__tagging_objects/).

#### RBAC-Modell

Auf der Sicherheits-/Compliance-Seite:

- Das Product-Security-Team, dem DefectDojo gehört, verfügt über Admin-Zugriff auf das gesamte System.
- Analysten, die für den VP of Cloud arbeiten, erhalten systemweiten Lesezugriff, sodass sie die notwendigen Berichte und Metriken erstellen können, damit der VP die Sicherheit der verschiedenen Cloud-Angebote bewerten kann.

Auf der Entwicklungsseite:

- Tech Leads für jedes einzelne Cloud-Produkt (z. B. Compute, Storage, gemeinsam genutzte Services) verfügen über **Maintainer-Zugriff** auf ihr zugewiesenes Produkt, um die Sicherheitsergebnisse für ihr jeweiliges Cloud-Produktangebot zu triagieren. Sie können Befunde überprüfen, innerhalb ihres Produkts Maßnahmen ergreifen und ihre Befunddaten auch umfassend neu organisieren.
- Entwickler, die an bestimmten Produkten arbeiten, erhalten **Schreibzugriff (Writer Access)** auf das Produkt, an dem sie arbeiten, sodass sie Befunde kommentieren, Peer-Reviews anfordern und Risikoakzeptanzen erstellen können.

### Onboarding neuer Akquisitionen: SaaSy Software

SaaSy Software ist ein schnell wachsendes Unternehmen, das häufig andere Softwarefirmen übernimmt.  Jedes Mal, wenn ein neues Unternehmen übernommen wird, sind der Director of Quality Engineering und das AppSec-Team plötzlich für viele neue Code-Repositorys, Entwickler und Prozesse zuständig.  Ihr DefectDojo-Modell stellt sicher, dass sie sich so schnell wie möglich einarbeiten können.

Wichtige Anliegen von SaaSy Software:

- Vermeidung öffentlicher Sicherheitsprobleme bei gleichzeitiger Einhaltung von Compliance-Programmen (wie SOC2).
- Fähigkeit, Tools und Prozesse aus neuen Produkten zuverlässig zu integrieren.
- Fähigkeit, Schwachstellen sowohl auf Produktions- als auch auf Entwicklungs-Branches zu melden und zu kategorisieren.

#### Testmodell

Das Testen bei SaaSy konzentriert sich eher auf grobe Leitlinien als auf standardisierte Tool-Nutzung, da jede Akquisition ihre eigenen Tools und Prozesse für AppSec mitbringt.  SaaSy muss sowohl interne Bewertungen (CI/CD, DAST, Container-Scans und Threat Modeling) als auch externe Bewertungen (Penetrationstests durch Dritte, Compliance-Audits) durchführen.

Um das Onboarding neuer Anwendungen zu unterstützen, verfolgt SaaSy Software einen einheitlichen Ansatz für ihr Datenmodell: Jedes Mal, wenn SaaSy eine neue Anwendung onboardet, wird für diese App ein neuer Produkttyp erstellt und es werden Unterprodukte für die zugehörigen Repositorys angelegt (Front-End, Backend-API usw.).

![image](images/example_product_hierarchy_saas.png)

Jedes dieser Produkte wird weiter in Engagements unterteilt, eines für den Hauptbranch und eines für jeden Entwicklungsbranch.  Tests innerhalb dieser Engagements dienen dazu, die Testaktivitäten zu kategorisieren.  Entwicklungs-Branches verfügen über eigene Tests, die die Ergebnisse von CI/CD- und SCA-Scans speichern.  Der Hauptbranch verfügt ebenfalls darüber, enthält aber zusätzlich Tests, in denen Berichte zu manuellen Code-Reviews und Threat Models gespeichert werden.

Alle diese Tests sind offen angelegt und können regelmäßig per Reimport aktualisiert werden.  Die [Deduplizierung](/triage_findings/finding_deduplication/about_deduplication/) erfolgt nur auf Engagement-Ebene, wodurch verhindert wird, dass Befunde in einem Code-Branch Befunde in einem anderen schließen.

Durch die konsequente Anwendung dieses Modells verfügt SaaSy über ein Modell, das auf jede neue Softwareakquisition angewendet werden kann, und das AppSec-Team kann schnell mit der Überwachung der Daten beginnen, um die Compliance sicherzustellen.

#### RBAC-Modell

Auf der Sicherheits-/Compliance-Seite:

- Das AppSec-Team bei SaaSy Software ist Eigentümer von DefectDojo und verfügt über vollständigen Admin-Zugriff auf die Software.
- QE- und Compliance-Teams verfügen über systemweiten Lesezugriff, um bei Bedarf Berichte abzurufen und Daten im Detail zu prüfen.

Auf der Entwicklungsseite:

- Jeder Product Owner verfügt über Schreibzugriff auf das Produkt, das er in DefectDojo besitzt, wodurch er Risikoakzeptanzen erstellen und Metriken für das Produkt einsehen kann.
- Entwickler verfügen über Lesezugriff auf jedes Produkt, an dem sie arbeiten.  Sie können Peer-Reviews für Befunde oder Probleme anfordern, die sie zu beheben versuchen.
