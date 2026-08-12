---
title: Organisationen
description: Organisationen in DefectDojo Pro verstehen
audience: pro
weight: 1
---

**ORGANISATIONEN** → Assets → Engagements → Tests → Befunde

## Überblick

**Organisationen** stehen ganz oben in der Produkthierarchie von DefectDojo. Organisationen unterscheiden sich von den nachgeordneten Objekten der Hierarchie — Assets, Engagements, Tests und Befunden —, da sie keine technischen Scan-Ziele sind, sondern in erster Linie als organisatorische Abstraktionen dienen, die Ihre Sicherheitsbemühungen unterteilen nach:
- Geschäftsbereich
- Entwicklungsteam
- Sicherheitsteam
- Softwareanwendungen
- Übergeordneter Produktfamilie
- Kunde oder Tochtergesellschaft
- Berichtsstruktur
- usw.

Das gemeinsame Thema der obigen Beispiele veranschaulicht den wesentlichen Nutzen von Organisationen: Sie sollten in der Regel stabile, langlebige Grenzen innerhalb Ihres Sicherheitsprogramms darstellen.

## Organisationsdaten und -struktur

Da Organisationen nicht direkt gescannt werden, ist der Name das einzige Pflichtfeld, das zu ihrer Erstellung erforderlich ist. Darüber hinaus fungieren sie als Container für Assets und deren nachgeordnete Engagements, Tests und Befunde.

Überlegen Sie beim Erstellen einer Organisation, wie deren Struktur Ihre Berichterstellung beeinflussen wird. Benötigen Sie Organisationen in erster Linie, um die Teams abzubilden, die an den Projekten (Assets) arbeiten, welche die Organisationen enthalten werden? Oder würden Organisationen besser übergeordnete Projekte darstellen, die unterschiedliche Iterationen der darin enthaltenen Projekte (Assets) umfassen?

Wenn Sie eine einzelne Organisation haben, die alle relevanten Informationen für einen bestimmten Geschäftsbereich oder ein bestimmtes Entwicklungsteam enthält, erleichtert deren Abbildung als Organisation eine reibungslosere Berichterstellung, anstatt einen Bericht aus verschiedenen Assets und Organisationen zusammenstellen zu müssen.

Wenn ein bestimmtes Softwareprojekt viele verschiedene Bereitstellungen oder Versionen hat, kann es sich lohnen, eine einzelne Organisation zu erstellen, die den Umfang des gesamten Projekts abdeckt, wobei jede Version als einzelnes Asset existiert. In manchen Workflows werden Organisationen auch verwendet, um Phasen des Softwarelebenszyklus zu trennen: eine Organisation für „In Entwicklung", eine Organisation für „In Produktion" usw.
​
Organisationen können verwendet werden, um für RBAC-Zwecke den Zugriff auf Tochtergesellschaften, erworbene Unternehmen oder andere regulierte Geschäftseinheiten festzulegen. In komplexen Unternehmen, in denen es viele einzigartige Projekte mit unterschiedlichen Zugriffsregeln gibt, sind Organisationen besonders relevant.

Letztlich hängt die Entscheidung, wie Organisationen und Assets verwendet werden, davon ab, wie Sie Ihre individuelle Organisationsstruktur und die Anforderungen Ihres Sicherheitsteams am besten abbilden möchten.

Nachfolgend finden Sie einige Beispielstrukturen, die Ihnen als Orientierung dienen, wie Sie Ihre Objekte entweder als Organisationen oder als Assets festlegen.

- **Organisation**: Zahlungsabteilung
    - Asset: Payments API - Production
    - Asset: Payments API - Staging
    - Asset: Billing Worker

- **Organisation**: Softwareprodukt A
    - Asset: Web Portal
    - Asset: Mobile Backend

Darüber hinaus dient die folgende Übersicht als Orientierungshilfe, ob etwas besser durch eine Organisation oder ein Asset dargestellt wird:

| Organizations | Assets |
|--------------|--------|
| Geschäftseinheiten | Einzelne Anwendungen |
| Abteilungen | Bereitstellungen/Umgebungen |
| Sicherheitszuständigkeitsbereiche | Infrastrukturkomponenten |
| Produktfamilien | Spezifische Microservices |
| Portfolioebene-Berichterstattung | Scan-Ziele |
| Kunden | Spezifische Softwareversionen |

Wie bereits erwähnt, kann Ihre Struktur je nach Ihren individuellen Sicherheitsanforderungen abweichen.

## Zugriff auf Organisationen

Organisationen sind über die Seitenleiste zugänglich. Das Untermenü bietet Zugriff auf Alle Organisationen sowie die Möglichkeit, eine neue Organisation zu erstellen.

![image](images/org_ss1.png)

## Organisationsansicht

Die Ansicht einer Organisation enthält verschiedene Tabellen und Diagramme, um deren Status auf einen Blick zu erfassen. Dazu gehören:

- **Beschreibung**
- **Commerce**
    - Ob die Organisation als Kritisch oder Wichtig eingestuft wurde
        - Die Kennzeichnung als Kritisch oder Wichtig dient ausschließlich Filterzwecken
- **Zugewiesene Mitglieder** (DefectDojo-Benutzer)
- **Zugewiesene Benutzergruppen**
    - Benutzergruppen, die der Organisation zur Berechtigungssteuerung zugewiesen wurden. Weitere Informationen zu Benutzergruppen finden Sie [hier](/admin/user_management/create_user_group/).
- **Liste der Assets innerhalb der Organisation**

## Arbeiten mit Organisationen

### Organisationen erstellen

Es gibt zwei Möglichkeiten, Organisationen zu erstellen:

- Über die Option **Neue Organisation** im Seitenmenü
- Über die Schaltfläche **Neue Organisation** oben in der Liste Alle Organisationen

### Organisationen bearbeiten

Organisationen können bearbeitet werden, indem Sie im Zahnradmenü oben rechts in der Ansicht der Organisation auf **Organisation bearbeiten** klicken. Dasselbe Menü kann auch über das ⋮-Kebab-Menü links neben der Organisation in der Ansicht Alle Organisationen aufgerufen werden.

Alle daraufhin bearbeitbaren Felder sind auch bereits beim Erstellen der Organisation verfügbar.

### Organisationen löschen

Das Löschen einer Organisation erfolgt, indem Sie in den Einstellungen der Organisation **Organisation löschen** auswählen.

Da Organisationen ganz oben in der Hierarchie stehen, werden beim Löschen sämtlicher nachgeordneter Sicherheitsverlauf, Beziehungen und untergeordnete Objekte entfernt, wie zum Beispiel:
- Alle in der Organisation enthaltenen Assets, Engagements und Tests
- Der gesamte zugehörige Sicherheitsverlauf, einschließlich Befunde und Integrationen
- Alle verknüpften Jira-Epics
- Alle Notizen und Datei-Uploads, die mit den Assets, Engagements und Tests innerhalb dieser Organisation verknüpft sind

Das Löschen einer Organisation kann nicht rückgängig gemacht werden. Wenn Sie eine Organisation „außer Betrieb nehmen" möchten, ohne die zugrunde liegenden Daten zu löschen (zum Beispiel, um alte Software-Testaufzeichnungen zu Auditzwecken zu erhalten), können Sie den Namen der Organisation ändern oder einen Tag hinzufügen, der anzeigt, dass sie sich in einem veralteten Zustand befindet.

## Organisationen vs. Metadaten

Organisationen sollen strukturelle Zuständigkeiten oder Berichtsgrenzen abbilden und keine leichtgewichtigen Klassifizierungen. Attribute wie Bereitstellungsstatus, interne Kennzeichnungen oder temporäre Workflow-Zustände lassen sich oft besser durch Tags oder Metadaten abbilden als durch separate Organisationen.

## Organisationsgrenzen

Organisationen legen sowohl Berichts- als auch Zugriffsgrenzen innerhalb von DefectDojo fest. Da Integrationen, RBAC-Berechtigungen, Zuständigkeiten, Metriken und Deduplizierungsmodelle häufig die Struktur der Organisationen übernehmen, hilft eine frühzeitig klar gestaltete Grenzziehung dabei, spätere Hierarchie-Wildwuchs und Fragmentierung der Berichterstattung zu vermeiden.

### Befunde und Automatisierung

Obwohl Integrationen in der Regel auf untergeordneten Objekten wie Assets, Engagements oder Befunden konfiguriert werden, legen Organisationen weiterhin die Zuständigkeits-, Berichts- und Zugriffsgrenzen fest, innerhalb derer diese Integrationen arbeiten.

Berechtigungen kaskadieren nach unten, das heißt, der Zugriff auf eine Organisation gewährt automatisch Zugriff auf alle Objekte innerhalb dieser Organisation (z. B. Assets, Engagements, Tests und Befunde).

Das RBAC-Modell von DefectDojo kann verwendet werden, um den Zugriff menschlicher Benutzer zu steuern, aber auch, um den Zugriff von API-Token auf bestimmte Organisationen zu beschränken.

Weitere Informationen zu Benutzerrollen finden Sie in unserem Artikel [Einführung in die Berechtigungstypen](/admin/user_management/set_user_permissions/#introduction-to-permission-types).

### Eigentümerschaft

Als übergeordnete Objekte implizieren Organisationen auch die Zuständigkeit für die darin enthaltenen untergeordneten Objekte. SLA-Nachverfolgung, Behebungs-Workflows, Ticket-Routing und die allgemeine Governance funktionieren reibungsloser, wenn Organisationen so eingerichtet wurden, dass sie die dafür verantwortlichen Personen genau widerspiegeln.

### Metriken/Berichterstellung

Metrik-Dashboards, Kacheln und Ansichten können nach Organisation gefiltert werden, wodurch sie eine entscheidende Komponente dafür sind, wie Ihre Sicherheitsdaten berechnet, visualisiert und letztlich exportiert werden.

Für Berichtszwecke ist es in der Regel einfacher, mehrere Organisationen in einem einzigen Dokument zusammenzufassen, als eine einzelne Organisation in separate Dokumente aufzuteilen. Wir empfehlen daher, Organisationen so granular einzurichten, wie es für die Berichte Ihres Teams sinnvoll ist. Es besteht beispielsweise keine Notwendigkeit, eine große Geschäftseinheit als Organisation abzubilden, wenn Sie hauptsächlich an einzelne Abteilungen innerhalb dieser Einheit berichten werden.

Eine effektive Strukturierung Ihrer Organisationen entsprechend Ihren Berichtsanforderungen ist entscheidend für eine genaue Bewertung Ihrer Sicherheitslage. Weitere Informationen zu Metriken finden Sie [hier](/metrics_reports/pro_metrics/pro__overview/).

### Deduplizierung

Die Deduplizierung in DefectDojo erfolgt auf Asset-Ebene und wird von der übergeordneten Organisation nicht beeinflusst.