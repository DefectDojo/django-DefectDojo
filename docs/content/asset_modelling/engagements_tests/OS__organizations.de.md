---
title: Organizations
description: Organizations in DefectDojo OS verstehen
audience: opensource
weight: 1
aliases:
- /asset_modelling/engagements_tests/os_producttype/
- /en/asset_modelling/engagements_tests/os_producttype/
---

**ORGANIZATIONS** → Assets → Engagements → Tests → Befunde

## Überblick 

**Organizations** stehen ganz oben in der Objekthierarchie von DefectDojo. Organizations unterscheiden sich von den untergeordneten Objekten der Hierarchie – Assets, Engagements, Tests und Befunde – dadurch, dass sie keine technischen Scan-Ziele sind, sondern in erster Linie als organisatorische Abstraktionen dienen, die Ihre Sicherheitsarbeit unterteilen nach: 
- Geschäftsbereich
- Entwicklungsteam
- Sicherheitsteam
- Softwareanwendungen
- Übergeordnete Produktfamilie
- Kunde oder Tochtergesellschaft
- Berichtsstruktur
- usw. 

Das gemeinsame Thema der obigen Beispiele veranschaulicht den wesentlichen Nutzen von Organizations: Sie sollten in der Regel stabile, langlebige Grenzen innerhalb Ihres Sicherheitsprogramms darstellen.

## Organization-Daten und -Struktur 

Da Organizations nicht direkt gescannt werden, ist der Name das einzige Pflichtfeld, das zu ihrer Erstellung erforderlich ist. Darüber hinaus fungieren sie als Container für Assets und deren untergeordnete Engagements, Tests und Befunde. 

Überlegen Sie beim Erstellen einer Organization, wie sich deren Struktur auf Ihre Berichterstattung auswirkt. Benötigen Sie Organizations in erster Linie, um die Teams abzubilden, die an den darin enthaltenen Projekten (Assets) arbeiten? Oder sollen Organizations eher übergeordnete Projekte darstellen, die verschiedene Iterationen der darin enthaltenen Projekte (Assets) umfassen?

Wenn eine einzelne Organization alle relevanten Informationen für einen bestimmten Geschäftsbereich oder ein bestimmtes Entwicklungsteam enthält, erleichtert deren Abbildung als Organization eine reibungslosere Berichterstattung, anstatt einen Bericht aus verschiedenen Assets und Organizations zusammenstellen zu müssen. 

Wenn ein bestimmtes Softwareprojekt viele unterschiedliche Deployments oder Versionen hat, kann es sinnvoll sein, eine einzelne Organization zu erstellen, die den Geltungsbereich des gesamten Projekts abdeckt, wobei jede Version als eigenständiges Asset existiert. In manchen Workflows werden Organizations auch verwendet, um Phasen des Software-Lebenszyklus zu trennen: eine Organization für „In Development“, eine Organization für „In Production“ usw.

Organizations können verwendet werden, um für RBAC-Zwecke den Zugriff auf Tochtergesellschaften, übernommene Unternehmen oder andere regulierte Geschäftseinheiten festzulegen. In komplexen Unternehmen mit vielen individuellen Projekten und unterschiedlichen Zugriffsregeln sind Organizations besonders relevant.

Letztlich hängt die Entscheidung, wie Sie Organizations und Assets einsetzen, davon ab, wie Sie Ihre individuelle Organisationsstruktur und die Anforderungen Ihres Sicherheitsteams am besten abbilden möchten. 

Nachfolgend finden Sie einige Beispielstrukturen, die Ihnen helfen zu entscheiden, ob Sie Ihre Objekte als Organizations oder als Assets festlegen. 

- **Organization**: Payments Division
    - Asset: Payments API - Production
    - Asset: Payments API - Staging
    - Asset: Billing Worker

- **Organization**: Software Product A
    - Asset: Web Portal
    - Asset: Mobile Backend

Die folgende Übersicht dient außerdem als Orientierungshilfe dafür, ob etwas besser als Organization oder als Asset abgebildet werden sollte: 

| Organizations | Assets |
|--------------|--------|
| Geschäftseinheiten | Einzelne Anwendungen |
| Abteilungen | Deployments/Umgebungen |
| Sicherheits-Verantwortungsbereiche | Infrastrukturkomponenten |
| Produktfamilien | Spezifische Microservices |
| Berichterstattung auf Portfolio-Ebene | Scan-Ziele |
| Kunden | Spezifische Softwareversionen |

Wie bereits erwähnt, kann Ihre Struktur je nach Ihren individuellen Sicherheitsanforderungen abweichen.

## Zugriff auf Organizations 

Organizations sind über die Seitenleiste zugänglich. Das Untermenü bietet außerdem die Möglichkeit, neue Organizations zu erstellen.

![image](images/organization_ss1.png)

### Organization-Ansicht 

Die Ansicht einer Organization enthält verschiedene Tabellen und Diagramme, um ihren Status auf einen Blick zu erfassen. Dazu gehören: 
- **Beschreibung**
- **Key/Critical-Checkbox**
    - Das Aktivieren von Critical oder Key dient ausschließlich Filterzwecken 
- **Liste der Assets innerhalb der Organization**
- **Autorisierte Benutzer** (DefectDojo-Benutzer)

## Arbeiten mit Organizations 

### Organizations erstellen 

Es gibt zwei Möglichkeiten, Organizations zu erstellen: 

- Über die Option **Add Organization** im Seitenmenü
- Über die Schaltfläche **Add Organization** oben in der Liste All Organizations 

### Organizations bearbeiten 

Organizations können bearbeitet werden, indem Sie in der Ansicht der Organization oben rechts in der Description-Tabelle im Dropdown-Menü auf **Edit** klicken. Dasselbe Menü ist auch über das Kebab-Menü ⋮ links neben der Organization in der Liste All Organizations erreichbar.

Alle weiteren bearbeitbaren Felder stehen auch beim Erstellen der Organization zur Verfügung.

### Organizations löschen 

Eine Organization können Sie löschen, indem Sie in den Einstellungen der Organization **Delete Organization** auswählen. 

Da Organizations ganz oben in der Hierarchie stehen, entfernt das Löschen den gesamten nachgelagerten Sicherheitsverlauf, alle Beziehungen und untergeordneten Objekte, darunter: 
- Alle in der Organization enthaltenen Assets, Engagements und Tests
- Der gesamte zugehörige Sicherheitsverlauf, einschließlich Befunde und Integrationen
- Alle verknüpften Jira Epics
- Alle Notizen und hochgeladenen Dateien, die mit den Assets, Engagements und Tests dieser Organization verknüpft sind

Das Löschen einer Organization kann nicht rückgängig gemacht werden. Wenn Sie eine Organization „stilllegen“ möchten, ohne die zugrunde liegenden Daten zu löschen (zum Beispiel um alte Testaufzeichnungen aus Audit-Gründen zu erhalten), können Sie den Namen der Organization ändern oder einen Tag hinzufügen, der den veralteten Status kennzeichnet.

## Organizations vs. Metadaten

Organizations sollen strukturelle Zuständigkeiten oder Berichtsgrenzen abbilden und keine leichtgewichtigen Klassifizierungen. Attribute wie Deployment-Status, interne Kennzeichnungen oder temporäre Workflow-Zustände lassen sich oft besser über Tags oder Metadaten abbilden als über separate Organizations.

## Organization-Grenzen 

Organizations legen sowohl Berichts- als auch Zugriffsgrenzen innerhalb von DefectDojo fest. Da Integrationen, RBAC-Berechtigungen, Zuständigkeiten, Metriken und Deduplizierungsmodelle häufig die Struktur der Organizations übernehmen, hilft eine frühzeitig klar gestaltete Grenzziehung dabei, spätere Hierarchie-Wildwuchs und fragmentierte Berichterstattung zu vermeiden.

### Befunde und Automatisierung 

Obwohl Integrationen üblicherweise auf untergeordneten Objekten wie Assets, Engagements oder Befunden konfiguriert werden, legen Organizations dennoch die Zuständigkeits-, Berichts- und Zugriffsgrenzen fest, innerhalb derer diese Integrationen arbeiten.

Berechtigungen werden nach unten vererbt, das heißt, der Zugriff auf eine Organization gewährt automatisch Zugriff auf alle Objekte innerhalb dieser Organization (z. B. Assets, Engagements, Tests und Befunde). 

Das RBAC-Modell von DefectDojo kann verwendet werden, um den Zugriff menschlicher Benutzer zu steuern, aber auch, um den Zugriff von API-Tokens auf bestimmte Organizations zu beschränken.

Weitere Informationen zu Benutzerrollen finden Sie in unserem Artikel [Permissions](/admin/user_management/os__authorized_users/).

### Zuständigkeit 

Als Objekte auf oberster Ebene implizieren Organizations auch die Zuständigkeit für die darin enthaltenen untergeordneten Objekte. SLA-Tracking, Remediation-Workflows, Ticket-Routing und die allgemeine Governance funktionieren reibungsloser, wenn Organizations so eingerichtet sind, dass sie die verantwortlichen Personen korrekt widerspiegeln.

### Metriken/Berichterstattung 

Metrik-Dashboards, Kacheln und Ansichten können nach Organization gefiltert werden, wodurch sie eine wesentliche Rolle dabei spielen, wie Ihre Sicherheitsdaten berechnet, visualisiert und letztlich exportiert werden. 

Für Berichtszwecke ist es in der Regel einfacher, mehrere Organizations in einem einzigen Dokument zusammenzufassen, als eine einzelne Organization in separate Dokumente aufzuteilen. Wir empfehlen daher, Organizations so granular anzulegen, wie es für die Berichte Ihres Teams sinnvoll ist. Es besteht beispielsweise keine Notwendigkeit, einen großen Geschäftsbereich als Organization abzubilden, wenn Sie hauptsächlich an einzelne Abteilungen innerhalb dieses Bereichs berichten werden.

Eine wirksame Strukturierung Ihrer Organizations entsprechend Ihren Berichtsanforderungen ist entscheidend für eine präzise Bewertung Ihrer Sicherheitslage. Weitere Informationen zu Metrics finden Sie [hier](/metrics_reports/dashboards/introduction_dashboard/).

### Deduplizierung 

Die Deduplizierung in DefectDojo erfolgt auf Asset-Ebene und wird von der übergeordneten Organization nicht beeinflusst.
