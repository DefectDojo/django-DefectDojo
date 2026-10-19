---
title: Berechtigungsübersichten für Aktionen
description: Alle Benutzerberechtigungen von DefectDojo Pro im Detail
weight: 4
audience: pro
aliases:
- /en/customize_dojo/user_management/user_permission_chart
---

> **DefectDojo Pro-Funktion.** Das auf dieser Seite beschriebene RBAC-System für Mitglieder/Gruppen/Globale Rollen ist Teil von DefectDojo Pro. Open-Source-DefectDojo verwendet das Modell [Autorisierte Benutzer](../os__authorized_users/) — siehe diese Seite für die Zugriffskontrolle in der Open-Source-Version sowie die [3.0-Upgrade-Hinweise](/releases/os_upgrading/3.0/#authorized-users-panel-replaces-membersgroups-under-legacy-authorization), wenn Sie zwischen den Editionen wechseln.

## Rollen-Berechtigungsübersicht

Diese Übersicht listet alle Berechtigungen auf, die sich auf ein Produkt oder einen Produkttyp beziehen, sowie welche Berechtigungen für welche Rolle verfügbar sind.

Die folgenden fünf Rollen sind die **integrierten Rollen** von DefectDojo Pro. Es handelt sich um feste Voreinstellungen: Ihre Berechtigungen sind auf jeder Instanz identisch und können nicht geändert werden. Wenn Sie eigene Rollen erstellt haben, beschreibt diese Übersicht die integrierten Rollen, aus denen sie geklont wurden, und nicht die Rollen selbst. Den vollständigen Katalog der Berechtigungen, die einer Rolle zugewiesen werden können, finden Sie unter [Benutzerdefinierte RBAC-Rollen](../pro__custom_rbac_roles/#choosing-permissions).

| **Abschnitt** | **Berechtigung** | Reader | Writer | Maintainer | Owner | API Importer |
| --- | --- | --- | --- | --- | --- | --- |
| **Produkt-/Produkttyp-Zugriff** | Zugewiesenes Produkt oder Produkttyp anzeigen ¹ | ☑️ | ☑️ | ☑️ | ☑️ | ☑️ |
|  | Verschachtelte Produkte, Engagements, Tests, Befunde, Endpunkte anzeigen | ☑️ | ☑️ | ☑️ | ☑️ | ☑️ |
|  | Neue Produkte hinzufügen (innerhalb des zugewiesenen Produkttyps) ² |  |  | ☑️ | ☑️ |  |
|  | Zugewiesene Produkte oder Produkttypen löschen |  |  |  | ☑️ |  |
| **Produkt-/Produkttyp-Mitgliedschaft** | Benutzer als Mitglieder hinzufügen (ohne Owner-Rolle) |  |  | ☑️ | ☑️ |  |
|  | Rollen von Mitgliedern bearbeiten (ohne Owner-Rolle) |  |  | ☑️ | ☑️ |  |
|  | Rollen von Mitgliedern bearbeiten (einschließlich Owner-Rolle) |  |  |  | ☑️ |  |
|  | Sich selbst aus der Produkt-/Produkttyp-Mitgliedschaft entfernen | ☑️ | ☑️ | ☑️ | ☑️ |  |
|  | Einem anderen Benutzer eine Owner-Rolle zuweisen |  |  |  | ☑️ |  |
|  | Eine zugehörige Produkt-/Produkttyp-Mitgliedschaft innerhalb einer Gruppe bearbeiten³ |  |  |  | ☑️ |  |
|  | Eine zugehörige Produkt-/Produkttyp-Mitgliedschaft innerhalb einer Gruppe löschen³ |  |  |  |  |  |
| **Engagements** (innerhalb eines Produkts) | Engagements hinzufügen, bearbeiten |  | ☑️ | ☑️ | ☑️ | ☑️ |
|  | Risikoakzeptanzen anzeigen ⁴ |  | ☑️ | ☑️ | ☑️ |  |
|  | Risikoakzeptanzen hinzufügen, bearbeiten |  | ☑️ | ☑️ | ☑️ |  |
|  | Engagements löschen |  |  | ☑️ | ☑️ |  |
| **Tests** (innerhalb eines Produkts) | Tests hinzufügen |  | ☑️ | ☑️ | ☑️ |  |
|  | Tests bearbeiten |  | ☑️ | ☑️ | ☑️ | ☑️ |
|  | Tests löschen |  |  | ☑️ | ☑️ |  |
| **Befunde**  (innerhalb eines Produkts) | Befunde hinzufügen |  | ☑️ | ☑️ | ☑️ |  |
|  | Befunde bearbeiten |  | ☑️ | ☑️ | ☑️ |  |
|  | Scan-Ergebnisse importieren, erneut importieren |  | ☑️ | ☑️ | ☑️ | ☑️ |
|  | Befunde löschen |  |  | ☑️ | ☑️ |  |
|  | Finding-Gruppen hinzufügen, bearbeiten, löschen |  | ☑️ | ☑️ | ☑️ |  |
| **Weitere Daten**  (innerhalb eines Produkts) | Endpunkte hinzufügen, bearbeiten |  | ☑️ | ☑️ | ☑️ |  |
|  | Endpunkte löschen |  |  | ☑️ | ☑️ |  |
|  | Benchmarks bearbeiten |  | ☑️ | ☑️ | ☑️ |  |
|  | Benchmarks löschen |  |  | ☑️ | ☑️ |  |
|  | Notizverlauf anzeigen | ☑️ | ☑️ | ☑️ | ☑️ |  |
|  | Eigene Notizen hinzufügen, bearbeiten, löschen | ☑️ | ☑️ | ☑️ | ☑️ | ☑️ |
|  | Notizen anderer bearbeiten |  | ☑️ | ☑️ | ☑️ | ☑️ |
|  | Notizen anderer löschen |  |  | ☑️ | ☑️ |  |

1. Ein Benutzer, dem nur auf Produktebene Berechtigungen zugewiesen wurden, kann den Produkttyp, dem das Produkt zugeordnet ist, nicht einsehen.
2. Wenn ein neues Produkt unter einem Produkttyp hinzugefügt wird, werden alle Benutzer auf Produkttyp-Ebene mit ihrer Produkttyp-Rolle als Mitglieder des neuen Produkts hinzugefügt.
3. Der Benutzer, der Änderungen an einer Gruppe vornehmen möchte, muss außerdem über die **Konfigurationsberechtigung** **Gruppe bearbeiten** sowie über die **Gruppen-Konfigurationsrolle** **Maintainer oder Owner** in der Gruppe verfügen, die er bearbeiten möchte.
4. Die Sichtbarkeit von Risikoakzeptanzen wird durch eine eigene Mindestberechtigung geregelt, die sich von der Sichtbarkeit von Befunden unterscheidet — ein Reader für das Produkt kann die zugrunde liegenden Befunde einsehen, aber **nicht** die Risikoakzeptanzen, zu denen diese Befunde gehören.  Details zu Berechtigungen für Risikoakzeptanzen, dem Verhalten des Ablaufdatums und den Workflows zur Wiedereinsetzung finden Sie unter [Risikoakzeptanzen (Pro)](/triage_findings/findings_workflows/pro__risk_acceptance/#risk-acceptance-permissions-and-visibility).

## Konfigurationsberechtigungsübersicht

Jede Konfigurationsberechtigung bezieht sich auf eine bestimmte Funktion der Software und ist mit einer Reihe von Aktionen verknüpft, die ein Benutzer im Zusammenhang mit dieser Funktion ausführen kann.

Die meisten Konfigurationsberechtigungen gewähren Benutzern Zugriff auf bestimmte Seiten der Benutzeroberfläche.

| **Konfigurationsberechtigung** | **Anzeigen ☑️** | **Hinzufügen ☑️** | **Bearbeiten ☑️** | **Löschen ☑️** |
| --- | --- | --- | --- | --- |
| Credential Manager | Zugriff auf die Seite **⚙️Konfiguration \> Credential Manager** | Neue Einträge im Credential Manager hinzufügen | Einträge im Credential Manager bearbeiten | Einträge im Credential Manager löschen |
| Entwicklungsumgebungen | entfällt | Neue Entwicklungsumgebungen zur Liste 🗓️**Engagements \> Umgebungen** hinzufügen | Entwicklungsumgebungen in der Liste 🗓️**Engagements \> Umgebungen** bearbeiten | Entwicklungsumgebungen aus der Liste **🗓️Engagements \> Umgebungen** löschen |
| Finding-Vorlagen¹ | Zugriff auf die Seite **Befunde \> Finding-Vorlagen** | Eine Finding-Vorlage hinzufügen | Eine Finding-Vorlage bearbeiten | Eine Finding-Vorlage löschen |
| Gruppen | Zugriff auf die Seite **👤Benutzer \> Gruppen** | Eine neue Benutzergruppe hinzufügen | Nur Superuser | Nur Superuser |
| Jira-Instanzen | Zugriff auf die **Seite ⚙️Konfiguration \> JIRA** | Eine neue JIRA-Konfiguration hinzufügen | Eine bestehende JIRA-Konfiguration bearbeiten | Eine JIRA-Konfiguration löschen |
| Sprachtypen |  |  |  |  |
| Login-Banner | entfällt | entfällt | Das Login-Banner bearbeiten, zu finden unter **⚙️Konfiguration \> Login-Banner** | entfällt |
| Ankündigungen | entfällt | entfällt | Ankündigungen konfigurieren, zu finden unter  **⚙️Konfiguration \> Ankündigungen** | entfällt |
| Notiztypen | Zugriff auf die Seite ⚙️Konfiguration \> Notiztypen | Einen Notiztyp hinzufügen | Einen Notiztyp bearbeiten | Einen Notiztyp löschen |
| Priorisierungs-Engines | Zugriff auf die Konfigurationsseite der Priorisierungs-Engine | Eine neue Priorisierungs-Engine hinzufügen | Eine bestehende Priorisierungs-Engine bearbeiten | Eine Priorisierungs-Engine löschen |
| Produkttypen | entfällt | Einen neuen Produkttyp hinzufügen (unter Produkte \> Produkttyp) | entfällt | entfällt |
| Fragebögen | Zugriff auf die Seite **Fragebögen \> Alle Fragebögen** | Einen neuen Fragebogen hinzufügen | Einen bestehenden Fragebogen bearbeiten | Einen Fragebogen löschen |
| Fragen | Zugriff auf die Seite **Fragebögen \> Fragen** | Eine neue Frage hinzufügen | Eine bestehende Frage bearbeiten | entfällt |
| Regularien | entfällt | Eine Regularie zur Seite **⚙️Konfiguration \> Regularien** hinzufügen | Eine bestehende Regularie bearbeiten | Eine Regularie löschen |
| Scheduling Service Schedule | Zugriff auf die Seite **Scheduling** | Nur Superuser | Einen bestehenden Zeitplan bearbeiten (Trigger ändern, aktivieren/deaktivieren) | Einen Zeitplan löschen |
| SLA-Konfiguration | Zugriff auf die Seite **⚙️Konfiguration \> SLA-Konfiguration** | Eine neue SLA-Konfiguration hinzufügen | Eine bestehende SLA-Konfiguration bearbeiten | Eine SLA-Konfiguration löschen |
| Testtypen | entfällt | Einen neuen Testtyp hinzufügen (unter **Engagements \> Testtypen**) | Einen bestehenden Testtyp bearbeiten | entfällt |
| Tool-Konfiguration | Zugriff auf die Seite **⚙️Konfiguration \> Tool-Konfiguration** | Eine neue Tool-Konfiguration hinzufügen | Eine bestehende Tool-Konfiguration bearbeiten | Eine Tool-Konfiguration löschen |
| Tool-Typen | Zugriff auf die Seite **⚙️Konfiguration \> Tool-Typen** | Einen neuen Tool-Typ hinzufügen | Einen bestehenden Tool-Typ bearbeiten | Einen Tool-Typ löschen |
| Benutzer | Zugriff auf die Seite **👤Benutzer \> Benutzer** | Einen neuen Benutzer zu DefectDojo hinzufügen | Einen bestehenden Benutzer bearbeiten | Einen Benutzer löschen |

1. Der Zugriff auf die Seite Finding-Vorlagen erfordert für diesen Benutzer außerdem die Globale Rolle **Writer, Maintainer** oder **Owner**.

## Gruppen-Konfigurationsberechtigungen

| Konfigurationsberechtigung | **Reader** | **Maintainer** | **Owner** |
| --- | --- | --- | --- |
| Gruppe anzeigen | ☑️ | ☑️ | ☑️ |
| Sich selbst aus der Gruppe entfernen | ☑️ | ☑️ | ☑️ |
| Die Rolle eines Mitglieds in einer Gruppe bearbeiten |  | ☑️ | ☑️ |
| Eine Produkt- oder Produkttyp-Mitgliedschaft aus einer Gruppe bearbeiten oder löschen¹ |  | ☑️ | ☑️ |
| Die Rolle eines Gruppenmitglieds zu Owner ändern |  |  | ☑️ |
| Gruppe löschen |  |  | ☑️ |

1. Dies erfordert außerdem, dass der Benutzer mindestens die Rolle Maintainer für das Produkt oder den Produkttyp hat, das bzw. den er bearbeiten möchte.
