---
title: Das Settings-Menü
description: Wie der Settings-Bereich der Seitenleiste von DefectDojo Pro aufgebaut
  ist, die Verzeichnisseite All Settings und wie Sie zwischen dem aktuellen und dem
  vorherigen Layout wechseln
weight: 6
audience: pro
---

Der Settings-Bereich der Seitenleiste bündelt alle administrativen Seiten von DefectDojo Pro. Welches Layout Sie sehen, hängt davon ab, wann Ihre Instanz erstellt wurde:

- **Neue Installationen** starten mit dem unten beschriebenen neu organisierten Layout.
- **Bestehende Installationen** behalten das bisherige Layout bei, bis ein Administrator **Menu 2.0** aktiviert (siehe [Layouts wechseln](#switching-layouts)).

In beiden Fällen behält **jede Settings-Seite dieselbe URL**. Lesezeichen, gespeicherte Links und alles in Ihren eigenen Runbooks funktionieren weiterhin, unabhängig davon, welches Layout aktiv ist.

## Das neu organisierte Layout

Settings ist in sieben Gruppen unterteilt, die nach dem benannt sind, was Sie erreichen möchten, statt nach dem betroffenen Teil des Systems.

| Gruppe | Was sie enthält |
| --- | --- |
| **System** | System Settings, Appearance, Announcement Banner, Login Banner, Email, Feature Flags |
| **Users & Permissions** | Users, Groups, Roles |
| **Finding Workflow** | Die drei Deduplication-Seiten, Finding Enrichment, Service Level Agreements, Prioritization Engines, Mitigation Policies |
| **Configuration** | Environments, Regulations, Note Types, Test Types, CI/CD Infrastructure, Tool Types, Tool Configurations |
| **Notifications** | Notification Events, Notification Webhooks |
| **Operations** | Audit Logs, Usage Logs, Schedules, Celery Status sowie — bei DefectDojo Cloud — Message Portal, Firewall Rules, Maintenance Windows |
| **License & Support** | License Manager, Version Manager, Contact Support |

Sie sehen immer nur die Einträge, für deren Öffnen Ihr Konto berechtigt ist, und eine Gruppe verschwindet vollständig, wenn keine ihrer Seiten für Sie verfügbar ist.

Zwei Konventionen sind erwähnenswert:

- **Es gibt keine separaten „New"-Einträge.** Jede Listenseite verfügt über eine Schaltfläche **New**, die das Erstellungsformular öffnet, sodass das Menü pro Katalog einen statt zwei Einträge enthält. Wenn Ihr Konto Datensätze erstellen, aber nicht auflisten kann, führt der Menüeintrag Sie direkt zum Erstellungsformular.
- **Nichts ist mehr als eine Ebene unterhalb einer Gruppe verschachtelt.** Um eine Seite zu erreichen, sind höchstens Settings → Gruppe → Seite nötig.

## All Settings

Der erste Eintrag im Bereich, **All Settings**, öffnet ein Verzeichnis aller Settings-Seiten, auf die Ihr Konto zugreifen kann, angeordnet in denselben Gruppen wie im Menü und durchsuchbar nach Name oder nach der Funktion der Seite. Die Suche nach `deduplication` findet die drei Deduplication-Seiten *und* System Settings, da System Settings ebenfalls Deduplication-Optionen enthält.

Die letzte Kategorie, **Elsewhere in the app**, listet Seiten auf, die DefectDojo konfigurieren, sich aber in anderen Bereichen der Seitenleiste befinden — die Autorisierungsanbieter, die Login- und MFA-Einstellungen, Jira-Instanzen, die Upstream- und Downstream-Connectors sowie den Universal Parser. Jede Kachel ist mit einem Chip versehen, der den Bereich angibt, zu dem sie gehört.

## Was sich verschoben hat

Wenn Sie an das vorherige Layout gewöhnt sind:

| Vorher | Jetzt |
| --- | --- |
| Settings → *(oberste Ebene)* → Feature Flags | Settings → System → Feature Flags |
| Settings → Pro Settings → System Settings | Settings → System → System Settings |
| Settings → Pro Settings → Appearance | Settings → System → Appearance |
| Settings → Pro Settings → Banner Settings → Announcement Banner Settings | Settings → System → Announcement Banner |
| Settings → Pro Settings → Banner Settings → Login Banner Settings | Settings → System → Login Banner |
| Settings → Pro Settings → Email Settings | Settings → System → Email |
| Settings → Users → All Users / New User | Settings → Users & Permissions → Users |
| Settings → Users → All Groups / New Group | Settings → Users & Permissions → Groups |
| Settings → Users → Roles | Settings → Users & Permissions → Roles |
| Settings → Pro Settings → Deduplication Settings → *(drei Seiten)* | Settings → Finding Workflow → Same Tool / Cross Tool / Reimport Deduplication |
| Settings → Pro Settings → Finding Enrichment Settings | Settings → Finding Workflow → Finding Enrichment |
| Settings → Configuration → Service Level Agreements | Settings → Finding Workflow → Service Level Agreements |
| Settings → Configuration → Prioritization Engines | Settings → Finding Workflow → Prioritization Engines |
| Settings → Configuration → Mitigation Policies | Settings → Finding Workflow → Mitigation Policies |
| Settings → Configuration → *(Referenzdaten-Kataloge)* | Settings → Configuration → *(unverändert)* |
| Settings → Pro Settings → Notification Settings | Settings → Notifications |
| Settings → Configuration → Audit Logs | Settings → Operations → Audit Logs |
| Settings → Configuration → Usage log | Settings → Operations → Usage Logs |
| Settings → Configuration → All Schedules | Settings → Operations → Schedules |
| Settings → Pro Settings → Celery Status | Settings → Operations → Celery Status |
| Settings → Cloud Manager → *(Cloud-Seiten)* | Settings → Operations |
| Settings → License Manager / Version Manager / Contact Support | Settings → License & Support |

Die Gruppe, die nach Ihrem Lizenzpaket benannt war — **Pro Settings** bei einer Pro-Instanz, **Enterprise Settings** bei einer Enterprise-Instanz — existiert nicht mehr. Ihre Seiten sind auf System, Finding Workflow, Notifications und Operations verteilt.

## Layouts wechseln

**Menu 2.0** auf der Seite [Feature Flags](/admin/feature_flags/pro__feature_flags/) steuert, welches Layout aktiv ist. Das Ein- oder Ausschalten formt die Seitenleiste sofort um; es ist kein Neustart erforderlich, und nichts anderes an Ihrer Instanz ändert sich.

Neue Installationen starten mit aktivierter Option. Bestehende Installationen starten mit deaktivierter Option, sodass ein Upgrade das Menü nie mitten im laufenden Betrieb eines Teams umstellt — schalten Sie die Option ein, sobald Ihre Administratoren bereit sind.

Solange die Option deaktiviert ist, ist die Seite **All Settings** nicht verfügbar, und ihre URL liefert Not Found zurück.
