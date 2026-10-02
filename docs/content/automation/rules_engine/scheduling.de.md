---
title: Regeln planen
description: Rules Engine-Regeln automatisch nach einem wiederkehrenden oder einmaligen
  Zeitplan ausführen
weight: 2
audience: pro
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Hinweis: Die Zeitplanung der Rules Engine ist eine reine DefectDojo-Pro-Funktion.</span>

Regeln können so geplant werden, dass sie automatisch ausgeführt werden, anstatt jedes Mal manuell ausgelöst zu werden.  Eine geplante Regel wird zur konfigurierten Zeit auf alle Befunde angewendet, die ihren Filterbedingungen entsprechen.

Die Zeitplanung ist standardmäßig deaktiviert und wird von DefectDojo pro Instanz aktiviert, nicht über die Feature-Flags-Seite. Wenden Sie sich an den [DefectDojo Support](mailto:support@defectdojo.com), um den **Scheduling Service** aktivieren zu lassen; die Option **Regel planen** erscheint, sobald dies geschehen ist. Siehe [Feature Flags](/admin/feature_flags/pro__feature_flags/), um zu erfahren, wie zentral von DefectDojo verwaltete Funktionen angezeigt werden.

Der Benutzer, der den Zeitplan einrichtet, muss über die Konfigurationsberechtigung **Change Scheduling Service Schedule** verfügen.

## Zeitplantypen

### Einmalige Ausführung

Ein Zeitplan vom Typ Einmalige Ausführung führt die Regel einmal zu einem bestimmten Datum und einer bestimmten Uhrzeit aus.  Nach Abschluss des Laufs wird der Zeitplan nicht wiederholt.

### Wiederkehrende Ausführung

Ein Zeitplan vom Typ Wiederkehrende Ausführung ermöglicht es Ihnen, eine Regel wiederkehrend auszulösen — zum Beispiel täglich um 9:00 Uhr oder jeden Montag um 15:00 Uhr.

**Hinweis:** Zeitpläne der Rules Engine sind auf Viertelstundenmarken beschränkt.  Das Minutenfeld eines Cron-Zeitplans muss einen der folgenden Werte haben: **0, 15, 30 oder 45**.  Andere Minutenwerte sind nicht zulässig.

Beispiele für gültige Zeitpläne:
- Jede volle Stunde: `0 * * * *`
- Jeden Tag um 9:15 Uhr: `15 9 * * *`
- Jeden Montag um 15:00 Uhr: `0 15 * * 1`
- Alle 15 Minuten: `0,15,30,45 * * * *`

## Einen Zeitplan für eine Regel erstellen

1. Navigieren Sie über das Menü **Rules Engine** in der Seitenleiste zur Seite **Alle Regeln**.
2. Suchen Sie die Regel, die Sie planen möchten, und öffnen Sie deren Aktionsmenü (**⋮**).
3. Klicken Sie auf **Regel planen**.  Diese Option ist nur sichtbar, wenn der Scheduling Service aktiviert ist und Sie über die erforderliche Berechtigung verfügen.
4. Füllen Sie im Modal **Regel planen** die folgenden Felder aus:

| Feld | Beschreibung |
|---|---|
| **Name** | Ein eindeutiger Name für diesen Zeitplan (erforderlich, max. 100 Zeichen). |
| **Beschreibung** | Optionale Beschreibung des Zwecks des Zeitplans. |
| **Auslösertyp** | Wählen Sie **Einmalige Ausführung** für eine einmalige Ausführung oder **Wiederkehrende Ausführung** für einen wiederkehrenden Cron-Zeitplan. |
| **Häufigkeit** | Für Wiederkehrende Ausführung: Verwenden Sie den Cron-Builder, um den Zeitraum (stündlich, täglich, wöchentlich usw.) sowie die konkreten Minuten-, Stunden- und Tageswerte auszuwählen. Für Einmalige Ausführung: Wählen Sie über die Datumsauswahl ein Datum und eine Uhrzeit aus. |
| **Zeitplan aktivieren** | Schalter zum Aktivieren oder Deaktivieren des Zeitplans.  Ein deaktivierter Zeitplan wird erst nach erneuter Aktivierung ausgeführt. |

5. Klicken Sie auf **Absenden**, um den Zeitplan zu speichern.  Die Regel wird automatisch zum nächsten geplanten Zeitpunkt ausgeführt.


## Berechtigungen

Der Zugriff auf die Zeitplanung innerhalb der Rules Engine erfordert Superuser-Berechtigungen oder die entsprechende Konfigurationsberechtigung.  Siehe [User Permission Chart](/admin/user_management/user_permission_chart) für Details.
