---
title: SLA-Konfiguration
description: Service Level Agreements für verschiedene Produkte konfigurieren
weight: 2
audience: opensource
aliases:
- /de/en/working_with_findings/sla_configuration
---

Jedes Product in DefectDojo kann über eine eigene Service Level Agreement (SLA)-Konfiguration verfügen, die angibt, wie viele Tage Ihrer Organisation zur Behebung oder anderweitigen Bearbeitung eines Findings zur Verfügung stehen.

Die SLA kann entweder anhand des **[Severity des Findings](/asset_modelling/os_hierarchy/product_hierarchy/#findings)** oder des **[Risikos des Findings](/asset_modelling/pro_hierarchy/priority_sla/)** (in DefectDojo Pro) festgelegt werden.

![image](images/sla_multiple.png)

SLAs wenden auf ein Finding einen Tage-Countdown an, basierend auf dem Tag, an dem das Finding in DefectDojo erstellt wurde. Wenn ein Finding innerhalb des Countdowns nicht geschlossen wird, wird das Finding als SLA-Verstoß gekennzeichnet.

## Arbeiten mit SLAs

Sie können SLAs verwenden, um die Behebungsrichtlinien Ihrer Organisation abzubilden. Sie können sie auch nutzen, um die am längsten aktiven, kritischsten Findings in Ihrer DefectDojo-Instanz zu priorisieren.

* Sie können Finding-Tabellen nach SLA-Tagen sortieren oder filtern.
* SLA-Verstöße können so konfiguriert werden, dass sie [Notifications](/admin/notifications/about_notifications/) an die dem betreffenden Product zugewiesenen DefectDojo-Benutzer auslösen.
* In **DefectDojo Pro** wird die SLA-Performance auch auf den Metrics-Dashboards [Executive Insights and Remediation](/metrics_reports/pro_metrics/pro__overview/) erfasst.
* Die SLA-Einhaltung kann in **DefectDojo Pro** auch auf einem individuellen [Dashboard](/metrics_reports/dashboards/custom-dashboards/) angezeigt werden — zum Beispiel mit einem SLA Burndown oder einem gefilterten Count-Widget.

### Status „Mitigated Within SLA“

Wenn ein Finding vor Ablauf der SLA-Frist erfolgreich Mitigated wird, erhält das Finding in der Spalte „Mitigated Within SLA" ein grünes Häkchen ✅.

![image](images/sla_mitigated_within.png)

Wenn ein Finding Mitigated wurde, jedoch nicht bevor die SLA verletzt wurde, erhält das Finding in der Spalte „Mitigated Within SLA" ein rotes X ❌.

### SLA-Verstöße

Wenn die SLA für ein bestimmtes Finding verletzt wird (das Finding wird nicht innerhalb des SLA-Zeitrahmens geschlossen), wechselt das grüne Häkchen ✅ zu einem roten X ❌. Die SLA wird weiterhin mit einer negativen Zahl verfolgt, die angibt, um wie viele Tage die SLA bereits überschritten wurde.

![image](images/sla_breached.png)

## Verwalten von SLA-Konfigurationen (Pro)

In DefectDojo Pro werden eine oder mehrere SLA-Konfigurationen unter **Configuration > Service Level Agreements** in der Seitenleiste verwaltet. Sie können ein **New Service Level Agreement** erstellen oder auf der Seite **All Service Level Agreements** mit vorhandenen SLA-Konfigurationen arbeiten.

![image](images/pro_sla_risk.png)

SLA-Konfigurationen können nur von Superusern oder von einem Benutzer mit der entsprechenden [Configuration Permission](/admin/user_management/user_permission_chart/#configuration-permission-chart) bearbeitet werden.

### SLA konfigurieren

SLA-Konfigurationen enthalten die Tage, die jedem **Severity**- oder **Risk**-Wert in DefectDojo zugewiesen sind.

![image](images/pro_new_sla.png)

Jedes Service Level Agreement kann einen eindeutigen Namen sowie eine optionale Beschreibung haben.

**Restart SLA on Finding Reactivation**: Wenn diese Option aktiviert ist, beginnt die SLA von Neuem, sobald ein Finding wieder geöffnet (Reopened) wird. Andernfalls basiert die SLA auf dem Erstellungsdatum des Findings.

Beim Bearbeiten einer SLA können Sie auswählen, ob diese SLA **Severity** oder **Risk** als Grundlage für die Zuweisung der Days To Remediate verwendet. Dies geschieht durch Auswahl der entsprechenden Option im Abschnitt **Service Level configuration Type** des Formulars.

Von hier aus können Sie die Anzahl der zulässigen Tage für jeden **Severity**- oder **Risk**-Level festlegen. Sie können SLAs auch selektiv erzwingen; indem Sie das Kontrollkästchen **Enforce ___ Finding Days** deaktivieren, können Sie die SLA-Berechnung für diese Severity- oder Risk-Stufen ignorieren.

## Eine SLA-Konfiguration auf ein Product anwenden (Pro)

Neu erstellte Products in DefectDojo verwenden immer die **Default SLA Configuration**, deren Werte Sie bei Bedarf anpassen können.

Wenn Sie SLA-Konfigurationen angelegt haben, können Sie im Formular **Edit Product** auswählen, welche davon auf Ihr Product angewendet wird.

![image](images/pro_sla_product.png)

### SLA-Neuberechnung

Sobald für ein Product eine neue SLA ausgewählt wurde, müssen die SLAs aller zugehörigen Findings von DefectDojo neu berechnet werden. Während dieser Vorgang läuft, kann die SLA eines Products nicht geändert werden.

## Hinweise zu SLAs

* SLAs können optional neu gestartet werden, sobald ein Finding mit dem Status [Risiko akzeptiert](/triage_findings/findings_workflows/os__risk_acceptance/) reaktiviert wird. Dies wird beim Erstellen der Risikoakzeptanz über das Feld **Restart SLA Expired** festgelegt.
* Ein Reimport eines Findings startet die SLA nicht neu - SLAs werden immer ab dem Zeitpunkt berechnet, an dem ein Finding erstmals erkannt wurde, es sei denn, **Restart SLA on Finding Reactivation** ist aktiviert.
* Der Ablauf einer Risikoakzeptanz oder die Reaktivierung eines geschlossenen Findings sind die einzigen Möglichkeiten, eine SLA für ein bereits erstelltes Finding zurückzusetzen oder neu zu berechnen (ohne die SLA-Konfiguration des Products zu ändern).
