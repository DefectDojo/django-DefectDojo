---
title: "Sysdig Secure"
description: "Einrichtung des Sysdig Secure Upstream-Connectors für DefectDojo"
weight: 130
audience: pro
---
Der Sysdig-Secure-Connector importiert **Container-/CNAPP-Schwachstellenbefunde** über die Vulnerability-Management-API von Sysdig Secure. Er synchronisiert das gesamte Konto über die konfigurierten Geltungsbereich(e) und erstellt für jede gescannte Asset-Gruppierung ein DefectDojo-Produkt.

#### Voraussetzungen

Ein Sysdig-Secure-**API-Token**: Gehen Sie in Sysdig Secure zu **Settings \> Sysdig Secure API Token** und kopieren Sie das Token. Sie benötigen außerdem Ihre Sysdig-**Region-URL** (zum Beispiel `https://us2.app.sysdig.com`, `https://eu1.app.sysdig.com`, oder Ihren On-Premises-Host).

#### Connector-Zuordnungen

1. Geben Sie Ihre Sysdig-Region-/Basis-URL in das Feld **Location** ein.
2. Geben Sie das API-Token in das Feld **Secret** ein.
3. Legen Sie optional **Scopes** fest — eine kommagetrennte Liste aus `runtime`, `registry` und/oder `pipeline` (leer lassen für `runtime`, den Geltungsbereich bereitgestellter Workloads).
4. Legen Sie optional **Runtime Product Grouping** fest — wie Runtime-Ergebnisse auf Produkte abgebildet werden: `cluster`, `namespace`, `workload` oder `image` (leer lassen für `namespace`). Registry- und Pipeline-Ergebnisse werden immer nach Image-Repository gruppiert.
5. Legen Sie optional einen **Minimum Severity**-Wert fest, um einzuschränken, welche Befunde importiert werden.

Jede Asset-Gruppierung wird zu einem Eintrag. Für jedes Scan-Ergebnis importiert der Connector jedes anfällige Paket als Befund. **Runtime**-Befunde (bereitgestellte Workloads) werden als dynamische Befunde erfasst und mit ihrem Kubernetes-Kontext (Cluster/Namespace/Workload/Container) getaggt; **Registry**- und **Pipeline**-Befunde werden als statische Image-Scan-Befunde erfasst. Sysdigs Schweregrad `NEGLIGIBLE` wird auf Info abgebildet.
