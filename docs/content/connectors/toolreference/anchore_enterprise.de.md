---
title: "Anchore"
description: "Einrichtung des Anchore Upstream-Connectors für DefectDojo"
weight: 16
audience: pro
---
Der Anchore-Connector verwendet das API-Token eines Benutzers, um Daten von Anchore Enterprise abzurufen. Produkte werden anhand von „Applications" zugeordnet und ermittelt, die sich in Anchore aus mehreren Images zusammensetzen - siehe [Anchore Enterprise Documentation](https://docs.anchore.com/current/docs/sbom_management/application_groups/application_management_anchorectl/) für weitere Informationen.

#### Connector-Zuordnungen

1. Die Anchore-URL in das Feld **Location**: Dies ist die URL, unter der Sie auf Anchore zugreifen.
2. Geben Sie einen gültigen API-Schlüssel in das Feld Secret ein. Dies ist der API-Schlüssel, der mit Ihrem Burp-Service-Konto verknüpft ist.

Weitere Informationen zum Erstellen eines Tokens für Anchore finden Sie in der offiziellen [Anchore-Dokumentation](https://docs.anchore.com/current/docs/).
