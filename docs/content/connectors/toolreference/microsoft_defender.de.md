---
title: "Microsoft Defender"
description: "Einrichtung des Microsoft Defender Upstream-Connectors für DefectDojo"
weight: 89
audience: pro
---
Der Microsoft-Defender-Connector importiert Geräte-Schwachstellenbefunde aus **Microsoft Defender Vulnerability Management (MDVM)** — einen Befund pro Kombination aus Gerät/Softwareversion/CVE, einschließlich Schweregrad, CVSS-Score, Ausnutzbarkeitsgrad und empfohlener Sicherheitsupdates. DefectDojo ermittelt Ihre Defender-**Gerätegruppen** und erstellt für jede einen Eintrag; Geräte, die keiner Gerätegruppe zugewiesen sind, werden unter einer synthetischen Gruppe **Unassigned** zusammengefasst.

**Bitte beachten Sie:** Dieser Connector unterscheidet sich vom dateibasierten Scan-Typ **„MSDefender Parser"**, der manuell exportierte Defender-Dateien importiert. Wählen Sie pro Produkt einen Importpfad, um doppelte Befunde zu vermeiden.

#### Voraussetzungen

Ihr Microsoft-Tenant benötigt eine aktive Lizenz, die die Defender-Vulnerability-Export-APIs einschließt: **Defender for Endpoint Plan 2**, **Microsoft Defender Vulnerability Management Standalone**, oder MDE P1/P2 mit dem MDVM-Add-on. (Das MDVM-*Add-on*-SKU allein reicht nicht aus — es setzt Defender for Endpoint Plan 2 voraus.)

Der Connector authentifiziert sich als Microsoft-Entra-ID-**App-Registrierung** mittels Client-Credentials-Flow. So erstellen Sie eine:

1. Öffnen Sie im [Azure-Portal](https://portal.azure.com) **App registrations \> New registration**. Benennen Sie sie (zum Beispiel `defectdojo-connector`), belassen Sie die Standardwerte, und wählen Sie **Register**.
2. Notieren Sie sich auf der **Overview**-Seite der App die **Application (client) ID** und die **Directory (tenant) ID**.
3. Öffnen Sie **API permissions \> Add a permission \> APIs my organization uses** und suchen Sie nach **WindowsDefenderATP**. Erscheint es nicht, wurde das Defender-Backend Ihres Tenants noch nicht bereitgestellt: Stellen Sie sicher, dass die Lizenz aktiv ist, öffnen Sie einmal [security.microsoft.com](https://security.microsoft.com), und versuchen Sie es nach einigen Minuten erneut.
4. Wählen Sie **Application permissions** (*nicht* Delegated — Delegated-Berechtigungen erscheinen nie im Service-Token des Connectors), erweitern Sie **Vulnerability**, markieren Sie **Vulnerability.Read.All**, und wählen Sie **Add permissions**.
5. Wählen Sie **Grant admin consent** und bestätigen Sie. Die Status-Spalte muss ein grünes Häkchen zeigen — ohne diesen Schritt liefert jeder API-Aufruf einen 403-Fehler.
6. Öffnen Sie **Certificates & secrets \> New client secret**, legen Sie ein Ablaufdatum fest, und kopieren Sie den **Value** des Secrets sofort (er wird nur einmal angezeigt). Der Connector funktioniert nicht mehr, wenn das Secret abläuft; notieren Sie sich daher das Datum.

#### Connector-Zuordnungen

1. Geben Sie `https://api.security.microsoft.com` in das Feld **Location** ein.
2. Geben Sie die **Directory (tenant) ID** in das Feld **Tenant ID** ein.
3. Geben Sie die **Application (client) ID** in das Feld **Client ID** ein.
4. Geben Sie den Wert des Client-Secrets in das Feld **Client Secret** ein.
5. Legen Sie optional einen **Minimum Severity**-Wert fest, um einzuschränken, welche Befunde importiert werden.

Jede Defender-Gerätegruppe wird zu einem Eintrag. Microsoft erneuert den vom Connector gelesenen Schwachstellen-Snapshot etwa alle 6 Stunden, und neu angebundene Geräte können bis zu ca. 24 Stunden benötigen, um ihre ersten Schwachstellendaten zu liefern — ein brandneuer Tenant wird legitim null Befunde synchronisieren, bis Geräte angebunden und bewertet wurden. Auch die Lizenzaktivierung selbst kann ca. 20 Minuten oder länger benötigen, bis sie die API erreicht (Fehler „No active license found" während dieses Zeitfensters lösen sich von selbst).
