---
title: "Microsoft Defender for Cloud"
description: "Einrichtung des Microsoft Defender for Cloud Upstream-Connectors für DefectDojo"
weight: 90
audience: pro
---
Der Microsoft-Defender-for-Cloud-Connector importiert Schwachstellenbefunde aus **Microsoft Defender Vulnerability Management (MDVM)**, wie sie von Defender for Cloud bereitgestellt werden — sowohl **Server**-Befunde (CVEs des Betriebssystems und der installierten Software von Azure-VMs) als auch **Container-Registry**-Befunde (CVEs von Container-Images), einschließlich Schweregrad, CVSS-Score, dem betroffenen Paket oder Image und Abhilfemaßnahmen. DefectDojo ermittelt die Azure-**Subscriptions**, die Ihr Service Principal lesen kann, und erstellt für jede aktivierte Subscription einen Eintrag.

**Bitte beachten Sie:** Dieser Connector unterscheidet sich vom **Microsoft-Defender**-Connector, der Gerätebefunde aus der Defender-for-Endpoint-API importiert. Defender for Cloud ist ein Azure-Produkt mit einer anderen API-Oberfläche (Azure Resource Manager/Resource Graph) und einem anderen Berechtigungsmodell (Azure RBAC). Verwenden Sie denjenigen, der zu Ihren Befundquellen passt — oder beide, wenn Sie beide Produkte nutzen.

#### Voraussetzungen

Sie benötigen eine oder mehrere **Azure-Subscriptions mit aktiviertem Microsoft Defender for Cloud**, wobei die relevanten Defender-Pläne für die zu scannenden Ressourcen aktiviert sind (unter **Microsoft Defender for Cloud \> Environment settings**, dann Ihre Subscription auswählen):

* **Defender for Servers (Plan 2)** — CVE-Befunde zum Betriebssystem und zur Software von Azure-VMs (agentloses Vulnerability Scanning).
* **Defender for Containers** — CVE-Befunde von Container-Registry-Images.

SQL-Vulnerability-Assessment- und Konfigurations-/Posture-Befunde werden bewusst **nicht** importiert — dieser Connector importiert ausschließlich CVE-Schwachstellen.

Der Connector authentifiziert sich als Microsoft-Entra-ID-**App-Registrierung** mittels Client-Credentials-Flow:

1. Öffnen Sie im [Azure-Portal](https://portal.azure.com) **App registrations \> New registration**. Benennen Sie sie (zum Beispiel `defectdojo-connector`), belassen Sie die Standardwerte, und wählen Sie **Register**.
2. Notieren Sie sich auf der **Overview**-Seite der App die **Application (client) ID** und die **Directory (tenant) ID**.
3. Öffnen Sie **Certificates & secrets \> New client secret**, legen Sie ein Ablaufdatum fest, und kopieren Sie den **Value** des Secrets sofort (er wird nur einmal angezeigt). Der Connector funktioniert nicht mehr, wenn das Secret abläuft; notieren Sie sich daher das Datum.
4. Gewähren Sie der App Lesezugriff auf jede zu importierende Subscription: Öffnen Sie **Subscriptions**, wählen Sie Ihre Subscription, dann **Access control (IAM) \> Add \> Add role assignment**. Wählen Sie die Rolle **Security Reader** (oder **Reader**), und weisen Sie sie im Tab **Members** der von Ihnen erstellten App zu — suchen Sie sie über den **Namen** oder die **Object ID** der App, da der Picker nicht mit der Client ID abgleicht. Wiederholen Sie dies für jede Subscription.

Anders als beim gerätebasierten Microsoft-Defender-Connector sind keine API-Berechtigungen oder Admin-Consent erforderlich: Der Zugriff auf Defender for Cloud wird ausschließlich über die oben genannte Azure-RBAC-Rollenzuweisung geregelt.

#### Connector-Zuordnungen

1. Geben Sie `https://management.azure.com` in das Feld **Location** ein. (Verwenden Sie bei souveränen Clouds den passenden ARM-Endpunkt, zum Beispiel `https://management.usgovcloudapi.net`.)
2. Geben Sie die **Directory (tenant) ID** in das Feld **Tenant ID** ein.
3. Geben Sie die **Application (client) ID** in das Feld **Client ID** ein.
4. Geben Sie den Wert des Client-Secrets in das Feld **Client Secret** ein.
5. Legen Sie optional einen **Minimum Severity**-Wert fest, um einzuschränken, welche Befunde importiert werden.

Jede aktivierte Azure-Subscription wird zu einem Eintrag. Befunde werden über Azure Resource Graph gelesen, sodass sie zügig sichtbar werden, sobald Defender for Cloud Ihre Ressourcen gescannt hat — die Scans selbst laufen jedoch nach dem Zeitplan von Microsoft: Container-Registry-Images werden meist innerhalb einer Stunde nach dem Push gescannt, während der erste agentlose Schwachstellen-Scan einer VM mehrere Stunden dauern kann. Eine neu aktivierte Subscription wird legitim null Befunde synchronisieren, bis ihre Ressourcen gescannt wurden.
