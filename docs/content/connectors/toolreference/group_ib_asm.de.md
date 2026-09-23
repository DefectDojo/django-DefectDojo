---
title: "Group-IB ASM"
description: "Einrichtung des Group-IB ASM Upstream-Connectors für DefectDojo"
weight: 68
audience: pro
---
Der Group-IB-ASM(Attack Surface Management)-Connector verwendet die Group-IB-ASM-REST-API, um externe Angriffsflächen-**Issues** (Befunde) in DefectDojo zu übertragen. DefectDojo ermittelt jedes Group-IB-**Unternehmen/Tenant** als separaten Eintrag und importiert die Issues dieses Unternehmens geplant und inkrementell. Das Asset, auf das sich jedes Issue bezieht (eine Domain, IP oder URL), wird dem resultierenden Befund als **Endpunkt** angehängt.

#### Voraussetzungen

Sie benötigen Ihren Group-IB-ASM-Login und einen API-Schlüssel. Wir empfehlen, für DefectDojo ein dediziertes Service-Konto anzulegen, damit automatisierte Aktivitäten von manuellen Team-Aktionen unterschieden werden können.

So generieren Sie einen API-Schlüssel:

1. Öffnen Sie Group-IB Attack Surface Management, klicken Sie unten links auf **Help** und wählen Sie **API**.
2. Klicken Sie auf **Generate API Key** (oben rechts, unter Ihrem Benutzernamen).
3. Geben Sie Ihr SSO-Passwort ein und klicken Sie auf **Next**, dann auf **Copy token**.
4. Speichern Sie den Schlüssel in einem Secret Manager und planen Sie eine regelmäßige Rotation ein.

#### Connector-Zuordnungen

Group-IB ASM authentifiziert sich mit HTTP Basic Auth, wobei der Benutzername Ihr ASM-Login und das Passwort Ihr API-Schlüssel ist. **Beide Werte sind erforderlich** — der API-Schlüssel allein reicht nicht aus.

1. Geben Sie `https://asm.group-ib.com` in das Feld **Location** ein. Dies ist für alle Group-IB-ASM-Tenants gleich.
2. Geben Sie Ihren ASM-Login (in der Regel eine E-Mail-Adresse) in das Feld **Username** ein.
3. Geben Sie Ihren API-Schlüssel in das Feld **API Key** (Secret) ein.
4. Legen Sie optional einen **Minimum Severity**-Wert fest, um einzuschränken, welche Befunde importiert werden. Befunde unterhalb des gewählten Schweregrads werden nicht importiert.

DefectDojo ordnet jedes Group-IB-**Unternehmen** als separaten Eintrag zu, wobei die Unternehmens-ID als Kennung verwendet wird. Beim ersten Sync trägt DefectDojo die jüngste Issue-Historie nach; nachfolgende Syncs erfolgen inkrementell und rufen nur seit dem letzten Sync geänderte Issues ab (anhand des jeweils neuesten `lastSeen`-Zeitstempels jedes Issues).

#### Beschränkung auf ein einzelnes Unternehmen (optional)

Standardmäßig ermittelt der Connector automatisch die für Ihre API-Anmeldedaten verfügbaren Unternehmen (über den ASM-Endpunkt `clients`) und erstellt einen Eintrag pro Unternehmen. Dies ist die empfohlene Einrichtung und erfordert keine zusätzliche Konfiguration.

Ist der Endpunkt `clients` für Ihren Tenant nicht verfügbar — zum Beispiel, weil er auf Partner-/MSP-Konten beschränkt ist —, kann der Connector auf ein Unternehmen beschränkt werden, indem dessen **Unternehmens-ID** als toolspezifisches Feld `company_id` in der Connector-Konfiguration angegeben wird. Ist `company_id` gesetzt, verwendet DefectDojo dieses Unternehmen direkt, statt Unternehmen aufzuzählen. Lassen Sie es nicht gesetzt, um die automatische Ermittlung zu verwenden.

Weitere Informationen finden Sie im Group-IB-ASM-REST-API-Handbuch (im Produkt verfügbar über **Help → API**).
