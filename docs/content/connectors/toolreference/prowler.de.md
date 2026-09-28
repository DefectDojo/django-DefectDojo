---
title: "Prowler"
description: "Einrichtung des Prowler Upstream-Connectors für DefectDojo"
weight: 108
audience: pro
---
Der Prowler-Connector verwendet die **Prowler-App**-REST-API, um Cloud-Security-Posture(CSPM)-Befunde von einer selbstgehosteten Prowler-App-Instanz zu importieren. DefectDojo ermittelt jeden Prowler-**Provider** (Cloud-Konto) als Eintrag und importiert die **FAIL**-Befunde des letzten abgeschlossenen Scans dieses Providers.

#### Voraussetzungen

Sie benötigen eine laufende, selbstgehostete **Prowler-App**-Instanz sowie entweder eine Benutzer-E-Mail-Adresse + ein Passwort (für JWT-Authentifizierung) oder einen Prowler-App-**API-Schlüssel**. Befunde erscheinen erst, sobald Sie ein Cloud-Konto (AWS, GCP, Azure, Kubernetes, ...) in der Prowler-App verbunden und einen Scan ausgeführt haben.

#### Connector-Zuordnungen

1. Geben Sie Ihre Prowler-App-URL in das Feld **Location** ein (zum Beispiel `https://prowler.your-company.com`).
2. Geben Sie für die JWT-Authentifizierung die **Email** und das **Password** des Prowler-App-Benutzers ein. Alternativ lassen Sie diese leer und geben einen Prowler-App-**API-Schlüssel** ein. Sind beide angegeben, wird E-Mail/Passwort (JWT) verwendet.
3. Legen Sie optional einen **Minimum Severity**-Wert fest, um einzuschränken, welche Befunde importiert werden. Befunde unterhalb des gewählten Schweregrads werden nicht importiert.

DefectDojo erstellt für jeden Prowler-Provider einen Eintrag und importiert die FAIL-Befunde von dessen letztem abgeschlossenem Scan, wobei Prowler-Schweregrade auf DefectDojo-Schweregrade abgebildet werden, die betroffene Cloud-Ressource (ARN/Ressourcen-ID) zur Komponente wird und die Abhilfemaßnahme sowie das Risiko der Prüfung in den Befund übernommen werden. Stummgeschaltete Befunde werden übersprungen. Cloud-Konto, Region und Dienst werden als Tags angehängt.

Weitere Informationen finden Sie in der **[Prowler-App-API-Dokumentation](https://api.prowler.com/api/v1/docs)**.
