---
title: "SonarQube"
description: "Einrichtung des SonarQube Upstream-Connectors für DefectDojo"
weight: 127
audience: pro
---
Der SonarQube-Connector kann Daten entweder von einem SonarCloud-Konto oder von einer lokalen SonarQube-Instanz abrufen.

**Für SonarCloud-Benutzer:**

1. Geben Sie https://sonarcloud.io/ in das Feld Location ein.
2. Geben Sie einen gültigen **API-Schlüssel** in das Feld Secret ein.

**Für SonarQube-Benutzer (On-Premise):**

1. Geben Sie die Basis-URL Ihrer SonarQube-Instanz in das Feld Location ein: zum Beispiel `https://my.sonarqube.com/`
2. Geben Sie einen gültigen **API-Schlüssel** in das Feld Secret ein. Dies muss ein **[User](https://docs.sonarsource.com/sonarqube/latest/user-guide/user-account/generating-and-using-tokens/)**-[API-Token-Typ](https://docs.sonarsource.com/sonarqube/latest/user-guide/user-account/generating-and-using-tokens/) sein.

Das Token benötigt Zugriff auf Projects, Vulnerabilities und Hotspots innerhalb von Sonar.

API-Tokens finden und generieren Sie über **My Account \-\> Security \-\> Generate Token** in der SonarQube-App. Weitere Informationen finden Sie in der [SonarQube-Dokumentation](https://docs.sonarsource.com/sonarqube/latest/user-guide/user-account/generating-and-using-tokens/).
