---
title: "BurpSuite"
description: "Einrichtung des BurpSuite Upstream-Connectors für DefectDojo"
weight: 30
audience: pro
---
Der Burp-Connector von DefectDojo ruft die GraphQL-API von Burp auf, um Daten abzurufen.

#### Voraussetzungen

Bevor Sie diesen Connector einrichten können, benötigen Sie einen API-Schlüssel eines Burp-Service-Kontos. Burp-Benutzerkonten verfügen standardmäßig nicht über API-Schlüssel, daher müssen Sie möglicherweise eigens dafür einen neuen Benutzer anlegen.

Eine Anleitung zum Einrichten eines Service-Account-Benutzers mit einem API-Schlüssel finden Sie in der [Burp-Dokumentation](https://portswigger.net/burp/documentation/enterprise/user-guide/api-documentation/create-api-user).

#### Connector-Zuordnungen

1. Geben Sie die Root-URL von Burp in das Feld **Location** ein: Dies ist die URL, unter der Sie auf das Burp-Tool zugreifen.
2. Geben Sie einen gültigen API-Schlüssel in das Feld Secret ein. Dies ist der API-Schlüssel, der mit Ihrem Burp-Service-Konto verknüpft ist.

Weitere Informationen zur Burp-API finden Sie in der offiziellen [Burp-Dokumentation](https://portswigger.net/burp/extensibility/enterprise/graphql-api/index.html).
