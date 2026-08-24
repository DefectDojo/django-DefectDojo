---
title: "Wiz"
description: "Einrichtung des Wiz Upstream-Connectors für DefectDojo"
weight: 142
audience: pro
---
Um den Wiz-Connector zu verwenden, müssen Sie ein Service-Konto erstellen: siehe die [Wiz-Dokumentation](https://docs.wiz.io/wiz-docs/docs/service-accounts-settings#add-a-service-account) für weitere Informationen. Sie benötigen ein Wiz-Konto, um auf die Dokumentation zuzugreifen.

Das Service-Konto muss alle folgenden Anforderungen erfüllen. Ein Service-Konto, dem eine davon fehlt, kann sich zwar erfolgreich authentifizieren, importiert aber nichts:

* **Type**: Custom Integration (GraphQL API).
* **API-Scopes**: mindestens `read:projects`, `read:issues` und `read:vulnerabilities`.
* **Projekt-Sichtbarkeit**: Das Service-Konto muss auf jedes zu importierende Wiz-Projekt beschränkt sein (oder auf alle Projekte). Der Connector ermittelt zunächst Ihre Wiz-Projekte und ruft dann die Befunde jedes Projekts ab — ein Konto, das Issues lesen kann, aber keine Projekt-Sichtbarkeit hat, ermittelt null Projekte, sodass nichts zu importieren ist und von keiner Seite ein Fehler gemeldet wird.

#### **Connector-Zuordnungen**

1. Geben Sie Ihre Wiz Client ID in das Feld Client ID ein.
2. Geben Sie das Wiz Client Secret in das Feld Secret ein.
