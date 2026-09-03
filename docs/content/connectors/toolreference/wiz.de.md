---
title: "Wiz"
description: "Einrichtung des Wiz Upstream-Connectors für DefectDojo"
weight: 142
audience: pro
---
Der Wiz-Connector importiert **Issues und Schwachstellen-Befunde**. DefectDojo erstellt einen Record für jedes **Wiz-Projekt** sowie einen Record auf Tenant-Ebene, der nach dem Tenant selbst benannt ist, zum Beispiel **Wiz Tenant abc12**. Dieser Record deckt den gesamten Wiz-Tenant ab.

**Sie benötigen keine Wiz-Projekte, um diesen Connector zu verwenden.** Wenn Ihr Tenant keine Projekte hat, ordnen Sie den Record diesen Tenant-Record zu. DefectDojo importiert dann jedes Issue und jeden Schwachstellen-Befund, den Ihr Service-Konto sehen kann. Dieser Record erfasst auch Befunde zu Ressourcen, die kein Projekt abdeckt. Ordnen Sie ihn daher zusätzlich zu Ihren Projekt-Records zu, wenn Ihre Projekte nicht alles abdecken. Wenn Sie sowohl einen Projekt-Record als auch den Record diesen Tenant-Record zuordnen, werden die Befunde dieses Projekts in zwei Assets importiert. Tun Sie das nur, wenn Sie beide Ansichten wünschen.

Um den Wiz-Connector zu verwenden, müssen Sie ein Service-Konto erstellen: siehe die [Wiz-Dokumentation](https://docs.wiz.io/wiz-docs/docs/service-accounts-settings#add-a-service-account) für weitere Informationen. Sie benötigen ein Wiz-Konto, um auf die Dokumentation zuzugreifen.

Das Service-Konto muss alle folgenden Anforderungen erfüllen. Ein Service-Konto, dem eine davon fehlt, kann sich zwar erfolgreich authentifizieren, importiert aber nichts:

* **Type**: Custom Integration (GraphQL API).
* **API-Scopes**: mindestens `read:projects`, `read:issues` und `read:vulnerabilities`. `read:projects` wird auch bei einem Tenant ohne Projekte benötigt, weil Discover weiterhin die Projektliste bei Wiz abfragt.
* **Projekt-Sichtbarkeit**: Das Service-Konto muss auf jedes zu importierende Wiz-Projekt beschränkt sein (oder auf alle Projekte). Ein Konto, das Issues lesen kann, aber keine Projekt-Sichtbarkeit hat, ermittelt keine Projekt-Records. Es steht dann nur der Record diesen Tenant-Record zur Verfügung.

#### **Connector-Zuordnungen**

1. Geben Sie Ihre Wiz Client ID in das Feld Client ID ein.
2. Geben Sie das Wiz Client Secret in das Feld Secret ein.
