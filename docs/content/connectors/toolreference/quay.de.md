---
title: "Quay"
description: "Einrichtung des Quay Upstream-Connectors für DefectDojo"
weight: 110
audience: pro
---
Der Quay-Connector verwendet die Project-Quay-REST-API, um Container-Repositories zu ermitteln und die von Quays integriertem **Clair**-Scanner erzeugten Schwachstellenberichte zu importieren. DefectDojo erstellt für jedes Quay-**Repository** einen Eintrag und liest bei jedem Sync den Clair-Sicherheitsbericht des Image-Manifests jedes aktiven Tags.

#### Voraussetzungen

Security Scanning (Clair) muss auf Ihrer Quay-Instanz aktiviert sein, und Sie benötigen ein Quay-**OAuth-2-Zugriffstoken**:

* Erstellen (oder öffnen) Sie in Quay eine Organisation, gehen Sie zu **Applications**, erstellen Sie eine OAuth-Anwendung, und dann **Generate Token** mit mindestens dem Scope **Read repositories**. Eine dedizierte Anwendung für DefectDojo wird empfohlen.
* Das Token wird bei jeder Anfrage als Bearer-Token gesendet und nie protokolliert.

#### Connector-Zuordnungen

1. Geben Sie Ihre Quay-Basis-URL in das Feld **Location** ein, zum Beispiel `https://quay.io` oder Ihr selbstgehostetes `https://quay.example.com`. Die URL muss HTTPS verwenden; geben Sie keinen abschließenden API-Pfad an — DefectDojo erstellt die API-Pfade automatisch.
2. Geben Sie das OAuth-Zugriffstoken in das Feld **Secret** ein.
3. Legen Sie optional einen **Namespace** fest, um die Ermittlung auf eine einzelne Quay-Organisation oder einen Benutzer zu beschränken. Leer lassen, um jedes Repository zu ermitteln, das das Token lesen kann.
4. Legen Sie optional einen **Minimum Severity**-Wert fest, um einzuschränken, welche Befunde importiert werden.

DefectDojo ordnet jedes Quay-**Repository** einem Eintrag zu. Für jedes Repository listet es die aktiven Tags auf, dedupliziert sie zu ihren eindeutigen Image-Manifesten (ein von mehreren Tags gemeinsam genutztes Manifest wird einmal gescannt) und liest den Clair-Bericht jedes Manifests. Manifeste, deren Scan Clair noch nicht abgeschlossen hat (zum Beispiel eine Multi-Architektur-Manifestliste oder ein noch in der Warteschlange befindliches Image), werden bis zu einem späteren Sync übersprungen. Jede Clair-Schwachstelle wird zu einem Befund — das betroffene Paket ist die Komponente, die Fix-Version wird zur Abhilfemaßnahme, und Clairs Schweregrade **Negligible**/**Unknown** werden als **Informational** erfasst.

Weitere Informationen finden Sie in der [Project-Quay-API-Dokumentation](https://docs.projectquay.io/api_quay.html) und der [Clair-Dokumentation](https://quay.github.io/clair/).
