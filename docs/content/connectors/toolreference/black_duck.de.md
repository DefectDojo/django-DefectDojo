---
title: "Black Duck"
description: "Einrichtung des Black Duck Upstream-Connectors für DefectDojo"
weight: 26
audience: pro
---
Der Black-Duck-Connector importiert **Software-Composition-Analysis(SCA)**-Befunde von einer Black-Duck(Synopsys/Black-Duck)-Hub-Instanz. DefectDojo ermittelt jedes Projekt in der Instanz und erstellt für jedes **Projekt** einen Eintrag; die Befunde eines Projekts stammen aus den anfälligen BOM-Komponenten der ausgewählten Version.

#### Voraussetzungen

Ein Black-Duck-**API-Token** für einen Benutzer, der die zu importierenden Projekte sehen kann. Öffnen Sie in Black Duck Ihr Benutzermenü \> **My Access Tokens** \> **Create New Token**, gewähren Sie (mindestens) Lesezugriff, und kopieren Sie das Token, wenn es angezeigt wird — es wird nur einmal angezeigt. Der Connector tauscht dieses Token bei jedem Sync gegen ein kurzlebiges Bearer-Token ein; es wird über das Secret-Feld des Connectors hinaus nie im Klartext gespeichert.

#### Connector-Zuordnungen

1. Geben Sie Ihre Black-Duck-Hub-URL in das Feld **Location** ein — zum Beispiel `https://your-company.app.blackduck.com`.
2. Geben Sie das API-Token in das Feld **Secret** ein.
3. Legen Sie optional einen **Minimum Severity**-Wert fest, um einzuschränken, welche Befunde importiert werden.

Jedes Black-Duck-Projekt wird zu einem Eintrag. Standardmäßig importiert der Connector die **released**-Version des Projekts (mit Rückgriff auf dessen erste Version); jede anfällige BOM-Komponente dieser Version wird zu einem Befund mit dem Titel `{vulnerability} in {component}:{version}`.

Dieser Connector unterscheidet sich von den dateibasierten Black-Duck-Parsern — seine Befunde verwenden den dedizierten Scan-Typ **Black Duck - Connectors Import**.
