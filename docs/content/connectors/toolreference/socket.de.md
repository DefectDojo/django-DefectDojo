---
title: "Socket"
description: "Einrichtung des Socket Upstream-Connectors für DefectDojo"
weight: 126
audience: pro
---
Der Socket-Connector verwendet die API von [Socket.dev](https://socket.dev), um **Software-Supply-Chain-Befunde** zu importieren — Sockets Warnungen zu Ihren Abhängigkeiten (Malware, Typosquats, Install-Skripte, bekannte Schwachstellen und über 70 weitere Kategorien). DefectDojo ermittelt jedes Repository in den Organisationen, auf die Ihr Token zugreifen kann, und erstellt für jedes einen Eintrag; anschließend werden die Warnungen aus dem letzten vollständigen Scan dieses Repositorys importiert.

#### Voraussetzungen

Sie benötigen ein Socket-**API-Token** — ein Organisations-Token, das im Socket-Dashboard unter **Settings → API Tokens** erstellt wird (mit den Scopes `repo:list` und Full-Scan-Lesezugriff). Das Token wird als Bearer-Token gesendet und nie protokolliert.

#### Connector-Zuordnungen

1. Behalten Sie den vorgegebenen Wert im Feld **Location**, `https://api.socket.dev/v0`, oder geben Sie es explizit an.
2. Geben Sie das Socket-API-Token in das Feld **Secret** ein.
3. Legen Sie optional einen **Minimum Severity**-Wert fest, um einzuschränken, welche Befunde importiert werden.

DefectDojo ordnet jedes **Repository** einem Eintrag zu und importiert die Warnungen aus dessen letztem vollständigen Scan. Jede Warnung wird zu einem Befund: Der Schweregrad stammt aus Sockets eigener Bewertung (low, medium, high, critical), das betroffene Paket wird zur Komponente und zu einer PURL, die Warnungskategorie (Supply-Chain-Risiko, Qualität, Wartung, Schwachstelle, Lizenz) wird als Tags erfasst, und die Warnungsdetails werden in die Beschreibung übernommen. Befunde werden als statische Befunde erfasst und anhand des Socket-Warnungsschlüssels dedupliziert.

Weitere Informationen finden Sie in der [Socket-API-Dokumentation](https://docs.socket.dev/reference).
