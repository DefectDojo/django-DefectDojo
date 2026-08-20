---
title: "HackerOne"
description: "Einrichtung des HackerOne Upstream-Connectors für DefectDojo"
weight: 69
audience: pro
---
Der HackerOne-Connector verwendet die HackerOne-REST-API, um Reports aus Ihrem Bug-Bounty- oder Vulnerability-Disclosure-Programm zu importieren. DefectDojo erstellt für jedes Programm, auf das das Token zugreifen kann, einen Eintrag und importiert dessen Reports als Befunde.

#### Voraussetzungen

Der Connector verwendet die **Customer**-API von HackerOne, die ein **Organization-API-Token** erfordert — ein persönliches Token aus Ihren Benutzereinstellungen funktioniert nur gegen die Hacker-API und authentifiziert sich hier nicht.

1. Gehen Sie in HackerOne zu **Organization Settings > API Tokens**.
2. Erstellen Sie ein Token und notieren Sie sowohl die **Identifier** als auch den **Token**-Wert. Lesezugriff auf das Programm ist ausreichend.

#### Connector-Zuordnungen

1. Geben Sie `https://api.hackerone.com` in das Feld **Location** ein.
2. Geben Sie die Token-**Identifier** in das Feld **API Token Identifier** ein.
3. Geben Sie den Token-Wert in das Feld **API Token** ein.
4. Legen Sie optional einen **Minimum Severity**-Wert fest, um einzuschränken, welche Befunde importiert werden.

Jedes Programm wird zu einem Eintrag, und seine Reports werden mit der beibehaltenen HackerOne-Schweregrad-Bewertung als Befunde importiert.
