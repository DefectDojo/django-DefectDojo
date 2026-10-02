---
title: "YesWeHack"
description: "Einrichtung des YesWeHack Upstream-Connectors für DefectDojo"
weight: 143
audience: pro
---
Der YesWeHack-Connector verwendet die YesWeHack-REST-API, um Reports aus Ihren Bug-Bounty- und Vulnerability-Disclosure-Programmen zu importieren. DefectDojo erstellt für jedes Programm, auf das Ihr Token zugreifen kann, einen Eintrag und importiert dessen Reports als Befunde.

#### Voraussetzungen

Sie benötigen ein YesWeHack-**Personal Access Token (PAT)**. Lesezugriff auf Ihre Programme ist ausreichend. Manche Konten erfordern beim Erstellen eines Tokens TOTP/MFA; einmal erstellt, verwendet der Connector nur den Token-Wert selbst.

1. Öffnen Sie in YesWeHack Ihre Kontoeinstellungen und gehen Sie zu **API / Personal Access Tokens**.
2. Erstellen Sie ein Token und kopieren Sie dessen Wert. Er wird nur einmal angezeigt.

#### Connector-Zuordnungen

1. Geben Sie `https://api.yeswehack.com/` in das Feld **Location** ein.
2. Geben Sie Ihr Personal Access Token in das Feld **Secret** ein.
3. Legen Sie optional einen **Minimum Severity**-Wert fest, um einzuschränken, welche Befunde importiert werden. Befunde unterhalb des gewählten Schweregrads werden nicht importiert.

DefectDojo erstellt für jedes Programm, auf das Ihr Token zugreifen kann, einen separaten Eintrag und importiert jeden Report als Befund. Der Schweregrad des Befunds wird der CVSS-Bewertung des Reports entnommen (mit Rückgriff auf die Triage-Priorität), und sein Status spiegelt den Workflow-Status des Reports wider — zum Beispiel werden gelöste Reports als behoben importiert, und als ungültig oder außerhalb des Geltungsbereichs markierte Reports werden als inaktiv importiert.
