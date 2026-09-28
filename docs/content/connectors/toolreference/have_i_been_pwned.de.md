---
title: "Have I Been Pwned"
description: "Einrichtung des Have I Been Pwned Upstream-Connectors für DefectDojo"
weight: 72
audience: pro
---
Der Have-I-Been-Pwned(HIBP)-Connector verwendet die HIBP-REST-API, um zu melden, welche Konten auf den eigenen Domains Ihrer Organisation in bekannten Datenpannen aufgetaucht sind. DefectDojo ermittelt jede von Ihnen bei HIBP verifizierte Domain und importiert einen Befund pro Datenpanne, die diese Domain betrifft.

#### Voraussetzungen

Sie benötigen einen Have-I-Been-Pwned-API-Schlüssel mit Domain-Suche, wofür mindestens ein **Core**-Abonnement erforderlich ist. Sie können einen Schlüssel über Ihr [Have-I-Been-Pwned-Konto](https://haveibeenpwned.com/API/Key) erhalten.

Sie müssen außerdem **mindestens eine Domain verifizieren**, bevor Datenpannen-Daten verfügbar sind. HIBP ermöglicht die Verifizierung einer Domain per DNS-TXT-Eintrag, Meta-Tag, Datei-Upload oder E-Mail, unter **Domain search** in Ihrem Konto. Solange keine Domain verifiziert ist, ermittelt der Connector keine Domains und importiert keine Befunde.

#### Connector-Zuordnungen

1. Geben Sie `https://haveibeenpwned.com` in das Feld **Location** ein.
2. Geben Sie Ihren API-Schlüssel in das Feld **Secret** ein.
3. Legen Sie optional einen **Minimum Severity**-Wert fest, um einzuschränken, welche Befunde importiert werden. Befunde unterhalb des gewählten Schweregrads werden nicht importiert.

DefectDojo erstellt für jede von Ihnen bei HIBP verifizierte Domain einen separaten Eintrag und importiert einen Befund pro Datenpanne, die Konten auf dieser Domain betrifft. Der Schweregrad jedes Befunds spiegelt die Art der durch die Datenpanne offengelegten Daten wider, und seine Beschreibung listet die betroffenen Konten auf Ihrer Domain auf, damit Ihr Team handeln kann.

Weitere Informationen finden Sie in der [Have-I-Been-Pwned-API-Dokumentation](https://haveibeenpwned.com/API/v3).
