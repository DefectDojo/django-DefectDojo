---
title: "MobSF"
description: "Einrichtung des MobSF Upstream-Connectors für DefectDojo"
weight: 91
audience: pro
---
Der MobSF-Connector verwendet die REST-API des [Mobile Security Framework (MobSF)](https://github.com/MobSF/Mobile-Security-Framework-MobSF), um statische Analyseergebnisse mobiler Anwendungen (APK/IPA) zu importieren. DefectDojo ermittelt jede App, die auf Ihrer MobSF-Instanz gescannt wurde, und erstellt für jede einen Eintrag; anschließend werden die statischen Analysebefunde dieser App importiert.

#### Voraussetzungen

Sie benötigen Ihren MobSF-**REST-API-Schlüssel**. Sie finden ihn auf der MobSF-Startseite unter **API** (in der MobSF-Dokumentation auch als `Authorization`-Wert angezeigt). Der Schlüssel wird bei jeder Anfrage gesendet und nie protokolliert.

#### Connector-Zuordnungen

1. Geben Sie Ihre MobSF-Basis-URL in das Feld **Location** ein (zum Beispiel `https://mobsf.example.com`).
2. Geben Sie im Feld **Secret** den MobSF-REST-API-Schlüssel ein.
3. Legen Sie optional einen **Minimum Severity**-Wert fest, um einzuschränken, welche Befunde importiert werden.

DefectDojo ordnet jede gescannte **App** einem Eintrag zu und importiert deren Befunde aus dem MobSF-JSON-Bericht über mehrere Abschnitte hinweg — Anwendungsberechtigungen, Code-Analyse, das Signaturzertifikat, das Android-Manifest, Android-API-Nutzung und Binäranalyse. Jeder Befund wird mit **CWE 919** (mobil) getaggt, und sein Schweregrad stammt aus MobSFs eigener Bewertung (high, warning, info, secure/good) — eine *gefährliche* Berechtigung wird als High behandelt. Befunde werden als statische Befunde erfasst und anhand von Scan, Abschnitt, Titel, Schweregrad und Dateipfad dedupliziert.

Weitere Informationen finden Sie in der [MobSF-REST-API-Dokumentation](https://mobsf.github.io/docs/#/rest_api).
