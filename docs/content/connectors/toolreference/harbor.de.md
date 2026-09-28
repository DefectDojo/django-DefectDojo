---
title: "Harbor"
description: "Einrichtung des Harbor Upstream-Connectors für DefectDojo"
weight: 71
audience: pro
---
Der Harbor-Connector verwendet die Harbor-v2.0-REST-API, um Container-Image-Schwachstellen aus Ihrer gesamten Registry zu importieren. DefectDojo zählt jedes Harbor-**Projekt** auf und erstellt für jedes einen Eintrag; anschließend durchläuft er die Repositories und Artefakte des Projekts und importiert die Schwachstellen aus jedem **gescannten** Artefakt — wobei das Image (Repository + Tag/Digest) als Befundkontext übernommen wird. Es gibt keine Pro-Image-Konfiguration.

#### Voraussetzungen

Sie benötigen ein Harbor-Konto (oder ein **Robot-Konto**) mit Pull-/Lesezugriff auf die zu importierenden Projekte. Wir empfehlen ein dediziertes Robot-Konto: Öffnen Sie in Harbor ein Projekt (oder **Administration \> Robot Accounts** für ein System-Robot), erstellen Sie einen Robot mit der Berechtigung **pull** auf Repositories und Artefakte, und kopieren Sie dessen vollständigen Namen und Secret. Robot-Namen beginnen standardmäßig mit `robot$`, das Präfix ist jedoch pro Harbor-Instanz konfigurierbar (manche verwenden `robot_`) — kopieren Sie den Namen exakt so, wie Harbor ihn anzeigt. Ein normaler Benutzername/Passwort funktioniert ebenfalls.

#### Connector-Zuordnungen

1. Geben Sie Ihre Harbor-URL in das Feld **Location** ein — zum Beispiel `https://harbor.example.com`. DefectDojo hängt den API-Pfad `/api/v2.0` automatisch an.
2. Geben Sie den Harbor-Benutzernamen oder einen Robot-Kontonamen exakt so, wie Harbor ihn anzeigt (standardmäßig `robot$<name>`), in das Feld **Username** ein.
3. Geben Sie das Passwort oder das Robot-Konto-Secret in das Feld **Secret** ein. Es wird per HTTP-Basic-Authentifizierung gesendet.
4. Legen Sie optional einen **Minimum Severity**-Wert fest, um einzuschränken, welche Befunde importiert werden.

Jedes Harbor-Projekt wird zu einem Eintrag. Für jedes Artefakt mit einem abgeschlossenen Scan werden dessen Schwachstellen als Befunde importiert; das betroffene Paket/die Version, ein von CVSS abgeleiteter Schweregrad, die CVE, die CWE und eine Abhilfemaßnahme (Fix-Version) werden einbezogen, sofern Harbor sie bereitstellt. Es werden nur gescannte Artefakte importiert — lösen Sie in Harbor einen Scan für noch nicht gescannte Images aus.
