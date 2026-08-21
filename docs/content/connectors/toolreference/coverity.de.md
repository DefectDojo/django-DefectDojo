---
title: "Coverity"
description: "Einrichtung des Coverity Upstream-Connectors für DefectDojo"
weight: 40
audience: pro
---
Der Coverity-Connector importiert Befunde von einem **Coverity-Connect**-Server. DefectDojo erstellt für jedes Coverity-**Projekt** einen Eintrag.

#### Connector-Zuordnungen

1. Geben Sie die URL Ihres Coverity-Connect-Servers in das Feld **Location** ein.
2. Geben Sie den Coverity-Connect-**Benutzernamen** in das Feld **Username** ein.
3. Geben Sie das Passwort oder den Authentifizierungsschlüssel des Benutzers in das Feld **Secret** ein.
4. Legen Sie optional einen **View Name** fest, um auszuwählen, welche gespeicherte Issue-Ansicht der Connector liest. Leer lassen, um den Standard **Outstanding Issues** zu verwenden.
5. Setzen Sie optional **Import All Issue Kinds** auf `true`, um den Import über den Standardfilter für Security- und Quality-Issues (`RESOURCE_LEAK`) hinaus zu erweitern.
