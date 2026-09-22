---
title: "Google Cloud"
description: "Einrichtung des Google Cloud Upstream-Connectors für DefectDojo"
weight: 67
audience: pro
---
Der Google-Cloud-Connector ist ein **Asset-Connector**: Er liest Ihre Google-Cloud-Ressourcenhierarchie und erstellt für jedes **Projekt** ein DefectDojo-Asset, gruppiert in Organisationen nach dem Ordner, in dem das Projekt liegt. Auch jeder Ordner wird zu einem Asset, sodass Ihre Organisation, Ordner und Projekte in DefectDojo als derselbe Baum erscheinen, den Sie in der Cloud-Console sehen. Es werden keine Befunde importiert.

**Bitte beachten Sie:** Dieser Connector importiert nur Ihr Projekt-**Inventar**. Um Befunde aus dem Security Command Center zu importieren, verwenden Sie den separaten Connector [Google Cloud Security Command Center](/connectors/toolreference/google_cloud_scc/). Die beiden sind unabhängig voneinander und dafür ausgelegt, gemeinsam zu laufen: Ein von diesem Connector erstelltes Projekt ist dasselbe Asset, auf dem SCC-Befunde landen, sodass der gemeinsame Betrieb nichts dupliziert.

#### Voraussetzungen

Der Connector authentifiziert sich mit einem Google-**Service-Konto** und liest nur Hierarchie-Metadaten: Namen, IDs, Lifecycle-Status und Labels von Ordnern und Projekten. Er liest keine Ressourceninhalte und keine Befunde.

1. Erstellen Sie in Google Cloud ein Service-Konto — ein dediziertes für DefectDojo wird empfohlen.
2. Gewähren Sie ihm die Rolle **Browser** (`roles/browser`) auf der Organisation oder dem Ordner, den Sie importieren möchten. Für das Durchlaufen der Hierarchie werden `resourcemanager.folders.list` und `resourcemanager.projects.list` benötigt. Eine benutzerdefinierte Rolle muss zusätzlich `resourcemanager.folders.get` und `resourcemanager.organizations.get` enthalten, sonst wird das oberste Asset nach seiner Ressourcen-ID statt nach seinem Anzeigenamen benannt.
3. Gewähren Sie die Rolle an der **obersten Stelle** des von Ihnen konfigurierten Geltungsbereichs. Der Connector durchläuft den gesamten Teilbaum, und ein Ordner, den er nicht lesen kann, lässt den Sync fehlschlagen, statt stillschweigend ein unvollständiges Inventar zu importieren.
4. Erstellen Sie einen **JSON-Schlüssel** für das Service-Konto und laden Sie ihn herunter.
5. Aktivieren Sie die **Cloud Resource Manager API** (`cloudresourcemanager.googleapis.com`) für das Projekt, dem das Service-Konto gehört.

#### Connector-Zuordnungen

1. Lassen Sie das Feld **Location** auf dem Standardwert `https://cloudresourcemanager.googleapis.com`, sofern Sie keinen nicht standardmäßigen Endpunkt verwenden.
2. Geben Sie im Feld **Parent Resource** die Wurzel der zu importierenden Hierarchie ein: `organizations/{id}` oder `folders/{id}`. Ein einzelnes Projekt ist keine Hierarchie, daher wird `projects/{id}` hier nicht akzeptiert — verwenden Sie für einen einzelnen Projekt-Geltungsbereich den Google-Cloud-SCC-Connector.
3. Fügen Sie den vollständigen Inhalt der **JSON-Schlüssel**-Datei des Service-Kontos in das Feld **Service Account Key** ein.

Jeder `ACTIVE`-Ordner und jedes `ACTIVE`-Projekt unterhalb des übergeordneten Elements wird zu einem Eintrag. Der Eintrag jedes Projekts wird nach dessen **Projekt-ID** benannt, und seine Organisation in DefectDojo ist der Ordner, in dem es liegt (oder Ihre Google-Cloud-Organisation, wenn das Projekt direkt darunter liegt).

Wird ein Projekt in Google Cloud gelöscht, wechselt es in den Status `DELETE_REQUESTED` und fällt aus dem Import heraus. Sein zugeordneter Eintrag wird daher beim nächsten Sync als `MISSING` markiert, statt entfernt zu werden — DefectDojo löscht niemals stillschweigend ein Asset. Dasselbe gilt für einen gelöschten Ordner.

Sobald ein Eintrag zugeordnet ist, aktualisiert dieser Connector seine Metadaten nie. Wenn Sie in Google Cloud einen Ordner umbenennen oder ein Projekt in einen anderen Ordner verschieben, zeigt DefectDojo weiterhin den alten Namen oder den alten Ordner an.

#### Zusammenspiel mit dem Google-Cloud-SCC-Connector

Beide Connectors identifizieren ein Projekt auf dieselbe Weise und benennen sein Asset jeweils nach der Projekt-ID. Wenn Sie zuerst diesen Connector ausführen, landen SCC-Befunde auf den von ihm erstellten Assets; lief zuerst SCC, übernimmt dieser Connector diese Assets und ergänzt sie um die Ordnerhierarchie. Sie müssen nichts doppelt zuordnen.

Für die Organisation gilt dieselbe Regel: Wenn dieser Connector das Asset erstellt, setzt er die Organisation auf den Ordner des Projekts. Erstellte der Google-Cloud-SCC-Connector das Asset zuerst, behält dieses Asset seine bestehende Organisation, und dieser Connector ergänzt es nur um die Ordnerhierarchie.
