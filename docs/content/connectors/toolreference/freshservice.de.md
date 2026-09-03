---
title: "Freshservice"
description: "Einrichtung des Freshservice Downstream-Connectors für DefectDojo"
weight: 61
audience: pro
---
Die Freshservice-Integration ermöglicht es Ihnen, DefectDojo-Befunde und Befundgruppen als Freshservice-Tickets zu übertragen, die einer Agenten-Gruppe Ihrer Wahl zugewiesen werden.

### Instanz-Einrichtung

- **Label** sollte die Bezeichnung sein, mit der Sie diese Integration identifizieren möchten.
- **Location** sollte auf Ihre Freshservice-URL gesetzt werden: `https://yourcompany.freshservice.com`.
- **API Key** sollte ein Freshservice-API-Key sein.  Sie finden ihn, indem Sie auf Ihr Profilbild (oben rechts) > **Profile settings** klicken - der Key erscheint rechts unterhalb des Abschnitts **Delegate Approvals**, nachdem Sie das Captcha gelöst haben.  Wird dort kein Key angezeigt, ist der API-Zugriff möglicherweise auf Kontoebene deaktiviert und muss zuerst von einem Administrator aktiviert werden.
- **Requester Email** sollte die E-Mail-Adresse sein, in deren Namen Tickets angefordert werden.  Freshservice verlangt für jedes Ticket einen Anforderer, daher erstellt DefectDojo Tickets mit dieser Adresse als Anforderer.

### Issue-Tracker-Zuordnung

- **Group ID** sollte die numerische ID der Freshservice-Agenten-Gruppe sein, der Tickets zugewiesen werden.  Sie finden sie in der URL, während Sie die Gruppe unter **Admin > Agent Groups** ansehen.
- **Workspace ID** (optional) leitet Tickets bei Konten mit mehreren Workspaces an einen bestimmten Workspace.  Lassen Sie das Feld leer, um den primären Workspace zu verwenden.

### Details zur Schweregrad-Zuordnung

Dies wird dem Freshservice-Ticketfeld **Priority** zugeordnet, das numerische Codes verwendet (`1` Low, `2` Medium, `3` High, `4` Urgent).  Die Prioritätsnamen werden ebenfalls akzeptiert:

- **Name des Schweregrad-Felds**: `Priority`
- **Info-Zuordnung**: `1`
- **Niedrig-Zuordnung**: `1`
- **Mittel-Zuordnung**: `2`
- **Hoch-Zuordnung**: `3`
- **Kritisch-Zuordnung**: `4`

### Details zur Status-Zuordnung

Dies wird dem Ticketfeld **Status** zugeordnet, das numerische Codes verwendet (`2` Open, `3` Pending, `4` Resolved, `5` Closed).  Die Statusnamen werden ebenfalls akzeptiert:

- **Name des Status-Felds**: `Status`
- **Aktiv-Zuordnung**: `2`
- **Geschlossen-Zuordnung**: `5`
- **Falsch-positiv-Zuordnung**: `5`
- **Risiko-akzeptiert-Zuordnung**: `3`

Einige Freshservice-spezifische Verhaltensweisen, die Sie kennen sollten:

- Aktualisierungen synchronisieren den vollständigen Ticketinhalt - Freshservice erlaubt es, Betreff und Beschreibung nach dem Erstellen zu bearbeiten.
- Tickets werden geschlossen und nicht gelöscht, wenn ein Befund entfernt wird; Tickets, die bereits Resolved oder Closed sind, bleiben unberührt.  Beim Schließen wird automatisch eine Lösungsnotiz angehängt, sodass Konten, die eine solche verlangen (eine verbreitete Geschäftsregel), das Schließen akzeptieren.
- Manche Konten berechnen die Priorität eines Tickets aus einer Impact-/Urgency-Matrix oder einer Geschäftsregel und ignorieren die beim Erstellen gesendete Priorität.  DefectDojo erkennt dies und wendet die zugeordnete Priorität mit einer nachgelagerten Aktualisierung erneut an, sodass die Zuordnung dennoch wirksam wird.
