---
title: Kalender
description: So verwenden Sie den Kalender in DefectDojo Pro
audience: opensource
weight: 9
---

Der Kalender von DefectDojo bietet eine zentrale Zeitleistenansicht aller Engagements und Tests mit definiertem Start- und Enddatum. So können Benutzer die Testaktivität über Produkte hinweg schnell erfassen, Terminüberschneidungen erkennen und direkt zu den zugehörigen Objekten navigieren. 

Wenn ein Benutzer ein Engagement oder einen Test erstellt und Start- und Enddatum festlegt, wird automatisch ein entsprechender Eintrag im Kalender angelegt. Einträge erscheinen an allen Tagen vom festgelegten Startdatum bis einschließlich des festgelegten Enddatums. 

## Zugriff auf den Kalender 

Die Kalenderseite ist über die Schaltfläche „Kalender“ in der Seitenleiste erreichbar. 

![image](images/OSC_ss3.png)

## Sichtbarkeit und Berechtigungen 

### Sichtbarkeit 

Die Kalenderseite enthält oben Filter und darunter ein monatliches Kalenderraster. Über die Navigationselemente oberhalb des Kalenders wechseln Sie zwischen den Monaten. 

Die Monatsansicht wird als festes Raster mit sechs Wochen dargestellt und beginnt mit der Woche, die den ersten Tag des ausgewählten Monats enthält.

Die im Kalender sichtbaren Einträge können nach Objekttyp (Engagements oder Tests) und nach der Testleitung gefiltert werden, die in den Einstellungen des Engagements oder Tests festgelegt wird. Klicken Sie nach dem Auswählen der Filterkriterien auf „Anwenden“, um die Kalenderansicht zu aktualisieren.

Es kann jeweils nur ein Objekttyp angezeigt werden. Beim Wechsel zwischen Engagements und Tests wird die Kalenderansicht entsprechend aktualisiert.

### Berechtigungen 

Der Kalender berücksichtigt die objektbezogenen Berechtigungen von DefectDojo. Benutzer sehen nur Engagements und Tests, auf die sie zugriffsberechtigt sind.

## Einträge ansehen und nutzen 

Innerhalb jeder Datumszelle sind die Einträge alphabetisch nach dem Namen des Objekts sortiert. Ein Klick auf einen Eintrag führt zum entsprechenden Objekt.

Die Anzahl der pro Tag sichtbaren Einträge ist dynamisch und hängt von der Bildschirmgröße und der Zoomstufe des Browsers ab. Übersteigt die Zahl der Einträge den verfügbaren Platz in einer Datumszelle, erscheint am unteren Rand der Zelle ein Link in der Form „+X weitere“.

![image](images/OSC_ss1.png)

Klicken Sie auf den Link „+X weitere“, um ein Dialogfenster mit allen Einträgen dieses Datums zu öffnen. 

![image](images/OSC_ss2.png)

Wichtig: Der Kalender selbst ist eine reine Leseansicht. Datumsangaben müssen in den Einstellungen des Engagement- oder Test-Objekts selbst geändert werden. 

### Benennungslogik 

Die Benennung der Einträge im Kalender unterscheidet sich je nach Objekttyp leicht. 

Engagement-Einträge enthalten: 
- Produktname
- Engagement-Name
- Testleitung

Test-Einträge enthalten:
- Produktname
- Engagement-Name
- Testtyp 
- Testleitung
