---
title: Kalender
description: So verwenden Sie den Kalender in DefectDojo Pro
audience: pro
weight: 9
---

DefectDojo verfügt über einen integrierten Kalender, mit dem Sie alle früheren und aktiven Engagements und Tests in Ihrer Organisation verfolgen können. Sobald ein Benutzer ein neues Engagement oder einen neuen Test erstellt und Start- und Enddatum festlegt, wird automatisch ein entsprechender Eintrag im Kalender angelegt. 

### Startseite 

Die Kalenderseite enthält oben Filter und darunter einen Monatskalender. Mit den Filtern legen Sie fest, welche Ergebnisse im Kalender erscheinen, und zwar anhand von:
- Engagement und/oder Test 
- Start- und Enddatum 
- Engagement-Status (z. B. Abgeschlossen, In Bearbeitung, Angehalten usw.) 
- Engagement-/Testleitung (d. h. wem ist das Engagement bzw. der Test zugewiesen?) 
- Engagement-Typ (z. B. Interactive oder CI/CD)
- Testtyp (z. B. Pen Test, Acunetix Scan, Tenable Scan usw.) 

![image](images/calendar1.png)
 
Nach dem Filtern können die Ergebnisse als ICS-Datei exportiert und weitergegeben werden. 

Wichtig: Der Kalender zeigt nur Engagements und Tests, auf die der Benutzer, der den Kalender ansieht, Zugriff hat. Engagements und Tests, für die der Benutzer keine Anzeigeberechtigung besitzt, werden nicht dargestellt. 

## Funktionen 

### Monatsansicht

Der Monatskalender zeigt pro Tag fünf Einträge in der Vorschau. Weitere Einträge dieses Tages bleiben verborgen, bis in der Zelle des jeweiligen Datums auf **„+ [X] Ereignisse“** geklickt wird. Nach dem Klick wechselt der Kalender von der Monatsansicht zur Tagesansicht.

Ein Klick auf einen Eintrag für einen Test oder ein Engagement öffnet ein Dialogfenster mit zusätzlichen Informationen zu diesem Eintrag, darunter: 
- Start- und Enddatum 
- Test- oder Engagement-Typ 
- Leitung 
- Status 
- Asset 
- Engagement 
- Test 

Von dort aus können das Asset, das Engagement oder der Test über einen Hyperlink aufgerufen werden.

### Tagesansicht 

In der Tagesansicht erscheinen alle derzeit aktiven Engagements und Tests in chronologisch absteigender Reihenfolge (d. h. ein neu erstelltes Engagement oder ein neuer Test steht am Ende der Einträge dieses Tages). Engagements werden in Blau dargestellt, Tests in Orange.

Sofern im jeweiligen Engagement bzw. Test festgelegt, enthält der Titel jedes Eintrags im Tageskalender Folgendes:
- Status 
- Produkt
- Engagement
- Test
- Zugewiesene Person 

#### Pfeile

Die Pfeile links und rechts an jedem Eintrag zeigen an, ob der jeweilige Test oder das jeweilige Engagement auch am vorherigen und/oder folgenden Tag vorhanden ist. 

Ein Test, der am selben Tag erstellt wurde, an dem er betrachtet wird, hat beispielsweise keine Pfeile auf der linken Seite, weil dieser Test am Tag davor noch nicht existierte. Umgekehrt hat ein Test, der am selben Tag endet, an dem er betrachtet wird, keine Pfeile auf der rechten Seite, weil der Eintrag am folgenden Tag nicht mehr existiert.

Da beispielsweise das letzte Engagement im Screenshot unten (**In Bearbeitung** Example Product A ▶ **Sample Engagement** (Nicht zugewiesen)) am Tag seiner Erstellung betrachtet wird und das geplante Enddatum auf den folgenden Tag gesetzt wurde, sind weder links noch rechts Pfeile vorhanden.

![image](images/calendar2.png)
