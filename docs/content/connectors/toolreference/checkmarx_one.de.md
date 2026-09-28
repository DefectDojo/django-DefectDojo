---
title: "Checkmarx ONE"
description: "Einrichtung des Checkmarx ONE Upstream-Connectors für DefectDojo"
weight: 33
audience: pro
---
Der Checkmarx-ONE-Connector von DefectDojo ruft die Checkmarx-API auf, um Daten abzurufen.

#### **Connector-Zuordnungen**

1. Geben Sie Ihren **Tenant Name** in das Feld **Checkmarx Tenant** ein. Dieser Name sollte auf der Checkmarx-ONE-Anmeldeseite oben rechts sichtbar sein:   
" Tenant: \<**Ihr Tenant-Name**\> "  
​
![image](images/connectors_tool_reference_2.png)

2. Geben Sie einen gültigen API-Schlüssel ein. Möglicherweise müssen Sie einen neuen generieren: siehe [Checkmarx-API-Dokumentation](https://docs.checkmarx.com/en/34965-68618-generating-an-api-key.html#UUID-f3b6481c-47f4-6cd8-9f0d-990896e36cd6_UUID-39ccc262-c7cb-5884-52ed-e1692a635e08) für Einzelheiten.
3. Geben Sie Ihren Tenant-Standort in das Feld **Location** ein. Diese URL ist wie folgt aufgebaut:  
​`https://<your-region>.ast.checkmarx.net/` . Ihre Region finden Sie am Anfang Ihrer Checkmarx-URL, wenn Sie die Checkmarx-App verwenden. **<https://ast.checkmarx.net>** ist der primäre US-Server (ohne Regionspräfix).

#### **Branch-Handhabung**

Standardmäßig importiert jeder Sync die Befunde des **einzigen zuletzt abgeschlossenen Scans** eines Projekts, unabhängig vom Branch. Wenn Ihre CI viele Branches scannt, „gewinnt" bei diesem Sync der Branch, der zuletzt gescannt wurde: Befunde, die nur auf anderen Branches existieren, werden nicht importiert, und der Close-Old-Abgleich des Syncs kann Befunde hin- und herwechselnd öffnen und schließen, je nachdem, welcher Branch gerade der aktuellste Scan ist.

Zwei optionale Felder steuern dieses Verhalten:

- **Branch**: fixiert jedes Projekt auf einen Branch-Namen — es werden nur Scans dieses Branches importiert. Dies ist ein einziger globaler Wert für den gesamten Connector und eignet sich daher für Umgebungen, in denen jedes Projekt denselben langlebigen Branch verwendet (z. B. `main`).
    - Ein **Platzhalter `*`** wird unterstützt. Ein Branch-Wert, der `*` enthält, wählt über *jeden* passenden Branch statt nur einen aus — zum Beispiel importiert `release/*` jeden Release-Branch, und `*` erfasst jeden Branch. In Kombination mit **Track Scanned Branches** lässt sich damit eine Gruppe von Branches verfolgen, ohne alle einzeln zu verfolgen.
    - Wenn ein Platzhalter innerhalb des Scan-Fensters **keinen** Branch trifft, wird dieser Sync **übersprungen**, statt als „der Branch hat keine Befunde" behandelt zu werden — sodass ein Muster, das vorübergehend auf nichts passt, nicht alle Befunde des Assets schließen kann.
- **Track Scanned Branches**: Wenn aktiviert, findet jeder Sync jeden Branch mit einem abgeschlossenen Scan in der jüngsten Scan-Historie des Projekts und importiert **den letzten abgeschlossenen Scan jedes Branches**, einen erneuten Import pro Branch. Die Befunde jedes Branches liegen in einem eigenen Engagement auf dem zugeordneten Asset mit dem Namen „\<Standard-Engagement\> \- \<Branch\>", sodass das Schließen veralteter Befunde pro Branch erfolgt: Ein in einen Branch gemergter Fix kann niemals die Befunde eines anderen Branches schließen. Der primäre Branch des Projekts (laut Checkmarx) wird zuerst importiert, sodass erneute Auftritte desselben Befunds auf anderen Branches mit dem Original des primären Branches dedupliziert werden.

Hinweise zu **Track Scanned Branches**:

- **Prüfen Sie, welcher Standard für Sie gilt.** Branch-Tracking ist bei **Neuinstallationen standardmäßig aktiviert**. Installationen von vor dieser Änderung behalten ihr bisheriges Verhalten bei, sodass der Schalter dort deaktiviert bleibt, bis ihn jemand einschaltet.
- Wenn beide Felder gesetzt sind, wird nur der fixierte **Branch** verfolgt — auch wenn dieser Branch-Wert ein Platzhaltermuster ist; in diesem Fall wird jeder passende Branch verfolgt.
- Ein Branch, der nicht mehr gescannt wird (gemergt oder gelöscht), erhält keine Updates mehr: Sein Engagement bleibt mit den zuletzt bekannten Befunden sichtbar, die Sie prüfen und gesammelt schließen können.
- Den Schalter später wieder auszuschalten ist unbedenklich: Die Branch-spezifischen Engagements erhalten dann einfach keine Importe mehr, und beim nächsten Sync wird wieder das Standard-Engagement verwendet.
- Connectors gleichen den Zustand nach dem Sync-Zeitplan ab. Branch-Tracking macht jeden Sync über alle Branches hinweg vollständig; es macht die Daten zwischen den Syncs jedoch nicht in Echtzeit verfügbar.
