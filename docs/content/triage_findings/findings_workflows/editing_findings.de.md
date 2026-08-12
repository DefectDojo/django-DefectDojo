---
title: Befunde bearbeiten
description: Ändern Sie den Status eines Befunds oder fügen Sie weitere Metadaten
  hinzu, während Sie ein Problem beheben
weight: 2
aliases:
- /en/working_with_findings/findings_workflows/editing_findings
---

Wenn Sie Notizen hinzufügen oder den Wortlaut eines Befunds aktualisieren möchten, damit er der aktuellen Situation besser entspricht, können Sie dies über das Formular „Befund bearbeiten“ tun.

## Formular „Befund bearbeiten“ öffnen

Sie können einen Befund aktualisieren, indem Sie oben das **⚙️ Zahnrad** **Menü** öffnen und auf **Befund bearbeiten** klicken.

![image](images/Editing_Findings.png)

Dadurch wird das Formular **Befund bearbeiten** geöffnet, in dem Sie die Metadaten bearbeiten, den Status des Befunds ändern und zusätzliche Informationen hinzufügen können.

![image](images/Editing_Findings_2.png)

### Formular „Befund bearbeiten“: Felder

* **"Test" kann nicht bearbeitet werden:** Befunde müssen immer einem Test-Objekt zugeordnet sein und können nicht aus diesem Kontext verschoben werden. Das Engagement, das einen Test enthält, kann jedoch in ein anderes Produkt verschoben werden.  
​
* **Found By** ist das Scan-Tool, das diesen Befund entdeckt hat. Beachten Sie, dass Sie zusätzliche Scan-Tools über das dem Test zugeordnete Tool hinaus hinzufügen können.  
​
* **Title** wird aus dem Scan-Bericht erstellt, Sie können diesen Titel bei Bedarf jedoch aussagekräftiger gestalten. Beachten Sie, dass sich dies auf die Deduplizierung auswirken kann, da die Deduplizierung im Allgemeinen die Titel von Befunden zur Erkennung von Duplikaten verwendet.  
​
* **Date** soll das Datum darstellen, an dem der Befund vom Scanner entdeckt wurde \- nicht unbedingt das Datum, an dem der Befund in DefectDojo importiert wurde. Dieses Datum wird aus dem Scan-Bericht übernommen, Sie können es jedoch bei Bedarf genauer aktualisieren (zum Beispiel bei der Arbeit mit historischen Daten oder bei Verwendung eines Scan-Tools, das keine Entdeckungsdaten protokolliert).  
​
* **Description** ist die vom Scan-Tool bereitgestellte Beschreibung eines Befunds. Sie können der Beschreibung des Befunds bei Bedarf Informationen hinzufügen oder daraus entfernen.  
​
* **Severity** wird auf Grundlage mehrerer Faktoren berechnet. Grundsätzlich handelt es sich dabei um den von einem Tool gemeldeten Schweregrad, der Schweregrad eines Befunds kann jedoch durch EPSS-Änderungen beeinflusst werden. Sie können den Schweregrad des Befunds auch manuell auf eine passende Stufe anpassen.  
​
* **Tags** sind generische Textbezeichnungen, mit denen Sie Ihre Befunde über Filter organisieren können \- oder die einfach als Kurzform zur Identifizierung eines bestimmten Befunds dienen können.  
​
* **Aktiv / Verifiziert** sind die primären Befund-Status, die von einem Tool verwendet werden. Aktive Befunde sind Befunde, die derzeit in Ihrem Netzwerk aktiv sind und von einem Tool gemeldet wurden. Verifiziert bedeutet, dass ein Teammitglied das Vorhandensein dieses Befunds bestätigt hat.  
​
* **SAST / DAST** sind Bezeichnungen, mit denen Sie Ihre Befunde nach dem Kontext ihrer Entdeckung organisieren. Diese Bezeichnung wird im Allgemeinen anhand des verwendeten Scan-Tools vergeben, Sie können sie jedoch bei Bedarf präziser anpassen (zum Beispiel, wenn der Befund sowohl von einem SAST- als auch einem DAST-Tool gefunden wurde).

### Bearbeiten von Mitigated Date und Mitigated By

Standardmäßig sind die Werte **Mitigated Date** und **Mitigated By** eines Befunds **nicht bearbeitbar**. Diese Felder sind sowohl im Formular „Befund bearbeiten“ als auch im Dialog „Befund schließen“ ausgeblendet, und das Mitigated Date wird immer automatisch auf den Zeitpunkt gesetzt, an dem der Befund geschlossen wird. Der Versuch, diese Werte über die API zu setzen oder rückzudatieren, wird aus demselben Grund abgelehnt.

Die Bearbeitung kann über die Servereinstellung `DD_EDITABLE_MITIGATED_DATA` aktiviert werden. Wenn diese aktiviert ist, erscheinen die Felder **Mitigated Date** und **Mitigated By** im Formular „Befund bearbeiten“ und im Dialog „Befund schließen“ und können auch über die API gesetzt werden — jedoch nur für Benutzer mit **Superuser**-Status. Mit anderen Worten: Die Bearbeitung erfordert *sowohl*, dass die Einstellung aktiviert ist, *als auch*, dass der handelnde Benutzer ein Superuser ist.

* **Warum dies standardmäßig deaktiviert ist:** Wenn eine Behebung rückdatiert werden kann, kann dies die SLA-Einhaltung verfälschen — ein Befund, der tatsächlich *außerhalb* seines SLA-Fensters behoben wurde, könnte so erfasst werden, als sei er *innerhalb* der SLA behoben worden. Das Aktivieren der Einstellung wirkt sich nur auf die Zukunft aus; sie ändert **nicht** das Mitigated Date oder das Alter bestehender Befunde.
* **Alles bleibt nachvollziehbar:** Jede Änderung an einem Befund, einschließlich Änderungen am Mitigated Date und Mitigated By, wird im Verlaufsprotokoll des Befunds erfasst — wer die Änderung wann vorgenommen hat sowie die vorherigen und neuen Werte.
* **Anwenden der Einstellung:** `DD_EDITABLE_MITIGATED_DATA` ist eine Umgebungsvariable auf Serverebene (siehe [Konfiguration](/get_started/open_source/configuration/)). Damit die Änderung wirksam wird, ist ein Neustart des Dienstes erforderlich.
* **DefectDojo Cloud / Pro:** Diese Einstellung kann nicht über die Benutzeroberfläche geändert werden. Wenden Sie sich an den DefectDojo-Support, um sie für Ihre Instanz aktivieren zu lassen.

## Bulk Edit Findings

Befunde können aus einer Befundliste heraus in großer Anzahl bearbeitet werden; diese finden Sie entweder auf der Findings-Seite selbst oder innerhalb eines Tests. 

### Befunde für Bulk Edit auswählen

Wenn Sie eine Tabelle mit mehreren Befunden betrachten, wie zum Beispiel die Tabelle „Findings From [tool]“ auf einer Testseite oder die Liste „All Findings“, können Sie die Kontrollkästchen neben den Befunden verwenden, um sie für Bulk Edit zu markieren. 

Wenn Sie auf diese Weise einen oder mehrere Befunde auswählen, wird das (versteckte) Bulk-Edit-Menü geöffnet, das die folgenden vier Optionen enthält:

* **Bulk Update Actions**: Wenden Sie Metadatenänderungen auf die ausgewählten Befunde an.
* **Risk Acceptance Actions: Erstellen Sie eine Full Risk Acceptance zur Steuerung der ausgewählten Befunde, oder fügen Sie die Befunde einer bestehenden Full Risk Acceptance hinzu**
* **Finding Group Actions: Erstellen Sie eine Finding Group aus den ausgewählten Befunden. Beachten Sie, dass Finding Groups nur innerhalb eines einzelnen Tests erstellt werden können.**
* **Delete: Löschen Sie die ausgewählten Befunde. Sie müssen diese Aktion in einem neuen Fenster bestätigen.**

![image](images/Bulk_Editing_Findings.png)

### Bulk Update Actions

Über das Menü Bulk Update Actions können Sie die folgenden Änderungen auf alle von Ihnen ausgewählten Befunde anwenden:

* Aktualisieren Sie den **Schweregrad**
* Wenden Sie einen neuen **Finding Status** an
* Ändern Sie das Discovery- oder Planned-Remediation-Datum der Befunde
* Fügen Sie eine **Simple Risk Acceptance,** hinzu, sofern die Option auf Produktebene aktiviert ist
* Wenden Sie **Tags** oder **Notizen** auf alle ausgewählten Befunde an.

![image](images/Bulk_Editing_Findings_2.png)

### Risk Acceptance Actions

Auf dieser Seite können Sie den ausgewählten Befunden eine **Full Risk Acceptance** hinzufügen. Sie können entweder eine neue **Full Risk Acceptance** erstellen oder die Befunde einer bereits bestehenden hinzufügen.

![image](images/Bulk_Editing_Findings_3.png)

### Finding Group Actions

Auf dieser Seite können Sie aus den ausgewählten Befunden eine neue Finding Group erstellen oder sie einer bestehenden Finding Group hinzufügen.

Finding Groups können jedoch nur innerhalb eines einzelnen **Tests** erstellt werden \- Befunde aus unterschiedlichen Tests, Engagements oder Produkten können nicht derselben Finding Group hinzugefügt werden.

![image](images/Bulk_Editing_Findings_4.png)

### Bulk Delete Findings

Sie können ausgewählte Befunde auch löschen, indem Sie auf die rote Schaltfläche **Delete** klicken. Es öffnet sich ein Popup-Fenster, in dem Sie zur Bestätigung dieser Entscheidung aufgefordert werden.

![image](images/Bulk_Editing_Findings_5.png)