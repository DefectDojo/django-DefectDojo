---
title: Definitionen der Befund-Status
description: 'Eine kurze Referenz zu Befund-Status: Offen, Verifiziert, Akzeptiert..'
weight: 2
aliases:
- /en/working_with_findings/findings_workflows/finding_status_definitions
---

Jeder in DefectDojo erstellte Befund hat einen Status, der relevante Informationen vermittelt. Status helfen Ihrem Team, den Fortschritt bei der Behebung von Problemen im Blick zu behalten.

Jeder Befund-Status hat eine kontextspezifische Bedeutung, die von Ihrem eigenen Team definiert werden muss. Dies sind unsere Vorschläge, die Nutzung in Ihrem Team kann jedoch abweichen.

Bitte beachten Sie, dass Offen/Geschlossen keine **expliziten** Status-Typen für Befunde sind.  Bestimmte Bereiche der Classic UI (zum Beispiel die Tabelle "All Open Findings") können sich auf offene oder geschlossene Befunde beziehen: Dies dient als Sammelbegriff für

* Aktive und/oder Verifizierte Befunde im Fall von "Open Findings"
* Inaktive und/oder Risiko akzeptiert, In Prüfung, Außerhalb des Geltungsbereichs, Falsch-positiv Befunde im Fall von "Closed Findings"

## **Offene Befund-Status**

Sobald ein Befund **Aktiv** ist, wird er als **Offener** Befund gekennzeichnet, unabhängig davon, ob er bereits **Verifiziert** wurde.

Offene Befunde finden Sie in der Ansicht **Findings > Open Findings** von DefectDojo.

### **Aktive Befunde**

„Dieser Befund wurde von einem Scan-Tool entdeckt.“

Standardmäßig wird jeder neu in DefectDojo erstellte Befund als **Aktiv** gekennzeichnet. Aktiv bedeutet in diesem Fall: „Dies ist ein neuer Befund, den DefectDojo bei einem früheren Import noch nicht erfasst hat.“ Wurde ein Befund in der Vergangenheit als Behoben markiert, taucht aber in Zukunft erneut in einem Scan auf, wird der Status dieses Befunds wieder geöffnet, um widerzuspiegeln, dass die Schwachstelle zurückgekehrt ist.

### **Verifizierte Befunde**

„Unser Team hat das Vorhandensein dieses Befunds bestätigt.“

Nur weil ein Tool ein Problem erfasst, bedeutet das nicht zwangsläufig, dass der Befund die Aufmerksamkeit des Engineering-Teams erfordert. Daher werden neue Befunde standardmäßig auch als **Unverifiziert** gekennzeichnet. 

Wenn Sie bestätigen können, dass der Befund tatsächlich vorliegt, können Sie ihn als **Verifiziert** markieren.

Bestimmte DefectDojo-Funktionen setzen voraus, dass Befunde Aktiv und Verifiziert sind.  Wenn Sie nicht jeden Befund manuell verifizieren müssen, können Sie die Verifiziert-Anforderung für einige oder alle dieser Funktionen auf der Seite **System Settings** deaktivieren (**Classic UI: Configuration > System Settings**, **Pro UI: Settings > System > System Settings**).

![image](images/verified_status_toggle.png)

Diese Verifiziert-Status sind erforderlich für

* Das Pushen von Jira-Issues
* Das Anwenden von Grading auf Produkte
* Das Berechnen von Metriken

## **Geschlossene Befund-Status**

„Die hier erfasste Schwachstelle ist nicht mehr aktiv“.

Sobald die Arbeit an einem Befund abgeschlossen ist, können Sie ihn über die Option Close Findings manuell schließen. Wird alternativ ein Scan erneut in DefectDojo importiert, der einen zuvor erfassten Befund nicht mehr enthält, wird dieser zuvor erfasste Befund automatisch geschlossen.

## **Inaktiv**

„Dieser Befund wurde bereits früher entdeckt, wurde jedoch entweder behoben oder erfordert keine sofortige Aufmerksamkeit.“

Wenn ein Befund als Inaktiv markiert ist, bedeutet dies, dass das Problem derzeit keine Auswirkungen auf die Softwareumgebung hat und nicht behoben werden muss. Dieser Status bedeutet nicht zwangsläufig, dass das Problem gelöst wurde, da auch aktive Risikoakzeptanzen Befunde als Inaktiv kennzeichnen.

### **In Prüfung**

„Ich habe diesen Befund an ein oder mehrere Teammitglieder zur Prüfung gesendet.“

Wenn sich ein Befund In Prüfung befindet, muss er von einem Teammitglied überprüft werden. Sie können einen Befund in die Prüfung versetzen, indem Sie im Dropdown-Menü des Befunds **Request Peer Review** auswählen.

![image](images/Finding_Status_Definitions.png)

### **Risiko akzeptiert**

„Unser Team hat das mit diesem Befund verbundene Risiko bewertet und ist zu dem Schluss gekommen, dass die Behebung gefahrlos aufgeschoben werden kann.“

Befunde können aus verschiedenen Gründen nicht immer behoben oder bearbeitet werden. Sie können einem Befund über die Option Add Risk Acceptance eine Risikoakzeptanz hinzufügen. Risikoakzeptanzen ermöglichen es Ihnen, Dateien hochzuladen und Notizen einzugeben, um eine Risikoakzeptanz-Entscheidung zu untermauern.

Risikoakzeptanzen haben Ablaufdaten, zu denen Sie die Auswirkungen des Befunds neu bewerten und über das weitere Vorgehen entscheiden können.

Weitere Informationen zu Risikoakzeptanzen finden Sie in unserem [Leitfaden](/triage_findings/findings_workflows/os__risk_acceptance/).

### **Außerhalb des Geltungsbereichs**

„Dieser Befund wurde von unserem Scan-Tool entdeckt, aber die Erkennung dieser Art von Schwachstelle war nicht das unmittelbare Ziel unseres Tests.“

Wenn Sie einen Befund als Außerhalb des Geltungsbereichs markieren, geben Sie damit an, dass er nicht direkt relevant für das Engagement oder den Test ist, in dem er enthalten ist.

Wenn Sie sich mit Test- und Behebungsmaßnahmen auf einen bestimmten Aspekt Ihrer Software konzentrieren, können Sie mit diesem Status kennzeichnen, dass dieser Befund nicht Teil dieser Maßnahmen ist.

### **Falsch-positiv**

„Dieser Befund wurde von unserem Scan-Tool entdeckt, aber nach Prüfung des Befunds haben wir festgestellt, dass die gemeldete Schwachstelle nicht existiert.“

Nachdem Sie einen Befund geprüft haben, stellen Sie möglicherweise fest, dass die gemeldete Schwachstelle tatsächlich nicht existiert. Der Status Falsch-positiv bleibt beim erneuten Import erhalten und verhindert, dass übereinstimmende Befunde geöffnet oder geschlossen werden, was zur Reduzierung von Störmeldungen beiträgt.  

Wenn ein anderes Scan-Tool einen ähnlichen Befund findet, wird dieser nicht als Falsch-positiv erfasst. DefectDojo kann Befunde nur innerhalb desselben Tools vergleichen, um festzustellen, ob ein Befund bereits erfasst wurde.

## Schweregrad vs. Risiko
Der Schweregrad spiegelt die technischen Auswirkungen eines Problems im Falle einer Ausnutzung wider. Das Risiko spiegelt die geschäftliche Dringlichkeit und die erforderliche Reaktion wider und berücksichtigt dabei Faktoren wie Exposition, Ausnutzbarkeit, kompensierende Kontrollen und betriebliche Auswirkungen.


## Definitionen der Risikostufen
### Dringend
Ein Befund, der ein unmittelbares und inakzeptables geschäftliches Risiko darstellt.

Hohe Wahrscheinlichkeit einer Ausnutzung oder beobachtete aktive Ausnutzung
Direkte Exposition kritischer Systeme, sensibler Daten oder Kundenumgebungen
Eingeschränkte oder keine kompensierenden Kontrollen
Untätigkeit könnte zu schwerwiegenden Geschäftsunterbrechungen, regulatorischen Auswirkungen oder Reputationsschäden führen

Erwartete Maßnahme: Sofortige Reaktion Typisches SLA: Notfallbehebung


### Handlungsbedarf
Ein Befund, der ein klares und handhabbares Risiko darstellt, das eine zeitnahe Behebung oder Minderung erfordert.

Ein realistischer Angriffspfad existiert
Das betroffene Asset ist exponiert, geschäftskritisch oder kundenseitig sichtbar
Kompensierende Kontrollen sind schwach, fehlen oder sind nicht überprüft
Eine Ausnutzung hätte messbare geschäftliche, sicherheitsrelevante oder Compliance-Auswirkungen zur Folge

Erwartete Maßnahme: Aktive Behebung oder Minderung erforderlich Typisches SLA: Kurzfristiges Behebungsfenster


### Mittleres Risiko
Ein Befund, der ein moderates geschäftliches Risiko darstellt und innerhalb eines geplanten Zeitrahmens behoben werden sollte.

Bei einer Ausnutzung könnten spürbare Auswirkungen auftreten
Eine gewisse Exposition besteht, eine Ausnutzung erfordert jedoch bestimmte Bedingungen oder Berechtigungen
Kann Produktionssysteme oder Kundendaten indirekt betreffen
Entspricht häufig Problemen mit mittlerem oder hohem Schweregrad ohne unmittelbare Ausnutzbarkeit

Erwartete Maßnahme: Priorisierte Behebung Typisches SLA: Geplantes Behebungsfenster


### Geringes Risiko
Ein Befund, der minimale geschäftliche Auswirkungen hat und keine sofortige Maßnahme erfordert.

Keine bekannte Ausnutzung in freier Wildbahn
Eingeschränkte oder keine Exposition (z. B. interne Systeme, Nicht-Produktionsumgebungen, starke kompensierende Kontrollen)
Die Behebung kann im Rahmen normaler Entwicklungs- oder Wartungszyklen erfolgen
Häufig informative Befunde oder Befunde mit niedrigem Schweregrad, kann jedoch auch Probleme mit höherem Schweregrad umfassen, die gut abgemildert sind

Erwartete Maßnahme: Verfolgen und opportunistisch adressieren Typisches SLA: Best Effort / Backlog

