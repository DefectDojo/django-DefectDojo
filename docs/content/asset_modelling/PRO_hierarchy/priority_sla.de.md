---
title: Priority, Risk und SLAs zuweisen
description: Wie DefectDojo Ihre Befunde einstuft
weight: 1
audience: pro
aliases:
- /de/en/working_with_findings/finding_priority
- /de/en/working_with_findings/priority_adjustments
---

![image](images/pro_finding_priority.png)

Effektives risikobasiertes Schwachstellenmanagement erfordert einen Ansatz, der sowohl den geschäftlichen Kontext als auch die technische Ausnutzbarkeit berücksichtigt. Mit der Priority- und Risk-Funktion von DefectDojo Pro können Benutzer Befunde automatisch in einen aussagekräftigen Kontext einordnen, sodass Schwachstellen mit hoher Auswirkung zuerst behandelt werden können.

**Priority** ist ein berechneter numerischer Rang, der auf alle Befunde in Ihrer DefectDojo-Instanz angewendet wird. Er ermöglicht es Ihnen, Schwachstellen schnell im Kontext zu verstehen, besonders in großen Organisationen, die die Sicherheitsanforderungen für viele Befunde und/oder Produkte überwachen.

**Risk** ist ein vierstufiges Bewertungssystem, das die Ausnutzbarkeit eines Befunds stärker berücksichtigt. Es ist als weniger granulare, eher „führungsebenengerechte" Version von Priority gedacht.

![image](images/pro_risk_example.png)

Priority- und Risk-Werte können zusammen mit anderen Filtern verwendet werden, um Befunde in jedem Kontext zu vergleichen, zum Beispiel:

* innerhalb eines einzelnen Produkts, Engagements oder Tests
* global über alle DefectDojo-Produkte hinweg
* zwischen einigen bestimmten Produkten

Die Anwendung von Finding Priority und Risk hilft Ihrem Team, auf die relevantesten Schwachstellen in Ihrer Organisation zu reagieren, und bietet außerdem einen Rahmen zur Unterstützung der Einhaltung gesetzlicher Standards.


Erfahren Sie mehr über Priority und Risk in den Office Hours von DefectDojo, Inc. vom Mai 2025:
<iframe width="560" height="315" src="https://www.youtube.com/embed/4SN0BWWsVm4?si=VYUzEGNeijjhoD22" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" referrerpolicy="strict-origin-when-cross-origin" allowfullscreen></iframe>


## Wie Priority & Risk berechnet werden
Der Wertebereich von Priority reicht von 0 bis 1150. Je höher die Zahl, desto dringender muss der
Befund triagiert oder behoben werden.

Ähnlich wie beim Schweregrad wird Risk von Niedrig -> Mittel -> Maßnahme erforderlich -> Dringend bewertet.  **Risk** berücksichtigt Priority-Felder und kann sich daher vom durch ein Tool gemeldeten Schweregrad unterscheiden.

![image](images/priority-overview.png)

## Priority-Felder: Produktebene

Jedes Produkt in DefectDojo verfügt über Metadaten, die die geschäftliche Kritikalität und
Risikofaktoren erfassen. Diese Metadaten werden verwendet, um Priority und Risk für die
zugehörigen Befunde zu berechnen.

Alle diese Metadatenfelder können im Formular **Edit Product** für ein bestimmtes Produkt festgelegt werden.

![image](images/priority_edit_product.png)

* **Criticality** kann auf einen der Werte Keine, Sehr niedrig, Niedrig, Mittel, Hoch oder Sehr
Hoch gesetzt werden. Criticality ist ein subjektives Feld; berücksichtigen Sie bei der Vergabe
daher, wie das Produkt im Vergleich zu anderen Produkten Ihrer Organisation einzuordnen ist.
* **User Records** ist eine numerische Schätzung der Benutzerdatensätze in einer Datenbank (oder
einem System, das auf diese Datenbank zugreifen kann).
* **Revenue** ist eine numerische Schätzung des Jahresumsatzes für das Produkt. Zur Berechnung von Priority ermittelt DefectDojo einen Prozentsatz, indem der Umsatz dieses Produkts mit der Summe aller Produkte innerhalb des Produkttyps verglichen wird.

Es ist in DefectDojo nicht möglich, eine Währung festzulegen. Stellen Sie daher sicher, dass alle Ihre Revenue-
Schätzungen dieselbe Währungseinheit verwenden. („50000" könnte 50.000 US-Dollar
oder ¥50.000 japanische Yen bedeuten - die Währungseinheit spielt keine Rolle, solange
der Umsatz für alle Ihre Produkte in derselben Währung berechnet wird).
* **External Audience** ist ein Wahr/Falsch-Wert - setzen Sie diesen auf Wahr (True), wenn auf
dieses Produkt von einem externen Publikum zugegriffen werden kann. Zum Beispiel Kunden, Benutzer
oder jeder außerhalb Ihrer Organisation.
* **Internet Accessible** ist ein Wahr/Falsch-Wert. Wenn dieses Produkt eine Verbindung zum offenen
Internet herstellen kann, sollten Sie diesen Wert auf Wahr (True) setzen.

Priority ist eine „relative" Berechnung, die dazu dient, verschiedene Produkte innerhalb
Ihrer DefectDojo-Instanz zu vergleichen. Letztlich liegt es an Ihrer Organisation zu entscheiden,
wie diese Filter gesetzt werden. Diese Werte sollten so genau wie möglich sein, aber das
primäre Ziel besteht darin, Ihre wichtigsten Produkte hervorzuheben, damit Sie Schwachstellen
gemäß den Richtlinien Ihrer Organisation priorisieren können, sodass diese Felder nicht
unbedingt perfekt gesetzt sein müssen.

## Priority-Felder: Befund-Ebene

Befunde innerhalb eines Produkts können über zusätzliche Metadaten verfügen, die die Priority- und Risk-Stufe des Befunds weiter anpassen:

* Ob der Befund einen **EPSS Score** aufweist oder nicht - dieser wird Befunden automatisch hinzugefügt und für Pro-Benutzer aktuell gehalten. Der **EPSS Score** ist das Feld, das in den Priority Score einfließt — **EPSS Percentile** wird am Befund zu Referenzzwecken erfasst, fließt aber nicht direkt in die Berechnung ein.
* Wie viele Endpunkte im Produkt von diesem Befund betroffen sind
* Ob ein Befund sich In Prüfung befindet
* Ob sich der Befund in der KEV-Datenbank (Known Exploited Vulnerabilities) befindet, die von DefectDojo regelmäßig überprüft wird
* Der vom Tool gemeldete Schweregrad eines Befunds (Info, Niedrig, Mittel, Hoch, Kritisch)

#### EPSS Score vs. EPSS Percentile

Zwei Befunde, die bei den sichtbaren Faktoren (Severity, Business Criticality, Internet Accessible, Exploit Available) identisch aussehen, können dennoch unterschiedliche Priority Scores erhalten, wenn sich ihre **EPSS Scores** unterscheiden.  Das ist zu erwarten: Der EPSS Score ist ein kontextabhängiger Eingabewert für die Berechnung.

EPSS Percentile wird am Befund zur Einordnung angezeigt, fließt aber nicht in die Berechnung des Priority Score ein.  Wenn Sie zwei Befunde vergleichen möchten, um eine Abweichung im Priority Score zu verstehen, betrachten Sie die EPSS-Score-Werte, nicht die Percentile-Werte.

Das genaue Gewicht, das EPSS Score (und die anderen Faktoren) in die Berechnung des Priority Score einbringt, wird absichtlich nicht veröffentlicht.  Wenn Sie beeinflussen möchten, wie stark sich EPSS Score in Ihrer Umgebung auf die Bewertung auswirkt, passen Sie den Regler **Exploitability** in Ihrer [Prioritization Engine](#prioritization-engines) an.


## Finding-Risk-Berechnung

![image](images/risk_table.png)

Die Risk-Spalte in einer Befundtabelle ist eine weitere Möglichkeit, Befunde schnell zu priorisieren.  Risk wird anhand der Priority-Stufe eines Befunds berechnet, berücksichtigt aber zusätzlich stärker dessen Ausnutzbarkeit.  Es ist als weniger granulare, eher „führungsebenengerechte" Version von Priority gedacht.

Die vier zuweisbaren Risk-Stufen sind:

![image](images/pro_risk_levels.png)

Die EPSS-Werte bzw. die Ausnutzbarkeit eines Befunds werden in der Risk-Berechnung wesentlich stärker gewichtet.  Dadurch kann ein Befund gleichzeitig eine hohe Priority und einen niedrigen Risk-Wert aufweisen.

Die Risk-Berechnung selbst kann derzeit nicht direkt angepasst werden. Ist jedoch [Threat Intelligence](/asset_modelling/pro_hierarchy/threat_intelligence/) aktiviert, können Sie mit dem **Actively-Exploited Risk Floor** das Ergebnis für den wichtigsten Fall steuern: Ein Befund, der nachweislich aktiv ausgenutzt wird, wird mindestens auf eine von Ihnen gewählte Risk-Stufe angehoben, statt aufgrund eines niedrigen Basis-Schweregrads in einer niedrigen Stufe zu verbleiben. Standardmäßig ist er auf **Maßnahme erforderlich** gesetzt, und jede Prioritization Engine kann ihn anheben, absenken oder zurücksetzen, um die Untergrenze zu deaktivieren. Siehe [Actively-Exploited Risk Floor](/asset_modelling/pro_hierarchy/threat_intelligence/#the-actively-exploited-risk-floor).

## Priority Insights Dashboard

Benutzer können sich mit dem Priority Insights Dashboard einen Überblick auf Führungsebene
über Priority und Risk in ihrer Umgebung verschaffen (Metrics > Priority Insights in der Seitenleiste)

![image](images/priority_dashboard.png)

Dieses Dashboard kann gefiltert werden, um bestimmte Produkte oder Zeiträume einzuschließen. Wie
andere Pro-Dashboards kann auch dieses Dashboard aus DefectDojo als PDF exportiert werden, um
schnell einen Bericht zu erstellen.

## Priority & Risk für die Einhaltung gesetzlicher Vorgaben festlegen

Dies ist eine nicht abschließende Liste gesetzlicher Standards, die spezifisch Methoden zur
Priorisierung von Schwachstellen vorschreiben:

* Die Einhaltung von [SOX (Sarbanes-Oxley Act](https://www.sarbanes-oxley-act.com/)) erfordert eine umsatzbasierte Priorisierung für
Systeme, die Finanzdaten betreffen. In DefectDojo kann der Umsatz eines Systems auf Produktebene
eingegeben werden.
* Die Einhaltung von [PCI DSS](https://www.pcisecuritystandards.org/standards/pci-dss/) erfordert eine Priorisierung anhand von Risikobewertungen und der
Kritikalität für Umgebungen mit Karteninhaberdaten. Business Criticality und External Audience können
auf Produktebene festgelegt werden, während der EPSS-Sync von DefectDojo auf Befundebene den
risikobasierten Ansatz von PCI unterstützt.
* [NIST SP 800-40](https://csrc.nist.gov/pubs/sp/800/40/r4/final) ist ein Leitfaden zur vorbeugenden Wartung, der ausdrücklich eine
Priorisierung von Schwachstellen anhand von geschäftlichen Auswirkungen, Produktkritikalität und
Internetzugänglichkeit fordert. All dies kann auf Produktebene in DefectDojo festgelegt werden.
* Die Einhaltung von Control A.12.6.1 der [ISO 27001/27002](https://www.iso.org/standard/27001) erfordert das Management technischer
Schwachstellen mit einer Priorisierung basierend auf der Risikobewertung.
* [GDPR Article 32](https://gdpr-info.eu/art-32-gdpr/) verlangt risikobasierte Sicherheitsmaßnahmen - User Records und External
Audience auf Produktebene können dabei helfen, Systeme in Ihrer Organisation zu priorisieren,
die personenbezogene Daten verarbeiten.
* Die Einhaltung von [FISMA/FedRAMP](https://help.fedramp.gov/hc/en-us) erfordert eine kontinuierliche Überwachung und risikobasierte Behebung von Schwachstellen.

Die Priority- und Risk-Berechnungen von DefectDojo Pro können angepasst werden, sodass Sie DefectDojo Pro auf Ihre internen Standards für Finding Priority und Risk zuschneiden können.

## Prioritization Engines

Ähnlich wie SLA-Konfigurationen ermöglichen Ihnen Prioritization Engines, die Regeln festzulegen, nach denen Priority und Risk berechnet werden.

![image](images/priority_default.png)

DefectDojo wird mit einer integrierten Prioritization Engine ausgeliefert, die auf alle Produkte angewendet wird.  Sie können diese Prioritization Engine jedoch bearbeiten, um die Gewichtung der **Befund**- und **Produkt**-Multiplikatoren zu ändern, wodurch angepasst wird, wie Priority und Risk für Befunde zugewiesen werden.

### Befund-Multiplikatoren

Acht kontextbezogene Faktoren beeinflussen den Priority Score eines Befunds.  Drei davon sind befundspezifisch, die anderen fünf werden anhand des Produkts zugewiesen, das den Befund enthält.

Sie können Ihre Prioritization Engine anpassen, indem Sie festlegen, wie diese Faktoren in die endgültige Berechnung einfließen.

![image](images/priority_sliders.png)

Wählen Sie einen Faktor durch Klicken auf die Schaltfläche aus; über den Regler steuern Sie, mit welchem Prozentsatz dieser Faktor angewendet wird.  Während Sie den Regler verschieben, sehen Sie, wie sich die Risk-Schwellenwerte entsprechend ändern.

#### Multiplikatoren auf Befundebene

* **Schweregrad** - der Schweregrad eines Befunds
* **Exploitability** - der KEV- und/oder EPSS-Wert eines Befunds
* **Endpunkte** - die Anzahl der einem Befund zugeordneten Endpunkte

#### Multiplikatoren auf Produktebene

* **Business Criticality** - die Business Criticality des zugehörigen Produkts (Keine, Sehr niedrig, Niedrig, Mittel, Hoch oder Sehr
Hoch)
* **User Records** - die Anzahl der User Records des zugehörigen Produkts
* **Revenue** - der Umsatz des zugehörigen Produkts, relativ zum Gesamtumsatz des Produkttyps
* **External Audience** - ob das zugehörige Produkt ein externes Publikum hat oder nicht
* **Internet Accessible** - ob das zugehörige Produkt aus dem Internet erreichbar ist oder nicht

### Risk-Schwellenwerte

Basierend auf der Abstimmung der Priority Engine empfiehlt DefectDojo automatisch Risk-Schwellenwerte.  Diese Schwellenwerte können jedoch ebenfalls angepasst und auf beliebige, von Ihnen als geeignet erachtete Werte gesetzt werden.

![image](images/risk_threshold.png)

## Neue Prioritization Engines erstellen

Sie können mehrere Prioritization Engines verwenden, die jeweils unterschiedlichen Produkten zugewiesen werden können.

![image](images/priority_engine_new.png)

Das Erstellen einer neuen Prioritization Engine öffnet das Prioritization-Engine-Formular.  Sobald dieses Formular abgeschickt wird, wird eine neue Prioritization Engine zur Tabelle hinzugefügt.

## Prioritization Engines Produkten zuweisen

Jedem Produkt kann über das Formular **Edit Product** für dieses Produkt eine aktuell verwendete Prioritization Engine zugeordnet werden.

![image](images/priority_chooseengine.png)

Beachten Sie: Wenn die Prioritization Engine eines Produkts geändert oder eine Prioritization Engine aktualisiert wird, ist die Prioritization Engine des Produkts bzw. die Prioritization Engine selbst bis zum Abschluss der Priorisierungsberechnung „Locked" (gesperrt).

Jedes Produkt in DefectDojo kann über eine eigene Service-Level-Agreement-Konfiguration (SLA) verfügen, die angibt, wie viele Tage Ihrer Organisation zur Behebung oder anderweitigen Bearbeitung eines Befunds zur Verfügung stehen.

Die SLA kann entweder auf Basis des **[Schweregrads des Befunds](/asset_modelling/os_hierarchy/product_hierarchy/#findings)** oder des **[Finding Risk](/asset_modelling/pro_hierarchy/priority_sla/)** (in DefectDojo Pro) festgelegt werden.

![image](images/sla_multiple.png)

SLAs wenden auf einen Befund einen Tage-Countdown an, der auf dem Tag basiert, an dem der Befund in DefectDojo erstellt wurde.  Wird ein Befund nicht innerhalb des Countdowns geschlossen (Closed), gilt der Befund als SLA-Verstoß.

## Arbeiten mit SLAs

Sie können SLAs nutzen, um die Behebungsrichtlinien Ihrer Organisation abzubilden.  Sie können sie außerdem verwenden, um die am längsten aktiven, kritischsten Befunde in Ihrer DefectDojo-Instanz zu priorisieren.

* Sie können Befundtabellen nach SLA-Tagen sortieren oder filtern.
* SLA-Verstöße können so konfiguriert werden, dass sie [Notifications](/admin/notifications/about_notifications/) an DefectDojo-Benutzer auslösen, die dem zugehörigen Produkt zugewiesen sind.
* In **DefectDojo Pro** wird die SLA-Performance außerdem auf den Metrics-Dashboards [Executive Insights and Remediation](/metrics_reports/pro_metrics/pro__overview/) erfasst.
* Die SLA-Einhaltung kann in **DefectDojo Pro** auch auf einem benutzerdefinierten [Dashboard](/metrics_reports/dashboards/custom-dashboards/) angezeigt werden — zum Beispiel mit einem SLA-Burndown- oder einem gefilterten Count-Widget.

### Status „Innerhalb der SLA behoben"

Wird ein Befund erfolgreich vor Ablauf der SLA-Frist behoben (Mitigated), erhält der Befund in der Spalte Mitigated Within SLA ein grünes ✅ Häkchen.

![image](images/sla_mitigated_within.png)

Wurde ein Befund behoben (Mitigated), jedoch erst nachdem die SLA verletzt wurde, erhält der Befund in der Spalte Mitigated Within SLA ein rotes ❌ X.

### SLA-Verstöße

Wenn die SLA für einen bestimmten Befund verletzt wird (der Befund wird nicht innerhalb der SLA-Frist geschlossen), wechselt das grüne ✅ Häkchen zu einem roten ❌ X.  Die SLA wird weiterhin mit einer negativen Zahl verfolgt, die angibt, um wie viele Tage die SLA überschritten wurde.

![image](images/sla_breached.png)

## SLA-Konfigurationen verwalten (Pro)

In DefectDojo Pro werden eine oder mehrere SLA-Konfigurationen unter **Configuration > Service Level Agreements** in der Seitenleiste verwaltet.  Sie können ein **New Service Level Agreement** erstellen oder über die Seite **All Service Level Agreements** mit bestehenden SLA-Konfigurationen arbeiten.

![image](images/pro_sla_risk.png)

SLA-Konfigurationen können nur von Superusern oder von einem Benutzer mit der entsprechenden [Configuration Permission](/admin/user_management/user_permission_chart/#configuration-permission-chart) bearbeitet werden.

### SLA konfigurieren

SLA-Konfigurationen enthalten die Anzahl der Tage, die jedem **Schweregrad**- oder **Risk**-Wert in DefectDojo zugewiesen sind.

![image](images/pro_new_sla.png)

Jedes Service Level Agreement kann über einen eindeutigen Namen sowie eine optionale Beschreibung verfügen.

**Restart SLA on Finding Reactivation**: Ist diese Option aktiviert, beginnt die SLA von Neuem, wenn ein Befund wieder geöffnet (Reopened) wird.  Andernfalls basiert die SLA auf dem Erstellungszeitpunkt des Befunds.

Beim Bearbeiten einer SLA können Sie wählen, ob diese SLA **Schweregrad** oder **Risk** als Maßstab für die Zuweisung von Days To Remediate verwendet.  Dies geschieht durch Auswahl der entsprechenden Option im Abschnitt **Service Level configuration Type** des Formulars.

Von hier aus können Sie die Anzahl der zulässigen Tage für jede **Schweregrad**- oder **Risk**-Stufe festlegen.  Sie können SLAs auch selektiv erzwingen; indem Sie **Enforce ___ Finding Days** deaktivieren, können Sie die SLA-Berechnung für diese Schweregrad- oder Risk-Stufen ignorieren.

## Eine SLA-Konfiguration auf ein Produkt anwenden (Pro)

Neu erstellte Produkte in DefectDojo wenden immer die **Default SLA Configuration** an, deren Werte Sie bei Bedarf anpassen können.

Wenn Sie über SLA-Konfigurationen verfügen, können Sie im Formular **Edit Product** auswählen, welche davon auf Ihr Produkt angewendet wird.

![image](images/pro_sla_product.png)

### SLA-Neuberechnung

Sobald für ein Produkt eine neue SLA ausgewählt wurde, müssen die SLAs aller zugehörigen Befunde von DefectDojo neu berechnet werden.  Während dieser Vorgang läuft, kann die SLA eines Produkts nicht geändert werden.

## Hinweise zu SLAs

* SLAs können optional neu gestartet werden, sobald ein Befund mit dem Status [Risiko akzeptiert](/triage_findings/findings_workflows/pro__risk_acceptance/) reaktiviert wird.  Dies wird beim Erstellen der Risikoakzeptanz über das Feld **Restart SLA Expired** festgelegt.
* Das erneute Importieren eines Befunds startet die SLA nicht neu - SLAs werden immer ab dem Zeitpunkt berechnet, an dem ein Befund erstmals erkannt wurde, sofern nicht **Restart SLA on Finding Reactivation** aktiviert ist.
* Der Ablauf einer Risikoakzeptanz oder die Reaktivierung eines geschlossenen (Closed) Befunds sind die einzigen Möglichkeiten, eine SLA für einen bereits erstellten Befund zurückzusetzen oder neu zu berechnen (ohne die SLA-Konfiguration des Produkts zu ändern).
