---
title: EPSS / KEV
description: Wie DefectDojo Pro Befunde mit EPSS- und CISA-KEV-Daten anreichert, wann
  die Synchronisierung erfolgt und wie dies die Priorität beeinflusst
audience: pro
weight: 2
aliases:
- /triage_findings/epss_kev/
---

DefectDojo Pro reichert Ihre Befunde automatisch mit zwei externen Threat-Intelligence-Quellen an — **EPSS** und **CISA KEV** — damit die Priorisierung widerspiegelt, wie wahrscheinlich eine Schwachstelle ausgenutzt wird, und nicht nur ihren CVSS-Schweregrad. Beide Quellen werden Befunden anhand der **CVE** zugeordnet, aktualisieren sich nach einem **täglichen Zeitplan** und fließen direkt in die berechnete **Priorität** jedes Befunds ein.

Anreicherungsdaten werden **einmal pro Schwachstelle** gespeichert und dann auf jeden Befund angewendet, der auf sie verweist. Das bedeutet, dass eine CVE, die in zehntausend Befunden vorkommt, nur einmal nachgeschlagen wird, und Sie können ihre EPSS- und KEV-Werte direkt im **Vulnerability Explorer** einsehen — nicht nur Befund für Befund.

Bei DefectDojo Cloud wird die Anreicherung vollständig verwaltet: DefectDojo pflegt die zugrunde liegenden Threat-Intelligence-Daten und stellt sie Ihrer Instanz bereit. Es gibt nichts zu installieren, keine Feed-URLs zu konfigurieren und keinen täglichen Job zu planen — das übernimmt DefectDojo für Sie.

## Die beiden Quellen

### EPSS – Exploit Prediction Scoring System

[EPSS](https://www.first.org/epss/) ist ein datengetriebenes Modell von FIRST, das die Wahrscheinlichkeit schätzt, mit der eine bestimmte CVE in den nächsten 30 Tagen in freier Wildbahn ausgenutzt wird. DefectDojo Pro speichert zu jedem passenden Befund zwei EPSS-Werte:

| Feld | Bedeutung |
| --- | --- |
| **EPSS Score** | Wahrscheinlichkeit einer Ausnutzung in den nächsten 30 Tagen, von `0.0` bis `1.0` (z. B. `0.94` = 94 %). |
| **EPSS Percentile** | Wo diese CVE im Vergleich zu allen bewerteten CVEs steht, von `0.0` bis `1.0` (z. B. `0.99` = in den obersten 1 % der am wahrscheinlichsten ausgenutzten CVEs). |

Wenn ein einzelner Befund **mehrere CVEs** aufweist, behält DefectDojo den **höchsten EPSS-Score** unter ihnen bei und verknüpft ihn mit dem Perzentil dieser CVE. Das Perzentil gehört immer zu derselben CVE wie der Score — die beiden werden niemals aus unterschiedlichen CVEs vermischt, da ein Perzentil nur zusammen mit seinem eigenen Score aussagekräftig ist.

### KEV – CISA Known Exploited Vulnerabilities

Der [CISA-KEV-Katalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) ist die maßgebliche Liste der US-Regierung für Schwachstellen, die nachweislich in freier Wildbahn ausgenutzt wurden. Anders als EPSS (eine Vorhersage) ist KEV eine Aussage über beobachtete, reale Ausnutzung. DefectDojo Pro speichert zu jedem passenden Befund drei KEV-Werte:

| Feld | Bedeutung |
| --- | --- |
| **Known Exploited** | `True`, wenn die CVE im CISA-KEV-Katalog aufgeführt ist. |
| **Ransomware Used** | `True`, wenn CISA vermerkt, dass die CVE in Ransomware-Kampagnen eingesetzt wurde. |
| **KEV Date** | Das Datum, an dem die Schwachstelle in den KEV-Katalog aufgenommen wurde. |

Wenn ein Befund **mehrere CVEs** aufweist, wird er als **Known Exploited** markiert, sobald **eine** seiner CVEs im Katalog steht, als **Ransomware Used**, sobald eine der CVEs dafür qualifiziert, und das **KEV Date** entspricht dem frühesten Aufnahmedatum unter ihnen.

Ein KEV-Signal wird nie durch eine Geschwister-CVE mit höherem EPSS unterdrückt. Trägt ein Befund eine CVE mit hohem EPSS-Score, die *nicht* in KEV gelistet ist, und eine weitere mit niedrigem EPSS-Score, die *es ist*, übernimmt der Befund den hohen EPSS-Score **und** wird als Known Exploited markiert — jedes Feld spiegelt unabhängig den ungünstigsten Fall über alle CVEs des Befunds hinweg wider.

> **Befunde ohne CVE werden nicht angereichert.** Beide Quellen gleichen ausschließlich anhand von CVE-Kennungen ab (`CVE-YYYY-NNNNN`). Ein Befund ohne CVE — oder mit nur einer herstellerspezifischen Kennung oder einer GHSA-artigen Kennung — erhält keine EPSS- oder KEV-Daten.

## Wann die Synchronisierung erfolgt

Die Anreicherung läuft **einmal täglich, automatisch**. Jeder Durchlauf erfolgt in zwei Phasen:

1. **Aktualisierung der Schwachstellendaten.** Jede CVE, die DefectDojo kennt, wird erneut mit den aktuellen EPSS- und KEV-Daten abgeglichen, und der Datensatz je Schwachstelle wird aktualisiert.
2. **Anwenden der Änderungen auf Befunde.** Nur die Schwachstellen, deren Werte sich tatsächlich *geändert* haben, werden an die Befunde weitergegeben, die auf sie verweisen, und nur diese Befunde werden neu bewertet.

Da die zweite Phase von den tatsächlichen Änderungen abhängt, ist ein ruhiger Tag günstig: Wenn keine der beiden Quellen etwas Neues veröffentlicht hat, wird der Durchlauf abgeschlossen, ohne Ihre Befunde neu zu schreiben. Ändert sich etwas — ein EPSS-Score verschiebt sich, oder eine CVE wird in den KEV-Katalog aufgenommen —, übernimmt jeder betroffene Befund dies beim nächsten Durchlauf.

Einige Konsequenzen, die Sie kennen sollten:

- **Befunde werden meist schon beim Import angereichert.** Seit **v3.2.0** wird die EPSS/KEV-Anreicherung bereits beim Import angewendet, sodass ein neu importierter CVE-Befund normalerweise nicht bis zum nächsten täglichen Zyklus warten muss, um Werte anzuzeigen. Wie unmittelbar das geschieht, hängt davon ab, ob DefectDojo die CVE bereits nachgeschlagen hat — siehe [Was „bei der Einfuhr angereichert" bedeutet](#what-enriched-at-import-time-covers) weiter unten. Der tägliche Durchlauf läuft weiterhin zusätzlich dazu und hält diese Werte aktuell, wenn sich EPSS-Scores ändern und sich der KEV-Katalog weiterentwickelt. Wird ein Befund, den Sie als angereichert erwarten, nicht angereichert, können Sie [eine Synchronisierung manuell auslösen](#running-a-sync-on-demand).
- **Werte werden aktuell gehalten, nicht eingefroren.** Eine CVE, die in den KEV-Katalog aufgenommen wird, setzt einen bestehenden Befund beim nächsten Durchlauf auf **Known Exploited** — kein erneuter Import nötig.
- **KEV-Entfernungen werden berücksichtigt.** Sind die CVEs eines Befunds nicht mehr in KEV gelistet, löscht der Durchlauf die veralteten Werte für **Known Exploited** / **Ransomware Used** / **KEV Date**, statt sie gesetzt zu lassen.

### Was „bei der Einfuhr angereichert" bedeutet

Da Anreicherungsdaten einmal pro Schwachstelle gespeichert werden, kann ein Import nur das sofort anwenden, was DefectDojo bereits nachgeschlagen hat. Es gibt drei Fälle:

| Beim Import ist die CVE … | Wann der Befund EPSS/KEV zeigt |
| --- | --- |
| **Bereits angereichert** — DefectDojo hat diese CVE schon zuvor nachgeschlagen, für einen beliebigen Befund in einem beliebigen Produkt | **Sofort**, als Teil des Imports. Dies ist der häufigste Fall: CVEs wiederholen sich über Scans und Teams hinweg, sodass die meisten CVEs in einem typischen Import bereits bekannt sind. |
| **Neu für DefectDojo**, und der Import bringt nur eine überschaubare Anzahl neuer CVEs mit | **Kurz nach dem Import**, im Hintergrund. Es gibt noch nichts Gespeichertes zum Anwenden, daher fordert der Import ein Nachschlagen nur für diese CVEs an und wendet die Ergebnisse an, sobald sie vorliegen. |
| **Neu für DefectDojo**, und der Import bringt eine sehr große Anzahl neuer CVEs mit — ein Erstimport oder ein umfangreicher Nachimport | **Beim nächsten täglichen Durchlauf**, oder bei der nächsten [manuell ausgelösten Synchronisierung](#running-a-sync-on-demand). Tausende brandneue CVEs nachzuschlagen, während der Import noch läuft, würde die Arbeit des täglichen Durchlaufs duplizieren, daher wird dies bewusst diesem Durchlauf überlassen. |

In jedem Fall treffen die Werte ohne erneuten Import ein, und der tägliche Durchlauf bleibt die Absicherung — nichts wird dauerhaft übersprungen.

> **Connector-Synchronisierungen werden auf die gleiche Weise angereichert**, mit einer Ausnahme: Eine **sehr große Connector-Synchronisierung wird in Blöcken importiert**, und blockweise Synchronisierungen reichern nicht beim Import an. Diese Befunde erhalten ihre EPSS/KEV-Werte aus dem nächsten täglichen Durchlauf oder aus einer manuell ausgelösten Synchronisierung.

## Anzeigen von KEV/EPSS im Vulnerability Explorer

Der **Vulnerability Explorer** listet eine Zeile pro Schwachstellen-ID mit denselben fünf KEV/EPSS-Spalten, die Sie auch in der Befundtabelle finden — **EPSS Score**, **EPSS Percentile**, **Known Exploited**, **Ransomware Used** und **KEV Date**:

![Bild](images/Pro_EPSS_KEV_Explorer_Columns.png)

Diese Werte beschreiben die Schwachstelle selbst und sind daher immer gleich, unabhängig davon, wie viele Befunde auf sie verweisen. EPSS Score, EPSS Percentile, Known Exploited und KEV Date sind alle sortierbar, was dies zum schnellsten Weg macht, um die Frage zu beantworten: „Welche Schwachstellen in meiner Umgebung werden tatsächlich ausgenutzt?" — sortieren Sie absteigend nach **EPSS Score** oder nach **Known Exploited**, um die im Katalog gelisteten CVEs nach oben zu bringen.

Die **Total Findings**-Zahl jeder Zeile verlinkt zur Befundliste, gefiltert nach dieser Schwachstelle, sodass Sie mit einem Klick von „diese CVE ist KEV-gelistet" zu „hier ist alles, was sie betrifft" gelangen.

## „Keine Daten" von „nicht ausgenutzt" unterscheiden

Eine leere KEV/EPSS-Spalte und ein rotes ✗ bedeuten unterschiedliche Dinge:

- **Rotes ✗ / ein Score** — diese Schwachstelle *wurde* geprüft. Ein ✗ unter Known Exploited bedeutet, dass CISA sie nicht listet.
- **Leer** — diese Schwachstelle wurde **noch nie angereichert**, ihr Ausnutzungsstatus ist schlicht unbekannt.

Hier wurde derselbe Explorer noch nie synchronisiert, sodass jede KEV/EPSS-Spalte leer ist, statt Nullen oder ✗-Markierungen anzuzeigen:

![Bild](images/Pro_EPSS_KEV_Explorer_Unenriched.png)

Dieselbe Unterscheidung zeigt sich auch am Befund selbst. Ein Befund, dessen CVEs noch nicht angereichert wurden, weist deutlich darauf hin und verlinkt zum Explorer, wo Sie eine Synchronisierung starten können:

![Bild](images/Pro_EPSS_KEV_Not_Enriched.png)

Sobald die Anreicherung gelaufen ist, meldet dasselbe Panel, was tatsächlich gefunden wurde:

![Bild](images/Pro_EPSS_KEV_Finding_Panel.png)

Das ist wichtig, denn „wir haben noch nicht nachgesehen" und „wir haben nachgesehen, und es wird nicht ausgenutzt" wären sonst nicht zu unterscheiden — und nur eine der beiden Aussagen ist ein Grund zur Entspannung.

## Eine Synchronisierung manuell ausführen

Sie müssen nicht auf den täglichen Zyklus warten. Die Schaltfläche **Sync KEV/EPSS data** oben im Vulnerability Explorer startet sofort eine Synchronisierung:

![Bild](images/Pro_EPSS_KEV_Sync_Started.png)

Während eine Synchronisierung läuft, ist die Schaltfläche deaktiviert, und an ihrer Stelle erscheint ein Fortschrittsbalken samt einer Schätzung der verbleibenden Zeit, sobald genug Arbeit erledigt ist, um eine solche zu berechnen. Die Statuszeile darüber meldet, was gerade passiert — zunächst, dass DefectDojo prüft, welche Schwachstellen sich geändert haben, danach, wie viele Befunde bereits aktualisiert wurden. Wenn der Durchlauf abgeschlossen ist, meldet die Zeile das Ergebnis: wie viele Befunde sich geändert haben, dass bereits alles aktuell war, oder — falls keine Quelle konfiguriert ist — dass die Synchronisierung nicht ausgeführt wurde.

Es läuft immer nur eine Synchronisierung gleichzeitig. Klicken Sie die Schaltfläche, während bereits eine läuft, hängt sich der Klick einfach an den laufenden Durchlauf an, statt einen zweiten zu starten — Sie können also gefahrlos klicken, wenn Sie nicht sicher sind, ob gerade eine Synchronisierung läuft. Eine Synchronisierung lässt sich auch gefahrlos wiederholen: Hat sich seit dem letzten Durchlauf nichts geändert, wird nichts neu geschrieben.

Dies ist der schnellste Weg, um EPSS- und KEV-Änderungen einzuholen, die seit dem letzten täglichen Zyklus veröffentlicht wurden, und um alle Befunde zu vervollständigen, die noch keine Anreicherungsdaten zeigen.

## Auswirkungen auf Priorität und Risiko

EPSS und KEV sind nicht nur informative Kennzeichnungen — sie sind direkte Eingaben für die **Priorisierungs-Engine** von DefectDojo Pro. Der `priority`-Wert jedes Befunds kombiniert mehrere Komponenten (Schweregrad, Exposition, Asset-Kontext und mehr); EPSS und KEV steuern die Komponente **externer Score**, die Schwachstellen belohnt, die wahrscheinlich ausgenutzt werden — oder bekanntermaßen bereits ausgenutzt wurden.

Der externe Score leitet sich aus dem **stärkeren** der folgenden Signale ab:

- **EPSS** trägt proportional zu seinem Score bei — eine höhere Ausnutzungswahrscheinlichkeit trägt stärker bei.
- Eine **KEV-Listung** trägt eine feste Gewichtung bei: **Known Exploited** zu sein *oder* in **Ransomware** eingesetzt zu werden, bringt einen spürbaren Aufschlag, und eine CVE, die **sowohl** Known Exploited **als auch** in Ransomware eingesetzt ist, bringt den größten Aufschlag.

Das größere der beiden Signale gewinnt, sodass ein Befund die volle Gutschrift entweder für einen hohen EPSS-Score oder für eine KEV-Listung erhält, ohne dafür bestraft zu werden, dass das jeweils andere fehlt. Dieser externe Score fließt dann zusammen mit Schweregrad und Exposition in die Gesamtpriorität des Befunds ein. Der Nettoeffekt: **Ein KEV-gelisteter oder EPSS-hoher Befund steigt über einen ansonsten vergleichbaren Befund, der keines von beidem aufweist**, sodass sich die Behebung auf das konzentriert, was tatsächlich am wahrscheinlichsten angegriffen wird.

> **EPSS und KEV sind die Basis — [Threat Intelligence](/asset_modelling/pro_hierarchy/threat_intelligence/) erweitert sie.** Mit aktivierter Threat-Intelligence-Anreicherung erkennt derselbe externe Score zusätzlich weaponisierte öffentliche Exploits, Nuclei-Erkennungsvorlagen, Proof-of-Concept-Code und bestätigte aktive Ausnutzung, wobei jedes dieser Signale als *Untergrenze* auf der EPSS-Skala wirkt. Zusätzlich kommt der [Risikoboden für aktiv ausgenutzte Schwachstellen](/asset_modelling/pro_hierarchy/threat_intelligence/#the-actively-exploited-risk-floor) hinzu, der verhindert, dass ein in freier Wildbahn ausgenutzter Befund allein deshalb in einem niedrigen Risikoband landet, weil sein Basis-Schweregrad Niedrig ist. Wie EPSS und KEV heben diese Signale einen Score immer nur an.

Dies geschieht automatisch — die Priorität wird genau für die Befunde neu berechnet, die von jedem Anreicherungsdurchlauf aktualisiert wurden, sodass die Priorisierung stets mit der aktuellsten Threat Intelligence Schritt hält.

> **Hinweis:** EPSS und KEV beeinflussen den **Prioritäts**-Score. Sie ändern nicht das Feld **Severity** eines Befunds. Sie können jedoch die **SLA**-Uhr beeinflussen: Wenn in Ihrer SLA-Konfiguration **Cap by KEV due date** aktiviert ist, wird die SLA-Frist eines KEV-gelisteten Befunds auf das von CISA vorgegebene Behebungsdatum für diese CVE vorgezogen. Trägt ein Befund mehrere KEV-gelistete CVEs, gilt das früheste Fälligkeitsdatum.

## Angereicherte Befunde filtern und anzeigen

Sobald Befunde angereichert sind, stehen die EPSS- und KEV-Werte in der gesamten Pro-Oberfläche zur Verfügung:

- **Am Befund** — EPSS Score, EPSS Percentile, Known Exploited, Ransomware Used und KEV Date werden alle in der Befund-Detailansicht angezeigt.
- **Sortierung** — Befundtabellen können nach EPSS Score / Percentile sortiert werden, um die am wahrscheinlichsten ausgenutzten Befunde zuerst anzuzeigen.
- **Filterung** — die Befundliste bietet Filter für **Known Exploited** und **Ransomware Used**, sodass Sie Ansichten oder Berichte erstellen können, die sich auf bestätigt in der Praxis ausgenutzte Schwachstellen beschränken.

Ein gängiger Workflow besteht darin, nach **Known Exploited = true** zu filtern und dann nach Priorität zu sortieren, um eine „das zuerst beheben"-Warteschlange zu erstellen, die auf bestätigter Ausnutzung basiert.

## Konfiguration

Bei **DefectDojo Cloud** ist die EPSS- und KEV-Anreicherung für Sie aktiviert und wird für Sie gepflegt — es gibt keine Quellen-Schalter, Feed-URLs oder Schwellenwerte einzustellen, und die tägliche Synchronisierung wird von DefectDojo verwaltet. Die Gewichtungen, die EPSS und KEV in Priorität übersetzen, sind fest in die Priorisierungs-Engine eingebaut.

Wenn bei Befunden, bei denen Sie es erwarten, keine EPSS- oder KEV-Daten erscheinen (und diese Befunde tatsächlich CVEs tragen), prüfen Sie zunächst die Statuszeile im Vulnerability Explorer — sie meldet das Ergebnis der letzten Synchronisierung, einschließlich des Falls, dass keine Quelle konfiguriert ist. Sieht das unauffällig aus und fehlen die Daten weiterhin, wenden Sie sich an den DefectDojo-Support, der bestätigen kann, ob die tägliche Synchronisierung Daten an Ihre Instanz liefert.

> *On-Premise-Installationen* konfigurieren die Anreicherung anders — jede Quelle kann unter den Finding-Enrichment-Einstellungen des Tuners aktiviert oder deaktiviert und auf eine benutzerdefinierte Feed-URL verwiesen werden. Diese Konfiguration gilt nicht für Cloud, wo die Daten von DefectDojo bereitgestellt werden.
