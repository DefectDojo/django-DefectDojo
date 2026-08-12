---
title: Hardware-Dimensionierung für selbst gehostetes DefectDojo Pro
description: Allgemeine Anleitung zur Dimensionierung von Rechenleistung, Arbeitsspeicher
  und Speicherplatz für eine selbst gehostete DefectDojo-Pro-Bereitstellung
draft: false
weight: 4
audience: pro
---

Die Dimensionierung einer DefectDojo-Bereitstellung lässt sich auf zwei Fragen reduzieren: Wie viele Daten halten Sie vor, und wie viele Personen arbeiten gleichzeitig darin. Diese Seite liefert Ausgangspunkte für beides.

Betrachten Sie das Folgende als allgemeine Orientierung, nicht als Spezifikation. Die Zahlen sind bewusst konservativ gewählt und gehen von einer Bereitstellung aus, die alltägliche Triage neben regelmäßigen Scan-Importen durchführt. Ihre eigenen Werte werden je nach Nutzung des Produkts abweichen, lesen Sie daher die Hinweise unter der Tabelle, bevor Sie irgendetwas bereitstellen.

Die Angaben erfolgen als generische vCPU- und Arbeitsspeicherwerte, damit sie für jeden Cloud-Anbieter oder On-Premise-Hardware gelten. Die Empfehlung für Anwendungsknoten geht von Kubernetes aus. Wenn Sie Docker Compose auf einem einzelnen Host betreiben, verwenden Sie dieselben Gesamtwerte.

## Dimensionierungstabelle

| Befunde | Gleichzeitige Benutzer | Datenbank | Anwendungsknoten |
| --- | --- | --- | --- |
| Bis zu 100K | Bis zu ~25 | 2–4 vCPU / 16–32 GB | 2 × (2–4 vCPU / 8–16 GB) |
| 100K–500K | ~25–50 | 4–8 vCPU / 32–64 GB | 2–3 × (4 vCPU / 16 GB) |
| 500K–1M | ~50–100 | 8 vCPU / 64–96 GB | 2–3 × (8 vCPU / 32 GB) |
| 1M–5M | ~100–250 | 8–16 vCPU / 96–128 GB | 5–6 × (8 vCPU / 32 GB) |
| 5M–10M | ~250–500 | 16–32 vCPU / 128–192 GB | 9–10 × (8 vCPU / 32 GB) |
| 500M | 500+ | 192 vCPU / 768 GB+ | 50+ × (8 vCPU / 32 GB) |

Wo Sie innerhalb eines Bereichs liegen, hängt von Ihrer Arbeitslast ab. Beginnen Sie am oberen Ende eines Bereichs, wenn etwas aus [Was Sie in eine höhere Stufe treibt](#what-pushes-you-up-a-tier) auf Sie zutrifft.

Die Zeile für 500M ist ein Referenzpunkt am äußersten Ende und keine Fortsetzung des darüber liegenden Musters, interpolieren Sie also nicht zwischen ihr und der 10M-Stufe. Eine Bereitstellung, die zwischen diesen beiden liegt, muss individuell dimensioniert werden. Sie setzt außerdem Arbeit voraus, die Hardware allein nicht für Sie erledigt — siehe [Sehr große Bereitstellungen](#very-large-deployments).

## So lesen Sie diese Zahlen

### Datenbank-Arbeitsspeicher zählt mehr als Datenbank-CPU

DefectDojo führt aggregationsintensive Abfragen über Ihre Befunde aus. Diese bleiben schnell, solange der Arbeitsdatenbestand und seine Indizes aus dem Arbeitsspeicher bedient werden, und verlangsamen sich schnell, sobald die Datenbank auf die Festplatte zugreifen muss. Wenn Sie wählen müssen, investieren Sie zuerst in Arbeitsspeicher, dann in Kerne. Die Tabelle spiegelt das wider: Der Arbeitsspeicher verdoppelt sich von Stufe zu Stufe grob, während die CPU-Anzahl deutlich langsamer steigt.

### Anwendungsknoten richten sich nach Benutzern, nicht nach Befunden

Die Angaben zu gleichzeitigen Benutzern in der Tabelle gehen davon aus, dass kleinere Datenmengen zu kleineren Teams gehören. Diese Annahme trifft oft nicht zu. Wenn Sie 200K Befunde halten, aber 100 Personen gleichzeitig in der UI arbeiten, dimensionieren Sie die Anwendungsebene für die Benutzer und belassen Sie die Datenbank dort, wo Ihre Befundanzahl sie einordnet. Beide skalieren unabhängig voneinander.

Es gibt eine Ausnahme am äußersten Ende der Tabelle. Import und Deduplizierung laufen auf der Anwendungsebene statt in der Datenbank. Sobald ein Datenbestand also groß genug ist, dass diese Arbeit dominiert, richtet sich die Knotenanzahl nach dem Ingest-Volumen statt nach der Benutzerzahl. Deshalb liegt die 500M-Zeile deutlich über dem, was ihre Benutzerzahl allein nahelegen würde.

### Die Knotenform ist flexibel

Kubernetes verteilt die Last unabhängig davon, ob Sie ihm wenige große Knoten oder mehr kleine geben, sodass die oben genannten Knotenanzahlen eine funktionierende Anordnung sind und keine feste Vorgabe. An zwei Dingen sollten Sie festhalten: Behalten Sie mindestens zwei Knoten, damit der Ausfall eines Knotens die Anwendung nicht lahmlegt, und vermeiden Sie Knoten kleiner als 2 vCPU / 8 GB, damit einzelne Pods problemlos eingeplant werden.

## Speicher

Planen Sie 20–30 GB Datenbankspeicher pro Million Befunde ein. Wo Sie innerhalb dieser Spanne liegen, hängt davon ab, wie viel Sie an jeden Befund hängen. Lange Beschreibungen und hohe Endpunktzahlen treiben Sie zum oberen Ende. Die Befund-Zeilen selbst machen davon nur einen kleinen Teil aus. Der Großteil des Platzes entfällt auf Indizes und auf die verknüpften Tabellen, die an jedem Befund hängen, sodass eine Dimensionierung allein anhand der Zeilendaten deutlich zu niedrig ausfällt.

Jede Stufe bis 10M passt in wenige hundert GB Allzweck-SSD-Speicher. Speicher ist günstig im Vergleich zu den Kosten, die entstehen, wenn er ausgeht. Planen Sie daher für den Stand ein, den Sie in einem Jahr erwarten, nicht für den heutigen. Wenn Ihr Anbieter Storage-Autoscaling bietet, aktivieren Sie es.

Die 500M-Zeile ist mit 2,5 TB dimensioniert. Diese Zahl setzt voraus, dass der Live-Datenbestand aktiv verwaltet wird, wobei ältere Befunde aus dem Hot Path archiviert werden, statt sich unbegrenzt anzusammeln. Naiv angewendet würde die oben genannte Rate pro Million eine unverwaltete 500M-Bereitstellung um ein Vielfaches höher ansetzen. Wenn Sie auf diese Größenordnung zusteuern, behandeln Sie die Archivierungsstrategie als Teil der Dimensionierung und nicht als etwas, das Sie später klären.

Speicher in dieser Größenordnung erfordert auch Aufmerksamkeit für den Durchsatz, nicht nur für die Kapazität. Sobald der Arbeitsdatenbestand nicht mehr in den Arbeitsspeicher passt, wird die standardmäßige Baseline-IOPS-Rate von Allzweck-Volumes deutlich vor der Kapazität zum limitierenden Faktor.

Der Medienspeicher ist getrennt und in der Regel deutlich kleiner. Er enthält hochgeladene Artefakte wie Screenshots und Dokumente zur Risikoakzeptanz. Dimensionieren Sie ihn daher anhand Ihrer eigenen Upload-Gewohnheiten.

## Was Sie in eine höhere Stufe treibt

Die Befundanzahl ist die zentrale Kennzahl, aber mehrere Faktoren führen dazu, dass Sie früher hochskalieren sollten, als die Anzahl allein nahelegt.

- **Importvolumen und -häufigkeit.** Große Scans, die häufig eintreffen, insbesondere mehrere gleichzeitig, erzeugen dauerhafte Last sowohl auf der Datenbank als auch auf den asynchronen Workern. CI-Pipelines, die bei jedem Build importieren, sind die übliche Ursache.
- **Deduplizierung.** Deduplizierung vergleicht eingehende Befunde mit dem, was Sie bereits vorhalten. Je mehr Befunde Sie haben und je umfassender Ihre Deduplizierungskonfiguration ist, desto mehr Arbeit verursacht jeder Import.
- **Reporting und Dashboards.** Metrik-Ansichten und die Erzeugung großer Berichte sind leselastig und belasten die Datenbank stärker als die alltägliche Triage.
- **API-Traffic.** Integrationen, die pollen oder große Ergebnismengen abrufen, erzeugen gleichzeitige Last, die in Ihrer Zahl interaktiver Benutzer nie auftaucht.
- **Aufbewahrung.** Bereitstellungen, die alles unbegrenzt aufbewahren, wachsen planmäßig in die nächste Stufe hinein. Archivieren oder Löschen alter Daten hält Sie länger auf dem aktuellen Stand.

## Sehr große Bereitstellungen

Jenseits der 10M-Stufe ist Hardware nicht mehr die vollständige Antwort. Zwei Dinge ändern sich.

Der begrenzende Faktor verschiebt sich vom Lesen zum Schreiben. Deduplizierung vergleicht jeden eingehenden Befund mit dem, was Sie bereits vorhalten, sodass die Kosten eines Imports mit der Größe des dahinterliegenden Datenbestands wachsen. Am oberen Ende der Tabelle stoßen Sie meist zuerst darauf, noch bevor Benutzer in der UI irgendetwas bemerken. Welches Importvolumen auch immer einen so großen Datenbestand aufgebaut hat, läuft in der Regel weiterhin, sodass Sie diese Kosten fortlaufend statt einmalig zahlen.

Die Arbeitsspeicherangaben setzen voraus, dass der Hot Set klein bleibt. Eine Bereitstellung arbeitet an aktuellen Befunden und lässt ältere weitgehend unangetastet, wodurch eine Datenbank weit mehr Daten halten kann, als sie Arbeitsspeicher hat, und trotzdem gut performt. Wenn sich Ihr Zugriffsmuster tatsächlich über den gesamten Datenbestand verteilt, benötigen Sie mehr Arbeitsspeicher, als die Tabelle angibt, und ab einem bestimmten Punkt reicht keine einzelne Instanz mehr aus.

Beide Punkte weisen auf dieselbe Aufgabe hin. Partitionierung und das Archivieren kalter Befunde aus dem Live-Datenbestand zählen in dieser Größenordnung mehr als ein weiteres Inkrement an vCPU, und umfangreiches Reporting gehört auf eine Read-Replica statt auf die Primärinstanz. Planen Sie das zusammen mit der Hardware ein, nicht erst danach, und sprechen Sie mit uns, bevor Sie bereitstellen.

## Im Zweifel aufrunden

Die hier genannten Zahlen sind bereits konservativ gehalten, und eine Nummer zu groß zu sein kostet weit weniger als eine Nummer zu klein. Insbesondere Arbeitsspeicherdruck bei der Datenbank degradiert nicht sanft. Die Leistung hält gut durch — bis sie es nicht mehr tut.

Anwendungskapazität später hinzuzufügen ist unkompliziert, da Sie einfach Knoten hinzufügen. Eine Datenbank neu zu dimensionieren bedeutet in der Regel Ausfallzeit — das ist also der Punkt, den es sich lohnt, von Anfang an richtig zu machen.

## Fragen oder Support

Das sind Ausgangspunkte, keine Grenzen. Wenn Ihre Bereitstellung am oberen Ende der Tabelle liegt oder Ihre Arbeitslast nicht den hier getroffenen Annahmen entspricht, sprechen Sie mit uns, bevor Sie bereitstellen. Wenden Sie sich an Ihren Account-Repräsentanten oder an [support@defectdojo.com](mailto:support@defectdojo.com).