---
title: Self-Hosting von DefectDojo Pro
date: 2021-02-02 20:46:29+01:00
weight: 5
audience: pro
---

DefectDojo Pro kann vollständig in Ihrer eigenen Umgebung selbst gehostet werden, sodass Sie die Kontrolle über Ihre Infrastruktur, Ihre Daten und Ihre Sicherheitslage behalten. Es eignet sich für Organisationen mit Compliance-, Datenresidenz- oder internen Sicherheitsanforderungen, die ein gehostetes Deployment ausschließen, und bietet dieselben Funktionen wie das Cloud-gehostete Produkt.

Diese Seite behandelt die verfügbaren Deployment-Modelle, was Sie vor dem Start benötigen und wie sich der Rest dieses Abschnitts einordnet.

## Zwei Deployment-Modelle

**Docker Compose auf einem einzelnen Host** ist die einfachere der beiden Varianten. Die Anwendung, die asynchronen Worker und der Cache laufen alle auf einer Maschine, verwaltet über ein von uns bereitgestelltes Kommandozeilen-Tool. Da bei diesem Aufbau nichts horizontal skaliert, muss der Host für Ihre Spitzenlast dimensioniert werden statt für den Durchschnitt, und bei den meisten Deployments ist die Spitzenlast ein großer Scan-Import, der eintrifft, während Anwender gleichzeitig in der UI arbeiten.

**Kubernetes, mit unserem Helm-Chart,** führt dieselben Komponenten als separate Workloads aus. Damit können Sie für den Normalbetrieb dimensionieren und bei steigender Last Replikate hinzufügen, und Sie können gezielt den Teil skalieren, der tatsächlich ausgelastet ist, statt die gesamte Maschine.

Beide Modelle verwenden PostgreSQL. Für den Produktivbetrieb empfehlen wir eine externe verwaltete Datenbank, wovon das Helm-Chart standardmäßig ausgeht. Das Compose-Tooling kann PostgreSQL auch in einem Container neben der Anwendung ausführen, was für die Evaluierung praktisch ist, aber nicht das ist, was Sie für Produktivdaten wollen.

Wenn Sie bereits Kubernetes betreiben, nutzen Sie es. Ein einzelner Host funktioniert einwandfrei, und viele Deployments laufen so, aber Sie kaufen damit Reserven ein, die Sie nicht anderweitig nutzen können. Wenn Sie kein Kubernetes betreiben und auch keines betreiben möchten, ist Compose eine legitime Wahl und kein Kompromiss.

## Bevor Sie beginnen

Dimensionieren Sie das Deployment zuerst. Beide Modelle hängen davon ab, ungefähr zu wissen, wie viele Befunde Sie erwarten und wie viele Personen gleichzeitig im Produkt arbeiten werden, und diese beiden Zahlen bestimmen unterschiedliche Teile des Deployments. Die Hinweise zur Hardware-Dimensionierung in diesem Abschnitt decken beides ab.

Sie benötigen eine Lizenzdatei und das Deployment-Tooling für das gewählte Modell. DefectDojo stellt beides zu Beginn Ihres Abonnements bereit. Falls Sie diese nicht haben oder sie neu ausgestellt werden müssen, wenden Sie sich an Ihren Kundenbetreuer oder an [support@defectdojo.com](mailto:support@defectdojo.com).

Außerdem benötigen Sie eine Umgebung zum Betrieb, eine für die Anwendung erreichbare PostgreSQL-Datenbank und einen Hostnamen, der auf das Deployment auflöst. Die einzelnen Installationsseiten behandeln die Details für jedes Modell.

## Was es sonst noch in diesem Abschnitt gibt

Die Seiten neben dieser behandeln den Rest des Lebenszyklus. Es gibt Hinweise zur Hardware-Dimensionierung, Anleitungen zum Umzug einer bestehenden Open-Source-Instanz in ein selbst gehostetes Pro-Deployment sowie ein Verfahren für die Installation, wenn der Ziel-Host keinen Zugang zum Internet hat.

Für bereits laufende Deployments gibt es Seiten zum Upgrade, zur Datensicherung, zur Anhebung der Limits, die große Scan-Uploads sonst ablehnen, sowie zur Erweiterung des Speicherplatzes für hochgeladene Dateien, wenn einem Host der Platz ausgeht. Nutzen Sie die Abschnittsnavigation, um sie zu durchsuchen.

## Fragen

Wenn Sie die beiden Modelle für Ihre Umgebung abwägen oder Ihre Gegebenheiten nicht den hier getroffenen Annahmen entsprechen, sprechen wir lieber vorab mit Ihnen darüber als danach.

Bestehende Kunden sollten sich an ihren Kundenbetreuer oder an [support@defectdojo.com](mailto:support@defectdojo.com) wenden. Wenn Sie DefectDojo Pro evaluieren und das Self-Hosting besprechen möchten, erreichen Sie uns unter [hello@defectdojo.com](mailto:hello@defectdojo.com).
