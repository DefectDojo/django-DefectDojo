---
title: Services
description: Nachverfolgung von Microservices
weight: 1
---

## Was ist ein Service?

Services (kurz für Microservices) sind eine optionale Funktion innerhalb von Assets, die zusätzlichen Kontext dazu liefert, wo genau innerhalb eines Assets ein Finding seinen Ursprung hat. Sie helfen dabei, Findings einer bestimmten Komponente eines Assets zuzuordnen, anstatt sie dem gesamten Asset zuzuschreiben, und sorgen so für Klarheit und präzisere Berichte in Umgebungen mit komplexen Architekturen.

Services sind nützlich, wenn Sie die Ergebnisse eines Tests weiter segmentieren möchten oder wenn Sie erwarten, dass mehrere Instanzen desselben Findings innerhalb einer Reimport-Pipeline auftreten, die Sie nicht deduplizieren möchten. Manche Scan-Tools erstellen für jeden Dateispeicherort separate Findings. Wenn Sie diese Instanzen eines Findings lieber als eigenständige Findings beibehalten möchten, können Services eine nützliche Möglichkeit sein, diese unterschiedlichen Speicherorte zu kennzeichnen.

## Services in Pro

Services sind in der Pro-Version verfügbar, wurden jedoch weitgehend durch die Möglichkeit abgelöst, übergeordnete-untergeordnete Beziehungen zwischen Assets herzustellen. Services erzielen dasselbe Ergebnis und können weiterhin nützlich sein, wenn eine Umstrukturierung der Assets nicht praktikabel ist oder wenn eine Deduplizierung auf Scan-Ebene erforderlich ist, ohne die Asset-Hierarchie zu verändern – allerdings gehen dabei Kontextinformationen verloren. So lassen sich beispielsweise Geschäftskritikalität, Umsatz und Personal Assets, aber nicht Services zuordnen. Services sind daher in erster Linie im Kontext von OS DefectDojo nützlich.

## Wie gebe ich einen Service an?

Die Option zur Angabe eines Service finden Sie auf den Formularen Import Scan bzw. Reimport im Dropdown-Menü Optional Fields. Danach wird die Deduplizierung auf Tests beschränkt, die denselben Service-Wert aufweisen.

Wichtig: Bei Services wird zwischen Groß- und Kleinschreibung unterschieden. Wenn der Service beim ursprünglichen Import als „Service 1“ (großes S) angegeben wurde und Sie einen Scan reimportieren, bei dem alle vorherigen Probleme behoben wurden, den Service dabei aber als „service 1“ (kleines s) angeben, greift die Deduplizierung nicht für den beabsichtigten Service.

## Wie funktionieren Services?

Services funktionieren, indem Sie festlegen können, auf welche vorherigen Tests die Deduplizierungsregeln beim Reimport angewendet werden.

Wenn Sie beispielsweise einen Scan importieren und den Service als „Service 1“ festlegen und dann einen zweiten Scan reimportieren und den Service als „Service 2“ festlegen, greift zwischen diesen beiden Scans keine Deduplizierung, da sich der Service unterscheidet.

Bei allen nachfolgenden Reimports werden frühere Ergebnisse des ersten Scans nur dann dedupliziert, wenn der Service als „Service 1“ festgelegt wurde, und frühere Ergebnisse des zweiten Scans nur dann, wenn der Service als „Service 2“ festgelegt wurde. Wenn sich der Service zwischen zwei Versionen eines reimportierten Scans unterscheidet, werden sie im Grunde als unterschiedliche Findings behandelt, selbst wenn die Scans selbst identisch sind.

Wenn in diesem Beispiel beim Reimport der Service weder als Service 1 noch als Service 2 festgelegt, sondern leer gelassen wird, greift die Deduplizierung weder für den ersten noch für den zweiten Scan, und es werden nur Findings ohne Service geschlossen.

## Wie sollten Services eingesetzt werden?

In der Praxis sind Services vor allem dann nützlich, wenn:

* Ein einzelnes Asset mehrere unabhängig bereitgestellte Komponenten enthält.
* Verschiedene Teams für unterschiedliche Teile desselben Assets verantwortlich sind.
* Sicherheitstests gegen einzelne Services durchgeführt werden (zum Beispiel das Scannen einer bestimmten API oder eines bestimmten Microservice).
