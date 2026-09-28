---
title: Komponenten
description: Nachverfolgung von Drittanbieter-Bibliotheken und Softwarekomponenten
  in DefectDojo Pro
audience: pro
weight: 1
---

In DefectDojo repräsentieren Komponenten Drittanbieter-Bibliotheken, Softwarekomponenten und Module, die potenziell Schwachstellen aufweisen.


## Komponentenansichten

DefectDojo Pro enthält eine eigene Tabellenansicht für Komponenten, die Sie in der Seitenleiste finden. Diese Ansicht zeigt für jede Komponente die aktiven Findings, die doppelten Findings und die Gesamtzahl der Findings. Diese Zahlen umfassen alle Assets der DefectDojo-Instanz.

Die Komponenten eines einzelnen Assets sehen Sie in der Asset-Ansicht.

## Die Komponententabelle

Die Komponententabelle zeigt die folgenden Spalten:

* **Komponente** — der Name der Komponente, befüllt aus den Scan-Daten.
* **Version** — die Version der Komponente, befüllt aus den Scan-Daten.
* **Aktive Findings** — Anzahl der aktiven Findings, die dieser Komponente zugeordnet sind.
* **Doppelte Findings** — Anzahl der doppelten Findings, die dieser Komponente zugeordnet sind.
* **Findings insgesamt** — Gesamtzahl aller Findings, die dieser Komponente zugeordnet sind.

Wenn Sie auf den Komponentennamen oder auf die Werte für Aktive Findings, Doppelte Findings oder Findings insgesamt klicken, öffnet sich eine nach dem jeweiligen Feld gefilterte Liste von Findings.

In der Tabelle wird eine Komponente **None** angezeigt, die alle Findings enthält, die keiner Komponente zugeordnet sind.

Importierte Komponenten bleiben auch dann in der Tabelle, wenn alle zugehörigen Findings behoben wurden. Wenn Findings für eine bestimmte Komponente importiert werden, wird die Komponententabelle aktualisiert, um die neuen Finding-Summen korrekt widerzuspiegeln.


### Beispiel

Eine Komponente, die aus einem Dependency-Check-Scan einer Anwendung mit einer anfälligen `lodash`-Abhängigkeit importiert wurde, könnte in der Tabelle wie folgt aussehen:

| Komponente | Version | Aktive Findings | Doppelte Findings | Findings insgesamt |
| --- | --- | --- | --- | --- |
| npm:lodash | 4.17.15 | 3 | 1 | 5 |

Ein Klick auf `npm:lodash` öffnet die Liste aller Findings, die auf diese Komponente verweisen. Ein Klick auf `3` öffnet dieselbe Liste, gefiltert auf nur aktive Findings.

## Komponenten hinzufügen

Komponenten können aus einem Scan-Import geparst oder durch manuelles Bearbeiten eines Findings hinzugefügt werden. Sobald ein Komponentenname mit einem Finding verknüpft ist, wird der Komponententabelle automatisch ein entsprechender Eintrag hinzugefügt. Wenn die Komponente bereits mit anderen Findings in DefectDojo verknüpft ist, werden die Summen für Aktive Findings, Doppelte Findings und Findings insgesamt entsprechend aktualisiert.

### Wie Komponenten aus Scan-Daten geparst werden

Beim Importieren eines Scans befüllen die Parser bei jedem Finding die Felder **Komponentenname** und **Komponentenversion** anhand der Scan-Ausgabe. Die Komponententabelle wird anschließend aus diesen Werten erstellt. Der Detailgrad und die Namenskonvention hängen vom Tool ab, mit dem der Scan erstellt wurde:

* **Software Composition Analysis (SCA)-Tools** melden in der Regel einen Paketnamen und eine genaue Version. OWASP Dependency-Check leitet die Komponente beispielsweise aus der [Package URL](https://github.com/package-url/purl-spec) in ihrer ID ab — aus einer purl `pkg:npm/lodash@4.17.15` wird `Component Name: npm:lodash`, `Component Version: 4.17.15`.
* **Container- und Betriebssystem-Paket-Scanner** wie Trivy, Anchore Grype und Anchore Engine melden das betroffene Betriebssystem- oder Sprachpaket — zum Beispiel `Component Name: curl`, `Component Version: 7.68.0`.
* **Sprachspezifische Abhängigkeits-Scanner** wie npm Audit, pip-audit, bundler-audit, Retire.js, Govulncheck und OSV-Scanner befüllen das betreffende Paket und die Version anhand der jeweiligen Ökosystem-Manifeste.

Scanner, die sich auf Konfiguration, Infrastruktur oder Quellcode-Logik konzentrieren (wie SAST- und IaC-Tools), befüllen die Komponentenfelder in der Regel nicht; ihre Findings erscheinen unter der Komponente **None**.

Um eine Komponente manuell hinzuzufügen oder zu ändern, bearbeiten Sie das Finding und setzen Sie die Felder **Komponentenname** und **Komponentenversion** direkt. Die Komponententabelle wird aktualisiert, sobald das Finding gespeichert wird.

## Komponenten aktualisieren

Um einen Komponentennamen oder eine Version zu aktualisieren, müssen bei allen mit der Komponente verknüpften Findings die Felder Komponentenname oder Komponentenversion aktualisiert werden.

## Komponenten entfernen

Um eine Komponente aus der Komponententabelle zu entfernen, müssen bei allen mit der Komponente verknüpften Findings die Felder Komponentenname und Komponentenversion entfernt werden. Komponenten werden außerdem entfernt, wenn alle zugehörigen Findings gelöscht werden.

Wenn alle Findings einer Komponente behoben sind, bleibt die Komponente in der Tabelle, aber ihr Wert für Aktive Findings wird auf 0 gesetzt.
