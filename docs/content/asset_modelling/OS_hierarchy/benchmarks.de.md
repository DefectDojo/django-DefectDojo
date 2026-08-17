---
title: OWASP-ASVS-Benchmarks
description: Ein Produkt anhand des OWASP Application Security Verification Standard
  benchmarken
weight: 6
audience: opensource
---

DefectDojo unterstützt das Benchmarking von Produkten anhand des [OWASP Application Security Verification Standard (ASVS)](https://owasp.org/www-project-application-security-verification-standard/), der eine Grundlage für die Prüfung technischer Sicherheitskontrollen von Webanwendungen bietet.

Mit Benchmarks können Sie messen, wie gut ein Produkt die von Ihrer Organisation festgelegten Sicherheitsanforderungen erfüllt, und einen Score zur besseren Sichtbarkeit auf der Produktseite veröffentlichen.

## Zugriff auf Benchmarks

Benchmarks sind über die Seite **Product** verfügbar. Um die Benchmarks-Ansicht zu öffnen, wählen Sie das Dropdown-Menü oben rechts auf der Produktseite und wählen Sie unten im Menü **OWASP ASVS v.3.1** aus.

## Benchmark-Stufen

OWASP ASVS definiert drei Stufen der Verifizierungsabdeckung:

- **Stufe 1** – Für jede Software. Deckt die kritischsten Sicherheitsanforderungen mit dem geringsten Prüfaufwand ab. Dies ist die Standardstufe in DefectDojo.
- **Stufe 2** – Für Anwendungen, die sensible Daten enthalten. Geeignet für die meisten Anwendungen.
- **Stufe 3** – Für die kritischsten Anwendungen, etwa solche, die hochwertige Transaktionen durchführen oder sensible medizinische, finanzielle oder sicherheitsrelevante Daten speichern.

Sie können mithilfe des Dropdown-Menüs oben rechts in der Benchmarks-Ansicht zwischen den Stufen wechseln.

## Benchmark-Score

Auf der linken Seite der Benchmarks-Ansicht wird der aktuelle Score Ihres Produkts für die ausgewählte ASVS-Stufe angezeigt:

- Der **gewünschte Score**, den Ihre Organisation als Ziel festgelegt hat
- Der **Prozentsatz der bestandenen Benchmarks** auf dem Weg zu diesem Score
- Die **Gesamtzahl der aktivierten Benchmarks** für die ausgewählte Stufe

Wenn Sie das Kontrollkästchen **Publish** aktivieren, wird der ASVS-Score direkt auf der Produktseite angezeigt.

## Verwalten von Benchmark-Einträgen

Einzelne Benchmark-Einträge können als bestanden oder nicht bestanden markiert werden, während Ihr Team die ASVS-Kontrollen durchgeht. Zusätzliche Benchmark-Einträge über den Standard-ASVS-Satz hinaus können über die **Django-Admin-Site** hinzugefügt oder aktualisiert werden.
