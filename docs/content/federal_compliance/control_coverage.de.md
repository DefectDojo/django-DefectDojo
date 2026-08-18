---
title: Kontrollabdeckung
description: Welche 800-53-Kontrollen Ihre Scanner testen, und offene Schwachstellen
  pro Kontrolle
weight: 6
audience: pro
---

Die Ansicht zur Kontrollabdeckung beantwortet eine einfache Frage: Welche 800-53-Kontrollen testen meine
Scanner tatsächlich, und wo liegen die offenen Schwachstellen pro Kontrolle?

![Die Heatmap zur Kontrollabdeckung](images/07-control-coverage.png)

## Woher die Zuordnungen stammen

Viele Scanner geben bereits Kontrollverweise aus, und DefectDojo extrahiert daraus automatisch
Kontroll-Zuordnungen. Unter anderem:

* **Prowler** schreibt NIST-800-53-Kontrolllisten in die Befundverweise.
* **Tenable**-Plugins enthalten 800-53-Querverweise.
* **InSpec**- und **MITRE SAF**-Profile markieren ihre Prüfungen mit `nist`-Kennungen.

Die Extraktion stützt sich auf den importierten Katalog, sodass eine Kennung, die der Katalog nicht
erkennt, nie zu einer Zuordnung führt.

Befunde ohne eigene Kontrollverweise werden den Standard-Scan-Kontrollen im Compliance-Profil
zugeschrieben — siehe [Compliance-Profil](../compliance_profile).

### Vorhandene Befunde nachträglich zuordnen

Die Extraktion läuft, sobald Befunde eintreffen. Um Befunde zuzuordnen, die bereits vor der Aktivierung
der Funktion importiert wurden, ordnen Sie sie nachträglich zu:

```
manage.py extract_control_mappings --product <id>
```

Verwenden Sie `--all`, um statt eines Produkts alle aktiven Befunde zu scannen. Der Befehl meldet, wie
viele Zuordnungen er erstellt hat, und lässt manuelle und unterdrückte Zuordnungen unangetastet.

## Eine Zuordnung korrigieren

Von Ihnen manuell erstellte oder korrigierte Zuordnungen haben immer Vorrang vor extrahierten, und eine
gelöschte Zuordnung bleibt gelöscht — erneute Importe stellen sie nicht wieder her.

## Was die Ansicht zeigt

* Eine **Heatmap nach Kontrollfamilie**.
* Pro Kontrolle die **ihr zugeordneten offenen Befunde**.

Die Kontrollen stammen aus den mitgelieferten Katalogen: NIST 800-53 Rev 5 und NIST 800-171 Rev 2, beide
werden beim Start importiert.

**Die Abdeckung ist ein unverbindlicher Hinweis, solange sich die Funktion in der Beta-Phase befindet.**
Die Kontrollabdeckung spiegelt wider, was Ihre Scanner melden und was die mitgelieferten Kataloge
erkennen. Sie ist keine Bestätigung, dass eine Kontrolle implementiert oder wirksam ist. Prüfen Sie die
Abdeckung gegen Ihren System Security Plan, bevor Sie sich für ein Assessment darauf verlassen.

## Nachvollziehbarkeit

Kontroll-Zuordnungen unterliegen der Audit-Historie. Jede Änderung protokolliert, wer was wann getan hat.
