---
title: CMMC-Level-2-Assessments
description: Eine Selbstbewertung gegen NIST 800-171 Rev 2 bewerten
weight: 5
audience: pro
---

Der Compliance-Tab kann eine CMMC-Level-2-Selbstbewertung anhand der Punktgewichte der DoD-Assessment-Methodik
gegen NIST 800-171 Rev 2 bewerten.

![Eine CMMC-Level-2-Bewertungsübersicht](images/05-cmmc-scorecard.png)

**Beta: Betrachten Sie den Wert als Schätzung.** Solange sich diese Funktion in der Beta-Phase befindet, sind die
mitgelieferten Punktgewichte und der daraus resultierende SPRS-Wert unverbindliche Hinweise und noch nicht
validiert. Prüfen Sie jeden Wert gegen die offizielle DoD-NIST-SP-800-171-Assessment-Methodik, bevor Sie sich
für eine Assessment-Einreichung oder einen vertraglichen Zweck darauf verlassen.

## Ergebnisse erfassen

Erfassen Sie für jede der 110 Anforderungen ein Ergebnis:

* **Erfüllt**
* **Nicht erfüllt**
* **Nicht zutreffend**
* **Geplant** (im POA&M)

![Der Workflow für Anforderungen](images/06-cmmc-requirements.png)

### Teilanrechnung

Einige Anforderungen haben eine dokumentierte Teilbedingung, die die Methodik mit einem reduzierten
Abzug statt dem vollen Gewicht bewertet. Wo eine solche existiert, können Sie sie in der Spalte **Partial
Credit** erfassen, und die Anforderung zieht dann die reduzierten Punkte ab. `3.13.11` ist das Beispiel:
eingesetzte, aber nicht FIPS-validierte Verschlüsselung zieht 3 statt 5 Punkte ab.

Anforderungen ohne dokumentierte Teilbedingung ziehen immer ihr volles Gewicht ab.

## Was das Assessment berechnet

### SPRS-Wert

110 minus dem Abzug für jede Anforderung, die nicht erfüllt oder nur geplant ist. Die Gewichte betragen 1, 3
oder 5 Punkte, sodass die Werte von 110 bis -203 reichen.

Anforderung 3.12.4 (die Anforderung zum System Security Plan) wird gemäß der Methodik als nicht zutreffend
bewertet.

### Ob ein bedingter Status möglich ist

CMMC erlaubt eine bedingte Zertifizierung bei einem Wert von mindestens **88** (80 Prozent), wenn jede offene
Lücke POA&M-fähig ist.

Die Methodik schließt bestimmte Anforderungen vollständig von POA&Ms aus. Unter den Anforderungen mit einem
Gewicht von mehr als einem Punkt kann nur **3.13.11** (FIPS-validierte Kryptografie) aufgeschoben werden.

### Die Abschlussfrist

Ein bedingtes Assessment hat **180 Tage** Zeit, um seine POA&M-Einträge abzuschließen. Läuft die Frist ab,
wechselt das Assessment auf abgelaufen.

## Status

Der Status wechselt von **in progress** zu **conditional** oder **final**. Bedingte Assessments zeigen die
verbleibenden Tage bis zum Ablauf ihrer Abschlussfrist.

Assessments unterliegen der Audit-Historie: Jede Änderung protokolliert, wer was wann geändert hat.
