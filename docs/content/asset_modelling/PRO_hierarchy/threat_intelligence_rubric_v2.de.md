---
title: "Threat Intelligence: Nachweisbasierte Bewertung (Rubric v2)"
description: "Wie geprüfte Nachweise einer Ausnutzung künftig in die Priority-Untergrenze von Threat Intelligence einfließen"
weight: 3
audience: pro
---

> **Noch nicht verfügbar.** Diese Seite beschreibt eine Funktion, die sich in Entwicklung befindet.
> Sie steht nicht auf der Seite **Feature Flags** und lässt sich noch nicht aktivieren, weder in
> DefectDojo Cloud noch auf einer Self-Hosted-Instanz. Derzeit wird jeder Befund so bewertet, wie
> unter [Threat Intelligence](../threat_intelligence/) beschrieben.

[Threat Intelligence](../threat_intelligence/#wie-sich-dies-auf-die-bewertung-auswirkt) macht aus
Exploit-Nachweisen eine **Untergrenze** auf der EPSS-Skala: Der externe Score eines Befunds liegt
mindestens auf der Untergrenze, die sein stärkster Nachweis erreicht. Die Tabelle dieser
Untergrenzen heißt **Rubric**. Rubric v2 ist ihre nächste Version. Sie behält jeden Wert der
Untergrenzen bei und ergänzt eine Art von Nachweis: **Angaben zu einer Ausnutzung, die die
Analysten von DefectDojo geprüft und bestätigt haben**.

## Was sich ändert

| Nachweis | Priority-Untergrenze (EPSS-Äquivalent) |
|---|---|
| Bestätigter Nachweis einer Ausnutzung **und** ein bestätigter, namentlich bekannter Bedrohungsakteur dahinter (neu) | 45% |
| In CISA KEV **und** in Ransomware verwendet | 30% |
| In KEV, in freier Wildbahn ausgenutzt oder **jeder bestätigte Nachweis einer Ausnutzung**, einschließlich einer bestätigten Canary-Beobachtung (neu) | 20% |
| Einsatzfähiger öffentlicher Exploit (Metasploit / Exploit-DB) | 15% |
| Nuclei-Erkennungsvorlage vorhanden | 12% |
| Nur öffentlicher Proof of Concept | 8% |
| Kein Exploit-Nachweis | keine Änderung |

Die Untergrenzen haben dieselben Werte wie heute, und der externe Score eines Befunds ist weiterhin
der höhere Wert aus seinem EPSS-abgeleiteten Wert und seiner höchsten Untergrenze. Die Rubric kann
einen Score also nur anheben.

In der Praxis bedeutet das:

- **Mehr Befunde erreichen die Untergrenze für „bekannte Ausnutzung".** Eine CVE, die nicht in
  CISA KEV steht, für die aber ein geprüfter Nachweis einer Ausnutzung vorliegt (ein
  Vorfallsbericht, ein Hersteller-Advisory, das die Ausnutzung nennt, eine Honeypot- oder
  Canary-Beobachtung), erhält dieselbe Untergrenze von 20% wie ein KEV-Eintrag.
- **Die oberste Untergrenze wird erreichbar.** Unter Rubric v1 setzte die Untergrenze von 45%
  Hersteller-Telemetrie voraus, die der Feed nicht enthält, daher hat kein Befund sie je erreicht.
  Unter Rubric v2 wird sie durch einen bestätigten Nachweis mit einem bestätigten, namentlich
  bekannten Bedrohungsakteur dahinter erreicht, und durch nichts Geringeres.
- **Nichts wird schwächer.** Ohne geprüften Nachweis wird eine Schwachstelle genau so bewertet wie
  heute. Ein KEV-Eintrag mit Ransomware-Nutzung bleibt bei 30%: Das Ransomware-Kennzeichen von CISA
  nennt keinen Akteur.

Was eine Untergrenze **nicht** anhebt: eine ungeprüfte oder abgelehnte Angabe, ein Proof of Concept
für sich allein und das Kennzeichen „Exploit verfügbar" eines Scanners oder Herstellers (diese
werden wie heute angezeigt und zählen nicht als Nachweis).

## Bevor die Funktion aktiviert wird

Der Wechsel einer Instanz zu Rubric v2 kann die Priorität von Befunden anheben. Deshalb misst
DefectDojo den Wechsel, bevor er erfolgt: für jede Instanz, wie viele Befunde von welcher
Untergrenze zu welcher wechseln würden, und für jeden Wechsel die Schwachstellen, hinter denen die
meisten Befunde stehen. Ihre aktuellen Prioritäten bleiben bei Rubric v1, bis Rubric v2
veröffentlicht ist.
