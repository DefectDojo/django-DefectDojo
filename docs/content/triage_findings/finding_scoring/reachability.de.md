---
title: Erreichbarkeit
description: Wie DefectDojo Pro erfasst, ob der verwundbare Code eines Befunds tatsächlich
  erreichbar ist, und wie sich dieses Ergebnis auf die Priorität auswirkt
audience: pro
weight: 3
---

Eine kritische CVE in Code, den Ihre Anwendung nie aufruft, stellt nicht dasselbe Risiko dar wie
dieselbe CVE auf einem aktiven Anfragepfad. **Erreichbarkeit** erfasst genau diesen Unterschied:
DefectDojo Pro protokolliert, ob der verwundbare Code jedes Befunds tatsächlich erreicht werden
kann, zeigt Ihnen, worauf diese Schlussfolgerung beruht, und lässt sie in die berechnete
**Priorität** des Befunds einfließen.

Erreichbarkeit ist eine **Beta**-Funktion und standardmäßig **deaktiviert**. Ein Superuser
aktiviert sie unter **Settings > Feature Flags**. Solange sie deaktiviert ist, werden keine
Einstufungen erfasst, die Priorität bleibt unverändert, und es erscheint keine
Erreichbarkeits-Oberfläche.

## Einstufungen

Jede Einstufung wird unabhängig von ihrer Quelle auf dieselben fünf Werte normalisiert:

| Einstufung | Bedeutung |
|---|---|
| **Reachable (runtime)** | Der verwundbare Code wurde bei der Ausführung beobachtet. |
| **Reachable (static)** | Es besteht ein Aufrufpfad zum verwundbaren Code von einem Einstiegspunkt der Anwendung aus. |
| **Potentially reachable** | Teilweiser Nachweis — zum Beispiel wird das verwundbare Paket verwendet, die konkrete Funktion konnte aber nicht bestätigt werden. |
| **Unreachable** | Die Analyse fand keinen Pfad zum verwundbaren Code. |
| **Unknown** | Für diesen Befund liegt noch keine Erreichbarkeitsanalyse vor. |

Die Normalisierung ist wichtig, weil sich Tools in ihrer Wortwahl unterscheiden: "no path found"
bei dem einen Scanner und "not in use" bei einem anderen bedeuten etwas anderes, und DefectDojo
erfasst beide als vergleichbare Einstufungen, statt sie zu einem einzigen Ja/Nein zu verflachen.

## Die Regeln, denen Erreichbarkeit folgt

Dieses Verhalten ist bewusst so gestaltet und ändert sich nicht von Tool zu Tool:

- **Unknown wirkt sich nie negativ auf einen Befund aus.** Die meisten Instanzen starten mit
  wenig oder keiner Erreichbarkeitsabdeckung. Ein Befund, den nichts analysiert hat, wird genauso
  bewertet, wie es bei deaktivierter Funktion der Fall wäre.
- **Unreachable senkt die Priorität. Es schließt niemals einen Befund.** Eine Einstufung als
  "unreachable" dämpft den Score, sodass tatsächlich aktive Probleme darüber einsortiert werden,
  aber der Befund bleibt offen und sichtbar. Erreichbarkeitsanalyse ist nicht perfekt, und ein
  fälschliches "unreachable", das einen aktiven kritischen Befund stillschweigend verbirgt, wäre
  der schlimmstmögliche Fehler.
- **Jede Einstufung zeigt ihre Quelle.** Keine Einstufung erscheint ohne das Tool, das sie
  erzeugt hat, dessen Konfidenz und, sofern bekannt, den analysierten Commit.
- **Einstufungen folgen der Deduplizierung.** Wenn mehrere Scanner dieselbe Schwachstelle melden
  und nur einer von ihnen Erreichbarkeit meldet, gilt die Einstufung für den gesamten
  Duplikat-Cluster, sodass Ihnen das Signal nicht verloren geht, wenn Sie ein weiteres Tool
  importieren.

## Woher Einstufungen stammen

Sie müssen keinen neuen Scanner einführen, um hiervon zu profitieren — DefectDojo liest
Erreichbarkeitsdaten aus, die Tools, die Sie möglicherweise bereits einsetzen, ohnehin erzeugen:

- **Scanner, die es in ihrer Ausgabe melden.** Mehrere unterstützte Parser führen
  Erreichbarkeitsdaten mit, entweder als strukturierte Daten oder im Berichtstext. Es ist keine
  zusätzliche Konfiguration nötig, außer den Bericht wie gewohnt zu importieren.
- **Connectors.** Ein Connector, der Erreichbarkeit unterstützt, sendet Einstufungen für die
  Produkte, die er synchronisiert, aktualisiert nach seinem üblichen Zeitplan.

Die Abdeckung ist normalerweise unvollständig, und das ist zu erwarten. Tools, die keine
Erreichbarkeit melden, belassen ihre Befunde einfach bei **Unknown**.

## Wie Erreichbarkeit die Priorität verändert

Erreichbarkeit ist ein weiterer Eingabewert für den in
[Bewertung & Priorisierung](../) beschriebenen Prioritäts-Score. Reachable-Einstufungen erhöhen
die Priorität eines Befunds, Unreachable senkt sie proportional zur Konfidenz der Quelle, und
Unknown lässt sie unverändert.

Die Stärke dieser Anpassung lässt sich, wie jeder andere Faktor, pro Priorisierungs-Engine
einstellen: Setzen Sie den Erreichbarkeits-Skalar auf `0`, um Einstufungen zu erfassen, ohne dass
sie die Scores überhaupt verändern, oder erhöhen Sie ihn, um Erreichbarkeit stärker zu gewichten.
Sie können die Auswirkung im Priorisierungs-Simulator vorab betrachten, bevor Sie sie anwenden.

Da das Aktivieren von Erreichbarkeit die Scores verschiebt, überprüfen Sie nach dem Einschalten
die Risikoschwellenwerte Ihrer Engine, damit Befunde in den erwarteten Kategorien landen.

### Erreichbarkeits-Risikoregeln

Diese Anpassung ist proportional zum Schweregrad eines Befunds, was bedeutet, dass sie zwei
Dinge, die Sie sich vielleicht wünschen, nicht abbilden kann. Ein Befund mit niedrigem
Schweregrad, dessen Code nachweislich erreichbar ist, erhält weiterhin nur einen kleinen
Aufschlag und bleibt in einem niedrigen Band; ein als unreachable gemeldeter kritischer Befund
kann trotzdem ganz oben in der Warteschlange stehen. Zwei optionale Regeln der
Priorisierungs-Engine legen stattdessen direkt ein Band fest:

- **Reachable risk floor** — das minimale Risikoband für Befunde, deren verwundbarer Code
  nachweislich erreichbar ist. Es hebt ein Band ausschließlich an.
- **Unreachable risk ceiling** — das maximale Risikoband für Befunde, die als unreachable
  gemeldet werden. Es senkt ein Band ausschließlich ab und schließt oder verbirgt niemals einen
  Befund; es begrenzt lediglich, wo er einsortiert wird.

Beide sind standardmäßig leer, sodass sich nichts ändert, bis Sie sie festlegen. Die Obergrenze
verfügt außerdem über eine **Mindestkonfidenz**: Sie greift nur, wenn die Unreachable-Einstufung
mindestens diese Konfidenz aufweist, denn genau so würde ein aktiver kritischer Befund bei einer
Einstufung mit niedriger Konfidenz begraben.

Ein Befund, dessen CVE als aktiv in freier Wildbahn ausgenutzt gemeldet wird, wird von der
Obergrenze nie begrenzt — der Nachweis einer Ausnutzung hat Vorrang vor der Behauptung, es gebe
keinen Pfad.

## Was Sie sehen

**Am Befund** — ein Erreichbarkeits-Badge sowie ein Panel **Reachability Sources**, das jede
Quelle auflistet, die dazu berichtet hat, mit Einstufung und Konfidenz jeder Quelle und der
Angabe, welche davon aktuell gilt. Liefert ein Tool einen Aufrufpfad, wird der stützende Nachweis
mit angezeigt.

**In der Befundliste** — eine Spalte und ein Filter für Erreichbarkeit, sodass Sie Ansichten wie
"Critical and reachable" erstellen und speichern können.

**Am Asset** — ein Panel **Reachability Coverage**, das die Aufteilung der Einstufungen für
dieses Asset zeigt, wie viele seiner Befunde überhaupt eine Einstufung tragen und wie viele
kritische Befunde durch Erreichbarkeit herabgestuft oder bestätigt wurden. Jede Zahl verlinkt zu
den passenden Befunden. Der Anteil, der noch bei Unknown liegt, wird zusammen mit den übrigen
Werten angezeigt: Er zeigt, zu welchem Anteil des Assets Erreichbarkeit derzeit überhaupt eine
Aussage treffen kann.
