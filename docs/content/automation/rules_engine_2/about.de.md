---
title: Über Rules Engine 2.0
description: Was Rules Engine 2.0 ist, wie man sie aktiviert, und die Konzepte, auf
  denen sie aufbaut
weight: 1
audience: pro
aliases:
- /de/automation/rules_engine_v2/about/
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Hinweis: Rules Engine 2.0 ist eine Funktion, die nur in DefectDojo Pro verfügbar ist.</span>

Rules Engine 2.0 ist ein visueller Automatisierungs-Baukasten. Statt eines Filters plus einer flachen Liste von Aktionen ist eine Regel ein **Graph**: ein Trigger-Knoten, der entscheidet, wann die Regel aufwacht, sowie eine beliebige Anzahl von Logik-, Befunde- und Egress-Knoten, die miteinander verbunden festlegen, was als Nächstes passiert.

Rules Engine 2.0 ist ausschließlich über die [Pro-UI](/get_started/about/ui_pro_vs_os/) zugänglich.

## Was sie gegenüber der Rules Engine hinzufügt

Die ursprüngliche [Rules Engine](/automation/rules_engine/about/) wendet eine geordnete Liste von Aktionen auf jeden Befund an, der auf einen Filter passt. Rules Engine 2.0 behält diese Fähigkeit bei und fügt vier Dinge hinzu:

* **Verzweigung.** Ein **Wenn / Filter**-Knoten leitet Elemente in einen true-Zweig und einen false-Zweig, sodass eine Regel kritische Befunde anders behandeln kann als den Rest, ohne in zwei Regeln aufgeteilt werden zu müssen.
* **Egress.** Eine Regel kann DefectDojo verlassen: ein JIRA-Issue oder ein Downstream-Ticket eröffnen, in Slack oder Microsoft Teams posten, eine E-Mail senden, einen Webhook aufrufen, eine In-App-Benachrichtigung auslösen oder einen Bericht erstellen.
* **Nachvollziehbarkeit.** Jede Ausführung wird Knoten für Knoten als [Ausführung](../runs/) erfasst, und jeder ausgehende Versand wird als [Zustellung](../deliveries/) erfasst, die genau angibt, was gesendet wurde, wohin es ging und wie es endete.
* **Ein Simulationsmodus.** Eine Regel kann exakt erfassen, was sie senden würde, ohne tatsächlich etwas zu senden – so testen Sie eine Regel sicher, bevor sie mit der Außenwelt in Berührung kommt.

Beide Engines laufen nebeneinander. Das Aktivieren von Rules Engine 2.0 deaktiviert oder konvertiert Ihre bestehenden Regeln nicht, und es gibt einen [Konverter](../converting_from_rules_engine/), falls Sie sie übertragen möchten.

## Rules Engine 2.0 aktivieren

Rules Engine 2.0 befindet sich in der Beta-Phase und ist standardmäßig ausgeschaltet. Ein Superuser aktiviert sie unter **Settings > Feature Flags**, sowohl auf Cloud- als auch auf On-Premise-Instanzen. Siehe [Feature Flags](/admin/feature_flags/pro__feature_flags/).

Sobald das Flag aktiviert ist, erscheint in der Seitenleiste ein Abschnitt **Rules Engine 2.0** mit drei Seiten:

| Page | What it is for |
|------|----------------|
| **Alle Regeln** | Die Regelliste. Erstellen, bearbeiten, aktivieren, ausführen und löschen Sie Regeln von hier aus. |
| **Ausführungen** | Jede Ausführung, mit ihrem Trace pro Knoten. |
| **Zustellungen** | Das Protokoll von allem, was Regeln nach außen gesendet haben. |

### Berechtigungen

Der Zugriff wird durch zwei globale Rollenberechtigungen geregelt, die mit der ursprünglichen Rules Engine geteilt werden:

* **Regel anzeigen** wird benötigt, um den Abschnitt in der Seitenleiste und alles darunter zu sehen.
* **Regel bearbeiten** wird benötigt, um zu erstellen, zu ändern, auszuführen, zu löschen, zu konvertieren, das Eigentum zu übernehmen und zu wiederholen.

Regel bearbeiten kommt einer administrativen Berechtigung nahe. Der Autor einer Regel kann auf jeden Befund zugreifen, den der Eigentümer der Regel sehen kann, und Ausgaben an externe Systeme richten. Vergeben Sie diese Berechtigung daher bewusst.

## Die Konzepte

### Regeln und Graphen

Eine Regel besteht aus einem Namen, einer Beschreibung, einem Eigentümer, einem Modus, einem Aktivierungsschalter und einem Graphen. Der Graph ist eine Menge von **Knoten** und den **Kanten** dazwischen. Er muss genau einen Trigger-Knoten enthalten und darf keinen Zyklus enthalten. Alles andere bleibt Ihnen überlassen, einschließlich der Möglichkeit, einen Knoten unverbunden zu lassen – das bedeutet lediglich, dass er ohne etwas zu bearbeiten läuft.

Neue Regeln werden immer **deaktiviert** erstellt, sodass das Aktivieren ein bewusster Vorgang ist.

### Elemente

Was sich entlang der Kanten eines Graphen bewegt, ist ein **Element**: eine JSON-Momentaufnahme eines Befunds samt seines umgebenden Kontexts.

```json
{
  "finding":      { "id": 1234, "title": "...", "severity": "High", "...": "..." },
  "test":         { "id": 12, "title": "...", "scan_type": "..." },
  "engagement":   { "id": 5,  "name": "..." },
  "product":      { "id": 3,  "name": "..." },
  "product_type": { "id": 1,  "name": "..." },
  "ctx":          { "trigger": "finding.created", "depth": 0, "source": "app" }
}
```

Bedingungen und Nachrichtenvorlagen werden anhand der Pfade in dieser Struktur geschrieben, zum Beispiel `finding.severity` oder `product.name`. Die vollständige Feldliste finden Sie unter [Regeln erstellen](../building_rules/).

### Eigentümer

Jede Regel läuft **als ihr Eigentümer**. Sie sieht genau die Befunde, die dieser Benutzer sehen kann, über dieselbe Autorisierung, die überall sonst im Produkt verwendet wird. Zwei Konsequenzen sind wissenswert:

* Wird der Zugriff des Regel-Eigentümers eingeschränkt, wird auch die Regel eingeschränkt.
* Eine Regel, deren Eigentümer-Konto gelöscht wurde, hat keinen Eigentümer mehr, sodass sie auf nichts mehr passt und nichts tut. Weisen Sie einen neuen Eigentümer zu, oder verwenden Sie **Eigentum übernehmen** aus der Regelliste, um sie wieder nutzbar zu machen.

### Modus: Simulate oder Live

Der Modus wird pro Regel festgelegt, nicht pro Knoten.

* **Simulate** (die Standardeinstellung) führt den gesamten Graphen real aus, einschließlich jeder Änderung an Befunden, aber Egress-Knoten erfassen lediglich, was sie *gesendet hätten*, und stoppen dort. Nichts verlässt DefectDojo.
* **Live** führt die Versände tatsächlich aus.

Simulierte Versände erscheinen weiterhin im Zustellungsprotokoll, markiert als `simulated`, mit ihrer vollständigen Payload. Das ist der vorgesehene Weg, eine Regel zu prüfen, bevor Sie sie freigeben.

Der Modus gilt bewusst für die gesamte Regel. Ein Graph, in dem manche Versände real sind und andere nicht, ist schwerer nachzuvollziehen als zwei getrennte Regeln.

### Ausführungen

Eine Ausführung einer Regel ist ein [Run](../runs/). Ein Run erfasst das Ereignis, das ihn ausgelöst hat, seinen Status, seinen Trace pro Knoten und etwaige Fehler. Eine Regel kann jeweils nur einen laufenden Run haben, sodass eine ausgelastete Regel in eine Warteschlange gerät, statt mit sich selbst zu konkurrieren.

### Zustellungen

Jeder ausgehende Nebeneffekt ist eine Zeile im [Zustellungs](../deliveries/)-Protokoll, geschrieben **bevor** ein Netzwerkaufruf stattfindet. Die Zeile enthält die Payload, das aufgelöste Ziel, den Status, die Anzahl der Wiederholungsversuche und alles, was das Ziel zurückgemeldet hat. Auch übersprungene Versände werden erfasst, sodass sich „die Regel hat nichts getan" und „die Regel hat nichts getan, weil der Befund bereits ein Ticket hatte" unterscheiden lassen.

### Herkunft

Jede Änderung, die eine Regel an einem Befund vornimmt, wird der Regel, dem Run und dem Knoten zugeordnet, die sie vorgenommen haben. Diese Zeitleiste ist am Befund selbst sichtbar, sodass Sie die Frage „Warum hat sich dieser Befund geändert?" beantworten können, ohne Regeldefinitionen zu lesen.

### Skalierung

Eine Regel verarbeitet alles, worauf ihr Geltungsbereich passt. Es gibt keine Obergrenze dafür, wie viele Befunde ein Run verarbeitet: Er arbeitet sie in Blöcken ab, sodass der Speicherverbrauch begrenzt bleibt statt der Abdeckung. Nur die Vorschau begrenzt, und sie sagt Ihnen, wenn sie das tut.

### Aufbewahrung

Ausführungen und Zustellungen werden beide standardmäßig 180 Tage lang aufbewahrt und danach entfernt. Das Produkt zeigt Ihnen das Zeitfenster und das Datum, an dem ein bestimmter Datensatz gelöscht wird, statt es implizit zu lassen, und beide Zeitfenster sind konfigurierbar. Siehe [Konfiguration](../configuration/#retention).

## Wie es weitergeht

* [Regeln erstellen](../building_rules/) behandelt den Editor, Trigger, Geltungsbereich, Bedingungen und Vorlagen.
* [Node-Referenz](../node_reference/) dokumentiert alle 25 Knoten.
* [Ausführungen](../runs/) behandelt Ausführung, Traces, Kaskadierung und Limits.
* [Zustellungen](../deliveries/) behandelt Kanäle, Status-Werte, Wiederholungsversuche und das erneute Senden.
* [Konvertieren aus der Rules Engine](../converting_from_rules_engine/) behandelt das Übertragen bestehender Regeln.
* [Konfiguration](../configuration/) behandelt die Einstellungen auf Deployment-Ebene.
