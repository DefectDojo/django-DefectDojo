---
title: Konfiguration
description: Einstellungen auf Deployment-Ebene für Rules Engine 2.0
weight: 7
audience: pro
aliases:
- /automation/rules_engine_v2/configuration/
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Note: Rules Engine 2.0 is a DefectDojo Pro-only feature.</span>

Rules Engine 2.0 funktioniert von Haus aus. Die Einstellungen auf dieser Seite richten sich an Deployments, die Durchsatz, Aufbewahrung oder die Richtlinie für ausgehenden Netzwerkverkehr anpassen müssen. Alle werden auf dieselbe Weise angewendet wie jede andere DefectDojo-Einstellung (siehe [Konfiguration](/get_started/open_source/configuration/)).

Rules Engine 2.0 wird getrennt von der ursprünglichen Rules Engine konfiguriert. Die beiden Engines teilen sich kein Tuning, sodass eine `DD_RULES_ENGINE_*`-Einstellung sich nicht auf Rules Engine 2.0 auswirkt und eine `DD_RULES_V2_*`-Einstellung sich nicht auf die ursprüngliche Engine auswirkt.

```python
DD_RULES_V2_EVENT_BATCH=(int, 500),
DD_RULES_V2_CHUNK_SIZE=(int, 1000),
DD_RULES_V2_STALLED_AFTER_MINUTES=(int, 30),
DD_RULES_V2_RUN_TIME_LIMIT_MINUTES=(int, 360),
DD_RULES_V2_ALLOW_PRIVATE_EGRESS=(bool, False),
DD_RULES_V2_DELIVERY_RETENTION_DAYS=(int, 180),
DD_RULES_V2_RUN_RETENTION_DAYS=(int, 180),
DD_RULES_V2_ENVELOPE_TEXT_MAX_CHARS=(int, 8000),
DD_RULES_V2_MAX_PER_ITEM_SENDS=(int, 1000),
```

## Durchsatz

### Befunde pro Event (`DD_RULES_V2_EVENT_BATCH`)

**Standard: 500.**

Wie viele Befund-IDs ein einzelnes Event trägt. Events überschreiten eine asynchrone Grenze und werden daher klein genug gehalten, um eine günstige Nachricht zu bleiben. Ein größerer Schreibvorgang fächert sich in mehrere Events auf, von denen jedes zu einem eigenen Lauf wird.

Eine Erhöhung führt zu weniger, größeren Läufen. Eine Verringerung führt zu mehr, kleineren.

### Befunde pro Chunk (`DD_RULES_V2_CHUNK_SIZE`)

**Standard: 1000.**

Wie viele Befunde ein Lauf gleichzeitig im Speicher hält. Ein Lauf wird in Chunks verarbeitet, daher ist dies ein Speicherregler und **keine** Obergrenze für das, was eine Regel verarbeitet: Eine Regel verarbeitet immer alles, was auf ihren Geltungsbereich passt.

Ein Envelope ist rund 2,7 KB pro Befund groß, sodass der Standardwert jeweils einige Megabyte belegt. Eine Erhöhung tauscht Speicher gegen weniger Round-Trips ein. Eine Verringerung bewirkt das Gegenteil.

### Envelope-Textobergrenze (`DD_RULES_V2_ENVELOPE_TEXT_MAX_CHARS`)

**Standard: 8000. Auf 0 setzen, um zu deaktivieren.**

Wie viele Zeichen von `description`, `mitigation` und `impact` ein Element trägt.

Diese drei Felder machen den größten Teil der Envelope-Größe aus. Die Obergrenze existiert für den ungewöhnlichen Fall eines Befunds mit einer sehr großen Beschreibung, bei dem ein voller Chunk davon deutlich größer wäre, als die Chunk-Größe vermuten lässt. Sie ist großzügig genug bemessen, dass eine gewöhnliche Instanz sie nie bemerkt.

Beachten Sie, dass dies beeinflusst, was Bedingungen und Vorlagen sehen können. Eine Bedingung, die gegen das Ende einer sehr langen Beschreibung prüft, sieht keinen Text jenseits der Obergrenze.

## Lebensdauer eines Laufs

### Stillstandsfenster (`DD_RULES_V2_STALLED_AFTER_MINUTES`)

**Standard: 30.**

Wie lange ein Lauf ohne Heartbeat auskommen darf, bevor er als abgebrochen behandelt, als fehlerhaft markiert und seine regelbezogene Sperre freigegeben wird.

Ein Lauf setzt nach jedem Chunk einen Heartbeat, daher wird dies ab dem letzten Heartbeat gemessen und nicht ab dem Start. Ein langer Durchlauf, der weiterhin Fortschritte macht, wird niemals mit einem abgestürzten Worker verwechselt, wodurch das Fenster kurz bleiben kann.

### Zeitlimit für Läufe (`DD_RULES_V2_RUN_TIME_LIMIT_MINUTES`)

**Standard: 360, also sechs Stunden.**

Die längste Zeit, die ein einzelner Lauf in Anspruch nehmen darf, bevor der Worker ihn beendet.

Dies ist ein Schutz gegen eine Regel, die nie fertig würde, während sie einen Worker-Slot und die Ausführungssperre ihrer Regel blockiert. Er ist bewusst großzügig bemessen, denn ein in Chunks unterteilter Durchlauf über einen sehr großen Geltungsbereich ist genau die Art von Arbeitslast, für die diese Engine gebaut ist.

## Aufbewahrung

Zwei Jobs begrenzen die drei Tabellen, die durch diese Funktion wachsen. Beide sind standardmäßig auf **180 Tage** eingestellt, und beide akzeptieren `0`, um das Bereinigen vollständig zu deaktivieren.

Die Aufbewahrung wird im Produkt sichtbar gemacht statt implizit zu bleiben: Die API liefert sowohl das Zeitfenster als auch das Datum, an dem ein bestimmter Datensatz gelöscht wird, und die Seiten, die einen Lauf oder eine Zustellung anzeigen, nennen dies in einem Satz. Das Datum wird beim Lesen berechnet, sodass eine Änderung des Zeitfensters sofort wirksam wird und nicht nur auf neue Datensätze angewendet wird.

### `DD_RULES_V2_DELIVERY_RETENTION_DAYS`

**Standard: 180.**

Wie viele Tage eine abgeschlossene Zustellung aufbewahrt wird.

Dies ist die am schnellsten wachsende Tabelle dieser Funktion. Ein Egress-Knoten pro Befund schreibt pro Lauf bis zu einem Chunk voller Zeilen, auch im Simulate-Modus. Erhöhen Sie den Wert, wenn Sie eine längere Prüfspur für ausgehende Vorgänge benötigen, und verringern Sie ihn, wenn das Volumen ein Problem darstellt.

### `DD_RULES_V2_RUN_RETENTION_DAYS`

**Standard: 180.**

Wie viele Tage ein abgeschlossener Lauf aufbewahrt wird, zusammen mit seinen Zeilen pro Knoten und der Herkunftsnachweis (Provenance) seiner Befunde.

Die Lauf-Seite wächst schneller als die Zustellungen, da die Provenance eine Zeile pro Befund, pro Mutationsknoten und pro Lauf umfasst. Eine stündliche Regel über einen großen Geltungsbereich erzeugt davon eine Menge.

Ein Lauf, der noch Zustellungen enthält, wird aufbewahrt, bis diese bereinigt sind, sodass ein kürzeres Lauf-Zeitfenster als Zustellungs-Zeitfenster nichts verwaist zurücklässt.

## Validierung des ausgehenden Ziels

Zwei Knoteneinstellungen nehmen ein Ziel als Freitext entgegen statt aus einem konfigurierten Objekt: die **URL** bei Call a Webhook und das **To** bei Send an Email. Beide werden beim Speichern der Regel validiert.

Für Webhook-URLs:

* Nur `http` und `https` werden akzeptiert. Andere Schemata werden grundsätzlich abgelehnt.
* Die URL muss einen Host enthalten.
* Standardmäßig wird ein Host abgelehnt, der zu einer Loopback-, Link-Local-, privaten, reservierten oder Multicast-Adresse aufgelöst wird.

Bei E-Mail-Adressen wird eine leere Adresse abgelehnt, ebenso eine, die einen Zeilenumbruch enthält, was einer Header-Injection entspricht.

Der Grund für die Netzwerkprüfung ist, dass der Worker, der die Anfrage sendet, sich normalerweise innerhalb Ihres Clusters befindet und weit mehr vom internen Netzwerk erreichen kann als die Person, die die Regel verfasst. Ohne die Prüfung ist eine Freitext-URL eine Primitive für Request Forgery: Richten Sie sie auf einen Metadatendienst oder einen internen Admin-Port, und die Antwort kommt über das Zustellungsprotokoll zurück.

Dies ist Defence-in-Depth und nicht die einzige Kontrolle. Rule Edit ist ohnehin nahezu administrativ. Es lohnt sich dennoch, denn so ist der Schadensradius einer zu großzügig vergebenen Rolle nicht „jeden internen HTTP-Endpunkt lesen“, und ein Tippfehler schlägt beim Speichern mit einer klaren Meldung fehl statt beim Senden mit einem Verbindungsfehler.

### Private Adressen zulassen (`DD_RULES_V2_ALLOW_PRIVATE_EGRESS`)

**Standard: aus.**

Schaltet die Netzwerkadressprüfung aus, sodass Webhooks an Loopback-, Link-Local- und private Adressen senden dürfen. Schema- und Formvalidierung gelten weiterhin.

Aktivieren Sie dies, wenn Sie tatsächlich einen Webhook an etwas mit einer privaten Adresse senden, was bei einem selbst gehosteten Chat- oder Webhook-Empfänger normalerweise der Fall ist.

## Obergrenze für Sendungen pro Befund

### `DD_RULES_V2_MAX_PER_ITEM_SENDS`

**Standard: 1000. Auf 0 setzen, um die Obergrenze aufzuheben.**

Die maximale Anzahl an Sendungen pro Befund, die ein einzelner Egress-Knoten in einem Lauf aufzeichnet.

Ein Knoten mit aktivierter Option **One Message per Finding** erzeugt eine Zustellungszeile und eine eingereihte Aufgabe pro Befund. Da ein Lauf keine Obergrenze für Elemente hat, würde eine Regel mit sehr breitem Geltungsbereich und aktiviertem Senden pro Befund andernfalls eine unbegrenzte Anzahl von beidem bedeuten.

Über diese Obergrenze hinaus zeichnet der Knoten ein **sichtbares Überspringen** auf, das angibt, für wie viele Befunde nichts gesendet wurde. Der Lauf schlägt dadurch nicht fehl und stoppt auch nicht stillschweigend.

## Verwandte Einstellungen

Einige Rules-Engine-2.0-Knoten verwenden systemweite Integrationskonfiguration statt einer eigenen:

* **Send a Slack Message** verwendet das System-Slack-Token und greift auf den System-Slack-Kanal zurück, wenn der Knoten keinen nennt.
* **Send a Microsoft Teams Message** verwendet den Microsoft-Teams-Webhook aus den Systemeinstellungen.
* **Create a JIRA Issue** verwendet die JIRA-Konfiguration des Produkts für Zusammenfassung, Beschreibung und Priorität.
* **Raise an In-App Alert** berücksichtigt die eigene **Rules Engine Match**-Benachrichtigungseinstellung jedes Empfängers.
