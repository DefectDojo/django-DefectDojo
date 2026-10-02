---
title: Endpoint Meta Importer
description: Tags und benutzerdefinierte Felder per CSV in großen Mengen auf Endpunkte
  anwenden
weight: 4
audience: opensource
---

Mit dem **Endpoint Meta Importer** können Sie über eine CSV-Datei Tags und benutzerdefinierte Felder auf viele Endpunkte gleichzeitig anwenden. Das ist besonders für Organisationen mit umfangreichen Infrastruktur-Scans nützlich, bei denen Endpunkte flexible Metadaten für Filterung, Sortierung und Berichte benötigen.

## CSV-Format

Die CSV-Datei muss eine Spalte `hostname` enthalten (erforderlich), dazu beliebig viele weitere Spalten für die Tags oder benutzerdefinierten Felder, die Sie anwenden möchten. Jeder weitere Spaltenname wird zum Schlüssel des Tags bzw. Feldes, und der Wert in der Zeile wird zum Wert des Tags bzw. Feldes.

**Beispiel:**

```
hostname,team,public_facing
sheets.google.com,data analytics,yes
docs.google.com,language processing,yes
feedback.internal.google.com,human resources,no
```

Damit werden die folgenden Metadaten angewendet:

| Endpunkt | Tags / Benutzerdefinierte Felder |
|---|---|
| `sheets.google.com` | `team:data analytics`, `public_facing:yes` |
| `docs.google.com` | `team:language processing`, `public_facing:yes` |
| `feedback.internal.google.com` | `team:human resources`, `public_facing:no` |

## Anforderungen

- Die Spalte `hostname` ist **erforderlich**. Sie wird verwendet, um bestehende Endpunkte mit passendem Host zu finden oder neue Endpunkte zu erstellen, wenn keine Übereinstimmung gefunden wird.
- Alle anderen Spaltennamen werden als Schlüssel für Tags bzw. benutzerdefinierte Felder behandelt.
- Werte werden im Format `key:value` gespeichert.

## Den Endpoint Meta Importer verwenden

Der Endpoint Meta Importer ist in der Registerkarte **Endpoints** in der Ansicht eines Produkts verfügbar. Laden Sie dort Ihre CSV-Datei hoch, um die Metadaten in großen Mengen auf Ihre Endpunkte anzuwenden.
