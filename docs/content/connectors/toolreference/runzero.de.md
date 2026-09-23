---
title: "runZero"
description: "Einrichtung des runZero Upstream-Connectors für DefectDojo"
weight: 115
audience: pro
---
Der runZero-Connector verwendet die runZero-Export-API, um das Asset-Inventar Ihrer gesamten Organisation mit DefectDojo zu synchronisieren. Er ist in erster Linie ein **Asset**-Connector: DefectDojo ermittelt jedes Asset und erstellt für jedes einen Eintrag, gruppiert in einen Produkttyp nach seiner runZero-**Site**. Optional kann er auch die Schwachstellen von runZero als Befunde importieren.

#### Voraussetzungen

Sie benötigen einen organisationsweiten **Export Token** von runZero (Account → API), der mit `XT` beginnt. Das Token ist organisationsgebunden (die Organisation ist im Token codiert), schreibgeschützt und wird als Bearer-Token gesendet — es wird nie protokolliert. Ein Community-/Starter-Tier ist verfügbar.

#### Connector-Zuordnungen

1. Geben Sie Ihre runZero-Konsolen-URL in das Feld **Location** ein, zum Beispiel `https://console.runzero.com`. Die URL muss HTTPS verwenden.
2. Geben Sie das Export Token in das Feld **Secret** ein.
3. Setzen Sie optional **Import Vulnerabilities** auf `true`, um auch runZero-Schwachstellen als Befunde zu importieren; lassen Sie es leer, um nur Assets zu synchronisieren.
4. Legen Sie optional einen **Minimum Severity**-Wert fest, um einzuschränken, welche Schwachstellenbefunde importiert werden (gilt nur, wenn Schwachstellen importiert werden).

DefectDojo ordnet jedes runZero-**Asset** einem Eintrag (VEP) zu: Der Anzeigename stammt aus dem Namen oder der Adresse des Assets, und dessen Site, Typ, Betriebssystem, Adressen und Tags werden als Attribute angehängt; die **Site** des Assets wird zu dessen Produkttyp. Assets werden mit einem vollständigen Export synchronisiert, den DefectDojo abgleicht (Hinzufügen/Entfernen). Ist **Import Vulnerabilities** aktiviert, wird jede runZero-Schwachstelle zu einem Befund an ihrem Asset — dabei werden Schweregrad, CVSS-Score, CVE, der betroffene Dienst-Endpunkt (`protocol://address:port`) und die Abhilfemaßnahme abgebildet.

Weitere Informationen finden Sie in der [runZero-API-Dokumentation](https://help.runzero.com/).
