---
title: Audit-Logs
description: Zugriff auf Audit-Logs für DefectDojo-Objekte
weight: 1
audience: pro
---

**Audit-Logs** bieten eine chronologische Aufzeichnung von Aktionen, die innerhalb von DefectDojo durchgeführt wurden. Sie gewährleisten Verantwortlichkeit und Compliance, indem sie festhalten, welcher Benutzer welche Aktion wann durchgeführt hat.

Audit-Logs sind wertvoll für:
- **Sicherheitsuntersuchungen**: Ermitteln, wer sensible Aktionen durchgeführt hat.
- **Compliance**: Nachweis einer prüfbaren Historie für Standards wie SOC 2, ISO 27001 oder interne Governance-Anforderungen.
- **Fehlerbehebung**: Feststellen, wann sich eine Konfiguration oder ein Objekt geändert hat.
- **Verantwortlichkeit**: Verfolgen administrativer und benutzerbezogener Aktivitäten über die gesamte Plattform hinweg.

Kurz gesagt, bieten Audit-Logs eine zentrale Aufzeichnung wichtiger Ereignisse, die Administratoren hilft, die Aktivitätshistorie ihrer Instanz über die Historie einzelner Objekte hinaus zu verstehen. 

### Zugriff auf Audit-Logs

Audit-Logs sind über die Seitenleiste im Untermenü Configurations zugänglich. 

![image](images/auditlogs_ss2.png)

### Berechtigungen 

Der Zugriff auf Audit-Logs wird durch die globale Rolle eines Benutzers bestimmt.

Die globalen Rollen API Importer, Reader und Writer erlauben keinen Zugriff auf Audit-Logs, während die Rollen Maintainer und Owner dies tun. Superuser haben unabhängig von ihrer globalen Rolle ebenfalls Zugriff auf Audit-Logs. 

Weitere Informationen zu Berechtigungen und globalen Rollen finden Sie [hier](/admin/user_management/pro_permissions_overhaul/).

## Inhalte der Audit-Logs 

Audit-Logs erfassen eine Vielzahl von Aktionen, unter anderem:
- Interaktionen mit Objekten (z. B. das Erstellen, Aktualisieren oder Löschen von Objekten).
- Aktualisierungen der Priorität und des Risiko-Scores eines Befunds.
- Erstellung und Bearbeitung von Benutzerprofilen.
- Aktualisierungen des EPSS-Perzentils. 

Die vollständige Liste der Änderungen und Aktionen, die in Audit-Logs erfasst werden, finden Sie [hier](../pro__audit_log_index/).

## Audit-Logs-Tabelle 

Audit-Logs enthalten mehrere Spalten mit verschiedenen Daten zur Verbesserung der Nachvollziehbarkeit, darunter:
- **Timestamp**: Der Zeitpunkt, zu dem die Änderung stattfand.
- **User**: Der Benutzer, der die Aktion durchgeführt hat.
- **Action**: Welche Aktion durchgeführt wurde (z. B. create, update, delete). 
- **Model**: Welcher Aspekt geändert wurde (z. B. Asset, User, Finding, Location, Firewall, URL usw.). 
- **Object ID**: Die eindeutige ID von DefectDojo für das geänderte Objekt. 
- **Object Name**: Der Name des betroffenen Objekts. 
- **Changes**: Die von der Aktion geänderten Felder, einschließlich ihrer vorherigen und aktualisierten Werte.
- **Data**: Ein exakter Schnappschuss des Datensatzes zum Zeitpunkt der Aktion, einschließlich aller Felder, nicht nur der geänderten. 
- **Context**: Umgebende Details dazu, wie die Änderung erfolgte, wer sie vorgenommen hat, aus welchem Bereich der App sie stammt, und eine Kennzeichnung, welcher Job die Änderung durchgeführt hat (falls es sich um einen automatisierten Job handelte). 
- **URL**: Die URL, die zur Ausführung des jeweiligen Vorgangs verwendet wurde. Diese Pfade können sich auf die Vue-Benutzeroberfläche von DefectDojo oder auf die REST-API beziehen. Das URL-Feld wird bei Backend-Prozessen nicht ausgefüllt. 
- **IP Address**: Die Netzwerkadresse des Geräts, von dem die Änderung vorgenommen wurde. Dies wird bei Backend-Prozessen nicht ausgefüllt.

### Audit-Logs-Zeitleiste

Standardmäßig zeigen Audit-Logs Einträge der letzten 31 Tage an. Ältere Einträge bleiben verfügbar und können durch Anpassen des Timestamp-Filters angezeigt werden. 

![image](images/auditlogs_ss3.gif)

### Filtern von Audit-Logs

Die Audit-Logs-Tabelle enthält Filter, mit denen Sie die angezeigten Ergebnisse eingrenzen können. Wenn Sie beispielsweise nur Aktionen sehen möchten, die Assets betreffen, können Sie innerhalb der Tabelle nach Assets filtern. 

![image](images/auditlogs_ss1.png)

Die Spalten innerhalb von Audit-Logs können außerdem alphabetisch, auf- oder absteigend oder chronologisch angeordnet werden, je nach Inhalt der jeweiligen Spalte. Spalten können zudem je nach gewünschter Anordnung nach links oder rechts gezogen werden.

![image](images/auditlogs_ss4.gif)

## Objektverlauf 

**Objektverlauf** bietet eine chronologische Aufzeichnung der Änderungen an einem einzelnen DefectDojo-Objekt (z. B. Organisation, Asset, Engagement, Test, Befunde, Endpunkte und Risikoakzeptanzen). Jeder Eintrag enthält Details wie Zeitstempel, Benutzer, durchgeführte Aktion und die zugehörigen Änderungen.

Im Gegensatz zu Audit-Logs, die Ereignisse für eine gesamte Instanz erfassen, bezieht sich der Objektverlauf ausschließlich auf die Aktivität eines einzelnen Objekts, wodurch es einfacher wird, die Historie eines Objekts zu verstehen, ohne durch unzusammenhängende Systemereignisse filtern zu müssen.

Der Objektverlauf ist nützlich für:
- Die Überprüfung der Entwicklung eines Objekts im Zeitverlauf.
- Die Feststellung, wann eine Änderung vorgenommen wurde.
- Die Ermittlung, welcher Benutzer eine Änderung vorgenommen hat.
- Die Fehlerbehebung bei unerwarteten Änderungen.

### Zugriff auf den Objektverlauf 

Der Objektverlauf ist über das Zahnradmenü oben rechts in der Ansicht eines Objekts zugänglich. Nur Benutzer mit Zugriff auf das betreffende Objekt können dessen Objektverlauf einsehen. 

### Audit-Logs und Objektverlauf 

Obwohl sich die Funktion von Audit-Logs und Objektverlauf überschneidet, arbeiten sie in unterschiedlichen Geltungsbereichen. Der Objektverlauf konzentriert sich auf Änderungen an einzelnen Objekten, während Audit-Logs eine instanzweite Aufzeichnung wichtiger Ereignisse in Ihrer gesamten DefectDojo-Instanz bieten und damit einen umfassenderen Überblick über die Aktivität geben.

## Endpunkte 

### Objektverlauf-Endpunkt (nur Pro)

<span style="background-color:rgba(242, 86, 29, 0.3)">DefectDojo Pro</span>-Benutzer haben Zugriff auf einen `/history`-API-Pfad für diese Objekte, um ähnliche Daten einzusehen.  Beispiel: `/api/v2/findings/{id}/history/`.

### Audit-Log-Endpunkt (nur Pro)

<span style="background-color:rgba(242, 86, 29, 0.3)">DefectDojo Pro</span>-Benutzer haben außerdem Zugriff auf einen dedizierten `/audit_log`-Endpunkt für ihre gesamte Instanz.  Dieses Protokoll kann nur von Benutzern oder API-Tokens mit Superuser-Berechtigungen abgerufen werden.

Diese API liefert 31 Tage an Audit-Logs zurück.

* Das Senden von Standard- oder leeren Parametern liefert die letzten 31 Tage an Audit-Logs zurück.

* Der Parameter `window_month` nimmt einen Monat und ein Jahr im Format MM-YYYY entgegen und liefert die Audit-Logs für diesen Monat.
* Sie können den Parameter `window_start` setzen, um diese Logs auf ein kürzeres Zeitfenster zu beschränken, anstatt den gesamten Monat zurückzugeben.

Weitere Informationen finden Sie in der API-Dokumentation, die sich in Ihrer Instanz befindet: `your-instance.cloud.defectdojo.com/api/v2/oa3/swagger-ui/`
