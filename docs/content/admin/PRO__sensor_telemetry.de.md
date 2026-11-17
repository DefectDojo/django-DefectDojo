---
title: "Teilen von Sensor-Telemetrie"
description: "Anonymisierte Sensor-Treffer freiwillig mit DefectDojo teilen und sehen, was Ihre Sensoren beigetragen haben"
weight: 11
audience: pro
draft: false
---

> **Noch nicht verfügbar:** Das Teilen von Sensor-Telemetrie lässt sich noch nicht aktivieren, weder in DefectDojo Cloud noch auf einer Self-Hosted-Instanz, unabhängig von ihrer Konfiguration. Diese Seite beschreibt, wie die Funktion nach ihrer Veröffentlichung arbeiten wird.

Mit dem Teilen von Sensor-Telemetrie sendet eine Instanz anonymisierte **Sensor-Treffer** (Ereignisse) an den Threat-Intelligence-Dienst von DefectDojo. Ein Treffer ist eine einzelne Erkennung durch einen Sensor auf Ihren Hosts, die mit einer CVE verknüpft ist. Geteilte Treffer zeigen dem Intelligence-Dienst, welche Schwachstellen in freier Wildbahn ausgenutzt werden, und dieser Nachweis erreicht über den Threat-Intelligence-Feed jede Instanz.

Das Teilen ist eine **DefectDojo Pro**-Funktion. Es ist **standardmäßig deaktiviert**, und es wird nichts gesendet, bis ein Superuser es aktiviert.

## Was geteilt wird und was nicht

Jedes Ereignis enthält vier Werte und sonst nichts:

| Feld | Bedeutung |
| --- | --- |
| CVE | Die CVE, mit der die zutreffende Erkennungsregel gekennzeichnet ist |
| Zeit | Die Stunde, in der der Treffer festgestellt wurde, in UTC. Minuten und Sekunden werden nicht gesendet |
| Quelle | Höchstens das Land und das Netzwerk (ASN), aus dem der Treffer kam. Oft leer |
| Beitragenden-ID | Eine zufällige Kennung, die sich jeden Kalendermonat ändert |

Ein Ereignis enthält nie einen Payload oder Request-Body, einen Hostnamen, eine IP-Adresse, einen Benutzernamen, eine Befehlszeile, einen Asset-Namen, einen Unternehmensnamen, den Namen oder die Kennung der Erkennungsregel oder den Namen oder die URL Ihrer Instanz. Eine Quelle wird nur ausgefüllt, wenn Ihre Instanz dafür eingerichtet ist, sie nachzuschlagen, und nur für eine öffentliche Adresse. DefectDojo ermittelt Land und Netzwerk dann auf Ihrer Instanz und verwirft die Adresse dort, bevor etwas gesendet wird.

Regelkennungen werden bewusst weggelassen: Eine selbst geschriebene Regel kann einen beliebigen Namen tragen, auch den Ihres Unternehmens, eines Hosts oder einer Person.

Ereignisse werden mit dem Lizenzschlüssel Ihrer Instanz an DefectDojo übermittelt; daran erkennt der Intelligence-Dienst sie an. Der Schlüssel wird mit der Übermittlung gesendet, nicht innerhalb der Ereignisse.

Mit der Beitragenden-ID kann der Intelligence-Dienst zählen, wie viele verschiedene Instanzen eine CVE innerhalb eines Monats gesehen haben. Sie wird zufällig erzeugt, jeden Monat durch eine neue ersetzt, und die alte lässt sich aus der neuen nicht ableiten.

Gesendet werden nur Treffer aus der Zeit nach dem Aktivieren des Teilens und aus den letzten 24 Stunden. Das Deaktivieren des Teilens löscht jedes Ereignis, das noch auf den Versand wartete, und verwirft die Beitragenden-ID; dasselbe geschieht bei einer Änderung der Vertragsbedingung. Wird das Teilen wieder aktiviert, beginnt es mit einer neuen Beitragenden-ID.

## Bevor Sie es aktivieren können

Das Teilen ist durch eine Bedingung in Ihrem DefectDojo-Vertrag geregelt. Die Karte nennt die **Version der Vertragsbedingung**, die Sie mit dem Aktivieren des Teilens annehmen, und das Teilen lässt sich erst aktivieren, wenn diese Version auf Ihrer Instanz verfügbar ist.

Die Vertragsbedingung wird veröffentlicht, bevor das Teilen verfügbar wird.

Veröffentlicht DefectDojo später eine neue Version der Bedingung, pausiert das Teilen von selbst. Die Karte zeigt das an, die unter der alten Version wartenden Ereignisse werden gelöscht, und es wird nichts gesendet, bis ein Superuser das Teilen unter der neuen Version wieder aktiviert. Während das Teilen pausiert ist, ist das Kontrollkästchen zunächst leer, sodass die neue Version nur durch erneutes Auswählen angenommen wird. Das Teilen beginnt dann neu, mit einer neuen Beitragenden-ID.

Auf einer Air-Gap-Instanz, in der öffentlichen Demo und in der Sandbox ist das Teilen nie verfügbar.

## Teilen aktivieren oder deaktivieren

1. Melden Sie sich als Superuser an und öffnen Sie **Settings > System Settings**.
2. Scrollen Sie zur Karte **Sensor Telemetry** am Ende der Seite.
3. Lesen Sie, was geteilt wird, und die Version der Vertragsbedingung, die die Karte nennt. Wenn Ihre Instanz die Adresse der Bedingung kennt, verlinkt die Karte sie neben der Version (**Read the contract term**).
4. Wählen Sie **Share Sensor Hit Events** und dann **Submit**. Zum Beenden heben Sie die Auswahl des Kontrollkästchens auf und wählen **Submit**.

Jede Änderung wird mit dem Benutzer, der sie vorgenommen hat, im Audit-Log festgehalten.

## Was die Karte anzeigt

* **Sharing**: Off, On, Paused (die Vertragsbedingung hat sich geändert), On, Not Sending (kein Intelligence-Endpunkt oder kein Lizenzschlüssel konfiguriert; die Karte sagt, was fehlt) oder Not Available.
* **Events Shared**, **Events Waiting** und **Events Dropped**: wie viele Ereignisse übermittelt wurden, in der Warteschlange stehen oder verworfen wurden. Ein Ereignis, das sich nicht übermitteln lässt, wird bis zu einen Tag lang erneut versucht und dann verworfen.
* **Last Shared**: wann zuletzt Ereignisse übermittelt wurden.
* **Die CVE-Liste**: die von Ihren Sensoren beobachteten CVEs, bis zu den 200 zuletzt gesehenen, mit der Anzahl der Treffer, wie viele davon geteilt wurden und wann jede zuerst und zuletzt gesehen wurde. Der Titel der Karte zeigt, wie viele CVEs insgesamt beobachtet wurden. Diese Liste wird auf Ihrer Instanz geführt, unabhängig davon, ob das Teilen aktiviert ist.
* **Seen Elsewhere**: ob andere teilende Instanzen dieselbe CVE gesehen haben. Die Spalte wird nur ausgefüllt, solange das Teilen aktiviert ist und der Intelligence-Dienst antwortet, und nur für CVEs, die Ihre Instanz bereits geteilt hat: Die Anfrage nennt die CVE, daher wird nach einer CVE, die nur vor dem Aktivieren des Teilens gesehen wurde, nie gefragt. Andernfalls erklärt die Zeile unter der Tabelle, warum sie leer ist, zum Beispiel dass auf der Instanz kein Intelligence-Endpunkt oder Lizenzschlüssel konfiguriert ist.

Die Karte erscheint, sobald Ihre Instanz Sensoren hat, eine CVE beobachtet hat oder für das Teilen konfiguriert wurde.

## Konfiguration bei Self-Hosted-Instanzen

Auf einer Self-Hosted-Instanz setzt der Betreiber diese Umgebungsvariablen. Alle sind standardmäßig leer, und leer bedeutet aus.

| Variable | Zweck |
| --- | --- |
| `DD_SENSOR_TELEMETRY_CONTRACT_TERM_VERSION` | Die Version der Vertragsbedingung. Ohne sie lässt sich das Teilen nicht aktivieren |
| `DD_SENSOR_TELEMETRY_CONTRACT_TERM_URL` | Optional. Die HTTPS-Adresse, unter der die Vertragsbedingung gelesen werden kann. Die Karte verlinkt sie neben der Version |
| `DD_SENSOR_TELEMETRY_ENDPOINT` | Die HTTPS-Basis-URL des Intelligence-Dienstes. Ohne sie wird nie ein Netzwerkaufruf ausgeführt |
| `DD_THREAT_INTEL_LICENSE_KEY` | Der Lizenzschlüssel, der mit jeder Übermittlung gesendet wird. Ohne ihn wird kein Netzwerkaufruf ausgeführt |
| `DD_SENSOR_TELEMETRY_SOURCE_RESOLVER` | Optional. Der gepunktete Python-Pfad einer Funktion, die eine öffentliche Quelladresse in ein Land und eine ASN umwandelt. DefectDojo liefert keine Länder- oder ASN-Datenbank mit, daher enthalten Ereignisse ohne diese Variable keine Quelle |
