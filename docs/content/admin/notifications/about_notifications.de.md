---
title: Über Benachrichtigungen & 🔔 Warnungen
description: Erfahren Sie mehr über Benachrichtigungen und In-App-Warnungen
aliases:
- /en/customize_dojo/notifications/about_notifications
---

DefectDojo hält Sie auf verschiedene Weise auf dem Laufenden. Benachrichtigungen können für bevorstehende Engagements, [Benutzererwähnungen](/triage_findings/findings_workflows/intro_to_findings/#notes-and-mentions), ablaufende SLAs und andere Ereignisse in der Software gesendet werden.

Dieser Artikel bietet einen Überblick über Benachrichtigungen sowohl auf systemweiter als auch auf persönlicher Ebene.

## Benachrichtigungstypen

DefectDojo behandelt Benachrichtigungen auf zwei unterschiedliche Arten:

* **Systemweite Benachrichtigungen** werden an alle Benutzer gesendet.
* **Persönliche Benachrichtigungen werden von einzelnen Benutzern festgelegt und zusätzlich zu allen systemweiten Benachrichtigungen empfangen.**

In beiden Fällen gelten die Regeln der [rollenbasierten Zugriffskontrolle](../../user_management/about_perms_and_roles/), sodass Benutzer keine Aktivitätsbenachrichtigungen für Produkte oder Produkttypen (oder deren zugehörige Objekte) erhalten, auf die sie keinen Zugriff haben.

## Zustellmethoden für Benachrichtigungen

Es gibt vier Zustellmethoden für DefectDojo-Benachrichtigungen:

* DefectDojo kann **🔔 Warnungen** anzeigen, die als Liste in der DefectDojo-Oberfläche gespeichert werden
* DefectDojo kann Benachrichtigungen an eine **E-Mail**-Adresse senden
* DefectDojo kann Benachrichtigungen an **Slack** senden, entweder in einen gemeinsamen oder einen individuellen Kanal
* DefectDojo kann Benachrichtigungen außerdem an **Microsoft Teams** in einen gemeinsamen Kanal senden

Benachrichtigungen können gleichzeitig an mehrere Ziele gesendet werden.

Um Slack- und Teams-Benachrichtigungen zu empfangen, benötigen Sie eine funktionierende Integration. Weitere Informationen zur Einrichtung dieser Integration finden Sie in unserem [Leitfaden](../email_slack_teams).

## In-App-Warnungen

Das Warnungssystem von DefectDojo hält Sie über alle Produkt- oder Systemaktivitäten auf dem Laufenden.

### Die Warnungsliste

Die Warnungsliste ist immer in der oberen rechten Ecke von DefectDojo sichtbar und enthält eine kompakte Liste von Benachrichtigungen. Ein Klick auf eine Warnung führt Sie direkt zur entsprechenden Seite in DefectDojo.

Sie können Ihre Warnungsliste öffnen, indem Sie auf das **🔔▼-Symbol** in der oberen rechten Ecke klicken:

![image](images/About_In-App_Alerts.png)

Um alle Ihre Benachrichtigungen mit zusätzlichen Details anzuzeigen, klicken Sie auf die Schaltfläche **Alle Warnungen anzeigen \>**, wodurch die **Warnungsseite** geöffnet wird.

Sie können in der Warnungsliste auch **Alle Warnungen löschen \>**.

### Die Warnungsseite

Die Warnungsseite speichert alle Ihre Warnungen in DefectDojo mit zusätzlichen Details. Auf dieser Seite können Sie die Beschreibungen der einzelnen Warnungen in DefectDojo lesen und sie aus der Warnungswarteschlange entfernen, sobald Sie sie nicht mehr benötigen.

![image](images/About_In-App_Alerts_2.png)

Um eine oder mehrere Warnungen von der Warnungsseite zu entfernen, aktivieren Sie das leere Kästchen daneben und klicken Sie anschließend auf die Schaltfläche **Auswahl entfernen** in der unteren rechten Ecke der Seite.

### Hinweise zu Warnungen

* Das Lesen einer Warnung oder das Öffnen der Warnungsseite entfernt keine Warnungen aus der Zählung neben dem Glockensymbol. So können Sie problemlos auf frühere Warnungen zugreifen, um sie als Erinnerungen oder persönliches Aktivitätsprotokoll zu nutzen.
* Die Verwendung der Funktion **Alle Warnungen löschen \>** im Warnungsmenü löscht auch die **Warnungsseite** vollständig, verwenden Sie diese Funktion daher mit Vorsicht.
* Das Entfernen einer Warnung wirkt sich nur auf Ihre eigene Warnungsliste aus \- die Warnungen anderer Benutzer sind davon nicht betroffen.
* Das Entfernen einer Warnung entfernt keinen Importverlauf oder Aktivitätsprotokolle aus DefectDojo.

## Eingrenzen von Benachrichtigungen für Überprüfungsanfragen (Pro)

Wenn eine Überprüfung von allen berechtigten Prüfern angefordert wird, werden alle für dieses Asset berechtigten Personen benachrichtigt. Das ist eine Menge E-Mails für einen Prüfer, der nur einen Teil Ihres Bestands betreut.

In der Benutzeroberfläche von DefectDojo Pro können Sie Ihre eigenen Benachrichtigungen für Überprüfungsanfragen eingrenzen. Auf Ihrer Seite für Benachrichtigungseinstellungen, unter **Überprüfungsanfragen**:

* **Umfang der Überprüfungsanfrage** — *Alle* (die Standardeinstellung) benachrichtigt Sie über alles, was Sie sehen können. *Ausgewählt* grenzt dies auf die von Ihnen ausgewählten Assets und Asset-Typen ein.
* **Assets für Überprüfungsanfragen** / **Asset-Typen für Überprüfungsanfragen** — der Ausschnitt des Bestands, über den Sie informiert werden möchten. Eine Anfrage passt, wenn sie sich auf eines Ihrer ausgewählten Assets *oder* einen Ihrer ausgewählten Asset-Typen bezieht.

Zwei Dinge sollten klar sein:

* Wenn Sie *Ausgewählt* wählen und nichts auswählen, bedeutet das **keine**, nicht alle.
* Das Eingrenzen unterdrückt die Benachrichtigung, **nicht die Anfrage**. Sie bleiben ein angeforderter Prüfer, und die Anfrage erscheint weiterhin in Ihrer Warteschlange [Meine Arbeit](/metrics_reports/dashboards/pro__my_work/) unter **Wartet auf meine Überprüfung** — Sie werden lediglich nicht darüber benachrichtigt. Dies ist beabsichtigt: Die Warteschlange ist der dauerhafte Datensatz, Benachrichtigungen sind die Erinnerung.

Diese Eingrenzung hat außerdem Vorrang vor dem weiter unten beschriebenen Override auf Systemebene, sodass ein Prüfer, der sich selbst ausgegrenzt hat, auch dann nicht benachrichtigt wird, wenn `review_requested` so konfiguriert ist, dass es persönliche Einstellungen überstimmt.

Die Eingrenzung kann auch über die API am Benachrichtigungs-Endpunkt festgelegt werden, was die praktische Vorgehensweise ist, wenn Sie viele Prüfer gleichzeitig konfigurieren.

## Benachrichtigungen zu Arbeitszuweisungen (Pro)

Wenn Ihnen Befunde zugewiesen werden, teilt Ihnen die Benachrichtigung **Arbeit zugewiesen** mit, wie viele es sind, und verlinkt zu Ihrer Warteschlange „Meine Arbeit".

Sie wird pro Person und nicht pro Befund zusammengefasst: Das Zuweisen von hundert Befunden sendet eine einzige Nachricht, nicht hundert. Wie bei Überprüfungsanfragen ist die Zuweisung in Ihrer Warteschlange sichtbar, unabhängig davon, ob die Benachrichtigung Sie erreicht.

## Überlegungen zur Open-Source-Version

### Spezifische Overrides

Systembenachrichtigungseinstellungen (scope: system) beschreiben das Senden von Benachrichtigungen an Superadmins. Benutzerbenachrichtigungseinstellungen (scope: personal) beschreiben das Senden von Benachrichtigungen an den jeweiligen Benutzer.

Es gibt jedoch einen speziellen Anwendungsfall, bei dem der Benutzer Benachrichtigungen deaktiviert (um weniger Störungen zu haben), die Systemeinstellung dieses Verhalten jedoch außer Kraft setzt. Diese Overrides gelten standardmäßig nur für `user_mentioned` und `review_requested`.

Der Umfang dieser Einstellung ist anpassbar (siehe die Umgebungsvariable `DD_NOTIFICATIONS_SYSTEM_LEVEL_TRUMP`).

Weitere Informationen zu diesem Verhalten finden Sie im [zugehörigen Pull Request #9699](https://github.com/DefectDojo/django-DefectDojo/pull/9699/)

### Webhooks (experimentell)

DefectDojo unterstützt außerdem Webhooks, die denselben Ereignissen wie andere Benachrichtigungen folgen (Sie können in denselben Situationen benachrichtigt werden). Details zur Einrichtung finden Sie auf [der zugehörigen Seite](/automation/api/notification_webhooks/).
