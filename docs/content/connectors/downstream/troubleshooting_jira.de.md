---
title: Fehlerbehebung bei Jira-Fehlern (Legacy)
description: Beheben von Problemen mit einer Jira-Integration
weight: 2
aliases:
- /de/issue_tracking/jira/troubleshooting_jira/
- /de/en/share_your_findings/troubleshooting_jira/
---

Es folgt eine Liste häufiger Probleme mit der Jira-Integration und Möglichkeiten, sie zu beheben.

## Ich kann keine Jira-Einstellungen in DefectDojo finden

Wenn es kein Jira-Menü in der Seitenleiste, keinen Jira-Bereich in den Produkt-/Engagement-Formularen und keine Option **Push to Jira** bei Befunden gibt, ist die Jira-Integration höchstwahrscheinlich noch in den Systemeinstellungen deaktiviert.  DefectDojo blendet alle Jira-Steuerelemente aus, bis die Integration aktiviert wurde.

Aktivieren Sie **Enable Jira Integration** auf der Seite Systemeinstellungen:

* Open Source: ⚙️ **Configuration \> System Settings**, dann **Enable JIRA integration** aktivieren.  Ein **Jira webhook secret** ist ebenfalls erforderlich, damit das Formular gespeichert werden kann, klicken Sie daher auf das Symbol 🔄, um eines zu erzeugen.  Siehe den [Jira-Integrationsleitfaden](/connectors/os_jira/os__jira_guide/#step-1-enable-the-jira-integration-in-system-settings).
* Pro: **\<Your Edition\> Settings \> System Settings**, dann **Enable Jira Integration** unter **Jira Integration Settings** aktivieren.  Siehe den [Jira-Integrationsleitfaden](/connectors/downstream/pro__jira_guide/#step-1-enable-the-jira-integration-in-system-settings).

Wenn die Einstellung bereits aktiviert ist und Sie das Jira-Menü trotzdem nicht sehen, fehlt Ihrem Benutzer möglicherweise die Konfigurationsberechtigung **View Jira Instance**, die ebenfalls erforderlich ist, damit das Menü erscheint.  Sie kann direkt auf der Benutzerseite oder über eine Benutzergruppe zugewiesen werden.  Siehe [Informationen zu Berechtigungen und Rollen](/admin/user_management/about_perms_and_roles/#configuration-permissions).

## DefectDojo kann Jira (oder andere ausgehende Dienste) überhaupt nicht erreichen

Wenn die Jira-Integration von DefectDojo mit Verbindungsfehlern wie „connection refused“, „no route to host“ oder allgemeinen Fehlern beim TLS-Handshake fehlschlägt — und die Anmeldedaten selbst gültig sind — befindet sich Ihre DefectDojo-Instanz möglicherweise hinter einer Firewall, die ausgehenden Datenverkehr über einen Forward-HTTPS-Proxy verlangt.

Setzen Sie bei On-Prem-Pro-Deployments die Umgebungsvariablen `HTTPS_PROXY` / `HTTP_PROXY` / `NO_PROXY` für das Deployment.  `dojo-compose-cli` gibt diese automatisch an die Container `uwsgi`, `celeryworker` und Connector weiter.  Die vollständige Konfigurationsanleitung finden Sie unter [DefectDojo hinter einem Forward-HTTPS-Proxy betreiben](/onprem_deployment/forward_proxy/).

> Hinweis: Das Setzen von `HTTPS_PROXY` konfiguriert nur den **ausgehenden** Datenverkehr von DefectDojo.  Es hat keinen Einfluss darauf, ob Jira **eingehende** Webhooks an DefectDojo zustellen kann — siehe dazu weiter unten [Änderungen an Jira-Issues aktualisieren die Befunde in DefectDojo nicht](#changes-made-to-jira-issues-are-not-updating-findings-in-defectdojo).

## Die Jira-Konfiguration in DefectDojo kann aufgrund von 404-, 401- oder 403-Fehlern nicht eingerichtet werden

Jira Cloud:
- Konsultieren Sie die Jira Cloud REST-API-Dokumentation zur Authentifizierung: https://developer.atlassian.com/cloud/jira/software/basic-auth-for-rest-apis/
- Überprüfen Sie über die Kommandozeile, ob die angegebenen Anmeldedaten Zugriff auf die erforderlichen Issues in Jira haben:

```
curl -D- \
   -u <emailaddress>:<personal_access_token> \
   -X GET \
   -H "Content-Type: application/json" \
   https://<COMPANY>.atlassian.net/rest/api/latest/issue/<JIRA_ISSUE_KEY>/transitions?expand=transitions.fields
```

Zum Beispiel:
```
curl -D- \
   -u defectdojo@example.com:ATATT1234567890abcdefghijklmnopqrstuvwxyz \
   -X GET \
   -H "Content-Type: application/json" \
   https://defectdojo.atlassian.net/rest/api/latest/issue/VULNERABILITY-1/transitions?expand=transitions.fields
```

Jira Data Center oder Server:
- Konsultieren Sie die Jira Data Center REST-API-Dokumentation zur Authentifizierung:
    - https://developer.atlassian.com/server/jira/platform/basic-authentication/ (Benutzername + Passwort)
    - https://confluence.atlassian.com/enterprise/using-personal-access-tokens-1026032365.html (Personal Access Token)
- Überprüfen Sie über die Kommandozeile, ob die angegebenen Anmeldedaten Zugriff auf die erforderlichen Issues in Jira haben:

```
curl -u username:password -X GET -H "Content-Type: application/json" https://<COMPANY>.atlassian.net/rest/api/latest/issue/<JIRA_ISSUE_KEY>/transitions?expand=transitions.fields
```

Zum Beispiel:
```
curl -u defectdojo@example.com:123456 -X GET -H "Content-Type: application/json" https://defectdojo.atlassian.net/rest/api/latest/issue/VULNERABILITY-1/transitions?expand=transitions.fields
```

Bei Verwendung von Personal Access Tokens:
```
curl -H "Authorization: Bearer <personal_access_token>" https://<COMPANY>.atlassian.net/rest/api/latest/issue/<JIRA_ISSUE_KEY>/transitions?expand=transitions.fields
```

Zum Beispiel:
```
curl -H "Authorization: Bearer ATATT1234567890abcdefghijklmnopqrstuvwxyz" https://<COMPANY>.atlassian.net/rest/api/latest/issue/<JIRA_ISSUE_KEY>/transitions?expand=transitions.fields
```

## Jira-Servicekonten werden nicht unterstützt

Jira Cloud-Servicekonten (erstellt über die Atlassian-Admin-Konsole) verwenden einen anderen API-Host als Standardbenutzerkonten und werden von der Jira-Integration von DefectDojo **derzeit nicht unterstützt**. Der Versuch, ein API-Token eines Servicekontos oder OAuth-2.0-Anmeldedaten eines Servicekontos zu verwenden, führt zu HTTP-403-Fehlern.

Um die Jira-Integration einzurichten, erstellen Sie ein normales Jira-Benutzerkonto (mit einer gültigen E-Mail-Adresse) und generieren Sie darüber ein API-Token. Wenn Sie von DefectDojo erstellte Issues eindeutig kennzeichnen möchten, erstellen Sie einen dedizierten Benutzer mit einem Namen wie „DefectDojo“ und verwenden Sie dessen API-Token für die Integration.

## Ich kann keine Epic Name ID für meinen Space finden
Bestimmte Spaces in Jira, etwa teamverwaltete Spaces, verwenden keine Epics und haben daher keine Epic Name ID.  Setzen Sie in diesem Fall die Epic Name ID in DefectDojo auf 0.

## Befunde, die ich per 'Push To Jira' übertrage, erscheinen nicht in Jira
Der Workflow 'Push To Jira' löst einen asynchronen Prozess aus, ein Issue sollte jedoch relativ schnell erstellt werden, nachdem 'Push To Jira' ausgelöst wurde.

* Prüfen Sie Ihre DefectDojo-Benachrichtigungen, um festzustellen, ob der Vorgang erfolgreich war.  Wenn der Push fehlgeschlagen ist, erhalten Sie eine Fehlerantwort von Jira in Ihren Benachrichtigungen.

Häufige Gründe, warum Issues nicht erstellt werden:
* Der von Ihnen ausgewählte Default Issue Type kann in diesem Jira-Space nicht verwendet werden
* Issues im Space haben Pflichtattribute, die ihre Erstellung über DefectDojo verhindern (dies lässt sich über Custom Fields in Jira lösen)


## Fehler: Product Misconfigured or no permissions in Jira?

Diese Fehlermeldung kann auftreten, wenn Sie versuchen, eine erstellte Jira-Konfiguration zu einem Produkt hinzuzufügen.  DefectDojo versucht, eine Verbindung zu Jira zu validieren, und schlägt diese Verbindung fehl, wird diese Fehlermeldung ausgegeben.

* Prüfen Sie, ob Ihre Jira-Anmeldedaten berechtigt sind, Issues in dem von Ihnen ausgewählten Jira-Space zu erstellen.
* Das Feld "Project Key" muss ein gültiger Jira-Space sein. Jira-Issues können innerhalb eines einzigen Spaces viele unterschiedliche Keys verwenden; am einfachsten überprüfen Sie Ihren Project Key, indem Sie sich die URL des jeweiligen Jira-Spaces ansehen: In der Regel sieht diese so aus: `https://xyz.atlassian.net/jira/core/projects/JTV/board`.  In diesem Fall ist `JTV` der Space Key.

## Änderungen an Jira-Issues aktualisieren die Befunde in DefectDojo nicht

* Stellen Sie zunächst sicher, dass der DefectDojo-Webhook-Empfänger korrekt konfiguriert ist und Updates erfolgreich empfangen kann.

* Stellen Sie sicher, dass das von DefectDojo verwendete SSL-Zertifikat von JIRA als vertrauenswürdig eingestuft wird. Für JIRA Cloud müssen Sie [ein gültiges SSL/TLS-Zertifikat verwenden, das von einer global vertrauenswürdigen Zertifizierungsstelle signiert wurde](https://developer.atlassian.com/cloud/jira/platform/deprecation-notice-registering-webhooks-with-non-secure-urls/)

* Wenn Sie versuchen, Statusänderungen zu übertragen, stellen Sie sicher, dass die Jira-Transition-Mappings korrekt eingerichtet sind (Reopen- / Close-Transition-IDs).

* [Testen](https://support.atlassian.com/jira/kb/testing-webhooks-in-jira-cloud/) Sie Ihren JIRA-Webhook mit einem öffentlichen Endpunkt wie Pipedream oder Beeceptor:

* Stellen Sie sicher, dass der Befund tatsächlich mit dem Jira-Issue verknüpft ist. Ist das Issue nicht mit einem DefectDojo-Befund verknüpft, wird die Webhook-Anfrage zwar akzeptiert (HTTP `200`), aber kein Befund aktualisiert.

* Denken Sie daran, dass der Endpunkt **immer HTTP `200`** zurückgibt, unabhängig davon, ob eine Aktualisierung angewendet wurde. Ein `200` auf Absenderseite (ein System-Webhook oder eine Jira-Automation-Regel) bestätigt nicht, dass die Änderung einen Befund erreicht hat — prüfen Sie den Antworttext und die DefectDojo-Logs, um das tatsächliche Ergebnis zu sehen.

* Wenn Sie **Jira Automation** (*Send web request*) anstelle eines System-Webhooks verwenden, prüfen Sie Folgendes:
    * Der **Body** der Anfrage ist auf **Custom data** gesetzt und enthält auf oberster Ebene ein `webhookEvent` mit dem Wert entweder `"jira:issue_updated"` oder `"comment_created"`. Die Body-Optionen **Empty** und **Jira issue data** lassen dieses Feld weg, und DefectDojo ignoriert jede Anfrage, deren `webhookEvent` es nicht erkennt.
    * `Content-Type: application/json` ist für die Anfrage gesetzt — DefectDojo lehnt jeden anderen Content-Type ab.
    * Bei Issue-Updates ist `issue.id` die **numerische** Jira-Issue-ID (`{{issue.id}}`), nicht der Issue-Key, und die Felder `resolution` und `updated` sind beide vorhanden (`resolution` kann `null` sein). Fehlen `resolution`/`updated`, wird die Anfrage stillschweigend übersprungen.
    * Bei Kommentaren enthält die `comment.self`-URL die numerische `{{issue.id}}` in ihrem Segment `.../issue/<id>/comment/...`, und sowohl `body` als auch `updateAuthor` sind vorhanden.
    * Wenn Kommentare nicht erscheinen, prüfen Sie die **Loop-Prävention**: DefectDojo überspringt einen Kommentar, wenn dessen Autor mit dem Jira-Konto übereinstimmt, das DefectDojo zum Posten von Kommentaren verwendet. Führen Sie die Automation-Regel als anderer Jira-Benutzer aus, wenn diese Kommentare übernommen werden sollen.
    * Verwenden Sie die Payload-Vorschau von Automation, um zu bestätigen, dass die Smart Values wie erwartet aufgelöst werden — ihre Namen können sich zwischen Jira-Instanzen unterscheiden.

## Jira-Epics werden nicht erstellt

`"Field 'customfield_xyz' cannot be set. It is not on the appropriate screen, or unknown."`

Die Jira-Integration von DefectDojo benötigt einen Custom-Field-Wert für 'Epic Name'.  Es kann jedoch sein, dass Ihre Projekteinstellungen 'Epic Name' beim Erstellen von Epics gar nicht als Feld verwenden.  Atlassian hat im [August 2023](https://community.atlassian.com/t5/Jira-articles/Upcoming-changes-to-epic-fields-in-company-managed-projects/ba-p/1997562) eine Änderung vorgenommen, durch die die Felder 'Epic Name' und 'Epic Summary' zusammengeführt wurden.

Neuere Jira-Spaces verwenden dieses Feld beim Erstellen von Epics standardmäßig möglicherweise nicht, was zu dieser Fehlermeldung führt.

Um dieses Problem zu beheben, können Sie das Feld 'Epic Name' zum Issue-Erstellungsbildschirm Ihres Projekts hinzufügen:

1. Versuchen Sie, in Jira manuell ein Epic zu erstellen (über die Jira-Oberfläche).
2. Öffnen Sie das Menü "..."
3. Klicken Sie auf 'Find Your Field'
4. Geben Sie 'Epic Name' ein
5. Fügen Sie Epic Name gemäß den Anweisungen von Jira als Feld zu diesem Bildschirm hinzu.

![image](images/epic_name_error.png)

## Konfigurieren von JIRA-Verbindungswiederholungen und Timeouts

Die JIRA-Integration von DefectDojo enthält konfigurierbare Einstellungen für Wiederholungsversuche und Timeouts, um Rate Limiting und Verbindungsprobleme zu behandeln. Diese Einstellungen sind wichtig, um die Reaktionsfähigkeit des Systems zu erhalten, insbesondere bei Verwendung von Celery-Workern.

### Verfügbare Konfigurationsvariablen

Die folgenden Umgebungsvariablen steuern das Verbindungsverhalten von JIRA:

- **`DD_JIRA_MAX_RETRIES`** (Standard: `3`): Maximale Anzahl an Wiederholungsversuchen bei behebbaren Fehlern. Die Integration wiederholt die Anfrage automatisch bei HTTP 429 (Too Many Requests), HTTP 503 (Service Unavailable) und Verbindungsfehlern. Weitere Informationen finden Sie in der [JIRA-Dokumentation zum Rate Limiting](https://developer.atlassian.com/cloud/jira/platform/rate-limiting/).

- **`DD_JIRA_CONNECT_TIMEOUT`** (Standard: `10` Sekunden): Verbindungs-Timeout für den Aufbau einer Verbindung zum JIRA-Server.

- **`DD_JIRA_READ_TIMEOUT`** (Standard: `30` Sekunden): Lese-Timeout für das Warten auf eine Antwort vom JIRA-Server, nachdem die Verbindung hergestellt wurde.

**Hinweis zum Rate Limiting**: Die jira-Bibliothek hat eine eingebaute maximale Wartezeit von 60 Sekunden für Rate-Limiting-Wiederholungen. Gibt der `Retry-After`-Header von JIRA eine Wartezeit von mehr als 60 Sekunden an, schlägt die Anfrage fehl und wird nicht wiederholt. Dies ist eine Einschränkung der aktuell verwendeten Version der jira-Bibliothek.

### Warum konservative Werte wichtig sind

**Wichtig**: Es wird empfohlen, für diese Einstellungen konservative (niedrigere) Werte zu verwenden. Hier ist der Grund:

1. **Blockierung von Celery-Tasks**: JIRA-Operationen in DefectDojo laufen als asynchrone Celery-Tasks. Wartet ein Task auf eine Verzögerung durch einen Wiederholungsversuch, blockiert er diesen Celery-Worker daran, andere Tasks zu verarbeiten.

2. **Erschöpfung des Worker-Pools**: Wenn mehrere JIRA-Operationen mit langen Verzögerungen wiederholt werden, kann Ihr Celery-Worker-Pool schnell erschöpft sein, wodurch sich andere Tasks (nicht nur JIRA-bezogene) stauen und warten müssen.

3. **Reaktionsfähigkeit des Systems**: Lange Verzögerungen bei Wiederholungsversuchen können den Anschein erwecken, das System reagiere nicht, insbesondere bei JIRA-Ausfällen oder Rate-Limiting-Ereignissen.

Rate Limiting für JIRA ist neu, teilen Sie uns daher gerne auf Slack oder GitHub mit, was für Sie am besten funktioniert.

## Jira und DefectDojo sind nicht mehr synchron

Manchmal ist Jira nicht erreichbar, DefectDojo ist nicht erreichbar, oder es gab einen Fehler in einem Webhook. In diesem Fall kann Jira nicht mehr mit DefectDojo synchron sein. Betrifft dies viele Issues, ist ein manueller Abgleich unter Umständen nicht praktikabel. Für dieses Szenario gibt es den Management-Befehl 'jira_status_reconciliation'.

Da dieser Befehl Zugriff auf das Backend erfordert, steht er Cloud-Nutzern von DefectDojo Pro nicht zur Verfügung; wenden Sie sich stattdessen bei diesem Problem an unser Support-Team.

{{< highlight bash >}}
usage: manage.py jira_status_reconciliation [-h] [--mode MODE] [--product PRODUCT] [--engagement ENGAGEMENT] [--dryrun] [--version] [-v {0,1,2,3}]

Reconcile finding status with JIRA issue status, stdout will contain semicolon seperated CSV results.
Risk Accepted findings are skipped. Findings created before 1.14.0 are skipped.

optional arguments:
  -h, --help            show this help message and exit
  --mode MODE           - reconcile: (default)reconcile any differences in status between Defect Dojo and JIRA, will look at the latest status change
                        timestamp in both systems to determine which one is the correct status
                        - push_status_to_jira: update JIRA status for all JIRA issues
                        connected to a Defect Dojo finding (will not push summary/description, only status)
                        - import_status_from_jira: update Defect Dojo
                        finding status from JIRA
  --product PRODUCT     Only process findings in this product (name)
  --engagement ENGAGEMENT
                        Only process findings in this product (name)
  --dryrun              Only print actions to be performed, but make no modifications.
  -v {0,1,2,3}, --verbosity {0,1,2,3}
                        Verbosity level; 0=minimal output, 1=normal output, 2=verbose output, 3=very verbose output
{{< /highlight >}}

Dies kann im uwsgi-Docker-Container mit folgendem Befehl ausgeführt werden:

{{< highlight bash >}}
$ docker compose exec uwsgi /bin/bash -c 'python manage.py jira_status_reconciliation'
{{< /highlight >}}

DEBUG-Ausgaben können über `-v 3` abgerufen werden, allerdings erst, nachdem Sie das Logging in Ihrer Datei settings.dist.py oder local_settings.py auf DEBUG-Level erhöht haben

{{< highlight bash >}}
$ docker compose exec uwsgi /bin/bash -c 'python manage.py jira_status_reconciliation -v 3'
{{< /highlight >}}

Am Ende des Befehls wird eine durch Semikolon getrennte CSV-Zusammenfassung ausgegeben. Diese kann erfasst werden, indem stdout in eine Datei umgeleitet wird:

{{< highlight bash >}}
$ docker compose exec uwsgi /bin/bash -c 'python manage.py jira_status_reconciliation > jira_reconciliation.csv'
{{< /highlight >}}
