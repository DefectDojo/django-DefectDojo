---
title: "Jira"
description: "Einrichtung des Jira Downstream-Connectors für DefectDojo"
weight: 82
audience: pro
---
Die Jira-Integration überträgt DefectDojo-Befunde und Befundgruppen als Issues in ein Jira-Projekt, hält den Status jedes Issues mit dem Befund synchron und verknüpft den Befund mit dem erstellten Issue. Sowohl Jira **Cloud** als auch **Data Center / Server** werden unterstützt. Jira Service Management wird nicht unterstützt.

### Auswahl einer Authentifizierungsmethode

Legen Sie zuerst **Jira Deployment** fest und wählen Sie dann eine **Authentication Method**:

**Jira Cloud**
- **API Token (E-Mail + Token)** – HTTP-Basic-Authentifizierung mit der E-Mail-Adresse eines Atlassian-Kontos und einem [API-Token](https://id.atlassian.com/manage-profile/security/api-tokens). Aufrufe gehen direkt an Ihre Site-URL.
- **OAuth 2.0 (empfohlen)** – eine einmalige Zustimmung im Browser; DefectDojo bezieht und erneuert die Token für Sie.
- **Service Account Token** – ein API-Token mit Scopes, das für ein Atlassian-[Servicekonto](https://support.atlassian.com/user-management/docs/manage-api-tokens-for-service-accounts/) erstellt wurde.

**Jira Data Center / Server**
- **Personal Access Token (empfohlen)**
- **Benutzername + Passwort**

> **Wie die Cloud-Authentifizierung Jira erreicht:** OAuth 2.0 und Service Account authentifizieren sich beide per Bearer-Token gegenüber Atlassians Gateway – `https://api.atlassian.com/ex/jira/{cloudId}` – und das ist ein *anderer Host* als Ihre Site-URL `https://your-site.atlassian.net`. DefectDojo verwendet für jeden API-Aufruf das Gateway, bildet den auf einem Befund angezeigten Ticket-Link jedoch immer aus Ihrer **Site-URL**, sodass der Link, den ein Benutzer anklickt, ein normaler, im Browser aufrufbarer `.../browse/{ISSUE-KEY}`-Link ist. (Bei API-Token- und Data-Center-Authentifizierung wird die Site-URL direkt aufgerufen, es gibt dort also keine Aufteilung.)

### Instanz-Einrichtung

- **Label** sollte die Bezeichnung sein, mit der Sie diese Integration identifizieren möchten.
- **Location** sollte auf Ihre Jira-**Site-URL** gesetzt werden, zum Beispiel `https://your-organization.atlassian.net`. Sie wird für die im Browser aufrufbaren Ticket-Links verwendet und – bei API-Token- und Data-Center-Authentifizierung – als API-Basis-URL.
- Die übrigen Felder hängen von der oben gewählten Methode ab (E-Mail + API-Token, OAuth-Client-Anmeldedaten, Servicekonto-Token, PAT oder Benutzername + Passwort).

### OAuth-2.0-Einrichtung (Cloud)

Erstellen Sie eine dedizierte App in der [Atlassian Developer Console](https://developer.atlassian.com/console/myapps/) und verbinden Sie sie anschließend aus DefectDojo heraus.

1. Wählen Sie **Create → OAuth 2.0 integration**. Es muss eine *OAuth 2.0 integration* sein – eine Connect- oder Forge-App kann den 3LO-Authorization-Code-Grant nicht nutzen (Sie würden `grant_type is not enabled for client` erhalten).
2. Wählen Sie bei der Frage nach dem **Access type** die Option **Resource-level**. Damit wird das Token auf die eine Jira-Site beschränkt, die der Benutzer autorisiert – genau das, worauf eine DefectDojo-Verbindung zielt. (**Account-level** gewährt Zugriff auf jede Site des Atlassian-Kontos – mehr als erforderlich.)
3. Fügen Sie unter **Permissions** die **Jira platform REST API** hinzu und erteilen Sie die unten aufgeführten Scopes. Hinweis: `offline_access` ist hier *nicht* aufgeführt – es ist ein Standard-OAuth-Scope, den DefectDojo in der Autorisierungs-URL anfordert, und nichts, das Sie auf diesem Bildschirm hinzufügen.
4. Klicken Sie unter **Authorization** neben **OAuth 2.0 (3LO)** auf **Configure** und setzen Sie die **Callback URL** auf `https://<your-defectdojo-host>/integrators/jira/oauth/callback` – sie muss exakt Ihrer DefectDojo-Site-URL entsprechen. Erst dadurch werden der Authorization-Code-Grant und Refresh-Token aktiviert; wird dies übersprungen, treten die Fehler `grant_type is not enabled` / `Client is not allowed to use offline_access` auf.
5. Kopieren Sie die **Client ID** und das **Client Secret** in das DefectDojo-Formular und klicken Sie auf **Submit**, um die Verbindung zu speichern.
6. Klicken Sie auf **Connect with Jira** und bestätigen Sie den Zustimmungsbildschirm. Atlassian leitet zurück zu DefectDojo, das die Token speichert und Ihre `cloudId` automatisch auflöst. Bei Erfolg erscheint die Anzeige „Connected“.

> Der Callback-Host ist die `SITE_URL` Ihrer DefectDojo-Instanz. Atlassian muss den Browser dorthin weiterleiten können, und der Wert muss exakt dem entsprechen, was DefectDojo sendet – verwenden Sie deshalb den echten Hostnamen, über den Ihre Benutzer DefectDojo erreichen, und keinen Wert, der nur aus dem internen Netzwerk erreichbar ist.

#### Minimale OAuth-Scopes

DefectDojo fordert standardmäßig diese vier klassischen Scopes an, und sie sind gleichzeitig das **absolute Minimum** – jeder davon deckt ein bestimmtes Verhalten ab:

| Scope | Erforderlich für |
|-------|--------------|
| `read:jira-work` | Lesen des Projekts, der Issues und der verfügbaren Übergänge (Verbindungsprüfung und Statussynchronisierung). |
| `write:jira-work` | Erstellen und Bearbeiten von Issues sowie Ausführen von Statusübergängen. |
| `read:jira-user` | Die Identitätsprüfung der Verbindung – DefectDojo ruft beim Prüfen des Zugriffs `/myself` auf. |
| `offline_access` | Ausgeben eines **Refresh-Tokens**. Ohne ihn läuft das Access-Token ab (etwa eine Stunde nach dem Verbinden) und die Verbindung funktioniert nicht mehr, weil DefectDojo es nicht länger erneuern kann. |

Atlassian empfiehlt klassische Scopes gegenüber granularen; die vier oben genannten halten den Footprint der App minimal und genügen für alles, was die Integration tut.

##### Alternative mit granularen Scopes

Wenn Ihre Organisation **granulare** Scopes anstelle klassischer verlangt, lautet der minimale äquivalente Satz:

| Granularer Scope | Erforderlich für |
|----------------|--------------|
| `read:user:jira` | Die Identitätsprüfung über `/myself`. |
| `read:project:jira` | Prüfen, ob das Zielprojekt existiert. |
| `read:issue:jira` | Lesen des aktuellen Status eines Issues während der Synchronisierung. |
| `write:issue:jira` | Erstellen und Bearbeiten von Issues **sowie Ausführen von Statusübergängen** – es gibt keinen separaten Schreib-Scope für Übergänge, denn ein Übergang ist ein Schreibvorgang am Issue. |
| `read:issue.transition:jira` | Auflisten der für ein Issue verfügbaren Übergänge. |
| `offline_access` | Das Refresh-Token (wie bei den klassischen Scopes). |

Je nach Feldkonfiguration Ihrer Site kann ein Endpunkt zusätzlich begleitende Lese-Scopes benötigen, um Felder zu expandieren – am häufigsten `read:status:jira` und `read:field:jira` (sowie `read:issue-meta:jira` beim Erstellen). Schlägt eine Übertragung mit einem `403`-Fehler „scope does not match“ fehl, fügen Sie genau den im Fehler genannten Scope hinzu. Genau dieses Ausufern begleitender Scopes ist der Grund, warum klassische Scopes empfohlen werden.

Für die Methode **Service Account Token** erteilen Sie dem Token `read:jira-work` und `write:jira-work` (sowie `read:jira-user`) – oder die oben genannten granularen Entsprechungen ohne `offline_access`. `offline_access` ist hier nicht relevant – ein Servicekonto-Token ist langlebig und wird von DefectDojo nicht erneuert.

### Issue-Tracker-Zuordnung

- **Project Key**: der Schlüssel des Jira-Projekts, in dem Issues erstellt werden, zum Beispiel `SEC`.
- **Issue Type**: der zu erstellende Issue-Typ, zum Beispiel `Bug` oder `Task`. Standard ist `Bug`.

### Details zur Schweregrad-Zuordnung

Die Standardwerte entsprechen dem Standard-Prioritätsschema von Jira. Passen Sie sie an die Prioritätsnamen in Ihrem Projekt an:

- **Name des Schweregrad-Felds**: `priority`
- **Info-Zuordnung**: `Lowest`
- **Niedrig-Zuordnung**: `Low`
- **Mittel-Zuordnung**: `Medium`
- **Hoch-Zuordnung**: `High`
- **Kritisch-Zuordnung**: `Highest`

### Details zur Status-Zuordnung

Status unterscheiden sich je nach Projekt-Workflow, daher sind diese Standardwerte dafür gedacht, an die Statusnamen **Ihres** Workflows angepasst zu werden:

- **Name des Status-Felds**: `status`
- **Aktiv-Zuordnung**: `To Do`
- **Geschlossen-Zuordnung**: `Done`
- **Falsch-positiv-Zuordnung**: `Done`
- **Risiko-akzeptiert-Zuordnung**: `Done`

### Benutzerdefinierte Felder (optional)

Sie können weitere Jira-Felder zuordnen – zum Beispiel eine beim Schließen erforderliche `resolution` oder `labels` – und zwar im Schritt **Custom Fields** der Zuordnung. Jede Zuordnung eines benutzerdefinierten Felds besteht aus vier Teilen:

- **Source** – woher der Wert kommt: ein Attribut des übertragenen **Befunds**, **Tests**, **Engagements** oder **Assets** oder ein **statischer Wert**.
- **Value** – bei einer Objektquelle das konkrete auszulesende Attribut, ausgewählt aus einer Liste der Felder dieses Objekts mit lesbaren Bezeichnungen (zum Beispiel *Schweregrad*, *CVE*, *Mitigation*). Bei der Quelle **Static value** ist dies ein Freitextfeld, in das Sie den wörtlichen Wert eingeben.
- **Vendor Field** – das Jira-Feld, in das geschrieben wird. Da DefectDojo den Feldkatalog von Jira lesen kann, ist dies eine durchsuchbare Auswahl, die jedes Feld mit seinem **Anzeigenamen** auflistet und für Sie in die interne ID auflöst – Sie wählen also *DD Close Justification* und DefectDojo speichert `customfield_10255`. Die Auswahl wird aus der Verbindung befüllt und funktioniert daher, sobald die Verbindung gespeichert und geprüft ist.
- **Application point** – *wann* das Feld gesendet wird: bei der **Ticket-Erstellung**, bei **jeder Aktualisierung** oder als Teil eines bestimmten Status-**Übergangs** (Aktiv / Geschlossen / Falsch-positiv / Risiko akzeptiert). Ein auf einen Übergang beschränktes Feld wird als Teil der Bearbeitung dieses Übergangs gesendet – so liefern Sie einen Wert, den Jira nur auf einem Übergangsbildschirm akzeptiert, meist eine `resolution`, die Ihr Workflow beim Auflösen eines Issues verlangt.

### Ticket-Vorlagen (optional)

Standardmäßig verwenden Jira-Issues den integrierten Titel und Textkörper von DefectDojo. Um sie anzupassen, hängen Sie im Schritt **Ticket Template** der Zuordnung eine **Ticket-Vorlage** an. Eine Vorlage definiert vier unabhängig voneinander optionale Bestandteile – Zusammenfassung und Beschreibung für den **Befund** sowie Zusammenfassung und Beschreibung für die **Befundgruppe**. Jeder leer gelassene Bestandteil fällt auf den integrierten Standard zurück, sodass Sie nur den Titel, nur den Textkörper oder alle vier überschreiben können. Verwenden Sie **Test render** im Vorlagen-Editor, um die gerenderte Ausgabe anhand von Beispieldaten vorab zu prüfen – so erkennen Sie Fehler wie unbekannte Platzhalter oder Werte, die die Längenbegrenzung eines Felds überschreiten – bevor Sie speichern. Wird eine Vorlage später gelöscht, fallen die Zuordnungen, die sie verwendet haben, automatisch auf die integrierten Standardwerte zurück.

### Funktionsweise

- **Erstellen / Aktualisieren / Löschen:** Beim Erstellen wird ein neues Issue übertragen und der Link am Befund vermerkt; beim Aktualisieren wird das bestehende Issue bearbeitet; beim Löschen eines Befunds wird sein Issue zwangsweise geschlossen (in Jira wird nichts gelöscht). Übertragungen können manuell erfolgen („Push to Integrator“) oder automatisch gemäß der Issue-Tracker-Zuweisung.
- **Statusabgleich:** Nach dem Erstellen (und bei jeder Aktualisierung) liest DefectDojo den aktuellen Status des Issues und sucht, falls er vom zugeordneten Ziel abweicht, einen einzelnen Workflow-Übergang, der ihn erreicht, und wendet diesen an. Existiert kein solcher Übergang, vermerkt die Zuordnung einen Fehler, anstatt stillschweigend zu scheitern. Alle auf Übergänge beschränkten benutzerdefinierten Felder werden mit diesem Übergang gesendet.
- **Ticket-Link:** Der am Befund angezeigte Link ist `https://your-site.atlassian.net/browse/{ISSUE-KEY}` – immer Ihre öffentliche Site-URL, niemals das interne Gateway.
- **Token-Lebenszyklus (OAuth):** DefectDojo verantwortet den gesamten Ablauf – es führt den Authorization-Code-Austausch durch, speichert Access- und Refresh-Token und erneuert sie bei Bedarf vor einer Übertragung, wobei das neue Refresh-Token jedes Mal gespeichert wird (Atlassian rotiert es bei jeder Erneuerung).
- **Speicherung der Anmeldedaten:** Alle Verbindungsdaten (Passwörter, Token, Client Secrets, OAuth-Token) werden verschlüsselt gespeichert und niemals über die API zurückgegeben – beim Bearbeiten einer Verbindung erscheint für gespeicherte Geheimnisse ein Platzhalter „leer lassen, um beizubehalten“.
