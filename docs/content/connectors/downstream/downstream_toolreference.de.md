---
title: Referenz zu Downstream-Connector-Tools
description: Detaillierte Einrichtungsanleitungen für Downstream Connectors
weight: 1
audience: pro
aliases:
- /en/share_your_findings/integrations_toolreference
- /issue_tracking/pro_integration/integrations_toolreference/
---

Hier finden Sie konkrete Anweisungen dazu, wie Sie einen DefectDojo Downstream Connector mit einem Issue-Tracker eines Drittanbieters einrichten.

## Azure DevOps Boards

### Instanz-Einrichtung

- **Label** sollte die Bezeichnung sein, mit der Sie diese Integration identifizieren möchten.
- **Location** sollte auf Ihre Azure-URL gesetzt werden, zum Beispiel `https://dev.azure.com/{your organization}`
- **Token** sollte auf ein persönliches Zugriffstoken aus Azure gesetzt werden.

Die Authentifizierung bei Azure DevOps erfordert ein [persönliches Zugriffstoken](https://learn.microsoft.com/en-us/azure/devops/organizations/accounts/use-personal-access-tokens-to-authenticate?view=azure-devops&tabs=Windows)
mit der Berechtigung „Read, Write and Manage“ für „Work Items“ im Azure-Projekt, mit dem Sie arbeiten möchten.

### Issue-Tracker-Zuordnung

Diese Angaben legen fest, wie DefectDojo Attribute von Befunden oder Befundgruppen einem bestimmten Projekt in Azure DevOps zuordnet:

#### Details zur Issue-Tracker-Zuordnung

Das Feld `Project ID` entspricht dem Namen oder der ID des Projekts in Azure.

#### Details zur Schweregrad-Zuordnung

Die Attribute im Formular sind als Standardwerte vorbelegt und lauten wie folgt:

- **Name des Schweregrad-Felds**: `/fields/Microsoft.VSTS.Common.Priority`
- **Info-Zuordnung**: `4`
- **Niedrig-Zuordnung**: `4`
- **Mittel-Zuordnung**: `3`
- **Hoch-Zuordnung**: `2`
- **Kritisch-Zuordnung**: `1`

#### Details zur Status-Zuordnung

Die Attribute im Formular sind als Standardwerte vorbelegt und lauten wie folgt:

- **Name des Status-Felds**: `/fields/System.State`
- **Aktiv-Zuordnung**: `To Do`
- **Geschlossen-Zuordnung**: `Done`
- **Falsch-positiv-Zuordnung**: `Done`
- **Risiko-akzeptiert-Zuordnung**: `Done`

## Bitbucket

Die Bitbucket-Integration ermöglicht es Ihnen, Issues in den [Issue-Tracker](https://support.atlassian.com/bitbucket-cloud/docs/enable-an-issue-tracker/) eines Bitbucket-Cloud-Repositorys zu übertragen.

Der Issue-Tracker ist in Bitbucket optional und muss im Repository aktiviert werden, bevor DefectDojo dort Issues erstellen kann. Öffnen Sie zum Aktivieren das Repository in Bitbucket, wählen Sie **Repository settings** und aktivieren Sie den Issue-Tracker anschließend unter **Features**.

### Instanz-Einrichtung

- **Label** sollte die Bezeichnung sein, mit der Sie diese Integration identifizieren möchten.
- **Location** sollte auf `https://bitbucket.org` gesetzt werden.
- **Email** sollte die E-Mail-Adresse des Atlassian-Kontos sein, zu dem das API-Token gehört.
- **API Token** sollte auf ein Atlassian-API-Token mit Scopes gesetzt werden.

Bitbucket-App-Passwörter wurden von Atlassian abgekündigt und funktionieren mit dieser Integration nicht. So erstellen Sie ein API-Token:

1. Öffnen Sie die [Atlassian-Kontoeinstellungen](https://id.atlassian.com/manage-profile/security/api-tokens) und wählen Sie **Security** und dann **Create and manage API tokens**.
2. Wählen Sie **Create API token with scopes**, benennen Sie das Token und legen Sie ein Ablaufdatum fest.
3. Wählen Sie **Bitbucket** als App aus.
4. Erteilen Sie dem Token die Berechtigung, Repositorys zu lesen sowie Issues zu lesen und zu schreiben.

### Issue-Tracker-Zuordnung

- **Workspace** sollte der Slug des Workspace sein, der das Repository enthält, so wie er in bitbucket.org-URLs erscheint.
- **Repository Slug** sollte der Slug des Repositorys sein, in dem Sie Issues erstellen möchten.

### Details zur Schweregrad-Zuordnung

Dies wird dem Bitbucket-Feld „Priority“ eines Issues zugeordnet. Die Attribute im Formular sind als Standardwerte vorbelegt, und jeder Wert muss eine der Bitbucket-Prioritäten sein: `trivial`, `minor`, `major`, `critical` oder `blocker`.

- **Name des Schweregrad-Felds**: `priority`
- **Info-Zuordnung**: `trivial`
- **Niedrig-Zuordnung**: `minor`
- **Mittel-Zuordnung**: `major`
- **Hoch-Zuordnung**: `critical`
- **Kritisch-Zuordnung**: `blocker`

### Details zur Status-Zuordnung

Dies wird dem Bitbucket-Feld „State“ eines Issues zugeordnet. Jeder Wert muss einer der Bitbucket-Issue-Status sein: `new`, `open`, `resolved`, `on hold`, `invalid`, `duplicate`, `wontfix` oder `closed`.

- **Name des Status-Felds**: `state`
- **Aktiv-Zuordnung**: `new`
- **Geschlossen-Zuordnung**: `resolved`
- **Falsch-positiv-Zuordnung**: `invalid`
- **Risiko-akzeptiert-Zuordnung**: `wontfix`

## GitHub

Die GitHub-Integration ermöglicht es Ihnen, Issues zu einem [GitHub Project](https://docs.github.com/en/issues/planning-and-tracking-with-projects/learning-about-projects/about-projects) hinzuzufügen, wodurch außerdem Issues in einem zugehörigen Repo geöffnet werden.  Diese Repos/Projects können entweder mit einer GitHub-Organisation oder mit einem persönlichen GitHub-Konto verknüpft sein.

### Instanz-Einrichtung

- **Label** sollte die Bezeichnung sein, mit der Sie diese Integration identifizieren möchten.
- **Location** sollte auf die URL Ihres GitHub-Benutzers oder Ihrer GitHub-Organisation gesetzt werden, je nachdem, wo Sie Issues erstellen möchten, zum Beispiel `https://github.com/{your-organization}`
- **Token** sollte auf ein persönliches Zugriffstoken aus GitHub gesetzt werden.

Persönliche Zugriffstoken für GitHub können unter https://github.com/settings/tokens erstellt werden.  Das Token muss die Scopes „Repo“ und „Project“ besitzen.

### Issue-Tracker-Zuordnung

- **Issue Tracker Mapping Label** sollte so gesetzt werden, dass es das Project oder Repo identifiziert, in dem Sie Issues erstellen möchten.
- **Project Number** sollte die ID eines GitHub-Projects sein, an das Sie Elemente senden möchten.  Sie finden sie in der URL, während Sie ein Project ansehen, zum Beispiel `https://github.com/orgs/{your-org}/projects/{project number}`.
- **Repository Name** sollte der Name eines Repos sein, das Ihrer Organisation (oder Ihrem Benutzer) zugeordnet ist und in das Sie Issues übertragen möchten.


### Details zur Schweregrad-Zuordnung

**Damit die Integration eingerichtet werden kann, MUSS im Project ein benutzerdefiniertes Feld für die Issue-Priorität angelegt sein, andernfalls wird der Schweregrad nicht korrekt zugeordnet und Issues werden nicht an GitHub übertragen.**

Folgen Sie dieser Anleitung, um ein [benutzerdefiniertes Feld](https://docs.github.com/en/issues/planning-and-tracking-with-projects/learning-about-projects/quickstart-for-projects#creating-a-field-to-track-priority) zu erstellen.
Für jeden Schweregrad muss eine entsprechende Single-Select-Option verfügbar sein.  Standardmäßig schlägt DefectDojo zum Beispiel P0, P1, P2, P3, P4 als mögliche Prioritätswerte vor, und jeder dieser Werte muss dem benutzerdefinierten Feld „Priority“ hinzugefügt werden.

- **Name des Schweregrad-Felds**: `Priority`
- **Info-Zuordnung**: `P0`
- **Niedrig-Zuordnung**: `P1`
- **Mittel-Zuordnung**: `P2`
- **Hoch-Zuordnung**: `P3`
- **Kritisch-Zuordnung**: `P4`

### Details zur Status-Zuordnung

Standardmäßig haben neue GitHub Projects für Issues die Status „In Progress“ und „Done“.  Dem Project können weitere Status hinzugefügt werden, um bei Bedarf den Status Falsch-positiv oder Risiko akzeptiert nachzuverfolgen.  Eine Möglichkeit dafür ist, dem Project-Board eine neue Statusspalte hinzuzufügen.

- **Name des Status-Felds**: `Status`
- **Aktiv-Zuordnung**: `In Progress`
- **Geschlossen-Zuordnung**: `Done`
- **Falsch-positiv-Zuordnung**: `Done`
- **Risiko-akzeptiert-Zuordnung**: `Done`

## GitLab

Die GitLab-Integration ermöglicht es Ihnen, Issues zu einem [GitLab-Projekt](https://docs.gitlab.com/ee/user/project/) hinzuzufügen.

### Instanz-Einrichtung

- **Label** sollte die Bezeichnung sein, mit der Sie diese Integration identifizieren möchten.
- **Location** sollte auf den Link zu Ihrem GitLab-Server gesetzt werden, zum Beispiel `https://gitlab.com/`.
- **Token** sollte auf ein persönliches Zugriffstoken aus GitLab gesetzt werden. Das Token muss API-Scopes besitzen. Siehe [GitLabs Anleitung zum Erstellen eines persönlichen Zugriffstokens](https://docs.gitlab.com/user/profile/personal_access_tokens/#create-a-personal-access-token).

### Issue-Tracker-Zuordnung

- **Project Name**: Der Name des Projekts in GitLab, an das Sie Issues senden möchten.

### Details zur Schweregrad-Zuordnung

Dies wird dem GitLab-Feld „Priority“ zugeordnet.
- **Name des Schweregrad-Felds**: `Priority`
- **Info-Zuordnung**: `1`
- **Niedrig-Zuordnung**: `2`
- **Mittel-Zuordnung**: `3`
- **Hoch-Zuordnung**: `4`
- **Kritisch-Zuordnung**: `5`

### Details zur Status-Zuordnung

Standardmäßig kennt GitLab die Status „opened“ und „closed“.  Zusätzliche Status-Labels können hinzugefügt werden, wenn Sie den Status Falsch-positiv oder Risiko akzeptiert nachverfolgen möchten.  Details finden Sie in den [GitLab-Docs](https://docs.gitlab.com/user/work_items/status/).

- **Name des Status-Felds**: `Status`
- **Aktiv-Zuordnung**: `opened`
- **Geschlossen-Zuordnung**: `closed`
- **Falsch-positiv-Zuordnung**: `closed`
- **Risiko-akzeptiert-Zuordnung**: `closed`

## Jira

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

## Linear

Die Linear-Integration ermöglicht es Ihnen, DefectDojo-Befunde als [Linear](https://linear.app/)-Issues zu übertragen. Issues werden in einem Team in Ihrem Linear-Workspace erstellt.

### Instanz-Einrichtung

- **Label** sollte die Bezeichnung sein, mit der Sie diese Integration identifizieren möchten.
- **Location** sollte auf `https://api.linear.app/graphql` gesetzt werden.
- **API Key** sollte auf einen persönlichen Linear-API-Key gesetzt werden. Keys können in Linear unter „Settings“, dann „Security & access“, dann [API](https://linear.app/settings/account/security) generiert werden. Der Key wird im Header `Authorization` an die GraphQL-API von Linear gesendet.

### Issue-Tracker-Zuordnung

- **Team (Group) ID** sollte auf die ID des Linear-Teams gesetzt werden, für das Issues erstellt werden. Sie können Ihre Teams und deren IDs auflisten, indem Sie die Linear-GraphQL-API aufrufen:

```
curl -H "Authorization: {{API_KEY}}" -H "Content-Type: application/json" \
  -d '{"query":"{ teams { nodes { id name key } } }"}' https://api.linear.app/graphql
```

### Details zur Schweregrad-Zuordnung

Ein Linear-Issue trägt eine numerische **Priorität** anstelle eines Schweregrad-Felds. Jeder DefectDojo-Schweregrad wird einer Linear-Priorität zugeordnet, wobei `1` „Urgent“ und `4` „Low“ bedeutet:

- **Name des Schweregrad-Felds**: `Priority`
- **Info-Zuordnung**: `4`
- **Niedrig-Zuordnung**: `4`
- **Mittel-Zuordnung**: `3`
- **Hoch-Zuordnung**: `2`
- **Kritisch-Zuordnung**: `1`

### Details zur Status-Zuordnung

Jeder Statuswert muss auf die ID eines Workflow-States in Ihrem Linear-Team gesetzt werden. Workflow-State-IDs sind je Workspace eindeutig, daher gibt es keine Standardwerte. Sie können die Workflow-States und ihre IDs auflisten, indem Sie die Linear-GraphQL-API aufrufen:

```
curl -H "Authorization: {{API_KEY}}" -H "Content-Type: application/json" \
  -d '{"query":"{ workflowStates { nodes { id name type team { key } } } }"}' https://api.linear.app/graphql
```

- **Name des Status-Felds**: `Workflow State ID`
- **Aktiv-Zuordnung**: die ID eines gestarteten oder noch nicht gestarteten States, zum Beispiel `Todo` oder `In Progress`.
- **Geschlossen-Zuordnung**: die ID eines abgeschlossenen States, zum Beispiel `Done`. Wenn ein Befund in DefectDojo gelöscht wird, wird sein Issue in diesen State verschoben.

## Opsgenie

Die Opsgenie-Integration ermöglicht es Ihnen, DefectDojo-Befunde und Befundgruppen als Opsgenie-Alerts zu übertragen, die optional an ein Opsgenie-Team als Responder geleitet werden.

### Instanz-Einrichtung

- **Label** sollte die Bezeichnung sein, mit der Sie diese Integration identifizieren möchten.
- **Location** sollte auf `https://api.opsgenie.com` gesetzt werden.  Wird Ihr Opsgenie-Konto in der EU-Serviceregion gehostet, verwenden Sie stattdessen `https://api.eu.opsgenie.com`.  Liegen Ihre Alerts in Jira Service Management Operations (Atlassian überführt Opsgenie in JSM), verwenden Sie `https://api.atlassian.com/jsm/ops/integration`.
- **API Key** sollte auf einen Opsgenie-**API-Integrations**-Key gesetzt werden.  Ein Kontoadministrator kann einen solchen in der Opsgenie-Web-App unter **Settings > Integrations** erstellen: Fügen Sie eine Integration des Typs **API** hinzu und erteilen Sie ihr *Create and Update Access* (sowie *Read Access*, damit DefectDojo die Verbindung prüfen kann).  Beachten Sie, dass dies ein Integrations-Key und kein persönlicher API-Key ist - DefectDojo authentifiziert sich mit `GenieKey`-Autorisierung, die nur Integrations-Keys unterstützen.

### Issue-Tracker-Zuordnung

- **Team Name** *(optional)* sollte der Name des Opsgenie-Teams sein, das erstellten Alerts als Responder hinzugefügt wird.  Sie können das Feld leer lassen: Ist der API-Integrations-Key teambezogen, werden Alerts automatisch an dieses Team geleitet, andernfalls entscheiden die Routing-Regeln Ihres Kontos über die Responder.

### Details zur Schweregrad-Zuordnung

Schweregrade werden dem Opsgenie-Alert-Feld **Priority** zugeordnet, das die feste Opsgenie-Skala von `P1` (kritisch) bis `P5` (informativ) verwendet:

- **Name des Schweregrad-Felds**: `Priority`
- **Info-Zuordnung**: `P5`
- **Niedrig-Zuordnung**: `P4`
- **Mittel-Zuordnung**: `P3`
- **Hoch-Zuordnung**: `P2`
- **Kritisch-Zuordnung**: `P1`

Ist ein Schweregrad einem unbekannten Wert zugeordnet, wird die Priorität weggelassen und Opsgenie wendet seinen eigenen Standard (`P3`) an.

### Details zur Status-Zuordnung

Opsgenie-Alerts sind `open` oder `closed`, und ein offener Alert kann zusätzlich `acknowledged` sein:

- **Name des Status-Felds**: `Status`
- **Aktiv-Zuordnung**: `open`
- **Geschlossen-Zuordnung**: `closed`
- **Falsch-positiv-Zuordnung**: `closed`
- **Risiko-akzeptiert-Zuordnung**: `acknowledged`

Beachten Sie, dass `closed` in Opsgenie ein endgültiger Status ist - ein geschlossener Alert kann nicht wieder geöffnet werden, und sein Alias wird freigegeben.  Anders als manche anderen Tools erlaubt Opsgenie Inhaltsänderungen nach dem Erstellen, sodass beim Übertragen eines aktualisierten Befunds neben dem Status auch Nachricht, Beschreibung und Priorität synchronisiert werden.

DefectDojo setzt den **Alias** jedes Alerts auf einen stabilen Schlüssel, der vom Befund oder von der Befundgruppe abgeleitet ist, und Opsgenie dedupliziert offene Alerts anhand des Alias - ein erneutes Übertragen desselben Befunds aktualisiert daher den bestehenden offenen Alert, anstatt ein Duplikat zu erzeugen.

## PagerDuty

Die PagerDuty-Integration ermöglicht es Ihnen, DefectDojo-Befunde und Befundgruppen als PagerDuty-Incidents zu übertragen, die auf einem PagerDuty-Service Ihrer Wahl eröffnet werden.

### Instanz-Einrichtung

- **Label** sollte die Bezeichnung sein, mit der Sie diese Integration identifizieren möchten.
- **Location** sollte auf `https://api.pagerduty.com` gesetzt werden.  Wird Ihr PagerDuty-Konto in der EU-Serviceregion gehostet, verwenden Sie stattdessen `https://api.eu.pagerduty.com`.
- **API Token** sollte auf einen PagerDuty-REST-API-Key gesetzt werden.  Ein Kontoadministrator kann einen solchen in der PagerDuty-Web-App unter **Integrations > API Access Keys > Create New API Key** erstellen.  Lassen Sie „Read-only“ deaktiviert - DefectDojo muss Incidents erstellen und aktualisieren.
- **From Email** sollte die E-Mail-Adresse eines gültigen Benutzers in Ihrem PagerDuty-Konto sein.  PagerDuty verlangt diese Adresse beim Erstellen oder Aktualisieren von Incidents, und sie wird als Anforderer des Incidents angezeigt.

### Issue-Tracker-Zuordnung

- **Service ID** sollte die ID des PagerDuty-Services sein, auf dem Incidents eröffnet werden.  Sie finden sie am Ende der URL, während Sie den Service in PagerDuty ansehen, zum Beispiel `https://{your-subdomain}.pagerduty.com/service-directory/{service id}`.

### Details zur Schweregrad-Zuordnung

Standardmäßig wird dies dem PagerDuty-Incident-Feld **Urgency** zugeordnet, das nur `high` oder `low` akzeptiert:

- **Name des Schweregrad-Felds**: `Urgency`
- **Info-Zuordnung**: `low`
- **Niedrig-Zuordnung**: `low`
- **Mittel-Zuordnung**: `low`
- **Hoch-Zuordnung**: `high`
- **Kritisch-Zuordnung**: `high`

Alternativ können Sie, wenn in Ihrem PagerDuty-Konto [Priorities](https://support.pagerduty.com/main/docs/incident-priority) aktiviert sind, Schweregrade stattdessen Prioritätsnamen zuordnen.  Setzen Sie den **Namen des Schweregrad-Felds** auf `Priority` und verwenden Sie die Prioritätsnamen Ihres Kontos (zum Beispiel `P1` bis `P5`) als Zuordnungswerte.  Bei einer Zuordnung auf Priority bleibt die Urgency des Incidents den Urgency-Regeln Ihres Services überlassen.

### Details zur Status-Zuordnung

PagerDuty-Incidents haben drei Status: `triggered`, `acknowledged` und `resolved`.

- **Name des Status-Felds**: `Status`
- **Aktiv-Zuordnung**: `triggered`
- **Geschlossen-Zuordnung**: `resolved`
- **Falsch-positiv-Zuordnung**: `resolved`
- **Risiko-akzeptiert-Zuordnung**: `acknowledged`

Beachten Sie, dass `resolved` in PagerDuty ein endgültiger Status ist - ein aufgelöster Incident kann nicht wieder geöffnet werden.  Beachten Sie außerdem, dass PagerDuty es nicht erlaubt, Titel oder Beschreibung eines Incidents nach dem Erstellen zu bearbeiten; beim Übertragen eines aktualisierten Befunds werden daher Status, Urgency und Priority synchronisiert, Inhaltsänderungen jedoch nicht.

## ServiceNow

Die ServiceNow-Integration ermöglicht es Ihnen, DefectDojo-Befunde als ServiceNow-Incidents zu übertragen.

### Instanz-Einrichtung

DefectDojo authentifiziert sich bei ServiceNow über OAuth 2.0. Wie Sie die OAuth-Anmeldedaten erstellen, hängt von Ihrem ServiceNow-Release ab – neuere Releases (Zurich und später) verwenden einen Client-Credentials-Grant, frühere Releases ein Refresh-Token.

#### ServiceNow Zurich und später (Client Credentials)

In neueren ServiceNow-Releases wurde die klassische Option „Create an OAuth API endpoint for external clients“ zugunsten der **New Inbound Integration Experience** abgekündigt, die einen an ein Servicekonto gebundenen OAuth-**Client-Credentials**-Grant ausgibt:

1. Suchen Sie in der linken Navigationsleiste nach „Application Registry“ und wählen Sie den Eintrag aus.
2. Klicken Sie auf **New** und wählen Sie dann **New Inbound Integration Experience**.
3. Wählen Sie **New Integration → OAuth - Client credentials grant**.
4. Setzen Sie den **OAuth Application User** auf das Servicekonto, das die Incidents erstellen wird. Die Rollen dieses Kontos bestimmen, was DefectDojo schreiben darf.
5. Speichern Sie die Registrierung. ServiceNow generiert **Client ID** und **Client Secret** automatisch (lassen Sie diese Felder beim Erstellen der Registrierung leer).

Anschließend in DefectDojo:

- **Instance Label** sollte die Bezeichnung sein, mit der Sie diese Integration identifizieren möchten.
- **Location** sollte auf die URL Ihres ServiceNow-Servers gesetzt werden, zum Beispiel `https://your-organization.service-now.com/`.
- **Client ID** sollte die Client ID aus der OAuth-Registrierung sein.
- **Client Secret** sollte das Client Secret aus der OAuth-Registrierung sein.

Lassen Sie die Felder Refresh Token, Username und Password leer – DefectDojo fordert für jede Synchronisierung ein frisches Client-Credentials-Token an.

#### Frühere ServiceNow-Releases (Refresh-Token)

Bei Releases, die noch die klassische Registrierung anbieten, benötigen Sie ein Refresh-Token, das dem Benutzer- oder Servicekonto zugeordnet ist, das Incidents an ServiceNow überträgt:

1. Suchen Sie in der linken Navigationsleiste nach „Application Registry“ und wählen Sie den Eintrag aus.
2. Klicken Sie auf „New“.
3. Wählen Sie „Create an OAuth API endpoint for external clients“.
4. Füllen Sie die erforderlichen Felder aus:
    * Name: Geben Sie Ihrer Anwendung einen sinnvollen Namen (z. B. Vulnerability Integration Client).
    * (Optional) Passen Sie die Token-Lebensdauer an:
    * Access Token Lifespan: Standard sind 1800 Sekunden (30 Minuten).
    * Refresh Token Lifespan: Standard sind 8640000 Sekunden (etwa 100 Tage).
5. Klicken Sie auf „Submit“, um den Anwendungsdatensatz zu erstellen.
6. Wählen Sie die Anwendung nach dem Absenden aus der Liste aus und notieren Sie sich die Felder **Client ID und Client Secret**.

Anschließend müssen Sie mit dieser Registrierung ein Refresh-Token beziehen, was nur über die ServiceNow-API möglich ist.  Öffnen Sie ein Terminalfenster und fügen Sie Folgendes ein (ersetzen Sie dabei die in `{{}}` eingeschlossenen Variablen durch die tatsächlichen Angaben Ihres Benutzers)

```
curl --request POST \
 --url {{INSTANCE_HOST}}/oauth_token.do \
 --header 'content-type: application/x-www-form-urlencoded' \
 --data grant_type=password \
 --data 'client_id={{CLIENT_ID}}' \
 --data 'client_secret={{CLIENT_SECRET}}' \
 --data 'username={{USERNAME}}' \
 --data 'password={{PASSWORD}}'
 ```

Wenn Ihre ServiceNow-Anmeldedaten korrekt sind und Zugriff auf Administratorebene in ServiceNow erlauben, sollten Sie eine Antwort mit einem RefreshToken erhalten.  Dieses Token benötigen Sie, um die Integration mit DefectDojo abzuschließen.

- **Instance Label** sollte die Bezeichnung sein, mit der Sie diese Integration identifizieren möchten.
- **Location** sollte auf die URL Ihres ServiceNow-Servers gesetzt werden, zum Beispiel `https://your-organization.service-now.com/`.
- **Refresh Token** ist das Feld, in das das Refresh-Token eingetragen wird.
- **Client ID** sollte die in der OAuth-App-Registrierung festgelegte Client ID sein.
- **Client Secret** sollte das in der OAuth-App-Registrierung festgelegte Client Secret sein.

### Details zur Schweregrad-Zuordnung

Dies wird dem ServiceNow-Feld „Impact“ zugeordnet.
- **Info-Zuordnung**: `1`
- **Niedrig-Zuordnung**: `1`
- **Mittel-Zuordnung**: `2`
- **Hoch-Zuordnung**: `3`
- **Kritisch-Zuordnung**: `3`

### Details zur Status-Zuordnung

- **Name des Status-Felds**: `State`
- **Aktiv-Zuordnung**: `New`
- **Geschlossen-Zuordnung**: `Closed`
- **Falsch-positiv-Zuordnung**: `Resolved`
- **Risiko-akzeptiert-Zuordnung**: `Resolved`

Jede Zuordnung akzeptiert eine Standard-Statusbezeichnung (`New`, `In Progress`, `On Hold`, `Resolved`, `Closed`, `Cancelled`) oder einen numerischen Statuswert. Auf Instanzen mit angepassten Incident-Status – oder wenn eine andere Tabelle als `incident` das Ziel ist – verwenden Sie den numerischen **Statuswert** aus der Auswahlliste Ihrer Instanz; ein numerischer Wert außerhalb des Standardsatzes wird genau so an ServiceNow gesendet, wie er konfiguriert ist. Der integrierte Standardwert für den Resolution-Code begleitet nur die Standardstatus „resolved“/„closed“; kombinieren Sie benutzerdefinierte Statuswerte daher mit den unten beschriebenen Zuordnungen für Abschluss- und Resolution-Felder.

### Abschluss- und Resolution-Felder

Manche ServiceNow-Instanzen erzwingen eine Data Policy, die Felder wie den **Resolution code** (`close_code`) zwingend erforderlich macht, sobald ein Incident in einen aufgelösten oder geschlossenen Status wechselt. Schließt DefectDojo einen Incident ohne diese Felder, weist ServiceNow den Schreibvorgang mit HTTP 403 *„Data Policy Exception“* zurück, und der Grund wird in der Fehleransicht der Integration festgehalten.

Hängen Sie die erforderlichen Felder mit **Custom Field Mappings** an den Statuswechsel an und setzen Sie **Apply On** auf die Disposition, die sie tragen soll:

- **Transition to Closed** – wird gesendet, wenn ein Befund behoben/geschlossen wird.
- **Transition to False Positive** – wird gesendet, wenn ein Befund als Falsch-positiv markiert wird.
- **Transition to Risk Accepted** – wird gesendet, wenn für einen Befund das Risiko akzeptiert wird.

Um zum Beispiel einen zwingend erforderlichen Resolution code zu erfüllen:

| Source | Field Name | Value | Apply On |
|---|---|---|---|
| Static | `close_code` | `Resolved by DefectDojo` | Transition to Closed |
| Static | `close_notes` | `Reviewed by the security team` | Transition to Closed |
| Static | `close_code` | `Not a defect` | Transition to False Positive |

Hinweise:

- Field Name ist der ServiceNow-Spaltenname – `close_code`, `close_notes` oder ein benutzerdefiniertes `u_...`-Feld.
- Übergangszuordnungen greifen, wenn sich der Status des Datensatzes tatsächlich ändert: bei einem Befund, der beim ersten Übertragen bereits geschlossen ist, bei einer Aktualisierung, die den Datensatz schließt oder wieder öffnet, und beim erzwungenen Schließen, wenn eine Ticket-Verknüpfung gelöscht wird. Sie werden bei routinemäßigen Aktualisierungen eines unveränderten Datensatzes nicht erneut gesendet, sodass Journalfelder wie `work_notes` pro Übergang einen Eintrag erhalten.
- Referenzfelder wie `assignment_group` und `assigned_to` erwarten eine **sys_id** und keinen Anzeigenamen.
- Werte, die als JSON interpretierbar sind, werden typisiert gesendet: `true`, `42`, `[...]`, `{...}` – und `null`, wodurch das Feld geleert wird. Um solchen Text als wörtliche Zeichenkette zu senden, schließen Sie ihn in doppelte Anführungszeichen ein (z. B. `"null"`).
- `short_description`, `description`, `state`, `impact`, `urgency` und `priority` gehören zur Beschreibungsvorlage und zu den Schweregrad-/Status-Zuordnungen und können daher nicht über eine Zuordnung benutzerdefinierter Felder gesetzt werden.
- Auf anderen Tabellen als `incident` werden Statuswerte, die dem Standardsatz für Incidents entsprechen (`1`, `2`, `3`, `6`, `7`, `8`), weiterhin mit Incident-Semantik interpretiert – einschließlich des automatischen Standard-Resolution-Codes bei `6`/`7`/`8`. Bevorzugen Sie auf benutzerdefinierten Tabellen Statuswerte außerhalb dieses Bereichs, oder geben Sie die Abschlussfelder wie oben beschrieben explizit an.

## ServiceNow SecOps

Die ServiceNow-SecOps-Integration (auch bekannt als **ServiceNow SecOps / Vulnerability Response**) überträgt DefectDojo-Befunde und Befundgruppen in eine ServiceNow-Sicherheitstabelle – einen **Security Incident** (`sn_si_incident`) oder ein **Vulnerable Item** (`sn_vul_vulnerable_item`) – und hält den Datensatz synchron, während sich der Befund ändert (Erstellen, Aktualisieren und Auflösen/Schließen). Sie ist das Security-Operations-Gegenstück zur oben beschriebenen ServiceNow-Issue-Tracker-Integration; verwenden Sie ServiceNow SecOps, wenn Sie die Anwendungen Security Incident Response (SIR) oder Vulnerability Response (VR) einsetzen.

### Instanz-Einrichtung

- **Instance Label** sollte die Bezeichnung sein, mit der Sie diese Integration identifizieren möchten.
- **Location** sollte auf die URL Ihres ServiceNow-Servers gesetzt werden, zum Beispiel `https://your-organization.service-now.com/`.

ServiceNow SecOps unterstützt drei Authentifizierungsmethoden; geben Sie **eine** davon an:

- **OAuth 2.0** – geben Sie eine **Client ID**, ein **Client Secret** und ein **Refresh Token** ein. Sie erhalten diese genau so, wie im Abschnitt [ServiceNow](#servicenow) oben beschrieben (erstellen Sie einen OAuth-API-Endpunkt in der Application Registry und tauschen Sie Ihre Anmeldedaten dann unter `/oauth_token.do` gegen ein Refresh-Token). Alternativ können Sie **Client ID** und **Client Secret** zusammen mit einem **Username** und **Password** angeben, um anstelle eines Refresh-Tokens den OAuth-Password-Grant zu verwenden.
- **API Key** – geben Sie einen **API Key** ein, der als Header `x-sn-apikey` gesendet wird. Der Key authentifiziert nichts, solange auf der Instanz kein Inbound Authentication Profile und keine REST API Access Policy daran angehängt sind.
- **HTTP Basic** – geben Sie **Username** und **Password** des Servicekontos ein.

Das Servicekonto (oder der OAuth-Client) benötigt Schreibzugriff auf die Zieltabelle.

### Issue-Tracker-Zuordnung

- **Target Table** legt die ServiceNow-Tabelle fest, in die Datensätze geschrieben werden: **Security Incident** (`sn_si_incident`, der Standard) oder **Vulnerable Item** (`sn_vul_vulnerable_item`).

### Details zur Schweregrad-Zuordnung

Bei einem Security Incident wird dies dem Feld **Impact** zugeordnet; ServiceNow leitet die Incident-Priorität aus Impact und Urgency ab, sodass Urgency dem zugeordneten Impact folgt, sofern Sie sie nicht selbst zuordnen. Bei einem Vulnerable Item ordnen Sie den Schweregrad dem Risikofeld zu, das Ihre Instanz verwendet. Die Standardwerte unten entsprechen der Standard-SIR-Impact-Skala (`1` Hoch, `2` Mittel, `3` Niedrig) und sind bearbeitbar.

- **Name des Schweregrad-Felds**: `impact`
- **Info-Zuordnung**: `3`
- **Niedrig-Zuordnung**: `3`
- **Mittel-Zuordnung**: `2`
- **Hoch-Zuordnung**: `1`
- **Kritisch-Zuordnung**: `1`

### Details zur Status-Zuordnung

Dies wird dem Feld **State** des Datensatzes zugeordnet. Statuswerte sind numerische Codes, die sich zwischen den Tabellen Security Incident und Vulnerable Item unterscheiden und pro Instanz angepasst werden können; prüfen Sie sie daher gegen Ihre eigene Konfiguration. Die Standardwerte unten verwenden die Standard-SIR-Statuscodes (`16` Analysis, `3` Closed).

- **Name des Status-Felds**: `state`
- **Aktiv-Zuordnung**: `16`
- **Geschlossen-Zuordnung**: `3`
- **Falsch-positiv-Zuordnung**: `3`
- **Risiko-akzeptiert-Zuordnung**: `3`

Wird ein Datensatz geschlossen, setzt DefectDojo zusätzlich den ServiceNow-**Close Code** und die **Close Notes** (`Resolved` für geschlossene Befunde, `False positive` und `Risk accepted` für die entsprechenden Status).

### Verhalten speziell bei ServiceNow SecOps

- **Deduplizierung** – jeder Datensatz wird in seinem Feld `correlation_id` mit dem DefectDojo-Identifikator des Befunds oder der Befundgruppe gekennzeichnet. Bevor DefectDojo einen Datensatz erstellt, sucht es per `correlation_id` nach einem vorhandenen; ein Treffer wird übernommen und aktualisiert statt dupliziert, sodass erneute Synchronisierungen idempotent sind.
- **Aktualisierungen** werden im Journal **Work notes** des Datensatzes eingetragen (intern), niemals in kundenseitig sichtbaren Comments.
- **Auflösen beim Löschen** – das Löschen eines Befunds in DefectDojo löst bzw. schließt den ServiceNow-Datensatz (State + Close Code), anstatt ihn zu löschen; Datensätze werden niemals endgültig gelöscht.
- **Referenzfelder** – die optionalen Werte `cmdb_ci`, `assignment_group` und `assigned_to` dürfen als Anzeigenamen angegeben werden; DefectDojo löst jeden in seine `sys_id` auf. Ein Name, der nicht auflösbar ist, wird mit einer Warnung verworfen, anstatt die Übertragung fehlschlagen zu lassen.

## Shortcut

Die Shortcut-Integration ermöglicht es Ihnen, DefectDojo-Befunde als [Shortcut](https://www.shortcut.com/)-Stories zu übertragen. Stories werden mit dem Story-Typ „Bug“ erstellt und einem Team in Ihrem Shortcut-Workspace zugewiesen.

### Instanz-Einrichtung

- **Label** sollte die Bezeichnung sein, mit der Sie diese Integration identifizieren möchten.
- **Location** sollte auf `https://api.app.shortcut.com` gesetzt werden.
- **API Token** sollte auf ein Shortcut-API-Token gesetzt werden. Token können in Shortcut unter „Settings“, dann „Your Account“, dann [API Tokens](https://app.shortcut.com/settings/account/api-tokens) generiert werden.

### Issue-Tracker-Zuordnung

- **Team (Group) ID** sollte auf die UUID des Shortcut-Teams gesetzt werden, für das Stories erstellt werden. Sie finden diese UUID, indem Sie die Team-Seite in Shortcut öffnen und den Identifikator aus der URL kopieren, oder indem Sie die Shortcut-API aufrufen:

```
curl -H "Shortcut-Token: {{API_TOKEN}}" https://api.app.shortcut.com/api/v3/groups
```

### Details zur Schweregrad-Zuordnung

Jeder Schweregradwert wird der Story als Label zugewiesen. Labels werden in Shortcut automatisch erstellt, falls sie noch nicht existieren; die Standardwerte unten können also unverändert übernommen oder durch Labelnamen Ihrer Wahl ersetzt werden. Ändert sich der Schweregrad eines Befunds, wird das alte Schweregrad-Label von der Story entfernt und das neue hinzugefügt.

- **Name des Schweregrad-Felds**: `Label`
- **Info-Zuordnung**: `sev-info`
- **Niedrig-Zuordnung**: `sev-low`
- **Mittel-Zuordnung**: `sev-medium`
- **Hoch-Zuordnung**: `sev-high`
- **Kritisch-Zuordnung**: `sev-critical`

### Details zur Status-Zuordnung

Jeder Statuswert muss auf die numerische ID eines Workflow-States in Ihrem Shortcut-Workspace gesetzt werden. Workflow-State-IDs sind je Workspace eindeutig, daher gibt es keine Standardwerte. Sie können die Workflow-States und ihre IDs auflisten, indem Sie die Shortcut-API aufrufen:

```
curl -H "Shortcut-Token: {{API_TOKEN}}" https://api.app.shortcut.com/api/v3/workflows
```

- **Name des Status-Felds**: `Workflow State ID`
- **Aktiv-Zuordnung**: die ID des States für offene Arbeit, zum Beispiel ein Backlog- oder To-Do-State.
- **Geschlossen-Zuordnung**: die ID eines States vom Typ „Done“. Wenn ein Befund in DefectDojo gelöscht wird, wird seine Story in diesen State verschoben.
- **Falsch-positiv-Zuordnung**: die ID des States, der für Falsch-positiv-Befunde verwendet wird.
- **Risiko-akzeptiert-Zuordnung**: die ID des States, der für Befunde mit akzeptiertem Risiko verwendet wird.

## Freshservice

Die Freshservice-Integration ermöglicht es Ihnen, DefectDojo-Befunde und Befundgruppen als Freshservice-Tickets zu übertragen, die einer Agenten-Gruppe Ihrer Wahl zugewiesen werden.

### Instanz-Einrichtung

- **Label** sollte die Bezeichnung sein, mit der Sie diese Integration identifizieren möchten.
- **Location** sollte auf Ihre Freshservice-URL gesetzt werden: `https://yourcompany.freshservice.com`.
- **API Key** sollte ein Freshservice-API-Key sein.  Sie finden ihn, indem Sie auf Ihr Profilbild (oben rechts) > **Profile settings** klicken - der Key erscheint rechts unterhalb des Abschnitts **Delegate Approvals**, nachdem Sie das Captcha gelöst haben.  Wird dort kein Key angezeigt, ist der API-Zugriff möglicherweise auf Kontoebene deaktiviert und muss zuerst von einem Administrator aktiviert werden.
- **Requester Email** sollte die E-Mail-Adresse sein, in deren Namen Tickets angefordert werden.  Freshservice verlangt für jedes Ticket einen Anforderer, daher erstellt DefectDojo Tickets mit dieser Adresse als Anforderer.

### Issue-Tracker-Zuordnung

- **Group ID** sollte die numerische ID der Freshservice-Agenten-Gruppe sein, der Tickets zugewiesen werden.  Sie finden sie in der URL, während Sie die Gruppe unter **Admin > Agent Groups** ansehen.
- **Workspace ID** (optional) leitet Tickets bei Konten mit mehreren Workspaces an einen bestimmten Workspace.  Lassen Sie das Feld leer, um den primären Workspace zu verwenden.

### Details zur Schweregrad-Zuordnung

Dies wird dem Freshservice-Ticketfeld **Priority** zugeordnet, das numerische Codes verwendet (`1` Low, `2` Medium, `3` High, `4` Urgent).  Die Prioritätsnamen werden ebenfalls akzeptiert:

- **Name des Schweregrad-Felds**: `Priority`
- **Info-Zuordnung**: `1`
- **Niedrig-Zuordnung**: `1`
- **Mittel-Zuordnung**: `2`
- **Hoch-Zuordnung**: `3`
- **Kritisch-Zuordnung**: `4`

### Details zur Status-Zuordnung

Dies wird dem Ticketfeld **Status** zugeordnet, das numerische Codes verwendet (`2` Open, `3` Pending, `4` Resolved, `5` Closed).  Die Statusnamen werden ebenfalls akzeptiert:

- **Name des Status-Felds**: `Status`
- **Aktiv-Zuordnung**: `2`
- **Geschlossen-Zuordnung**: `5`
- **Falsch-positiv-Zuordnung**: `5`
- **Risiko-akzeptiert-Zuordnung**: `3`

Einige Freshservice-spezifische Verhaltensweisen, die Sie kennen sollten:

- Aktualisierungen synchronisieren den vollständigen Ticketinhalt - Freshservice erlaubt es, Betreff und Beschreibung nach dem Erstellen zu bearbeiten.
- Tickets werden geschlossen und nicht gelöscht, wenn ein Befund entfernt wird; Tickets, die bereits Resolved oder Closed sind, bleiben unberührt.  Beim Schließen wird automatisch eine Lösungsnotiz angehängt, sodass Konten, die eine solche verlangen (eine verbreitete Geschäftsregel), das Schließen akzeptieren.
- Manche Konten berechnen die Priorität eines Tickets aus einer Impact-/Urgency-Matrix oder einer Geschäftsregel und ignorieren die beim Erstellen gesendete Priorität.  DefectDojo erkennt dies und wendet die zugeordnete Priorität mit einer nachgelagerten Aktualisierung erneut an, sodass die Zuordnung dennoch wirksam wird.

## ServiceDesk Plus

Die Integration mit ManageEngine ServiceDesk Plus ermöglicht es Ihnen, DefectDojo-Befunde und Befundgruppen als ServiceDesk-Plus-Requests zu übertragen, die einer Support-Gruppe Ihrer Wahl zugewiesen werden.  Sowohl die **Cloud**-Edition (ServiceDesk Plus OnDemand) als auch die **On-Premises**-Edition werden von derselben Integration unterstützt - die Anmeldedaten, die Sie angeben, bestimmen, welcher Modus verwendet wird.

### Instanz-Einrichtung

- **Label** sollte die Bezeichnung sein, mit der Sie diese Integration identifizieren möchten.
- **Location** sollte auf Ihre ServiceDesk-Plus-URL gesetzt werden: `https://sdpondemand.manageengine.com` für die Cloud-Edition (oder Ihr regionales Äquivalent) beziehungsweise die Adresse Ihres Servers bei On-Premises-Installationen.

Geben Sie dann **einen** der beiden Anmeldedatensätze an:

#### On-Premises: Technician Key

- **Technician Key** sollte ein API-Key sein, der für einen Techniker auf Ihrem Server unter **Admin > General Settings > API** generiert wurde.  Lassen Sie die Zoho-OAuth-Felder leer.

#### Cloud: Zoho OAuth

Die Cloud-Edition authentifiziert sich über Zoho Accounts OAuth:

1. Öffnen Sie die [Zoho API Console](https://api-console.zoho.com/) und erstellen Sie einen **Self Client**.
2. Notieren Sie sich die **Client ID** und das **Client Secret**.
3. Geben Sie im Tab „Generate Code“ des Self Client den Scope `SDPOnDemand.requests.ALL` ein, wählen Sie eine Dauer und generieren Sie den Code.
4. Tauschen Sie den Code gegen ein Refresh-Token:

```
curl --request POST \
 --url 'https://accounts.zoho.com/oauth/v2/token' \
 --data 'grant_type=authorization_code' \
 --data 'client_id={{CLIENT_ID}}' \
 --data 'client_secret={{CLIENT_SECRET}}' \
 --data 'code={{GENERATED_CODE}}'
```

5. Geben Sie die **Client ID**, das **Client Secret** und das zurückgegebene **Refresh Token** im Instanzformular ein.  Wird Ihr Konto außerhalb des US-Rechenzentrums gehostet, setzen Sie die **Token URL** auf Ihren regionalen Zoho-Accounts-Endpunkt (zum Beispiel `https://accounts.zoho.eu/oauth/v2/token`).

### Issue-Tracker-Zuordnung

- **Group Name** sollte der Name der ServiceDesk-Plus-Support-Gruppe sein, der Requests zugewiesen werden, genau so, wie er unter **Admin > Users > Support Groups** erscheint.

### Details zur Schweregrad-Zuordnung

Dies wird dem ServiceDesk-Plus-Request-Feld **Priority** anhand des Namens zugeordnet, unter Verwendung der Prioritätsnamen Ihres Kontos:

- **Name des Schweregrad-Felds**: `Priority`
- **Info-Zuordnung**: `Low`
- **Niedrig-Zuordnung**: `Normal`
- **Mittel-Zuordnung**: `Medium`
- **Hoch-Zuordnung**: `High`
- **Kritisch-Zuordnung**: `High`

### Details zur Status-Zuordnung

Dies wird dem Request-Feld **Status** anhand des Namens zugeordnet.  Die Standardwerte verwenden die integrierten Status:

- **Name des Status-Felds**: `Status`
- **Aktiv-Zuordnung**: `Open`
- **Geschlossen-Zuordnung**: `Closed`
- **Falsch-positiv-Zuordnung**: `Closed`
- **Risiko-akzeptiert-Zuordnung**: `On Hold`

Einige ServiceDesk-Plus-spezifische Verhaltensweisen, die Sie kennen sollten:

- Aktualisierungen synchronisieren den vollständigen Request-Inhalt - anders als die meisten Tracker erlaubt ServiceDesk Plus es, Betreff und Beschreibung nach dem Erstellen zu bearbeiten.
- Requests werden geschlossen und nicht gelöscht, wenn ein Befund entfernt wird; Requests, die bereits Closed oder Resolved sind, bleiben unberührt.
- Macht Ihr Konto beim Schließen Felder zwingend erforderlich (zum Beispiel eine Lösung), kann ein von DefectDojo angestoßenes Schließen von diesen Regeln abgewiesen werden und erscheint dann in der Fehlertabelle der Integration.

## Zendesk

Die Zendesk-Integration ermöglicht es Ihnen, DefectDojo-Befunde und Befundgruppen als Zendesk-Tickets zu übertragen, die einer Zendesk-Gruppe Ihrer Wahl zugewiesen werden.

### Instanz-Einrichtung

- **Label** sollte die Bezeichnung sein, mit der Sie diese Integration identifizieren möchten.
- **Location** sollte auf die URL Ihres Zendesk-Kontos gesetzt werden, zum Beispiel `https://your-subdomain.zendesk.com`.
- **Email** sollte die E-Mail-Adresse des Zendesk-Agenten sein, zu dem das API-Token gehört.
- **API Token** sollte auf ein Zendesk-API-Token gesetzt werden.  Ein Administrator kann eines im Zendesk Admin Center unter **Apps and integrations > APIs > Zendesk API** erstellen (der Token-Zugriff muss aktiviert sein).

### Issue-Tracker-Zuordnung

- **Group ID** sollte die numerische ID der Zendesk-Gruppe sein, der Tickets zugewiesen werden.  Sie finden sie im Admin Center unter **People > Team > Groups** oder in der URL, während Sie die Gruppe ansehen.

### Details zur Schweregrad-Zuordnung

Dies wird dem Zendesk-Ticketfeld **Priority** zugeordnet, das `low`, `normal`, `high` und `urgent` akzeptiert:

- **Name des Schweregrad-Felds**: `Priority`
- **Info-Zuordnung**: `low`
- **Niedrig-Zuordnung**: `low`
- **Mittel-Zuordnung**: `normal`
- **Hoch-Zuordnung**: `high`
- **Kritisch-Zuordnung**: `urgent`

### Details zur Status-Zuordnung

Zendesk-Tickets unterstützen die Status `new`, `open`, `pending`, `hold`, `solved` und `closed`.  Beachten Sie, dass `hold` in Ihrem Konto aktiviert sein muss, bevor es verwendet werden kann.

- **Name des Status-Felds**: `Status`
- **Aktiv-Zuordnung**: `new`
- **Geschlossen-Zuordnung**: `solved`
- **Falsch-positiv-Zuordnung**: `solved`
- **Risiko-akzeptiert-Zuordnung**: `pending`

Einige Zendesk-spezifische Verhaltensweisen, die Sie kennen sollten:

- Die Ticketbeschreibung ist in Zendesk der erste Kommentar und kann nach dem Erstellen nicht bearbeitet werden; beim Übertragen eines aktualisierten Befunds werden daher Betreff, Priorität und Status des Tickets synchronisiert, Änderungen der Beschreibung jedoch nicht.
- Tickets werden als `solved` markiert und nicht gelöscht, wenn ein Befund entfernt wird; Zendesk schließt gelöste Tickets nach einer bestimmten Zeit automatisch.
- `closed` ist ein endgültiger Status - geschlossene Tickets können überhaupt nicht mehr aktualisiert werden, und das Übertragen eines Befunds, dessen Ticket geschlossen ist, meldet einen Fehler.
