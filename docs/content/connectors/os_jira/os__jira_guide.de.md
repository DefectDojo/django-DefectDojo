---
title: Jira
description: Arbeiten Sie mit der Jira-Integration
weight: 2
audience: opensource
aliases:
- /de/issue_tracking/jira/os__jira_guide/
---

DefectDojo's Jira-Integration kann verwendet werden, um Befund-Daten an einen oder mehrere Jira-Spaces zu übertragen. Auf diese Weise können Sie DefectDojo in Ihren üblichen Entwicklungsworkflow integrieren. Hier sind einige Beispiele, wie das funktionieren kann:

* Das AppSec-Team kann Befunde selektiv an einen von Entwicklern genutzten Jira-Space übertragen, sodass die Behebung von Issues angemessen neben der regulären Entwicklung priorisiert werden kann. Entwickler, die mit diesem Board arbeiten, müssen nicht auf DefectDojo zugreifen - sie können ihre gesamte Arbeit an einem Ort erledigen.
* DefectDojo kann ALLE Befunde an einen bidirektionalen Jira-Space übertragen, den das AppSec-Team nutzt, sodass die Validierung von Issues aufgeteilt werden kann. Dieses Board bleibt mit DefectDojo synchron und ermöglicht komplexe Workflows zur Behebung.
* DefectDojo kann Befunde aus separaten Produkten und/oder Engagements selektiv an separate Jira-Spaces übertragen, um alles im richtigen Kontext zu halten.

# Jira einrichten

Für die Einrichtung von Jira sind folgende Schritte erforderlich:
1. Aktivieren Sie die Jira-Integration in den Systemeinstellungen. Bis Sie dies tun, sind die übrigen Jira-Einstellungen in DefectDojo überall ausgeblendet.
2. Verbinden Sie eine Jira-Instanz, entweder mit einem Benutzernamen/Passwort oder einem API-Token. Es können mehrere Instanzen verknüpft werden.
3. Fügen Sie diese Jira-Instanz einem oder mehreren Produkten oder Engagements in DefectDojo hinzu.
4. Wenn Sie die bidirektionale Synchronisierung nutzen möchten, erstellen Sie einen Jira-Webhook, der Updates an DefectDojo sendet.

## Schritt 1: Aktivieren Sie die Jira-Integration in den Systemeinstellungen

Die Jira-Integration ist standardmäßig deaktiviert, und solange sie deaktiviert ist, blendet DefectDojo alle übrigen Jira-Steuerelemente in der Oberfläche aus. Dies ist als Erstes zu konfigurieren: Keiner der folgenden Schritte ist verfügbar, bevor sie aktiviert wurde.

Solange die Integration deaktiviert ist, erscheint der Eintrag ⚙️ **Configuration \> JIRA** nicht in der Seitenleiste, sodass es keine Möglichkeit gibt, eine Jira-Instanz hinzuzufügen:

![image](images/jira-config-menu-hidden-os.png)

### Aktivieren Sie die Integration

1. Navigieren Sie in der DefectDojo-Seitenleiste zu ⚙️ **Configuration \> System Settings**.
​
2. Aktivieren Sie **Enable JIRA integration**.
​
3. Sobald die Integration aktiviert ist, wird ein **Jira webhook secret** benötigt. Klicken Sie auf das 🔄-Symbol neben dem Feld, um eines zu generieren. Wenn Sie das Formular ohne Secret absenden, wird es mit der Meldung *"This field is required when enable Jira Integration is True"* abgelehnt:

![image](images/jira-webhook-secret-required-os.png)

Das Secret ist Teil der Webhook-URL, an die Jira sendet (`https://<YOUR DOJO DOMAIN>/jira/webhook/<SECRET>`); behandeln Sie den generierten Wert daher wie ein Credential. Sie müssen es Jira nur dann übergeben, wenn Sie die bidirektionale Synchronisierung in [Schritt 4](#step-4-configure-bidirectional-sync-jira-webhook) einrichten; das Generieren an dieser Stelle erfüllt lediglich die Formularanforderung.

4. Klicken Sie auf **Submit**. ⚙️ **Configuration \> JIRA** erscheint nun in der Seitenleiste:

![image](images/jira-enable-system-settings-os.png)

### Was diese Einstellung steuert

Das Aktivieren von **Enable JIRA integration** sorgt dafür, dass die übrige Jira-Oberfläche erscheint. Wenn sie aktiviert ist, erhalten Sie:

* die Seite ⚙️ **Configuration \> JIRA**, auf der Jira-Instanzen hinzugefügt und bearbeitet werden
* den Bereich **JIRA** in den Formularen Edit Product (Asset) und Edit Engagement, mit dem ein Produkt oder Engagement mit einem Jira-Space verknüpft wird
* die Steuerelemente **Push to Jira** bei Befunden, Finding Groups und Bulk-Edit-Formularen sowie die Jira-Spalten und -Filter in den Listen für Befunde, Engagements und Produkte

Zum Beispiel erscheint der Bereich **JIRA** erst am unteren Ende des Edit-Product-Formulars, sobald die Integration aktiviert ist:

![image](images/jira-asset-settings-visible-os.png)

Die Einstellung steuert die Integration auch außerhalb der Benutzeroberfläche: Solange sie deaktiviert ist, überträgt DefectDojo keine Befunde an Jira (einschließlich über die API gesendeter `push_to_jira`-Anfragen), und eingehende Jira-Webhooks werden ignoriert.

Die übrigen Jira-Felder auf der Seite System Settings (**Enable JIRA web hook**, **Jira minimum severity**, **Jira labels**, **Add vulnerability Id as a JIRA label**) bleiben unabhängig davon sichtbar, ob die Integration aktiviert oder deaktiviert ist, haben aber keine Wirkung, bevor sie aktiviert wurde.

## Schritt 2: Verbinden Sie eine Jira-Instanz

Sobald die Integration aktiviert ist, besteht der nächste Schritt bei der Einrichtung der Jira-Integration von DefectDojo darin, eine Jira-Instanz zu verbinden. Bitte beachten Sie, dass Jira Service Management derzeit nicht unterstützt wird.

#### Erforderliche Informationen von Jira

Atlassian verwendet unterschiedliche Authentifizierungsmethoden für Jira Cloud und Jira Data Center.

für **Jira Cloud** benötigen Sie:
* eine Jira-URL, z. B. https://yourcompany.atlassian.net/
* ein Konto mit Berechtigungen zum Erstellen und Aktualisieren von Issues in Ihrer Jira-Instanz. Dies kann sein:
    * eine standardmäßige Kombination aus **Benutzername/Passwort**
    * eine Kombination aus **Benutzername/API-Token**

für **Jira Data Center (oder Server)** benötigen Sie:
* eine Jira-URL, z. B. https://jira.yourcompany.com
* ein Konto mit Berechtigungen zum Erstellen und Aktualisieren von Issues in Ihrer Jira-Instanz. Dies kann sein:
    * eine standardmäßige Kombination aus **Benutzername/Passwort**

Optional können Sie zuordnen:
* Jira-Transitions, die das erneute Öffnen und Schließen von Befunden auslösen
* Jira-Resolutions, die den Status Risiko akzeptiert und Falsch-positiv auf Befunde anwenden können (optional)

Eine einzelne Jira-Instanzverbindung kann mehrere Jira-Spaces verwalten, solange das von DefectDojo verwendete Jira-Konto bzw. Token über die Berechtigung verfügt, Issues im jeweiligen Jira-Space zu erstellen.

### Fügen Sie eine Jira-Instanz hinzu

1. Stellen Sie sicher, dass **Enable JIRA integration** in den System Settings aktiviert ist, wie in [Schritt 1](#step-1-enable-the-jira-integration-in-system-settings) beschrieben. Die Option ⚙️ **Configuration \> JIRA** erscheint erst dann in der Seitenleiste.
​
2. Navigieren Sie in der DefectDojo-Seitenleiste zur Seite ⚙️ **Configuration \> JIRA**.
​
![image](images/Connect_DefectDojo_to_Jira.png)

3. Sie sehen eine Liste aller derzeit konfigurierten Jira-Spaces, die mit DefectDojo verknüpft sind. Um eine neue Project Configuration hinzuzufügen, klicken Sie auf das Schraubenschlüssel-Symbol und wählen Sie entweder **Add Jira Configuration (Express)** oder **Add Jira Configuration**.

#### Add Jira Configuration (Express)

Die Express-Methode ermöglicht eine schnellere Verknüpfung eines Spaces. Verwenden Sie die Express-Methode, wenn Sie einen Jira-Space einfach schnell verbinden möchten und keinen komplexen Jira-Workflow haben.

![image](images/Connect_DefectDojo_to_Jira_2.png)

1. Wählen Sie einen Namen für diese Jira Configuration zur Verwendung in DefectDojo. Dieser Name ist lediglich eine Bezeichnung für die Instanzverbindung in DefectDojo und muss keinen Bezug zu Jira-Daten haben.
​
2. Wählen Sie die URL der Jira-Instanz Ihres Unternehmens - vermutlich ähnlich wie `https://**yourcompany**.atlassian.net`, wenn Sie eine Jira-Cloud-Installation verwenden.
​
3. Geben Sie eine passende Authentifizierungsmethode in die Felder Username / Password für Jira ein:
    * Für die standardmäßige **Jira-Authentifizierung mit Benutzername/Passwort** geben Sie einen Jira-Benutzernamen und das zugehörige Passwort in diese Felder ein.
    * Für die Authentifizierung mit dem **API-Token eines Benutzers (Jira Cloud)** geben Sie den Benutzernamen zusammen mit dem zugehörigen **API-Token** in das Passwortfeld ein.
​
4. Wählen Sie den Default issue type, mit dem Issues in Jira erstellt werden sollen. Die Optionen hierfür sind **Bug, Task, Story** und **Epic** (Standard-Issue-Typen von Jira) sowie **Spike** und **Security**, die benutzerdefinierte Issue-Typen sind. Wenn Sie einen anderen Issue-Typ verwenden möchten, wenden Sie sich bitte an [support@defectdojo.com](mailto:support@defectdojo.com).
​
5. Wählen Sie Ihr Issue Template, das die Issue Description bestimmt, wenn Issues in Jira erstellt werden.

Die beiden Typen sind:
- **Jira\_full**, das alle Befund-Informationen in Jira-Issues aufnimmt
- **Jira\_limited**, das eine geringere Menge an Befund-Informationen und Metadaten aufnimmt.

Wenn Sie dieses Feld leer lassen, wird standardmäßig **Jira\_full** verwendet.

6. Wählen Sie einen oder mehrere Jira Resolution-Typen aus, die den Status eines Befunds auf Accepted ändern (wenn die Resolution beim Issue ausgelöst wird). Wenn Sie diese Automatisierung nicht nutzen möchten, können Sie das Feld leer lassen.
​
7. Wählen Sie einen oder mehrere Jira Resolution-Typen aus, die den Status eines Befunds auf Falsch-positiv ändern (wenn die Resolution beim Issue ausgelöst wird). Wenn Sie diese Automatisierung nicht nutzen möchten, können Sie das Feld leer lassen.
​
8. Entscheiden Sie, ob Sie SLA Notifications als Kommentar auf einem Jira-Issue senden möchten.
​
9. Entscheiden Sie, ob Befunde automatisch mit Jira synchronisiert werden sollen. Wenn dies aktiviert ist, werden Jira-Issues automatisch mit den zugehörigen Befunden synchron gehalten. Ist dies nicht aktiviert, müssen Sie Änderungen an einem Befund manuell übertragen, nachdem das Issue in Jira erstellt wurde.
​
10. Wählen Sie Ihren Issue key. In Jira ist dies die einem Issue zugeordnete Zeichenfolge (z. B. das Wort **'EXAMPLE'** in einem Issue namens **EXAMPLE\-123**). Wenn Sie Ihren Issue Key nicht kennen, erstellen Sie ein neues Issue im Jira-Space. Im folgenden Screenshot sehen wir, dass der Issue Key in unserem Jira-Space **DEF** lautet.
​
![image](images/Connect_DefectDojo_to_Jira_3.png)
​
11. Klicken Sie auf **Submit.** DefectDojo sucht automatisch nach passenden Mappings in Jira und fügt sie der Konfiguration hinzu. Sie können diese Konfiguration nun mit einem oder mehreren Produkten in DefectDojo verknüpfen.

#### Add Jira Configuration (Standard)

Die Standard Jira Configuration fügt einige zusätzliche Schritte hinzu, die eine präzisere Steuerung von Jira-Mappings und -Interaktionen ermöglichen. Dies kann auch nachträglich geändert werden, nachdem eine Jira-Konfiguration hinzugefügt wurde, selbst wenn sie mit der Express-Methode erstellt wurde.
​
### Zusätzliche Formularoptionen

* **Epic Name ID:** Wenn Sie mehrere Epic-Typen in Jira haben, können Sie den gewünschten festlegen, indem Sie dessen ID in der Jira Field Spec ermitteln.
​
Um die 'Epic name id' zu ermitteln, rufen Sie `https://<YOUR JIRA URL>/rest/api/2/field` auf und suchen Sie nach Epic Name. Kopieren Sie die Nummer aus `number` und fügen Sie sie hier ein.
​  ​
* **Reopen Transition ID:** Wenn Sie eine bestimmte Jira-Transition zum erneuten Öffnen eines Issues verwenden möchten, können Sie hier die Transition ID angeben. Bei Verwendung der Express Jira Configuration findet DefectDojo automatisch eine passende Transition und erstellt das Mapping.
​
Rufen Sie `https://<YOUR JIRA URL>/rest/api/latest/issue/<ANY VALID ISSUE KEY>/transitions?expand-transitions.fields` auf, um die ID für Ihre Jira-Instanz zu finden. Fügen Sie sie in das Feld Reopen Transition ID ein.
​
* **Close Transition ID:** Wenn Sie eine bestimmte Jira-Transition zum Schließen eines Issues verwenden möchten, können Sie hier die Transition ID angeben. Bei Verwendung der **Express Jira Configuration** findet DefectDojo automatisch eine passende Transition und erstellt das Mapping.
​
Rufen Sie `https://<YOUR JIRA URL>/rest/api/latest/issue/<ANY VALID ISSUE KEY>/transitions?expand-transitions.fields` auf, um die ID für Ihre Jira-Instanz zu finden. Fügen Sie sie in das Feld Close Transition ID ein.
​
* **Mapping Severity Fields:** Jedem Jira-Issue ist eine Priority zugeordnet, die DefectDojo automatisch anhand des Schweregrads eines Befunds vergibt. Geben Sie die Namen der jeweiligen Priority ein, denen Sie die Schweregrade Info, Niedrig, Mittel, Hoch und Kritisch zuordnen möchten.

* **Finding Text** \- wenn Sie jedem erstellten Issue zusätzlichen standardisierten Text hinzufügen möchten, können Sie diesen Text hier eingeben. Dies ist kein Text, der einem Feld in Jira zugeordnet wird, sondern zusätzlicher Text, der der Issue Description hinzugefügt wird. Zum Beispiel "**Created by DefectDojo**".

Kommentare (in Jira) und Notizen (in DefectDojo) können synchron gehalten werden. Diese Einstellung kann aktiviert werden, sobald die Jira-Konfiguration einem Produkt hinzugefügt wurde, über das Formular **Edit Product**.

## Schritt 3: Verbinden Sie ein Produkt oder Engagement mit Jira

Jedes Produkt bzw. Engagement in DefectDojo verfügt über eigene Einstellungen, die bestimmen, wie Befunde in JIRA-Issues umgewandelt werden. Von hier aus können Sie den zugehörigen Jira-Space festlegen und das Standardverhalten beim Erstellen von Issues, Epics, Labels und anderen JIRA-Metadaten einstellen.

### Fügen Sie Jira einem Produkt oder Engagement hinzu

In der Classic UI finden Sie die Jira-Einstellungen, indem Sie das Formular Edit Product oder Edit Engagement öffnen. Schaltfläche "**📝 Edit**" unter **Settings** auf der Seite:

![image](images/Add_a_Connected_Jira_Project_to_a_Product.png)

#### Liste der Jira-Einstellungen

Die Jira-Einstellungen befinden sich weiter unten auf der Seite Product Settings.

![image](images/Add_a_Connected_Jira_Project_to_a_Product_2.png)

#### Jira Instance

Wenn Sie mehrere Jira-Instanzen für separate Produkte oder Teams innerhalb Ihrer Organisation eingerichtet haben, können Sie angeben, in welchem Jira-Space DefectDojo Issues erstellen soll. Wählen Sie ein Project aus dem Dropdown-Menü.

Wenn in diesem Menü keine Jira-Instanzen aufgeführt sind, prüfen Sie, ob diese Projects in Ihrer globalen Jira Configuration für DefectDojo verbunden sind - yourcompany.defectdojo.com/jira.

#### Project key

Dies ist der Key des Space, den Sie mit DefectDojo verwenden möchten.  Der Space Key für ein bestimmtes Project findet sich in der URL oder unter "Space key" in den Space Settings.

![image](images/Add_a_Connected_Jira_Project_to_a_Product_3.png)

#### Issue template

Hier legen Sie fest, wie viele DefectDojo-Metadaten an Jira gesendet werden sollen. Wählen Sie eine von zwei Optionen:

* **jira\_full**: Issues übernehmen alle Parameter aus DefectDojo - eine vollständige Description, CVE, Severity usw. Nützlich, wenn Sie den vollständigen Kontext eines Befunds in Jira benötigen (zum Beispiel, wenn jemand an diesem Issue arbeitet, der keinen Zugriff auf DefectDojo hat).

Hier ist ein Beispiel für ein **jira\_full**-Issue:
​
![image](images/Add_a_Connected_Jira_Project_to_a_Product_4.png)

* **Jira\_limited:** Issues übernehmen nur den DefectDojo-Link, die Product/Engagement/Test-Links, sowie die Felder Reporter und Environment. Alle anderen Felder werden nur in DefectDojo erfasst. Nützlich, wenn Sie in Jira keinen vollständigen Befund-Kontext benötigen (zum Beispiel, wenn jemand an diesem Issue arbeitet, der überwiegend in DefectDojo arbeitet und das vollständige Bild nicht zusätzlich in JIRA benötigt.)

​Hier ist ein Beispiel für ein **jira\_limited**-Issue:​

![image](images/Add_a_Connected_Jira_Project_to_a_Product_5.png)

#### Component

Wenn Sie Ihren Jira-Space über Components verwalten, können Sie hier die passende Component für DefectDojo zuweisen. Um mehr als eine Component zuzuweisen, geben Sie eine durch Kommas getrennte Liste ein (zum Beispiel `Security, DevSecOps`); jeder Wert wird als separate Component an Jira gesendet.

**Custom fields**

Wenn Sie bei DefectDojo-Issues keine Custom Fields benötigen, können Sie dieses Feld auf 'null' belassen.

Wenn jedoch Ihre Jira Space Settings **erfordern**, dass bei neuen Issues Custom Fields verwendet werden, müssen Sie diese Mappings fest codieren.

**Jira Cloud ermöglicht es Ihnen inzwischen, einen Default-Wert für ein Custom Field direkt in der App zu erstellen. Weitere Informationen zur Konfiguration finden Sie in [Atlassians Dokumentation zu Custom Fields](https://support.atlassian.com/jira-cloud-administration/docs/configure-a-custom-field/).**

Beachten Sie, dass DefectDojo keine Issue-spezifischen Metadaten als Custom Fields senden kann, sondern nur einen Default-Wert. Dieser Abschnitt sollte nur eingerichtet werden, wenn Ihr Jira-Space **erfordert, dass diese Custom Fields existieren** in jedem Issue in Ihrem Space.

Folgen Sie **[dieser Anleitung](#custom-fields-in-jira)**, um mit der Arbeit an Custom Fields zu beginnen.

**Jira labels**

Wählen Sie die relevanten Labels aus, mit denen das Issue in Jira erstellt werden soll, z. B. **DefectDojo**, **YourProductName..**

![image](images/Add_a_Connected_Jira_Project_to_a_Product_6.png)

#### Default assignee

Der Name des Default Assignee in Jira. Wenn dieses Feld leer bleibt, folgt DefectDojo beim Erstellen von Issues dem Standardverhalten Ihres Jira-Space.

### Zusätzliche Formularoptionen

#### Enable Connection With Jira Space

Jira-Integrationen können nur dann aus Ihrer Instanz entfernt werden, wenn noch keine zugehörigen Issues erstellt wurden.  Wurden bereits Issues erstellt, gibt es keine Möglichkeit, eine Jira-Instanz vollständig aus DefectDojo zu entfernen.

Sie können Ihre Jira-Integration jedoch deaktivieren, indem Sie sie auf Produktebene deaktivieren. Dadurch werden vorhandene, von DefectDojo erstellte Jira-Tickets weder gelöscht noch geändert, aber weitere Updates werden deaktiviert.

#### Add Vulnerability Id as a Jira label

Damit können Sie die Vulnerability-ID-Daten automatisch als Jira Label hinzufügen. Vulnerability-IDs werden Befunden von einzelnen Sicherheitstools hinzugefügt - dabei kann es sich um Common Vulnerabilities and Exposures (CVE)-IDs oder ein anderes, für das meldende Tool spezifisches Format handeln.

#### Enable Engagement Epic Mapping (For Products)

In DefectDojo repräsentieren Engagements eine Sammlung von Arbeit. Jedes Engagement enthält einen oder mehrere Tests, die wiederum einen oder mehrere zu behebende Befunde enthalten. Epics in Jira funktionieren auf ähnliche Weise, und mit dieser Checkbox können Sie Engagements als Epics an Jira übertragen.

* Ein Engagement in DefectDojo - beachten Sie die drei unten aufgeführten Befunde.
​
![image](images/Add_a_Connected_Jira_Project_to_a_Product_8.png)
* Wie dasselbe Engagement beim Übertragen an JIRA zu einem Epic wird - die Befunde des Engagements werden ebenfalls übertragen und liegen innerhalb des Engagements als Child Issues vor.

![image](images/Add_a_Connected_Jira_Project_to_a_Product_9.png)

#### Push All Issues

Wenn aktiviert, überträgt DefectDojo automatisch alle aktiven und verifizierten Befunde als Issues an Jira. Wenn nicht aktiviert, müssen alle Befunde manuell an Jira übertragen werden.

#### Push Notes

Wenn aktiviert, werden Jira-Kommentare beim zugehörigen Befund in DefectDojo unter Notes zum Issue (Screenshot) übernommen, und umgekehrt; Notizen zu Befunden werden dem zugehörigen Jira-Issue als Comments hinzugefügt.

#### Send SLA Notifications As Comments

Wenn aktiviert, erhalten Issues, die gegen die Service-Level-Agreement-Regeln von DefectDojo verstoßen, einen entsprechenden Kommentar im Jira-Issue. Diese Kommentare werden täglich gepostet, bis das Issue gelöst ist.

Service Level Agreements können unter **Configuration \> SLA Configuration** in DefectDojo konfiguriert und jedem Produkt zugewiesen werden.

#### Send Risk Acceptance Expiration Notifications As Comment?

Wenn aktiviert, erhält jedes Issue, dessen zugehörige DefectDojo Risikoakzeptanz abläuft, einen entsprechenden Kommentar im Jira-Issue. Diese Kommentare werden täglich gepostet, bis das Issue gelöst ist.

### Jira-Einstellungen auf Engagement-Ebene

Dadurch können verschiedene Engagements innerhalb eines Produkts unterschiedliche zugrunde liegende Jira-Einstellungen haben. Standardmäßig '**inherit Jira settings from product'** die Engagements, das heißt, sie übernehmen dieselben Jira-Einstellungen wie das Produkt, unter dem sie verschachtelt sind.

Sie können jedoch **Product Key**, **Issue Template, Custom Fields, Jira Labels, Default Assignee** eines Engagements so ändern, dass sie von den Standard-Produkteinstellungen abweichen

Sie erreichen diese Seite über die Seite **Edit Engagement**: **your\-instance.defectdojo.com/engagement/\[id]/edit**.

Die Seite Edit Engagement finden Sie über die Engagement-Seite, indem Sie auf das ☰-Menü neben der Description des Engagements klicken.

![image](images/Creating_Issues_in_Jira_5.png)

## Schritt 4: Konfigurieren Sie die bidirektionale Synchronisierung: Jira Webhook

Die Jira-Integration ermöglicht die bidirektionale Synchronisierung über Webhook. DefectDojo empfängt Jira-Benachrichtigungen an einer eindeutigen Adresse, wodurch je nach Konfiguration Jira-Kommentare bei Befunden empfangen oder Befunde über Jira gelöst werden können.

### Finden Sie Ihre Jira-Webhook-URL

Ihr Jira Webhook setzt sich aus Ihrer DefectDojo-URL und dem **Jira webhook secret** zusammen, das Sie in [Schritt 1](#step-1-enable-the-jira-integration-in-system-settings) generiert haben.  Beide werden auf der Seite ⚙️ **Configuration \> System Settings** neben dem Feld **Jira webhook secret** angezeigt (siehe Screenshot in Schritt 1).

Außerdem müssen Sie auf derselben Seite **Enable JIRA web hook** aktivieren, bevor DefectDojo eingehende Jira-Benachrichtigungen verarbeitet.  Eingehende Webhooks werden ignoriert, wenn entweder diese Option oder **Enable JIRA integration** deaktiviert ist.

### Erstellen Sie den Jira Webhook

1. Rufen Sie `**https:// \<YOUR JIRA URL\> /plugins/servlet/webhooks**` auf
2. Klicken Sie auf 'Create a Webhook'.
3. Geben Sie im Feld 'URL' Folgendes ein: `https:// \<**YOUR DOJO DOMAIN**\> /jira/webhook/ \<**YOUR GENERATED WEBHOOK SECRET**\>`. Das Web Hook Secret ist wie oben beschrieben neben dem Feld **Jira webhook secret** aufgeführt.
4. Aktivieren Sie unter 'Comments' die Option 'Created'. Aktivieren Sie unter Issue die Option 'Updated'.
5. Stellen Sie sicher, dass Ihre JIRA-Instanz dem von Ihrer DefectDojo-Instanz verwendeten SSL-Zertifikat vertraut. Für JIRA Cloud muss DefectDojo [ein gültiges SSL/TLS-Zertifikat verwenden, das von einer global vertrauenswürdigen Zertifizierungsstelle signiert wurde](https://developer.atlassian.com/cloud/jira/platform/deprecation-notice-registering-webhooks-with-non-secure-urls/)

Beachten Sie, dass Sie zur Nutzung dieses Webhooks kein Secret innerhalb von Jira erstellen müssen. Das Secret ist Bestandteil der URL von DefectDojo, sodass es genügt, die vollständige URL in das Jira-Webhook-Formular einzutragen.

Eingehende Webhook-Anfragen werden über das Secret in dieser URL authentifiziert; behandeln Sie die vollständige URL daher wie ein Credential und halten Sie sie geheim.

#### Testen Sie den Webhook

Sobald ein oder mehrere Issues aus DefectDojo-Befunden erstellt wurden, können Sie den Webhook testen, indem Sie einem dieser Befunde einen Comment hinzufügen. Der Comment sollte vom Jira-Webhook als Notiz empfangen werden.

Wenn dies nicht korrekt funktioniert, könnte dies an einem Firewall-Problem auf Ihrer Jira-Instanz liegen, das den Webhook blockiert.

* Die Firewall Rules von DefectDojo enthalten eine Checkbox für **Jira Cloud,** die aktiviert sein muss, bevor DefectDojo Webhook-Nachrichten von Jira empfangen kann.

### Alternative: Verwendung von Jira Automation (Send web request)

Manche Jira-Instanzen erlauben keine System-Webhooks unter `/plugins/servlet/webhooks` — zum Beispiel wenn dieser Administrationsbereich eingeschränkt ist und nur **Jira Automation**-Regeln zulässig sind. In diesem Fall können Sie dieselbe bidirektionale Synchronisierung über die Aktion **Send web request** von Automation steuern, die an denselben DefectDojo-Webhook-Endpunkt sendet.

Der Webhook-Endpunkt von DefectDojo akzeptiert jeden HTTP-`POST` mit `Content-Type: application/json` und einem gültigen Secret im URL-Pfad. Er erfordert **nicht**, dass die Anfrage vom System-Webhook-Mechanismus von Jira stammt, sodass die Aktion "Send web request" von Automation als direkter Ersatz funktioniert.

#### Voraussetzungen

Es gelten dieselben Voraussetzungen wie beim System-Webhook:

* **Enable JIRA integration** und **Enable JIRA web hook** sind beide auf der Seite ⚙️ **Configuration \> System Settings** aktiviert.
* Auf dieser Seite ist ein nicht leeres **Jira webhook secret** festgelegt. Das Secret darf nur die Zeichen `A-Z`, `a-z`, `0-9`, `_` und `-` enthalten.
* Der Befund (bzw. die Finding Group) ist bereits mit dem Jira-Issue verknüpft. Ist das Issue mit keinem DefectDojo-Befund verknüpft, wird die Anfrage zwar weiterhin akzeptiert (HTTP `200`), es erfolgt jedoch keine Aktion.

#### Wie DefectDojo die Anfrage verarbeitet

* DefectDojo verzweigt anhand eines Felds `webhookEvent` auf oberster Ebene. Nur `"jira:issue_updated"` und `"comment_created"` werden verarbeitet; jeder andere Wert wird akzeptiert, aber ignoriert. Automation fügt dieses Feld **nicht** von sich aus hinzu, Sie müssen es also selbst in den Request Body aufnehmen.
* Setzen Sie deshalb den **Body** der Anfrage auf **Custom data** und geben Sie das unten stehende JSON an. Die Body-Optionen **Empty** und **Jira issue data** enthalten das erforderliche Feld `webhookEvent` nicht, sodass DefectDojo sie ignoriert.
* Der Endpunkt gibt unabhängig davon, ob ein Update angewendet wurde, immer HTTP `200` zurück. Erfolg oder Misserfolg sind nur im Response Body und in den DefectDojo-Logs sichtbar - ein `200` im Audit Log von Automation bestätigt für sich genommen **nicht**, dass das Update einen Befund erreicht hat.

#### Regel 1 — Issue aktualisiert

Erstellen Sie eine Automation-Regel mit:

* **Trigger:** *Issue transitioned* (oder ein anderer Trigger, der auslöst, wenn sich die synchronisierten Felder ändern, z. B. *Field value changed* beim Status).
* **Action:** *Send web request*
  * **Web request URL:** `https://<YOUR DOJO DOMAIN>/jira/webhook/<YOUR WEBHOOK SECRET>`
  * **HTTP method:** `POST`
  * **Web request body:** *Custom data*
  * **Headers:** `Content-Type: application/json`
  * **Custom data:**

```json
{
  "webhookEvent": "jira:issue_updated",
  "issue": {
    "id": "{{issue.id}}",
    "fields": {
      "updated": "{{issue.updated}}",
      "resolution": null,
      "status": { "statusCategory": { "key": "{{issue.status.statusCategory.key}}" } },
      "assignee": { "name": "{{issue.assignee.accountId}}", "displayName": "{{issue.assignee.displayName}}" }
    }
  }
}
```

Einschränkungen für Issue-Updates:

* `issue.id` muss die **numerische interne Jira-Issue-ID** sein (`{{issue.id}}`), nicht der Issue Key (z. B. `PROJ-123`). DefectDojo ordnet das Update anhand dieser numerischen ID einem Befund zu.
* Die Felder `resolution` und `updated` müssen immer vorhanden sein. `resolution` darf `null` sein, fehlt jedoch eines der Felder, wird die Anfrage akzeptiert (`200`) und stillschweigend nicht verarbeitet.
* Die Status-Synchronisierung und die automatische Mitigation richten sich nach `status.statusCategory.key`, dessen Jira-Werte `new` (To Do), `indeterminate` (In Progress) und `done` (Done) sind. Ein Befund wird nur dann als behoben markiert, wenn das Issue tatsächlich geschlossen ist, nicht allein deshalb, weil zufällig ein Resolution-Wert vorhanden ist.

#### Regel 2 — Issue kommentiert

Erstellen Sie eine zweite Automation-Regel mit:

* **Trigger:** *Issue commented*
* **Action:** *Send web request* — dieselbe URL, Methode, Header und Body-Option *Custom data* wie bei Regel 1, mit folgendem Body:

```json
{
  "webhookEvent": "comment_created",
  "comment": {
    "self": "https://<your-jira-host>/rest/api/2/issue/{{issue.id}}/comment/{{comment.id}}",
    "body": "{{comment.body}}",
    "updateAuthor": { "name": "{{comment.author.accountId}}", "displayName": "{{comment.author.displayName}}" }
  }
}
```

Einschränkungen für Kommentare:

* Sowohl `body` als auch `updateAuthor` müssen vorhanden sein.
* DefectDojo leitet das Ziel-Issue aus der URL `comment.self` ab — konkret aus der `<id>` im Segment `.../issue/<id>/comment/...` —, sodass dort `{{issue.id}}` (die numerische ID) erscheinen muss.
* **Loop-Vermeidung:** Stimmt der Kommentarautor mit dem Jira-Konto überein, das DefectDojo für seine eigenen Kommentare verwendet, überspringt DefectDojo den Kommentar, um eine Echo-Schleife zu vermeiden. Wenn *alle* Kommentare übernommen werden sollen, führen Sie die Automation-Regel mit einem **anderen** Jira-Benutzer aus als dem, der in der Jira-Instanz von DefectDojo konfiguriert ist.

#### Hinweis zu Smart Values

Die oben gezeigten Smart Values (`{{issue.id}}`, `{{issue.status.statusCategory.key}}`, `{{comment.author.accountId}}` und so weiter) sind die Standardnamen von Jira Cloud, können jedoch zwischen Instanzen variieren. Prüfen Sie vor dem produktiven Einsatz mit der Payload-Vorschau von Automation, dass jeder Smart Value den erwarteten Wert liefert.

## Testen der Jira-Integration

#### Test 1: Werden Befunde erfolgreich an Jira übertragen?

Um zu testen, ob die Jira-Integration ordnungsgemäß funktioniert, können Sie dem mit Jira verknüpften Produkt in DefectDojo einen neuen, leeren Befund hinzufügen. **Product \> Findings \> Add New Finding.**

Fügen Sie einen beliebigen Titel, Schweregrad und eine Beschreibung hinzu und klicken Sie anschließend auf "Finished". Der Befund sollte mit allen relevanten Metadaten als Issue in Jira erscheinen.

Wenn Jira-Issues nicht korrekt erstellt werden, prüfen Sie Ihre Notifications auf Fehlercodes.

* Stellen Sie sicher, dass der mit der Jira Configuration von DefectDojo verknüpfte Jira User über die Berechtigung verfügt, Issues in diesem Jira-Space zu erstellen und zu aktualisieren.

#### Test 2: Jira-Webhooks senden an DefectDojo

Um die Jira-Webhooks zu testen, fügen Sie einem Befund, der auch als Issue in JIRA existiert (zum Beispiel dem Test-Issue aus dem obigen Abschnitt), eine Note hinzu.

Wenn die Webhooks korrekt konfiguriert sind, sollten Sie die Note in Jira als Comment beim Issue sehen.

Wenn dies nicht korrekt funktioniert, könnte dies an einem Firewall-Problem auf Ihrer Jira-Instanz liegen, das den Webhook blockiert.

* Die Firewall Rules von DefectDojo enthalten eine Checkbox für **Jira Cloud,** die aktiviert sein muss, bevor DefectDojo Webhook-Nachrichten von Jira empfangen kann.

## Verbindung zu Jira trennen

Jira-Integrationen können nur dann aus Ihrer Instanz entfernt werden, wenn noch keine zugehörigen Issues erstellt wurden.  Wurden bereits Issues erstellt, gibt es keine Möglichkeit, eine Jira-Instanz vollständig aus DefectDojo zu entfernen.

Sie können Ihre Jira-Integration jedoch deaktivieren, indem Sie sie auf Produktebene deaktivieren.  Im Formular **Edit Product** können Sie die Option "Enable Connection With Jira Space" deaktivieren.  Dadurch werden vorhandene, von DefectDojo erstellte Jira-Tickets weder gelöscht noch geändert, aber weitere Updates werden deaktiviert.

# Befunde an Jira übertragen

## Befunde an Jira übertragen
Ein Produkt mit einem JIRA-Mapping kann Befunde als Issues an Jira übertragen. Dies kann auf zwei verschiedene Arten erfolgen:

* Befunde können manuell, pro Befund, als Issues erstellt werden.
* Befunde können automatisch übertragen werden, wenn die Einstellung '**Push All Issues**' bei einem Produkt aktiviert ist. (Dies gilt nur für Befunde, die **Aktiv** und **Verifiziert** sind).

Zusätzlich haben Sie die Möglichkeit, statt einzelner Befunde Finding Groups an Jira zu übertragen. Dadurch entsteht ein einzelnes Issue, das viele zusammenhängende DefectDojo-Befunde enthält.

### Einen Befund manuell übertragen

1. Navigieren Sie auf einer Befund-Seite in DefectDojo zur Überschrift **JIRA**. Existiert der Befund noch nicht als Issue in JIRA, hat die JIRA-Überschrift den Wert '**None**'.
​
2. Ein Klick auf den Pfeil neben dem Wert **None** erstellt ein neues Jira-Issue. In welchem State das Issue erstellt wird, hängt vom Workflow Ihres Teams und der Jira-Konfiguration mit DefectDojo ab. Wenn der Befund nicht erscheint, aktualisieren Sie die Seite.
​
![image](images/Creating_Issues_in_Jira.png)

3. Sobald das Issue erstellt wurde, erstellt DefectDojo einen Link zum Issue, der sich aus dem Jira Key und der Issue ID zusammensetzt. Neben diesem Link befindet sich außerdem ein rotes Papierkorb-Symbol, mit dem Sie das Issue aus Jira löschen können.
​
![image](images/Creating_Issues_in_Jira_2.png)

4. Ein erneuter Klick auf den Pfeil überträgt alle an einem Issue vorgenommenen Änderungen an Jira und aktualisiert das Jira-Issue entsprechend. Ist die Einstellung '**Push All Issues**' beim zugehörigen Produkt des Befunds aktiviert, geschieht dies automatisch.

### Jira-Kommentare

* Wenn einem Jira-Issue ein Kommentar hinzugefügt wird, wird derselbe Kommentar dem Befund im Bereich **Notizen** hinzugefügt.
* Ebenso wird eine Notiz, die einem Befund hinzugefügt wird, als Kommentar dem Jira-Issue hinzugefügt.

### Jira-Statusänderungen

Die Jira Configuration in DefectDojo enthält Einträge für zwei Jira-Transitions, die eine Statusänderung bei einem Befund auslösen.

* Wenn in Jira die **Transition 'Close'** ausgeführt wird, wird auch der zugehörige Befund geschlossen und in DefectDojo als **Inaktiv** und **Behoben** markiert. DefectDojo protokolliert diese Änderung auf der Befund-Seite unter der Überschrift **Mitigated By**.
​
![image](images/Creating_Issues_in_Jira_3.png)

* Wenn beim Jira-Issue die **Transition 'Reopen'** ausgeführt wird, wird der zugehörige Befund in DefectDojo auf **Aktiv** gesetzt und verliert seinen Status **Behoben**.

### Zuordnung von Jira-Resolutions zu Risikoakzeptanz / Falsch-positiv

Zusätzlich zu den Transitions Close/Reopen enthält die Jira Configuration optionale Felder, mit denen Sie eine Jira-**Resolution** einem DefectDojo-Befundstatus zuordnen können.  Diese werden während des Workflows **Add Jira Configuration (Express)** (Schritte 6 und 7) festgelegt und können später an der Jira Configuration bearbeitet werden:

* **Risk Accepted Finding Mapping Resolution** — wenn ein Jira-Issue mit dieser Resolution geschlossen wird, erhält der verknüpfte Befund in DefectDojo den Status Risiko akzeptiert.
* **False Positive Finding Mapping Resolution** — wenn ein Jira-Issue mit dieser Resolution geschlossen wird, erhält der verknüpfte Befund in DefectDojo den Status Falsch-positiv.

#### Status vs. Resolution: Eine häufige Verwechslung

Diese Felder ordnen die Jira-**Resolution** zu, nicht den Jira-**Status**.  Status und Resolution sind zwei unabhängige Jira-Konzepte: Der Status beschreibt, an welcher Stelle im Workflow sich das Issue befindet (Open, In Progress, Done), während die Resolution beschreibt, wie es gelöst wurde (Fixed, Won't Do, Duplicate, False Positive usw.).

Eine häufige Verwechslung besteht darin, dass eine Jira-Workflow-Transition den Status auf "Done" ändern kann, *ohne* eine Resolution zu setzen.  In diesem Fall greift das Resolution-Mapping von DefectDojo nie — stattdessen wird der Befund gemäß dem oben beschriebenen Standardverhalten der **Transition 'Close'** als **Behoben** markiert, nicht als Risiko akzeptiert oder Falsch-positiv.

#### Voraussetzung: Eine Post-Function "Set issue resolution" bei der Jira-Workflow-Transition

Die Workflow-Engine von Jira füllt das Resolution-Feld nicht automatisch aus.  Jede Transition, die ein Issue mit einer bestimmten Resolution schließen soll, benötigt eine an der Transition selbst konfigurierte Post-Function **Set issue resolution**.  Ohne diese Post-Function wechselt das Issue zwar in den neuen Status, die Resolution bleibt jedoch leer, und das Mapping von DefectDojo hat nichts, womit es abgleichen kann.

Ein Jira-Administrator kann diese Post-Function hinzufügen unter **Project Settings → Workflows → (edit workflow) → (select the closing transition) → Post Functions → Add post function → Set issue resolution**.

## Finding Groups als Jira-Issues übertragen

Wenn Finding Groups aktiviert sind, können Sie eine Group von Befunden als ein einzelnes Issue an Jira übertragen, statt separate Issues für jeden Befund zu erstellen.

Das mit einer Finding Group verknüpfte Jira-Issue kann jedoch nicht über DefectDojo bearbeitet oder gelöscht werden. Es muss direkt in der Jira-Instanz gelöscht werden.

### Finding Groups automatisch erstellen und übertragen

Bei aktiviertem Auto-Push To Jira und einer beim Import ausgewählten Group-By-Option:

Solange die Finding Groups erfolgreich erstellt werden, wird die Finding Group als Issue automatisch an Jira übertragen, nicht die einzelnen Befunde.

![image](images/Creating_Issues_in_Jira_4.png)

## Custom Fields in Jira
<span style="background: rgba(243, 122, 78,0.5">DefectDojo unterstützt derzeit nicht die Übergabe Issue-spezifischer Informationen an diese Custom Fields - diese Felder müssen nach der Erstellung des Issues manuell in Jira aktualisiert werden. Jedes Custom Field wird von DefectDojo nur mit einem Default-Wert erstellt.</span>

<span style="background: rgba(0, 207, 83, 0.44)"> Jira Cloud ermöglicht es Ihnen inzwischen, einen Default-Wert für ein Custom Field direkt in der App zu erstellen. Weitere Informationen zur Konfiguration finden Sie in [Atlassians Dokumentation zu Custom Fields](https://support.atlassian.com/jira-cloud-administration/docs/configure-a-custom-field/).</span>

Die integrierten Jira Issue Types von DefectDojo (**Bug, Task, Story** und **Epic)** sind so eingerichtet, dass sie 'out of the box' funktionieren. Datenfelder in DefectDojo werden automatisch den entsprechenden Feldern in Jira zugeordnet. Standardmäßig weist DefectDojo jedem neu erstellten Issue Priority, Labels und einen Reporter zu.

Manche Jira-Konfigurationen erfordern, dass zusätzliche Custom Fields berücksichtigt werden, bevor ein Issue erstellt werden kann. Dieser Prozess ermöglicht es Ihnen, diese Custom Fields in Ihrer DefectDojo \-\> Jira-Integration zu berücksichtigen und so sicherzustellen, dass Issues erfolgreich erstellt werden. Diese Custom Fields werden allen API-Aufrufen hinzugefügt, die von DefectDojo an eine verknüpfte Jira-Instanz gesendet werden.

Wenn Sie in Jira noch keine Custom Fields verwenden, müssen Sie diesen Prozess nicht durchführen.

1. Notieren Sie die Namen Ihrer Custom Fields in Jira (**Jira UI**)
2. Ermitteln Sie die Key-Werte für die neuen Custom Fields (Jira Field Spec Endpoint)
3. Ermitteln Sie die zulässigen Daten für jedes Custom Field anhand der Key-Werte als Referenz (Jira Issue Endpoint)
4. Erstellen Sie einen Field-Reference-JSON-Block, um alle Custom-Field-Keys und zulässigen Daten festzuhalten (Jira Issue Endpoint)
5. Speichern Sie den JSON-Block im zugehörigen DefectDojo-Produkt, damit Custom Fields aus Jira erstellt werden können (DefectDojo UI)
6. Testen Sie Ihre Arbeit und stellen Sie sicher, dass alle erforderlichen Daten korrekt aus Jira übernommen werden

#### Schritt 1: Notieren Sie die Namen Ihrer Custom Fields in Jira

Jira unterstützt eine Vielzahl unterschiedlicher Context Fields, darunter Date Pickers, Custom Labels, Radio Buttons. Jedes dieser Context Fields hat einen eigenen Key-Wert, der in der Jira API zu finden ist.

Notieren Sie sich die Namen aller benötigten Custom Fields, da Sie im nächsten Schritt die Jira API durchsuchen müssen, um sie zu finden.

**Beispiel einer Custom-Field-Liste (Ihre Custom-Field-Namen werden abweichen):**

* DefectDojo Custom URL Field
* Ein weiteres Beispiel für ein Custom Field
* ...

#### Schritt 2: Ermitteln Sie die Key-Werte Ihrer Jira Custom Fields

Beginnen Sie diesen Prozess, indem Sie zur Field Spec URL für Ihre gesamte Jira-Instanz navigieren.

Hier ist ein Beispiel für eine Field Spec URL:

`https://yourcompany-example.atlassian.net/rest/api/2/field`

Die API gibt eine lange JSON-Zeichenfolge zurück, die in lesbaren Text formatiert werden sollte (mit einem Code-Editor, einer Browser-Erweiterung oder <https://jsonformatter.org/>).

Das von dieser URL zurückgegebene JSON enthält alle Ihre Jira-Custom-Fields, von denen die meisten für DefectDojo irrelevant sind und den Wert `"Null"` haben. Jedes Objekt in dieser API-Antwort entspricht einem anderen Feld in Jira. Sie müssen nach den Objekten suchen, deren `"name"`-Attribute mit den Namen der in der Jira UI erstellten Custom Fields übereinstimmen, und dann den Wert ihres "key"-Attributs notieren.

![image](images/Using_Custom_Fields.png)

Sobald Sie das passende Objekt in der JSON-Ausgabe gefunden haben, können Sie den "key"-Wert bestimmen - in diesem Fall ist es `customfield_10050`.

Jira generiert für jedes Custom Field unterschiedliche Key-Werte, die sich nach der Erstellung jedoch nicht mehr ändern. Wenn Sie künftig ein weiteres Custom Field erstellen, erhält es einen neuen Key-Wert.

**Erweiterung unserer Custom-Field-Liste:**

* "DefectDojo Custom URL Field" \= customfield\_10050
* "Another example of a Custom Field" \= customfield\_12345
* ...

#### Schritt 3 \- Ermitteln Sie die Custom Fields bei einem Jira-Issue

Suchen Sie ein Issue in Jira, das die in Schritt 2 notierten Custom Fields enthält. Kopieren Sie den Issue Key des Titels (sollte etwa wie "`EXAMPLE-123`" aussehen) und navigieren Sie zur folgenden URL:

`https://yourcompany-example.atlassian.net/rest/api/2/issue/EXAMPLE-123`

Dies liefert eine weitere JSON-Zeichenfolge zurück.

Wie zuvor enthält die API-Ausgabe viele `customfield_##`-Objektparameter mit `null`-Werten - dies sind Custom Fields, die Jira standardmäßig hinzufügt und die für dieses Issue nicht relevant sind. Sie enthält außerdem `customfield_##`-Werte, die den im vorherigen Schritt gefundenen Custom-Field-Key-Werten entsprechen. Anders als bei der Field-Spec-Ausgabe sehen Sie hier keine Namen, die diese Custom Fields identifizieren, weshalb Sie die Key-Werte in Schritt 2 notieren mussten.

![image](images/Using_Custom_Fields_2.png)

**Beispiel:**
Wir wissen, dass `customfield_10050` das DefectDojo Custom URL Field repräsentiert, da wir dies in Schritt 2 notiert haben. Wir können nun sehen, dass `customfield_10050` im Issue `EXAMPLE-123` den Wert `"https://google.com"` enthält.

#### Schritt 4 \- Erstellen Sie eine JSON Field Reference aus jedem Jira-Custom-Field-Key

Sie müssen nun den Wert jedes Custom Field aus Ihrer Liste übernehmen und in einem JSON-Objekt speichern (als Referenz). Custom Fields, die nicht Ihrer Liste entsprechen, können Sie ignorieren.

Dieses JSON-Objekt enthält alle Default-Werte für neue Jira-Issues. Wir empfehlen, Namen zu verwenden, die Ihr Team leicht als zu ändernde 'Default'-Werte erkennt: '`change-me.com`', '`Change this paragraph.`' usw.

**Beispiel:**

Aus Schritt 3 wissen wir nun, dass Jira für "`customfield_10050`" eine URL-Zeichenfolge erwartet. Damit können wir unser Beispiel-JSON-Objekt aufbauen.

Angenommen, wir hätten außerdem ein DefectDojo-bezogenes Kurztextfeld gefunden, das wir als "`customfield_67890`" identifiziert haben. Wir würden dieses Feld in unserer zweiten API-Ausgabe betrachten, den zugehörigen Wert ansehen und den gespeicherten Wert ebenfalls in unserem Beispiel-JSON-Objekt referenzieren.
​
Ihr JSON-Objekt wird beim Hinzufügen weiterer Custom Fields etwa so aussehen.

```
{
	"customfield_10050": "https://change-me.com",
	"customfield_67890": "This is the short text custom field."
}
```

Wiederholen Sie diesen Vorgang, bis alle für DefectDojo relevanten Custom Fields aus Jira zu Ihrer JSON Field Reference hinzugefügt wurden.

#### Datentypen und Jira-Syntax

Manche Felder, wie Date-Felder, können sich auf mehrere Custom Fields in Jira beziehen. In diesem Fall müssen Sie beide Felder zu Ihrer JSON Field Reference hinzufügen.

```
  "customfield_10040": "1970-01-01",
  "customfield_10041": "1970-01-01T03:30:00.000+0200",
```

Andere Felder, wie das Label-Feld, werden möglicherweise als Liste von Strings erfasst - achten Sie darauf, dass Ihre JSON Field Reference ein Format verwendet, das der API-Ausgabe von Jira entspricht.

```
// a list of custom labels on a Jira object
  "customfield_10042": [
    "custom-label-one",
    "this-is-default",
    "change-me-please"
  ],
```

Andere Custom Fields können zusätzliche, kontextbezogene Informationen enthalten, die aus der Field Reference entfernt werden sollten. Das Custom Multichoice Field enthält beispielsweise einen zusätzlichen Block in der API-Ausgabe, den Sie entfernen müssen, da dieser Block den aktuellen Wert des Felds speichert.

* Sie sollten das zusätzliche Objekt aus diesem Feld entfernen:

```
"customfield_10047": [
    {
      "value": "A"
    },
    {
      "self": "example.url...",
      "value": "C",
      "id": "example ID"
    }
]
```
* stattdessen können Sie dies wie folgt kürzen und den zweiten Teil weglassen:

```
"customfield_10047": [
   {
      "value": "A"
   }
]
```

#### Beispiel einer vollständigen Field Reference

Hier ist eine vollständige JSON Field Reference mit Inline-Kommentaren, die erklären, worauf sich jedes Custom Field bezieht. Dies ist als umfassendes Beispiel gedacht. Ihr JSON enthält abhängig von den Custom Values, die Sie bei der Issue-Erstellung verwenden möchten, andere Key-Werte und Datenpunkte.

```
{
  "customfield_10050": "https://change-me.com",

  "customfield_10049": "This is a short text custom field",

// two different fields, but both correspond to the same custom date attribute
  "customfield_10040": "1970-01-01",
  "customfield_10041": "1970-01-01T03:30:00.000+0200",

// a list of custom labels on a Jira object
  "customfield_10042": [
    "custom-label-one",
    "this-is-default",
    "change-me-please"
  ],

// custom number field
  "customfield_10043": 0,

// custom paragraph field
  "customfield_10044": "This is a very long winded way to say CHANGE ME PLEASE",

// custom radio button field
  "customfield_10045": {
    "value": "radio button option"
  },

// custom multichoice field
  "customfield_10047": [
    {
      "value": "A"
    }
  ],

// custom checkbox field
  "customfield_10039": [
    {
      "value": "A"
    }
  ],

// custom select list (singlechoice) field
  "customfield_10048": {
    "value": "1"
  }
}
```

#### Schritt 5 \- Fügen Sie die Custom Fields einem DefectDojo-Produkt hinzu

Sie können diese Custom Fields nun im Bereich Custom Fields dem zugehörigen DefectDojo-Produkt hinzufügen. Auch hier gilt:

* Navigieren Sie zu Edit Product \- defectdojo.com/product/ID/edit .
* Navigieren Sie zu Custom fields und fügen Sie die JSON Field Reference als reinen Text in das Feld Custom Fields ein.
* Klicken Sie auf 'Submit'.

#### Schritt 6 \- Testen Sie Ihre Jira Custom Fields anhand eines neuen Befunds:

Wenn Sie nun einen neuen Befund im mit Jira verknüpften Produkt erstellen, erstellt Jira automatisch alle diese Custom Fields gemäß dem darin enthaltenen JSON-Block. Diese Custom Fields werden mit den Default-Werten ("change\-me\-please" usw.) erstellt.

Navigieren Sie innerhalb des Produkts in DefectDojo zur Seite Findings \> Add New Finding. Stellen Sie sicher, dass der Befund sowohl Aktiv als auch Verifiziert ist, damit er an Jira übertragen wird, und prüfen Sie anschließend auf Jira-Seite, dass die Custom Fields erfolgreich und ohne Inkonsistenzen erstellt wurden.
