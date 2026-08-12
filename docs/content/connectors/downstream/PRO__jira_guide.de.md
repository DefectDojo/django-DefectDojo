---
title: Jira (Legacy)
description: Mit der Jira-Integration arbeiten
weight: 1
audience: pro
aliases:
- /issue_tracking/jira/pro__jira_guide/
- /en/share_your_findings/jira_guide
---

> **Diese Seite dokumentiert die veraltete Jira-Integration.** Die hier beschriebene produktbezogene Jira-Integration wurde durch den **[Jira Downstream Connector](/connectors/downstream/about/)** abgelöst, der auf jeder DefectDojo-Pro-Instanz allgemein verfügbar ist und die empfohlene Methode darstellt, um Befunde an Jira zu übertragen. In der Pro-Seitenleiste trägt **Connect > Jira** aus diesem Grund ein `LEGACY`-Abzeichen — siehe [Menu Badges](/navigation/pro__menu_badges/).
>
> **Wenn Sie Jira zum ersten Mal einrichten, beginnen Sie mit dem [Downstream Connector](/connectors/downstream/about/) anstelle dieser Anleitung.**
>
> **Nutzen Sie bereits die veraltete Integration?** DefectDojo Pro enthält eine integrierte Migration, die Ihre bestehende klassische Jira-Konfiguration auf Downstream Connectors überführt, einschließlich der bereits übertragenen Tickets — siehe [Migration zum Jira Downstream Connector](#migrating-to-the-jira-downstream-connector) unten.
>
> Die veraltete Integration funktioniert weiterhin, und diese Anleitung bleibt dafür gültig.

Die Jira-Integration von DefectDojo kann verwendet werden, um Befund-Daten an einen oder mehrere Jira-Bereiche zu übertragen. Auf diese Weise können Sie DefectDojo in Ihren Standard-Entwicklungsworkflow integrieren. Hier einige Beispiele, wie das funktionieren kann:

* Das AppSec-Team kann Befunde selektiv an einen von Entwicklern genutzten Jira-Bereich übertragen, sodass die Behebung von Problemen angemessen neben der regulären Entwicklung priorisiert werden kann. Entwickler in diesem Board müssen nicht auf DefectDojo zugreifen - sie können ihre gesamte Arbeit an einem Ort behalten.
* DefectDojo kann ALLE Befunde an einen bidirektionalen Jira-Bereich übertragen, den das AppSec-Team nutzt, wodurch die Validierung von Problemen aufgeteilt werden kann. Dieses Board bleibt mit DefectDojo synchron und ermöglicht komplexe Behebungs-Workflows.
* DefectDojo kann Befunde selektiv aus separaten Produkten und/oder Engagements an separate Jira-Bereiche übertragen, um alles im richtigen Kontext zu halten.

## Migration zum Jira Downstream Connector

DefectDojo Pro kann eine bestehende klassische Jira-Einrichtung für Sie in eine Downstream-Connector-Konfiguration umwandeln, anstatt Sie zum manuellen Neuaufbau zu zwingen.

**Wo Sie es finden:** Gehen Sie zu **Connect \> Downstream**, um die Seite **Downstream Connectors** zu öffnen, und verwenden Sie die Karte **Classic Jira Migration**. Klicken Sie auf **Migrate from classic Jira** und bestätigen Sie anschließend.

Die Karte erscheint nur, wenn eine klassische Jira-Konfiguration zum Migrieren vorhanden ist oder ein vorheriger Lauf zu melden ist — eine Instanz, die nie klassisches Jira verwendet hat, sieht sie also nicht. Sobald alles migriert wurde, bleibt die Karte bestehen, aber die Schaltfläche ist deaktiviert, da nichts mehr zu tun ist.

Das Ausführen der Migration erfordert **globale Maintainer-Berechtigungen** (genauer gesagt die Berechtigung, Integrationen zu bearbeiten), und sie muss aus einer angemeldeten Browsersitzung heraus ausgeführt werden — sie kann nicht über ein API-Token gesteuert werden.

### Was mit bereits übertragenen Tickets geschieht

**Ihre bestehenden Jira-Tickets werden beibehalten und neu verknüpft — sie werden nicht verwaist, und der Connector öffnet keine Duplikate.** Jeder Befund, den das klassische Jira bereits übertragen hatte, behält sein Ticket, und der Connector übernimmt die Aktualisierung dieses gleichen Tickets vor Ort. Links auf Befundgruppen werden auf dieselbe Weise übernommen.

Die einzige Ausnahme sind **Engagement-Epics**. Der Downstream Connector kennt kein Epic-Konzept, daher werden Epic-Issues in den Warnungen der Migration gemeldet und unangetastet gelassen.

### Was migriert wird

* Ihre Jira-**Instanz**-Verbindung — URL und Zugangsdaten — wird zu einer Downstream-Connector-Integrationsinstanz und behält ihren Namen bei.
* **Schweregrad-Zuordnungen** und **Status-Zuordnungen** (Ihre Schlüssel für Öffnen- und Schließen-Übergänge) werden übernommen.
* Jede **Jira-Projekt**-Konfiguration wird zu einer Issue-Tracker-Zuordnung, behält ihren Projektschlüssel und Issue-Typ bei und bleibt demselben Produkt oder Engagement zugewiesen.
* **Push All Issues** wird beibehalten: Projekte, bei denen es aktiviert war, übertragen weiterhin automatisch.
* **Benutzerdefinierte Felder**, **Felder für Schließen/Wiedereröffnen-Übergänge**, **Komponente**, **Standard-Zuweisung** und **Labels** werden in Feldzuordnungen umgewandelt. Wo Sie *Vulnerability Id als Jira-Label hinzufügen* verwendet haben, wird dies ebenfalls zu einer Label-Zuordnung.
* Ein Verzeichnis mit **benutzerdefinierten Issue-Vorlagen** wird zu einer Ticket-Vorlage. Die Standardvorlagen werden nicht kopiert, da der Connector bereits Entsprechungen mitbringt.

### Was nicht übernommen wird

Diese werden als Warnungen beim Migrationslauf gemeldet — sie stoppen ihn nicht. Achten Sie in den Ergebnissen auf die Liste *"Dinge, die der Connector nicht übernehmen kann"*.

* **Jira → DefectDojo Rücksynchronisation.** Dies ist der wichtige Punkt. Der Downstream Connector synchronisiert keine Änderungen *zurück* von Jira, daher werden Auflösungs-Zuordnungen, die Risikoakzeptanz oder Falsch-positiv aus einer Jira-Auflösung anwenden, nicht migriert. **Wenn Sie auf Rücksynchronisation angewiesen sind, lassen Sie die klassische Jira-Instanz konfiguriert** — die Migration entfernt sie nicht.
* **Engagement Epic Mapping** — der Connector kennt kein Epic-Konzept.
* **Push Notes**, **SLA-Benachrichtigungskommentare** und **Kommentare zum Ablauf der Risikoakzeptanz** — der Connector postet diese nicht an Jira.
* Benutzerdefinierte Felder mit den Namen `summary`, `description`, `project`, `issuetype` oder `status` — diese sind für den Connector reserviert, und eine Feldzuordnung, die eines davon verwendet, wird übersprungen.
* Werte benutzerdefinierter Felder mit mehr als 512 Zeichen — werden übersprungen statt abgeschnitten.
* Ein Jira-Projekt, das weder einem Produkt noch einem Engagement zugeordnet ist, erzeugt keine Zuweisung.

### Was danach mit der klassischen Integration geschieht

**Nichts wird doppelt übertragen.** Für jedes migrierte Projekt schaltet die Migration das klassische Jira-Projekt ab, sodass ab diesem Zeitpunkt nur noch der Connector überträgt. Sie müssen nichts manuell deaktivieren.

Ihre klassische Konfiguration wird **beibehalten, nicht gelöscht** — die Instanz-, Projekt- und Issue-Datensätze bleiben alle erhalten, nur die Übertragungseinstellungen werden abgeschaltet. Das ist beabsichtigt: Es macht die Änderung rückgängig machbar und hält die Rücksynchronisation funktionsfähig, falls Sie darauf angewiesen sind.

**Um zurückzurollen**, aktivieren Sie die klassischen Jira-Projekteinstellungen erneut und entfernen Sie die von der Migration erstellte Connector-Konfiguration. Es gibt kein Ein-Klick-Rückgängig.

**Erneutes Ausführen ist sicher.** Die Migration protokolliert, was sie bereits konvertiert hat, und überspringt dies bei einem zweiten Lauf, sodass nichts doppelt entsteht. Wenn ein Projekt oder eine Instanz fehlschlägt, wird der Rest trotzdem migriert — ein fehlgeschlagenes Projekt bleibt auf der klassischen Integration aktiv, statt abgeschaltet zu werden, sodass es weiter funktioniert, während Sie die Ursache untersuchen.

### Während des Laufs

Die Migration läuft im Hintergrund und meldet laufend den Fortschritt. Nach Abschluss erhalten Sie eine Zusammenfassung — wie viele Connectors, Zuordnungen, Zuweisungen, Vorlagen und Ticket-Links erstellt wurden, wie viele klassische Projekte abgeschaltet wurden und was übersprungen wurde — zusammen mit den oben beschriebenen Warnungen. Es läuft jeweils nur eine Migration gleichzeitig.

# Jira einrichten

Das Einrichten von Jira erfordert folgende Schritte:
1. Aktivieren Sie die Jira-Integration in den Systemeinstellungen. Bis Sie das tun, sind die übrigen Jira-Einstellungen in DefectDojo überall ausgeblendet.
2. Verbinden Sie eine Jira-Instanz, entweder mit Benutzername/Passwort oder einem API-Token. Mehrere Instanzen können verknüpft werden.
3. Fügen Sie diese Jira-Instanz einem oder mehreren Produkten oder Engagements innerhalb von DefectDojo hinzu.
4. Wenn Sie bidirektionale Synchronisation nutzen möchten, erstellen Sie einen Jira-Webhook, der Updates an DefectDojo sendet.

## Schritt 1: Aktivieren Sie die Jira-Integration in den Systemeinstellungen

Die Jira-Integration ist standardmäßig deaktiviert, und solange sie deaktiviert ist, blendet DefectDojo jede andere Jira-Steuerung in der Oberfläche aus. Dies ist als Erstes zu konfigurieren: Keiner der folgenden Schritte ist verfügbar, bevor sie aktiviert ist.

Während die Integration deaktiviert ist, gibt es keinen Eintrag **Jira Instances** in der Seitenleiste, sodass es keine Möglichkeit gibt, eine Jira-Instanz hinzuzufügen:

![image](images/jira-menu-hidden-pro.png)

### Integration aktivieren

1. Navigieren Sie in der DefectDojo-Seitenleiste zu **Settings \> System \> System Settings**. Auf Instanzen, die noch das vorherige Menülayout verwenden, befindet sich dies unter einer nach Ihrem Lizenzpaket benannten Gruppe — **Pro Settings** oder **Enterprise Settings**. Siehe [Das Einstellungsmenü](/navigation/pro__settings_menu/).
​
2. Aktivieren Sie im Abschnitt **Jira Integration Settings** die Option **Enable Jira Integration**.
​
3. Klicken Sie auf **Submit**. **Jira Instances** erscheint sofort in der Seitenleiste, ohne dass die Seite neu geladen werden muss:

![image](images/jira-enable-system-settings-pro.png)

### Was diese Einstellung steuert

Das Aktivieren von **Enable Jira Integration** bewirkt, dass der Rest der Jira-Oberfläche erscheint. Mit aktivierter Einstellung erhalten Sie:

* das Menü **Jira Instances**, in dem Jira-Instanzen hinzugefügt und bearbeitet werden
* die Seite **Jira Project Settings** im ⚙️-Menü der Assets sowie die Jira-Einstellungen bei Engagements
* die Aktionen **Push to Jira** bei Befunden und Befundgruppen, die Jira-Felder in den Formularen für Befunde und Massenbearbeitung sowie die Jira-Spalten in den Listen für Assets, Engagements, Befunde und Befundgruppen (einschließlich CSV-Exporte)

Die Einstellung steuert die Integration auch außerhalb der Oberfläche: Solange sie deaktiviert ist, überträgt DefectDojo keine Befunde an Jira (einschließlich `push_to_jira`-Anfragen über die API), und eingehende Jira-Webhooks werden ignoriert.

Die übrigen Jira-Felder in **Jira Integration Settings** (**Add Vulnerability ID as Jira Label**, **Enable Jira Web Hook**, **Disable Jira Web Hook Secret**, **Jira Web Hook Secret**, **Jira Minimum Severity**) bleiben unabhängig davon sichtbar, ob die Integration aktiviert ist oder nicht, haben aber keine Wirkung, bevor sie aktiviert ist.

## Schritt 2: Verbinden Sie eine Jira-Instanz

Nachdem die Integration aktiviert ist, ist das Verbinden einer Jira-Instanz der nächste Schritt bei der Einrichtung der Jira-Integration von DefectDojo. Bitte beachten Sie, dass Jira Service Management derzeit nicht unterstützt wird.

#### Von Jira benötigte Informationen

Atlassian verwendet unterschiedliche Authentifizierungsmethoden für Jira Cloud und Jira Data Center.

Für **Jira Cloud** benötigen Sie:
* eine Jira-URL, z. B. https://yourcompany.atlassian.net/
* ein Konto mit Berechtigungen zum Erstellen und Aktualisieren von Issues in Ihrer Jira-Instanz. Dies kann sein:
    * eine Standard-**Benutzername/Passwort**-Kombination
    * eine **Benutzername/API-Token**-Kombination

Für **Jira Data Center (oder Server)** benötigen Sie:
* eine Jira-URL, z. B. https://jira.yourcompany.com
* ein Konto mit Berechtigungen zum Erstellen und Aktualisieren von Issues in Ihrer Jira-Instanz. Dies kann sein:
    * eine Standard-**Benutzername/Passwort**-Kombination
    * eine **E-Mail-Adresse/Personal Access Token**-Kombination

Optional können Sie zuordnen:
* Jira-Übergänge, die das Wiedereröffnen und Schließen von Befunden auslösen
* Jira-Auflösungen, die Risikoakzeptanz- und Falsch-positiv-Status auf Befunde anwenden können (optional)

Mehrere Jira-Bereiche können von einer einzigen Jira-Instanzverbindung verwaltet werden, solange das von DefectDojo verwendete Jira-Konto/-Token die Berechtigung hat, Issues im zugehörigen Jira-Bereich zu erstellen.

### Eine Jira-Instanz hinzufügen

1. Stellen Sie sicher, dass **Enable Jira Integration** in den Systemeinstellungen aktiviert ist, wie in [Schritt 1](#step-1-enable-the-jira-integration-in-system-settings) beschrieben. Das Menü **Jira Instances** erscheint erst dann in der Seitenleiste.

2. Navigieren Sie in der DefectDojo-Seitenleiste zur Seite **Enterprise Settings \> Jira Instances \> + New Jira Instance**.

![image](images/jira-instance-beta.png)

3. Wählen Sie einen **Configuration Name** für die Verwendung dieser Jira-Instanz in DefectDojo. Dieser Name ist lediglich eine Bezeichnung für die Instanzverbindung in DefectDojo und muss keinen Bezug zu Jira-Daten haben.

4. Wählen Sie die URL Ihrer Unternehmens-Jira-Instanz \- wahrscheinlich ähnlich zu `https://**yourcompany**.atlassian.net`, wenn Sie eine Jira-Cloud-Installation verwenden.

5. Geben Sie eine geeignete Authentifizierungsmethode in die Felder Username/Password für Jira ein:
    * Für standardmäßige **Benutzername/Passwort-Jira-Authentifizierung** geben Sie einen Jira-Benutzernamen und das zugehörige Passwort in diese Felder ein.
    * Für die Authentifizierung mit dem **API-Token eines Benutzers (Jira Cloud)** geben Sie den Benutzernamen mit dem zugehörigen **API-Token** im Passwortfeld ein.
    * Für die Authentifizierung mit einem **Personal Access Token von Jira (auch PAT genannt, nur bei Jira Data Center und Jira Server verwendet)** geben Sie den PAT im Passwortfeld ein. Der Benutzername wird für die Authentifizierung mit einem Jira-PAT nicht verwendet, das Feld ist in diesem Formular jedoch weiterhin erforderlich, sodass Sie hier einen Platzhalterwert zur Identifizierung Ihres PAT verwenden können.

Beachten Sie, dass der mit dieser Verbindung verknüpfte Benutzer berechtigt sein muss, Issues zu erstellen und auf Daten in Ihrer Jira-Instanz zuzugreifen.

6. Sie müssen Werte für eine Epic Name ID, eine Re-open Transition ID und eine Close Transition ID angeben. Diese Werte können später geändert werden. Während Sie bei Jira angemeldet sind, können Sie diese Werte über folgende URLs abrufen:
- **Epic Name ID**: Besuchen Sie `https://<YOUR JIRA URL>/rest/api/2/field` und suchen Sie nach Epic Name. Kopieren Sie die Zahl aus `number` und fügen Sie sie hier ein. Wenn Sie keine Epic Name ID haben, die Ihrem Bereich in Jira zugeordnet ist (z. B. weil Sie einen team-verwalteten Bereich verwenden), geben Sie in diesem Feld 0 ein.
- **Re-open Transition ID**: Besuchen Sie `https://<YOUR JIRA URL>/rest/api/latest/issue/<ANY VALID ISSUE KEY>/transitions?expand-transitions.fields`, um die ID für Ihre Jira-Instanz zu finden. Fügen Sie sie in das Feld Reopen Transition ID ein.
- **Close Transition ID**: Besuchen Sie `https://<YOUR JIRA URL>/rest/api/latest/issue/<ANY VALID ISSUE KEY>/transitions?expand-transitions.fields`, um die ID für Ihre Jira-Instanz zu finden. Fügen Sie sie in das Feld Close Transition ID ein.

7. Wählen Sie den Standard-Issue-Typ, mit dem Sie Issues in Jira erstellen möchten. Die Optionen dafür sind **Bug, Task, Story** und **Epic** (die Standard-Jira-Issue-Typen) sowie **Spike** und **Security**, welche benutzerdefinierte Issue-Typen sind. Wenn Sie einen anderen Issue-Typ verwenden möchten, wenden Sie sich bitte an [support@defectdojo.com](mailto:support@defectdojo.com).

8. Wählen Sie Ihre Issue-Vorlage, welche die Issue-Beschreibung bestimmt, wenn Issues in Jira erstellt werden.

Die beiden Typen sind:
- **Jira\_full**, das alle Befund-Informationen in Jira-Issues einschließt
- **Jira\_limited**, das eine geringere Menge an Befund-Informationen und Metadaten einschließt.

Wenn Sie dieses Feld leer lassen, wird standardmäßig **Jira\_full** verwendet. Wenn Sie eine andere Art von Vorlage benötigen, wenden Sie sich an [support@defectdojo.com](mailto:support@defectdojo.com).

9. Geben Sie bei Bedarf den Namen einer Jira-Auflösung ein, die den Status eines Befunds auf Akzeptiert oder Falsch-positiv ändert (wenn die Auflösung beim Issue ausgelöst wird).

Das Formular kann von hier aus übermittelt werden. Wenn Sie möchten, können Sie Ihre Jira-Integration unter Optional Fields weiter anpassen. Ein Klick auf diese Schaltfläche ermöglicht es Ihnen, generischen Text auf Jira-Issues anzuwenden oder die Zuordnung der Jira Severity Mappings zu ändern.

## Schritt 3: Verbinden Sie ein Produkt oder Engagement mit Jira

Jedes Produkt oder Engagement in DefectDojo hat eigene Einstellungen, die bestimmen, wie Befunde in JIRA-Issues umgewandelt werden. Von hier aus können Sie den zugehörigen Jira-Bereich festlegen und das Standardverhalten für das Erstellen von Issues, Epics, Labels und anderen JIRA-Metadaten einstellen.

### Jira zu einem Produkt hinzufügen

Sie finden diese Seite, indem Sie auf das Zahnrad-Menü bei einem Produkt ⚙️ klicken und die Seite **Jira Project Settings** öffnen.

![image](images/jira-project-settings.png)

#### Jira-Instanz

Wenn Sie mehrere Jira-Instanzen für separate Produkte oder Teams innerhalb Ihrer Organisation eingerichtet haben, können Sie angeben, in welchem Jira-Bereich DefectDojo Issues erstellen soll. Wählen Sie einen Bereich aus dem Dropdown-Menü.

Wenn dieses Menü keine Jira-Instanzen auflistet, bestätigen Sie, dass diese Bereiche in Ihrer globalen Jira-Konfiguration für DefectDojo verbunden sind \- yourcompany.defectdojo.com/jira.

#### Projektschlüssel

Dies ist der Schlüssel des Bereichs, den Sie mit DefectDojo verwenden möchten. Der Bereichsschlüssel für einen bestimmten Bereich findet sich in der URL. (Dies wurde zuvor als **Jira Project Key** bezeichnet, wird aber seit September 2025 in Jira als **Space Key** bezeichnet).

![image](images/Add_a_Connected_Jira_Project_to_a_Product_3.png)

#### Epic Issue Type Name

Der Name des Epic-Issue-Typs in Jira. Standardmäßig "Epic", kann aber geändert werden, wenn Ihre Jira-Instanz einen anderen Namen verwendet.

#### Issue-Vorlage

Hier können Sie festlegen, wie viele DefectDojo-Metadaten Sie an Jira senden möchten. Wählen Sie eine der beiden Optionen:

* **jira\_full**: Issues erfassen alle Parameter aus DefectDojo \- eine vollständige Beschreibung, CVE, Schweregrad usw. Nützlich, wenn Sie den vollständigen Befund-Kontext in Jira benötigen (zum Beispiel, wenn jemand an diesem Issue arbeitet, der keinen Zugriff auf DefectDojo hat).

Hier ist ein Beispiel für ein **jira\_full**-Issue:
​
![image](images/Add_a_Connected_Jira_Project_to_a_Product_4.png)

* **Jira\_limited:** Issues erfassen nur den DefectDojo-Link, die Links zu Produkt/Engagement/Test, den Reporter und die Environment-Felder. Alle anderen Felder werden nur in DefectDojo erfasst. Nützlich, wenn Sie in Jira keinen vollständigen Befund-Kontext benötigen (zum Beispiel, wenn jemand an diesem Issue arbeitet, der hauptsächlich in DefectDojo arbeitet und nicht auch das vollständige Bild in JIRA benötigt.)

​Hier ist ein Beispiel für ein **jira\_limited**-Issue:

![image](images/Add_a_Connected_Jira_Project_to_a_Product_5.png)

#### Komponente

Wenn Sie Ihren Jira-Bereich mit Komponenten verwalten, können Sie hier die passende Komponente für DefectDojo zuweisen. Um mehr als eine Komponente zuzuweisen, geben Sie eine durch Kommas getrennte Liste ein (zum Beispiel `Security, DevSecOps`); jeder Wert wird als separate Komponente an Jira gesendet.

#### Benutzerdefinierte Felder

Wenn Sie keine benutzerdefinierten Felder mit DefectDojo-Issues verwenden müssen, können Sie dieses Feld auf 'null' belassen.

Wenn Ihre Jira-Bereichseinstellungen jedoch **erfordern**, dass Sie benutzerdefinierte Felder bei neuen Issues verwenden, müssen Sie diese Zuordnungen fest codieren.

Beachten Sie, dass DefectDojo keine Issue-spezifischen Metadaten als benutzerdefinierte Felder senden kann, sondern nur einen Standardwert. Dieser Abschnitt sollte nur eingerichtet werden, wenn Ihr Jira-Bereich **erfordert, dass diese benutzerdefinierten Felder** in jedem Issue in Ihrem Bereich existieren.

Folgen Sie **[dieser Anleitung](#custom-fields-in-jira)**, um mit benutzerdefinierten Feldern zu arbeiten.

#### Felder für Schließen-/Wiedereröffnen-Übergänge

Manche Jira-Workflows **erfordern**, dass bestimmte Felder als Teil eines Übergangs gesetzt werden — zum Beispiel ein Workflow, der sich weigert, ein Issue zu schließen, sofern nicht auf dem Schließen-Bildschirm ein Auflösungs- und ein Begründungsfeld angegeben werden. Die obige Einstellung für benutzerdefinierte Felder gilt nur, wenn ein Issue *erstellt* wird, sie kann diese Workflows also nicht erfüllen.

Ohne diese Einstellungen sendet DefectDojo Schließen-/Wiedereröffnen-Übergänge ohne Felder. Ein Workflow, der Felder erfordert, lehnt diesen Übergang ab, und der Befund und das Jira-Issue geraten außer Sync: Der Befund wird in DefectDojo als Behoben angezeigt, während das Issue in Jira offen bleibt.

Die Einstellungen **Close Transition fields** und **Reopen Transition fields** akzeptieren ein JSON-Objekt, das als `fields`-Payload des Schließen-/Wiedereröffnen-Übergangsaufrufs gesendet wird. Um zum Beispiel Issues mit einer Auflösung von *Won't Fix* zusammen mit einem Begründungswert zu schließen:

```json
{
    "resolution": {"name": "Won't Fix"},
    "customfield_10200": "Risk accepted by security team #report-false-positive"
}
```

Lassen Sie diese Einstellungen auf 'null', wenn Ihr Jira-Workflow keine Felder bei Übergängen erfordert.

**Welche Felder benötigen Sie?**

* Fragen Sie Ihren Jira-Administrator, welche Felder sich auf den **Übergangsbildschirmen** für Schließen/Wiedereröffnen befinden und welche davon von einem Validator erzwungen werden. Das konfigurierte JSON muss **jedes** erforderliche Feld erfüllen: Fehlt ein erforderliches Feld im Payload, lehnt Jira den gesamten Übergang ab und setzt nichts — nur einen Teil der erforderlichen Felder anzugeben, hilft nicht.
* Umgekehrt müssen Felder **auf dem Übergangsbildschirm** vorhanden sein, um überhaupt gesendet zu werden: Jira lehnt Übergänge ab, die versuchen, Felder zu setzen, die für diesen Übergang nicht auf dem Bildschirm vorhanden sind.
* Bei Workflows, die mit dem aktuellen Workflow-Editor von Jira Cloud erstellt wurden, füllt Jira automatisch die Standard-Auflösung der Site aus, wenn ein Issue in einen Status der Kategorie "Erledigt" wechselt. Eine erforderliche Auflösung allein blockiert dort also keinen einfachen Übergang, und der praktische Nutzen von `"resolution"` in diesem Payload besteht darin, einen *aussagekräftigen* Wert zu wählen (zum Beispiel *False Positive*) anstelle des Site-Standards. Workflows, die mit dem klassischen Editor oder mit Marketplace-Validator-Apps erstellt wurden, können die Auflösung weiterhin fest erfordern.
* Wiedereröffnen-Übergänge löschen die Auflösung typischerweise über den Workflow selbst, daher benötigen **Reopen Transition fields** in der Regel nur die von Ihrem Workflow erforderlichen benutzerdefinierten Felder.

**Hinweise:**

* Dasselbe JSON wird für *jeden* Schließen- (oder Wiedereröffnen-)Übergang für das Produkt oder Engagement gesendet — die Werte sind statisch und variieren nicht pro Befund. Wenn Sie unterschiedliche Felder je nach Disposition benötigen (zum Beispiel eine andere Auflösung für Falsch-positiv-Befunde als für behobene Befunde), verwenden Sie den DefectDojo Pro Jira Integrator, der pro-Status-Übergangsfeldzuordnungen unterstützt.
* Werte verwenden dasselbe Format wie die REST-API von Jira: Zeichenketten für Textfelder, `{"name": ...}` für Auflösungen, `[{"name": ...}]` für Mehrfachauswahlfelder usw.
* Wenn Übergänge abgelehnt wurden, während diese Einstellungen fehlten oder unvollständig waren, behebt eine Korrektur der Einstellungen die Abweichung: Der nächste Statuspush für den Befund versucht den Übergang mit den konfigurierten Feldern erneut.
* Beide Einstellungen sind auch über den REST-Endpunkt `/api/v2/jira_projects/` verfügbar (`close_transition_fields` / `reopen_transition_fields`), sodass sie über die API verwaltet werden können.
* Diese Felder werden auch angewendet, wenn DefectDojo ein Issue schließt, weil dessen Befund **gelöscht** wurde — die Werte werden zum Zeitpunkt erfasst, an dem das Schließen eingereiht wird.

#### Jira-Labels

Wählen Sie die relevanten Labels aus, mit denen das Issue in Jira erstellt werden soll, z. B. **DefectDojo**, **YourProductName..**

![image](images/Add_a_Connected_Jira_Project_to_a_Product_6.png)

#### Standard-Zuweisung

Der Name der Standard-Zuweisung in Jira. Wenn leer gelassen, folgt DefectDojo dem Standardverhalten Ihres Jira-Bereichs beim Erstellen von Issues.

### Jira-Projekteinstellungen

#### Enabled

Dieser Schalter steuert, ob DefectDojo Befunde für dieses Produkt an Jira überträgt. Das Deaktivieren löscht oder ändert keine vorhandenen, von DefectDojo erstellten Jira-Tickets, verhindert aber weitere Updates oder das Erstellen neuer Issues.

Jira-Integrationen können nur dann von Ihrer Instanz entfernt werden, wenn keine zugehörigen Issues erstellt wurden. Wenn Issues erstellt wurden, gibt es keine Möglichkeit, eine Jira-Instanz vollständig aus DefectDojo zu entfernen.

#### Vulnerability Id als Jira-Label hinzufügen

Dies ermöglicht es Ihnen, die Vulnerability-ID-Daten automatisch als Jira-Label hinzuzufügen. Vulnerability-IDs werden Befunden von einzelnen Sicherheitstools hinzugefügt \- dies können Common Vulnerabilities and Exposures (CVE)-IDs oder ein anderes, für das meldende Tool spezifisches Format sein.

#### Push All Issues

Wenn aktiviert, überträgt DefectDojo automatisch alle Aktiven und Verifizierten Befunde als Issues an Jira. Wenn nicht aktiviert, müssen alle Befunde manuell an Jira übertragen werden (einzeln oder per Massenübertragung).

Wenn diese Einstellung aktiviert ist, bleiben Jira-Issues auch dann mit DefectDojo synchron, wenn sich der Status des Befunds ändert.

#### Enable Engagement Epic Mapping

In DefectDojo repräsentieren Engagements eine Ansammlung von Arbeit. Jedes Engagement enthält einen oder mehrere Tests, die einen oder mehrere zu behebende Befunde enthalten. Epics in Jira funktionieren ähnlich, und dieses Kontrollkästchen ermöglicht es Ihnen, Engagements als Epics an Jira zu übertragen.

* Ein Engagement in DefectDojo \- beachten Sie die drei unten aufgeführten Befunde.
​
![image](images/Add_a_Connected_Jira_Project_to_a_Product_8.png)
* Wie dasselbe Engagement zu einem Epic wird, wenn es an JIRA übertragen wird \- die Befunde des Engagements werden ebenfalls übertragen und leben innerhalb des Epics als untergeordnete Issues.

![image](images/Add_a_Connected_Jira_Project_to_a_Product_9.png)

#### Push Notes

Wenn aktiviert, werden Jira-Kommentare beim zugehörigen Befund in DefectDojo unter Notizen angezeigt, und umgekehrt; Notizen zu Befunden werden dem zugehörigen Jira-Issue als Kommentare hinzugefügt.

#### SLA-Benachrichtigungen als Kommentare senden

Wenn aktiviert, erhalten alle Issues, die gegen die Service Level Agreement-Regeln von DefectDojo verstoßen, entsprechende Kommentare im Jira-Issue. Diese Kommentare werden täglich gepostet, bis das Issue gelöst ist.

Service Level Agreements können in DefectDojo unter **Configuration \> SLA Configuration** konfiguriert und jedem Produkt zugewiesen werden.

#### Benachrichtigungen zum Ablauf der Risikoakzeptanz als Kommentar senden

Wenn aktiviert, erhält jedes Issue, bei dem die zugehörige DefectDojo-Risikoakzeptanz abläuft, einen entsprechenden Kommentar im Jira-Issue. Diese Kommentare werden täglich gepostet, bis das Issue gelöst ist.

### Jira-Einstellungen auf Engagement-Ebene

Standardmäßig **übernehmen Engagements die Jira-Einstellungen von ihrem Produkt**. Sie können die Jira-Einstellungen jedoch für einzelne Engagements überschreiben.

Um auf die Jira-Einstellungen auf Engagement-Ebene zuzugreifen, klicken Sie auf das Zahnrad-Menü ⚙️ bei einem Engagement und öffnen Sie die Seite **Jira Project Settings**.

Von hier aus können Sie **Inherit from Product** deaktivieren und Engagement-spezifische Werte für **Project Key**, **Issue Template, Custom Fields, Jira Labels, Default Assignee** und andere Einstellungen angeben.

Beachten Sie, dass ein Engagement, sobald ihm ein eigenes Jira-Projekt zugewiesen ist, nicht mehr vom Produkt erben kann.

![image](images/Creating_Issues_in_Jira_5.png)

## Schritt 4: Bidirektionale Synchronisation konfigurieren: Jira-Webhook

Die Jira-Integration ermöglicht bidirektionale Synchronisation über Webhook. DefectDojo empfängt Jira-Benachrichtigungen an einer eindeutigen Adresse, wodurch je nach Konfiguration Jira-Kommentare bei Befunden empfangen werden können oder Befunde über Jira aufgelöst werden können.

### Ihre Jira-Webhook-URL finden

Ihr Jira-Webhook befindet sich im Formular System Settings unter **Jira Integration Settings**: **Enterprise Settings \> System Settings** in der Seitenleiste.

Sie müssen außerdem auf derselben Seite **Enable Jira Web Hook** aktivieren, bevor DefectDojo eingehende Jira-Benachrichtigungen verarbeitet. Eingehende Webhooks werden ignoriert, wenn entweder dieses Kästchen oder **Enable Jira Integration** (siehe [Schritt 1](#step-1-enable-the-jira-integration-in-system-settings)) deaktiviert ist.

![image](images/Configuring_the_Jira_DefectDojo_Webhook.png)

### Den Jira-Webhook erstellen

1. Besuchen Sie `**https:// \<YOUR JIRA URL\> /plugins/servlet/webhooks**`
2. Klicken Sie auf 'Create a Webhook'.
3. Geben Sie für das Feld mit der Bezeichnung 'URL' ein: `https:// \<**YOUR DOJO DOMAIN**\> /jira/webhook/ \<**YOUR GENERATED WEBHOOK SECRET**\>`. Das Web Hook Secret ist unter den oben genannten Jira Integration Settings aufgeführt.
4. Aktivieren Sie unter 'Comments' die Option 'Created'. Aktivieren Sie unter Issue die Option 'Updated'.
5. Stellen Sie sicher, dass Ihre JIRA-Instanz dem von Ihrer DefectDojo-Instanz verwendeten SSL-Zertifikat vertraut. Für JIRA Cloud muss DefectDojo [ein gültiges SSL/TLS-Zertifikat verwenden, das von einer global vertrauenswürdigen Zertifizierungsstelle signiert wurde](https://developer.atlassian.com/cloud/jira/platform/deprecation-notice-registering-webhooks-with-non-secure-urls/)

Beachten Sie, dass Sie kein Secret innerhalb von Jira erstellen müssen, um diesen Webhook zu verwenden. Das Secret ist in die URL von DefectDojo eingebaut, daher genügt es, einfach die vollständige URL in das Jira-Webhook-Formular einzutragen.

Eingehende Webhook-Anfragen werden über das Secret in dieser URL authentifiziert, behandeln Sie die vollständige URL daher als Zugangsdaten und halten Sie sie geheim.

#### Den Webhook testen

Sobald Sie ein oder mehrere Issues aus DefectDojo-Befunden erstellt haben, können Sie den Webhook testen, indem Sie einem dieser Befunde eine Notiz hinzufügen. Die Notiz sollte vom Jira-Webhook als Notiz empfangen werden.

Wenn dies nicht korrekt funktioniert, könnte dies an einem Firewall-Problem auf Ihrer Jira-Instanz liegen, das den Webhook blockiert.

* Die Firewall-Regeln von DefectDojo enthalten ein Kontrollkästchen für **Jira Cloud**, das aktiviert werden muss, bevor DefectDojo Webhook-Nachrichten von Jira empfangen kann.

### Alternative: Jira Automation verwenden (Send web request)

Manche Jira-Instanzen erlauben keine System-Webhooks unter `/plugins/servlet/webhooks` — zum Beispiel, wenn dieser Verwaltungsbereich eingeschränkt ist und nur **Jira Automation**-Regeln erlaubt sind. In diesem Fall können Sie dieselbe bidirektionale Synchronisation über die Aktion **Send web request** von Automation steuern, die an denselben DefectDojo-Webhook-Endpunkt postet.

Der Webhook-Endpunkt von DefectDojo akzeptiert jede HTTP-`POST`-Anfrage mit `Content-Type: application/json` und einem gültigen Secret im URL-Pfad. Es ist **nicht** erforderlich, dass die Anfrage vom System-Webhook-Mechanismus von Jira stammt, daher funktioniert die Aktion "Send web request" von Automation als direkter Ersatz.

#### Voraussetzungen

Es gelten dieselben Voraussetzungen wie beim System-Webhook:

* **Enable JIRA integration** und **Enable JIRA web hook** sind beide auf der Seite ⚙️ **Configuration \> System Settings** aktiviert.
* Ein nicht-leeres **Jira webhook secret** ist auf dieser Seite gesetzt. Das Secret darf nur die Zeichen `A-Z`, `a-z`, `0-9`, `_` und `-` enthalten.
* Der Befund (oder die Befundgruppe) ist bereits mit dem Jira-Issue verknüpft. Wenn das Issue nicht mit einem DefectDojo-Befund verknüpft ist, wird die Anfrage trotzdem akzeptiert (HTTP `200`), aber es wird keine Aktion ausgeführt.

#### Wie DefectDojo die Anfrage verarbeitet

* DefectDojo verzweigt anhand eines Feldes `webhookEvent` auf oberster Ebene. Nur `"jira:issue_updated"` und `"comment_created"` werden verarbeitet; jeder andere Wert wird akzeptiert und ignoriert. Automation fügt dieses Feld nicht von sich aus hinzu, Sie müssen es also selbst in den Anfragetext aufnehmen.
* Setzen Sie den Anfrage-**Body** deshalb auf **Custom data** und geben Sie das untenstehende JSON an. Die Body-Optionen **Empty** und **Jira issue data** enthalten das erforderliche Feld `webhookEvent` nicht, DefectDojo wird sie daher ignorieren.
* Der Endpunkt gibt immer HTTP `200` zurück, unabhängig davon, ob ein Update angewendet wurde. Erfolg oder Misserfolg sind nur im Antworttext und in den DefectDojo-Protokollen sichtbar — ein `200` im Audit-Log von Automation bestätigt für sich allein nicht, dass das Update einen Befund erreicht hat.

#### Regel 1 — Issue aktualisiert

Erstellen Sie eine Automation-Regel mit:

* **Trigger:** *Issue transitioned* (oder ein anderer Trigger, der auslöst, wenn sich die von Ihnen synchronisierten Felder ändern, z. B. *Field value changed* bei Status).
* **Aktion:** *Send web request*
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

* `issue.id` muss die **numerische interne Jira-Issue-ID** (`{{issue.id}}`) sein, nicht der Issue-Schlüssel (z. B. `PROJ-123`). DefectDojo ordnet das Update anhand dieser numerischen ID einem Befund zu.
* Die Felder `resolution` und `updated` müssen immer vorhanden sein. `resolution` darf `null` sein, aber wenn eines der beiden Felder fehlt, wird die Anfrage akzeptiert (`200`) und stillschweigend nicht verarbeitet.
* Statussynchronisation und automatische Behebung werden durch `status.statusCategory.key` gesteuert, dessen Jira-Werte `new` (To Do), `indeterminate` (In Progress) und `done` (Done) sind. Ein Befund wird nur dann als behoben markiert, wenn das Issue tatsächlich geschlossen wurde, nicht schon deshalb, weil zufällig ein Auflösungswert vorhanden ist.

#### Regel 2 — Issue kommentiert

Erstellen Sie eine zweite Automation-Regel mit:

* **Trigger:** *Issue commented*
* **Aktion:** *Send web request* — dieselbe URL, Methode, denselben Header und dieselbe Body-Option *Custom data* wie bei Regel 1, mit folgendem Body:

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
* DefectDojo leitet das Ziel-Issue aus der URL `comment.self` ab — genauer gesagt aus der `<id>` im Segment `.../issue/<id>/comment/...` — daher muss `{{issue.id}}` (die numerische ID) dort erscheinen.
* **Schleifenvermeidung:** Wenn der Kommentarautor mit dem Jira-Konto übereinstimmt, das DefectDojo zum Posten eigener Kommentare verwendet, überspringt DefectDojo den Kommentar, um eine Echo-Schleife zu vermeiden. Wenn Sie möchten, dass *alle* Kommentare eingelesen werden, führen Sie die Automation-Regel als **anderen** Jira-Benutzer aus als den, der in der Jira-Instanz von DefectDojo konfiguriert ist.

#### Ein Hinweis zu Smart Values

Die oben gezeigten Smart Values (`{{issue.id}}`, `{{issue.status.statusCategory.key}}`, `{{comment.author.accountId}}` usw.) sind die Standardnamen von Jira Cloud, können jedoch zwischen Instanzen variieren. Verwenden Sie vor dem Live-Gang die Payload-Vorschau von Automation, um zu bestätigen, dass jeder Smart Value zu dem aufgelöst wird, was Sie erwarten.

## Die Jira-Integration testen

#### Test 1: Werden Befunde erfolgreich an Jira übertragen?

Um zu testen, ob die Jira-Integration ordnungsgemäß funktioniert, können Sie dem mit Jira verknüpften Produkt in DefectDojo einen neuen leeren Befund hinzufügen. **Product \> Findings \> Add New Finding.**

Geben Sie beliebigen Titel, Schweregrad und Beschreibung ein und klicken Sie dann auf "Finished". Der Befund sollte mit allen relevanten Metadaten als Issue in Jira erscheinen.

Wenn Jira-Issues nicht korrekt erstellt werden, prüfen Sie Ihre Notifications auf Fehlercodes.

* Bestätigen Sie, dass der mit der Jira-Konfiguration von DefectDojo verknüpfte Jira-Benutzer die Berechtigung hat, Issues in diesem bestimmten Jira-Bereich zu erstellen und zu aktualisieren.

#### Test 2: Jira-Webhooks senden an DefectDojo

Um die Jira-Webhooks zu testen, fügen Sie einem Befund, der auch in JIRA als Issue existiert (zum Beispiel dem Test-Issue im obigen Abschnitt), eine Notiz hinzu.

Wenn die Webhooks korrekt konfiguriert sind, sollten Sie die Notiz in Jira als Kommentar zum Issue sehen.

Wenn dies nicht korrekt funktioniert, könnte dies an einem Firewall-Problem auf Ihrer Jira-Instanz liegen, das den Webhook blockiert.

* Die Firewall-Regeln von DefectDojo enthalten ein Kontrollkästchen für **Jira Cloud**, das aktiviert werden muss, bevor DefectDojo Webhook-Nachrichten von Jira empfangen kann.

## Die Verbindung zu Jira trennen

Jira-Integrationen können nur dann von Ihrer Instanz entfernt werden, wenn keine zugehörigen Issues erstellt wurden. Wenn Issues erstellt wurden, gibt es keine Möglichkeit, eine Jira-Instanz vollständig aus DefectDojo zu entfernen.

Sie können Ihre Jira-Integration jedoch deaktivieren, indem Sie sie auf Produktebene deaktivieren. Deaktivieren Sie auf der Seite **Jira Project Settings** (zugänglich über das ⚙️-Zahnrad-Menü bei einem Produkt) den Schalter **Enabled**. Dies löscht oder ändert keine vorhandenen, von DefectDojo erstellten Jira-Tickets, deaktiviert aber weitere Updates.

# Befunde an Jira übertragen

Ein Produkt mit einer JIRA-Zuordnung kann Befunde über mehrere Methoden als Issues an Jira übertragen. Sie können Befunde einzeln, in Massen, als Befundgruppen oder automatisch übertragen.

## Einen einzelnen Befund übertragen

1. Öffnen Sie den Befund, den Sie übertragen möchten.
2. Klicken Sie auf das **☰ Finding Menu** und wählen Sie **Push to Jira**.
3. Bestätigen Sie die Übertragung bei entsprechender Aufforderung. DefectDojo erstellt ein Jira-Issue und verknüpft es mit dem Befund.

Sobald das Issue erstellt wurde, zeigt DefectDojo auf der Befund-Seite einen Link zum Jira-Issue an.

![image](images/Creating_Issues_in_Jira_2.png)

Sie können auch das Kontrollkästchen **Push to Jira** aktivieren, wenn Sie einen Befund über das Formular **Edit Finding** bearbeiten. Wenn der Befund gespeichert wird, wird er an Jira übertragen.

### Ein verknüpftes Jira-Issue aktualisieren

Wenn ein Befund bereits ein verknüpftes Jira-Issue hat, aktualisiert das erneute Auswählen von **Push to Jira** das vorhandene Jira-Issue mit allen in DefectDojo vorgenommenen Änderungen. Wenn **Push All Issues** für das Produkt aktiviert ist, geschieht diese Synchronisation automatisch.

### Einen Befund von Jira trennen

Um die Verknüpfung zwischen einem Befund und seinem Jira-Issue zu entfernen, klicken Sie auf das **☰ Finding Menu** und wählen Sie **Unlink From Jira**. Dies entfernt die Verknüpfung in DefectDojo, löscht aber nicht das Jira-Issue selbst.

## Befunde in Massen übertragen

Sie können mehrere Befunde gleichzeitig mit dem Formular Bulk Update an Jira übertragen:

1. Wählen Sie in einer Befundliste über die Kontrollkästchen die Befunde aus, die Sie übertragen möchten.
2. Öffnen Sie das Formular **Bulk Update**.
3. Aktivieren Sie unter **Jira Settings** das Kontrollkästchen **Push to Jira**.
4. Klicken Sie auf **Submit**.

Die ausgewählten Befunde werden für die Übertragung an Jira eingereiht. DefectDojo zeigt eine Bestätigungsmeldung an, wie viele Befunde eingereiht wurden.

## Engagements als Epics übertragen

Wenn **Enable Engagement Epic Mapping** in Ihren Jira Project Settings aktiviert ist, können Sie ein Engagement als Epic an Jira übertragen. Die Befunde des Engagements werden als untergeordnete Issues innerhalb dieses Epics übertragen.

Um ein Engagement als Epic zu übertragen:

1. Öffnen Sie das Engagement, das Sie übertragen möchten.
2. Klicken Sie auf das **☰ Engagement Menu** und wählen Sie **Push to Jira**.
3. Geben Sie optional einen **Epic Name** (standardmäßig der Engagement-Name, falls leer gelassen) und eine **Epic Priority** an.
4. Aktivieren Sie **Push to Jira (Create Epic)** und übermitteln Sie das Formular.

## Befundgruppen als Jira-Issues übertragen

Wenn Sie Befundgruppen aktiviert haben, können Sie eine Gruppe von Befunden als ein einzelnes Issue statt als separate Issues für jeden Befund an Jira übertragen.

Um eine Befundgruppe zu übertragen:

1. Öffnen Sie die Befundgruppe.
2. Klicken Sie auf das **☰ Finding Group Menu** und wählen Sie **Push to Jira**, oder aktivieren Sie das Kontrollkästchen **Push to Jira** beim Bearbeiten der Befundgruppe.

Das mit einer Befundgruppe verknüpfte Jira-Issue muss bei Bedarf direkt aus der Jira-Instanz gelöscht werden.

### Befundgruppen automatisch erstellen und übertragen

Bei aktiviertem **Push All Issues** für das Produkt und einer beim Import ausgewählten **Group By**-Option:

Solange die Befundgruppen erfolgreich erstellt werden, wird die Befundgruppe automatisch als Issue an Jira übertragen, nicht die einzelnen Befunde.

![image](images/Creating_Issues_in_Jira_4.png)

## Automatisches Übertragungsverhalten

DefectDojo kann Befunde und Updates in mehreren Szenarien automatisch an Jira übertragen:

### Push All Issues

Wenn die Einstellung **Push All Issues** in den Jira Project Settings eines Produkts aktiviert ist, erstellt DefectDojo automatisch Jira-Issues für alle Aktiven und Verifizierten Befunde. Dies schließt Befunde ein, die per Scan-Import erstellt wurden. Sobald ein Jira-Issue erstellt wurde, bleibt es auch dann mit DefectDojo synchron, wenn sich der Status des Befunds ändert.

### Automatische Synchronisation bei Statusänderungen

Wenn **Push All Issues** oder die systemweite Einstellung **Finding Jira Sync** aktiviert ist, aktualisiert DefectDojo automatisch verknüpfte Jira-Issues, wenn bestimmte Aktionen an Befunden durchgeführt werden:

* **Request Review** \- Ein Kommentar wird zum verknüpften Jira-Issue hinzugefügt (oder zum Jira-Issue der Befundgruppe, wenn der Befund zu einer Gruppe gehört).
* **Clear Review** \- Ein Kommentar wird zum verknüpften Jira-Issue hinzugefügt.
* **Close Finding** \- Das verknüpfte Jira-Issue wird aktualisiert, um die Schließung widerzuspiegeln. Wenn **Push Notes** aktiviert ist, wird auch ein Kommentar hinzugefügt.

## Jira-Kommentare und Notizen

Wenn **Push Notes** in den Jira Project Settings aktiviert ist:

* Wenn ein Kommentar zu einem Jira-Issue hinzugefügt wird, wird derselbe Kommentar dem Befund unter dem Abschnitt **Notes** hinzugefügt.
* Wird umgekehrt eine Notiz zu einem Befund hinzugefügt, wird die Notiz dem Jira-Issue als Kommentar hinzugefügt.

## Jira-Statusänderungen

Die Konfiguration der Jira-Instanz enthält Einträge für zwei Jira-Übergänge, die eine Statusänderung bei einem Befund auslösen.

* Wenn der **'Close'-Übergang** bei Jira durchgeführt wird, wird auch der zugehörige Befund geschlossen und in DefectDojo als **Inaktiv** und **Behoben** markiert. DefectDojo protokolliert diese Änderung auf der Befund-Seite unter der Überschrift **Mitigated By**.
​
![image](images/Creating_Issues_in_Jira_3.png)

* Wenn der **'Reopen'-Übergang** beim Jira-Issue durchgeführt wird, wird der zugehörige Befund in DefectDojo auf **Aktiv** gesetzt und verliert seinen **Behoben**-Status.

## Jira-Auflösungen auf Risikoakzeptanz/Falsch-positiv zuordnen

Die Konfiguration der Jira-Instanz enthält zwei optionale Felder, mit denen Sie eine Jira-**Auflösung** einem DefectDojo-Befundstatus zuordnen können:

* **Risk Accepted Finding Mapping Resolution** — wenn ein Jira-Issue mit dieser Auflösung geschlossen wird, wird der verknüpfte Befund in DefectDojo zu Risiko akzeptiert.
* **False Positive Finding Mapping Resolution** — wenn ein Jira-Issue mit dieser Auflösung geschlossen wird, wird der verknüpfte Befund in DefectDojo zu Falsch-positiv.

### Status vs. Auflösung: Eine häufige Verwechslung

Diese Felder ordnen die Jira-**Auflösung** zu, nicht den Jira-**Status**. Status und Auflösung sind zwei unabhängige Jira-Konzepte: Der Status beschreibt, wo sich das Issue im Workflow befindet (Open, In Progress, Done), während die Auflösung beschreibt, wie es gelöst wurde (Fixed, Won't Do, Duplicate, False Positive usw.).

### Voraussetzung: Eine "Set issue resolution"-Post-Funktion beim Jira-Workflow-Übergang

Die Workflow-Engine von Jira füllt das Auflösungsfeld nicht automatisch aus. Jeder Übergang, der ein Issue mit einer bestimmten Auflösung schließen soll, benötigt eine am Übergang selbst konfigurierte **Set issue resolution**-Post-Funktion. Ohne diese Post-Funktion wechselt das Issue zwar in den neuen Status, aber die Auflösung bleibt leer, und die Zuordnung von DefectDojo hat nichts, womit sie abgleichen kann.

Ein Jira-Administrator kann diese Post-Funktion über **Project Settings → Workflows → (Workflow bearbeiten) → (den Schließen-Übergang auswählen) → Post Functions → Add post function → Set issue resolution** hinzufügen.

# Benutzerdefinierte Felder in Jira

<span style="background: rgba(243, 122, 78,0.5">DefectDojo unterstützt derzeit nicht die Übergabe von Issue-spezifischen Informationen in diese benutzerdefinierten Felder \- diese Felder müssen nach der Erstellung des Issues manuell in Jira aktualisiert werden. Jedes benutzerdefinierte Feld wird von DefectDojo nur mit einem Standardwert erstellt.</span>

<span style="background: rgba(0, 207, 83, 0.44)"> Jira Cloud ermöglicht es Ihnen nun, einen Standardwert für benutzerdefinierte Felder direkt in der App zu erstellen. [Siehe die Dokumentation von Atlassian zu benutzerdefinierten Feldern](https://support.atlassian.com/jira-cloud-administration/docs/configure-a-custom-field/) für weitere Informationen zur Konfiguration.</span>

Die integrierten Jira-Issue-Typen von DefectDojo (**Bug, Task, Story** und **Epic**) sind so eingerichtet, dass sie 'von Haus aus' funktionieren. Datenfelder in DefectDojo werden automatisch den entsprechenden Feldern in Jira zugeordnet. Standardmäßig weist DefectDojo jedem neu erstellten Issue Priority, Labels und einen Reporter zu.

Manche Jira-Konfigurationen erfordern die Berücksichtigung zusätzlicher benutzerdefinierter Felder, bevor ein Issue erstellt werden kann. Dieser Prozess ermöglicht es Ihnen, diese benutzerdefinierten Felder in Ihrer DefectDojo \-\> Jira-Integration zu berücksichtigen und sicherzustellen, dass Issues erfolgreich erstellt werden. Diese benutzerdefinierten Felder werden jedem API-Aufruf hinzugefügt, der von DefectDojo an eine verknüpfte Jira-Instanz gesendet wird.

Wenn Sie in Jira noch keine benutzerdefinierten Felder verwenden, müssen Sie diesem Prozess nicht folgen.

1. Die Namen Ihrer benutzerdefinierten Felder in Jira erfassen (**Jira UI**)
2. Die Key-Werte für die neuen benutzerdefinierten Felder ermitteln (Jira Field Spec Endpoint)
3. Die zulässigen Daten für jedes benutzerdefinierte Feld anhand der Key-Werte als Referenz ermitteln (Jira Issue Endpoint)
4. Einen JSON-Feldreferenzblock erstellen, um alle Keys benutzerdefinierter Felder und zulässigen Daten zu verfolgen (Jira Issue Endpoint)
5. Den JSON-Block im zugehörigen DefectDojo-Produkt speichern, um die Erstellung benutzerdefinierter Felder aus Jira zu ermöglichen (DefectDojo UI)
6. Ihre Arbeit testen und sicherstellen, dass alle erforderlichen Daten korrekt von Jira fließen

#### Schritt 1: Die Namen Ihrer benutzerdefinierten Felder in Jira erfassen

Jira unterstützt eine Vielzahl unterschiedlicher Kontextfelder, einschließlich Date Pickers, benutzerdefinierter Labels und Radio Buttons. Jedes dieser Kontextfelder hat einen anderen Key-Wert, der in der Jira-API zu finden ist.

Notieren Sie sich die Namen jedes erforderlichen benutzerdefinierten Feldes, da Sie im nächsten Schritt die Jira-API danach durchsuchen müssen.

**Beispiel einer Liste benutzerdefinierter Felder (Ihre Namen für benutzerdefinierte Felder werden anders lauten):**

* DefectDojo Custom URL Field
* Ein weiteres Beispiel für ein benutzerdefiniertes Feld
* ...

#### Schritt 2: Ihre Jira Custom Field Key-Werte finden

Beginnen Sie diesen Prozess, indem Sie zur Field Spec URL für Ihre gesamte Jira-Instanz navigieren.

Hier ist ein Beispiel für eine Field Spec URL:

`https://yourcompany-example.atlassian.net/rest/api/2/field`

Die API gibt eine lange JSON-Zeichenkette zurück, die in lesbaren Text formatiert werden sollte (mit einem Code-Editor, einer Browser-Erweiterung oder <https://jsonformatter.org/>).

Das von dieser URL zurückgegebene JSON enthält alle Ihre benutzerdefinierten Jira-Felder, von denen die meisten für DefectDojo irrelevant sind und Werte von `"Null"` haben. Jedes Objekt in dieser API-Antwort entspricht einem anderen Feld in Jira. Sie müssen nach den Objekten suchen, deren `"name"`-Attribute mit den Namen der von Ihnen in der Jira-UI erstellten benutzerdefinierten Felder übereinstimmen, und dann den Wert ihres "key"-Attributs notieren.

![image](images/Using_Custom_Fields.png)

Sobald Sie das passende Objekt in der JSON-Ausgabe gefunden haben, können Sie den "key"-Wert bestimmen \- in diesem Fall ist es `customfield_10050`.

Jira generiert für jedes benutzerdefinierte Feld unterschiedliche Key-Werte, aber diese Key-Werte ändern sich nach der Erstellung nicht mehr. Wenn Sie in Zukunft ein weiteres benutzerdefiniertes Feld erstellen, erhält es einen neuen Key-Wert.

**Unsere Liste benutzerdefinierter Felder erweitern:**

* "DefectDojo Custom URL Field" \= customfield\_10050
* "Ein weiteres Beispiel für ein benutzerdefiniertes Feld" \= customfield\_12345
* ...

#### Schritt 3 \- Die benutzerdefinierten Felder bei einem Jira-Issue finden

Finden Sie ein Issue in Jira, das die in Schritt 2 erfassten benutzerdefinierten Felder enthält. Kopieren Sie den Issue-Schlüssel für den Titel (sollte ähnlich aussehen wie "`EXAMPLE-123`") und navigieren Sie zu folgender URL:

`https://yourcompany-example.atlassian.net/rest/api/2/issue/EXAMPLE-123`

Dies liefert eine weitere JSON-Zeichenkette.

Wie zuvor enthält die API-Ausgabe viele `customfield_##`-Objektparameter mit `null`-Werten \- dies sind benutzerdefinierte Felder, die Jira standardmäßig hinzufügt und die für dieses Issue nicht relevant sind. Sie enthält außerdem `customfield_##`-Werte, die den im vorherigen Schritt gefundenen Key-Werten benutzerdefinierter Felder entsprechen. Im Gegensatz zur Field-Spec-Ausgabe sehen Sie hier keine Namen, die diese benutzerdefinierten Felder identifizieren, weshalb Sie die Key-Werte in Schritt 2 notieren mussten.

![image](images/Using_Custom_Fields_2.png)

**Beispiel:**
Wir wissen, dass `customfield_10050` das DefectDojo Custom URL Field repräsentiert, da wir es in Schritt 2 notiert haben. Wir können nun sehen, dass `customfield_10050` im Issue `EXAMPLE-123` den Wert `"https://google.com"` enthält.

#### Schritt 4 \- Eine JSON-Feldreferenz aus jedem Jira Custom Field Key erstellen

Sie müssen nun den Wert jedes benutzerdefinierten Feldes aus Ihrer Liste nehmen und in einem JSON-Objekt speichern (zur Verwendung als Referenz). Sie können alle benutzerdefinierten Felder ignorieren, die nicht in Ihrer Liste vorkommen.

Dieses JSON-Objekt enthält alle Standardwerte für neue Jira-Issues. Wir empfehlen, Namen zu verwenden, die Ihr Team leicht als 'Standard'-Werte erkennt, die geändert werden müssen: '`change-me.com`', '`Change this paragraph.`' usw.

**Beispiel:**

Aus Schritt 3 wissen wir nun, dass Jira für "`customfield_10050`" eine URL-Zeichenkette erwartet. Wir können dies nutzen, um unser Beispiel-JSON-Objekt zu erstellen.

Angenommen, wir hätten auch ein DefectDojo-bezogenes Kurztextfeld gefunden, das wir als "`customfield_67890`" identifiziert haben. Wir würden dieses Feld in unserer zweiten API-Ausgabe betrachten, den zugehörigen Wert ansehen und den gespeicherten Wert ebenfalls in unserem Beispiel-JSON-Objekt referenzieren.
​
Ihr JSON-Objekt beginnt so auszusehen, während Sie weitere benutzerdefinierte Felder hinzufügen.

```
{
	"customfield_10050": "https://change-me.com",
	"customfield_67890": "This is the short text custom field."
}
```

Wiederholen Sie diesen Prozess, bis alle für DefectDojo relevanten benutzerdefinierten Felder aus Jira zu Ihrer JSON-Feldreferenz hinzugefügt wurden.

#### Datentypen \& Jira-Syntax

Manche Felder, wie zum Beispiel Datumsfelder, können sich auf mehrere benutzerdefinierte Felder in Jira beziehen. In diesem Fall müssen Sie beide Felder zu Ihrer JSON-Feldreferenz hinzufügen.

```
  "customfield_10040": "1970-01-01",
  "customfield_10041": "1970-01-01T03:30:00.000+0200",
```

Andere Felder, wie zum Beispiel das Label-Feld, werden möglicherweise als Liste von Zeichenketten geführt \- bitte stellen Sie sicher, dass Ihre JSON-Feldreferenz ein Format verwendet, das der API-Ausgabe von Jira entspricht.

```
// a list of custom labels on a Jira object
  "customfield_10042": [
    "custom-label-one",
    "this-is-default",
    "change-me-please"
  ],
```

Andere benutzerdefinierte Felder können zusätzliche, kontextbezogene Informationen enthalten, die aus der Feldreferenz entfernt werden sollten. Zum Beispiel enthält das Feld Custom Multichoice in der API-Ausgabe einen zusätzlichen Block, den Sie entfernen müssen, da dieser Block den aktuellen Wert des Feldes speichert.

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
* stattdessen können Sie dies wie folgt kürzen und den zweiten Teil ignorieren:

```
"customfield_10047": [
   {
      "value": "A"
   }
]
```

#### Beispiel für eine vollständige Feldreferenz

Hier ist eine vollständige JSON-Feldreferenz mit Inline-Kommentaren, die erklären, wozu jedes benutzerdefinierte Feld gehört. Dies ist als umfassendes Beispiel gedacht. Ihr JSON wird je nach den benutzerdefinierten Werten, die Sie bei der Issue-Erstellung verwenden möchten, unterschiedliche Key-Werte und Datenpunkte enthalten.

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

#### Schritt 5 \- Die benutzerdefinierten Felder zu einem DefectDojo-Produkt hinzufügen

Sie können diese benutzerdefinierten Felder nun dem zugehörigen DefectDojo-Produkt auf der Seite Jira Project Settings hinzufügen (zugänglich über das ⚙️-Zahnrad-Menü beim Produkt). Fügen Sie die JSON-Feldreferenz als reinen Text in das Feld **Custom Fields** ein und speichern Sie.

#### Schritt 6 \- Ihre Jira Custom Fields anhand eines neuen Befunds testen:

Wenn Sie nun einen neuen Befund im mit Jira verknüpften Produkt erstellen, erstellt Jira automatisch all diese benutzerdefinierten Felder in Jira gemäß dem darin enthaltenen JSON-Block. Diese benutzerdefinierten Felder werden mit den Standardwerten ("change\-me\-please" usw.) erstellt.

Navigieren Sie innerhalb des Produkts in DefectDojo zur Seite Findings \> Add New Finding. Stellen Sie sicher, dass der Befund sowohl Aktiv als auch Verifiziert ist, um sicherzustellen, dass er an Jira übertragen wird, und bestätigen Sie dann auf der Jira-Seite, dass die benutzerdefinierten Felder ohne Inkonsistenzen erfolgreich erstellt wurden.
