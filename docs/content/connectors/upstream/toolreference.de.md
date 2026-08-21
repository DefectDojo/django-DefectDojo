---
title: Referenz zu Upstream-Connector-Tools
description: Unsere Liste der unterstützten Connector-Tools und wie Sie sie mit DefectDojo
  einrichten
aliases:
- /de/import_data/pro/connectors/connectors_tool_reference/
- /de/en/connecting_your_tools/connectors/connectors_tool_reference
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Hinweis: Upstream-Connectors sind eine reine DefectDojo-Pro-Funktion.</span>

Beim Einrichten eines Connectors für ein unterstütztes Tool müssen Sie DefectDojo bestimmte Informationen zur API des Tools mitteilen. Grundsätzlich benötigen Sie:

* **Location** \-ein Feld, das im Allgemeinen auf die URL Ihres Tools in Ihrem Netzwerk verweist,
* **Secret** \- in der Regel ein API-Schlüssel.

Viele Tools stellen genau einen festen API\-Host bereit. Für diese füllt DefectDojo das Feld **Location** beim Anlegen des Connectors automatisch aus. Sie müssen die URL also nicht von dieser Seite kopieren. Behalten Sie den vorgegebenen Wert. Ändern Sie ihn nur, wenn Ihre Instanz einen anderen Host verwendet, zum Beispiel eine selbst gehostete Installation oder eine andere Region.

Manche Tools benötigen über **Location** und **Secret** hinaus weitere API-bezogene Felder. Möglicherweise müssen Sie auch auf der Seite des Tools Änderungen vornehmen, um einen eingehenden Connector von DefectDojo zu ermöglichen.

![image](images/connectors_tool_reference.png)

Jedes Tool hat eine andere API-Konfiguration, und dieser Leitfaden soll Ihnen helfen, die API des Tools so einzurichten, dass DefectDojo eine Verbindung herstellen kann.

Wann immer möglich, empfehlen wir, in Ihrem Sicherheitstool ein neues Konto „DefectDojo Bot" anzulegen, das ausschließlich vom Connector verwendet wird. So können Sie besser zwischen manuell von Ihrem Team ausgeführten Aktionen und automatisierten Aktionen des Connectors unterscheiden.

# **Asset-Connectors**

Die meisten Connectors importieren **Befunde** aus einem Sicherheitstool. **Asset-Connectors** funktionieren anders: Sie importieren stattdessen Ihr **Asset-Inventar**. Ein Asset-Connector zählt die Assets auf, die in einer externen Plattform vorhanden sind (zum Beispiel die Repositories in einer GitLab-Gruppe), und erstellt und pflegt automatisch die entsprechenden **Produkte** (Assets) und **Produkttypen** (Organisationen) in DefectDojo. Ein Asset-Connector importiert keine Befunde.

* **Discover** und **Sync** gleichen beide die Asset-Liste ab. Neue Assets erscheinen als `NEW`-Einträge; sobald sie zugeordnet sind (automatisch, wenn Auto-Mapping aktiviert ist), erstellt DefectDojo das Produkt und ordnet es einem vom Tool abgeleiteten Produkttyp zu — zum Beispiel dem GitLab-Namespace oder dem Azure-DevOps-Projekt.
* Wird ein Asset später upstream entfernt (zum Beispiel ein gelöschtes Repository), wird sein zugeordneter Eintrag beim nächsten Sync als `MISSING` markiert, damit Ihr Team ihn prüfen kann. DefectDojo löscht niemals stillschweigend ein Produkt.

Azure DevOps, Backstage, Bitbucket, GitHub, GitLab, Jira Service Management Assets und ServiceNow CMDB sind Asset-Connectors. runZero ist in erster Linie ein Asset-Connector, kann aber optional auch Schwachstellen als Befunde importieren. Alle anderen unten aufgeführten Connectors importieren Befunde.

# **Unterstützte Connectors**

## **Acunetix 360**

Der Acunetix-360-Connector importiert **DAST-Schwachstellenbefunde** von der Acunetix-360-Cloud-Plattform (der Invicti-Plattform). DefectDojo ermittelt die gescannten Websites Ihres Kontos und erstellt für jede **Website** einen Eintrag; die Befunde einer Website stammen aus deren letztem abgeschlossenen Scan.

**Bitte beachten Sie:** Dieser Connector ist für **Acunetix 360** (das Cloud-Produkt unter `online.acunetix360.com`). Er ist nicht für den On-Premises-Scanner Acunetix Standard/Premium gedacht, der über eine andere API verfügt.

#### Voraussetzungen

Ein Acunetix-360-Konto und eine **API-Anmeldeinformation**: Öffnen Sie in Acunetix 360 Ihr Kontomenü \> **API Settings**, und notieren Sie sich die **API User ID** und generieren Sie ein **API Token**. Der Connector authentifiziert sich damit als HTTP-Basic-Anmeldedaten, daher wird ein dediziertes Service-Konto empfohlen, um automatisierte Aktivitäten von manuellen Team-Aktionen zu unterscheiden.

#### Connector-Zuordnungen

1. Geben Sie Ihre Acunetix-360-URL in das Feld **Location** ein: `https://online.acunetix360.com`.
2. Geben Sie die API User ID in das Feld **API User ID** ein.
3. Geben Sie das API Token in das Feld **API Token** ein.
4. Legen Sie optional einen **Minimum Severity**-Wert fest, um einzuschränken, welche Befunde importiert werden.

Jede gescannte Website wird zu einem Eintrag. Die Befunde stammen aus dem letzten abgeschlossenen Scan der Website; Schwachstellen, die Acunetix 360 als **Accepted Risk** oder **False Positive** markiert hat, werden weiterhin importiert, aber als inaktiv gekennzeichnet (risikoakzeptiert oder falsch-positiv), damit das DefectDojo-Produkt die Triage des Herstellers widerspiegelt.

## **Akamai API Security**

Der Akamai-API-Security-Connector verwendet einen API-Schlüssel, um Sicherheitsbefunde von der Akamai-API abzurufen. DefectDojo ermittelt Ihre Akamai-Umgebung und erstellt separate Einträge für jede in Ihrem Konto konfigurierte **Application** und jeden **Host**.

#### Voraussetzungen

Sie benötigen einen API-Schlüssel mit Zugriff auf die Akamai-API. Wir empfehlen, für DefectDojo ein dediziertes Service-Konto anzulegen, um automatisierte Aktivitäten klar von manuellen Team-Aktionen zu unterscheiden.

#### Connector-Zuordnungen

1. Geben Sie die Basis-URL Ihrer Akamai-API in das Feld **Location** ein. Diese URL ist spezifisch für Ihre Akamai-Instanz, zum Beispiel
2. Geben Sie einen gültigen **API Key** in das Feld **Secret** ein.

DefectDojo ordnet **Applications** und **Hosts** als separate Einträge zu. Jede Application erscheint als `{name} (application)` und jeder Host als `{name} (host)` in Ihrer Eintragsliste.

## **Anchore**

Der Anchore-Connector verwendet das API-Token eines Benutzers, um Daten von Anchore Enterprise abzurufen. Produkte werden anhand von „Applications" zugeordnet und ermittelt, die sich in Anchore aus mehreren Images zusammensetzen - siehe [Anchore Enterprise Documentation](https://docs.anchore.com/current/docs/sbom_management/application_groups/application_management_anchorectl/) für weitere Informationen.

#### Connector-Zuordnungen

1. Die Anchore-URL in das Feld **Location**: Dies ist die URL, unter der Sie auf Anchore zugreifen.
2. Geben Sie einen gültigen API-Schlüssel in das Feld Secret ein. Dies ist der API-Schlüssel, der mit Ihrem Burp-Service-Konto verknüpft ist.

Weitere Informationen zum Erstellen eines Tokens für Anchore finden Sie in der offiziellen [Anchore-Dokumentation](https://docs.anchore.com/current/docs/).

## **AWS Security Hub**

Der AWS-Security-Hub-Connector verwendet einen AWS-Zugriffsschlüssel, um mit den Security-Hub-APIs zu interagieren.

#### Voraussetzungen

Anstatt den AWS-Zugriffsschlüssel eines Teammitglieds zu verwenden, empfehlen wir, in Ihrem AWS-Konto speziell für DefectDojo einen IAM-Benutzer anzulegen, dessen Berechtigungen auf das für die Interaktion mit Security Hub Notwendige beschränkt sind.

Die AWS-Richtlinie „**[AWSSecurityHubReadOnlyAccess](https://docs.aws.amazon.com/aws-managed-policy/latest/reference/AWSSecurityHubReadOnlyAccess.html)**" bietet die für einen Connector erforderliche Zugriffsebene. Wenn Sie eine benutzerdefinierte Richtlinie für einen Connector schreiben möchten, müssen Sie die folgenden Berechtigungen einbeziehen:

* [DescribeHub](https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_DescribeHub.html)
* [GetFindingAggregator](https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_GetFindingAggregator.html)
* [GetFindings](https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_GetFindings.html)
* [ListFindingAggregators](https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_ListFindingAggregators.html)

Eine funktionierende Richtliniendefinition könnte wie folgt aussehen:

```
{  
    "Version": "2012-10-17",  
    "Statement": [  
        {  
            "Sid": "AWSSecurityHubConnectorPerms",  
            "Effect": "Allow",  
            "Action": [  
                "securityhub:DescribeHub",  
                "securityhub:GetFindingAggregator",  
                "securityhub:GetFindings",  
                "securityhub:ListFindingAggregators"  
            ],  
            "Resource": "*"  
        }  
    ]  
}
```

**Bitte beachten Sie:** Wir benötigen möglicherweise in Zukunft zusätzliche API-Aktionen, um die bestmögliche Erfahrung zu bieten, was Aktualisierungen dieser Richtlinie erfordern wird.

Sobald Sie Ihren IAM-Benutzer erstellt und ihm mit einer geeigneten Richtlinie/Rolle die notwendigen Berechtigungen zugewiesen haben, müssen Sie einen Zugriffsschlüssel generieren, den Sie dann zum Erstellen eines Connectors verwenden können.

#### Connector-Zuordnungen

1. Geben Sie den passenden [AWS-API-Endpunkt für Ihre Region](https://docs.aws.amazon.com/general/latest/gr/sechub.html#sechub_region) in das Feld **Location** ein**:** Um beispielsweise Ergebnisse aus der Region `us-east-1` abzurufen, würden Sie Folgendes angeben

`https://securityhub.us-east-1.amazonaws.com`
2. Geben Sie einen gültigen **AWS Access Key** in das Feld **Access Key** ein.
3. Geben Sie den passenden **Secret Key** in das Feld **Secret Key** ein.

DefectDojo kann mithilfe der Funktion **regionsübergreifende Aggregation** von Security Hub Befunde aus mehr als einer Region abrufen. Wenn die [regionsübergreifende Aggregation](https://docs.aws.amazon.com/securityhub/latest/userguide/finding-aggregation.html) aktiviert ist, sollten Sie den API-Endpunkt Ihrer „**Aggregation Region**" angeben. Für zusätzlich verknüpfte Regionen werden in DefectDojo anhand Ihrer AWS-Konto-ID und des Regionsnamens ProductRecords erstellt.

## **Azure DevOps**

Der Azure-DevOps-Connector ist ein **Asset-Connector**: Er zählt die Git-Repositories in jedem Projekt Ihrer Azure-DevOps-Organisation auf und erstellt für jedes Repository ein DefectDojo-Asset, gruppiert in Organisationen nach Azure-DevOps-Projekt. Es werden keine Befunde importiert.

#### Voraussetzungen

Sie benötigen ein Personal Access Token (PAT) für die Organisation. Wir empfehlen, das Token von einem dedizierten Service-Konto aus zu erstellen. Es werden nur Lese-Scopes benötigt:

1. Öffnen Sie in Azure DevOps **User settings \> Personal access tokens \> New Token**.
2. Klicken Sie auf **Show all scopes** und wählen Sie dann **Code: Read** und **Project and Team: Read**.

Nur Azure DevOps Services (dev.azure.com) wird unterstützt; der On-Premise Azure DevOps Server wird derzeit nicht unterstützt.

#### Connector-Zuordnungen

1. Geben Sie Ihre Organisations-URL in das Feld **Location** ein: `https://dev.azure.com/{your-organization}`. Auch die alten `https://{your-organization}.visualstudio.com`-URLs werden akzeptiert, und zusätzliche Pfadsegmente (zum Beispiel ein Link zu einem bestimmten Projekt) werden ignoriert.
2. Geben Sie das PAT in das Feld **Secret** ein.

Jedes Repository wird zu einem nach dem Repository benannten Eintrag, gruppiert nach seinem Azure-DevOps-**Projekt**. Deaktivierte Repositories werden übersprungen; das Deaktivieren oder Löschen eines Repositorys markiert seinen Eintrag beim nächsten Sync daher als `MISSING`.

## **Backstage**

Der Backstage-Connector ist ein **Asset-Connector**: Anstatt Befunde zu importieren, überträgt er Ihren [Backstage](https://backstage.io)-Software-Katalog in DefectDojo und hält Ihre Produkthierarchie und Team-Zuständigkeit damit synchron. Er ist für Organisationen konzipiert, die ihr Service-Inventar und ihre Organisationsstruktur in Backstage pflegen und möchten, dass DefectDojo diese Struktur widerspiegelt, statt sie manuell zu pflegen.

#### Was zugeordnet wird

| Backstage | DefectDojo |
|---|---|
| **System** | Produkttyp (Components ohne System werden unter einem konfigurierbaren Produkttyp „Backstage / Uncategorized" gruppiert) |
| **Component** | Produkt — benannt nach dem `title` der Entität (Rückgriff auf `name`), mit der Katalogbeschreibung |
| **Owning Group** (`ownedBy`-Beziehung) | Eine mit dem Produkt verknüpfte DefectDojo-Gruppe (Standardrolle: Maintainer, konfigurierbar) |
| **Owner email** (E-Mail des Gruppenprofils oder E-Mail eines User-Owners) | Ein Produktmitglied, sofern bereits ein DefectDojo-Benutzer mit dieser E-Mail-Adresse existiert (es werden nie Benutzer angelegt) |
| `metadata.tags`, `spec.type`, `spec.lifecycle`, Namespace, Domain | Produkt-Tags mit dem Präfix `backstage:` |
| `metadata.annotations` | Wird am Eintrag gespeichert (begrenzt); ausgewählte Annotationen können über **Annotation Mappings** zu vollwertigen Attributen oder Tags hochgestuft werden |

Einträge werden über die vom Server vergebene `metadata.uid` der Entität identifiziert, sodass Umbenennungen in Backstage das zugeordnete Produkt beim nächsten Sync **an Ort und Stelle** aktualisieren — keine Duplikate. Der Produktname folgt stets dem Katalog: Um ein von diesem Connector verwaltetes Produkt umzubenennen, benennen Sie die Component in Backstage um (eine Umbenennung auf DefectDojo-Seite oder ein bei der manuellen Zuordnung vergebener eigener Name wird beim nächsten Sync auf den Katalognamen zurückgesetzt, sofern dies nicht mit einem anderen Produkt kollidieren würde). Eigentümerwechsel verschieben die Gruppenzuordnung des Produkts. Components, die aus dem Katalog verschwinden (oder mit der Annotation `backstage.io/orphan` gekennzeichnet sind), werden als **MISSING** markiert — DefectDojo löscht nie von sich aus ein Produkt. Domain- und Group-Hierarchie (übergeordnete Teams) werden nur als Tags/Metadaten erfasst; sie erzeugen keine zusätzlichen Hierarchieebenen.

#### Voraussetzungen

Der Connector authentifiziert sich mit einem **statischen externen Zugriffstoken** gegenüber dem Backstage-Backend. Definieren Sie in Ihrer Backstage-App-Konfiguration ein Token und beschränken Sie es (empfohlen) auf das Catalog-Plugin:

```yaml
backend:
  auth:
    externalAccess:
      - type: static
        options:
          token: ${DEFECTDOJO_BACKSTAGE_TOKEN}
          subject: defectdojo-connector
        accessRestrictions:
          - plugin: catalog
```

Generieren Sie ein starkes Zufallstoken (zum Beispiel mit `openssl rand -hex 32`) und speichern Sie es in der Umgebung Ihrer Backstage-Bereitstellung. Einzelheiten finden Sie in der [Backstage-Dokumentation zur Service-to-Service-Authentifizierung](https://backstage.io/docs/auth/service-to-service-auth).

#### Connector-Zuordnungen

1. Geben Sie Ihre **Backstage-Backend-Root-URL** in das Feld **Location** ein: zum Beispiel `https://backstage.example.com` (der Connector hängt `/api/catalog` an). Dies muss die **Backend**-URL sein, nicht die Frontend-Web-UI.
2. Geben Sie das statische externe Zugriffstoken in das Feld **Secret** ein.

Optionale Felder (für die Standardwerte leer lassen):

* **Namespaces** — kommagetrennte Katalog-Namespaces, die importiert werden sollen; bei leerem Feld werden alle Namespaces importiert.
* **Component Types** — kommagetrennte `spec.type`-Werte (z. B. `service,website`); bei leerem Feld werden alle Typen importiert.
* **Page Size** — Seitengröße der Katalogabfrage (1\-500, Standard 250).
* **TLS Verification** — nur auf `false` setzen, wenn Backstage ein Zertifikat verwendet, das DefectDojo nicht verifizieren kann (interne CA); nicht empfohlen.
* **Uncategorized Product Type** — der Produkttyp für Components ohne System (Standard `Backstage / Uncategorized`).
* **Owner Group Role** — die Rolle, die dem verantwortlichen Team bei zugeordneten Produkten gewährt wird (Standard `Maintainer`).
* **Annotation Mappings** — ein JSON-Objekt, das Annotationsschlüssel auf Namen von Eintragsattributen abbildet, oder auf `"tag"`, um eine Annotation als Produkt-Tag zu importieren, z. B. `{"github.com/project-slug": "GITHUB_PROJECT", "example.com/tier": "tag"}`.

Bei aktiviertem **Auto\-Map** baut ein einziger Discover \+ Sync die vollständige Struktur aus Produkttyp/Produkt/Eigentümerschaft ohne manuelle Schritte auf. Bei deaktiviertem Auto\-Map erscheinen ermittelte Components als Einträge, die auf Ihre Zuordnungsentscheidung warten.

#### Einschränkungen (v1)

* Die **Group-Mitgliedschaft von Backstage wird nicht synchronisiert**: Der Connector erstellt/verknüpft das verantwortliche Team als DefectDojo-Gruppe, aber das Befüllen dieser Gruppe mit Benutzern bleibt Ihrem Identity-Provider oder Ihren Administratoren überlassen.
* Nur Components werden zu Produkten; APIs, Resources und Domains werden nicht als Assets importiert (Domains erscheinen als Tags).
* Tags und Annotationen werden normalisiert und begrenzt, um in die DefectDojo-Feldgrenzen zu passen (überlange Werte werden gekürzt).

**Ein Hinweis zur umgekehrten Richtung:** Die Anzeige von DefectDojo-Befunden und -Bewertungen *innerhalb* von Backstage (auf Entitätsseiten) wäre ein naheliegender nächster Schritt, der als Backstage-Frontend-Plugin umgesetzt würde, das die DefectDojo-REST-API konsumiert — dies liegt bewusst außerhalb des Umfangs dieses Connectors, der ausschließlich Katalogdaten in DefectDojo überträgt.

## **Black Duck**

Der Black-Duck-Connector importiert **Software-Composition-Analysis(SCA)**-Befunde von einer Black-Duck(Synopsys/Black-Duck)-Hub-Instanz. DefectDojo ermittelt jedes Projekt in der Instanz und erstellt für jedes **Projekt** einen Eintrag; die Befunde eines Projekts stammen aus den anfälligen BOM-Komponenten der ausgewählten Version.

#### Voraussetzungen

Ein Black-Duck-**API-Token** für einen Benutzer, der die zu importierenden Projekte sehen kann. Öffnen Sie in Black Duck Ihr Benutzermenü \> **My Access Tokens** \> **Create New Token**, gewähren Sie (mindestens) Lesezugriff, und kopieren Sie das Token, wenn es angezeigt wird — es wird nur einmal angezeigt. Der Connector tauscht dieses Token bei jedem Sync gegen ein kurzlebiges Bearer-Token ein; es wird über das Secret-Feld des Connectors hinaus nie im Klartext gespeichert.

#### Connector-Zuordnungen

1. Geben Sie Ihre Black-Duck-Hub-URL in das Feld **Location** ein — zum Beispiel `https://your-company.app.blackduck.com`.
2. Geben Sie das API-Token in das Feld **Secret** ein.
3. Legen Sie optional einen **Minimum Severity**-Wert fest, um einzuschränken, welche Befunde importiert werden.

Jedes Black-Duck-Projekt wird zu einem Eintrag. Standardmäßig importiert der Connector die **released**-Version des Projekts (mit Rückgriff auf dessen erste Version); jede anfällige BOM-Komponente dieser Version wird zu einem Befund mit dem Titel `{vulnerability} in {component}:{version}`.

Dieser Connector unterscheidet sich von den dateibasierten Black-Duck-Parsern — seine Befunde verwenden den dedizierten Scan-Typ **Black Duck - Connectors Import**.

## **Bitbucket**

Der Bitbucket-Connector ist ein **Asset-Connector**: Er zählt die Repositories in den von Ihnen benannten Bitbucket-Cloud-Workspaces auf und erstellt für jedes Repository ein DefectDojo-Asset, gruppiert in Organisationen nach Bitbucket-Projekt. Es werden keine Befunde importiert.

#### Voraussetzungen

Bitbucket Cloud erfordert ein **scoped** Atlassian-API-Token — klassische (nicht-scoped) Atlassian-API-Tokens werden von Bitbucket mit dem Fehler „API Token provided has no Bitbucket scopes" abgelehnt.

1. Gehen Sie zu [id.atlassian.com/manage-profile/security/api-tokens](https://id.atlassian.com/manage-profile/security/api-tokens) und wählen Sie **Create API token with scopes**.
2. Wählen Sie die **Bitbucket**-App und gewähren Sie dann die Lese-Scopes: `read:account:bitbucket`, `read:workspace:bitbucket`, `read:repository:bitbucket` und `read:project:bitbucket`.

Nur Bitbucket Cloud (bitbucket.org) wird unterstützt. Bitbucket Server hat 2024 das Ende seiner Lebensdauer erreicht, und Bitbucket Data Center wird nicht unterstützt.

#### Connector-Zuordnungen

1. Geben Sie `https://bitbucket.org` in das Feld **Location** ein.
2. Geben Sie die Atlassian-Konto-E-Mail-Adresse, zu der das Token gehört, in das Feld **Email** ein.
3. Geben Sie das scoped API-Token in das Feld **Secret** ein.
4. Geben Sie einen oder mehrere Workspace-Slugs (kommagetrennt) in das Feld **Workspace Slugs** ein. Dieses Feld ist erforderlich: Die scoped API-Tokens von Bitbucket können Workspaces nicht automatisch auflisten, daher muss DefectDojo mitgeteilt werden, welche Workspaces gelesen werden sollen.

Jedes Repository wird zu einem nach dem Repository benannten Eintrag, gruppiert nach seinem Bitbucket-**Projekt**.

## **Bugcrowd**

Der Bugcrowd-Connector verwendet die Bugcrowd-REST-API, um Einreichungen aus Ihren Bug-Bounty- und Vulnerability-Disclosure-Programmen zu importieren. DefectDojo ermittelt die Programme, auf die Ihr API-Token zugreifen kann, und erstellt für jedes einen Eintrag, wobei die Einreichungen des Programms als Befunde importiert werden.

#### Voraussetzungen

Sie benötigen ein Bugcrowd-**API-Token** mit Zugriff auf die zu importierenden Programme. Wir empfehlen, für DefectDojo ein dediziertes Service-Konto anzulegen, damit automatisierte Aktivitäten leicht von manuellen Team-Aktionen zu unterscheiden sind. Generieren Sie das Token in Bugcrowd unter **Organization settings \> API credentials**; Lesezugriff auf Submissions, Programme und Targets ist ausreichend.

#### Connector-Zuordnungen

1. Geben Sie `https://api.bugcrowd.com` in das Feld **Location** ein.
2. Geben Sie Ihr Bugcrowd-API-Token in das Feld **Secret** ein. Es wird als `Authorization: Token`-Header gesendet.
3. Legen Sie optional einen **Minimum Severity**-Wert fest, um einzuschränken, welche Befunde importiert werden.

Jedes Bugcrowd-**Programm** wird zu einem Eintrag, und seine Einreichungen werden mit dem beibehaltenen Bugcrowd-Schweregrad als Befunde importiert. Doppelte Einreichungen werden ausgeschlossen, sodass ein erneuter Import keine wiederholten Befunde für dasselbe Problem erzeugt.

## **Bright Security**

Der Bright-Security-Connector verwendet die [Bright](https://brightsec.com)-API (ehemals NeuraLegion), um **DAST-Befunde** zu importieren. DefectDojo ermittelt jeden Scan, auf den das Token zugreifen kann, und erstellt für jeden abgeschlossenen Scan einen Eintrag; anschließend werden die Issues dieses Scans als Befunde importiert.

#### Voraussetzungen

Sie benötigen einen Bright-**API-Schlüssel**, der in der Bright-App unter **User settings → API keys** erstellt wird (ein `Org`- oder persönlicher Schlüssel). Der Schlüssel wird im Header `Authorization: Api-Key` gesendet und nie protokolliert.

#### Connector-Zuordnungen

1. Behalten Sie den vorgegebenen Wert im Feld **Location**, `https://app.brightsec.com`, oder geben Sie Ihren Bright-Host explizit an.
2. Geben Sie den Bright-API-Schlüssel in das Feld **Secret** ein.
3. Legen Sie optional einen **Minimum Severity**-Wert fest, um einzuschränken, welche Befunde importiert werden.

DefectDojo ordnet jeden abgeschlossenen **Scan** einem Eintrag zu und jedes **Issue** einem Befund: Der Schweregrad stammt aus Brights eigener Bewertung (Critical/High/Medium/Low), der CVSS-Score, die CWE und die Abhilfemaßnahme werden übernommen, der betroffene Entry Point wird zum Endpunkt, und der Request/Response-Nachweis wird in die Beschreibung aufgenommen. Befunde werden als dynamische Befunde erfasst und anhand der Bright-Issue-ID dedupliziert.

Weitere Informationen finden Sie in der [Bright-API-Dokumentation](https://docs.brightsec.com/).

## **BurpSuite**

Der Burp-Connector von DefectDojo ruft die GraphQL-API von Burp auf, um Daten abzurufen.

#### Voraussetzungen

Bevor Sie diesen Connector einrichten können, benötigen Sie einen API-Schlüssel eines Burp-Service-Kontos. Burp-Benutzerkonten verfügen standardmäßig nicht über API-Schlüssel, daher müssen Sie möglicherweise eigens dafür einen neuen Benutzer anlegen.

Eine Anleitung zum Einrichten eines Service-Account-Benutzers mit einem API-Schlüssel finden Sie in der [Burp-Dokumentation](https://portswigger.net/burp/documentation/enterprise/user-guide/api-documentation/create-api-user).

#### Connector-Zuordnungen

1. Geben Sie die Root-URL von Burp in das Feld **Location** ein: Dies ist die URL, unter der Sie auf das Burp-Tool zugreifen.
2. Geben Sie einen gültigen API-Schlüssel in das Feld Secret ein. Dies ist der API-Schlüssel, der mit Ihrem Burp-Service-Konto verknüpft ist.

Weitere Informationen zur Burp-API finden Sie in der offiziellen [Burp-Dokumentation](https://portswigger.net/burp/extensibility/enterprise/graphql-api/index.html).

## **Censys**

Der Censys-Connector liest Host-Assets aus der Censys Platform und importiert die exponierten Dienste jedes Hosts als Befunde. Er verwendet die globale Such-API der Censys Platform, um die Hosts zu ermitteln, auf die Sie ihn beschränken.

#### Voraussetzungen

Sie benötigen ein Censys-**Platform**-Konto mit API-Zugriff:

* Ein **Personal Access Token**, erstellt in der Censys Platform Console unter Personal Access Tokens.
* Ihre **Organization ID**, die auf derselben Einstellungsseite unter „Current Organization" angezeigt wird. Der API-Zugriff auf den Such-Endpunkt erfordert eine Organisation, daher ist mindestens ein Starter-Tier erforderlich. Free-Tier-Tokens haben keine Organization ID und können die Such-API nicht nutzen.

Pro-Host-CVE- und Risikodaten sind nur in den Censys-Core(Enterprise)-Tiers verfügbar, sodass Befunde in niedrigeren Tiers exponierte Dienste statt Schwachstellen darstellen.

Weitere Informationen finden Sie in der [Censys-Platform-API-Dokumentation](https://docs.censys.com/reference/get-started).

#### Connector-Zuordnungen

1. Geben Sie `https://api.platform.censys.io` in das Feld **Location** ein.
2. Geben Sie Ihr Personal Access Token in das Feld **API Key** ein.
3. Geben Sie Ihre **Organization ID** ein.
4. Geben Sie eine **Search Query** ein, die den Import auf Ihre eigenen Assets beschränkt, zum Beispiel `host.autonomous_system.asn: <your ASN>` oder `host.ip: 203.0.113.0/24`.
5. Legen Sie optional einen **Minimum Severity**-Wert fest, um einzuschränken, welche Befunde importiert werden.

DefectDojo erstellt für jeden Host einen Eintrag und importiert dessen exponierte Dienste als Befunde.

## **Checkmarx ONE**

Der Checkmarx-ONE-Connector von DefectDojo ruft die Checkmarx-API auf, um Daten abzurufen.

#### **Connector-Zuordnungen**

1. Geben Sie Ihren **Tenant Name** in das Feld **Checkmarx Tenant** ein. Dieser Name sollte auf der Checkmarx-ONE-Anmeldeseite oben rechts sichtbar sein:   
" Tenant: \<**Ihr Tenant-Name**\> "  
​
![image](images/connectors_tool_reference_2.png)

2. Geben Sie einen gültigen API-Schlüssel ein. Möglicherweise müssen Sie einen neuen generieren: siehe [Checkmarx-API-Dokumentation](https://docs.checkmarx.com/en/34965-68618-generating-an-api-key.html#UUID-f3b6481c-47f4-6cd8-9f0d-990896e36cd6_UUID-39ccc262-c7cb-5884-52ed-e1692a635e08) für Einzelheiten.
3. Geben Sie Ihren Tenant-Standort in das Feld **Location** ein. Diese URL ist wie folgt aufgebaut:  
​`https://<your-region>.ast.checkmarx.net/` . Ihre Region finden Sie am Anfang Ihrer Checkmarx-URL, wenn Sie die Checkmarx-App verwenden. **<https://ast.checkmarx.net>** ist der primäre US-Server (ohne Regionspräfix).

#### **Branch-Handhabung**

Standardmäßig importiert jeder Sync die Befunde des **einzigen zuletzt abgeschlossenen Scans** eines Projekts, unabhängig vom Branch. Wenn Ihre CI viele Branches scannt, „gewinnt" bei diesem Sync der Branch, der zuletzt gescannt wurde: Befunde, die nur auf anderen Branches existieren, werden nicht importiert, und der Close-Old-Abgleich des Syncs kann Befunde hin- und herwechselnd öffnen und schließen, je nachdem, welcher Branch gerade der aktuellste Scan ist.

Zwei optionale Felder steuern dieses Verhalten:

- **Branch**: fixiert jedes Projekt auf einen Branch-Namen — es werden nur Scans dieses Branches importiert. Dies ist ein einziger globaler Wert für den gesamten Connector und eignet sich daher für Umgebungen, in denen jedes Projekt denselben langlebigen Branch verwendet (z. B. `main`).
    - Ein **Platzhalter `*`** wird unterstützt. Ein Branch-Wert, der `*` enthält, wählt über *jeden* passenden Branch statt nur einen aus — zum Beispiel importiert `release/*` jeden Release-Branch, und `*` erfasst jeden Branch. In Kombination mit **Track Scanned Branches** lässt sich damit eine Gruppe von Branches verfolgen, ohne alle einzeln zu verfolgen.
    - Wenn ein Platzhalter innerhalb des Scan-Fensters **keinen** Branch trifft, wird dieser Sync **übersprungen**, statt als „der Branch hat keine Befunde" behandelt zu werden — sodass ein Muster, das vorübergehend auf nichts passt, nicht alle Befunde des Assets schließen kann.
- **Track Scanned Branches**: Wenn aktiviert, findet jeder Sync jeden Branch mit einem abgeschlossenen Scan in der jüngsten Scan-Historie des Projekts und importiert **den letzten abgeschlossenen Scan jedes Branches**, einen erneuten Import pro Branch. Die Befunde jedes Branches liegen in einem eigenen Engagement auf dem zugeordneten Asset mit dem Namen „\<Standard-Engagement\> \- \<Branch\>", sodass das Schließen veralteter Befunde pro Branch erfolgt: Ein in einen Branch gemergter Fix kann niemals die Befunde eines anderen Branches schließen. Der primäre Branch des Projekts (laut Checkmarx) wird zuerst importiert, sodass erneute Auftritte desselben Befunds auf anderen Branches mit dem Original des primären Branches dedupliziert werden.

Hinweise zu **Track Scanned Branches**:

- **Prüfen Sie, welcher Standard für Sie gilt.** Branch-Tracking ist bei **Neuinstallationen standardmäßig aktiviert**. Installationen von vor dieser Änderung behalten ihr bisheriges Verhalten bei, sodass der Schalter dort deaktiviert bleibt, bis ihn jemand einschaltet.
- Wenn beide Felder gesetzt sind, wird nur der fixierte **Branch** verfolgt — auch wenn dieser Branch-Wert ein Platzhaltermuster ist; in diesem Fall wird jeder passende Branch verfolgt.
- Ein Branch, der nicht mehr gescannt wird (gemergt oder gelöscht), erhält keine Updates mehr: Sein Engagement bleibt mit den zuletzt bekannten Befunden sichtbar, die Sie prüfen und gesammelt schließen können.
- Den Schalter später wieder auszuschalten ist unbedenklich: Die Branch-spezifischen Engagements erhalten dann einfach keine Importe mehr, und beim nächsten Sync wird wieder das Standard-Engagement verwendet.
- Connectors gleichen den Zustand nach dem Sync-Zeitplan ab. Branch-Tracking macht jeden Sync über alle Branches hinweg vollständig; es macht die Daten zwischen den Syncs jedoch nicht in Echtzeit verfügbar.

## **Cloudflare**

Der Cloudflare-Connector importiert **Security-Center-Insights** — Probleme mit der Sicherheitslage, die Cloudflare zu Ihrem Konto und Ihren Zonen aufzeigt, etwa einen fehlenden DMARC-Eintrag, nicht aktiviertes DNSSEC oder ein Zertifikatsproblem. DefectDojo erstellt für jede Zone (Domain) mit offenen Insights einen Eintrag, plus einen Eintrag auf Kontoebene für Insights, die keiner bestimmten Zone zugeordnet sind.

#### Voraussetzungen

Sie benötigen ein Cloudflare-**API-Token** (nicht den veralteten Global API Key). Erstellen Sie eines im Cloudflare-Dashboard unter **My Profile > API Tokens > Create Token**. Die schnellste Option ist die Vorlage **„Read all resources"**; für ein Token mit minimalen Rechten gewähren Sie **Zone > Zone > Read** (alle Zonen) sowie kontoweiten Lesezugriff für Security Center.

#### Connector-Zuordnungen

1. Geben Sie `https://api.cloudflare.com/client/v4` in das Feld **Location** ein.
2. Geben Sie das API-Token in das Feld **Secret** ein.
3. Legen Sie optional einen **Minimum Severity**-Wert fest, um einzuschränken, welche Befunde importiert werden.

DefectDojo ermittelt automatisch die Konten und Zonen, auf die das Token zugreifen kann — es ist keine Konto-ID erforderlich. Es werden nur offene (aktive, nicht verworfene) Insights importiert, sodass Insights, die Sie in Cloudflare beheben oder verwerfen, beim nächsten Sync automatisch in DefectDojo als behoben markiert werden.

## **Cobalt.io**

Der Cobalt.io-Connector verwendet die Cobalt.io-API (v2), um Pentest-Befunde aus Ihrer Cobalt.io-Organisation abzurufen. DefectDojo ermittelt jede Organisation, auf die Ihr API-Token zugreifen kann, und erstellt für jedes **Asset** (die Einheit, die Cobalt pentestet) einen separaten Eintrag.

#### Voraussetzungen

Sie benötigen ein persönliches Cobalt.io-**API-Token**. Wir empfehlen, für DefectDojo ein dediziertes Service-Konto anzulegen, um automatisierte Aktivitäten klar von manuellen Team-Aktionen zu unterscheiden. Generieren Sie ein Token unter **Settings \> API Tokens** in der Cobalt.io-Oberfläche. Organisations-Tokens werden automatisch ermittelt \- Sie müssen sie nicht angeben.

#### Connector-Zuordnungen

1. Geben Sie die Basis-URL der Cobalt.io-API in das Feld **Location** ein: `https://api.cobalt.io` (oder Ihren regionalen Host, zum Beispiel `https://api.us.cobalt.io`).
2. Geben Sie Ihr **persönliches API-Token** in das Feld **Secret** ein.
3. Geben Sie optional ein **Organization Token** ein, um den Sync auf eine einzelne Organisation zu beschränken. Bleibt das Feld leer, synchronisiert DefectDojo jede Organisation, auf die das persönliche API-Token zugreifen kann.

DefectDojo ordnet jedes Cobalt.io-**Asset** als separaten Eintrag zu. Für jedes zugeordnete Asset werden Befunde importiert, wobei deren Cobalt.io-Status (zum Beispiel `valid_fix`, `wont_fix`, `invalid`) den Befundstatus in DefectDojo bestimmt.

## **Contrast**

Der Contrast-Connector verwendet die Contrast-Assess-REST-API, um Anwendungsschwachstellen zu importieren. DefectDojo ermittelt die Anwendungen in Ihrer Contrast-Organisation und erstellt für jede einen Eintrag.

#### Voraussetzungen

Sie benötigen vier Werte von Contrast. Wir empfehlen, ein dediziertes Service-Konto anzulegen, damit automatisierte Aktivitäten leicht von den manuellen Aktionen Ihres Teams zu unterscheiden sind. In der Contrast-Oberfläche finden Sie unter **User Settings > Profile > Your Keys**:

* Ihren organisationsweiten **API Key**.
* Ihren persönlichen **Service Key**.
* Den **Benutzernamen**, zu dem die Anmeldedaten gehören (die Login-E-Mail-Adresse des Kontos).
* Ihre **Organization ID** — die UUID der Organisation, aus der importiert werden soll, ebenfalls unter **Organization Settings** angezeigt.

#### Connector-Zuordnungen

1. Geben Sie die URL, über die Sie auf Contrast zugreifen, in das Feld **Location** ein — beim gehosteten Produkt ist dies typischerweise `https://app.contrastsecurity.com` (oder Ihre regionale/selbstgehostete Team-Server-URL).
2. Geben Sie die Login-E-Mail-Adresse des Kontos in das Feld **Username** ein.
3. Geben Sie den organisationsweiten **API Key** in das Feld **API Key** ein.
4. Geben Sie den persönlichen **Service Key** in das Feld **Service Key** ein.
5. Geben Sie die **Organization ID** (UUID) in das Feld **Organization ID** ein.
6. Legen Sie optional einen **Minimum Severity**-Wert fest, um einzuschränken, welche Befunde importiert werden.

Jede Contrast-Anwendung wird zu einem Eintrag, und ihre Schwachstellen werden als Befunde importiert.

## **Coverity**

Der Coverity-Connector importiert Befunde von einem **Coverity-Connect**-Server. DefectDojo erstellt für jedes Coverity-**Projekt** einen Eintrag.

#### Connector-Zuordnungen

1. Geben Sie die URL Ihres Coverity-Connect-Servers in das Feld **Location** ein.
2. Geben Sie den Coverity-Connect-**Benutzernamen** in das Feld **Username** ein.
3. Geben Sie das Passwort oder den Authentifizierungsschlüssel des Benutzers in das Feld **Secret** ein.
4. Legen Sie optional einen **View Name** fest, um auszuwählen, welche gespeicherte Issue-Ansicht der Connector liest. Leer lassen, um den Standard **Outstanding Issues** zu verwenden.
5. Setzen Sie optional **Import All Issue Kinds** auf `true`, um den Import über den Standardfilter für Security- und Quality-Issues (`RESOURCE_LEAK`) hinaus zu erweitern.

## **CrowdStrike Falcon**

Der CrowdStrike-Falcon-Connector importiert **Spotlight-Schwachstellen** und **EDR-Detections** von der Falcon-Plattform als zwei separate Befundtypen (`CrowdStrike:Spotlight` und `CrowdStrike:Detections`). DefectDojo erstellt für jeden Falcon-**Host** einen Eintrag.

#### Voraussetzungen

Ein Falcon-**API-Client** (Client ID und Secret), erstellt in der Falcon-Konsole unter **Support \> API Clients and Keys**. Gewähren Sie ihm die Scopes für die zu importierenden Daten: **Hosts: Read** (erforderlich, für die Host-Ermittlung), **Vulnerabilities (Spotlight): Read** (für Spotlight-Befunde) und **Alerts: Read** (für EDR-Detections). Die beiden Befundtypen sind unabhängig voneinander — fehlt dem Client ein Scope, wird dieser Befundtyp übersprungen, statt den Sync scheitern zu lassen; ein Client ohne **Alerts: Read** importiert also weiterhin Spotlight-Schwachstellen.

#### Connector-Zuordnungen

1. Geben Sie die Basis-URL der API Ihrer Falcon-Cloud in das Feld **Location** ein, passend zu Ihrer Konsolen-Region — zum Beispiel `https://api.crowdstrike.com` (US\-1), `https://api.us-2.crowdstrike.com` (US\-2), `https://api.eu-1.crowdstrike.com` (EU\-1) oder `https://api.laggar.gcw.crowdstrike.com` (US\-GOV\-1).
2. Geben Sie die Client ID des API-Clients in das Feld **Client ID** ein.
3. Geben Sie das Secret des API-Clients in das Feld **Client Secret** ein.
4. Legen Sie optional einen **Minimum Severity**-Wert fest, um einzuschränken, welche Befunde importiert werden.

Jeder Falcon-Host wird zu einem Eintrag, benannt nach Hostname, Betriebssystem und Typ. Es werden nur Spotlight-Schwachstellen mit dem Status **open** und **reopened** importiert, sodass ein erneuter Import behobene Befunde schließt.

## **Deepfence ThreatMapper**

Der Deepfence-ThreatMapper-Connector verwendet die REST-API der [ThreatMapper](https://github.com/deepfence/ThreatMapper)-Management-Konsole, um **Schwachstellen-Scan**-Ergebnisse zu importieren. DefectDojo ermittelt jeden Node, den ThreatMapper gescannt hat — ein Container-Image, einen Host oder einen Container — und erstellt für jeden einen Eintrag; anschließend wird der letzte abgeschlossene Scan dieses Nodes als Befunde importiert.

#### Voraussetzungen

Sie benötigen ein ThreatMapper-**API-Token**, das Sie in der Konsole unter **Settings → User Management** finden (der API-Schlüssel Ihres Benutzers). Der Connector tauscht dieses bei jedem Sync gegen ein kurzlebiges Zugriffstoken ein; das API-Token wird nie protokolliert.

#### Connector-Zuordnungen

1. Geben Sie die URL Ihrer ThreatMapper-Konsole in das Feld **Location** ein (zum Beispiel `https://threatmapper.example.com`).
2. Geben Sie im Feld **Secret** das ThreatMapper-API-Token ein.
3. Wenn Ihre Konsole ein selbstsigniertes Zertifikat verwendet, setzen Sie **Skip TLS Verification** auf `true`.
4. Legen Sie optional einen **Minimum Severity**-Wert fest, um einzuschränken, welche Befunde importiert werden.

DefectDojo ordnet jeden gescannten **Node** einem Eintrag zu und jede **CVE** im letzten abgeschlossenen Schwachstellen-Scan einem Befund. Der Schweregrad stammt aus ThreatMappers eigener Bewertung, und das betroffene Paket, der CVSS-Score, die Fix-Version (als Abhilfemaßnahme), Referenzlinks und ein Detailblock werden übernommen. Befunde werden als dynamische Befunde erfasst und anhand von Node, CVE, Paket und Paketpfad dedupliziert.

Weitere Informationen finden Sie in der [ThreatMapper-Dokumentation](https://community.deepfence.io/threatmapper/docs/v2.5/).

## Dependency\-Track

Dieser Connector ruft Daten von einer On-Premise-Dependency\-Track-Instanz über die REST-API ab.

​**Connector-Zuordnungen**

1. Geben Sie die URL Ihres lokalen Dependency\-Track-Servers in das Feld **Location** ein.
2. Geben Sie einen gültigen API-Schlüssel in das Feld **Secret** ein.

So generieren Sie einen Dependency\-Track-API-Schlüssel:

1. **Access Management**: Navigieren Sie in der Dependency\-Track-Oberfläche zu Administration \> Access Management \> Teams.
2. **Teams Setup**: Sie können entweder ein neues Team erstellen oder ein bestehendes auswählen. Mit Teams können Sie den API-Zugriff anhand der Gruppenmitgliedschaft verwalten.
3. **Generate API Key**: Suchen Sie auf der Detailseite des ausgewählten Teams den Abschnitt „API Keys". Klicken Sie auf die Schaltfläche \+, um einen neuen API-Schlüssel zu generieren.
4. **Assign Permissions**: Klicken Sie im Abschnitt „Permissions" der Team-Seite auf die Schaltfläche \+, um die Berechtigungsauswahl zu öffnen. Wählen Sie die Berechtigungen **VIEW\_PORTFOLIO** und **VIEW\_VULNERABILITY**, um API-Zugriff auf Projekt-Portfolios und Schwachstellendetails zu ermöglichen.
5. Klicken Sie auf „**Select**", um diese Berechtigungen zu bestätigen und zu speichern.

Weitere Informationen finden Sie in der **[Dependency\-Track-Dokumentation](https://docs.dependencytrack.org/integrations/rest-api/)**.

## **Docker Scout**

Der Docker-Scout-Connector verwendet die Docker-Scout-Metrics-Exporter-API, um den Schwachstellenstatus der Images Ihrer Organisation zu melden. DefectDojo ermittelt jeden Docker-Scout-Stream (Ihre Laufzeitumgebungen) und importiert für jeden eine Zusammenfassung der Schwachstellen und der Richtlinien-Compliance.

#### Voraussetzungen

Sie benötigen ein persönliches Docker-Zugriffstoken, das von einem **Owner** einer Docker-Organisation erstellt wurde, die **bei Docker Scout registriert** ist. Der Metrics Exporter ist eine Funktion auf Organisationsebene, daher liefert ein persönliches Konto oder eine nicht bei Docker Scout registrierte Organisation keine Daten.

Erstellen Sie das Token in Ihren Docker-Kontoeinstellungen unter **Personal access tokens**, und notieren Sie sich Ihren Docker-**Organisations-Namespace**, den Sie ebenfalls benötigen.

#### Connector-Zuordnungen

1. Geben Sie `https://api.scout.docker.com` in das Feld **Location** ein.
2. Geben Sie Ihr persönliches Docker-Zugriffstoken in das Feld **Secret** ein.
3. Geben Sie Ihren Docker-**Organization**-Namespace ein.
4. Legen Sie optional einen **Minimum Severity**-Wert fest, um einzuschränken, welche Befunde importiert werden. Befunde unterhalb des gewählten Schweregrads werden nicht importiert.

DefectDojo erstellt für jeden Docker-Scout-Stream einen separaten Eintrag und importiert einen Befund pro Schweregrad für die Schwachstellen, die Docker Scout in diesem Stream zählt, sowie einen Befund für jedes Image, das Ihre Docker-Scout-Richtlinie nicht erfüllt. Die Metrics-API von Docker Scout meldet aggregierte Zählwerte statt einzelner CVEs, daher fassen diese Befunde den Status eines Streams zusammen. Öffnen Sie den Stream in Docker Scout für Details pro Image und pro CVE.

Weitere Informationen finden Sie in der [Docker-Scout-Dokumentation](https://docs.docker.com/scout/).

## **Endor Labs**

Der Endor-Labs-Connector verwendet die Endor-Labs-REST-API, um einen gesamten Endor-Labs-**Namespace** zu synchronisieren. DefectDojo ermittelt jedes Endor-**Projekt** als Eintrag und importiert die Befunde dieses Projekts, wobei Endors **Reachability**-Bewertung übernommen wird, damit Sie Schwachstellen priorisieren können, deren betroffener Code tatsächlich erreichbar ist.

#### Voraussetzungen

Sie benötigen einen Endor-Labs-**API-Schlüssel** (eine Schlüsselkennung plus deren Secret) und den **Namespace**, den Sie synchronisieren möchten. Erstellen Sie den Schlüssel in der Endor-Labs-Plattform unter **Settings \> Access \> API Keys**; der Schlüssel benötigt Lesezugriff auf die Projekte und Befunde in diesem Namespace.

Der Connector authentifiziert sich, indem er den API-Schlüssel und das Secret gegen ein kurzlebiges Bearer-Token eintauscht — das Secret wird nur für diesen Austausch verwendet und nie im Klartext gespeichert.

#### Connector-Zuordnungen

1. Geben Sie `https://api.endorlabs.com` in das Feld **Location** ein. Wenn Ihr Tenant in einer anderen Region gehostet wird, verwenden Sie stattdessen die API-Basis-URL dieser Region.
2. Geben Sie den zu synchronisierenden Endor-Labs-**Namespace** ein (zum Beispiel `your-org` oder `your-org.team`).
3. Geben Sie die **API-Key**-Kennung ein.
4. Geben Sie das zum Schlüssel gehörende **API Secret** ein.
5. Setzen Sie optional **Traverse Child Namespaces** auf `true`, um auch Befunde aus untergeordneten Namespaces des konfigurierten Namespace zu importieren.
6. Legen Sie optional einen **Minimum Severity**-Wert fest, um einzuschränken, welche Befunde importiert werden. Befunde unterhalb des gewählten Schweregrads werden nicht importiert.

DefectDojo erstellt für jedes Endor-Labs-Projekt im Namespace einen Eintrag und importiert dessen Befunde, wobei Endor-Schweregrade auf DefectDojo-Schweregrade, die CVE/GHSA-Kennungen und den CVSS-Score jeder Schwachstelle sowie Endors Reachability-Tags abgebildet werden. Die Reachability-Bewertung (zum Beispiel *Reachable — vulnerable function is called* oder *Unreachable*) wird als Impact des Befunds sowie als Tag angezeigt.

Weitere Informationen finden Sie in der **[Endor-Labs-REST-API-Dokumentation](https://docs.endorlabs.com/rest-api/)**.

## **Edgescan**

Der Edgescan-Connector verwendet die Edgescan-REST-API, um offene Schwachstellen aus Ihrem gesamten Edgescan-Konto zu importieren. DefectDojo zählt jedes Edgescan-**Asset** auf und erstellt für jedes einen Eintrag; anschließend werden die offenen Schwachstellen dieses Assets als Befunde importiert — es gibt keine Pro-Asset-Konfiguration.

#### Voraussetzungen

Sie benötigen ein Edgescan-API-Token. Erstellen Sie eines in Ihrem Edgescan-Konto unter **Account settings \> API tokens**: Geben Sie eine Bezeichnung ein, klicken Sie auf **Create**, und kopieren Sie das generierte Token (es wird nur einmal angezeigt). Wir empfehlen ein dediziertes Konto für den Connector, damit automatisierte Aktivitäten leicht zu unterscheiden sind.

#### Connector-Zuordnungen

1. Geben Sie Ihre Edgescan-URL in das Feld **Location** ein — `https://live.edgescan.com` für die Standard-Hosted-Plattform, oder den Host Ihres Tenants, falls abweichend.
2. Geben Sie Ihr Edgescan-API-Token in das Feld **Secret** ein. Es wird als `X-API-TOKEN`-Header gesendet.
3. Legen Sie optional einen **Minimum Severity**-Wert fest, um einzuschränken, welche Befunde importiert werden.

Jedes Edgescan-Asset wird zu einem Eintrag, und jede offene Schwachstelle dieses Assets wird als Befund importiert. Der Schweregrad wird von Edgescans numerischer Skala (1–5) auf DefectDojos Info–Kritisch abgebildet, und CVE-Referenzen, die CWE sowie ein CVSS-v3-Vektor werden einbezogen, sofern Edgescan sie bereitstellt.

## **Escape**

Der Escape-Connector verwendet die [Escape](https://escape.tech)-API, um **API-Sicherheits(DAST)-Befunde** zu importieren. DefectDojo zählt jede Organisation, auf die das Token zugreifen kann, sowie jede Anwendung darin auf, erstellt für jede Anwendung mit einem Scan einen Eintrag und importiert die Issues des letzten Scans dieser Anwendung als Befunde — es gibt keine Pro-Anwendungs-Konfiguration.

#### Voraussetzungen

Sie benötigen einen Escape-**API-Schlüssel**, der in der Escape-App unter **Settings → API keys** erstellt wird. Der Schlüssel wird im Header `Authorization: Key` gesendet und nie protokolliert.

#### Connector-Zuordnungen

1. Behalten Sie den vorgegebenen Wert im Feld **Location**, `https://public.escape.tech/v2`, oder geben Sie Ihren Escape-API-Host explizit an.
2. Geben Sie den Escape-API-Schlüssel in das Feld **Secret** ein.
3. Legen Sie optional einen **Minimum Severity**-Wert fest, um einzuschränken, welche Befunde importiert werden.

DefectDojo ordnet jede **Anwendung** einem Eintrag zu und jedes Scan-**Issue** einem Befund: Der Schweregrad stammt aus Escapes Bewertung (Critical/High/Medium/Low), die CWE wird übernommen, die OWASP-Kategorie und die HTTP-Methode werden zu Tags, die betroffene URL wird zum Endpunkt, und die Abhilfehinweise werden einbezogen. Befunde werden als dynamische Befunde erfasst und anhand der Escape-Issue-ID dedupliziert.

Weitere Informationen finden Sie in der [Escape-API-Dokumentation](https://docs.escape.tech/).

## **Fairwinds Insights**

Der Fairwinds-Insights-Connector verwendet die REST-API von [Fairwinds Insights](https://insights.fairwinds.com), um **Kubernetes-Sicherheitsbefunde** aus Ihrer gesamten Organisation zu importieren. DefectDojo zählt jeden aktiven **Cluster** auf und erstellt für jeden einen Eintrag; anschließend werden die Security-**Action Items** dieses Clusters \(von Polaris, Trivy, Kube\-bench, OPA und den anderen Insights-Berichten\) als Befunde importiert — es gibt keine Pro-Cluster-Konfiguration.

#### Voraussetzungen

Sie benötigen einen Fairwinds-Insights-**Organisationsnamen** und ein **API-Token**. Erstellen Sie das Token in der Insights-App unter **Organization Settings \> Tokens**; ein `read_only`-Token ist ausreichend. Das Token ist organisationsweit gültig und wird als Bearer-Token gesendet; es wird nie protokolliert.

#### Connector-Zuordnungen

1. Behalten Sie den vorgegebenen Wert im Feld **Location**, `https://insights.fairwinds.com`, oder geben Sie Ihren Insights-Host explizit an.
2. Geben Sie Ihren Insights-**Organization**-Namen ein (den Slug, der in Ihrer Dashboard-URL angezeigt wird).
3. Geben Sie das Insights-API-Token in das Feld **Secret** ein.
4. Legen Sie optional einen **Minimum Severity**-Wert fest, um einzuschränken, welche Befunde importiert werden.

DefectDojo ordnet jeden aktiven **Cluster** einem Eintrag zu und jedes Security-**Action Item** einem Befund: Der Schweregrad stammt aus Fairwinds' numerischer Bewertung \(abgebildet auf DefectDojos Info–Kritisch\), der Fairwinds-Bericht, der das Item erzeugt hat \(`polaris`, `trivy`, `kube-bench`, ...\), wird zu einem Tool-Tag, die betroffene Kubernetes-Ressource und das Container-Image werden einbezogen, und etwaige CVE-Kennungen werden extrahiert. Befunde werden als statische Befunde erfasst und anhand der Fairwinds-Action-Item-ID dedupliziert.

Weitere Informationen finden Sie in der [Fairwinds-Insights-API-Dokumentation](https://insights.docs.fairwinds.com/technical-details/api/).

## **Fortify**

Der Fortify-Connector importiert SAST-/DAST-Ergebnisse von Fortify (OpenText/Micro Focus) und deckt beide Editionen ab, die sich die Plattform teilen: **SSC** (Software Security Center, selbstgehostet) und **Fortify on Demand (FoD)** (SaaS). Er synchronisiert das gesamte Konto: DefectDojo ermittelt jede Anwendung (SSC-Projektversion/FoD-Release) und erstellt für jede einen Eintrag; anschließend werden die Issues dieser Anwendung als Befunde importiert.

#### Voraussetzungen

- **SSC**: ein **FortifyToken** — erstellen Sie eines in der SSC-Oberfläche unter **Administration → Token Management** (ein CIToken/UnifiedLoginToken).
- **FoD**: ein **OAuth2-API-Schlüssel** — eine Client ID und ein Client Secret aus **Settings → API** (mit dem Scope `api-tenant`).

Das Token und das OAuth-Secret werden nie protokolliert.

#### Connector-Zuordnungen

1. Geben Sie die Fortify-Basis-URL in das Feld **Location** ein: für SSC Ihren Server-Host (der Connector ergänzt `/ssc/api/v1`); für FoD den API-Host Ihrer Region, z. B. `https://api.ams.fortify.com`.
2. Setzen Sie **Edition** auf `SSC` oder `FoD`.
3. Geben Sie für **FoD** die OAuth-**Client ID** ein; für SSC leer lassen.
4. Geben Sie in **Token / Client Secret** das SSC-FortifyToken oder das FoD-OAuth-Client-Secret ein.
5. Legen Sie optional einen **Minimum Severity**-Wert fest, um einzuschränken, welche Befunde importiert werden.

DefectDojo ordnet jede Fortify-**Anwendung** einem Eintrag zu und jedes **Issue** einem Befund: Der Schweregrad stammt aus Fortifys eigener **Friority**-Bewertung (Critical/High/Medium/Low), der Titel kombiniert die Issue-Kategorie mit Datei und Zeile, und Dateipfad, Zeile, Kingdom, Analyzer und Engine-Typ werden übernommen. Issues von statischen Analyse-Engines (SCA) werden als statische Befunde erfasst und WebInspect(DAST)-Issues als dynamische Befunde; unterdrückte, entfernte und verborgene Issues werden übersprungen, als „Not an Issue" geprüfte Issues werden als falsch-positiv markiert, und „Exploitable"/geprüfte Issues werden als verifiziert markiert.

Weitere Informationen finden Sie in der Dokumentation zu [Fortify SSC](https://www.microfocus.com/documentation/fortify-software-security-center/) und [Fortify on Demand](https://api.ams.fortify.com/swagger/ui).

## **GitGuardian**

Der GitGuardian-Connector verwendet die GitGuardian-REST-API, um **Secret-Incidents** zu importieren — von GitGuardian erkannte offengelegte Anmeldedaten in Ihren überwachten Quellen. DefectDojo erstellt für jede überwachte Quelle (Repository oder Perimeter) mit derzeit offenen Incidents einen Eintrag und importiert jeden offenen Incident als Befund.

Zu Ihrer Sicherheit importiert der Connector nur Incident-**Metadaten** — den Detektor, den Schweregrad, die Gültigkeit, den Status und einen Link zurück zu GitGuardian. Der offengelegte Secret-Wert selbst wird von DefectDojo nie abgerufen oder gespeichert; folgen Sie dem Link in jedem Befund, um die betroffenen Stellen in GitGuardian zu prüfen.

#### Voraussetzungen

Sie benötigen einen GitGuardian-API-Schlüssel. Wir empfehlen ein **Service-Account-Token** (statt eines persönlichen Zugriffstokens), damit automatisierte Aktivitäten leicht zu unterscheiden sind. Erstellen Sie es unter **API** im GitGuardian-Dashboard und gewähren Sie diese Lese-Scopes:

* `incidents:read`
* `sources:read`

#### Connector-Zuordnungen

1. Geben Sie Ihre GitGuardian-API-URL in das Feld **Location** ein: `https://api.gitguardian.com` für die SaaS-Plattform, oder die API-URL Ihrer selbstgehosteten Instanz.
2. Geben Sie den API-Schlüssel in das Feld **Secret** ein.

Es werden nur **offene** Incidents (Status `TRIGGERED` oder `ASSIGNED`) importiert; Incidents, die Sie in GitGuardian beheben oder ignorieren, werden beim nächsten Sync automatisch in DefectDojo als behoben markiert. Ein bestätigt aktives Secret (Gültigkeit *valid*) wird als verifizierter Befund importiert.

## **GitHub**

Der GitHub-Connector ist ein **Asset-Connector**: Er zählt die Repositories auf, auf die Ihr Token zugreifen kann, und erstellt für jedes ein DefectDojo-Asset, gruppiert in Organisationen nach GitHub-Owner (Organisation oder Benutzer). Es werden keine Befunde importiert.

**Bitte beachten Sie:** Dieser Connector importiert nur Ihr Repository-**Inventar**. Um GitHub-Sicherheitswarnungen — Code Scanning, Dependabot und Secret Scanning — als Befunde zu importieren, verwenden Sie den separaten **GitHub-Advanced-Security**-Connector weiter unten. Beide sind unabhängig voneinander und können gemeinsam betrieben werden.

#### Voraussetzungen

Der Connector authentifiziert sich mit einem GitHub-**Personal Access Token** und liest nur Repository-**Metadaten** (Name, Beschreibung, URL und Owner) — er greift nicht auf Ihren Code, Ihre Issues oder Sicherheitswarnungen zu. Er importiert jedes Repository, das dem Konto des Tokens gehört, an dem es mitarbeitet oder dessen Organisation es angehört; stellen Sie daher sicher, dass das Konto des Tokens die zu spiegelnden Repositories sehen kann. Wir empfehlen ein dediziertes Service-Konto.

Das Token benötigt nur lesenden Zugriff auf Repository-Metadaten:

- Ein *fein-granulares* Token benötigt **Repository permissions → Metadata: Read-only**, gewährt für die zu importierenden Repositories (oder die gesamte Organisation).
- Ein *klassisches* Token benötigt den Scope **`repo`**, um private Repositories einzuschließen (verwenden Sie **`public_repo`**, wenn Sie nur öffentliche benötigen), sowie **`read:org`**, damit organisationseigene Repositories aufgelöst werden.

Nur GitHub.com (einschließlich GitHub Enterprise Cloud) wird unterstützt. GitHub Enterprise **Server** wird von diesem Connector derzeit nicht unterstützt.

#### Connector-Zuordnungen

1. Geben Sie `https://api.github.com` in das Feld **Location** ein.
2. Geben Sie das Personal Access Token in das Feld **Secret** ein.

Es muss keine Organisations- oder Repository-Liste eingegeben werden — DefectDojo importiert jedes Repository, das das Token sehen kann. Jedes Repository wird zu einem nach dem Repository benannten Eintrag, gruppiert nach seinem GitHub-**Owner** (Organisation oder Benutzer). Wird ein Repository später gelöscht oder verliert das Token den Zugriff darauf, wird sein zugeordneter Eintrag beim nächsten Sync als `MISSING` markiert statt entfernt — DefectDojo löscht niemals stillschweigend ein Produkt.

## **GitHub Advanced Security**

Der GitHub-Advanced-Security-Connector importiert **Code-Scanning-**, **Dependabot-** und **Secret-Scanning**-Warnungen von GitHub als drei separate Befundtypen (`GitHub:CodeScanning`, `GitHub:Dependabot` und `GitHub:SecretScanning`). DefectDojo ermittelt jedes nicht archivierte Repository in der konfigurierten Organisation und erstellt für jedes einen Eintrag.

#### Voraussetzungen

GitHub-Advanced-Security-Funktionen müssen für die zu importierenden Repositories aktiviert sein. Der Connector authentifiziert sich mit einem GitHub-**Personal Access Token**:

1. Öffnen Sie in GitHub **Settings \> Developer settings \> Personal access tokens** und erstellen Sie ein Token, das der Zielorganisation gehört (oder Zugriff darauf hat).
2. Gewähren Sie ihm Lesezugriff auf die Sicherheitswarnungen: Ein *fein-granulares* Token benötigt **Read-only**-Zugriff auf **Code scanning alerts**, **Dependabot alerts** und **Secret scanning alerts** der Repositories der Organisation; ein *klassisches* Token benötigt die Scopes **`repo`** und **`security_events`**.
3. Stellen Sie sicher, dass der Owner des Tokens die zu importierenden Repositories sehen kann — der Connector sieht nur Repositories, auf die das Token zugreifen kann.

#### Connector-Zuordnungen

1. Geben Sie `https://api.github.com` in das Feld **Location** ein. Verwenden Sie für GitHub Enterprise Server `https://<your-host>/api/v3`.
2. Geben Sie den Organisations-Login in das Feld **Organization** ein.
3. Geben Sie das Personal Access Token in das Feld **Secret** ein.
4. Legen Sie optional einen **Minimum Severity**-Wert fest, um einzuschränken, welche Befunde importiert werden.

Jedes nicht archivierte Repository wird zu einem Eintrag, der über die drei Warnungsfamilien nach offenen Warnungen abgefragt wird. Eine Warnungsfamilie, die für ein Repository nicht aktiviert ist, wird übersprungen statt als behoben gemeldet, sodass deaktivierte Funktionen keine falschen Schließungen verursachen.

## **GitLab**

Der GitLab-Connector ist ein **Asset-Connector**: Er zählt jedes Projekt (Repository) auf, auf das Ihr Token zugreifen kann, und erstellt für jedes ein DefectDojo-Asset, gruppiert in Organisationen nach GitLab-Namespace (Gruppe oder Benutzer). Es werden keine Befunde importiert.

#### Voraussetzungen

Sie benötigen ein Personal Access Token mit dem Scope **read_api**. Wir empfehlen, das Token von einem dedizierten Service-Konto aus zu erstellen; der Connector listet die Projekte auf, in denen dieses Konto Mitglied ist.

#### Connector-Zuordnungen

1. Geben Sie Ihre GitLab-URL in das Feld **Location** ein: `https://gitlab.com`, oder die Basis-URL Ihrer selbstgehosteten Instanz.
2. Geben Sie das Personal Access Token in das Feld **Secret** ein.

Jedes Projekt wird zu einem nach dem Projekt benannten Eintrag, gruppiert nach seinem **Namespace**. Projekte, die in GitLab zur Löschung vorgesehen sind (von einem Benutzer gelöscht, aber noch nicht durch den Hintergrundjob von GitLab endgültig entfernt), werden automatisch ausgeschlossen; das Löschen eines Projekts markiert seinen Eintrag daher beim nächsten Sync als `MISSING`, statt ein umbenanntes Geister-Asset zu hinterlassen.

## **Google Cloud Security Command Center**

Der Google-Cloud-SCC-Connector verwendet die Security-Command-Center-v2-REST-API, um aktive Sicherheitsbefunde aus Ihrer Google-Cloud-Organisation, -Ordner oder -Projekt zu importieren. DefectDojo erstellt für jedes Google-Cloud-**Projekt** mit offenen Befunden einen Eintrag.

#### Voraussetzungen

Security Command Center muss für Ihre Organisation **aktiviert** sein (das Standard-Tier ist kostenlos). Anschließend benötigen Sie ein Service-Konto, das Befunde auflisten kann, sowie einen JSON-Schlüssel dafür:

1. Erstellen Sie in Google Cloud ein Service-Konto — ein dediziertes für DefectDojo wird empfohlen.
2. Gewähren Sie ihm die Rolle **Security Center Findings Viewer** (`roles/securitycenter.findingsViewer`) auf der Ebene, aus der Sie importieren möchten (Organisation, Ordner oder Projekt).
3. Erstellen Sie einen **JSON-Schlüssel** für das Service-Konto und laden Sie ihn herunter.

#### Connector-Zuordnungen

1. Lassen Sie das Feld **Location** auf dem Standardwert `https://securitycenter.googleapis.com`, sofern Sie keinen nicht standardmäßigen Endpunkt verwenden.
2. Geben Sie im Feld **Parent Resource** den Geltungsbereich für den Import ein: `organizations/{id}`, `folders/{id}` oder `projects/{id}`.
3. Fügen Sie den vollständigen Inhalt der **JSON-Schlüssel**-Datei des Service-Kontos in das Feld **Service Account Key** ein.
4. Legen Sie optional einen **Minimum Severity**-Wert fest, um einzuschränken, welche Befunde importiert werden.

Es werden nur `ACTIVE`, nicht stummgeschaltete Befunde importiert, sodass Befunde, die Sie in SCC deaktivieren oder stummschalten, beim nächsten Sync automatisch in DefectDojo als behoben markiert werden. Das betroffene GCP-Projekt jedes Befunds wird zu dessen Eintrag.

## **Group-IB ASM**

Der Group-IB-ASM(Attack Surface Management)-Connector verwendet die Group-IB-ASM-REST-API, um externe Angriffsflächen-**Issues** (Befunde) in DefectDojo zu übertragen. DefectDojo ermittelt jedes Group-IB-**Unternehmen/Tenant** als separaten Eintrag und importiert die Issues dieses Unternehmens geplant und inkrementell. Das Asset, auf das sich jedes Issue bezieht (eine Domain, IP oder URL), wird dem resultierenden Befund als **Endpunkt** angehängt.

#### Voraussetzungen

Sie benötigen Ihren Group-IB-ASM-Login und einen API-Schlüssel. Wir empfehlen, für DefectDojo ein dediziertes Service-Konto anzulegen, damit automatisierte Aktivitäten von manuellen Team-Aktionen unterschieden werden können.

So generieren Sie einen API-Schlüssel:

1. Öffnen Sie Group-IB Attack Surface Management, klicken Sie unten links auf **Help** und wählen Sie **API**.
2. Klicken Sie auf **Generate API Key** (oben rechts, unter Ihrem Benutzernamen).
3. Geben Sie Ihr SSO-Passwort ein und klicken Sie auf **Next**, dann auf **Copy token**.
4. Speichern Sie den Schlüssel in einem Secret Manager und planen Sie eine regelmäßige Rotation ein.

#### Connector-Zuordnungen

Group-IB ASM authentifiziert sich mit HTTP Basic Auth, wobei der Benutzername Ihr ASM-Login und das Passwort Ihr API-Schlüssel ist. **Beide Werte sind erforderlich** — der API-Schlüssel allein reicht nicht aus.

1. Geben Sie `https://asm.group-ib.com` in das Feld **Location** ein. Dies ist für alle Group-IB-ASM-Tenants gleich.
2. Geben Sie Ihren ASM-Login (in der Regel eine E-Mail-Adresse) in das Feld **Username** ein.
3. Geben Sie Ihren API-Schlüssel in das Feld **API Key** (Secret) ein.
4. Legen Sie optional einen **Minimum Severity**-Wert fest, um einzuschränken, welche Befunde importiert werden. Befunde unterhalb des gewählten Schweregrads werden nicht importiert.

DefectDojo ordnet jedes Group-IB-**Unternehmen** als separaten Eintrag zu, wobei die Unternehmens-ID als Kennung verwendet wird. Beim ersten Sync trägt DefectDojo die jüngste Issue-Historie nach; nachfolgende Syncs erfolgen inkrementell und rufen nur seit dem letzten Sync geänderte Issues ab (anhand des jeweils neuesten `lastSeen`-Zeitstempels jedes Issues).

#### Beschränkung auf ein einzelnes Unternehmen (optional)

Standardmäßig ermittelt der Connector automatisch die für Ihre API-Anmeldedaten verfügbaren Unternehmen (über den ASM-Endpunkt `clients`) und erstellt einen Eintrag pro Unternehmen. Dies ist die empfohlene Einrichtung und erfordert keine zusätzliche Konfiguration.

Ist der Endpunkt `clients` für Ihren Tenant nicht verfügbar — zum Beispiel, weil er auf Partner-/MSP-Konten beschränkt ist —, kann der Connector auf ein Unternehmen beschränkt werden, indem dessen **Unternehmens-ID** als toolspezifisches Feld `company_id` in der Connector-Konfiguration angegeben wird. Ist `company_id` gesetzt, verwendet DefectDojo dieses Unternehmen direkt, statt Unternehmen aufzuzählen. Lassen Sie es nicht gesetzt, um die automatische Ermittlung zu verwenden.

Weitere Informationen finden Sie im Group-IB-ASM-REST-API-Handbuch (im Produkt verfügbar über **Help → API**).

## **HackerOne**

Der HackerOne-Connector verwendet die HackerOne-REST-API, um Reports aus Ihrem Bug-Bounty- oder Vulnerability-Disclosure-Programm zu importieren. DefectDojo erstellt für jedes Programm, auf das das Token zugreifen kann, einen Eintrag und importiert dessen Reports als Befunde.

#### Voraussetzungen

Der Connector verwendet die **Customer**-API von HackerOne, die ein **Organization-API-Token** erfordert — ein persönliches Token aus Ihren Benutzereinstellungen funktioniert nur gegen die Hacker-API und authentifiziert sich hier nicht.

1. Gehen Sie in HackerOne zu **Organization Settings > API Tokens**.
2. Erstellen Sie ein Token und notieren Sie sowohl die **Identifier** als auch den **Token**-Wert. Lesezugriff auf das Programm ist ausreichend.

#### Connector-Zuordnungen

1. Geben Sie `https://api.hackerone.com` in das Feld **Location** ein.
2. Geben Sie die Token-**Identifier** in das Feld **API Token Identifier** ein.
3. Geben Sie den Token-Wert in das Feld **API Token** ein.
4. Legen Sie optional einen **Minimum Severity**-Wert fest, um einzuschränken, welche Befunde importiert werden.

Jedes Programm wird zu einem Eintrag, und seine Reports werden mit der beibehaltenen HackerOne-Schweregrad-Bewertung als Befunde importiert.

## **Harbor**

Der Harbor-Connector verwendet die Harbor-v2.0-REST-API, um Container-Image-Schwachstellen aus Ihrer gesamten Registry zu importieren. DefectDojo zählt jedes Harbor-**Projekt** auf und erstellt für jedes einen Eintrag; anschließend durchläuft er die Repositories und Artefakte des Projekts und importiert die Schwachstellen aus jedem **gescannten** Artefakt — wobei das Image (Repository + Tag/Digest) als Befundkontext übernommen wird. Es gibt keine Pro-Image-Konfiguration.

#### Voraussetzungen

Sie benötigen ein Harbor-Konto (oder ein **Robot-Konto**) mit Pull-/Lesezugriff auf die zu importierenden Projekte. Wir empfehlen ein dediziertes Robot-Konto: Öffnen Sie in Harbor ein Projekt (oder **Administration \> Robot Accounts** für ein System-Robot), erstellen Sie einen Robot mit der Berechtigung **pull** auf Repositories und Artefakte, und kopieren Sie dessen vollständigen Namen und Secret. Robot-Namen beginnen standardmäßig mit `robot$`, das Präfix ist jedoch pro Harbor-Instanz konfigurierbar (manche verwenden `robot_`) — kopieren Sie den Namen exakt so, wie Harbor ihn anzeigt. Ein normaler Benutzername/Passwort funktioniert ebenfalls.

#### Connector-Zuordnungen

1. Geben Sie Ihre Harbor-URL in das Feld **Location** ein — zum Beispiel `https://harbor.example.com`. DefectDojo hängt den API-Pfad `/api/v2.0` automatisch an.
2. Geben Sie den Harbor-Benutzernamen oder einen Robot-Kontonamen exakt so, wie Harbor ihn anzeigt (standardmäßig `robot$<name>`), in das Feld **Username** ein.
3. Geben Sie das Passwort oder das Robot-Konto-Secret in das Feld **Secret** ein. Es wird per HTTP-Basic-Authentifizierung gesendet.
4. Legen Sie optional einen **Minimum Severity**-Wert fest, um einzuschränken, welche Befunde importiert werden.

Jedes Harbor-Projekt wird zu einem Eintrag. Für jedes Artefakt mit einem abgeschlossenen Scan werden dessen Schwachstellen als Befunde importiert; das betroffene Paket/die Version, ein von CVSS abgeleiteter Schweregrad, die CVE, die CWE und eine Abhilfemaßnahme (Fix-Version) werden einbezogen, sofern Harbor sie bereitstellt. Es werden nur gescannte Artefakte importiert — lösen Sie in Harbor einen Scan für noch nicht gescannte Images aus.

## **Have I Been Pwned**

Der Have-I-Been-Pwned(HIBP)-Connector verwendet die HIBP-REST-API, um zu melden, welche Konten auf den eigenen Domains Ihrer Organisation in bekannten Datenpannen aufgetaucht sind. DefectDojo ermittelt jede von Ihnen bei HIBP verifizierte Domain und importiert einen Befund pro Datenpanne, die diese Domain betrifft.

#### Voraussetzungen

Sie benötigen einen Have-I-Been-Pwned-API-Schlüssel mit Domain-Suche, wofür mindestens ein **Core**-Abonnement erforderlich ist. Sie können einen Schlüssel über Ihr [Have-I-Been-Pwned-Konto](https://haveibeenpwned.com/API/Key) erhalten.

Sie müssen außerdem **mindestens eine Domain verifizieren**, bevor Datenpannen-Daten verfügbar sind. HIBP ermöglicht die Verifizierung einer Domain per DNS-TXT-Eintrag, Meta-Tag, Datei-Upload oder E-Mail, unter **Domain search** in Ihrem Konto. Solange keine Domain verifiziert ist, ermittelt der Connector keine Domains und importiert keine Befunde.

#### Connector-Zuordnungen

1. Geben Sie `https://haveibeenpwned.com` in das Feld **Location** ein.
2. Geben Sie Ihren API-Schlüssel in das Feld **Secret** ein.
3. Legen Sie optional einen **Minimum Severity**-Wert fest, um einzuschränken, welche Befunde importiert werden. Befunde unterhalb des gewählten Schweregrads werden nicht importiert.

DefectDojo erstellt für jede von Ihnen bei HIBP verifizierte Domain einen separaten Eintrag und importiert einen Befund pro Datenpanne, die Konten auf dieser Domain betrifft. Der Schweregrad jedes Befunds spiegelt die Art der durch die Datenpanne offengelegten Daten wider, und seine Beschreibung listet die betroffenen Konten auf Ihrer Domain auf, damit Ihr Team handeln kann.

Weitere Informationen finden Sie in der [Have-I-Been-Pwned-API-Dokumentation](https://haveibeenpwned.com/API/v3).

## **HCL AppScan**

Der HCL-AppScan-Connector verwendet die AppScan-v4-REST-API, um Issues aus **AppScan on Cloud (ASoC)** oder einem selbstgehosteten **AppScan 360°** zu importieren (beide teilen sich die API). Er synchronisiert das gesamte Konto: DefectDojo ermittelt jede Anwendung und erstellt für jede einen Eintrag; anschließend werden die Issues dieser Anwendung (DAST, SAST und IAST) als Befunde importiert.

#### Voraussetzungen

Sie benötigen einen AppScan-**API-Schlüssel** — eine Key ID und ein Key Secret, generiert unter Ihren AppScan-Kontoeinstellungen (API Key). Der Connector tauscht diese bei jedem Lauf gegen ein kurzlebiges Session-Token ein; Key ID, Key Secret und Token werden nie protokolliert.

#### Connector-Zuordnungen

1. Geben Sie die AppScan-Konsolen-URL in das Feld **Location** ein: Verwenden Sie für ASoC `https://cloud.appscan.com` (oder `https://eu.cloud.appscan.com` für die EU-Region); verwenden Sie für AppScan 360° den Host Ihrer Instanz.
2. Setzen Sie **Provider** auf `ASOC` für AppScan on Cloud oder auf `A360` für ein selbstgehostetes AppScan 360°.
3. Geben Sie die **API Key ID** und das **API Key Secret** ein.
4. Legen Sie optional einen **Minimum Severity**-Wert fest, um einzuschränken, welche Befunde importiert werden.

DefectDojo ordnet jede AppScan-**Anwendung** einem Eintrag (VEP) zu und jedes **Issue** einem Befund: Der Titel ist der Issue-Typ mit angehängter Domain/Entität/Cause-ID/URL/Pfad; der Schweregrad bildet Informational auf Info ab (Low/Medium/High/Critical werden unverändert übernommen); die CWE, eine beschriftete Beschreibung, die Abhilfemaßnahme und der Hinweis sowie der Host/Port-Endpunkt werden übernommen. Issues aus statischer Analyse werden als statische Befunde erfasst und dynamische/interaktive Issues als dynamische Befunde; offene Issues sind aktiv, und behobene/bestandene Issues sind behoben.

Weitere Informationen finden Sie in der [AppScan-REST-API-Dokumentation](https://help.hcl-software.com/appscan/ASoC/appseccloud_rest_apis.html).

## **Intigriti**

Der Intigriti-Connector verwendet die externe Unternehmens-API von Intigriti, um Bug-Bounty-/Pentest-**Submissions** in DefectDojo zu übertragen. Er synchronisiert das gesamte Unternehmenskonto: DefectDojo ermittelt jedes Programm, auf das das Token zugreifen kann, und erstellt für jedes einen Eintrag; anschließend werden die Submissions dieses Programms als Befunde importiert.

#### Voraussetzungen

Sie benötigen ein Intigriti-**Company-API-Token**. Generieren Sie im Intigriti-Unternehmensportal unter **Company Settings > API** (Scope `company_external_api`) ein Zugriffstoken mit Lesezugriff auf Ihre Programme und Submissions. Ein dediziertes Token für DefectDojo wird empfohlen. Das Token wird als Bearer-Token gesendet und nie protokolliert.

#### Connector-Zuordnungen

1. Geben Sie die Basis-URL der externen Intigriti-Unternehmens-API in das Feld **Location** ein: `https://api.intigriti.com/external/company`. Die URL muss HTTPS verwenden.
2. Geben Sie das Unternehmens-API-Token in das Feld **Secret** ein.
3. Legen Sie optional einen **Minimum Severity**-Wert fest, um einzuschränken, welche Befunde importiert werden.

DefectDojo ordnet jedes Intigriti-**Programm** einem Eintrag zu und jede **Submission** einem Befund, mit dem Submission-Code als Schlüssel. Der Schweregrad des Befunds folgt der Bewertung von Intigriti (Exceptional/Critical → Critical, dann High/Medium/Low, ansonsten Informational), und der Lifecycle-Status der Submission wird auf den Befundstatus abgebildet: offene/in Triage befindliche Submissions sind aktiv, akzeptierte Submissions sind verifiziert, und geschlossene Submissions werden je nach Schließungsgrund zu behoben, einem Duplikat, außerhalb des Geltungsbereichs, falsch-positiv oder risikoakzeptiert. Die Befundbeschreibung übernimmt den Schwachstellentyp des Reports, das betroffene Asset, den Proof of Concept und die Antworten des Forschers.

Weitere Informationen finden Sie in der [Intigriti-API-Dokumentation](https://kb.intigriti.com/en/articles/6117846-intigriti-api).

## **Intruder**

Der Intruder-Connector verwendet die [Intruder-REST-API](https://developers.intruder.io/), um den Status Ihres gesamten Kontos in DefectDojo zu übertragen. Jedes Intruder-**Target** wird als Eintrag (Produkt) ermittelt; jedes **Vorkommen** eines Issues auf einem Target wird zu einem Befund.

#### Connector-Zuordnungen

1. Lassen Sie das Feld **Location** auf `https://api.intruder.io/` (dem Standard-Intruder-API-Server).
2. Geben Sie ein Intruder-**API-Zugriffstoken** in das Feld **Secret** ein.

Generieren Sie ein Zugriffstoken in Intruder unter **My account > API Access Tokens** (Sie benötigen Ihr Kontopasswort, um es zu erstellen, und das Token wird nur einmal angezeigt). Einzelheiten finden Sie in der [Intruder-API-Dokumentation](https://developers.intruder.io/docs/creating-an-access-token).

Befunde werden pro Vorkommen abgeleitet: Der Schweregrad stammt aus dem Issue-Schweregrad, CVEs und CVSS aus dem Vorkommen, der Standort aus Target/Port, und ein zurückgestelltes (snoozed) Vorkommen wird als inaktiver Befund (falsch-positiv oder risikoakzeptiert) importiert.

## **IriusRisk**

Der IriusRisk-Connector verwendet ein API-Token, um Threat-Modeling-Daten aus Ihrer IriusRisk-Instanz abzurufen.

#### Voraussetzungen

Sie benötigen ein API-Token aus Ihrem IriusRisk-Konto. Wir empfehlen, für DefectDojo ein dediziertes Service-Konto anzulegen, um automatisierte Aktivitäten klar von manuellen Team-Aktionen zu unterscheiden.

So generieren Sie ein API-Token in IriusRisk:

1. Melden Sie sich bei Ihrer IriusRisk-Instanz an.
2. Navigieren Sie zu Ihrem **User Profile** im Menü oben rechts.
3. Wählen Sie **API Token** und generieren Sie ein neues Token.

Weitere Informationen finden Sie in der [IriusRisk-API-Dokumentation](https://support.iriusrisk.com/hc/en-us/categories/360001148511).

#### Connector-Zuordnungen

1. Geben Sie die URL Ihrer IriusRisk-Instanz in das Feld **Location URL** ein. Bei Cloud-gehosteten Instanzen ist dies typischerweise `https://{your-subdomain}.iriusrisk.com`. Verwenden Sie bei On-Premise-Installationen die Basis-URL Ihrer Instanz.
2. Geben Sie Ihr **API Token** in das Feld **Secret** ein.
3. Legen Sie optional einen **Minimum Severity**-Wert fest, um einzuschränken, welche Befunde importiert werden. Befunde unterhalb des gewählten Schweregrads werden nicht importiert.

## **JFrog Xray**

Der JFrog-Xray-Connector verwendet die JFrog-Xray-REST-API, um Schwachstellendaten aus Ihren Artifactory-Repositories abzurufen. DefectDojo ermittelt alle Repositories in Ihrer JFrog-Instanz und erzeugt über Xray Schwachstellenberichte, wobei Befunde geplant importiert werden.

#### Voraussetzungen

Sie benötigen ein API-Token mit Zugriff auf sowohl die Artifactory- als auch die Xray-API. Wir empfehlen, für DefectDojo ein dediziertes Service-Konto anzulegen. Das Konto benötigt:

* Lesezugriff auf Artifactory-Repositories
* Berechtigung, Xray-Schwachstellenberichte zu erzeugen und anzuzeigen (Berechtigung `Apply on Watches` in Xray oder gleichwertig)

#### Connector-Zuordnungen

1. Geben Sie die Basis-URL Ihrer JFrog-Instanz in das Feld **Location** ein. Dies sollte die Root-URL Ihrer JFrog-Instanz sein, zum Beispiel `https://your-instance.jfrog.io`. Geben Sie keinen abschließenden Pfad an — DefectDojo erstellt die passenden API-Pfade automatisch.
2. Geben Sie ein gültiges **Reference Token** in das Feld **Secret** ein. Tokens können unter **User Management \> Access Tokens** in der JFrog-Platform-Oberfläche generiert werden.
Sie müssen ein **Reference Token** generieren und diesen Wert verwenden.

Erforderliche Token-Scopes für JFrog Xray:

- **All Services**, da DefectDojo Zugriff sowohl auf den XRay- als auch auf den Artifactory-Dienst benötigt
- Mindestens **Manage Reports + Manage Resources**.

Standardmäßig ordnet DefectDojo jedes Artifactory-**Repository** als separaten Eintrag zu. Jeder Sync erzeugt über Xray einen vollständigen Schwachstellenbericht pro Repository, sodass die Befundstatus in DefectDojo stets den aktuellen Zustand des Repositorys widerspiegeln.

#### Repository-Filter (optional)

Standardmäßig ermittelt der Connector **jedes** Repository in Ihrer JFrog-Instanz. Bei Instanzen mit einer großen Anzahl von Repositories — von denen viele für die Sicherheitsprüfung möglicherweise nicht relevant sind — kann die Ermittlung mit dem optionalen Feld **Repository Filter** unter **Import Filters** im Connector-Formular eingegrenzt werden.

Der Filter wird während der Ermittlung angewendet, **bevor irgendeine Arbeit pro Repository erfolgt**. Ein Repository außerhalb des Filters verursacht keine Kosten: Für dieses wird kein Xray-Bericht erzeugt, und im Artefakt-Modus werden keine seiner Artefakte der ersten Ebene aufgelistet. Dies macht ihn zur effektivsten Methode, um sowohl die Sync-Zeit als auch die Last zu reduzieren, die DefectDojo auf Ihre JFrog-Instanz legt — mehr als jede später im Sync angewendete Einstellung. Er wird insbesondere in Kombination mit **Artifact-Level Records** bei großen Instanzen empfohlen.

**Syntax:** eine kommagetrennte Liste von Repository-Schlüsseln. Jeder Eintrag kann `*`-Platzhalter verwenden:

* Ein Eintrag, der `*` enthält, wird als Muster abgeglichen — `releases-*` erfasst jeden Repository-Schlüssel, der mit `releases-` beginnt, und `*docker-pr-local*` erfasst jeden Schlüssel, der `docker-pr-local` enthält. Ein `*` erfasst eine beliebige Zeichenfolge, auch `/`.
* Ein Eintrag ohne `*` muss einem Repository-Schlüssel **exakt** entsprechen.
* Ein Repository wird ermittelt, wenn es auf **einen beliebigen** Eintrag der Liste passt. Leerzeichen um Kommas werden ignoriert.

```
releases-*, snapshots
```

Das obige Beispiel ermittelt jedes Repository, dessen Schlüssel mit `releases-` beginnt, sowie das einzelne Repository mit dem exakten Namen `snapshots`.

Hinweise:

* Der Filter ist eine **Allow-Liste** — eine Übereinstimmung wählt ein Repository aus. Es gibt keine Ausschluss- oder Negationssyntax, sodass sich „alles außer X" nicht direkt ausdrücken lässt.
* Der Abgleich erfolgt **groß-/kleinschreibungssensitiv**, sowohl bei exakten Einträgen als auch bei Platzhaltern. `*` ist das einzige Platzhalterzeichen; `?` und Zeichenbereiche werden nicht unterstützt.
* **Leer lassen, um jedes Repository zu ermitteln.** Ein Wert, der nur aus Leerzeichen oder Kommas besteht, wird als leer behandelt.
* Ein Filter, der auf nichts passt, ermittelt einfach nichts — es gibt keine Fehlermeldung. Findet ein Sync unerwartet keine Repositories, prüfen Sie im Connector-Log den Eintrag `repository filter scoped discovery`, der meldet, wie viele der insgesamt vorhandenen Repositories getroffen wurden.
* Das Feld kann nach dem Erstellen der Verbindung geändert werden.

**Den Filter später ändern:** Repositories, die ein neu eingeengter Filter jetzt ausschließt, werden nicht mehr ermittelt, und ihre bestehenden Einträge durchlaufen den normalen Lebenszyklus für Produkte, die das Tool nicht mehr meldet — **zugeordnete** Einträge werden beim nächsten Sync als `MISSING` markiert, und nicht zugeordnete `NEW`-Einträge werden entfernt. Bereits in DefectDojo importierte Befunde werden nicht gelöscht; der Filter steuert nur die Ermittlung.

#### Artifact-Level Records

Der Schalter **Artifact-Level Records** ändert die Ermittlung auf eine Ebene unterhalb des Repositorys: Jeder Eintrag der ersten Ebene unter einer Repository-Root (bei Docker-Repositories jedes Image; bei generischen Repositories jede Datei oder jeder Ordner der obersten Ebene) wird zu einem eigenen Eintrag. Jeder Sync erzeugt weiterhin einen einzigen Xray-Bericht pro Repository — DefectDojo ordnet jede Schwachstelle den Artefakten zu, die sie betrifft, sodass sich die Last auf Ihre JFrog-Instanz nicht erhöht.

> **Prüfen Sie vor Ihrem ersten Sync, in welchem Modus Sie sich befinden.** Artifact-Level Records ist bei **Neuinstallationen standardmäßig aktiviert**. Installationen von vor Einführung dieser Funktion behalten ihr bestehendes Repository-Level-Layout bei, sodass der Schalter dort deaktiviert bleibt, bis ihn jemand einschaltet. In beiden Fällen kann der Schalter jederzeit geändert werden — siehe *Eine bestehende Verbindung umstellen* unten.

Bei aktiviertem Artifact-Level Records:

* Repositories bleiben als Einträge bestehen und werden zu **übergeordneten Assets**: Sie tragen selbst keine Befunde, aber wenn die Asset-Hierarchie-Funktion aktiviert ist, verknüpft DefectDojo jedes Artefakt-Asset automatisch mit einer `parent`-Beziehung mit seinem Repository-Asset. Assets können dann nach Parent/Child gefiltert werden, und Befunde werden in der Hierarchie nach oben aggregiert.
* Eine Schwachstelle, die mehrere Artefakte betrifft, wird in das Asset jedes betroffenen Artefakts importiert, sodass jedes Asset die vollständige Menge der es betreffenden Befunde zeigt.
* Befunde beziehen sich auf den **neuesten Build** jedes Artefakts, sodass die Befunde eines Artefakts dessen aktuellen Build beschreiben, statt Ergebnisse aus jedem von Xray je gescannten Build anzusammeln.
* Von diesem Connector erzeugte Hierarchiebeziehungen überschreiben nie von Ihnen manuell erstellte Beziehungen. Hat ein Asset bereits einen von Ihnen zugewiesenen Parent, lässt der Connector ihn unangetastet.
* Das Token benötigt zusätzlich Lesezugriff auf die Artifactory-Storage-API (in den obigen Scopes enthalten).

**Eine bestehende Verbindung auf Artifact-Level Records umstellen:** Der Schalter kann jederzeit geändert werden. Beim ersten Sync danach erscheinen neue Artefakt-Einträge zur Zuordnung — aktivieren Sie **Auto Map** für die Verbindung beim Umschalten, damit Befunde ohne Lücke übertragen werden. Die Repository-Level-Assets erhalten keine Befunde mehr, und ihre zuvor importierten Befunde werden beim nächsten Sync geschlossen (dieselben Befunde werden mit neuem Status unter den neuen Artefakt-Assets erneut importiert); Notizen und Historie zu den alten Repository-Level-Befunden bleiben am Repository-Asset erhalten. Ein Zurückschalten kehrt dies um: Repository-Einträge tragen wieder Befunde (zuvor geschlossene Befunde werden bei erneuter Übereinstimmung wieder geöffnet), und Artefakt-Einträge werden als MISSING markiert — ihre Assets und Befunde bleiben erhalten, erhalten aber keine Updates mehr, sodass Sie sie nach Belieben archivieren können.

Weitere Informationen finden Sie in der [JFrog-Xray-REST-API-Dokumentation](https://jfrog.com/help/r/jfrog-rest-apis/xray-rest-apis).

## **Jira Service Management Assets**

Der JSM-Assets-Connector ist ein **Asset-Connector**: Er zählt die Objekte in Ihrem Jira-Service-Management-Assets-Workspace (ehemals Insight) auf und erstellt für jedes Objekt ein DefectDojo-Asset, gruppiert in Organisationen nach Objektschema. Es werden keine Befunde importiert.

#### Voraussetzungen

* Assets erfordert einen **Jira-Service-Management-Premium- oder -Enterprise-Plan**. Bei Free- oder Standard-Plänen antwortet die Assets-API mit `403 "Access to Assets API was denied"`, obwohl der Rest der Site funktioniert.
* Das verwendete Atlassian-Konto muss auf der Site über **Jira-Service-Management-Produktzugriff** verfügen (einen Agent-Sitzplatz) — reiner Site-Zugriff genügt nicht.
* Erstellen Sie ein klassisches Atlassian-API-Token unter [id.atlassian.com/manage-profile/security/api-tokens](https://id.atlassian.com/manage-profile/security/api-tokens). Wir empfehlen ein dediziertes Service-Konto.

#### Connector-Zuordnungen

1. Geben Sie Ihre Atlassian-Site-URL in das Feld **Location** ein: `https://{your-site}.atlassian.net`.
2. Geben Sie die Atlassian-Konto-E-Mail-Adresse, zu der das Token gehört, in das Feld **Email** ein.
3. Geben Sie das API-Token in das Feld **Secret** ein.

Jedes Assets-Objekt wird zu einem nach dem Label des Objekts benannten Eintrag, gruppiert nach seinem **Objektschema**.

## **Kubescape**

Der Kubescape-Connector liest Kubernetes-Posture(Fehlkonfigurations)-Ergebnisse, die vom [Kubescape-Operator](https://kubescape.io/docs/install-operator/) erzeugt werden, direkt aus der Kubernetes-API des Clusters — ein ARMO-SaaS-Konto ist nicht erforderlich. Er liest die `WorkloadConfigurationScan`-Objekte, die von der im Cluster laufenden Storage-Aggregated-API des Operators bereitgestellt werden (`spdx.softwarecomposition.kubescape.io/v1beta1`). Jeder Kubernetes-**Namespace** mit Posture-Ergebnissen wird einem Eintrag (Produkt) zugeordnet; jede fehlgeschlagene Kontrolle auf einer Workload wird zu einem Befund.

#### Voraussetzungen

- Der Kubescape-Operator muss im Zielcluster mit aktiviertem Konfigurations-Scanning installiert sein (siehe [Installing in your cluster](https://kubescape.io/docs/install-operator/)). Bestätigen Sie mit `kubectl get workloadconfigurationscans -A`, dass Ergebnisse vorhanden sind.
- Eine **kubeconfig**, die Lesezugriff auf die API-Gruppe `spdx.softwarecomposition.kubescape.io` gewährt (list/get auf `workloadconfigurationscans`) für den Zielcluster.

#### Connector-Zuordnungen

1. Geben Sie die API-Server-URL des Clusters (oder eine sprechende Cluster-Kennung) in das Feld **Location** ein.
2. Fügen Sie die **kubeconfig** für den Zielcluster in das Feld `kubeconfig` ein. Setzen Sie optional `kube_context`, um einen Kontext darin auszuwählen, und `cluster_name`, um die ermittelten Produkte zu beschriften.
3. Jeder Namespace mit Posture-Ergebnissen wird als Eintrag ermittelt; ordnen Sie die gewünschten den DefectDojo-Produkten zu.

Befunde werden pro fehlgeschlagener Kontrolle abgeleitet: Der Kontrollname und die Workload identifizieren den Befund, der Schweregrad stammt aus dem Score-Faktor der Kontrolle, die Kontroll-ID wird zur Schwachstellen-ID, und jeder Befund verlinkt auf seine Kontrollreferenz unter `https://hub.armosec.io/docs/`.

## **Mend**

Der Mend-Connector (ehemals **WhiteSource**) verwendet die Mend-API, um Sicherheitsbefunde aus Ihrer Mend-Organisation zu importieren. DefectDojo erstellt für jedes Mend-**Projekt** einen Eintrag.

#### Voraussetzungen

Sie benötigen einen Mend-(Service-)Benutzer mit einem **User Key** (einem persönlichen Zugriffstoken) und Ihre Mend-**Organization UUID**. Wir empfehlen ein dediziertes Service-Konto, damit automatisierte Aktivitäten leicht von manuellen Team-Aktionen zu unterscheiden sind. Die Organization UUID finden Sie in der Mend-App unter **Administration > Organization UUID**.

#### Connector-Zuordnungen

1. Geben Sie Ihre Mend-API-URL in das Feld **Location** ein. Diese URL ist **regionsspezifisch** — verwenden Sie die API-Basis-URL der Region, in der Ihre Mend-Organisation gehostet wird.
2. Geben Sie die Login-E-Mail-Adresse des Mend-Benutzers in das Feld **Email** ein.
3. Geben Sie Ihre Mend-**Organization UUID** in das Feld **Organization UUID** ein.
4. Geben Sie den Mend-**User Key** in das Feld **User Key** ein.
5. Legen Sie optional einen **Minimum Severity**-Wert fest, um einzuschränken, welche Befunde importiert werden.

## **Lacework / FortiCNAPP**

Der Lacework-/FortiCNAPP-Connector verwendet die Lacework-v2-API, um **Host- und Container-Schwachstellen** für Ihr gesamtes Lacework-Konto zu importieren.

#### Voraussetzungen

Sie benötigen einen Lacework-**API-Schlüssel** — eine API-Key-ID und ein Secret, erstellt in der Lacework-Konsole unter **Settings → API keys**. Der Connector tauscht diese bei jedem Sync gegen ein kurzlebiges Zugriffstoken ein; Key-ID, Secret und Token werden nie protokolliert.

#### Connector-Zuordnungen

1. Geben Sie Ihre Lacework-Konto-URL in das Feld **Location** ein — zum Beispiel `https://YOUR-ACCOUNT.lacework.net` (ein bloßer Kontoname wird ebenfalls akzeptiert).
2. Geben Sie die **API Key ID** und das **API Secret** ein.
3. Legen Sie optional einen **Minimum Severity**-Wert fest, um einzuschränken, welche Befunde importiert werden.

DefectDojo ordnet das Lacework-**Konto** einem Eintrag zu (der gesamte Konto-Geltungsbereich). Jede **Container**- und **Host**-Schwachstelle wird zu einem Befund: Der Schweregrad stammt aus Laceworks eigener Bewertung, das betroffene Paket und die Version werden zur Komponente, die Fix-Version wird zur Abhilfemaßnahme, und das betroffene Image/der betroffene Host wird als Tags erfasst. Container-Schwachstellen werden als statische Befunde erfasst (Image-Scans) und Host-Schwachstellen als dynamische Befunde (Scans laufender Hosts).

Weitere Informationen finden Sie in der [Lacework-API-Dokumentation](https://docs.lacework.net/api/v2/docs).

## **Microsoft Defender**

Der Microsoft-Defender-Connector importiert Geräte-Schwachstellenbefunde aus **Microsoft Defender Vulnerability Management (MDVM)** — einen Befund pro Kombination aus Gerät/Softwareversion/CVE, einschließlich Schweregrad, CVSS-Score, Ausnutzbarkeitsgrad und empfohlener Sicherheitsupdates. DefectDojo ermittelt Ihre Defender-**Gerätegruppen** und erstellt für jede einen Eintrag; Geräte, die keiner Gerätegruppe zugewiesen sind, werden unter einer synthetischen Gruppe **Unassigned** zusammengefasst.

**Bitte beachten Sie:** Dieser Connector unterscheidet sich vom dateibasierten Scan-Typ **„MSDefender Parser"**, der manuell exportierte Defender-Dateien importiert. Wählen Sie pro Produkt einen Importpfad, um doppelte Befunde zu vermeiden.

#### Voraussetzungen

Ihr Microsoft-Tenant benötigt eine aktive Lizenz, die die Defender-Vulnerability-Export-APIs einschließt: **Defender for Endpoint Plan 2**, **Microsoft Defender Vulnerability Management Standalone**, oder MDE P1/P2 mit dem MDVM-Add-on. (Das MDVM-*Add-on*-SKU allein reicht nicht aus — es setzt Defender for Endpoint Plan 2 voraus.)

Der Connector authentifiziert sich als Microsoft-Entra-ID-**App-Registrierung** mittels Client-Credentials-Flow. So erstellen Sie eine:

1. Öffnen Sie im [Azure-Portal](https://portal.azure.com) **App registrations \> New registration**. Benennen Sie sie (zum Beispiel `defectdojo-connector`), belassen Sie die Standardwerte, und wählen Sie **Register**.
2. Notieren Sie sich auf der **Overview**-Seite der App die **Application (client) ID** und die **Directory (tenant) ID**.
3. Öffnen Sie **API permissions \> Add a permission \> APIs my organization uses** und suchen Sie nach **WindowsDefenderATP**. Erscheint es nicht, wurde das Defender-Backend Ihres Tenants noch nicht bereitgestellt: Stellen Sie sicher, dass die Lizenz aktiv ist, öffnen Sie einmal [security.microsoft.com](https://security.microsoft.com), und versuchen Sie es nach einigen Minuten erneut.
4. Wählen Sie **Application permissions** (*nicht* Delegated — Delegated-Berechtigungen erscheinen nie im Service-Token des Connectors), erweitern Sie **Vulnerability**, markieren Sie **Vulnerability.Read.All**, und wählen Sie **Add permissions**.
5. Wählen Sie **Grant admin consent** und bestätigen Sie. Die Status-Spalte muss ein grünes Häkchen zeigen — ohne diesen Schritt liefert jeder API-Aufruf einen 403-Fehler.
6. Öffnen Sie **Certificates & secrets \> New client secret**, legen Sie ein Ablaufdatum fest, und kopieren Sie den **Value** des Secrets sofort (er wird nur einmal angezeigt). Der Connector funktioniert nicht mehr, wenn das Secret abläuft; notieren Sie sich daher das Datum.

#### Connector-Zuordnungen

1. Geben Sie `https://api.security.microsoft.com` in das Feld **Location** ein.
2. Geben Sie die **Directory (tenant) ID** in das Feld **Tenant ID** ein.
3. Geben Sie die **Application (client) ID** in das Feld **Client ID** ein.
4. Geben Sie den Wert des Client-Secrets in das Feld **Client Secret** ein.
5. Legen Sie optional einen **Minimum Severity**-Wert fest, um einzuschränken, welche Befunde importiert werden.

Jede Defender-Gerätegruppe wird zu einem Eintrag. Microsoft erneuert den vom Connector gelesenen Schwachstellen-Snapshot etwa alle 6 Stunden, und neu angebundene Geräte können bis zu ca. 24 Stunden benötigen, um ihre ersten Schwachstellendaten zu liefern — ein brandneuer Tenant wird legitim null Befunde synchronisieren, bis Geräte angebunden und bewertet wurden. Auch die Lizenzaktivierung selbst kann ca. 20 Minuten oder länger benötigen, bis sie die API erreicht (Fehler „No active license found" während dieses Zeitfensters lösen sich von selbst).

## **Microsoft Defender for Cloud**

Der Microsoft-Defender-for-Cloud-Connector importiert Schwachstellenbefunde aus **Microsoft Defender Vulnerability Management (MDVM)**, wie sie von Defender for Cloud bereitgestellt werden — sowohl **Server**-Befunde (CVEs des Betriebssystems und der installierten Software von Azure-VMs) als auch **Container-Registry**-Befunde (CVEs von Container-Images), einschließlich Schweregrad, CVSS-Score, dem betroffenen Paket oder Image und Abhilfemaßnahmen. DefectDojo ermittelt die Azure-**Subscriptions**, die Ihr Service Principal lesen kann, und erstellt für jede aktivierte Subscription einen Eintrag.

**Bitte beachten Sie:** Dieser Connector unterscheidet sich vom **Microsoft-Defender**-Connector, der Gerätebefunde aus der Defender-for-Endpoint-API importiert. Defender for Cloud ist ein Azure-Produkt mit einer anderen API-Oberfläche (Azure Resource Manager/Resource Graph) und einem anderen Berechtigungsmodell (Azure RBAC). Verwenden Sie denjenigen, der zu Ihren Befundquellen passt — oder beide, wenn Sie beide Produkte nutzen.

#### Voraussetzungen

Sie benötigen eine oder mehrere **Azure-Subscriptions mit aktiviertem Microsoft Defender for Cloud**, wobei die relevanten Defender-Pläne für die zu scannenden Ressourcen aktiviert sind (unter **Microsoft Defender for Cloud \> Environment settings**, dann Ihre Subscription auswählen):

* **Defender for Servers (Plan 2)** — CVE-Befunde zum Betriebssystem und zur Software von Azure-VMs (agentloses Vulnerability Scanning).
* **Defender for Containers** — CVE-Befunde von Container-Registry-Images.

SQL-Vulnerability-Assessment- und Konfigurations-/Posture-Befunde werden bewusst **nicht** importiert — dieser Connector importiert ausschließlich CVE-Schwachstellen.

Der Connector authentifiziert sich als Microsoft-Entra-ID-**App-Registrierung** mittels Client-Credentials-Flow:

1. Öffnen Sie im [Azure-Portal](https://portal.azure.com) **App registrations \> New registration**. Benennen Sie sie (zum Beispiel `defectdojo-connector`), belassen Sie die Standardwerte, und wählen Sie **Register**.
2. Notieren Sie sich auf der **Overview**-Seite der App die **Application (client) ID** und die **Directory (tenant) ID**.
3. Öffnen Sie **Certificates & secrets \> New client secret**, legen Sie ein Ablaufdatum fest, und kopieren Sie den **Value** des Secrets sofort (er wird nur einmal angezeigt). Der Connector funktioniert nicht mehr, wenn das Secret abläuft; notieren Sie sich daher das Datum.
4. Gewähren Sie der App Lesezugriff auf jede zu importierende Subscription: Öffnen Sie **Subscriptions**, wählen Sie Ihre Subscription, dann **Access control (IAM) \> Add \> Add role assignment**. Wählen Sie die Rolle **Security Reader** (oder **Reader**), und weisen Sie sie im Tab **Members** der von Ihnen erstellten App zu — suchen Sie sie über den **Namen** oder die **Object ID** der App, da der Picker nicht mit der Client ID abgleicht. Wiederholen Sie dies für jede Subscription.

Anders als beim gerätebasierten Microsoft-Defender-Connector sind keine API-Berechtigungen oder Admin-Consent erforderlich: Der Zugriff auf Defender for Cloud wird ausschließlich über die oben genannte Azure-RBAC-Rollenzuweisung geregelt.

#### Connector-Zuordnungen

1. Geben Sie `https://management.azure.com` in das Feld **Location** ein. (Verwenden Sie bei souveränen Clouds den passenden ARM-Endpunkt, zum Beispiel `https://management.usgovcloudapi.net`.)
2. Geben Sie die **Directory (tenant) ID** in das Feld **Tenant ID** ein.
3. Geben Sie die **Application (client) ID** in das Feld **Client ID** ein.
4. Geben Sie den Wert des Client-Secrets in das Feld **Client Secret** ein.
5. Legen Sie optional einen **Minimum Severity**-Wert fest, um einzuschränken, welche Befunde importiert werden.

Jede aktivierte Azure-Subscription wird zu einem Eintrag. Befunde werden über Azure Resource Graph gelesen, sodass sie zügig sichtbar werden, sobald Defender for Cloud Ihre Ressourcen gescannt hat — die Scans selbst laufen jedoch nach dem Zeitplan von Microsoft: Container-Registry-Images werden meist innerhalb einer Stunde nach dem Push gescannt, während der erste agentlose Schwachstellen-Scan einer VM mehrere Stunden dauern kann. Eine neu aktivierte Subscription wird legitim null Befunde synchronisieren, bis ihre Ressourcen gescannt wurden.

## **MobSF**

Der MobSF-Connector verwendet die REST-API des [Mobile Security Framework (MobSF)](https://github.com/MobSF/Mobile-Security-Framework-MobSF), um statische Analyseergebnisse mobiler Anwendungen (APK/IPA) zu importieren. DefectDojo ermittelt jede App, die auf Ihrer MobSF-Instanz gescannt wurde, und erstellt für jede einen Eintrag; anschließend werden die statischen Analysebefunde dieser App importiert.

#### Voraussetzungen

Sie benötigen Ihren MobSF-**REST-API-Schlüssel**. Sie finden ihn auf der MobSF-Startseite unter **API** (in der MobSF-Dokumentation auch als `Authorization`-Wert angezeigt). Der Schlüssel wird bei jeder Anfrage gesendet und nie protokolliert.

#### Connector-Zuordnungen

1. Geben Sie Ihre MobSF-Basis-URL in das Feld **Location** ein (zum Beispiel `https://mobsf.example.com`).
2. Geben Sie im Feld **Secret** den MobSF-REST-API-Schlüssel ein.
3. Legen Sie optional einen **Minimum Severity**-Wert fest, um einzuschränken, welche Befunde importiert werden.

DefectDojo ordnet jede gescannte **App** einem Eintrag zu und importiert deren Befunde aus dem MobSF-JSON-Bericht über mehrere Abschnitte hinweg — Anwendungsberechtigungen, Code-Analyse, das Signaturzertifikat, das Android-Manifest, Android-API-Nutzung und Binäranalyse. Jeder Befund wird mit **CWE 919** (mobil) getaggt, und sein Schweregrad stammt aus MobSFs eigener Bewertung (high, warning, info, secure/good) — eine *gefährliche* Berechtigung wird als High behandelt. Befunde werden als statische Befunde erfasst und anhand von Scan, Abschnitt, Titel, Schweregrad und Dateipfad dedupliziert.

Weitere Informationen finden Sie in der [MobSF-REST-API-Dokumentation](https://mobsf.github.io/docs/#/rest_api).

## **NeuVector**

Der NeuVector-Connector verwendet die Controller-REST-API von [NeuVector](https://github.com/neuvector/neuvector), um Container-**Image-Schwachstellen-Scans** zu importieren. DefectDojo ermittelt jedes von NeuVector gescannte Image und erstellt für jedes einen Eintrag; anschließend wird der Scan-Bericht dieses Images als Befunde importiert.

#### Voraussetzungen

Sie benötigen einen NeuVector-**Benutzernamen und ein Passwort** für ein Controller-Konto mit Berechtigung, Scan-Ergebnisse zu lesen. Der Connector meldet sich mit diesen Anmeldedaten an, um ein Session-Token zu erhalten; das Passwort und das Token werden nie protokolliert.

#### Connector-Zuordnungen

1. Geben Sie Ihre NeuVector-Controller-URL einschließlich des REST-API-Ports in das Feld **Location** ein — zum Beispiel `https://neuvector.example.com:10443`.
2. Geben Sie den Controller-**Username** und das **Password** ein.
3. Wenn Ihr Controller ein selbstsigniertes Zertifikat verwendet, setzen Sie **Skip TLS Verification** auf `true`.
4. Legen Sie optional einen **Minimum Severity**-Wert fest, um einzuschränken, welche Befunde importiert werden.

DefectDojo ordnet jedes gescannte **Image** einem Eintrag zu und jede **CVE** in dessen Scan-Bericht einem Befund. Der Schweregrad stammt aus NeuVectors eigener Bewertung, und das betroffene Paket und die Version, der CVSSv3-Score und -Vektor, die Fix-Version (als Abhilfemaßnahme) sowie ein Referenzlink werden übernommen. Befunde werden anhand von Image, CVE, Paket, Version und Schweregrad dedupliziert.

Weitere Informationen finden Sie in der [NeuVector-API-Dokumentation](https://open-docs.neuvector.com/automation/automation).

## **Nuclei (ProjectDiscovery Cloud)**

Der Nuclei-Connector verwendet die REST-API der ProjectDiscovery Cloud Platform (PDCP), um [nuclei](https://github.com/projectdiscovery/nuclei)-Scan-Ergebnisse aus Ihrem PDCP-Konto abzurufen. DefectDojo ermittelt jeden Scan im Konto und erstellt für jeden **Scan** einen separaten Eintrag.

#### Voraussetzungen

Sie benötigen einen ProjectDiscovery-Cloud-**API-Schlüssel**. Wir empfehlen, für DefectDojo ein dediziertes Service-Konto anzulegen, um automatisierte Aktivitäten klar von manuellen Team-Aktionen zu unterscheiden. Generieren Sie einen Schlüssel unter **Settings \> API Key** in der ProjectDiscovery-Cloud-Oberfläche ([cloud.projectdiscovery.io](https://cloud.projectdiscovery.io)). Ergebnisse gelangen entweder über gehostete Scans oder über die mit `-dashboard` ausgeführte nuclei-CLI zu PDCP.

#### Connector-Zuordnungen

1. Geben Sie die Basis-URL der PDCP-API in das Feld **Location** ein: `https://api.projectdiscovery.io`.
2. Geben Sie Ihren **API-Schlüssel** in das Feld **Secret** ein.
3. Geben Sie optional eine **Team ID** ein, um den Sync auf einen Team-Workspace zu beschränken (zu finden unter **Settings \> Team**). Bleibt das Feld leer, synchronisiert DefectDojo Ihren persönlichen Workspace.
4. Legen Sie optional einen **Minimum Severity**-Wert fest, um einzuschränken, welche Befunde importiert werden.

DefectDojo ordnet jeden PDCP-**Scan** als separaten Eintrag zu und importiert dessen Befunde über alle Schweregrade hinweg, einschließlich informativer.

## **OpenVAS / Greenbone**

Der OpenVAS-/Greenbone-Connector importiert **Netzwerk-Schwachstellenbefunde** aus einer Greenbone-Instanz (Greenbone Community Edition oder Greenbone Enterprise). Er kommuniziert mit `gvmd` über **GMP (Greenbone Management Protocol)** — ein XML-Protokoll über ein TLS-Socket, nicht HTTP — und synchronisiert die gesamte Instanz: Er zählt Scan-**Tasks** auf und erstellt für jeden ein DefectDojo-Produkt, wobei die Ergebnisse des jeweils letzten Berichts jedes Tasks importiert werden.

#### Voraussetzungen

Ein Greenbone-**GMP-Benutzer** (Benutzername + Passwort) und Netzwerkzugriff auf den GMP-TLS-Port von gvmd (standardmäßig **9390**). Der Compose-Stack der Greenbone Community Edition stellt gvmd über einen Unix-Socket bereit; um ihn von einem vernetzten Connector aus zu erreichen, betreiben Sie den Connector entweder dort, wo er den Socket erreichen kann, oder exponieren Sie den GMP-TLS-Port (zum Beispiel eine `socat`-TLS-Bridge zu `gvmd.sock`).

#### Connector-Zuordnungen

1. Geben Sie den gvmd-Host in das Feld **Location** ein (Host oder `host:port`).
2. Geben Sie den GMP-**Username** und das **Password** ein.
3. Legen Sie optional den **GMP Port** fest (Standard 9390).
4. Für das standardmäßige selbstsignierte Zertifikat von gvmd geben Sie entweder ein **CA Certificate (PEM)** zur Verifizierung an, oder setzen Sie **Skip TLS Verification** auf `true`.
5. Legen Sie optional einen **Minimum Severity**-Wert fest, um einzuschränken, welche Befunde importiert werden.

Jeder Greenbone-Task wird zu einem Eintrag. Befunde stammen aus dem letzten abgeschlossenen Bericht des Tasks — einer pro `<result>`. Der Schweregrad wird der Threat-Level-Angabe des Ergebnisses entnommen (Greenbones informative Stufen `Log`/`Debug` werden auf Info abgebildet), wobei der numerische CVSS-Score erfasst wird; CVE-Referenzen werden zu Schwachstellen-IDs, die NVT-Lösung wird zur Abhilfemaßnahme, und Host/Port jedes Ergebnisses werden zu einem Endpunkt.

## Probely

Dieser Connector verwendet die Probely-REST-API, um Daten abzurufen.

​**Connector-Zuordnungen**

1. Geben Sie die passende API-Server-Adresse in das Feld **Location** ein. (entweder <https://api.us.probely.com/> oder <https://api.eu.probely.com/>)
2. Geben Sie einen gültigen API-Schlüssel in das Feld **Secret** ein.

Einen API-Schlüssel finden Sie in Probely unter dem Menü User \> API Keys.  
Weitere Informationen finden Sie in der [Probely-Dokumentation](https://help.probely.com/en/articles/8592281-how-to-generate-an-api-key).

## Prowler

Der Prowler-Connector verwendet die **Prowler-App**-REST-API, um Cloud-Security-Posture(CSPM)-Befunde von einer selbstgehosteten Prowler-App-Instanz zu importieren. DefectDojo ermittelt jeden Prowler-**Provider** (Cloud-Konto) als Eintrag und importiert die **FAIL**-Befunde des letzten abgeschlossenen Scans dieses Providers.

#### Voraussetzungen

Sie benötigen eine laufende, selbstgehostete **Prowler-App**-Instanz sowie entweder eine Benutzer-E-Mail-Adresse + ein Passwort (für JWT-Authentifizierung) oder einen Prowler-App-**API-Schlüssel**. Befunde erscheinen erst, sobald Sie ein Cloud-Konto (AWS, GCP, Azure, Kubernetes, ...) in der Prowler-App verbunden und einen Scan ausgeführt haben.

#### Connector-Zuordnungen

1. Geben Sie Ihre Prowler-App-URL in das Feld **Location** ein (zum Beispiel `https://prowler.your-company.com`).
2. Geben Sie für die JWT-Authentifizierung die **Email** und das **Password** des Prowler-App-Benutzers ein. Alternativ lassen Sie diese leer und geben einen Prowler-App-**API-Schlüssel** ein. Sind beide angegeben, wird E-Mail/Passwort (JWT) verwendet.
3. Legen Sie optional einen **Minimum Severity**-Wert fest, um einzuschränken, welche Befunde importiert werden. Befunde unterhalb des gewählten Schweregrads werden nicht importiert.

DefectDojo erstellt für jeden Prowler-Provider einen Eintrag und importiert die FAIL-Befunde von dessen letztem abgeschlossenem Scan, wobei Prowler-Schweregrade auf DefectDojo-Schweregrade abgebildet werden, die betroffene Cloud-Ressource (ARN/Ressourcen-ID) zur Komponente wird und die Abhilfemaßnahme sowie das Risiko der Prüfung in den Befund übernommen werden. Stummgeschaltete Befunde werden übersprungen. Cloud-Konto, Region und Dienst werden als Tags angehängt.

Weitere Informationen finden Sie in der **[Prowler-App-API-Dokumentation](https://api.prowler.com/api/v1/docs)**.

## Qualys

Der Qualys-Connector importiert **VMDR-Host-Schwachstellendetektionen** — jeweils verknüpft mit den Metadaten der Qualys-KnowledgeBase (QID) — von der Qualys Cloud Platform. DefectDojo erstellt für jeden Qualys-**Host** in Ihrer Subscription einen Eintrag.

#### Voraussetzungen

Ein Qualys-Benutzerkonto mit **VMDR-API-Zugriff** sowie die **API-Server(Platform)-URL** Ihrer Subscription — diese unterscheidet sich je nach Subscription. Sie finden sie in der Qualys-Oberfläche unter **Help \> About** oder auf der Qualys-Seite [Platform Identification](https://www.qualys.com/platform-identification/) (zum Beispiel `https://qualysapi.qualys.com` für US Platform 1, oder `https://qualysapi.qg2.apps.qualys.com` für US Platform 2).

#### Connector-Zuordnungen

1. Geben Sie Ihre Qualys-API-Server-URL in das Feld **Location** ein (zum Beispiel `https://qualysapi.qualys.com`).
2. Geben Sie den Qualys-API-Benutzernamen in das Feld **Username** ein.
3. Geben Sie das Qualys-API-Passwort in das Feld **Secret** ein.
4. Legen Sie optional einen **Minimum Severity**-Wert fest, um einzuschränken, welche Befunde importiert werden.

Jeder Qualys-Host wird zu einem Eintrag. Detektionen, die Qualys als **Fixed** markiert hat, werden ausgeschlossen, sodass ein erneuter Import behobene Befunde schließt.

## **Quay**

Der Quay-Connector verwendet die Project-Quay-REST-API, um Container-Repositories zu ermitteln und die von Quays integriertem **Clair**-Scanner erzeugten Schwachstellenberichte zu importieren. DefectDojo erstellt für jedes Quay-**Repository** einen Eintrag und liest bei jedem Sync den Clair-Sicherheitsbericht des Image-Manifests jedes aktiven Tags.

#### Voraussetzungen

Security Scanning (Clair) muss auf Ihrer Quay-Instanz aktiviert sein, und Sie benötigen ein Quay-**OAuth-2-Zugriffstoken**:

* Erstellen (oder öffnen) Sie in Quay eine Organisation, gehen Sie zu **Applications**, erstellen Sie eine OAuth-Anwendung, und dann **Generate Token** mit mindestens dem Scope **Read repositories**. Eine dedizierte Anwendung für DefectDojo wird empfohlen.
* Das Token wird bei jeder Anfrage als Bearer-Token gesendet und nie protokolliert.

#### Connector-Zuordnungen

1. Geben Sie Ihre Quay-Basis-URL in das Feld **Location** ein, zum Beispiel `https://quay.io` oder Ihr selbstgehostetes `https://quay.example.com`. Die URL muss HTTPS verwenden; geben Sie keinen abschließenden API-Pfad an — DefectDojo erstellt die API-Pfade automatisch.
2. Geben Sie das OAuth-Zugriffstoken in das Feld **Secret** ein.
3. Legen Sie optional einen **Namespace** fest, um die Ermittlung auf eine einzelne Quay-Organisation oder einen Benutzer zu beschränken. Leer lassen, um jedes Repository zu ermitteln, das das Token lesen kann.
4. Legen Sie optional einen **Minimum Severity**-Wert fest, um einzuschränken, welche Befunde importiert werden.

DefectDojo ordnet jedes Quay-**Repository** einem Eintrag zu. Für jedes Repository listet es die aktiven Tags auf, dedupliziert sie zu ihren eindeutigen Image-Manifesten (ein von mehreren Tags gemeinsam genutztes Manifest wird einmal gescannt) und liest den Clair-Bericht jedes Manifests. Manifeste, deren Scan Clair noch nicht abgeschlossen hat (zum Beispiel eine Multi-Architektur-Manifestliste oder ein noch in der Warteschlange befindliches Image), werden bis zu einem späteren Sync übersprungen. Jede Clair-Schwachstelle wird zu einem Befund — das betroffene Paket ist die Komponente, die Fix-Version wird zur Abhilfemaßnahme, und Clairs Schweregrade **Negligible**/**Unknown** werden als **Informational** erfasst.

Weitere Informationen finden Sie in der [Project-Quay-API-Dokumentation](https://docs.projectquay.io/api_quay.html) und der [Clair-Dokumentation](https://quay.github.io/clair/).

## **Rapid7 InsightAppSec**

Der Rapid7-InsightAppSec-Connector importiert **DAST-Schwachstellenbefunde** von der InsightAppSec-Cloud-Plattform, angereichert mit Attack-Module-Metadaten (zum Beispiel *SQL Injection*), CVSS-Scores und den vom Scan gesammelten Nachweisen. DefectDojo erstellt für jede InsightAppSec-**App** einen Eintrag.

**Bitte beachten Sie:** Dieser Connector unterscheidet sich vom **Rapid7-InsightVM**-Connector weiter unten — InsightAppSec ist Rapid7s Cloud-DAST-Produkt auf der Insight-Plattform, während InsightVM-Befunde aus Ihrer eigenen Security Console stammen.

#### Voraussetzungen

Ein Insight-Platform-Konto mit InsightAppSec sowie ein Platform-**API-Schlüssel**: Öffnen Sie in der [Rapid7-Insight-Plattform](https://insight.rapid7.com) das Einstellungsmenü (Zahnrad) \> **API Keys** und generieren Sie einen **User Key** (beliebige Rolle) oder einen **Organization Key** (Platform-Admins). Kopieren Sie den Schlüssel, wenn er angezeigt wird — er wird nur einmal angezeigt.

Sie benötigen außerdem Ihre Platform-**Region**, sichtbar in Ihrer Insight-URL (zum Beispiel `us`, `us2`, `us3`, `eu`, `ca`, `au` oder `ap`).

#### Connector-Zuordnungen

1. Geben Sie Ihren regionalen API-Endpunkt in das Feld **Location** ein — zum Beispiel `https://us.api.insight.rapid7.com` (ersetzen Sie `us` durch Ihre Region).
2. Geben Sie den API-Schlüssel der Insight-Plattform in das Feld **API Key** ein.
3. Legen Sie optional einen **Minimum Severity**-Wert fest, um einzuschränken, welche Befunde importiert werden.

Jede InsightAppSec-App wird zu einem Eintrag. Es werden nur **offene** Schwachstellen (Unreviewed oder Verified) importiert — Befunde, die Rapid7 als Remediated, False Positive, Ignored oder Duplicate markiert hat, werden ausgeschlossen, sodass ein erneuter Import sie in DefectDojo schließt. Schweregrade werden direkt abgebildet (`SAFE` und `INFORMATIONAL` werden als Info importiert).

## **Rapid7 InsightVM**

Der Rapid7-InsightVM-Connector importiert Asset-Schwachstellenbefunde aus Ihrer InsightVM-**Security Console** (API v3), angereichert mit dem globalen Schwachstellenkatalog der Console. DefectDojo erstellt für jede InsightVM-**Site** einen Eintrag.

#### Voraussetzungen

Netzwerkzugriff von DefectDojo auf Ihre Security Console sowie ein **Benutzerkonto** der Console — dessen Login wird für die HTTP-Basic-Authentifizierung verwendet. Die Console-API wird standardmäßig auf Port **3780** bereitgestellt.

#### Connector-Zuordnungen

1. Geben Sie die URL Ihrer Security Console einschließlich des Ports in das Feld **Location** ein — zum Beispiel `https://console.example.com:3780`.
2. Geben Sie den Console-Benutzernamen in das Feld **Username** ein.
3. Geben Sie das Console-Passwort in das Feld **Secret** ein.
4. Legen Sie optional einen **Minimum Severity**-Wert fest, um einzuschränken, welche Befunde importiert werden.

Jede InsightVM-Site wird zu einem Eintrag; der Connector durchläuft die Assets der Site und importiert deren anfällige Befunde.

## **runZero**

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

## **Semgrep**

Dieser Connector verwendet die Semgrep-REST-API, um Daten abzurufen.

#### Connector-Zuordnungen

Geben Sie `https://semgrep.dev/api/v1/` in das Feld **Location** ein.

1. Geben Sie einen gültigen API-Schlüssel in das Feld **Secret** ein. Sie finden diesen auf der Tokens-Seite:   
​  
„Settings" in der linken Navigationsleiste \> Tokens \> Create new token ([https://semgrep.dev/orgs/\-/settings/tokens](https://semgrep.dev/orgs/-/settings/tokens))

Weitere Informationen finden Sie in der [Semgrep-Dokumentation](https://semgrep.dev/docs/semgrep-cloud-platform/semgrep-api/#tag__badge-list).

## **ServiceNow CMDB**

Der ServiceNow-CMDB-Connector ist ein **Asset-Connector**: Anstatt Befunde zu importieren, liest er Configuration Items (CIs) aus Ihrer ServiceNow Configuration Management Database und erstellt für jede CI ein DefectDojo-Asset, gruppiert in Organisationen nach CI-Klasse. Es werden keine Befunde importiert.

#### Voraussetzungen

Sie benötigen eine ServiceNow-Instanz und ein Konto, das die CMDB-Tabellen über die ServiceNow-Table-API lesen kann. Wir empfehlen ein dediziertes, schreibgeschütztes Service-Konto für DefectDojo. Das Konto benötigt Lesezugriff auf die zu importierenden `cmdb_ci`-Tabellen.

#### Connector-Zuordnungen

1. Geben Sie die URL Ihrer ServiceNow-Instanz in das Feld **Location** ein: `https://{your-instance}.service-now.com`.
2. Wählen oder erstellen Sie eine ServiceNow-**Tool Configuration**, die die Instanz-Anmeldedaten enthält (den ServiceNow-Benutzernamen und das Passwort).

Jedes Configuration Item wird zu einem nach der CI benannten Eintrag, gruppiert nach seiner **CI-Klasse** (zum Beispiel Application, Server oder Business Service). Discovery und Sync gleichen die CI-Liste ab: Neue CIs erscheinen als `NEW`-Einträge, und eine aus der CMDB entfernte CI wird beim nächsten Sync als `MISSING` markiert, damit Ihr Team sie prüfen kann. DefectDojo löscht niemals stillschweigend ein Produkt.

## **Shodan**

Der Shodan-Connector verwendet die Shodan-REST-API, um die von Shodan auf Ihren im Internet exponierten Hosts beobachteten Schwachstellen (CVEs) zu importieren. Sie geben eine Shodan-Suchanfrage an, die den Import auf Ihre eigenen Assets beschränkt; DefectDojo erstellt für jeden passenden Host einen Eintrag und importiert dessen CVEs als Befunde.

#### Voraussetzungen

Sie benötigen einen Shodan-API-Schlüssel, den Sie auf Ihrer Shodan-**Account**-Seite finden. Die Host-Suche mit Schwachstellendaten erfordert eine Shodan-Mitgliedschaft oder einen kostenpflichtigen API-Plan — die kostenlose Stufe kann Suchergebnisse nicht seitenweise durchblättern.

#### Connector-Zuordnungen

1. Geben Sie `https://api.shodan.io` in das Feld **Location** ein.
2. Geben Sie Ihren Shodan-API-Schlüssel in das Feld **API Key** ein.
3. Geben Sie im Feld **Search Query** eine Shodan-Abfrage ein, die den Import auf die Assets Ihrer Organisation beschränkt — zum Beispiel `hostname:example.com`, `net:203.0.113.0/24` oder `org:"Example Inc"`. Es werden nur Hosts importiert, die dieser Abfrage entsprechen; beschränken Sie sie daher auf Infrastruktur, die Ihnen gehört.
4. Legen Sie optional einen **Minimum Severity**-Wert fest, um einzuschränken, welche Befunde importiert werden.

Jeder passende Host wird zu einem Eintrag, und jede von Shodan auf den exponierten Diensten dieses Hosts erkannte CVE wird als Befund importiert — der Schweregrad wird aus dem CVSS-Score abgeleitet, wobei EPSS- und CISA-KEV-Kontext einbezogen wird, sofern verfügbar. Jede Seite der Suchergebnisse verbraucht ein Shodan-Abfrage-Guthaben.

## SonarQube

Der SonarQube-Connector kann Daten entweder von einem SonarCloud-Konto oder von einer lokalen SonarQube-Instanz abrufen.

**Für SonarCloud-Benutzer:**

1. Geben Sie https://sonarcloud.io/ in das Feld Location ein.
2. Geben Sie einen gültigen **API-Schlüssel** in das Feld Secret ein.

**Für SonarQube-Benutzer (On-Premise):**

1. Geben Sie die Basis-URL Ihrer SonarQube-Instanz in das Feld Location ein: zum Beispiel `https://my.sonarqube.com/`
2. Geben Sie einen gültigen **API-Schlüssel** in das Feld Secret ein. Dies muss ein **[User](https://docs.sonarsource.com/sonarqube/latest/user-guide/user-account/generating-and-using-tokens/)**-[API-Token-Typ](https://docs.sonarsource.com/sonarqube/latest/user-guide/user-account/generating-and-using-tokens/) sein.

Das Token benötigt Zugriff auf Projects, Vulnerabilities und Hotspots innerhalb von Sonar.

API-Tokens finden und generieren Sie über **My Account \-\> Security \-\> Generate Token** in der SonarQube-App. Weitere Informationen finden Sie in der [SonarQube-Dokumentation](https://docs.sonarsource.com/sonarqube/latest/user-guide/user-account/generating-and-using-tokens/).

## **Snyk**

Der Snyk-Connector verwendet die Snyk-REST-API, um Daten abzurufen.

#### Connector-Zuordnungen

1. Geben Sie **[https://api.snyk.io/rest](https://api.snyk.io/v1)** oder **[https://api.eu.snyk.io/rest](https://api.eu.snyk.io/v1)** (für eine regionale EU-Bereitstellung) in das Feld **Location** ein.
2. Geben Sie einen gültigen API-Schlüssel in das Feld **Secret** ein. API-Tokens finden Sie auf der **[Account-Settings](https://docs.snyk.io/getting-started/how-to-obtain-and-authenticate-with-your-snyk-api-token)**-[Seite](https://docs.snyk.io/getting-started/how-to-obtain-and-authenticate-with-your-snyk-api-token) eines Benutzers in Snyk.

Weitere Informationen finden Sie in der [Snyk-API-Dokumentation](https://docs.snyk.io/snyk-api).

## **Socket**

Der Socket-Connector verwendet die API von [Socket.dev](https://socket.dev), um **Software-Supply-Chain-Befunde** zu importieren — Sockets Warnungen zu Ihren Abhängigkeiten (Malware, Typosquats, Install-Skripte, bekannte Schwachstellen und über 70 weitere Kategorien). DefectDojo ermittelt jedes Repository in den Organisationen, auf die Ihr Token zugreifen kann, und erstellt für jedes einen Eintrag; anschließend werden die Warnungen aus dem letzten vollständigen Scan dieses Repositorys importiert.

#### Voraussetzungen

Sie benötigen ein Socket-**API-Token** — ein Organisations-Token, das im Socket-Dashboard unter **Settings → API Tokens** erstellt wird (mit den Scopes `repo:list` und Full-Scan-Lesezugriff). Das Token wird als Bearer-Token gesendet und nie protokolliert.

#### Connector-Zuordnungen

1. Behalten Sie den vorgegebenen Wert im Feld **Location**, `https://api.socket.dev/v0`, oder geben Sie es explizit an.
2. Geben Sie das Socket-API-Token in das Feld **Secret** ein.
3. Legen Sie optional einen **Minimum Severity**-Wert fest, um einzuschränken, welche Befunde importiert werden.

DefectDojo ordnet jedes **Repository** einem Eintrag zu und importiert die Warnungen aus dessen letztem vollständigen Scan. Jede Warnung wird zu einem Befund: Der Schweregrad stammt aus Sockets eigener Bewertung (low, medium, high, critical), das betroffene Paket wird zur Komponente und zu einer PURL, die Warnungskategorie (Supply-Chain-Risiko, Qualität, Wartung, Schwachstelle, Lizenz) wird als Tags erfasst, und die Warnungsdetails werden in die Beschreibung übernommen. Befunde werden als statische Befunde erfasst und anhand des Socket-Warnungsschlüssels dedupliziert.

Weitere Informationen finden Sie in der [Socket-API-Dokumentation](https://docs.socket.dev/reference).

## **Sonatype IQ**

Der Sonatype-IQ-Connector verwendet die REST-API des Sonatype-IQ-Servers (Nexus Lifecycle), um Open-Source-Komponentenschwachstellen zu importieren. Er zählt jede Anwendung in Ihrer IQ-Organisation auf und importiert für jede die Komponentenschwachstellen aus dem letzten Bericht dieser Anwendung auf der von Ihnen konfigurierten Lifecycle-Stufe. DefectDojo erstellt automatisch für jede Anwendung einen Eintrag — es gibt keine Pro-Anwendungs-Konfiguration.

#### Voraussetzungen

Sie benötigen ein Sonatype-IQ-Benutzerkonto mit der Berechtigung **View IQ Elements** für die zu importierenden Anwendungen. Sonatype empfiehlt die Authentifizierung mit einem **User Token** (generiert unter **My Profile > User Token** im IQ Server) statt eines Passworts; die beiden Teile des Tokens werden unten den Feldern Username und User Token zugeordnet. Der Connector funktioniert sowohl mit selbstgehostetem IQ Server als auch mit von Sonatype gehosteten (SaaS-)Instanzen.

#### Connector-Zuordnungen

1. Geben Sie im Feld **Location** die Basis-URL Ihres IQ-Servers ein — für einen selbstgehosteten Server `https://iq.example.com`; für eine von Sonatype gehostete Instanz `https://<tenant>.sonatype.app/platform`.
2. Geben Sie den IQ-Benutzer (oder den User-Code-Teil Ihres User Tokens) in das Feld **Username** ein.
3. Geben Sie das IQ-User-Token (oder das Passwort) in das Feld **User Token** ein.
4. Legen Sie optional eine **Stage** fest, um zu wählen, dessen Bericht pro Anwendung importiert wird (`build`, `stage-release`, `release` usw.). Leer lassen, um `build` zu verwenden.
5. Legen Sie optional einen **Minimum Severity**-Wert fest, um einzuschränken, welche Befunde importiert werden.

Jede Anwendung wird zu einem Eintrag, und jedes Sicherheitsproblem im letzten Bericht dieser Anwendung für die gewählte Stufe wird als Befund importiert. Der Schweregrad wird aus dem numerischen Score des Issues abgeleitet, und CVE-Referenzen, die CWE, der CVSS-Vektor sowie die Package-URL (PURL) der betroffenen Komponente werden einbezogen, sofern verfügbar.
## **Sysdig Secure**

Der Sysdig-Secure-Connector importiert **Container-/CNAPP-Schwachstellenbefunde** über die Vulnerability-Management-API von Sysdig Secure. Er synchronisiert das gesamte Konto über die konfigurierten Geltungsbereich(e) und erstellt für jede gescannte Asset-Gruppierung ein DefectDojo-Produkt.

#### Voraussetzungen

Ein Sysdig-Secure-**API-Token**: Gehen Sie in Sysdig Secure zu **Settings \> Sysdig Secure API Token** und kopieren Sie das Token. Sie benötigen außerdem Ihre Sysdig-**Region-URL** (zum Beispiel `https://us2.app.sysdig.com`, `https://eu1.app.sysdig.com`, oder Ihren On-Premises-Host).

#### Connector-Zuordnungen

1. Geben Sie Ihre Sysdig-Region-/Basis-URL in das Feld **Location** ein.
2. Geben Sie das API-Token in das Feld **Secret** ein.
3. Legen Sie optional **Scopes** fest — eine kommagetrennte Liste aus `runtime`, `registry` und/oder `pipeline` (leer lassen für `runtime`, den Geltungsbereich bereitgestellter Workloads).
4. Legen Sie optional **Runtime Product Grouping** fest — wie Runtime-Ergebnisse auf Produkte abgebildet werden: `cluster`, `namespace`, `workload` oder `image` (leer lassen für `namespace`). Registry- und Pipeline-Ergebnisse werden immer nach Image-Repository gruppiert.
5. Legen Sie optional einen **Minimum Severity**-Wert fest, um einzuschränken, welche Befunde importiert werden.

Jede Asset-Gruppierung wird zu einem Eintrag. Für jedes Scan-Ergebnis importiert der Connector jedes anfällige Paket als Befund. **Runtime**-Befunde (bereitgestellte Workloads) werden als dynamische Befunde erfasst und mit ihrem Kubernetes-Kontext (Cluster/Namespace/Workload/Container) getaggt; **Registry**- und **Pipeline**-Befunde werden als statische Image-Scan-Befunde erfasst. Sysdigs Schweregrad `NEGLIGIBLE` wird auf Info abgebildet.

## Tenable

Der Tenable-Connector verwendet die **Tenable.io**-REST-API, um Daten abzurufen. Scans werden vom Tenable-VM-Endpunkt `/scans` abgerufen.

On-Premise-Tenable-Connectors sind derzeit nicht verfügbar.

#### **Connector-Zuordnungen**

1. Geben Sie <https://cloud.tenable.com> in das Feld Location ein.
2. Geben Sie einen gültigen **API-Schlüssel** in das Feld Secret ein.

Weitere Informationen finden Sie in der [Tenable-API-Dokumentation](https://docs.tenable.com/vulnerability-management/Content/Settings/my-account/GenerateAPIKey.htm).

## **Tenable Web App Scanning**

Der Tenable-Web-App-Scanning-Connector importiert **Web-Anwendungs(DAST)-Befunde** von Tenable Web App Scanning. Es handelt sich um einen separaten Connector zu Tenable (Vulnerability Management): Die beiden Produkte decken unterschiedliche Assets ab und werden unabhängig voneinander konfiguriert, sodass Sie entweder eines oder beide verwenden können.

DefectDojo erstellt für jede **gescannte Web-Anwendung** einen Eintrag. Anwendungen werden aus Ihren Web-App-Scanning-Scan-Konfigurationen ermittelt; eine Konfiguration, die nie ausgeführt wurde, erzeugt erst nach ihrem ersten abgeschlossenen Scan einen Eintrag. Scannen mehrere Konfigurationen dieselbe Anwendung, teilen sie sich einen einzigen Eintrag.

#### Voraussetzungen

Tenable-**API-Schlüssel** (ein Access Key und ein Secret Key) für einen Benutzer mit Web-App-Scanning-Berechtigungen. Generieren Sie diese in Tenable unter **My Account \> API Keys**, und stellen Sie sicher, dass der Benutzer die zu importierenden Scans sehen kann — auf Vulnerability Management beschränkte Schlüssel können keine Web-App-Scanning-Daten lesen.

On-Premise-Tenable-Connectors sind derzeit nicht verfügbar.

#### Connector-Zuordnungen

1. Geben Sie <https://cloud.tenable.com> in das Feld **Location** ein.
2. Geben Sie Ihren **Access Key** und **Secret Key** ein.
3. Legen Sie optional einen **Minimum Severity**-Wert fest, um einzuschränken, welche Befunde importiert werden.

Befunde werden mit dem Schweregrad importiert, den Tenable für Ihr Konto meldet, einschließlich jeder von Ihrem Team neu eingestuften Bewertung. Jeder Befund enthält die betroffene URL als Endpunkt, den Request-Parameter und die Payload, die ihn ausgelöst haben, sowie Tenables Nachweis und Ausgabe als Schritte zur Reproduktion, zusammen mit CWE-, CVE-, CVSS- und EPSS-Werten, sofern das erkennende Plugin diese liefert.

Es werden nur derzeit offene oder wiedereröffnete Befunde importiert. Ein von Tenable als behoben markierter Befund wird beim nächsten Sync in DefectDojo geschlossen.

## **Veracode**

Der Veracode-Connector importiert Anwendungsbefunde von der Veracode-Plattform, aufgeteilt nach Scan-Typ in die Befundtypen **SAST**, **DAST**, **SCA** und **Manual**. DefectDojo erstellt für jede Veracode-**Anwendung** einen Eintrag.

#### Voraussetzungen

Generieren Sie eine Veracode-**API-Anmeldeinformation** für ein Konto, das die zu importierenden Anwendungen sehen kann: Öffnen Sie in der Veracode-Plattform Ihr Kontomenü \> **API Credentials** und wählen Sie **Generate API Credentials** (siehe [Managing Veracode API credentials](https://docs.veracode.com/r/c_api_credentials3)). Kopieren Sie sowohl die **API ID** als auch den **API Secret Key** — das Secret wird nur einmal angezeigt.

#### Connector-Zuordnungen

1. Geben Sie die Basis-URL der Veracode-API in das Feld **Location** ein: `https://api.veracode.com` (kommerzielle Region), `https://api.veracode.eu` (europäische Region) oder `https://api.veracode.us` (US-Bundesregion).
2. Geben Sie die API ID in das Feld **API ID** ein.
3. Geben Sie den API Secret Key in das Feld **Secret** ein.
4. Legen Sie optional einen **Minimum Severity**-Wert fest, um einzuschränken, welche Befunde importiert werden.

Jede Veracode-Anwendung wird zu einem Eintrag. Es werden nur **offene** Befunde importiert, sodass ein erneuter Import von Veracode als behoben gemeldete Befunde schließt.

## **Wazuh**

Der Wazuh-Connector verwendet den Wazuh Indexer (OpenSearch), um Schwachstellenbefunde abzurufen. Wazuh 4.8 und später speichern erkannte CVEs im Indexer statt in der Wazuh-Server-API, daher liest dieser Connector sie direkt aus dem Index `wazuh-states-vulnerabilities-*`.

DefectDojo erstellt für jeden Wazuh-Agenten (Endpunkt) einen Eintrag und importiert die von diesem Agenten erkannten CVEs geplant als Befunde.

#### Voraussetzungen

Sie benötigen:

* Die Basis-URL Ihres Wazuh Indexer einschließlich des Ports (der Indexer lauscht standardmäßig auf Port 9200). DefectDojo verbindet sich direkt mit dem Indexer, dieser Endpunkt muss daher von DefectDojo aus erreichbar sein. Bei selbstverwalteten Bereitstellungen ist dies der Host, auf dem der Wazuh Indexer läuft. Verwenden Sie bei Wazuh Cloud den in Ihrer Wazuh-Cloud-Konsole angezeigten Indexer-Endpunkt, der sich von der Wazuh-Dashboard-URL unterscheidet.
* Einen Indexer-Benutzer und ein Passwort mit Lesezugriff auf den Index `wazuh-states-vulnerabilities-*`. Wir empfehlen, für DefectDojo einen dedizierten Benutzer anzulegen.

Die Schwachstellenerkennung muss in Wazuh aktiviert sein, damit der Vulnerability-State-Index befüllt wird. Weitere Informationen finden Sie in der [Wazuh-Dokumentation zur Schwachstellenerkennung](https://documentation.wazuh.com/current/user-manual/capabilities/vulnerability-detection/index.html).

#### Connector-Zuordnungen

1. Geben Sie die Basis-URL Ihres Wazuh Indexer einschließlich Schema und Port in das Feld **Location** ein, zum Beispiel `https://your-indexer.example.com:9200`. Geben Sie keinen abschließenden Pfad an. DefectDojo erstellt die Suchpfade automatisch.
2. Geben Sie den Indexer-Benutzernamen in das Feld **Username** ein.
3. Geben Sie das Indexer-Passwort in das Feld **Password** ein.
4. Legen Sie optional einen **Minimum Severity**-Wert fest, um einzuschränken, welche Befunde importiert werden. Befunde unterhalb des gewählten Schweregrads werden nicht importiert.

## Wiz

Der Wiz-Connector importiert **Issues und Schwachstellen-Befunde**. DefectDojo erstellt einen Record für jedes **Wiz-Projekt** sowie einen Record auf Tenant-Ebene, der nach dem Tenant selbst benannt ist, zum Beispiel **Wiz Tenant abc12**. Dieser Record deckt den gesamten Wiz-Tenant ab.

**Sie benötigen keine Wiz-Projekte, um diesen Connector zu verwenden.** Wenn Ihr Tenant keine Projekte hat, ordnen Sie den Record diesen Tenant-Record zu. DefectDojo importiert dann jedes Issue und jeden Schwachstellen-Befund, den Ihr Service-Konto sehen kann. Dieser Record erfasst auch Befunde zu Ressourcen, die kein Projekt abdeckt. Ordnen Sie ihn daher zusätzlich zu Ihren Projekt-Records zu, wenn Ihre Projekte nicht alles abdecken. Wenn Sie sowohl einen Projekt-Record als auch den Record diesen Tenant-Record zuordnen, werden die Befunde dieses Projekts in zwei Assets importiert. Tun Sie das nur, wenn Sie beide Ansichten wünschen.

Um den Wiz-Connector zu verwenden, müssen Sie ein Service-Konto erstellen: siehe die [Wiz-Dokumentation](https://docs.wiz.io/wiz-docs/docs/service-accounts-settings#add-a-service-account) für weitere Informationen. Sie benötigen ein Wiz-Konto, um auf die Dokumentation zuzugreifen.

Das Service-Konto muss alle folgenden Anforderungen erfüllen. Ein Service-Konto, dem eine davon fehlt, kann sich zwar erfolgreich authentifizieren, importiert aber nichts:

* **Type**: Custom Integration (GraphQL API).
* **API-Scopes**: mindestens `read:projects`, `read:issues` und `read:vulnerabilities`. `read:projects` wird auch bei einem Tenant ohne Projekte benötigt, weil Discover weiterhin die Projektliste bei Wiz abfragt.
* **Projekt-Sichtbarkeit**: Das Service-Konto muss auf jedes zu importierende Wiz-Projekt beschränkt sein (oder auf alle Projekte). Ein Konto, das Issues lesen kann, aber keine Projekt-Sichtbarkeit hat, ermittelt keine Projekt-Records. Es steht dann nur der Record diesen Tenant-Record zur Verfügung.

#### **Connector-Zuordnungen**

1. Geben Sie Ihre Wiz Client ID in das Feld Client ID ein.
2. Geben Sie das Wiz Client Secret in das Feld Secret ein.

## **YesWeHack**

Der YesWeHack-Connector verwendet die YesWeHack-REST-API, um Reports aus Ihren Bug-Bounty- und Vulnerability-Disclosure-Programmen zu importieren. DefectDojo erstellt für jedes Programm, auf das Ihr Token zugreifen kann, einen Eintrag und importiert dessen Reports als Befunde.

#### Voraussetzungen

Sie benötigen ein YesWeHack-**Personal Access Token (PAT)**. Lesezugriff auf Ihre Programme ist ausreichend. Manche Konten erfordern beim Erstellen eines Tokens TOTP/MFA; einmal erstellt, verwendet der Connector nur den Token-Wert selbst.

1. Öffnen Sie in YesWeHack Ihre Kontoeinstellungen und gehen Sie zu **API / Personal Access Tokens**.
2. Erstellen Sie ein Token und kopieren Sie dessen Wert. Er wird nur einmal angezeigt.

#### Connector-Zuordnungen

1. Geben Sie `https://api.yeswehack.com/` in das Feld **Location** ein.
2. Geben Sie Ihr Personal Access Token in das Feld **Secret** ein.
3. Legen Sie optional einen **Minimum Severity**-Wert fest, um einzuschränken, welche Befunde importiert werden. Befunde unterhalb des gewählten Schweregrads werden nicht importiert.

DefectDojo erstellt für jedes Programm, auf das Ihr Token zugreifen kann, einen separaten Eintrag und importiert jeden Report als Befund. Der Schweregrad des Befunds wird der CVSS-Bewertung des Reports entnommen (mit Rückgriff auf die Triage-Priorität), und sein Status spiegelt den Workflow-Status des Reports wider — zum Beispiel werden gelöste Reports als behoben importiert, und als ungültig oder außerhalb des Geltungsbereichs markierte Reports werden als inaktiv importiert.
