---
title: MCP Server
description: Mit dem MCP Server von DefectDojo können Sie LLMs zusammen mit DefectDojo
  Pro nutzen
draft: false
audience: pro
weight: 23
aliases:
- /en/ai/mcp_server_pro
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Hinweis: KI-Funktionen sind ausschließlich in DefectDojo Pro verfügbar.</span>

Der DefectDojo Model Context Protocol (MCP) Server ermöglicht Large Language Models (LLMs) die intelligente Interaktion mit den Schwachstellenmanagement-Daten von DefectDojo. Anders als herkömmliche API-Integrationen, die lediglich Daten übertragen, liefert der MCP-Server strukturierten Kontext und semantische Bedeutung, sodass KI-Assistenten anspruchsvolle Sicherheitsanalysen durchführen und umsetzbare Erkenntnisse gewinnen können.

- **Strukturierter Kontext:** MCP verleiht DefectDojo-Daten semantische Bedeutung, statt nur Rohdaten zu übertragen
- **Vorverarbeitete Daten:** Die normalisierten, deduplizierten Daten von DefectDojo ersparen dem LLM die Vorverarbeitung
- **Business-Intelligence-Integration:** Verbindet technische Schwachstellendaten mit geschäftlichem Kontext
- **Analysen für die Führungsebene:** Erzeugt Berichte, die für technische Teams bis hin zur Geschäftsführung geeignet sind
- **10-facher Mehrwert:** KI-gestützte Analysen liefern exponentiell mehr Nutzen als manuelle Abfragen

> **🔑 Wichtig:** Der Endpunkt des MCP-Servers liegt unter `/mcp`, alle Funktionsaufrufe verwenden jedoch die Basis-URL von DefectDojo. Diese Trennung sorgt für sicheren, strukturierten Zugriff auf Schwachstellendaten.

## Verbindung zu MCP herstellen

### Voraussetzungen

- DefectDojo-Instanz mit aktiviertem MCP Server (v2.51.2 oder neuer)
- Gültiges DefectDojo-API-Token mit entsprechenden Berechtigungen
- KI-Anbieter: Claude, ChatGPT, Gemini oder ein eigener MCP-kompatibler Client

> **⚠️ Sicherheitshinweis:** Ihr API-Token ist eine höchst sensible Information, die zur Authentifizierung und Autorisierung dient. **ZEIGEN SIE DAS TOKEN IN KEINEN ANFRAGEN ODER ANTWORTEN**, wenn Sie Konfigurationen oder Screenshots weitergeben.

### Verbindungsmethoden

Es gibt **zwei verschiedene Wege**, sich mit dem DefectDojo MCP Server zu verbinden, abhängig davon, welche KI-Oberfläche Sie verwenden:

#### Methode 1: Konfigurationsdatei

**Verwendet von:** Claude Desktop, MCP Inspector und anderen Desktop-MCP-Clients

**So funktioniert es:**
- Token und Verbindungsdaten werden in einer Konfigurationsdatei gespeichert
- Die Verbindung wird beim Start der Anwendung automatisch aufgebaut
- Es müssen keine Anweisungen in Unterhaltungen eingefügt werden
- Der MCP Server steht in allen Unterhaltungen zur Verfügung

**Vorteile:** Einmal einrichten, überall nutzbar. Sicherer, da das Token nicht im Chatverlauf steht.

#### Methode 2: Manueller Prompt

**Verwendet von:** Claude.ai-Weboberfläche, ChatGPT-Weboberfläche (mit Plugins), Gemini-Weboberfläche

**So funktioniert es:**
- Sie fügen die Verbindungsanweisungen am Anfang jeder Unterhaltung ein
- Oder Sie hinterlegen die Anweisungen in einem Claude Project, damit sie automatisch übernommen werden
- Die KI liest die Anweisungen und verbindet sich mit dem MCP Server
- Jede neue Unterhaltung benötigt die Anweisungen erneut

**Vorteile:** Funktioniert im Webbrowser, ohne Software zu installieren.

> **💡 Welche Methode soll ich verwenden?** Nutzen Sie **Methode 1 (Konfigurationsdatei)**, wenn Sie eine Desktop-App haben, die dies unterstützt. Nutzen Sie **Methode 2 (Manueller Prompt)**, wenn Sie eine Weboberfläche verwenden.

### Verbindungsdaten des MCP Servers

Alle Methoden verwenden diese zentralen Parameter:

| Parameter | Wert | Hinweise |
|-----------|-------|-------|
| **Transporttyp** | `Streamable HTTP` | ⚠️ SSE (Server-Sent Events) ist veraltet |
| **MCP-Endpunkt-URL** | `https://[YOUR-INSTANCE].defectdojo.com/mcp` | Dient zum Aufbau der MCP-Verbindung |
| **Basis-URL für Funktionen** | `https://[YOUR-INSTANCE].defectdojo.com/` | Wird in allen Tool-Funktionsaufrufen verwendet |
| **Authentifizierung** | `Authorization: Token [YOUR_API_TOKEN]` | ⚠️ Präfix "Token" verwenden, nicht "Bearer" |

## Schnellstart-Anleitungen je KI-Anbieter

<details>
<summary><h3>🖥️ Claude Desktop (Methode 1: Konfigurationsdatei)</h3></summary>

**Schritt 1: Konfigurationsdatei finden**

- **macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows:** `%APPDATA%\Claude\claude_desktop_config.json`
- **Linux:** `~/.config/Claude/claude_desktop_config.json`

**Schritt 2: Konfigurationsdatei bearbeiten**

Fügen Sie den Abschnitt `mcpServers` mit den Daten Ihrer DefectDojo-Instanz hinzu oder aktualisieren Sie ihn:

```json
{
  "mcpServers": {
    "DefectDojo-MCP": {
      "command": "npx",
      "args": [
        "mcp-remote",
        "https://your-instance.defectdojo.com/mcp",
        "--header",
        "Authorization: Token YOUR_API_TOKEN"
      ]
    }
  }
}
```

> **⚠️ Wichtig:** Das Flag `--header` mit den Authentifizierungsdaten ist erforderlich. Ersetzen Sie `YOUR_API_TOKEN` durch Ihr tatsächliches DefectDojo-API-Token.

**Schritt 3: Claude Desktop neu starten**

Schließen Sie Claude Desktop und öffnen Sie es erneut, damit die Änderungen wirksam werden.

**Schritt 4: Verbindung prüfen**

Starten Sie eine neue Unterhaltung und fragen Sie: `"Can you connect to DefectDojo?"`

Bei Erfolg bestätigt Claude, dass Zugriff auf die Tools des DefectDojo MCP Servers besteht.

> **✅ Fertig!** Der DefectDojo MCP Server steht nun in allen Unterhaltungen zur Verfügung. Es müssen keine Anweisungen mehr eingefügt werden.

</details>

<details>
<summary><h3>🌐 Claude.ai-Weboberfläche (Methode 2: Manueller Prompt)</h3></summary>

Die Claude.ai-Weboberfläche unterstützt keine Konfigurationsdateien. Sie müssen die Verbindungsanweisungen in jeder Unterhaltung angeben oder ein Claude Project verwenden.

#### Option A: Anweisungen pro Unterhaltung einfügen

**Schritt 1: Die folgenden Anweisungen kopieren**

```
For this project, use the DefectDojo MCP server with these parameters in ALL function calls:

- **URL:** https://your-instance.defectdojo.com/ (base URL, NOT the /mcp endpoint)
- **Token:** YOUR_API_TOKEN
- **IMPORTANT:** DO NOT SHOW THE TOKEN IN ANY REQUESTS OR RESPONSES

The MCP server connects to https://your-instance.defectdojo.com/mcp but function calls must use the base URL.

**Do not show any of the API requests or responses.**
```

**Schritt 2: Neue Unterhaltung starten**

Fügen Sie die Anweisungen am Anfang der Unterhaltung ein und stellen Sie anschließend Ihre Sicherheitsfragen.

**Schritt 3: Für jede neue Unterhaltung wiederholen**

Diese Anweisungen müssen am Anfang jeder neuen Unterhaltung enthalten sein.

#### Option B: Ein Claude Project verwenden (empfohlen)

**Schritt 1: Ein Claude Project erstellen**

- Klicken Sie in Claude.ai in der linken Seitenleiste auf "Projects"
- Klicken Sie auf "Create Project"
- Benennen Sie es mit "DefectDojo Security Analysis"

**Schritt 2: Benutzerdefinierte Anweisungen zum Project hinzufügen**

Fügen Sie unter Project Settings → Custom Instructions Folgendes ein:

```
For this project, use the DefectDojo MCP server with these parameters in ALL function calls:

- **URL:** https://your-instance.defectdojo.com/
- **Token:** YOUR_API_TOKEN
- **IMPORTANT:** DO NOT SHOW THE TOKEN IN ANY REQUESTS OR RESPONSES

The MCP server connects to https://your-instance.defectdojo.com/mcp but function calls must use the base URL.

Do not show any of the API requests or responses.
```

**Schritt 3: Das Project für alle DefectDojo-Unterhaltungen nutzen**

Alle Unterhaltungen innerhalb dieses Projects haben automatisch Zugriff auf den DefectDojo MCP Server.

> **✅ Fertig!** Wenn Sie in diesem Project arbeiten, hat Claude automatisch Zugriff auf DefectDojo MCP.

</details>

<details>
<summary><h3>💬 ChatGPT (Methode 2: Manueller Prompt)</h3></summary>

> **⚠️ Hinweis:** Die MCP-Unterstützung von ChatGPT ist im Vergleich zu Claude eingeschränkt. Für eine native MCP-Integration sind möglicherweise ChatGPT Plus oder Enterprise sowie bestimmte Plugin-Konfigurationen erforderlich.

**Schritt 1: Verfügbarkeit des MCP-Plugins prüfen**

Prüfen Sie in ChatGPT, ob im Plugin-Store MCP- oder API-Connector-Plugins verfügbar sind. Die MCP-Unterstützung hängt vom Abonnement ab.

**Schritt 2: Verbindungsanweisungen kopieren**

```
I need you to connect to a DefectDojo MCP server with these details:

MCP Endpoint: https://your-instance.defectdojo.com/mcp
Base URL for API calls: https://your-instance.defectdojo.com/
Authentication: Authorization header with value "Token YOUR_API_TOKEN"

Use this connection to access DefectDojo vulnerability data. The server provides tools for:
- Getting findings with severity, status, and date filters
- Accessing products, engagements, tests
- User and group management
- Analyzing security trends

Do not show the API token in responses.
```

**Schritt 3: Am Anfang jeder Unterhaltung einfügen**

Fügen Sie diese Anweisungen hinzu, wenn Sie eine neue Unterhaltung zur Sicherheitsanalyse mit DefectDojo beginnen.

**Alternative: Ein Custom GPT verwenden**

Wenn Sie ChatGPT Plus haben, erstellen Sie ein Custom GPT, dessen Anweisungen die DefectDojo-Verbindungsdaten enthalten, um den Zugriff wiederverwenden zu können.

</details>

<details>
<summary><h3>💎 Google Gemini (Methode 2: Manueller Prompt)</h3></summary>

> **⚠️ Hinweis:** Die MCP-Unterstützung von Gemini entwickelt sich noch. Die native Integration ist möglicherweise eingeschränkt. Für den vollen Funktionsumfang empfiehlt sich die Gemini API in Verbindung mit MCP-Client-Bibliotheken.

**Schritt 1: Verbindungsanweisungen kopieren**

```
Connect to DefectDojo vulnerability management system via MCP server:

MCP Server: https://your-instance.defectdojo.com/mcp
API Base URL: https://your-instance.defectdojo.com/
Authentication: Token YOUR_API_TOKEN (use Authorization header with "Token" prefix)

Available capabilities:
- Query findings by severity (Critical, High, Medium, Low, Info)
- Filter by status (Active, Verified, False Positive, etc.)
- Filter by date ranges (Today, Past 7/30/90 days, etc.)
- Access products, engagements, tests, users, groups
- Generate security analysis and reports

Important: Do not display the authentication token in responses.
```

**Schritt 2: Unterhaltung mit den Anweisungen beginnen**

Beginnen Sie jede neue Gemini-Unterhaltung mit diesen Anweisungen, wenn Sie mit DefectDojo-Daten arbeiten.

**Für fortgeschrittene Benutzer:**

Für den programmatischen Zugriff mit vollständiger Unterstützung des MCP-Protokolls empfiehlt sich die Gemini API mit MCP-Client-Bibliotheken (Python, JavaScript).

</details>

<details>
<summary><h3>🔍 MCP Inspector (Test und Validierung)</h3></summary>

**Anwendungsfall:** Testen Sie Ihre DefectDojo-MCP-Verbindung, erkunden Sie die verfügbaren Tools und validieren Sie die Konfiguration, bevor Sie sie mit KI-Assistenten nutzen.

**Schritt 1: MCP Inspector installieren**

```bash
# macOS (using Homebrew)
brew install mcp-inspector

# Or using npm (all platforms)
npm install -g @modelcontextprotocol/inspector
```

**Schritt 2: MCP Inspector starten**

```bash
mcp-inspector
```

Damit wird ein lokaler Webserver gestartet (normalerweise unter `http://localhost:6274`)

**Schritt 3: Verbindung in der Weboberfläche konfigurieren**

- **Transporttyp:** `Streamable HTTP`
- **URL:** `https://your-instance.defectdojo.com/mcp`
- **Verbindungstyp:** `Via Proxy`
- **Benutzerdefinierte Header:**
  - Name: `Authorization`
  - Wert: `Token YOUR_API_TOKEN`
  - **Wichtig:** Aktivieren Sie den Schalter neben dem Header

**Schritt 4: Auf "Connect" klicken**

Nach dem Verbinden können Sie Folgendes erkunden:

- **Registerkarte Tools:** Alle 12 verfügbaren Tools und ihre Parameter ansehen
- **Registerkarte Prompts:** Vorkonfigurierte Prompt-Vorlagen ansehen
- **Registerkarte Resources:** Verfügbare Datenressourcen prüfen

> **✅ Ideal für:** Die Überprüfung Ihrer Konfiguration, bevor Sie KI-Assistenten einrichten, das Erkunden der Tool-Funktionen und die Fehlersuche bei Verbindungsproblemen.

</details>

---

> **✅ Verbindung erfolgreich?** Sobald die Verbindung über eine der Methoden steht, testen Sie sie, indem Sie Ihren KI-Assistenten fragen: `"How many active findings do we have in DefectDojo?"`

---

## Referenz der verfügbaren Tools

Der DefectDojo MCP Server stellt 12 Tools für den Zugriff auf Schwachstellendaten und deren Analyse bereit. Jedes Tool verarbeitet Parameter intelligent und gibt strukturierte Daten zurück, die für die Analyse durch LLMs optimiert sind.

> **💡 Hinweis zu Parametern:** Alle Tools akzeptieren einen optionalen Parameter `token`. Wird er in einzelnen Aufrufen nicht angegeben, verwendet das LLM das Token aus der Verbindungskonfiguration.

---

### 🔍 Tools zur Analyse von Befunden

<details>
<summary><h4>get_findings</h4></summary>

**Beschreibung:** Ruft Befunde aus DefectDojo mit umfangreichen Filtermöglichkeiten ab. Dies ist das leistungsfähigste und am häufigsten genutzte Tool für die Schwachstellenanalyse.

**Parameter:**

**severity** (optional)
- **Typ:** Array von Strings
- **Werte:** `Critical`, `High`, `Medium`, `Low`, `Info`
- **Beispiel:** `["Critical", "High"]`
- **Verwendung:** Filtert Befunde nach Schweregrad. Für kombinierte Abfragen können mehrere Werte angegeben werden.

**status** (optional)
- **Typ:** Array von Strings
- **Werte:** `Any`, `Active`, `Open`, `Verified`, `Out of Scope`, `False Positive`, `Inactive`, `Risk Accepted`, `Closed`, `Under Review`
- **Beispiel:** `["Active", "Verified"]`
- **Verwendung:** Filtert Befunde nach ihrem aktuellen Status. Verwenden Sie `Active` für die Bewertung des aktuellen Risikos.

**date** (optional)
- **Typ:** Array mit einem einzelnen String-Wert
- **Werte:** `0 - Any date`, `1 - Today`, `2 - Past 7 days`, `3 - Past 30 days`, `4 - Past 90 days`, `5 - Current month`, `6 - Current year`, `7 - Past year`
- **Beispiel:** `["3 - Past 30 days"]`
- **Verwendung:** Filtert Befunde nach Entdeckungsdatum. Es ist nur ein Wert zulässig.

**limit** (optional)
- **Typ:** Zahl
- **Standard:** 100
- **Bereich:** 1-100
- **Verwendung:** Anzahl der zurückgegebenen Befunde. Wenn Sie nur die Anzahl benötigen, setzen Sie den Wert auf 1 und verwenden Sie die Eigenschaft count in der Antwort.

**offset** (optional)
- **Typ:** Zahl
- **Standard:** 0
- **Verwendung:** Paginierungs-Offset zum Abrufen weiterer Ergebnisse.

> **💡 Best Practice:** Verwenden Sie bei Abfragen zur Risikobewertung immer `status: ["Active"]`, um sich auf aktuelle, offene Schwachstellen statt auf historische Daten zu konzentrieren.

**Beispielabfrage:**

**Benutzerfrage:** "Show me all Critical and High severity active findings from the past 30 days"

**Das LLM ruft auf:**
```
get_findings({
  severity: ["Critical", "High"],
  status: ["Active"],
  date: ["3 - Past 30 days"],
  limit: 100
})
```

</details>

<details>
<summary><h4>get_finding_by_id</h4></summary>

**Beschreibung:** Ruft detaillierte Informationen zu einem bestimmten Befund über dessen eindeutige ID ab.

**Parameter:**

**finding_id** (erforderlich)
- **Typ:** Zahl
- **Minimum:** 1
- **Verwendung:** Die eindeutige ID des abzurufenden Befunds.

**Beispielabfrage:**

**Benutzerfrage:** "Get details for finding #1234"

**Das LLM ruft auf:** `get_finding_by_id({ finding_id: 1234 })`

</details>

---

### 📦 Tools für Produkte und Engagements

<details>
<summary><h4>get_products</h4></summary>

**Beschreibung:** Ruft alle Produkte aus DefectDojo ab. Produkte stehen für Anwendungen, Dienste oder Systeme, die getestet werden.

**Parameter:**

**limit** (optional)
- **Standard:** 100
- **Verwendung:** Maximale Anzahl der zurückgegebenen Produkte.

**offset** (optional)
- **Standard:** 0
- **Verwendung:** Paginierungs-Offset.

</details>

<details>
<summary><h4>get_product_types</h4></summary>

**Beschreibung:** Ruft die Produkttyp-Kategorien aus DefectDojo ab. Produkttypen helfen dabei, Produkte in logische Gruppen zu ordnen.

**Parameter:** Wie bei `get_products`

</details>

<details>
<summary><h4>get_engagements</h4></summary>

**Beschreibung:** Ruft Engagements für Sicherheitstests ab. Engagements stehen für bestimmte Testaktivitäten oder Zeiträume eines Produkts.

**Parameter:** Wie bei `get_products`

</details>

<details>
<summary><h4>get_tests</h4></summary>

**Beschreibung:** Ruft Sicherheitstests aus DefectDojo ab. Tests enthalten Scan-Ergebnisse bestimmter Sicherheitstools oder manueller Tests.

**Parameter:** Wie bei `get_products`

</details>

---

### 👥 Tools für Benutzer- und Zugriffsverwaltung

<details>
<summary><h4>get_users</h4></summary>

**Beschreibung:** Ruft alle Benutzer aus DefectDojo ab, für Stakeholder-Analysen und die Zuordnung von Verantwortlichkeiten.

**Parameter:**

**limit** (optional)
- **Standard:** 100

**offset** (optional)
- **Standard:** 0

</details>

<details>
<summary><h4>get_user_by_id</h4></summary>

**Beschreibung:** Ruft detaillierte Informationen zu einem bestimmten Benutzer ab.

**Parameter:**

**user_id** (erforderlich)
- **Typ:** Zahl
- **Minimum:** 1

</details>

<details>
<summary><h4>get_groups</h4></summary>

**Beschreibung:** Ruft Benutzergruppen ab, um die Organisationsstruktur zu analysieren und Berechtigungen zuzuordnen.

**Parameter:** Wie bei `get_users`

</details>

<details>
<summary><h4>get_group_by_id</h4></summary>

**Beschreibung:** Ruft detaillierte Informationen zu einer bestimmten Gruppe ab.

**Parameter:**

**group_id** (erforderlich)
- **Typ:** Zahl
- **Minimum:** 1

</details>

<details>
<summary><h4>get_dojo_group_members</h4></summary>

**Beschreibung:** Ruft alle Mitglieder einer bestimmten Gruppe für Teamanalysen ab.

**Parameter:**

**group_id** (erforderlich)
- **Typ:** Zahl
- **Minimum:** 1

**limit** (optional)
- **Standard:** 100

**offset** (optional)
- **Standard:** 0

</details>

<details>
<summary><h4>get_roles</h4></summary>

**Beschreibung:** Ruft Rollendefinitionen aus DefectDojo ab, um Berechtigungsstrukturen nachzuvollziehen.

**Parameter:** Wie bei `get_users`

</details>

---

## Vorkonfigurierte Prompts

Der DefectDojo MCP Server enthält vorkonfigurierte Prompts, die Best Practices für gängige Analyseszenarien zeigen. Ihr KI-Assistent kann diese Prompts direkt aufrufen.

### 🛡️ SAST-Prüfbericht

**Zweck:** Erstellt einen umfassenden Bericht, der die Wirksamkeit von SAST-Tools (Static Application Security Testing) auf Basis der DefectDojo-Daten bewertet.

**Die erzeugte Analyse enthält:**

- Falsch-positiv-Raten je Tool und Schwachstellentyp
- Durchschnittliche Behebungsdauer je Schweregrad
- Kritische Schwachstellen, die mehrfach auftreten (Lücken in der Deduplizierung)
- Vergleich der Leistung der Entwicklungsteams
- Empfehlungen zur Verbesserung der Tool-Konfiguration
- Schulungslücken, die sich aus wiederkehrenden Schwachstellenmustern ergeben
- Kostenanalyse des aktuellen im Vergleich zum empfohlenen Tooling-Ansatz

**Ausgabeformat:** Technischer Bewertungsbericht in HTML, geeignet zur Begründung von Budgetanträgen für Sicherheitstools.

### 📊 Bericht zur Sicherheitslage

**Zweck:** Erstellt einen Bericht im Dashboard-Stil, der auf Basis der DefectDojo-Daten einen Überblick über die Sicherheitslage gibt und sich für vierteljährliche Vorstandssitzungen eignet.

**Die erzeugte Analyse enthält:**

- Schwachstellentrends der letzten 90 Tage
- Entwicklungsteams mit den meisten Befunden vom Schweregrad Kritisch/Hoch
- Risikoexposition je Produkt und Produkttyp
- Die fünf wichtigsten CWE-Kategorien, die sofortige Aufmerksamkeit erfordern
- Konkrete Behebungsmaßnahmen mit Kosten-Nutzen-Analyse
- Sechsmonats-Roadmap zur Verbesserung der Sicherheitslage

**Ausgabeformat:** HTML-Bericht für die Führungsebene mit visuellen Elementen, Statistikkarten und Fokus auf Geschäftsrisiken.

> **💡 Prompts verwenden:** Um einen Prompt aufzurufen, fragen Sie einfach Ihren KI-Assistenten: "Create a SAST Review Report" oder "Generate a Security Landscape Report using DefectDojo data"

---

## Anwendungsbeispiele

### Anwendungsfall 1: Sicherheits-Dashboard für die Führungsebene

**Szenario:** Ein CISO benötigt vierteljährliche Sicherheitsmetriken für eine Vorstandspräsentation

**Benutzer-Prompt:**

```
"Create an executive security dashboard for our Q4 board meeting showing:
- Total vulnerability counts by severity
- Trends over the past 90 days  
- Which products have the highest risk exposure
- Top 5 vulnerability categories needing attention
- Specific remediation recommendations with ROI
- A 6-month roadmap for improving our security posture"
```

**Was im Hintergrund passiert:**

1. `get_findings` - Gesamtzahl der aktiven Befunde ermitteln
2. `get_findings` - Analyse der Schweregrade Kritisch und Hoch
3. `get_findings` - Trenddaten der letzten 90 Tage
4. `get_products` - Verteilung der Schwachstellen auf Produkte
5. `get_engagements` - Aktuelle Testaktivitäten

**Erzeugte Ausgabe:** HTML-Bericht für die Führungsebene mit Schwachstellentrends, Risikoexposition je Produkt, den wichtigsten CWE-Kategorien, konkreten Behebungsmaßnahmen samt ROI und einer Sechsmonats-Roadmap für die Sicherheit.

---

### Anwendungsfall 2: Leistungsanalyse der Entwicklungsteams

**Szenario:** Ein Engineering-Manager möchte wissen, welche Teams zusätzliche Sicherheitsschulungen benötigen

**Benutzer-Prompt:**

```
"Which development teams have the most security findings? What types of vulnerabilities 
are they creating repeatedly? Based on this analysis, recommend specific security 
training programs for each team."
```

**Was im Hintergrund passiert:**

1. `get_findings` - Alle aktiven Befunde
2. `get_products` - Befunde mit Produkten und Teams verknüpfen
3. `get_groups` - Organisationsstruktur der Teams
4. `get_users` - Verantwortlichkeit einzelner Entwickler

**Gelieferte Analyse:** Nach Team gruppierte Befunde, CWE-Musteranalyse mit wiederkehrenden Fehlern, Ermittlung von Schulungslücken und Empfehlungen für gezielte Sicherheitsschulungen.

---

### Anwendungsfall 3: Bewertung der Tool-Wirksamkeit

**Szenario:** Ein Sicherheitsteam bewertet den ROI der aktuellen SAST-Tools

**Benutzer-Prompt:**

```
"Analyze the effectiveness of our SAST tools. Show me false positive rates, 
mean time to remediation, which tools find the most valuable vulnerabilities, 
and recommend configuration improvements or alternative tools."
```

**Was im Hintergrund passiert:**

1. `get_tests` - Alle Sicherheitstests je Tool
2. `get_findings` - Falsch-positiv-Analyse
3. `get_findings` - Aktive Befunde je Tool
4. `get_findings` - Geschlossene Befunde für Behebungsmuster

**Gelieferte Analyse:** Falsch-positiv-Raten je Tool, durchschnittliche Behebungsdauer je Schweregrad, Analyse doppelter Befunde, Empfehlungen zur Tool-Konfiguration, Schulungslücken und Kosten-Nutzen-Analyse alternativer Tooling-Ansätze.

---

### Anwendungsfall 4: Compliance-Berichte

**Szenario:** Vorbereitung auf ein SOC-2-Audit, das Nachweise zum Schwachstellenmanagement erfordert

**Benutzer-Prompt:**

```
"Generate a SOC 2 compliance report showing our vulnerability management processes, 
including discovery and remediation procedures, SLA compliance, continuous monitoring 
evidence, and accountability documentation."
```

**Was im Hintergrund passiert:**

1. `get_findings` - Aktive Befunde mit Schweregrad Kritisch/Hoch
2. `get_findings` - Entdeckungstrends seit Jahresbeginn
3. `get_engagements` - Testhäufigkeit und Abdeckung
4. `get_users` - Verantwortlichkeiten bei der Behebung

**Gelieferte Analyse:** Prozesse zur Entdeckung und Behebung von Schwachstellen, Nachverfolgung der SLA-Einhaltung, Nachweise für kontinuierliche Überwachung, Dokumentation der Verantwortlichkeiten und Lücken, die vor dem Audit geschlossen werden müssen.

---

### Anwendungsfall 5: Risikopriorisierung

**Szenario:** Ein Sicherheitsteam hat begrenzte Ressourcen und muss die Behebungsmaßnahmen priorisieren

**Benutzer-Prompt:**

```
"What are the highest priority vulnerabilities we should fix first? Consider severity, 
how long they've been open, exploitability, and business impact. Give me a prioritized 
remediation roadmap with effort estimates."
```

**Was im Hintergrund passiert:**

1. `get_findings` - Aktive Befunde mit Schweregrad Kritisch/Hoch
2. `get_products` - Kontext zur geschäftlichen Kritikalität
3. Alterungsmetriken analysieren (Tage seit der Entdeckung)
4. Abgleich mit EPSS-Werten (Exploit-Vorhersage)

**Gelieferte Analyse:** Nach Risiko sortierte Schwachstellenliste, die Schweregrad, Alter, Ausnutzbarkeit und geschäftliche Auswirkungen kombiniert. Konkrete Behebungs-Roadmap mit Aufwandsschätzungen und erwarteter Risikoreduzierung.

---


## Best Practices und Abfragemuster

### Strategie zum progressiven Laden von Daten

Ihr KI-Assistent optimiert die Leistung, indem er diese Muster für das Laden von Daten automatisch anwendet:

**1. Mit zusammenfassenden Daten beginnen**

Fragen Sie nach Anzahlen, bevor Sie eine detaillierte Analyse anfordern:

```
"How many critical and high severity findings do we have?"
```

Ihr KI-Assistent verwendet das Tool `get_findings` mit `limit: 1`, um effizient nur die Anzahl abzurufen.

**2. Paginierung gezielt einsetzen**

Bei großen Datenmengen blättert Ihr KI-Assistent automatisch durch die Ergebnisse:

```
"Analyze all our active vulnerabilities"
```

Die KI führt bei Bedarf mehrere Aufrufe durch, beginnt mit sinnvollen Limits und erhöht sie, falls erforderlich.

**3. Daten effizient wiederverwenden**

Stellen Sie zusammenhängende Fragen nacheinander, um redundante Abfragen zu vermeiden:

```
"Show me all critical findings, then tell me which CWE categories they fall into"
```

Die KI verwendet die Befunddaten aus der ersten Abfrage für die CWE-Analyse erneut.

### Intelligente Filterstrategien

Formulieren Sie Ihre Prompts so, dass sie die leistungsfähigen Filtermöglichkeiten von DefectDojo nutzen:

#### Abfragen nach Schweregrad

**Benutzer-Prompt:**
```
"Show me all Critical and High severity issues that need immediate attention"
```

**Im Hintergrund:** Die KI verwendet `get_findings` mit Filtern für Schweregrad und Status

#### Zeitbasierte Abfragen

**Benutzer-Prompt:**
```
"What new vulnerabilities have been discovered in the past 30 days?"
```

**Im Hintergrund:** Die KI wendet den Datumsfilter für "Past 30 days" mit dem Status Aktiv an

#### Kombinierte Filter

**Benutzer-Prompt:**
```
"Give me a risk assessment of all critical and high active findings from the past 90 days"
```

**Im Hintergrund:** Die KI kombiniert Filter für Schweregrad, Status und Datum für eine umfassende Analyse

### Analyse mit Querverweisen

Ihr KI-Assistent verknüpft Befunde automatisch mit dem organisatorischen Kontext. Stellen Sie einfach umfassende Fragen:

**Benutzer-Prompt:**
```
"Which products have the most critical vulnerabilities and who is responsible for fixing them?"
```

**Im Hintergrund:** Die KI verknüpft Befunde → Tests → Engagements → Produkte → Benutzer/Gruppen, um den vollständigen Kontext herzustellen

### Analyse von Schwachstellen-Informationen

**CWE-Musteranalyse**

**Benutzer-Prompt:**
```
"What are the most common vulnerability types in our codebase and which teams are creating them?"
```

Die KI gruppiert Befunde nach CWE, um wiederkehrende Muster, Schulungsbedarf und Architekturprobleme zu erkennen.

**Alterungsmetriken**

**Benutzer-Prompt:**
```
"How long have our critical vulnerabilities been open? Which ones are overdue for remediation?"
```

Die KI berechnet die Zeit seit der Entdeckung und markiert Befunde, die SLA-Schwellenwerte überschreiten.

**Schwachstellendichte**

**Benutzer-Prompt:**
```
"Which products have the highest vulnerability density and represent the greatest risk?"
```

Die KI berechnet die Befunde je Produkt und erzeugt Risikobewertungen, die Schweregrad und Menge kombinieren.

### Standards zur Verbesserung von Berichten

#### Immer einbeziehen

- **Konkrete Metriken:** Tatsächliche Anzahlen je Schweregrad statt Verallgemeinerungen
- **CWE-Analyse:** Die häufigsten Schwachstellentypen mit Beschreibungen
- **Alterungsdaten:** Wie lange Schwachstellen bereits offen sind
- **Umsetzbare Empfehlungen:** Was als Nächstes zu tun ist, mit Zeitplänen
- **ROI-Berechnungen:** Erwartete Kosten im Verhältnis zum Nutzen der Maßnahmen
- **Erfolgsmetriken:** Wie Verbesserungen gemessen werden

#### Einordnung in den Branchenkontext

Vergleichen Sie DefectDojo-Befunde mit Branchen-Frameworks:

- **OWASP Top 10:** Sicherheitsrisiken von Webanwendungen
- **SANS Top 25:** Die gefährlichsten Softwareschwächen
- **CWE Top 25:** Die häufigsten und schwerwiegendsten Schwächen
- **Compliance-Frameworks:** SOC 2, ISO 27001, NIST CSF

## Fehlerbehebung bei MCP

### Diagnose-Checkliste

Prüfen Sie diese Punkte, wenn Verbindungsprobleme auftreten:

- ✅ Der Transporttyp ist **Streamable HTTP** (nicht SSE)
- ✅ Die MCP-Endpunkt-URL ist korrekt: `https://[instance].defectdojo.com/mcp`
- ✅ Der Authorization-Header ist aktiviert (Schalter auf ON)
- ✅ Das Tokenformat enthält das Präfix `Token`
- ✅ Das Token ist gültig und verfügt über die erforderlichen Berechtigungen
- ✅ Die DefectDojo-Instanz ist erreichbar (Anmeldung über die Weboberfläche möglich)
- ✅ Das Netzwerk erlaubt HTTPS-Verbindungen

### Häufige Verbindungsprobleme

#### ❌ "Connection Error - Check if your MCP server is running"

**Ursache:** Verwendung des veralteten Transporttyps SSE (Server-Sent Events)

**Lösung:** Ändern Sie den Transporttyp auf `Streamable HTTP`

**Warum:** Der DefectDojo MCP Server verwendet das moderne Streamable-HTTP-Protokoll. SSE ist veraltet und wird nicht unterstützt.

---

#### ❌ "Authentication Failed" oder "401 Unauthorized"

**Ursache:** Falsches Format des Authentifizierungs-Headers oder ungültiges Token

**Lösungen:**

1. Prüfen Sie, ob der Header-Wert das Präfix `Token` verwendet (nicht `Bearer`)
   ```
   ✅ Correct: Token 7c6cc2xxxxxxxxxxxxxxxxxxxx87fcf72ec2b3fb
   ❌ Wrong: Bearer 7c6cc2xxxxxxxxxxxxxxxxxxxx87fcf72ec2b3fb
   ```

2. Stellen Sie sicher, dass der Schalter für den Authorization-Header AKTIVIERT ist (auf ON)
3. Prüfen Sie, ob das Token in DefectDojo noch gültig ist (Admin → API Tokens)
4. Prüfen Sie, ob das Token über die erforderlichen Leseberechtigungen verfügt

---

#### ❌ Das Tool gibt leere Ergebnisse zurück

**Mögliche Ursachen:**

- Die Filter sind zu restriktiv (keine Daten erfüllen die Kriterien)
- Die DefectDojo-Instanz enthält keine Daten in der angefragten Kategorie
- Unzureichende Token-Berechtigungen

**Lösungen:**

1. Versuchen Sie zunächst eine breitere Abfrage: `get_findings({ limit: 10 })`
2. Entfernen Sie die Filter einzeln, um den einschränkenden Filter zu finden
3. Prüfen Sie die Token-Berechtigungen in DefectDojo
4. Prüfen Sie direkt in der DefectDojo-Oberfläche, ob Daten vorhanden sind

---

#### ⚠️ Langsame Antwortzeiten

**Ursache:** Es werden zu viele Daten auf einmal abgefragt

**Lösungen:**

- Verringern Sie den Parameter `limit` (beginnen Sie mit 50 bis 100)
- Verwenden Sie spezifischere Filter, um die Ergebnismenge zu verkleinern
- Laden Sie progressiv: zuerst Anzahlen, dann Details
- Setzen Sie bei großen Datenmengen Paginierung ein

---