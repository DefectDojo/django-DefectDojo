---
title: MCP Server
description: Il server MCP di DefectDojo consente di utilizzare gli LLM con DefectDojo
  Pro
draft: false
audience: pro
weight: 23
aliases:
- /it/en/ai/mcp_server_pro
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Nota: le funzionalità di IA sono disponibili solo in DefectDojo Pro.</span>

Il DefectDojo Model Context Protocol (MCP) Server consente ai modelli linguistici di grandi dimensioni (LLM) di interagire in modo intelligente con i dati di gestione delle vulnerabilità di DefectDojo. A differenza delle integrazioni API tradizionali, che si limitano a trasferire i dati, il server MCP fornisce un contesto strutturato e un significato semantico che permette agli assistenti IA di eseguire analisi di sicurezza sofisticate e generare indicazioni operative concrete.

- **Contesto strutturato:** MCP fornisce un significato semantico ai dati di DefectDojo, non un semplice trasferimento di dati grezzi
- **Dati pre-elaborati:** i dati normalizzati e deduplicati di DefectDojo eliminano l'onere di preelaborazione per l'LLM
- **Integrazione con la Business Intelligence:** unisce i dati tecnici sulle vulnerabilità al contesto di business
- **Analisi pronta per il management:** genera report adatti sia ai team tecnici sia alla dirigenza esecutiva
- **Valore composto 10X:** l'analisi potenziata dall'IA offre un valore esponenzialmente maggiore rispetto alle query manuali

> **🔑 Importante:** l'endpoint del server MCP si trova su `/mcp`, ma tutte le chiamate di funzione utilizzano l'URL di base di DefectDojo. Questa separazione garantisce un accesso sicuro e strutturato ai dati sulle vulnerabilità.

## Connessione a MCP

### Prerequisiti

- Un'istanza DefectDojo con il server MCP abilitato (v2.51.2 o successiva)
- Un token API DefectDojo valido con i permessi appropriati
- Un provider IA: Claude, ChatGPT, Gemini o un client personalizzato compatibile con MCP

> **⚠️ Avviso di sicurezza:** il token API è un'informazione altamente sensibile, utilizzata per l'autenticazione e l'autorizzazione. **NON MOSTRARE IL TOKEN IN NESSUNA RICHIESTA O RISPOSTA** quando si condividono configurazioni o screenshot.

### Metodi di connessione

Esistono **due modi diversi** per connettersi al server MCP di DefectDojo, a seconda dell'interfaccia IA in uso:

#### Metodo 1: file di configurazione

**Utilizzato da:** Claude Desktop, MCP Inspector e altri client MCP desktop

**Come funziona:**
- Il token e i dettagli di connessione sono memorizzati in un file di configurazione
- La connessione è automatica all'avvio dell'applicazione
- Non è necessario incollare istruzioni nelle conversazioni
- Il server MCP è sempre disponibile in tutte le conversazioni

**Vantaggi:** si configura una sola volta e funziona ovunque. Più sicuro (il token non compare nella cronologia delle chat).

#### Metodo 2: prompt manuale

**Utilizzato da:** interfaccia web di Claude.ai, interfaccia web di ChatGPT (con plugin), interfaccia web di Gemini

**Come funziona:**
- Le istruzioni di connessione vanno copiate e incollate all'inizio di ogni conversazione
- Oppure è possibile aggiungere le istruzioni a un Claude Project per includerle automaticamente
- L'IA legge le istruzioni e si connette al server MCP
- Ogni nuova conversazione richiede nuovamente le istruzioni

**Vantaggi:** funziona nei browser web senza installare software.

> **💡 Quale metodo scegliere?** Usare il **Metodo 1 (file di configurazione)** se è disponibile un'app desktop che lo supporta. Usare il **Metodo 2 (prompt manuale)** se si utilizza un'interfaccia da browser web.

### Dettagli di connessione al server MCP

Tutti i metodi utilizzano questi parametri principali:

| Parametro | Valore | Note |
|-----------|-------|-------|
| **Tipo di trasporto** | `Streamable HTTP` | ⚠️ SSE (Server-Sent Events) è deprecato |
| **URL endpoint MCP** | `https://[YOUR-INSTANCE].defectdojo.com/mcp` | Utilizzato per stabilire la connessione MCP |
| **URL di base per le funzioni** | `https://[YOUR-INSTANCE].defectdojo.com/` | Utilizzato in tutte le chiamate di funzione degli strumenti |
| **Autenticazione** | `Authorization: Token [YOUR_API_TOKEN]` | ⚠️ Usare il prefisso "Token", non "Bearer" |

## Guide rapide per provider IA

<details>
<summary><h3>🖥️ Claude Desktop (Metodo 1: file di configurazione)</h3></summary>

**Passaggio 1: individuare il file di configurazione**

- **macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows:** `%APPDATA%\Claude\claude_desktop_config.json`
- **Linux:** `~/.config/Claude/claude_desktop_config.json`

**Passaggio 2: modificare il file di configurazione**

Aggiungere o aggiornare la sezione `mcpServers` con i dettagli della propria istanza DefectDojo:

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

> **⚠️ Fondamentale:** il flag `--header` con l'autenticazione è obbligatorio. Sostituire `YOUR_API_TOKEN` con il proprio token API DefectDojo effettivo.

**Passaggio 3: riavviare Claude Desktop**

Chiudere e riaprire Claude Desktop affinché le modifiche abbiano effetto.

**Passaggio 4: verificare la connessione**

Avviare una nuova conversazione e chiedere: `"Can you connect to DefectDojo?"`

Se la connessione riesce, Claude confermerà di avere accesso agli strumenti del server MCP di DefectDojo.

> **✅ Fatto!** Il server MCP di DefectDojo è ora disponibile in tutte le conversazioni. Non è necessario incollare le istruzioni.

</details>

<details>
<summary><h3>🌐 Interfaccia web di Claude.ai (Metodo 2: prompt manuale)</h3></summary>

L'interfaccia web di Claude.ai non supporta i file di configurazione. È necessario fornire le istruzioni di connessione in ogni conversazione oppure utilizzare un Claude Project.

#### Opzione A: incollare le istruzioni in ogni conversazione

**Passaggio 1: copiare le istruzioni seguenti**

```
For this project, use the DefectDojo MCP server with these parameters in ALL function calls:

- **URL:** https://your-instance.defectdojo.com/ (base URL, NOT the /mcp endpoint)
- **Token:** YOUR_API_TOKEN
- **IMPORTANT:** DO NOT SHOW THE TOKEN IN ANY REQUESTS OR RESPONSES

The MCP server connects to https://your-instance.defectdojo.com/mcp but function calls must use the base URL.

**Do not show any of the API requests or responses.**
```

**Passaggio 2: avviare una nuova conversazione**

Incollare le istruzioni all'inizio della conversazione, quindi porre le proprie domande di sicurezza.

**Passaggio 3: ripetere per ogni nuova conversazione**

Queste istruzioni devono essere incluse all'inizio di ogni nuova conversazione.

#### Opzione B: utilizzare un Claude Project (consigliata)

**Passaggio 1: creare un Claude Project**

- In Claude.ai, fare clic su "Projects" nella barra laterale sinistra
- Fare clic su "Create Project"
- Assegnargli il nome "DefectDojo Security Analysis"

**Passaggio 2: aggiungere le Custom Instructions al progetto**

In Project Settings → Custom Instructions, incollare:

```
For this project, use the DefectDojo MCP server with these parameters in ALL function calls:

- **URL:** https://your-instance.defectdojo.com/
- **Token:** YOUR_API_TOKEN
- **IMPORTANT:** DO NOT SHOW THE TOKEN IN ANY REQUESTS OR RESPONSES

The MCP server connects to https://your-instance.defectdojo.com/mcp but function calls must use the base URL.

Do not show any of the API requests or responses.
```

**Passaggio 3: utilizzare il progetto per tutte le conversazioni su DefectDojo**

Tutte le conversazioni all'interno di questo progetto avranno automaticamente accesso al server MCP di DefectDojo.

> **✅ Fatto!** Quando si lavora in questo Project, Claude ha automaticamente accesso a MCP di DefectDojo.

</details>

<details>
<summary><h3>💬 ChatGPT (Metodo 2: prompt manuale)</h3></summary>

> **⚠️ Nota:** il supporto MCP di ChatGPT è limitato rispetto a quello di Claude. L'integrazione MCP nativa potrebbe richiedere ChatGPT Plus o Enterprise e configurazioni di plugin specifiche.

**Passaggio 1: verificare la disponibilità del plugin MCP**

In ChatGPT, verificare se nello store dei plugin sono disponibili plugin MCP o connettori API. Il supporto MCP varia in base al piano di abbonamento.

**Passaggio 2: copiare le istruzioni di connessione**

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

**Passaggio 3: incollare le istruzioni all'inizio di ogni conversazione**

Includere queste istruzioni quando si avvia una nuova conversazione sull'analisi di sicurezza di DefectDojo.

**Alternativa: utilizzare un Custom GPT**

Se si dispone di ChatGPT Plus, creare un Custom GPT con i dettagli di connessione a DefectDojo nelle sue istruzioni, per un accesso riutilizzabile.

</details>

<details>
<summary><h3>💎 Google Gemini (Metodo 2: prompt manuale)</h3></summary>

> **⚠️ Nota:** il supporto MCP di Gemini è in evoluzione. L'integrazione nativa potrebbe essere limitata. Valutare l'uso delle Gemini API con librerie client MCP per la piena funzionalità.

**Passaggio 1: copiare le istruzioni di connessione**

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

**Passaggio 2: avviare la conversazione con le istruzioni**

Iniziare ogni nuova conversazione su Gemini con queste istruzioni quando si lavora con i dati di DefectDojo.

**Per utenti avanzati:**

Valutare l'uso delle Gemini API con librerie client MCP (Python, JavaScript) per un accesso programmatico con pieno supporto al protocollo MCP.

</details>

<details>
<summary><h3>🔍 MCP Inspector (test e convalida)</h3></summary>

**Caso d'uso:** testare la connessione MCP a DefectDojo, esplorare gli strumenti disponibili e convalidare la configurazione prima di utilizzarla con gli assistenti IA.

**Passaggio 1: installare MCP Inspector**

```bash
# macOS (using Homebrew)
brew install mcp-inspector

# Or using npm (all platforms)
npm install -g @modelcontextprotocol/inspector
```

**Passaggio 2: eseguire MCP Inspector**

```bash
mcp-inspector
```

Questo avvierà un server web locale (di solito su `http://localhost:6274`)

**Passaggio 3: configurare la connessione nell'interfaccia web**

- **Tipo di trasporto:** `Streamable HTTP`
- **URL:** `https://your-instance.defectdojo.com/mcp`
- **Tipo di connessione:** `Via Proxy`
- **Header personalizzati:**
  - Nome: `Authorization`
  - Valore: `Token YOUR_API_TOKEN`
  - **Importante:** attivare l'interruttore accanto all'header

**Passaggio 4: fare clic su "Connect"**

Una volta connessi, è possibile esplorare:

- **Scheda Tools:** visualizzare tutti i 12 strumenti disponibili e i relativi parametri
- **Scheda Prompts:** visualizzare i modelli di prompt preconfigurati
- **Scheda Resources:** verificare le risorse di dati disponibili

> **✅ Ideale per:** verificare che la configurazione funzioni prima di impostare gli assistenti IA, esplorare le funzionalità degli strumenti e risolvere i problemi di connessione.

</details>

---

> **✅ Connessione riuscita?** Una volta connessi con qualsiasi metodo, effettuare un test chiedendo al proprio assistente IA: `"How many active findings do we have in DefectDojo?"`

---

## Riferimento degli strumenti disponibili

Il server MCP di DefectDojo mette a disposizione 12 strumenti per accedere ai dati sulle vulnerabilità e analizzarli. Ogni strumento include una gestione intelligente dei parametri e restituisce dati strutturati ottimizzati per l'analisi da parte degli LLM.

> **💡 Nota sui parametri:** tutti gli strumenti accettano un parametro opzionale `token`. Se non viene fornito nelle singole chiamate, l'LLM utilizzerà il token della configurazione di connessione.

---

### 🔍 Strumenti di analisi dei riscontri

<details>
<summary><h4>get_findings</h4></summary>

**Descrizione:** recupera i riscontri da DefectDojo con funzionalità di filtro sofisticate. È lo strumento più potente e utilizzato di frequente per l'analisi delle vulnerabilità.

**Parametri:**

**severity** (Facoltativo)
- **Tipo:** array di stringhe
- **Valori:** `Critical`, `High`, `Medium`, `Low`, `Info`
- **Esempio:** `["Critical", "High"]`
- **Utilizzo:** filtra i riscontri in base al livello di gravità. È possibile fornire più valori per query composte.

**status** (Facoltativo)
- **Tipo:** array di stringhe
- **Valori:** `Any`, `Active`, `Open`, `Verified`, `Out of Scope`, `False Positive`, `Inactive`, `Risk Accepted`, `Closed`, `Under Review`
- **Esempio:** `["Active", "Verified"]`
- **Utilizzo:** filtra i riscontri in base al loro stato attuale. Usare `Active` per la valutazione del rischio corrente.

**date** (Facoltativo)
- **Tipo:** array con un singolo valore stringa
- **Valori:** `0 - Any date`, `1 - Today`, `2 - Past 7 days`, `3 - Past 30 days`, `4 - Past 90 days`, `5 - Current month`, `6 - Current year`, `7 - Past year`
- **Esempio:** `["3 - Past 30 days"]`
- **Utilizzo:** filtra i riscontri in base alla data di rilevamento. È consentito un solo valore.

**limit** (Facoltativo)
- **Tipo:** numero
- **Predefinito:** 100
- **Intervallo:** 1-100
- **Utilizzo:** numero di riscontri da restituire. Per ottenere solo il conteggio, impostare il valore su 1 e utilizzare la proprietà count nella risposta.

**offset** (Facoltativo)
- **Tipo:** numero
- **Predefinito:** 0
- **Utilizzo:** offset di paginazione per recuperare risultati aggiuntivi.

> **💡 Best practice:** per le query di valutazione del rischio, utilizzare sempre `status: ["Active"]` per concentrarsi sulle vulnerabilità attuali e non risolte, anziché sui dati storici.

**Esempio di query:**

**L'utente chiede:** "Mostrami tutti i riscontri attivi di gravità critica e alta degli ultimi 30 giorni"

**Chiamata dell'LLM:**
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

**Descrizione:** recupera informazioni dettagliate su un riscontro specifico utilizzando il suo identificatore univoco.

**Parametri:**

**finding_id** (Obbligatorio)
- **Tipo:** numero
- **Minimo:** 1
- **Utilizzo:** l'ID univoco del riscontro da recuperare.

**Esempio di query:**

**L'utente chiede:** "Recupera i dettagli del riscontro #1234"

**Chiamata dell'LLM:** `get_finding_by_id({ finding_id: 1234 })`

</details>

---

### 📦 Strumenti per prodotti ed engagement

<details>
<summary><h4>get_products</h4></summary>

**Descrizione:** recupera tutti i prodotti da DefectDojo. I prodotti rappresentano applicazioni, servizi o sistemi sottoposti a test.

**Parametri:**

**limit** (Facoltativo)
- **Predefinito:** 100
- **Utilizzo:** numero massimo di prodotti da restituire.

**offset** (Facoltativo)
- **Predefinito:** 0
- **Utilizzo:** offset di paginazione.

</details>

<details>
<summary><h4>get_product_types</h4></summary>

**Descrizione:** recupera le categorie di tipo di prodotto da DefectDojo. I tipi di prodotto aiutano a organizzare i prodotti in raggruppamenti logici.

**Parametri:** uguali a `get_products`

</details>

<details>
<summary><h4>get_engagements</h4></summary>

**Descrizione:** recupera gli engagement di test di sicurezza. Gli engagement rappresentano attività di test specifiche o periodi di tempo relativi a un prodotto.

**Parametri:** uguali a `get_products`

</details>

<details>
<summary><h4>get_tests</h4></summary>

**Descrizione:** recupera i test di sicurezza da DefectDojo. I test contengono i risultati delle scansioni di strumenti di sicurezza specifici o di test manuali.

**Parametri:** uguali a `get_products`

</details>

---

### 👥 Strumenti per la gestione di utenti e accessi

<details>
<summary><h4>get_users</h4></summary>

**Descrizione:** recupera tutti gli utenti da DefectDojo per l'analisi degli stakeholder e la mappatura delle responsabilità.

**Parametri:**

**limit** (Facoltativo)
- **Predefinito:** 100

**offset** (Facoltativo)
- **Predefinito:** 0

</details>

<details>
<summary><h4>get_user_by_id</h4></summary>

**Descrizione:** recupera informazioni dettagliate su un utente specifico.

**Parametri:**

**user_id** (Obbligatorio)
- **Tipo:** numero
- **Minimo:** 1

</details>

<details>
<summary><h4>get_groups</h4></summary>

**Descrizione:** recupera i gruppi utente per l'analisi della struttura organizzativa e la mappatura dei permessi.

**Parametri:** uguali a `get_users`

</details>

<details>
<summary><h4>get_group_by_id</h4></summary>

**Descrizione:** recupera informazioni dettagliate su un gruppo specifico.

**Parametri:**

**group_id** (Obbligatorio)
- **Tipo:** numero
- **Minimo:** 1

</details>

<details>
<summary><h4>get_dojo_group_members</h4></summary>

**Descrizione:** recupera tutti i membri di un gruppo specifico per l'analisi del team.

**Parametri:**

**group_id** (Obbligatorio)
- **Tipo:** numero
- **Minimo:** 1

**limit** (Facoltativo)
- **Predefinito:** 100

**offset** (Facoltativo)
- **Predefinito:** 0

</details>

<details>
<summary><h4>get_roles</h4></summary>

**Descrizione:** recupera le definizioni dei ruoli da DefectDojo per comprendere le strutture dei permessi.

**Parametri:** uguali a `get_users`

</details>

---

## Prompt preconfigurati

Il server MCP di DefectDojo include prompt preconfigurati che dimostrano le best practice per gli scenari di analisi più comuni. Questi prompt possono essere richiamati direttamente dal proprio assistente IA.

### 🛡️ Report di revisione SAST

**Scopo:** creare un report completo che valuta l'efficacia degli strumenti SAST (Static Application Security Testing) in base ai dati di DefectDojo.

**L'analisi generata include:**

- Tassi di falsi positivi per strumento e tipo di vulnerabilità
- Tempo medio di correzione per livello di gravità
- Vulnerabilità critiche che compaiono più volte (lacune nella deduplicazione)
- Confronto delle prestazioni tra i team di sviluppo
- Consigli per migliorare la configurazione degli strumenti
- Lacune formative individuate a partire da pattern di vulnerabilità ricorrenti
- Analisi dei costi dell'approccio attuale rispetto a quello consigliato

**Formato di output:** report di valutazione tecnica in HTML, adatto per giustificare le richieste di budget per gli strumenti di sicurezza.

### 📊 Report sul panorama della sicurezza

**Scopo:** creare un report in stile dashboard che offre una panoramica del panorama della sicurezza in base ai dati di DefectDojo, adatto per le riunioni trimestrali del board.

**L'analisi generata include:**

- Tendenze delle vulnerabilità negli ultimi 90 giorni
- Team di sviluppo con il maggior numero di riscontri di gravità critica/alta
- Esposizione al rischio per prodotto e tipo di prodotto
- Le prime 5 categorie CWE che richiedono attenzione immediata
- Azioni di correzione specifiche con analisi costi-benefici
- Roadmap a 6 mesi per migliorare la postura di sicurezza

**Formato di output:** report in HTML di livello esecutivo con elementi visivi, schede statistiche e attenzione al rischio di business.

> **💡 Utilizzo dei prompt:** per richiamare un prompt, è sufficiente chiedere al proprio assistente IA: "Crea un report di revisione SAST" oppure "Genera un report sul panorama della sicurezza usando i dati di DefectDojo"

---

## Esempi di casi d'uso

### Caso d'uso 1: dashboard esecutiva sulla sicurezza

**Scenario:** il CISO ha bisogno di metriche di sicurezza trimestrali per una presentazione al board

**Prompt dell'utente:**

```
"Create an executive security dashboard for our Q4 board meeting showing:
- Total vulnerability counts by severity
- Trends over the past 90 days  
- Which products have the highest risk exposure
- Top 5 vulnerability categories needing attention
- Specific remediation recommendations with ROI
- A 6-month roadmap for improving our security posture"
```

**Cosa avviene dietro le quinte:**

1. `get_findings` - Recupera il conteggio totale dei riscontri attivi
2. `get_findings` - Analisi di gravità critica e alta
3. `get_findings` - Dati di tendenza sugli ultimi 90 giorni
4. `get_products` - Distribuzione delle vulnerabilità per prodotto
5. `get_engagements` - Attività di test recenti

**Output generato:** report HTML di livello esecutivo con tendenze delle vulnerabilità, esposizione al rischio per prodotto, principali categorie CWE, azioni di correzione specifiche con ROI e roadmap di sicurezza a 6 mesi.

---

### Caso d'uso 2: analisi delle prestazioni dei team di sviluppo

**Scenario:** un responsabile di ingegneria vuole capire quali team necessitano di formazione aggiuntiva sulla sicurezza

**Prompt dell'utente:**

```
"Which development teams have the most security findings? What types of vulnerabilities 
are they creating repeatedly? Based on this analysis, recommend specific security 
training programs for each team."
```

**Cosa avviene dietro le quinte:**

1. `get_findings` - Tutti i riscontri attivi
2. `get_products` - Collega i riscontri a prodotti/team
3. `get_groups` - Struttura organizzativa dei team
4. `get_users` - Responsabilità individuale degli sviluppatori

**Analisi fornita:** riscontri raggruppati per team, analisi dei pattern CWE che evidenzia errori ripetuti, individuazione delle lacune formative e consigli per programmi di formazione sulla sicurezza mirati.

---

### Caso d'uso 3: valutazione dell'efficacia degli strumenti

**Scenario:** il team di sicurezza valuta il ROI degli strumenti SAST attuali

**Prompt dell'utente:**

```
"Analyze the effectiveness of our SAST tools. Show me false positive rates, 
mean time to remediation, which tools find the most valuable vulnerabilities, 
and recommend configuration improvements or alternative tools."
```

**Cosa avviene dietro le quinte:**

1. `get_tests` - Tutti i test di sicurezza per strumento
2. `get_findings` - Analisi dei falsi positivi
3. `get_findings` - Riscontri attivi per strumento
4. `get_findings` - Riscontri chiusi per i pattern di correzione

**Analisi fornita:** tassi di falsi positivi per strumento, tempo medio di correzione per gravità, analisi dei riscontri duplicati, consigli sulla configurazione degli strumenti, lacune formative e analisi costi-benefici di approcci alternativi agli strumenti.

---

### Caso d'uso 4: reportistica di conformità

**Scenario:** preparazione per un audit SOC 2 che richiede evidenze di gestione delle vulnerabilità

**Prompt dell'utente:**

```
"Generate a SOC 2 compliance report showing our vulnerability management processes, 
including discovery and remediation procedures, SLA compliance, continuous monitoring 
evidence, and accountability documentation."
```

**Cosa avviene dietro le quinte:**

1. `get_findings` - Riscontri attivi di gravità critica/alta
2. `get_findings` - Tendenze di rilevamento da inizio anno
3. `get_engagements` - Frequenza e copertura dei test
4. `get_users` - Responsabilità di correzione

**Analisi fornita:** processi di rilevamento e correzione delle vulnerabilità, monitoraggio della conformità agli SLA, evidenze di monitoraggio continuo, documentazione delle responsabilità e lacune da correggere prima dell'audit.

---

### Caso d'uso 5: definizione delle priorità di rischio

**Scenario:** il team di sicurezza ha risorse limitate e deve stabilire le priorità degli interventi di correzione

**Prompt dell'utente:**

```
"What are the highest priority vulnerabilities we should fix first? Consider severity, 
how long they've been open, exploitability, and business impact. Give me a prioritized 
remediation roadmap with effort estimates."
```

**Cosa avviene dietro le quinte:**

1. `get_findings` - Riscontri attivi di gravità critica/alta
2. `get_products` - Contesto di criticità di business
3. Analisi delle metriche di invecchiamento (giorni trascorsi dal rilevamento)
4. Confronto incrociato con i punteggi EPSS (previsione di sfruttamento)

**Analisi fornita:** elenco delle vulnerabilità classificate per rischio, che combina gravità, anzianità, sfruttabilità e impatto sul business. Roadmap di correzione specifica con stime di impegno e riduzione del rischio prevista.

---


## Best practice e pattern di query

### Strategia di caricamento progressivo dei dati

Il proprio assistente IA ottimizza le prestazioni seguendo automaticamente questi pattern di caricamento dei dati:

**1. Iniziare con i dati di riepilogo**

Chiedere i conteggi prima di richiedere un'analisi dettagliata:

```
"How many critical and high severity findings do we have?"
```

Il proprio assistente IA utilizzerà lo strumento `get_findings` con `limit: 1` per recuperare in modo efficiente solo il conteggio.

**2. Utilizzare una paginazione strategica**

Per i set di dati di grandi dimensioni, l'assistente IA scorre automaticamente i risultati su più pagine:

```
"Analyze all our active vulnerabilities"
```

Se necessario, l'IA effettuerà più chiamate, iniziando con limiti ragionevoli e aumentandoli secondo necessità.

**3. Riutilizzo efficiente dei dati**

Porre domande correlate in sequenza per evitare query ridondanti:

```
"Show me all critical findings, then tell me which CWE categories they fall into"
```

L'IA riutilizzerà i dati dei riscontri della prima query per l'analisi CWE.

### Strategie di filtro intelligenti

Definire i prompt in modo da sfruttare le potenti funzionalità di filtro di DefectDojo:

#### Query basate sulla gravità

**Prompt dell'utente:**
```
"Show me all Critical and High severity issues that need immediate attention"
```

**Dietro le quinte:** l'IA utilizza `get_findings` con filtri di gravità e stato

#### Query basate sul tempo

**Prompt dell'utente:**
```
"What new vulnerabilities have been discovered in the past 30 days?"
```

**Dietro le quinte:** l'IA applica il filtro data per "Past 30 days" con stato attivo

#### Filtro combinato

**Prompt dell'utente:**
```
"Give me a risk assessment of all critical and high active findings from the past 90 days"
```

**Dietro le quinte:** l'IA combina i filtri di gravità, stato e data per un'analisi completa

### Analisi incrociata

Il proprio assistente IA collega automaticamente i riscontri al contesto organizzativo. Basta porre domande complete:

**Prompt dell'utente:**
```
"Which products have the most critical vulnerabilities and who is responsible for fixing them?"
```

**Dietro le quinte:** l'IA collega riscontri → test → engagement → prodotti → utenti/gruppi per un contesto completo

### Analisi di intelligence sulle vulnerabilità

**Analisi dei pattern CWE**

**Prompt dell'utente:**
```
"What are the most common vulnerability types in our codebase and which teams are creating them?"
```

L'IA raggrupperà i riscontri per CWE per individuare pattern ricorrenti, esigenze formative e problemi architetturali.

**Metriche di invecchiamento**

**Prompt dell'utente:**
```
"How long have our critical vulnerabilities been open? Which ones are overdue for remediation?"
```

L'IA calcola il tempo trascorso dal rilevamento e segnala i riscontri che superano le soglie SLA.

**Densità delle vulnerabilità**

**Prompt dell'utente:**
```
"Which products have the highest vulnerability density and represent the greatest risk?"
```

L'IA calcola i riscontri per prodotto e genera punteggi di rischio combinando gravità e volume.

### Standard per il miglioramento dei report

#### Includere sempre

- **Metriche specifiche:** conteggi effettivi per gravità, non generalizzazioni
- **Analisi CWE:** principali tipi di vulnerabilità con descrizioni
- **Dati di invecchiamento:** da quanto tempo le vulnerabilità sono aperte
- **Consigli operativi:** cosa fare in seguito, con tempistiche
- **Calcoli del ROI:** costo previsto rispetto al beneficio delle azioni
- **Metriche di successo:** come misurare il miglioramento

#### Integrazione del contesto di settore

Confrontare i riscontri di DefectDojo con i framework di settore:

- **OWASP Top 10:** rischi di sicurezza delle applicazioni web
- **SANS Top 25:** le vulnerabilità software più pericolose
- **CWE Top 25:** le vulnerabilità più comuni e di maggiore impatto
- **Framework di conformità:** SOC 2, ISO 27001, NIST CSF

## Risoluzione dei problemi di MCP

### Elenco di controllo diagnostico

Verificare questi elementi in caso di problemi di connessione:

- ✅ Il tipo di trasporto è **Streamable HTTP** (non SSE)
- ✅ L'URL dell'endpoint MCP è corretto: `https://[instance].defectdojo.com/mcp`
- ✅ L'header Authorization è abilitato (l'interruttore è su ON)
- ✅ Il formato del token include il prefisso `Token`
- ✅ Il token è valido e dispone dei permessi appropriati
- ✅ L'istanza DefectDojo è raggiungibile (è possibile accedere tramite l'interfaccia web)
- ✅ La connettività di rete consente connessioni HTTPS

### Problemi di connessione comuni

#### ❌ "Connection Error - Check if your MCP server is running"

**Causa:** utilizzo del tipo di trasporto SSE (Server-Sent Events), ormai deprecato

**Soluzione:** modificare il tipo di trasporto in `Streamable HTTP`

**Perché:** il server MCP di DefectDojo utilizza il moderno protocollo Streamable HTTP. SSE è deprecato e non è supportato.

---

#### ❌ "Authentication Failed" or "401 Unauthorized"

**Causa:** formato dell'header di autenticazione non corretto oppure token non valido

**Soluzioni:**

1. Verificare che il valore dell'header utilizzi il prefisso `Token` (non `Bearer`)
   ```
   ✅ Correct: Token 7c6cc2xxxxxxxxxxxxxxxxxxxx87fcf72ec2b3fb
   ❌ Wrong: Bearer 7c6cc2xxxxxxxxxxxxxxxxxxxx87fcf72ec2b3fb
   ```

2. Assicurarsi che l'interruttore dell'header Authorization sia ABILITATO (impostato su ON)
3. Verificare che il token sia ancora valido in DefectDojo (Admin → API Tokens)
4. Verificare che il token disponga dei permessi appropriati per l'accesso in lettura

---

#### ❌ Lo strumento restituisce risultati vuoti

**Possibili cause:**

- I filtri sono troppo restrittivi (nessun dato corrisponde ai criteri)
- L'istanza DefectDojo non contiene dati nella categoria richiesta
- Permessi del token insufficienti

**Soluzioni:**

1. Provare prima con una query più ampia: `get_findings({ limit: 10 })`
2. Rimuovere i filtri uno alla volta per individuare quello troppo restrittivo
3. Verificare i permessi del token in DefectDojo
4. Verificare se i dati esistono direttamente nell'interfaccia utente di DefectDojo

---

#### ⚠️ Tempi di risposta lenti

**Causa:** richiesta di una quantità eccessiva di dati in una sola volta

**Soluzioni:**

- Ridurre il parametro `limit` (iniziare con 50-100)
- Utilizzare filtri più specifici per ridurre le dimensioni del set di risultati
- Utilizzare il caricamento progressivo: ottenere prima i conteggi, poi i dettagli
- Implementare la paginazione per i set di dati di grandi dimensioni

---
