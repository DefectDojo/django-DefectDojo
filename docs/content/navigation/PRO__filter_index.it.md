---
title: Indice dei filtri
description: Riferimento per tutti i filtri in DefectDojo
weight: 5
aliases:
- /it/en/working_with_findings/organizing_engagements_tests/filter_index
---

**Nota: al momento questo articolo tratta solo i filtri sui Riscontri disponibili nella UI di DefectDojo Pro, ma in futuro sarà ampliato per coprire altri tipi di oggetto, oltre ai filtri della versione Open-Source.**

Di seguito è riportato un elenco dei filtri applicabili nella UI di DefectDojo Pro per ordinare gli elenchi di Riscontri.  I filtri di DefectDojo possono essere utilizzati per facilitare la navigazione tra gli elenchi di oggetti, per creare [dashboard](/metrics_reports/dashboards/custom-dashboards/) personalizzate o per costruire automazioni tramite il [Rules Engine](/automation/rules_engine/about).

## Come vengono valutati i filtri sulle date

I filtri che prevedono una data — **Date Created**, **SLA Expiration Date**, **Last Status Update**, **Planned Remediation Date**, e i filtri sulle date di Jira elencati di seguito — offrono cinque operatori:

| Operatore | Corrisponde a |
| --- | --- |
| **On** | L'intera giornata indicata. |
| **Before** | Tutto ciò che precede l'inizio della giornata indicata. La giornata indicata stessa **non** è inclusa. |
| **After** | Tutto ciò che segue l'inizio della giornata indicata — quindi la giornata indicata **è** inclusa. |
| **During** | Da un giorno di inizio a un giorno di fine, entrambi **inclusi**. |
| **Within** | Una finestra mobile che termina nel momento attuale: ultimi 7, 14, 30, 90 o 180 giorni, oppure ultimo anno. |

Da notare che **Before** e **After** non sono deliberatamente l'una lo specchio dell'altra: *Before 8 August* esclude l'8 agosto, mentre *After 8 August* lo include.

### Limiti del giorno e fuso orario

**On**, **Before**, **After** e **During** calcolano i limiti del giorno nel **proprio fuso orario**, rilevato dal browser. Un intervallo di date copre quindi il periodo da mezzanotte a mezzanotte così come *lo si vive*, anziché in UTC o nel fuso orario del server. Due persone in fusi orari diversi possono quindi vedere risultati leggermente diversi dallo stesso filtro per i Riscontri che ricadono vicino al limite di un giorno.

**Within** non risente di questo effetto — è una finestra mobile calcolata a ritroso dal momento attuale, quindi non ha limiti di giornata da calcolare.

> **Dove questo non si applica.** Solo le richieste provenienti dalla UI Pro trasmettono il proprio fuso orario. Tutto ciò che viene eseguito senza un browser — l'API REST `/api/v2`, i report pianificati e il Rules Engine — utilizza invece il fuso orario configurato sul server (`DD_TIME_ZONE`, `UTC` a meno che l'amministratore non l'abbia modificato). Se il fuso orario del browser è diverso da quello del server, un report pianificato e un filtro a schermo che utilizzano la stessa data possono restituire righe leggermente diverse. Le esportazioni avviate da una tabella filtrata nella UI non risentono di questo effetto — utilizzano il fuso orario dell'utente, coerente con ciò che si stava visualizzando.

## Come vengono valutati i filtri numerici

I filtri numerici — tra cui **Age** e **SLA** — offrono un operatore di corrispondenza accanto al valore: **Equals**, **Not Equals**, **Greater Than**, **Greater Than or Equal To**, **Less Than**, **Less Than or Equal To**, **In List**, e **Not In List**. Se si inserisce un valore senza scegliere un operatore, viene applicato **Equals**.

## Filtri SLA

Tre filtri riguardano l'SLA, e rispondono a domande diverse:

| Filtro | Tipo | Cosa corrisponde |
| --- | --- | --- |
| **SLA Expiration Date** | Data, con gli operatori sopra indicati | La data in cui scade l'SLA del Riscontro. |
| **SLA** | Numero, con operatori | **Giorni rimanenti** sull'orologio dell'SLA. I valori negativi indicano un ritardo, quindi `Less Than 0` trova tutto ciò che ha già superato la scadenza, mentre `Less Than 7` trova ciò che scade entro la settimana. |
| **Mitigated Within SLA** | Vero / Falso | Se un Riscontro che **è stato mitigato** è stato mitigato prima della scadenza del suo SLA. |

**Mitigated Within SLA ha un ambito più ristretto di quanto sembri, ed è un punto in cui è facile sbagliare.** Entrambi i valori corrispondono solo a Riscontri **già mitigati** e che **non hanno gravità Info**:

* **True** — mitigato entro o prima della data di scadenza dell'SLA.
* **False** — mitigato dopo la data di scadenza dell'SLA.

Un Riscontro **aperto** già in ritardo non corrisponde a **nessuno dei due** valori, perché non è ancora stato mitigato. Per trovare questi casi, utilizzare invece **SLA** `Less Than 0`. I Riscontri con gravità Info sono esclusi da entrambi i lati.

> Se la configurazione SLA di un Riscontro ha **Cap SLA by CISA KEV Due Date** abilitato, sia **SLA** sia **SLA Expiration Date** riflettono la scadenza ridotta e limitata dal KEV, anziché la normale finestra basata sulla gravità. Non esiste un indicatore separato per questo nei filtri — vedere [EPSS / KEV](/triage_findings/finding_scoring/epss_kev/).

## Riscontri
Questi campi sono specifici dei Riscontri di DefectDojo e vengono utilizzati per organizzare un Riscontro.  Ciascuno di questi filtri corrisponde a una colonna separata nella tabella All Findings.

I Riscontri in DefectDojo possono essere filtrati per:

### Metadati DefectDojo
Questi filtri sono direttamente collegati alle funzionalità principali di DefectDojo.

##### Non modificabili
Questi filtri vengono assegnati al momento della creazione del problema e non possono essere modificati direttamente tramite Edit Finding.

* Finding Severity (una tra Info, Low, Medium, High, Critical)
* Product
* Product Type
* Engagement
* Engagement Version
* Test
* Test Type
* Test Version
* Date Created
* Age (età del Riscontro in giorni)
* SLA (giorni rimanenti sull'orologio dell'SLA — un valore negativo indica un ritardo; vedere [Filtri SLA](#sla-filters))
* SLA Expiration Date (vedere [Filtri SLA](#sla-filters))
* Mitigated Within SLA (Vero o Falso — da notare che corrisponde solo ai Riscontri già Mitigati; vedere [Filtri SLA](#sla-filters))
* Reporter (utente o servizio che ha creato il Riscontro)
* Found by (indica lo strumento)

##### Modificabili
Questi campi vengono impostati alla creazione di un problema, ma possono essere modificati con l'avanzare della sua gestione.

* [Status](/triage_findings/findings_workflows/finding_status_definitions/)
* Last Status Update (Timestamp)
* Mitigated (Vero o Falso)

##### Funzioni aggiuntive del modello
Queste funzioni di DefectDojo possono essere utilizzate per organizzare ulteriormente i Riscontri o per monitorare la remediation.

* Finding Tags
* Reviewers (Assigned User)
* Has Notes (Vero/Falso)
* Group (fa riferimento al [Finding Group](/triage_findings/findings_workflows/editing_findings/#finding-group-actions), se presente)
* Risk Acceptance (selezionare una o più Risk Acceptance esistenti dall'elenco)

### Metadati specifici dello strumento
Questi campi non hanno un impatto diretto sulle funzionalità di DefectDojo, ma forniscono informazioni aggiuntive utili a spiegare e mitigare i problemi.  Possono essere impostati al momento della creazione iniziale di un Riscontro (utilizzando le informazioni presenti in un report in ingresso), oppure possono essere modificati da un utente.

* CWE Value
* Vulnerability ID (di solito un CVE)
* EPSS Score
* EPSS Percentile
* Service
* Planned Remediation Date
* Planned Remediation Version
* Has Component (Vero/Falso)
* Component Name
* Component Version
* File Path
* Effort for Fixing

### Metadati Jira
Se si utilizza l'integrazione Jira, questi filtri tracciano gli aggiornamenti degli Jira Issue collegati.

* Jira Issue (è possibile filtrare in base al fatto che il Riscontro ne abbia uno oppure no)
* Jira Age (età dello Jira Issue)
* Jira Change (ultima volta in cui le modifiche sono state inviate a Jira)
