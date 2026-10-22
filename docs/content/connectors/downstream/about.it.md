---
title: Connettori a valle
weight: 1
audience: pro
aliases:
- /it/en/share_your_findings/integrations
- /it/issue_tracking/pro_integration/integrations/
---

**Disponibilità:** i Connettori a valle sono generalmente disponibili e attivi su ogni istanza di DefectDojo Pro, sia Cloud che On-Premise. Non c'è nulla da abilitare e non sono più elencati nella pagina Feature Flags.

I Connettori a valle consentono di inviare i Riscontri e i Gruppi di riscontri a sistemi di ticket tracking, per integrare facilmente la remediation della sicurezza con i flussi di lavoro di sviluppo già in uso dal team.

Connettori a valle supportati:
- Azure Devops
- Bitbucket
- Freshservice
- GitHub
- GitLab Boards
- Jira
- Linear
- Opsgenie
- PagerDuty
- ServiceDesk Plus
- ServiceNow
- ServiceNow SecOps / Vulnerability Response
- Shortcut
- Zendesk

## Apertura della pagina Connettori a valle

La pagina Connettori a valle si trova in **Import > Connectors > Downstream Connectors** nella barra laterale.

![image](images/integrators_3.png)

## Configurazione di un Connettore a valle

Un Connettore a valle è configurato con tre componenti principali:

- **Istanza di integrazione**: è il metodo di connessione primario che DefectDojo utilizzerà con un sistema di terze parti. L'Istanza include dettagli come un'etichetta, una posizione e le credenziali con cui connettersi, oltre a qualsiasi altra informazione richiesta dal fornitore.
- **Mappatura dell'Issue Tracker**: è il punto in cui vengono memorizzate le informazioni di mappatura, ovvero i dettagli necessari per connettersi a un determinato "progetto" all'interno del fornitore. Questi dettagli includono il nome o l'ID del "progetto" e le mappature tra la gravità e lo stato dei Riscontri di DefectDojo e il campo corrispondente nel "ticket" del fornitore. È possibile configurare più mappature se si desidera inviare i Riscontri a più "progetti".
- **Assegnazione dell'Issue Tracker**: è il punto in cui i Prodotti e gli Engagement di DefectDojo vengono assegnati a una determinata Mappatura dell'Issue Tracker, con opzioni per Prodotto/Engagement che definiscono come un Riscontro verrà inviato a un determinato sistema del fornitore.

Questi componenti sono gerarchici: ogni **Istanza** ha una o più **Mappature**, che a loro volta hanno una o più **Assegnazioni dell'Issue Tracker**.

![image](images/integrators_2.png)

## Invio di Riscontri e Gruppi di riscontri

Una volta configurati questi componenti, i Riscontri e i Gruppi di riscontri possono essere inviati a un determinato Issue Tracker in due modi: manualmente o automaticamente.

- **Manualmente**: i Riscontri e i Gruppi di riscontri contenuti in un Prodotto/Engagement con una Mappatura dell'Issue Tracker assegnata avranno un'opzione "Push to Integrator". Questa creerà un Issue nell'Issue Tracker con le informazioni corrispondenti del Riscontro/Gruppo di riscontri. Push to Integrator può essere usato anche per aggiornare un Issue esistente.

### Invio automatico dei Riscontri

I Riscontri possono anche essere inviati automaticamente, con l'**Assegnazione dell'Issue Tracker** che stabilisce come questi oggetti verranno inviati. Sono disponibili quattro opzioni:

- **Only Explicitly Publish Changes to Target**: questa opzione disabilita qualsiasi comportamento automatico nel Prodotto o Engagement assegnato. L'unico modo per inviare un Riscontro o un Gruppo di riscontri sarà farlo esplicitamente, come descritto sopra.
- **Automatically Link New Finding to Target**: quando nuovi Riscontri o Gruppi di riscontri vengono **creati** nel Prodotto o Engagement assegnato, DefectDojo invierà automaticamente l'oggetto all'Issue Tracker. Una volta creati, questi Riscontri o Gruppi di riscontri non verranno aggiornati senza un'azione manuale di Push to Integrator.
- **Automatically Update Existing Link on Finding Edit**: quando i Riscontri o i Gruppi di riscontri vengono **aggiornati** nel Prodotto o Engagement assegnato, l'oggetto viene inviato automaticamente all'Issue Tracker se un collegamento esistente è già stato creato manualmente.
- **Automatically Link New and Update Existing Link on Finding Edit**: quando i Riscontri o i Gruppi di riscontri vengono creati **o** aggiornati nel Prodotto o Engagement assegnato, l'oggetto viene inviato automaticamente all'Issue Tracker.

#### Filtri di invio

Ogni Assegnazione dell'Issue Tracker può facoltativamente restringere quali Riscontri vengono inviati **automaticamente**:

- **Minimum Severity**: crea automaticamente i ticket solo per i Riscontri con gravità pari o superiore a quella selezionata. Lasciare vuoto per includere tutte le gravità.
- **Active findings only**: crea automaticamente i ticket solo per i Riscontri attivi, escludendo quelli già mitigati, falsi positivi o con rischio accettato nel momento in cui l'assegnazione li rileva per la prima volta.

Questi filtri si applicano solo alla **creazione** automatica. Gli aggiornamenti a un Riscontro che ha già un ticket collegato vengono sempre inviati, quindi i cambiamenti di stato (comprese le chiusure) continuano a essere propagati. Un **Push to Integrator** manuale ignora sempre i filtri. Lasciare entrambi i valori predefiniti mantiene il comportamento originale di invio di ogni Riscontro.

#### Assegnazione di più Prodotti

Un'Assegnazione dell'Issue Tracker punta a un singolo Prodotto o Engagement. Per coprire più asset, creare un'Assegnazione per ogni Prodotto (o Engagement). Se è inoltre necessario che i campi del fornitore differiscano per asset — ad esempio un diverso **Assignment group** o **Assigned to** di ServiceNow, oppure un progetto Jira diverso — creare una Mappatura dell'Issue Tracker separata (con le proprie Mappature dei campi personalizzati) per ciascun asset e far puntare ogni Assegnazione alla Mappatura corrispondente.

## Rappresentazione del ticket dell'Issue Tracker

I ticket dell'Issue Tracker sono rappresentati da una serie di icone nella colonna "Integrator Tickets" durante la visualizzazione e l'elenco
dei Riscontri e dei Gruppi di riscontri

Icone da sinistra a destra:

- **Integration Type**: il tipo di Issue Tracker a cui è associato il ticket
- **Ticket ID**: l'ID del ticket, come definito dall'Issue Tracker
- **Ticket Link**: il collegamento diretto al ticket, come definito dall'Issue Tracker
- **Changelog**: indica quando il ticket dell'Issue Tracker è stato associato a un Riscontro o Gruppo di riscontri, oltre all'ultima volta che DefectDojo ha apportato una modifica al ticket

![image](images/integrators_1.png)

## Requisiti specifici per fornitore

Ogni fornitore avrà requisiti diversi per il modo in cui DefectDojo dovrà interagire con esso. Questo può presentarsi sotto forma di un meccanismo di autenticazione, campi aggiuntivi su base "progetto" o mappature di gravità/stato.

Per l'elenco completo dei requisiti, aprire le pagine specifiche per fornitore riportate di seguito:

- [Azure Devops](/connectors/downstream/downstream_toolreference/#azure-devops-boards)
- [Bitbucket](/connectors/downstream/downstream_toolreference/#bitbucket)
- [Freshservice](/connectors/downstream/downstream_toolreference/#freshservice)
- [GitHub](/connectors/downstream/downstream_toolreference/#github)
- [GitLab Boards](/connectors/downstream/downstream_toolreference/#gitlab)
- [Jira](/connectors/downstream/downstream_toolreference/#jira)
- [Linear](/connectors/downstream/downstream_toolreference/#linear)
- [Opsgenie](/connectors/downstream/downstream_toolreference/#opsgenie)
- [PagerDuty](/connectors/downstream/downstream_toolreference/#pagerduty)
- [ServiceDesk Plus](/connectors/downstream/downstream_toolreference/#servicedesk-plus)
- [ServiceNow](/connectors/downstream/downstream_toolreference/#servicenow)
- [ServiceNow SecOps / Vulnerability Response](/connectors/downstream/downstream_toolreference/#servicenow-secops)
- [Shortcut](/connectors/downstream/downstream_toolreference/#shortcut)
- [Zendesk](/connectors/downstream/downstream_toolreference/#zendesk)

## Gestione degli errori e debug

I Connettori a valle possono generare errori per svariati motivi, come problemi di connettività, autenticazione, permessi, ecc. Per facilitare
il debug di questi errori, ogni Mappatura dell'Issue Tracker dispone di una tabella di errori che elenca quando si è verificato l'errore, il motivo per cui si è
verificato e il Riscontro o Gruppo di riscontri che non è stato possibile inviare.

Questi errori si trovano nella pagina All Issue Tracker Mappings & Assignments, nella colonna ⚠️ Total Errors.

![image](images/integrators_4.png)

Facendo clic sulla voce Total Errors si accede a una pagina con descrizioni più dettagliate degli errori associati a questo Connettore a valle.

### Vedere tutti i fallimenti in un unico posto

La tabella degli errori per singola mappatura copre un solo Connettore a valle. [Diagnostics](/admin/diagnostics/pro__diagnostics/) li copre tutti, insieme a ogni altro tentativo di integrazione sull'istanza — connettori a monte, importazioni, Jira, SSO e il motore delle regole — con lo stesso filtraggio e ordinamento su tutto quanto.

Usarla quando la domanda è più ampia di una singola mappatura:

* un tentativo che **non si è mai concluso** piuttosto che fallito, cosa che nessuna tabella degli errori riporta, perché non si è verificato alcun errore
* se un fallimento è specifico di un'integrazione o si sta verificando contemporaneamente su più integrazioni
* chi o cosa ha avviato un tentativo, e rispetto a quale configurazione

Le credenziali citate in un errore vengono rimosse prima che la riga venga memorizzata, e il dettaglio tecnico completo è riservato ai superuser.

## Struttura della pagina Connettori a valle

I Connettori a valle sono elencati in due sezioni, **Configured Connectors** e **Available Connectors**, ciascuna ordinata alfabeticamente con un conteggio di quanto viene mostrato accanto al proprio titolo. Uno strumento può contenere più configurazioni; ciascuna è un riquadro a sé, intitolato `<Tool> - <label>`, ordinato per etichetta. Il riquadro **Request Downstream Connector** su DefectDojo Pro Cloud non viene conteggiato.
