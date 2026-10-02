---
title: Log di audit
description: Accedi ai log di audit per gli oggetti DefectDojo
weight: 1
audience: pro
---

I **Log di audit** forniscono un registro cronologico delle azioni eseguite all'interno di DefectDojo. Garantiscono responsabilità e conformità registrando quale utente ha eseguito quale azione e quando.

I log di audit sono utili per:
- **Indagini di sicurezza**: determinare chi ha eseguito azioni sensibili.
- **Conformità**: dimostrare una cronologia verificabile per standard come SOC 2, ISO 27001 o requisiti di governance interni.
- **Risoluzione dei problemi**: identificare quando una configurazione o un oggetto è cambiato.
- **Responsabilità**: tracciare l'attività amministrativa e degli utenti sulla piattaforma.

In sintesi, i Log di audit forniscono un registro centralizzato degli eventi importanti che aiuta gli amministratori a comprendere la cronologia delle attività della propria istanza, al di là della cronologia di un singolo oggetto.

### Accesso ai Log di audit

I Log di audit sono accessibili tramite la barra laterale, all'interno del sottomenu Configurazioni.

![image](images/auditlogs_ss2.png)

### Autorizzazioni

L'accesso ai Log di audit è determinato dal ruolo globale di un Utente.

I ruoli globali API Importer, Reader e Writer non consentono l'accesso ai Log di audit, mentre i ruoli Maintainer e Owner sì. Anche i Superuser hanno accesso ai Log di audit indipendentemente dal proprio ruolo globale.

Ulteriori informazioni sulle autorizzazioni e sui ruoli globali sono disponibili [qui](/admin/user_management/pro_permissions_overhaul/).

## Contenuto dei Log di audit

I Log di audit tracciano una varietà di azioni, tra cui, a titolo esemplificativo ma non esaustivo:
- Interazioni con gli oggetti (ad es. creazione, aggiornamento o eliminazione di oggetti).
- Aggiornamenti alla priorità e al punteggio di rischio di un Riscontro.
- Creazione e modifica dei profili Utente.
- Aggiornamenti del percentile EPSS.

L'elenco completo delle modifiche e delle azioni registrate nei Log di audit è disponibile [qui](../pro__audit_log_index/).

## Tabella dei Log di audit

I Log di audit includono più colonne con vari dati per migliorare la tracciabilità, tra cui:
- **Timestamp**: il momento in cui è avvenuta la modifica.
- **User**: l'utente che ha eseguito l'azione.
- **Action**: quale azione è stata eseguita (ad es. creazione, aggiornamento, eliminazione).
- **Model**: quale aspetto è stato modificato (ad es. Asset, User, Finding, Location, Firewall, URL, ecc.).
- **Object ID**: l'ID univoco di DefectDojo per l'oggetto modificato.
- **Object Name**: il nome dell'oggetto interessato.
- **Changes**: i campi specifici modificati dall'azione, inclusi i valori precedenti e aggiornati.
- **Data**: uno snapshot esatto del record nel momento in cui è stata eseguita l'azione, inclusi tutti i campi, non solo quelli modificati.
- **Context**: dettagli sul contesto di come è avvenuta la modifica, chi l'ha effettuata, da dove nell'app proviene e un'etichetta che indica quale job ha eseguito la modifica (se si trattava di un job automatizzato).
- **URL**: l'URL utilizzato per eseguire l'operazione specifica. Questi percorsi possono fare riferimento alla Vue UI di DefectDojo o alla REST API. Il campo URL non verrà popolato per i processi back-end.
- **IP Address**: l'indirizzo di rete del dispositivo che ha effettuato la modifica. Non verrà popolato per i processi back-end.

### Cronologia dei Log di audit

Per impostazione predefinita, i Log di audit mostrano le voci degli ultimi 31 giorni. Le voci più vecchie restano disponibili e possono essere visualizzate modificando il filtro Timestamp.

![image](images/auditlogs_ss3.gif)

### Filtrare i Log di audit

La tabella dei Log di audit include filtri che aiutano a restringere i risultati visualizzati. Ad esempio, se si desidera vedere solo le azioni relative agli Asset, è possibile filtrare per Asset all'interno della tabella.

![image](images/auditlogs_ss1.png)

Le colonne all'interno dei Log di audit possono anche essere ordinate in ordine alfabetico, crescente/decrescente o cronologico, a seconda del contenuto della colonna in questione. Le colonne possono inoltre essere trascinate a sinistra o a destra in base alla disposizione preferita.

![image](images/auditlogs_ss4.gif)

## Cronologia oggetto

La **Cronologia oggetto** fornisce un registro cronologico delle modifiche apportate a un singolo oggetto DefectDojo (ad es. Organization, Asset, Engagement, Test, Riscontri, Endpoint e Accettazioni del rischio). Ogni voce include dettagli come timestamp, utente, azione eseguita e le modifiche associate.

A differenza dei Log di audit, che registrano eventi sull'intera istanza, la Cronologia oggetto riguarda esclusivamente l'attività di un singolo oggetto, rendendo più facile comprendere la cronologia di un oggetto senza dover filtrare eventi di sistema non correlati.

La Cronologia oggetto è utile per:
- Rivedere l'evoluzione di un oggetto nel tempo.
- Determinare quando è stata effettuata una modifica.
- Identificare quale utente ha apportato una modifica.
- Risolvere modifiche inattese.

### Accesso alla Cronologia oggetto

È possibile accedere alla Cronologia oggetto tramite il menu a forma di ingranaggio nell'angolo in alto a destra della visualizzazione di qualsiasi oggetto. Solo gli Utenti con accesso all'oggetto in questione possono visualizzarne la Cronologia oggetto.

### Log di audit e Cronologia oggetto

Sebbene le funzioni di Log di audit e Cronologia oggetto si sovrappongano, operano su ambiti diversi. La Cronologia oggetto si concentra sulle modifiche apportate ai singoli oggetti, mentre i Log di audit forniscono un registro a livello di sistema degli eventi significativi in tutta l'istanza DefectDojo, offrendo una visione più ampia e d'insieme dell'attività.

## Endpoint

### Endpoint della Cronologia oggetto (solo Pro)

Gli utenti <span style="background-color:rgba(242, 86, 29, 0.3)">DefectDojo Pro</span> hanno accesso a un percorso API `/history` per questi oggetti per visualizzare dati simili. Ad esempio: `/api/v2/findings/{id}/history/`.

### Endpoint dei Log di audit (solo Pro)

Gli utenti <span style="background-color:rgba(242, 86, 29, 0.3)">DefectDojo Pro</span> hanno inoltre accesso a un endpoint dedicato `/audit_log` per l'intera istanza. Questo log è accessibile solo da utenti o token API con autorizzazioni superuser.

Questa API restituisce 31 giorni di log di audit.

* L'invio di parametri predefiniti o vuoti restituirà gli ultimi 31 giorni di log di audit.

* Il parametro `window_month` accetta un mese e un anno nel formato MM-YYYY e fornisce i log di audit per quel mese.
* È possibile impostare il parametro `window_start` per limitare questi log a un intervallo più breve, invece di restituire l'intero mese.

Per ulteriori informazioni, consulta la documentazione API disponibile nella tua istanza: `your-instance.cloud.defectdojo.com/api/v2/oa3/swagger-ui/`.
