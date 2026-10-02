---
title: Tabelle delle autorizzazioni per azione
description: Tutte le autorizzazioni utente di DefectDojo Pro in dettaglio
weight: 4
audience: pro
aliases:
- /it/en/customize_dojo/user_management/user_permission_chart
---

> **Funzionalità di DefectDojo Pro.** Il sistema RBAC Membri / Gruppi / Ruoli globali descritto in questa pagina fa parte di DefectDojo Pro. La versione open source di DefectDojo utilizza il modello [Utenti autorizzati](../os__authorized_users/) — consulta quella pagina per il controllo degli accessi nella versione open source, e le [note di aggiornamento alla 3.0](/releases/os_upgrading/3.0/#authorized-users-panel-replaces-membersgroups-under-legacy-authorization) se stai passando da un'edizione all'altra.

## Tabella delle autorizzazioni per ruolo

Questa tabella elenca tutte le autorizzazioni relative a un Prodotto o Tipo di prodotto, oltre a quali autorizzazioni sono disponibili per ciascun ruolo.

I cinque ruoli seguenti sono i **ruoli integrati** di DefectDojo Pro. Sono preset bloccati: le loro autorizzazioni sono identiche su ogni istanza e non possono essere modificate. Se hai creato i tuoi ruoli personalizzati, questa tabella descrive i ruoli integrati da cui sono stati clonati, non i ruoli stessi. Per il catalogo completo delle autorizzazioni che è possibile assegnare a un ruolo, consulta [Ruoli RBAC personalizzati](../pro__custom_rbac_roles/#choosing-permissions).

| **Section** | **Permission** | Reader | Writer | Maintainer | Owner | API Importer |
| --- | --- | --- | --- | --- | --- | --- |
| **Accesso a Prodotto/Tipo di prodotto** | Visualizzare il Prodotto o Tipo di prodotto assegnato ¹ | ☑️ | ☑️ | ☑️ | ☑️ | ☑️ |
|  | Visualizzare Prodotti, Engagement, Test, Riscontri ed Endpoint annidati | ☑️ | ☑️ | ☑️ | ☑️ | ☑️ |
|  | Aggiungere nuovi Prodotti (all'interno del Tipo di prodotto assegnato) ² |  |  | ☑️ | ☑️ |  |
|  | Eliminare i Prodotti o Tipi di prodotto assegnati |  |  |  | ☑️ |  |
| **Appartenenza a Prodotto/Tipo di prodotto** | Aggiungere Utenti come Membri (escluso il Ruolo Owner) |  |  | ☑️ | ☑️ |  |
|  | Modificare i Ruoli dei membri (escluso il Ruolo Owner) |  |  | ☑️ | ☑️ |  |
|  | Modificare i Ruoli dei membri (incluso il Ruolo Owner) |  |  |  | ☑️ |  |
|  | Rimuoversi dall'appartenenza a Prodotto/Tipo di prodotto | ☑️ | ☑️ | ☑️ | ☑️ |  |
|  | Assegnare un Ruolo Owner a un altro Utente |  |  |  | ☑️ |  |
|  | Modificare un'appartenenza a Prodotto/Tipo di prodotto associata all'interno di un Gruppo³ |  |  |  | ☑️ |  |
|  | Eliminare un'appartenenza a Prodotto/Tipo di prodotto associata all'interno di un Gruppo³ |  |  |  |  |  |
| **Engagement** (all'interno di un Prodotto) | Aggiungere, modificare Engagement |  | ☑️ | ☑️ | ☑️ | ☑️ |
|  | Visualizzare le Accettazioni del rischio ⁴ |  | ☑️ | ☑️ | ☑️ |  |
|  | Aggiungere, modificare Accettazioni del rischio |  | ☑️ | ☑️ | ☑️ |  |
|  | Eliminare Engagement |  |  | ☑️ | ☑️ |  |
| **Test** (all'interno di un Prodotto) | Aggiungere Test |  | ☑️ | ☑️ | ☑️ |  |
|  | Modificare Test |  | ☑️ | ☑️ | ☑️ | ☑️ |
|  | Eliminare Test |  |  | ☑️ | ☑️ |  |
| **Riscontri**  (all'interno di un Prodotto) | Aggiungere Riscontri |  | ☑️ | ☑️ | ☑️ |  |
|  | Modificare Riscontri |  | ☑️ | ☑️ | ☑️ |  |
|  | Importare, reimportare risultati della scansione |  | ☑️ | ☑️ | ☑️ | ☑️ |
|  | Eliminare Riscontri |  |  | ☑️ | ☑️ |  |
|  | Aggiungere, modificare, eliminare Gruppi di riscontri |  | ☑️ | ☑️ | ☑️ |  |
| **Altri dati**  (all'interno di un Prodotto) | Aggiungere, modificare Endpoint |  | ☑️ | ☑️ | ☑️ |  |
|  | Eliminare Endpoint |  |  | ☑️ | ☑️ |  |
|  | Modificare Benchmark |  | ☑️ | ☑️ | ☑️ |  |
|  | Eliminare Benchmark |  |  | ☑️ | ☑️ |  |
|  | Visualizzare la cronologia delle Note | ☑️ | ☑️ | ☑️ | ☑️ |  |
|  | Aggiungere, modificare, eliminare le proprie Note | ☑️ | ☑️ | ☑️ | ☑️ | ☑️ |
|  | Modificare le Note di altri utenti |  | ☑️ | ☑️ | ☑️ | ☑️ |
|  | Eliminare le Note di altri utenti |  |  | ☑️ | ☑️ |  |

1. Un utente a cui sono assegnate autorizzazioni solo a livello di Prodotto non può visualizzare il Tipo di prodotto in cui è contenuto.
2. Quando un nuovo Prodotto viene aggiunto sotto un Tipo di prodotto, tutti gli Utenti a livello di Tipo di prodotto verranno aggiunti come Membri del nuovo Prodotto con il loro Ruolo a livello di Tipo di prodotto.
3. L'utente che desidera apportare modifiche a un Gruppo deve anche avere le **Autorizzazioni di configurazione** **Edit Group**, e un **Ruolo di configurazione del Gruppo** di **Maintainer o Owner** nel Gruppo che desidera modificare.
4. La visibilità delle Accettazioni del rischio è regolata da un'autorizzazione minima distinta rispetto alla visibilità dei Riscontri: un Reader sul Prodotto può visualizzare i Riscontri sottostanti ma **non può** visualizzare le Accettazioni del rischio a cui questi Riscontri appartengono. Per dettagli sulle autorizzazioni delle Accettazioni del rischio, sul comportamento della data di scadenza e sui flussi di ripristino, consulta [Accettazioni del rischio (Pro)](/triage_findings/findings_workflows/pro__risk_acceptance/#risk-acceptance-permissions-and-visibility).

## Tabella delle autorizzazioni di configurazione

Ogni Autorizzazione di configurazione si riferisce a una particolare funzione del software e ha un insieme associato di azioni che un utente può eseguire relative a questa funzione.

La maggior parte delle Autorizzazioni di configurazione consente agli utenti di accedere a determinate pagine dell'interfaccia. 

| **Configuration Permission** | **View ☑️** | **Add ☑️** | **Edit ☑️** | **Delete ☑️** |
| --- | --- | --- | --- | --- |
| Credential Manager | Accesso alla pagina **⚙️Configuration \> Credential Manager** | Aggiunta di nuove voci al Credential Manager | Modifica delle voci del Credential Manager | Eliminazione delle voci del Credential Manager |
| Development Environments | n/d | Aggiunta di nuovi Development Environments all'elenco 🗓️**Engagements \> Environments** | Modifica dei Development Environments nell'elenco 🗓️**Engagements \> Environments** | Eliminazione dei Development Environments dall'elenco **🗓️Engagements \> Environments** |
| Finding Templates¹ | Accesso alla pagina **Findings \> Finding Templates** | Aggiunta di un Finding Template | Modifica di un Finding Template | Eliminazione di un Finding Template |
| Groups | Accesso alla pagina **👤Users \> Groups** | Aggiunta di un nuovo Gruppo di utenti | Solo Superuser | Solo Superuser |
| Jira Instances | Accesso alla pagina **⚙️Configuration \> JIRA** | Aggiunta di una nuova configurazione JIRA | Modifica di una configurazione JIRA esistente | Eliminazione di una configurazione JIRA |
| Language Types |  |  |  |  |
| Login Banner | n/d | n/d | Modifica del login banner, disponibile in **⚙️Configuration \> Login Banner** | n/d |
| Announcements | n/d | n/d | Configurazione degli Announcements, disponibile in  **⚙️Configuration \> Announcements** | n/d |
| Note Types | Accesso alla pagina ⚙️Configuration \> Note Types | Aggiunta di un Note Type | Modifica di un Note Type | Eliminazione di un Note Type |
| Prioritization Engines | Accesso alla pagina di configurazione del Prioritization Engine | Aggiunta di un nuovo Prioritization Engine | Modifica di un Prioritization Engine esistente | Eliminazione di un Prioritization Engine |
| Product Types | n/d | Aggiunta di un nuovo Product Type (in Products \> Product Type) | n/d | n/d |
| Questionnaires | Accesso alla pagina **Questionnaires \> All Questionnaires** | Aggiunta di un nuovo Questionnaire | Modifica di un Questionnaire esistente | Eliminazione di un Questionnaire |
| Questions | Accesso alla pagina **Questionnaires \> Questions** | Aggiunta di una nuova Question | Modifica di una Question esistente | n/d |
| Regulations | n/d | Aggiunta di una Regulation alla pagina **⚙️Configuration \> Regulations** | Modifica di una Regulation esistente | Eliminazione di una Regulation |
| Scheduling Service Schedule | Accesso alla pagina **Scheduling** | Solo Superuser | Modifica di uno Schedule esistente (cambio trigger, abilitazione/disabilitazione) | Eliminazione di uno Schedule |
| SLA Configuration | Accesso alla pagina **⚙️Configuration \> SLA Configuration** | Aggiunta di una nuova SLA Configuration | Modifica di una SLA Configuration esistente | Eliminazione di una SLA Configuration |
| Test Types | n/d | Aggiunta di un nuovo Test Type (in **Engagements \> Test Types**) | Modifica di un Test Type esistente | n/d |
| Tool Configuration | Accesso alla pagina **⚙️Configuration \> Tool Configuration** | Aggiunta di una nuova Tool Configuration | Modifica di una Tool Configuration esistente | Eliminazione di una Tool Configuration |
| Tool Types | Accesso alla pagina **⚙️Configuration \> Tool Types** | Aggiunta di un nuovo Tool Type | Modifica di un Tool Type esistente | Eliminazione di un Tool Type |
| Users | Accesso alla pagina **👤Users \> Users** | Aggiunta di un nuovo Utente a DefectDojo | Modifica di un Utente esistente | Eliminazione di un Utente |

1. L'accesso alla pagina Finding Templates richiede anche il Ruolo globale **Writer, Maintainer** o **Owner** per questo utente.

## Autorizzazioni di configurazione del Gruppo

| Configuration Permission | **Reader** | **Maintainer** | **Owner** |
| --- | --- | --- | --- |
| Visualizzare il Gruppo | ☑️ | ☑️ | ☑️ |
| Rimuoversi dal Gruppo | ☑️ | ☑️ | ☑️ |
| Modificare il ruolo di un Membro in un Gruppo |  | ☑️ | ☑️ |
| Modificare o eliminare un'appartenenza a Prodotto o Tipo di prodotto da un Gruppo¹ |  | ☑️ | ☑️ |
| Cambiare il ruolo di un Membro del Gruppo a Owner |  |  | ☑️ |
| Eliminare il Gruppo |  |  | ☑️ |

1. Questo richiede inoltre che l'Utente abbia almeno un Ruolo Maintainer sul Prodotto o Tipo di prodotto che desidera modificare.
