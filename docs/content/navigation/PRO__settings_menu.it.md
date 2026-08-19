---
title: Il menu Impostazioni
description: Come è organizzata la sezione Impostazioni della barra laterale di DefectDojo
  Pro, la pagina directory All Settings e come passare tra il layout attuale e quello
  precedente
weight: 6
audience: pro
---

La sezione Settings della barra laterale raggruppa tutte le pagine amministrative di DefectDojo Pro. Il layout visualizzato dipende dal momento in cui è stata creata l'istanza:

- Le **nuove installazioni** si aprono con il layout riorganizzato descritto di seguito.
- Le **installazioni esistenti** mantengono il layout precedente finché un amministratore non attiva **Menu 2.0** (vedere [Passare da un layout all'altro](#switching-layouts)).

In entrambi i casi, **ogni pagina delle impostazioni mantiene lo stesso URL**. I segnalibri, i link salvati e qualsiasi riferimento nei propri runbook continuano a funzionare indipendentemente dal layout attivo.

## Il layout riorganizzato

Settings è suddiviso in sette gruppi, denominati in base a ciò che si sta cercando di fare, piuttosto che in base alla parte del sistema coinvolta.

| Gruppo | Cosa contiene |
| --- | --- |
| **System** | System Settings, Appearance, Announcement Banner, Login Banner, E-mail, Feature Flags |
| **Users & Permissions** | Users, Groups, Roles |
| **Finding Workflow** | le tre pagine Deduplication, Finding Enrichment, Service Level Agreements, Prioritization Engines, Mitigation Policies |
| **Configuration** | Environments, Regulations, Note Types, Test Types, CI/CD Infrastructure, Tool Types, Tool Configurations |
| **Notifications** | Notification Events, Notification Webhooks |
| **Operations** | Audit Logs, Usage Logs, Schedules, Celery Status e — su DefectDojo Cloud — Message Portal, Firewall Rules, Maintenance Windows |
| **License & Support** | License Manager, Version Manager, Contact Support |

Sono visibili solo le voci che l'account è autorizzato ad aprire, e un gruppo scompare del tutto quando nessuna delle sue pagine è disponibile per l'utente.

Vale la pena conoscere due convenzioni:

- **Non esistono voci "New" separate.** Ogni pagina elenco ha un pulsante **New** che apre il modulo di creazione, quindi il menu presenta una sola voce per catalogo anziché due. Se l'account può creare un record ma non elencarli, la voce di menu porta direttamente al modulo di creazione.
- **Nulla si annida per più di un livello sotto un gruppo.** Per raggiungere una pagina bastano al massimo Settings → gruppo → pagina.

## All Settings

La prima voce della sezione, **All Settings**, apre una directory di tutte le pagine delle impostazioni raggiungibili dall'account, organizzate negli stessi gruppi del menu e ricercabili per nome o per funzione della pagina. Cercando `deduplication` si trovano le tre pagine di deduplicazione *e* System Settings, poiché anche System Settings contiene opzioni di deduplicazione.

L'ultima categoria, **Elsewhere in the app**, elenca le pagine che configurano DefectDojo ma che si trovano in altre sezioni della barra laterale — i provider di autorizzazione, le impostazioni Login e MFA, le istanze Jira, i connettori Upstream e Downstream, e l'Universal Parser. Ogni riquadro è contrassegnato con un'etichetta che indica la sezione di appartenenza.

## Cosa è cambiato di posto

Per chi è abituato al layout precedente:

| Prima | Ora |
| --- | --- |
| Settings → *(livello superiore)* → Feature Flags | Settings → System → Feature Flags |
| Settings → Pro Settings → System Settings | Settings → System → System Settings |
| Settings → Pro Settings → Appearance | Settings → System → Appearance |
| Settings → Pro Settings → Banner Settings → Announcement Banner Settings | Settings → System → Announcement Banner |
| Settings → Pro Settings → Banner Settings → Login Banner Settings | Settings → System → Login Banner |
| Settings → Pro Settings → E-mail Settings | Settings → System → E-mail |
| Settings → Users → All Users / New User | Settings → Users & Permissions → Users |
| Settings → Users → All Groups / New Group | Settings → Users & Permissions → Groups |
| Settings → Users → Roles | Settings → Users & Permissions → Roles |
| Settings → Pro Settings → Deduplication Settings → *(tre pagine)* | Settings → Finding Workflow → Same Tool / Cross Tool / Reimport Deduplication |
| Settings → Pro Settings → Finding Enrichment Settings | Settings → Finding Workflow → Finding Enrichment |
| Settings → Configuration → Service Level Agreements | Settings → Finding Workflow → Service Level Agreements |
| Settings → Configuration → Prioritization Engines | Settings → Finding Workflow → Prioritization Engines |
| Settings → Configuration → Mitigation Policies | Settings → Finding Workflow → Mitigation Policies |
| Settings → Configuration → *(cataloghi di dati di riferimento)* | Settings → Configuration → *(invariato)* |
| Settings → Pro Settings → Notification Settings | Settings → Notifications |
| Settings → Configuration → Audit Logs | Settings → Operations → Audit Logs |
| Settings → Configuration → Usage log | Settings → Operations → Usage Logs |
| Settings → Configuration → All Schedules | Settings → Operations → Schedules |
| Settings → Pro Settings → Celery Status | Settings → Operations → Celery Status |
| Settings → Cloud Manager → *(pagine cloud)* | Settings → Operations |
| Settings → License Manager / Version Manager / Contact Support | Settings → License & Support |

Il gruppo che prendeva il nome dal pacchetto di licenza — **Pro Settings** su un'istanza Pro, **Enterprise Settings** su una Enterprise — non esiste più. Le sue pagine sono distribuite tra System, Finding Workflow, Notifications e Operations.

## Passare da un layout all'altro

**Menu 2.0** nella pagina [Feature Flags](/admin/feature_flags/pro__feature_flags/) controlla quale layout è attivo. Attivarlo o disattivarlo rimodella immediatamente la barra laterale; non è necessario alcun riavvio e nient'altro nell'istanza cambia.

Le nuove installazioni partono con l'opzione attivata. Le installazioni esistenti partono con l'opzione disattivata, in modo che un aggiornamento non riorganizzi mai il menu sotto un team a metà lavoro — attivarla quando gli amministratori sono pronti.

Quando è disattivata, la pagina **All Settings** non è disponibile e il suo URL restituisce Not Found.
