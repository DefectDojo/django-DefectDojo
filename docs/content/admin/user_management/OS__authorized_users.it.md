---
title: Permessi Open Source
description: Come viene concesso l'accesso a Prodotti e Tipi di prodotto in DefectDojo
  open source
weight: 1
audience: opensource
---

DefectDojo open source controlla l'accesso a Prodotti e Tipi di prodotto con il modello **Authorized Users**. Ogni Prodotto e Tipo di prodotto ha un pannello Authorized Users che elenca le persone che possono vedere quel record e i dati annidati al suo interno.

Se utilizzi DefectDojo Pro, questo articolo non si applica alla tua installazione — Pro utilizza un sistema basato sui ruoli più ricco, descritto in [Permessi in DefectDojo](../about_perms_and_roles/).

## Come viene concesso l'accesso

Esistono due elenchi, ed è sufficiente che un utente compaia in uno solo di essi per ottenere l'accesso:

- **L'elenco Authorized Users di un Prodotto** concede l'accesso a quel singolo Prodotto, oltre a tutto ciò che è annidato al suo interno (i suoi Engagement, Test, Riscontri ed Endpoint).
- **L'elenco Authorized Users di un Tipo di prodotto** concede l'accesso al Tipo di prodotto stesso **e si propaga a cascata a ogni Prodotto sottostante**. Un utente autorizzato su un Tipo di prodotto non deve essere aggiunto anche a ogni Prodotto figlio — è già coperto.

Non esistono ruoli, gruppi o ruoli globali. Un utente è presente nell'elenco (oppure è un superuser/membro dello staff — vedi sotto), oppure non può vedere il Prodotto.

## Superuser e staff bypassano gli elenchi

Gli utenti contrassegnati come **superuser** o **staff** in DefectDojo possono vedere e agire su ogni Prodotto e Tipo di prodotto indipendentemente dagli elenchi Authorized Users. Gli elenchi esistono per concedere l'accesso agli utenti non staff; non limitano lo staff o i superuser.

Il primo account creato su un'installazione nuova di DefectDojo è automaticamente un superuser.

## Chi può modificare gli elenchi

Solo gli utenti **superuser** o **staff** vedono i controlli per aggiungere o rimuovere persone da un pannello Authorized Users. Chiunque altro abbia accesso a un Prodotto o Tipo di prodotto vede il pannello come un elenco di sola lettura — utile per scoprire chi altro fa parte del team, ma non per modificarne l'appartenenza.

## Dove si trova il pannello

Il pannello Authorized Users compare in due pagine nell'interfaccia classica:

- La **pagina dei dettagli del Prodotto** ha un pannello Authorized Users per quel Prodotto. Supporta due azioni per gli utenti staff:
  - **Aggiungere un utente all'elenco Authorized Users del Prodotto**
  - **Rimuovere un utente dall'elenco Authorized Users del Prodotto**
- La **pagina dei dettagli del Tipo di prodotto** ha un pannello Authorized Users per quel Tipo di prodotto, con le due azioni corrispondenti:
  - **Aggiungere un utente all'elenco Authorized Users del Tipo di prodotto**
  - **Rimuovere un utente dall'elenco Authorized Users del Tipo di prodotto**

Quando rimuovi un utente dall'elenco di un Tipo di prodotto, viene rimossa anche la cascata — perde l'accesso a ogni Prodotto figlio, a meno che non sia ancora presente nell'elenco di uno specifico Prodotto, oppure sia staff/superuser.

## Scegliere tra accesso a livello di Prodotto o di Tipo di prodotto

Alcune regole pratiche:

- Se una persona deve vedere ogni Prodotto sotto una categoria (ad esempio, ogni Prodotto di proprietà di un determinato team), inseriscila nell'elenco del **Tipo di prodotto** e lascia che sia la cascata a occuparsi del resto.
- Se una persona deve vedere solo uno specifico Prodotto, inseriscila nell'elenco di quel **Prodotto**.
- Se ti accorgi di aggiungere la stessa persona a molti singoli Prodotti sotto un unico Tipo di prodotto, è un segnale che dovresti invece aggiungerla al Tipo di prodotto.

## Provenendo da una versione precedente di DefectDojo

DefectDojo open source è tornato al modello Authorized Users nella versione 3.0. Se stai eseguendo l'aggiornamento da una release che utilizzava il sistema Members / Groups / Global Roles, il tuo accesso esistente viene riportato automaticamente in Authorized Users dall'aggiornamento — non è necessaria alcuna mappatura manuale.

L'aggiornamento include un comando di gestione di sola lettura, `preview_legacy_authorization_migration`, che riassume cosa cambierebbe un aggiornamento a fronte di una copia del tuo database. Il flusso di lavoro consigliato è installare la 3.0 in un ambiente di staging con uno snapshot della produzione, eseguire il comando, rivedere il riepilogo e quindi aggiornare la produzione.

Se ti stai muovendo nella direzione opposta — da open source a DefectDojo Pro — Pro include un comando `reconcile_authorized_users_to_rbac` che riporta l'accesso Authorized Users nell'RBAC di Pro. Supporta `--dry-run` ed è idempotente.

Per maggiori dettagli su entrambi i percorsi, consulta le [note di aggiornamento della 3.0](/releases/os_upgrading/3.0/#authorized-users-panel-replaces-membersgroups-under-legacy-authorization).
