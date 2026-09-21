---
title: Gestione utenti
description: Gestisci utenti, controllo degli accessi e autenticazione in DefectDojo
summary: ''
date: 2023-09-07 16:06:50+02:00
lastmod: 2023-09-07 16:06:50+02:00
draft: false
weight: 5
chapter: true
seo:
  title: ''
  description: ''
  canonical: ''
  robots: ''
exclude_search: true
---

La gestione utenti di DefectDojo è diversa in ciascuna edizione. Scegli la sezione che corrisponde alla tua installazione.

## DefectDojo Open-Source

DefectDojo open-source utilizza il modello **Utenti autorizzati**: a un utente viene concesso l'accesso a un Prodotto o a un Tipo di prodotto aggiungendolo all'elenco Utenti autorizzati di quel record. I Superuser e lo staff possono vedere tutto.

* [Utenti autorizzati](./os__authorized_users/) — come concedere l'accesso a Prodotti e Tipi di prodotto

L'autenticazione su DefectDojo open-source si basa su nome utente/password locali, oltre al flusso di reset della password.

## DefectDojo Pro

DefectDojo Pro utilizza un sistema basato sui ruoli con Membri, Gruppi e Ruoli globali. Agli utenti può inoltre essere concesso l'accesso SSO tramite SAML o uno dei provider OAuth supportati.

* [Autorizzazioni in DefectDojo](./about_perms_and_roles/) — panoramica di Ruoli, Appartenenze, Ruoli globali e Autorizzazioni di configurazione
* [Imposta le autorizzazioni di un utente](./set_user_permissions/) — assegnazione di Ruoli, Ruoli globali e Autorizzazioni di configurazione
* [Condividi le autorizzazioni: Gruppi di utenti](./create_user_group/) — assegnazione delle autorizzazioni a molti utenti contemporaneamente
* [Imposta le autorizzazioni in Pro](./pro_permissions_overhaul/) — interfaccia specifica di Pro per la gestione di Membri e Autorizzazioni
* [Reimpostazione in blocco delle credenziali utente](./pro__resetting_user_credentials/) — ruota i token API e forza il reset della password per molti utenti contemporaneamente
* [Tabelle delle autorizzazioni per azione](./user_permission_chart/) — riferimento completo di ogni autorizzazione per ogni Ruolo predefinito
* [Ruoli RBAC personalizzati](./pro__custom_rbac_roles/) — crea i tuoi ruoli scegliendo le singole autorizzazioni
* [Single Sign-On](/admin/sso/) — configurazione SAML e OAuth per Pro

## Migrazione tra edizioni

Se stai passando dagli Utenti autorizzati di open-source all'RBAC di Pro, oppure stai eseguendo l'aggiornamento da una versione open-source precedente alla 3.0 che utilizzava l'RBAC verso l'attuale modello Utenti autorizzati, consulta le [note di aggiornamento alla 3.0](/releases/os_upgrading/3.0/#authorized-users-panel-replaces-membersgroups-under-legacy-authorization). L'accesso esistente viene preservato automaticamente.
