---
title: Endpoint Meta Importer
description: Applica in blocco tag e campi personalizzati agli endpoint tramite CSV
weight: 4
audience: opensource
---

L'**Endpoint Meta Importer** ti permette di applicare tag e campi personalizzati a un gran numero di endpoint contemporaneamente utilizzando un file CSV. Questo è particolarmente utile per le organizzazioni che eseguono scansioni intensive dell'infrastruttura, dove gli endpoint necessitano di metadati flessibili per il filtraggio, l'ordinamento e la reportistica.

## Formato CSV

Il file CSV deve avere una colonna `hostname` (obbligatoria), più un numero qualsiasi di colonne aggiuntive che rappresentano i tag o i campi personalizzati che vuoi applicare. Ogni nome di colonna aggiuntiva diventa la chiave del tag/campo, e il valore della sua riga diventa il valore del tag/campo.

**Esempio:**

```
hostname,team,public_facing
sheets.google.com,data analytics,yes
docs.google.com,language processing,yes
feedback.internal.google.com,human resources,no
```

Questo applicherebbe i seguenti metadati:

| Endpoint | Tag / Campi personalizzati |
|---|---|
| `sheets.google.com` | `team:data analytics`, `public_facing:yes` |
| `docs.google.com` | `team:language processing`, `public_facing:yes` |
| `feedback.internal.google.com` | `team:human resources`, `public_facing:no` |

## Requisiti

- La colonna `hostname` è **obbligatoria**. Viene usata per trovare endpoint esistenti con un host corrispondente, o per creare nuovi endpoint se non viene trovata alcuna corrispondenza.
- Tutti gli altri nomi di colonna sono trattati come chiavi di tag/campi personalizzati.
- I valori vengono archiviati nel formato `key:value`.

## Utilizzo dell'Endpoint Meta Importer

L'Endpoint Meta Importer è disponibile nella scheda **Endpoints** quando visualizzi un Prodotto. Carica lì il tuo file CSV per applicare i metadati ai tuoi endpoint in blocco.
