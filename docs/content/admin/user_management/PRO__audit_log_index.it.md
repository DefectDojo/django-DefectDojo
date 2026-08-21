---
title: Registrazione degli audit
description: Ogni azione di creazione, modifica ed eliminazione che DefectDojo registra
  nel proprio log di audit, oltre a cosa viene acquisito e come configurare la conservazione.
draft: false
weight: 4
---

DefectDojo registra una cronologia di controllo (audit trail) delle modifiche ai propri dati.  Ogni oggetto monitorato registra automaticamente eventi di **create**, **update** e **delete**, e le tabelle di relazione (molti-a-molti) registrano eventi di **add** e **remove**.

## Come funziona

Il tracciamento degli audit è guidato da trigger di database registrati per ciascun modello. Per ogni
oggetto monitorato, possono scattare tre tipi di evento:

| Tipo di evento    | Quando scatta                                                                 | Azione     |
| ------------- | ----------------------------------------------------------------------------- | ---------- |
| `InsertEvent` | Viene creato un nuovo record                                                        | **Create** |
| `UpdateEvent` | Un record cambia — solo quando il valore di un campo reale cambia effettivamente               | **Update** |
| `DeleteEvent` | Un record viene eliminato                                                            | **Delete** |

Le tabelle di relazione molti-a-molti (tag, revisori, intervalli IP del firewall) tracciano
solo **add** (`InsertEvent`) e **remove** (`DeleteEvent`) — non esiste un
"update" per una riga di relazione.

### Cosa viene acquisito con ogni evento

- **Who** — l'utente che ha eseguito l'azione, ricavato dal contesto della richiesta.
- **When** — un timestamp.
- **Source IP** — l'indirizzo remoto, rispettando le catene di proxy `X-Forwarded-For`.
- **Before/after snapshot** — i valori completi dei campi del record.
- **Context / label** — raggruppa gli eventi originati dalla stessa richiesta. L'etichetta
  `initial_backfill` contrassegna i record storici importati quando il tracciamento è stato
  attivato per la prima volta.

Gli eventi prodotti dai job in background vengono ricollegati al contesto della
richiesta di origine, così un'azione completata in modo asincrono viene comunque
attribuita all'utente che l'ha avviata.

## Core (Open Source) — azioni monitorate

| Oggetto                         | Create | Update | Delete | Note                                          |
| ------------------------------ | :----: | :----: | :----: | ---------------------------------------------- |
| Utente                           |   ✅   |   ✅   |   ✅   | `password` esclusa dagli snapshot             |
| Tipo di prodotto                   |   ✅   |   ✅   |   ✅   |                                                |
| Prodotto                        |   ✅   |   ✅   |   ✅   |                                                |
| Engagement                     |   ✅   |   ✅   |   ✅   |                                                |
| Test                           |   ✅   |   ✅   |   ✅   |                                                |
| Riscontro                        |   ✅   |   ✅   |   ✅   |                                                |
| Gruppo di Riscontri                  |   ✅   |   ✅   |   ✅   |                                                |
| Modello di Riscontro               |   ✅   |   ✅   |   ✅   |                                                |
| Accettazione del rischio                |   ✅   |   ✅   |   ✅   |                                                |
| Endpoint                       |   ✅   |   ✅   |   ✅   |                                                |
| Posizione                       |   ✅   |   ✅   |   ✅   |                                                |
| URL                            |   ✅   |   ✅   |   ✅   |                                                |
| Webhook di Notifica           |   ✅   |   ✅   |   ✅   | `header_name` / `header_value` esclusi (segreti) |

### Core — eventi di relazione (add / remove)

| Relazione                       | Add | Remove |
| ---------------------------------- | :-: | :----: |
| Riscontro → Revisori                | ✅  |   ✅   |
| Riscontro → Tag                     | ✅  |   ✅   |
| Riscontro → Tag ereditati           | ✅  |   ✅   |
| Prodotto → Tag                     | ✅  |   ✅   |
| Engagement → Tag                  | ✅  |   ✅   |
| Engagement → Tag ereditati        | ✅  |   ✅   |
| Test → Tag                        | ✅  |   ✅   |
| Test → Tag ereditati              | ✅  |   ✅   |
| Endpoint → Tag                    | ✅  |   ✅   |
| Endpoint → Tag ereditati          | ✅  |   ✅   |
| Modello di Riscontro → Tag            | ✅  |   ✅   |
| App Analysis (Technology) → Tag   | ✅  |   ✅   |
| Objects/Product → Tag             | ✅  |   ✅   |

## Pro — azioni monitorate

| Oggetto                            | Create | Update | Delete | Note                          |
| --------------------------------- | :----: | :----: | :----: | ------------------------------ |
| Enhanced Finding                  |   ✅   |   ✅   |   ✅   | Companion Pro del Riscontro       |
| Regola                              |   ✅   |   ✅   |   ✅   | Motore delle regole                   |
| Azione della regola                       |   ✅   |   ✅   |   ✅   |                                |
| Condizione dell'azione della regola             |   ✅   |   ✅   |   ✅   |                                |
| Voce di filtro della regola                 |   ✅   |   ✅   |   ✅   |                                |
| Operazione del motore delle regole            |   ✅   |   ✅   |   ✅   |                                |
| Messaggio dell'operazione del motore delle regole    |   ✅   |   ✅   |   ✅   |                                |
| Attività pianificata                    |   ✅   |   ✅   |   ✅   |                                |
| Esecuzione dell'attività pianificata                |   ✅   |   ✅   |   ✅   |                                |
| Policy di mitigazione                 |   ✅   |   ✅   |   ✅   |                                |
| Impostazione configurabile                   |   ✅   |   ✅   |   ✅   | Modifiche alla configurazione di sistema   |
| Stato Feature Flag                |   ✅   |   ✅   |   ✅   | Attivazione/disattivazione flag + pin di sistema |
| Definizione Feature Flag           |   ✅   |   ✅   |   ✅   | Sincronizzazione di metadata / registro |
| Cloud Firewall                    |   ✅   |   ✅   |   ✅   | campo `locked` escluso        |
| Maschera IP Firewall                  |   ✅   |   ✅   |   ✅   |                                |

### Pro — RBAC / permessi

| Oggetto                        | Create | Update | Delete |
| ----------------------------- | :----: | :----: | :----: |
| Gruppo                         |   ✅   |   ✅   |   ✅   |
| Ruolo                          |   ✅   |   ✅   |   ✅   |
| Appartenenza al gruppo              |   ✅   |   ✅   |   ✅   |
| Ruolo globale                   |   ✅   |   ✅   |   ✅   |
| Assegnazione gruppo al prodotto      |   ✅   |   ✅   |   ✅   |
| Assegnazione gruppo al tipo di prodotto |   ✅   |   ✅   |   ✅   |
| Membro del prodotto             |   ✅   |   ✅   |   ✅   |
| Membro del tipo di prodotto           |   ✅   |   ✅   |   ✅   |

### Pro — eventi di relazione (add / remove)

| Relazione                | Add | Remove |
| --------------------------- | :-: | :----: |
| Cloud Firewall → Intervalli IP  | ✅  |   ✅   |

## Configurazione e conservazione (On-Premise Controls)

| Impostazione              | Variabile d'ambiente                  | Predefinito            | Effetto                                                              |
| -------------------- | -------------------------------------- | ------------------ | ------------------------------------------------------------------ |
| Abilita la registrazione degli audit | `DD_ENABLE_AUDITLOG`                  | `True`             | Quando è `False`, tutti i trigger di cronologia sono disabilitati e nessun evento viene registrato |
| Periodo di conservazione     | `DD_AUDITLOG_FLUSH_RETENTION_PERIOD`  | `-1` (mai eliminare) | Mesi di cronologia da conservare; gli eventi più vecchi vengono eliminati in blocco dal job di pulizia  |
| Dimensione del batch di pulizia    | `DD_AUDITLOG_FLUSH_BATCH_SIZE`        | `1000`             | Righe eliminate per batch durante la pulizia                              |
| Numero massimo di batch di pulizia    | `DD_AUDITLOG_FLUSH_MAX_BATCHES`       | `100`              | Limite al numero di batch per ogni esecuzione di pulizia                        |

## Note e limitazioni

- **I segreti non vengono mai acquisiti.** Le password degli utenti e i valori degli header dei
  webhook di notifica sono esplicitamente esclusi dagli snapshot degli eventi.
- **Gli update vengono registrati solo in caso di modifica reale.** Un salvataggio che non altera alcun
  valore di campo non produce alcun evento di update; i campi gestiti automaticamente come
  il solo `last_updated` non ne fanno scattare uno.
- **Gli eventi di autenticazione non vengono acquisiti qui.** Solo le modifiche
  ai dati. Le attività di login, logout e tentativo di accesso fallito sono gestite separatamente e non fanno parte di questo log di audit.
