---
title: Informazioni su Sensei
description: Cos'è Sensei e come funziona lo scan-and-fix ospitato da DefectDojo
draft: false
audience: pro
weight: 1
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Nota: Sensei è una funzionalità esclusiva di DefectDojo Pro ed è attualmente in versione BETA.</span>

**Sensei** è la funzionalità di **scan-and-fix** basata sull'IA di DefectDojo per i repository di codice sorgente. Collega un repository (tramite una **GitHub App**, **GitLab**, **Bitbucket** o **Azure DevOps**) e Sensei lo analizza, importa i risultati come Riscontri di DefectDojo e poi utilizza un large language model per **correggere questi riscontri aprendo pull/merge request**, tutto senza uscire da DefectDojo.

> **🔀 Più provider:** Sensei supporta **GitHub** (github.com e GitHub Enterprise Server), **GitLab** (gitlab.com e self-managed), **Bitbucket** (Cloud e Server/Data Center) e **Azure DevOps**, tutti con lo stesso flusso di scan-and-fix. Dove questa guida indica *pull request*, GitLab utilizza una **merge request**; il *controllo di stato* della PR viene pubblicato come **commit status** di GitLab/Azure oppure come **build status** di Bitbucket. La connessione varia in base al provider (vedi [Configurare Sensei](/sensei/setup_sensei/)); tutto ciò che segue l'onboarding è identico.

- **Scan-and-fix in un unico posto:** i repository vengono analizzati e corretti dalla pagina Sensei e dai tuoi riscontri, utilizzando gli stessi dati di riscontro normalizzati e deduplicati del resto di DefectDojo.
- **Preview-first:** Sensei mette in staging le *candidate* di correzione per la revisione. Nulla viene inviato a un LLM e nessuna pull request viene aperta finché non approvi, quindi non ci sono costi a sorpresa né PR inaspettate.
- **Credenziali a breve durata:** Sensei funziona interamente tramite una GitHub App e utilizza token di installazione a breve durata. Non c'è nulla da incollare e nulla da ruotare.
- **A consumo e vincolata alla licenza:** Sensei è una funzionalità Pro con quote per istanza per le correzioni e i repository sottoposti a onboarding.

> **🧠 Prima che il codice esista:** Sensei genera anche un modello delle minacce, percorsi di attacco e requisiti di sicurezza a partire dal *design* di una funzionalità, senza che sia coinvolto alcun repository — vedi [Modellazione delle minacce](/sensei/threat_modeling/).

> **🔎 BETA:** Sensei è in fase di sviluppo attivo ed è contrassegnato come **BETA** in tutta l'interfaccia. Il comportamento e le schermate possono cambiare tra una release e l'altra.

> **📍 Dove trovarlo:** apri **Sensei** dalla navigazione a sinistra.

![Hub di Sensei](images/hub_overview.png)

## Come funziona la scansione ospitata da DefectDojo

La scansione ospitata da DefectDojo è il modo consigliato per eseguire Sensei. Le scansioni vengono eseguite **all'interno di DefectDojo** e nulla viene aggiunto al tuo repository:

1. **Collega una GitHub App** e installala nell'organizzazione (o account) proprietaria dei tuoi repository.
2. **Esegui l'onboarding di un repository** per la scansione ospitata e scegli come vengono segnalati i riscontri e (facoltativamente) corretti automaticamente.
3. **Sensei analizza il repository** (su richiesta, oppure automaticamente all'apertura di una pull request) e importa i risultati in un engagement con lo stesso nome del branch.
4. **Sensei corregge i riscontri** generando una correzione e aprendo una pull request sul branch predefinito del repository.

Ogni repository sottoposto a onboarding è collegato a un **asset** di DefectDojo (Prodotto), in modo che i suoi riscontri, engagement e correzioni convivano con il resto dei tuoi dati.

## I tre modi per avviare una correzione

Sensei può correggere un riscontro in tre modi:

- **Il pulsante Fix su un riscontro:** avvia una correzione singola direttamente dalla tabella dei riscontri o dalla pagina di dettaglio di un riscontro. Vedi [Correggere i riscontri con Sensei](/sensei/fixing_findings/).
- **Candidate di correzione automatica:** dopo ogni scansione, Sensei mette in staging come candidate i riscontri che corrispondono ai tuoi criteri. Le rivedi e approvi quelle da correggere (oppure lasci che Sensei le corregga automaticamente). Vedi [Candidate di correzione automatica](/sensei/fixing_findings/#auto-fix-candidate-triage).
- **Un commento `/fix` su una pull request:** commenta `/fix` su una pull request e Sensei invia una correzione a quella PR.

## Requisiti

- Una licenza **DefectDojo Pro** che includa la funzionalità **Sensei**.
- Un provider di controllo del codice sorgente connesso (vedi [Configurare Sensei](/sensei/setup_sensei/)): una **GitHub App** (github.com o Enterprise Server), un token di accesso a progetto/gruppo **GitLab** (gitlab.com o self-managed), una connessione **Bitbucket** (Cloud o Server/Data Center — OAuth, token API o token di accesso), oppure un Personal Access Token di **Azure DevOps**.
- Per **configurare** Sensei (collegare le app, eseguire l'onboarding dei repository): un ruolo globale di **Maintainer** o **Owner**.
- Per **avviare una correzione** su un riscontro: accesso almeno di livello **Writer** al Prodotto di quel riscontro.

## Quote

Sensei viene misurato in base alla tua licenza. L'hub di Sensei mostra due indicatori di utilizzo nella parte superiore della pagina:

- **Correzioni:** il numero di correzioni applicate rispetto al limite prepagato. L'approvazione di una candidata o l'avvio di una correzione consuma questa quota.
- **Repository sottoposti a onboarding:** il numero di repository sottoposti a onboarding rispetto al limite di repository.

Quando viene raggiunta una quota, Sensei blocca ulteriori correzioni (o onboarding) finché non viene aumentata. Per i dettagli, vedi [Riferimento](/sensei/sensei_reference/#quotas-and-metering).
