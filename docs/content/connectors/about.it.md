---
title: Informazioni sui Connectors
description: Il punto di riferimento unificato per gli Upstream Connectors e i Downstream
  Connectors nell'interfaccia Pro
summary: ''
date: 2026-07-14 00:00:00+00:00
lastmod: 2026-07-14 00:00:00+00:00
draft: false
weight: 1
chapter: true
sidebar:
  collapsed: true
seo:
  title: ''
  description: ''
  canonical: ''
  robots: ''
pro-feature: true
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Nota: i Connector sono una funzionalità esclusiva di DefectDojo Pro.</span>

**Connectors** è l'unico punto di riferimento nell'interfaccia di DefectDojo Pro per ogni strumento con cui DefectDojo comunica, in entrambe le direzioni. Unisce due funzionalità che in precedenza erano configurate in punti separati:

* **Upstream Connectors** (in precedenza **API Connectors**) importano riscontri e inventario degli asset *in ingresso* dai tuoi scanner e strumenti di sicurezza.
* **Downstream Connectors** (in precedenza **Integrations**) inviano riscontri *in uscita* verso i tuoi sistemi di issue tracking e ticketing.

Se pensi a DefectDojo come all'hub dei tuoi dati di sicurezza, gli Upstream Connectors sono il modo in cui i dati arrivano, mentre i Downstream Connectors sono il modo in cui il lavoro di remediation viene inviato all'esterno.

## Dove trovare i Connectors

Nella barra laterale dell'interfaccia Pro, apri il gruppo **Connectors** sotto l'intestazione **Import**:

* **Connectors > Upstream Connectors** — sostituisce la vecchia voce **API Connectors** (in precedenza sotto Import).
* **Connectors > Downstream Connectors** — sostituisce la vecchia voce **Integrations** (in precedenza sotto Settings). Questa direzione è attualmente in **Beta**.

I vecchi segnalibri e i deep link continuano a funzionare: gli URL legacy di **API Connectors** e **Integrations** reindirizzano automaticamente alle nuove pagine **Upstream Connectors** e **Downstream Connectors**.

## Chi può vedere cosa

* **Upstream Connectors** è visibile agli utenti con un ruolo globale (Global Role) di Reader o superiore.
* **Downstream Connectors** è visibile solo ai superuser ed è attualmente in **Beta** per le istanze DefectDojo Pro ospitate su Cloud.

Il gruppo **Connectors** appare nella barra laterale se almeno una delle due pagine è visibile per te.

## Le pagine Connectors

Entrambe le direzioni condividono lo stesso layout rinnovato:

* Ogni strumento viene mostrato come un **riquadro** a larghezza piena — logo a sinistra, nome dello strumento e una breve descrizione al centro, e un pulsante di azione a destra.
* Ogni sezione dispone di una **casella di ricerca** che filtra i riquadri in base al nome dello strumento man mano che digiti.

Nella pagina **Upstream Connectors**:

* **Configured Connectors** elenca i connector già configurati. Ogni riquadro mostra un riepilogo dello stato operativo (stato di salute, ultima operazione e conteggio totale / dei record mappati) e un menu **Manage Configuration** con le azioni **Manage Records & Operations**, **Edit Configuration** e **Delete Configuration**.
* **Available Connectors** elenca gli strumenti supportati non ancora configurati, ciascuno con un pulsante **Add Configuration**.
* Un filtro nell'intestazione della pagina restringe entrambe le sezioni per tipo di connector: **All**, **Asset** (oppure **Product**, a seconda del vocabolario della tua istanza) per i connector che importano l'inventario degli asset, e **Finding** per i connector che importano dati di vulnerabilità.

Nella pagina **Downstream Connectors**:

* **Available Integrations** elenca ogni sistema di issue tracking supportato. I riquadri delle integrazioni che hai configurato mostrano un conteggio delle Integration Instances esistenti.

## Prossimi passi

* Leggi [Informazioni sugli Upstream Connectors](/connectors/upstream/about/) e [aggiungi il tuo primo Upstream Connector](/connectors/upstream/add_edit/) per iniziare a importare automaticamente i riscontri.
* Leggi la [guida ai Downstream Connectors](/connectors/downstream/about/) per inviare i riscontri ai tuoi sistemi di issue tracking.
