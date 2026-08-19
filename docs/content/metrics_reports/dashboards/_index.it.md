---
title: Dashboard
summary: ''
date: 2023-09-07 16:06:50+02:00
lastmod: 2023-09-07 16:06:50+02:00
draft: false
weight: 1
chapter: true
seo:
  title: ''
  description: ''
  canonical: ''
  robots: ''
exclude_search: true
---

La Dashboard è la pagina principale di DefectDojo, un riepilogo delle prestazioni del proprio team e un punto di partenza per monitorare le aree di maggiore interesse.

## Open source vs. DefectDojo Pro

Il funzionamento della dashboard dipende dall'edizione in uso:

| | Open Source | DefectDojo Pro |
|---|---|---|
| **Dashboard principale** | Un'unica Dashboard principale fissa per tutti | Dashboard **personalizzabili** per singolo utente |
| **Scelta degli elementi visualizzati** | Il superuser attiva/disattiva un insieme fisso di grafici | Ogni utente aggiunge, configura e dispone i **widget** |
| **Dashboard multiple con nome** | No | Sì — crea qualsiasi numero di **layout** e passa dall'uno all'altro |
| **Condivisione / clonazione / impostazione predefinita** | — | Sì — pubblica i layout per il proprio team, clona i modelli e imposta quello predefinito |
| **REST API + automazione con LLM** | — | Sì — esplora il catalogo, crea layout e visualizza i dati dei widget |

In sintesi: la versione **open source** offre a ogni utente la stessa Dashboard principale integrata, con un insieme fisso di componenti. **DefectDojo Pro** permette a ogni utente di creare le proprie dashboard a partire dai widget, condividerle e gestire l'intero sistema tramite l'interfaccia utente, la REST API o un LLM.

## Prossimi passi

**Open Source**

- **[Dashboard principale di DefectDojo](introduction_dashboard/)** — la pagina integrata predefinita: schede di riepilogo, grafici di gravità e la loro configurazione da parte di un superuser.

**DefectDojo Pro**

- **[Dashboard personalizzabili](custom-dashboards/)** — concetti (layout, widget, catalogo, condivisione) e una guida completa all'interfaccia utente.
- **[Automatizzare le dashboard con l'API](custom-dashboards-api/)** — esplora il catalogo dei widget, crea e aggiorna i layout e visualizza i dati dei widget tramite la REST API, con uno script completo.
- **[Creare dashboard con un LLM](custom-dashboards-llm/)** — affida a un LLM la progettazione e la creazione delle dashboard.
