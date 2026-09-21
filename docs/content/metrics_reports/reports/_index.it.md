---
title: Report Builder
description: Metriche sulle prestazioni e approfondimenti
summary: ''
date: 2026-01-20 17:33:00+00:00
lastmod: 2026-01-20 17:33:00+00:00
draft: false
weight: 2
chapter: true
seo:
  title: ''
  description: ''
  canonical: ''
  robots: ''
exclude_search: true
---

Il Report Builder ti permette di trasformare i dati di DefectDojo in report curati e condivisibili — riepiloghi esecutivi, istantanee di conformità, pacchetti POA&M, dettagli ingegneristici e altro ancora — per destinatari all'interno e all'esterno del tuo team di sicurezza.

## Open source vs. DefectDojo Pro

Il modo in cui costruisci i report dipende dall'edizione che usi:

| | Open Source | DefectDojo Pro |
|---|---|---|
| **Costruire un report** | Sì — assemblato da widget | Sì — composto da Blocchi riutilizzabili |
| **Eseguire e recuperare l'output** | Sì (HTML, stampa in PDF) | Sì (PDF o HTML salvato) |
| **Salvare Temi / Blocchi / Template riutilizzabili** | No — da ricostruire ogni volta | Sì |
| **Cronologia persistente dei report generati** | No | Sì — elenco, download, riesecuzione |
| **Automazione via API REST + LLM** | — | Sì — creazione → esecuzione → download completi |

In breve: **open source** ti permette di costruire un report, eseguirlo ed esportare il risultato, ma non salva i template né mantiene una cronologia dei report. **DefectDojo Pro** trasforma il reporting in elementi costitutivi riutilizzabili e personalizzabili con il tuo brand, che puoi gestire dall'interfaccia, dall'API REST o con un LLM.

## Dove andare ora

**DefectDojo Pro**

- **[Report Builder](report-builder/)** — concetti (Temi, Blocchi, Template, Report generati) e un percorso guidato completo dell'interfaccia.
- **[Automatizzare i report con l'API](report-builder-api/)** — crea, esegui, monitora e scarica i report tramite l'API REST, con uno script completo.
- **[Creazione di report con un LLM](report-builder-llm/)** — lascia che un LLM progetti, crei, esegua e scarichi i report per te.

**Open Source**

- **[Usare il Report Builder](using-the-report-builder/)** — costruisci, esegui ed esporta un report con il builder basato su widget.
