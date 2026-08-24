---
title: Lingue e Righe di Codice
description: Importa i dati sulla composizione linguistica per un Prodotto utilizzando
  lo strumento cloc
weight: 3
audience: opensource
aliases:
- /it/en/open_source/languages
---

DefectDojo può visualizzare una ripartizione dei linguaggi di programmazione e delle righe di codice per un Prodotto, popolata importando un report dallo strumento [cloc](https://github.com/AlDanial/cloc) (Count Lines of Code) tramite l'API.

## Generazione del report cloc

Esegui `cloc` sul tuo codice utilizzando il flag `--json` per produrre un file JSON nel formato corretto:

```bash
cloc --json /path/to/your/project > cloc-report.json
```

## Importazione tramite API

Carica il report JSON su DefectDojo tramite l'API. Durante l'importazione, tutti i dati linguistici esistenti per il Prodotto vengono sostituiti con il contenuto del nuovo file.

L'endpoint di importazione è documentato nella [documentazione API v2 di DefectDojo](../api-v2-docs/).

## Visualizzazione dei risultati

Dopo l'importazione, la ripartizione dei linguaggi viene visualizzata sul lato sinistro della pagina dei dettagli del Prodotto, mostrando ogni linguaggio e il relativo numero di righe. I colori di ogni linguaggio sono definiti dalle voci nella tabella `Language_Type`, pre-popolata con dati da GitHub.

## Aggiornamento dei colori dei linguaggi

GitHub aggiorna periodicamente i colori dei linguaggi man mano che emergono nuovi linguaggi. Per scaricare i dati sui colori più recenti, esegui il seguente comando di gestione:

```bash
./manage.py import_github_languages
```

Questo legge da [ozh/github-colors](https://github.com/ozh/github-colors) e aggiunge nuovi linguaggi o aggiorna i colori esistenti.
