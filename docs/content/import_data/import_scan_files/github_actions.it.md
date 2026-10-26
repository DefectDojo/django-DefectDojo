---
title: Importazione da GitHub Actions
description: Importare i risultati di una scansione da un workflow di GitHub Actions
  con l'azione DefectDojo ufficiale
weight: 3
---

L'[azione DefectDojo](https://github.com/DefectDojo/defectdojo-action) ufficiale importa un report di scansione in DefectDojo da un workflow di GitHub Actions. Funziona con DefectDojo Pro e con l'edizione Open Source, e legge ogni formato di report supportato da DefectDojo, incluso SARIF.

Ogni esecuzione effettua un Reimport nello stesso Test: i Riscontri che lo scanner non segnala più vengono chiusi e ciascun Riscontro conserva la propria cronologia. L'azione registra nel Test la build, il branch, il commit e il repository, e può far fallire il passaggio del workflow quando restano attivi Riscontri con una severità scelta.

## Prima di iniziare

1. Creare una chiave API v2 per un utente autorizzato a importare nell'Asset (e a crearlo, se si consente all'azione di creare gli Asset). La chiave si trova sotto **API v2 Token** nel menu utente (**API v2 Key** nell'interfaccia Open Source).
2. Nel repository GitHub, aggiungere la chiave come secret denominato `DEFECTDOJO_API_TOKEN` in **Settings > Secrets and variables > Actions**.

## Aggiungere l'azione a un workflow

Eseguire lo scanner, quindi passare il relativo report all'azione:

```yaml
name: Security scan
on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - name: Scan
        uses: aquasecurity/trivy-action@ed142fd0673e97e23eac54620cfb913e5ce36c25 # v0.36.0
        with:
          scan-type: fs
          format: json
          output: trivy.json
      - name: Import into DefectDojo
        uses: DefectDojo/defectdojo-action@v1
        with:
          defectdojo-url: https://defectdojo.example.com
          api-token: ${{ secrets.DEFECTDOJO_API_TOKEN }}
          file: trivy.json
          scan-type: Trivy Scan
          fail-on: critical
```

`scan-type` è il nome del formato di report così come lo elenca DefectDojo, ad esempio `SARIF`, `Trivy Scan` o `Semgrep JSON Report`. Per l'elenco completo dei nomi, consultare [Strumenti supportati](/supported_tools/).

## Destinazione dei Riscontri

Se non vengono impostati esplicitamente, l'azione utilizza nomi derivati dal repository e crea quelli non ancora esistenti:

| Oggetto DefectDojo | Valore predefinito | Input |
| --- | --- | --- |
| Organizzazione (Tipo di Prodotto) | Proprietario del repository | `organization-name` o `product-type-name` |
| Asset (Prodotto) | Nome del repository | `asset-name` o `product-name` |
| Engagement | Nome del branch | `engagement-name` |
| Test | Tipo di scansione | `test-title` |

Quando un Engagement riceve più report dello stesso tipo di scansione, assegnare a ciascuno un `test-title` distinto, in modo che ogni Reimport individui il proprio Test.

### Branch, pull request e tag

Ogni branch ottiene un proprio Engagement, per cui la scansione di una pull request non chiude né riapre mai i Riscontri del branch predefinito. Le pull request utilizzano il branch di origine, i tag utilizzano il nome del tag e la merge queue utilizza un Engagement per ciascun branch di base.

Gli Engagement creati dall'azione per qualsiasi branch diverso da quello predefinito eseguono la deduplicazione solo al proprio interno (**Deduplicazione solo all'interno di questo engagement**). In caso contrario, un Riscontro rilevato per la prima volta su un branch contrassegnerebbe come duplicato la copia presente nel branch predefinito. L'impostazione manuale di `engagement-name` o di `deduplication-on-engagement` disattiva questo comportamento, per cui un Engagement denominato esplicitamente esegue la deduplicazione sull'intero Asset come di consueto. Gli Engagement dei branch rimangono in DefectDojo dopo il merge del branch: per tenerli fuori dai conteggi dell'Asset, eseguire l'importazione solo sul branch predefinito.

## Far fallire la build

Impostare `fail-on` su `low`, `medium`, `high` o `critical` per far fallire il passaggio quando, dopo l'importazione, il Test contiene Riscontri attivi con tale severità o superiore. I duplicati non vengono conteggiati. Il riepilogo del job mostra i conteggi per severità e un collegamento al Test.

## Funzionalità Pro

Con DefectDojo Pro, l'azione può inoltre:

- Inviare i nuovi Riscontri ai Connectors configurati per l'Asset (`push-to-connector: true`).
- Importare report di grandi dimensioni in background (`background-import: true`). L'azione attende il completamento dell'elaborazione del Test prima di riportare i conteggi o di applicare `fail-on`.
- Segnalare quando un Asset è stato rinominato o spostato, in modo da poter aggiornare i nomi nel workflow.

Con l'edizione Open Source, `push-to-connector` e `background-import` vengono ignorati con un avviso e l'importazione viene comunque eseguita. Impostare `strict: true` per far fallire invece il passaggio.

## Pull request da fork

GitHub non fornisce i secret ai workflow eseguiti su pull request provenienti da fork, quindi l'azione non può autenticarsi e il passaggio fallisce. Eseguire l'importazione su `push`, oppure ometterla per le pull request provenienti da fork:

```yaml
      - name: Import into DefectDojo
        if: github.event_name != 'pull_request' || github.event.pull_request.head.repo.full_name == github.repository
        uses: DefectDojo/defectdojo-action@v1
```

Non utilizzare `pull_request_target` per aggirare questa limitazione: viene eseguito con i propri secret mentre effettua il checkout di codice che non si controlla.

## Tutti gli input e gli output

Il [README dell'azione](https://github.com/DefectDojo/defectdojo-action#inputs) elenca ogni input e ogni output. La maggior parte degli input corrisponde a un campo dell'endpoint **/reimport** descritto in [Importazione tramite API](/import_data/import_scan_files/api_pipeline_modelling/).
