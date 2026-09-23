---
title: ☑️ Lista di controllo per i nuovi utenti
description: Inizia con DefectDojo
draft: 'false'
weight: 3
audience: opensource
---

Ecco un riferimento rapido che puoi utilizzare per garantire un'implementazione di successo, da una tela bianca a un'app pienamente funzionante.  Questo articolo presuppone che tu abbia **DefectDojo Community Edition** installato e funzionante nel tuo ambiente.

L'essenza di DefectDojo consiste nell'importare i dati di sicurezza, organizzarli e presentarli alle persone che hanno bisogno di conoscerli.  Ecco alcuni modi per ottenere questo risultato in DefectDojo Open-Source:

### DefectDojo Open-Source

1. Gli utenti Open-Source possono iniziare creando il loro primo [Tipo di Prodotto e Prodotto](/asset_modelling/os_hierarchy/product_hierarchy/).  Una volta creati, possono [importare un file](/import_data/import_scan_files/os__import_scan_ui/) in uno di quei Prodotti utilizzando l'interfaccia.

2. Ora che hai dei dati in DefectDojo, valuta di espandere la struttura dei tuoi Prodotti [Panoramica della gerarchia dei Prodotti](/asset_modelling/os_hierarchy/product_hierarchy/). La Gerarchia dei Prodotti crea un inventario funzionante delle tue app, che ti aiuta a suddividere i tuoi dati in categorie logiche. Queste categorie possono essere utilizzate per applicare regole di controllo degli accessi, o per segmentare i tuoi report verso il team corretto.

3. Utilizza il [Report Builder](/metrics_reports/reports/using-the-report-builder/#opening-the-report-builder) per riepilogare i dati che hai importato. I Report possono essere utilizzati per condividere rapidamente i Riscontri con gli stakeholder, come i Product Owner.

Questa è l'essenza di DefectDojo: importare i dati di sicurezza, organizzarli e presentarli alle persone che hanno bisogno di conoscerli.

Tutte queste funzionalità possono essere automatizzate, e poiché DefectDojo può gestire oltre 500 strumenti (al momento della stesura di questo testo) sarai pronto per creare un inventario di sicurezza funzionale dell'intera produzione della tua organizzazione.

### Funzionalità Open-Source
- La tua organizzazione utilizza Jira? Scopri come utilizzare la nostra [integrazione Jira](/connectors/os_jira/os__jira_guide/) per creare ticket Jira a partire dai dati che importi.
- Prevedi di condividere DefectDojo con molti utenti della tua organizzazione? Consulta le nostre guide sulla [gestione degli utenti](/admin/user_management/about_perms_and_roles/) e configura il controllo degli accessi basato sui ruoli (RBAC).
- Pronto a immergerti nell'automazione? Scopri come utilizzare l'[API di DefectDojo](/import_data/import_scan_files/api_pipeline_modelling/) per importare automaticamente nuovi dati e costruire una solida pipeline CI/CD.
