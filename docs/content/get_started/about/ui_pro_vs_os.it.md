---
title: 🎨 Modifiche alla UI Pro
description: Lavorare con diverse UI in DefectDojo
draft: 'false'
weight: 5
audience: pro
aliases:
- /it/en/about_defectdojo/ui_pro_vs_os
---

In late 2023, DefectDojo, Inc. ha rilasciato una nuova UI per DefectDojo Pro, che è ora la UI predefinita per questa edizione.

La UI Pro introduce i seguenti miglioramenti in DefectDojo:

- Design moderno ed elegante realizzato con Vue.js.
- Distribuzione dei dati e tempi di caricamento ottimizzati, specialmente per grandi set di dati.
- Accesso a nuove funzionalità Pro, tra cui le viste [Connettori Upstream](/connectors/upstream/about/), [Universal Importer](/import_data/pro/specialized_import/external_tools/) e [Metriche Pro](/metrics_reports/pro_metrics/pro__overview/).
- Flussi di lavoro dell'interfaccia migliorati: filtri, dashboard e navigazione più efficaci.

## Passare alla UI Pro

Per accedere alla UI Pro, apri il menu Opzioni utente dall'angolo in alto a destra.  Puoi anche tornare alla UI Classica dallo stesso menu.

![image](images/beta-classic-uis.png)

## Modifiche alla navigazione

![image](images/pro_ui_overview.png)

1. La **Barra laterale** è stata riorganizzata in quattro categorie principali: Dashboard, Importa, Gestisci e Impostazioni.

2. La Homepage, le [funzionalità native di connessione API basate su AI](/metrics_reports/ai/mcp_server_pro/), le Metriche Pro e la vista Calendario sono tutte accessibili sotto Dashboard.

4. I metodi di importazione si trovano nella sezione Importa: configura i [Connettori](/connectors/about/) per estrarre i riscontri dai tuoi scanner (Upstream) o inviarli agli issue tracker (Downstream), usa il modulo [Aggiungi riscontri](/import_data/import_scan_files/pro__import_scan_ui/) per aggiungere Riscontri, usa [Smart Upload](/import_data/pro/specialized_import/smart_upload/) per gestire gli strumenti di scansione dell'infrastruttura, oppure utilizza i nostri strumenti esterni—[Universal Importer e DefectDojo CLI](/import_data/pro/specialized_import/external_tools/)—per semplificare i processi di importazione e reimportazione dei Riscontri e degli oggetti associati.

5. La sezione **Gestisci** ti permette di visualizzare diversi oggetti nella [Gerarchia dei prodotti](/asset_modelling/os_hierarchy/product_hierarchy/), con viste per Tipi di prodotto, Prodotti, Engagement, Test, Riscontri, Accettazioni del rischio, Endpoint e Componenti.  Ci sono sezioni aggiuntive per generare report (Generatore di report), utilizzare i sondaggi (Sondaggi), oltre a un [Motore di regole](/automation/rules_engine/about/). 

5. La sezione **Impostazioni** ti permette di configurare la tua istanza DefectDojo, tra cui Licenza, Impostazioni Cloud, Utenti, Configurazione delle funzionalità e Impostazioni Enterprise a livello di amministrazione. (Le Integrazioni si sono spostate in **Importa > Connettori > Connettori Downstream**.)

6. La sezione **Impostazioni** contiene le pagine amministrative, raggruppate in Sistema, Utenti e permessi, Flusso di lavoro dei riscontri, Configurazione, Notifiche, Operazioni e Licenza e supporto, con una pagina **Tutte le impostazioni** che le elenca e le rende ricercabili tutte. Consulta [Il menu Impostazioni](/navigation/pro__settings_menu/).

7. La UI Pro dispone anche di un **nuovo formato di tabella**, utilizzato nella [Gerarchia dei prodotti](/asset_modelling/os_hierarchy/product_hierarchy/) per facilitare la navigazione.  Si può fare clic su ciascuna colonna per applicare un filtro pertinente, e le colonne possono essere riordinate per presentare i dati come preferisci.

8. La tabella dispone anche di un menu **"Attiva/disattiva colonne"** che permette di aggiungere o rimuovere colonne dalla tabella.

## Filtrare la tabella

In questo screenshot stiamo filtrando tutti i Riscontri che si trovano in "Sam's Awesome Product". Dopo aver fatto clic su Applica, il contenuto di questo elenco di Riscontri si aggiornerà per riflettere il filtro scelto.

![image](images/pro_ui_sams_filter.png)

## Nuove dashboard

Nuove visualizzazioni di Metriche sono incluse nella UI Pro. Tutti questi report possono essere filtrati ed esportati come PDF per condividerli con un pubblico più ampio.

![image](images/program_insights.png)

- La dashboard **Executive Insights** mostra lo stato attuale dei tuoi Prodotti e Tipi di prodotto.
- **Priority Insights** mostra i riscontri più critici con la possibilità di filtrare per diversi intervalli temporali, Tipi di prodotto, Prodotti e Tag.
- La dashboard **Program Insights** mostra l'efficacia del tuo team di sicurezza e i risparmi sui costi associati alla separazione di duplicati e falsi positivi dai Riscontri effettivamente utilizzabili.
- **Remediation Insights** mostra l'efficacia del tuo team nella remediation dei Riscontri.
- **Tool Insights** mostra l'efficacia della tua suite di strumenti (e delle pipeline dei Connettori Upstream) nel rilevare e segnalare le vulnerabilità.
