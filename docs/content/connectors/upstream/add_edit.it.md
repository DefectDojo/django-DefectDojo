---
title: Aggiungere o modificare i Connettori Upstream
description: Collegati a uno strumento di sicurezza supportato
aliases:
- /it/import_data/pro/connectors/add_edit_connectors/
- /it/en/connecting_your_tools/connectors/add_edit_connectors
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Nota: i Connettori Upstream sono una funzionalità esclusiva di DefectDojo Pro.</span>

Il processo per aggiungere e configurare un Connettore Upstream è simile, indipendentemente dallo strumento che stai cercando di collegare. Tuttavia, alcuni strumenti potrebbero richiederti di creare chiavi API o di completare passaggi aggiuntivi.

Prima di iniziare questo processo, ti consigliamo di consultare il nostro [Riferimento specifico per strumento](../toolreference/) per trovare le risorse API dello strumento che stai cercando di collegare.

1. Se non l'hai già fatto, inizia **passando all'interfaccia utente Pro** in DefectDojo.
2. Dal menu laterale sinistro, apri il gruppo **Connectors** annidato sotto l'intestazione **Import**, e fai clic su **Upstream Connectors**.
​
![image](images/add_edit_connectors.png)

3. Scegli un nuovo Connettore che vuoi aggiungere a DefectDojo in **Available Connectors**, e fai clic sul pulsante **Add Configuration** sul riquadro dello strumento. Puoi usare la casella **Search Connectors** per filtrare ciascuna sezione per nome dello strumento, oppure l'interruttore **All / Asset / Finding** nell'intestazione della pagina per filtrare per tipo di connettore.  
​  
Puoi anche modificare un Connettore esistente sotto l'intestazione **Configured Connectors**. Fai clic su **Manage Configuration \> Edit Configuration** per il Connettore Configurato che vuoi modificare.  
​
![image](images/add_edit_connectors_2.png)

4. Avrai bisogno di un **Location URL** accessibile per lo strumento, insieme a una chiave API **Secret**. La posizione della chiave API dipenderà dallo strumento che stai cercando di configurare. Consulta il nostro [Riferimento specifico per strumento](../toolreference/) per maggiori dettagli.  
​
5. Imposta un **Label** per questa connessione per aiutarti a identificarla in DefectDojo.  
​
6. Pianifica la discovery e la sincronizzazione automatiche del Connettore usando le pianificazioni **Discovery Configuration** e **Synchronization Configuration**. Queste possono essere modificate in seguito.  
​
7. Seleziona se desideri **Enable Auto\-Mapping**. Abilitare Auto\-Mapping creerà un nuovo Prodotto in DefectDojo per archiviare i dati provenienti da questo connettore. Auto\-Mapping può essere attivato o disattivato in qualsiasi momento.  
​
8. Fai clic su **Submit.**

![image](images/add_edit_connectors_3.png)

## Prossimi passi

* Ora che hai aggiunto un connettore, puoi confermare che tutto sia configurato correttamente eseguendo un'operazione di [Discover](../manage_operations/#discover-operations).
