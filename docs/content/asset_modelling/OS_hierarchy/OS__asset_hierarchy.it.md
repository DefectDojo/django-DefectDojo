---
title: 'Gerarchia degli Asset: Panoramica'
description: Informazioni su Organizzazioni, Asset, Engagement, Test e Riscontri
weight: 1
audience: opensource
aliases:
- /it/en/working_with_findings/organizing_engagements_tests/product_hierarchy
- /it/asset_modelling/os_hierarchy/product_hierarchy/
- /it/en/asset_modelling/os_hierarchy/product_hierarchy/
---

DefectDojo utilizza cinque classi di dati principali per organizzare il tuo lavoro: **Organizzazioni, Asset**, **Engagement**, **Test** e **Riscontri**.

DefectDojo è progettato per essere flessibile e adattarsi al tuo team, anziché costringere il team ad adattarsi allo strumento. Sarai in grado di progettare uno spazio di lavoro solido e adattabile una volta compreso come queste classi di dati possono essere utilizzate per organizzare il tuo lavoro.

### Diagramma della gerarchia degli Asset
![image](images/Asset_Hierarchy_Full.png)


## **Organizzazioni**

La prima categoria di dati che dovrai configurare in DefectDojo è un'Organizzazione. Le Organizzazioni sono pensate per categorizzare gli Asset in un modo specifico. Questo potrebbe essere:

* per dominio aziendale
* per team di sviluppo
* per team di sicurezza

![image](images/Asset_Hierarchy_Overview.png)
*Gli Asset sono raggruppati e annidati sotto la propria Organizzazione.*

Alle Organizzazioni è possibile applicare regole di controllo degli accessi basato sui ruoli (Role\-Based Access Control), che limitano la capacità dei membri del team di visualizzare e interagire con i loro dati (inclusi eventuali Asset sottostanti con dati di Engagement, Test e Riscontro). Per maggiori informazioni sui ruoli utente, consulta il nostro articolo **Introduzione ai Ruoli**.

#### Cosa può rappresentare un'Organizzazione?

* Se un particolare progetto software ha molte distribuzioni o versioni distinte, potrebbe valere la pena creare una singola Organizzazione che copra l'ambito dell'intero progetto, con ogni versione esistente come Asset individuale.
​
* Potresti anche considerare di utilizzare le Organizzazioni per rappresentare le fasi del tuo processo di sviluppo software: un'Organizzazione per 'In Development', un'Organizzazione per 'In Production', ecc.
​
* In definitiva, sta a te decidere come organizzare i tuoi Asset e cosa vuoi che le tue Organizzazioni rappresentino. La tua gerarchia DefectDojo potrebbe dover cambiare per adattarsi alle esigenze dei tuoi team di sicurezza.

## **Asset**

Un **Asset** in DefectDojo è pensato per rappresentare qualsiasi progetto, programma o applicazione che stai attualmente testando. L'Asset ospita tutto il lavoro di sicurezza e la cronologia dei test relativi all'obiettivo sottostante.

![image](images/Asset_Hierarchy_Overview_2.png)

* un **Nome** univoco
* una **Descrizione**
* un'**Organizzazione**
* una **Configurazione SLA** assegnata

Gli Asset possono avere un ambito ampio o specifico, a tua scelta. Per impostazione predefinita, gli Asset sono oggetti completamente separati nella gerarchia, ma possono essere raggruppati per **Organizzazione**.

Gli Asset sono 'isolati' e non interagiscono con altri Asset. Le funzionalità intelligenti di DefectDojo, come la **Deduplicazione**, si applicano solo nel contesto di un singolo Asset.

Come le **Organizzazioni**, anche gli **Asset** possono avere regole di controllo degli accessi basato sui ruoli, che limitano la capacità dei membri del team di visualizzarli e interagire con essi (così come con eventuali dati di Engagement, Test e Riscontro sottostanti). Per maggiori informazioni sui ruoli utente, consulta il nostro articolo **Introduzione ai Ruoli**.

#### Cosa può rappresentare un Asset?

Il concetto di 'Asset' di DefectDojo non corrisponde necessariamente 1:1 a ciò che la tua organizzazione definirebbe un 'Prodotto'. Lo sviluppo software è complesso e le esigenze di sicurezza possono variare notevolmente anche nell'ambito di un singolo software.

I seguenti scenari sono buoni motivi per considerare la creazione di un Asset DefectDojo separato:

* "**ExampleAsset**" ha una versione Windows, una versione Mac e una versione Cloud
* "**ExampleAsset 1\.0**" utilizza componenti software completamente diversi da "**ExampleAsset 2\.0**", ed entrambe le versioni sono attivamente supportate dalla tua azienda.
* Il team assegnato a lavorare su "**ExampleAsset version A**" è diverso dal team Asset assegnato a lavorare su "**ExampleAsset version B**", e necessita quindi di autorizzazioni di sicurezza diverse.

Queste variazioni all'interno di un singolo Asset possono anche essere gestite a livello di Engagement. Nota che gli Engagement non dispongono di controllo degli accessi come invece Asset e Organizzazioni.

## **Engagement**

Una volta configurato un Asset, puoi iniziare a creare e pianificare Engagement. Gli Engagement sono pensati per rappresentare i momenti in cui viene svolto il testing, e contengono uno o più **Test**.

Gli Engagement hanno sempre:

* un **Nome** univoco
* **Date di inizio e fine** previste
* uno **Status** (Not Started, In Progress, Cancelled, Completed...)
* un **Testing Lead** assegnato
* un **Asset** associato

Esistono due tipi di Engagement: **Interactive** e **CI/CD**.

* Un **Interactive Engagement** viene generalmente eseguito da un ingegnere. Gli Interactive Engagement si concentrano sul testing dell'applicazione mentre è in esecuzione, utilizzando un test automatizzato, un tester umano o qualsiasi attività che “interagisce” con le funzionalità dell'applicazione. Consulta la [definizione di IAST di OWASP](https://owasp.org/www-project-devsecops-guideline/latest/02c-Interactive-Application-Security-Testing#:~:text=Interactive%20Application%20Security%20Testing,interacting%E2%80%9D%20with%20the%20application%20functionality.).
* Un **CI/CD Engagement** è pensato per l'integrazione automatizzata con una pipeline CI/CD. I CI/CD Engagement sono pensati per importare dati come azione automatizzata, attivata da una fase del processo di rilascio.

Gli Engagement possono essere monitorati utilizzando la visualizzazione **Calendar** di DefectDojo.

#### Cosa può rappresentare un Engagement?

Gli Engagement sono pensati per rappresentare gruppi di sforzi di test correlati. Il modo in cui desideri raggruppare i tuoi sforzi di test dipende dal tuo approccio.

Se hai uno sforzo di test pianificato, un Engagement ti offre un luogo in cui archiviare tutti i risultati correlati. Ecco un esempio di questo tipo di Engagement:

#### **Engagement:** ExampleSoftware 1\.5\.2 \- Sforzo di test interattivo

*In questo esempio, un team di sicurezza esegue più test nello stesso giorno come parte di un rilascio software.*

* **Test:** Risultati Nessus Scan (12 marzo\)
* **Test:** Risultati NPM Scan Audit (12 marzo\)
* **Test:** Risultati Snyk Scan (12 marzo\)
​
Puoi anche organizzare i risultati dei Test CI/CD all'interno di un Engagement. Questi tipi di Engagement sono 'Open\-Ended' (senza fine), il che significa che non hanno una data e aggiungeranno invece dati aggiuntivi ogni volta che vengono eseguite le azioni CI/CD associate.

#### Engagement: ExampleSoftware - Test CI/CD

*In questo esempio, più scansioni CI/CD vengono importate automaticamente come Test ogni volta che viene creato un nuovo rilascio software.*

* Test: Risultati scansione 1\.5\.2 (12 marzo\)
* Test: Risultati scansione 1\.5\.1 (3 marzo\)
* Test: Risultati scansione 1\.5\.0 (14 febbraio\)

Gli Engagement possono essere organizzati nel modo più adatto al tuo team. Tutti gli Engagement annidati sotto un Asset possono essere visualizzati dal team assegnato a lavorare sull'Asset.

## **Test**

I Test sono un raggruppamento di attività svolte dagli ingegneri per cercare di individuare le falle in un Asset.

I Test hanno sempre:

* un **Titolo del Test** univoco
* un **Tipo di Test** specifico (API Test, Nessus Scan, ecc.)
* un **Ambiente** di test associato
* un **Engagement** associato

I Test possono essere creati in diversi modi.  I Test possono essere creati automaticamente quando i dati di scansione vengono importati direttamente in un Engagement, generando un nuovo Test contenente i dati della scansione. I Test possono anche essere creati in previsione della pianificazione di futuri engagement, oppure per riscontri di sicurezza inseriti manualmente che richiedono tracciamento e correzione.

### **Tipi di Test**

DefectDojo supporta due categorie di Tipi di Test:

1. **Tipi di Test basati su parser**: corrispondono a scanner di sicurezza specifici che producono output in formati come XML, JSON o CSV. Durante l'importazione dei risultati della scansione, DefectDojo utilizza parser specializzati per convertire l'output dello scanner in Riscontri.

2. **Tipi di Test senza parser**: vengono utilizzati per i Riscontri creati manualmente e non importati da file di scansione.  Questi Tipi di Test utilizzano il metodo [Generic Findings Import](/supported_tools/parsers/generic_findings_import/) per visualizzare Riscontri e metadati.

I seguenti Tipi di Test compaiono nel menu a discesa "Scan Type" durante la creazione di un nuovo test.
   * API Test
   * Static Check
   * Pen Test
   * Web Application Test
   * Security Research
   * Threat Modeling
   * Manual Code Review

I Tipi di Test senza parser devono essere utilizzati quando è necessario creare manualmente riscontri che richiedono una correzione ma non provengono dall'output di uno scanner automatizzato.

#### **Tipi di Test basati su parser**

I tipi di test basati su parser possono essere classificati in base al modo in cui viene determinato il nome del tipo di test:

- **Nomi di Tipo di Test fissi**: il nome del tipo di test è predefinito e noto prima dell'importazione (ad es. "ZAP Scan", "Nessus Scan").

- **Nomi di Tipo di Test definiti dal report**: il nome del tipo di test viene estratto dal contenuto del report di scansione al momento dell'importazione.

Alcuni esempi includono:
  - **Generic Findings Import**: crea tipi di test in base al campo `type` nei report JSON
  - **SARIF**: crea tipi di test in base ai nomi degli strumenti nel report SARIF (ad es. "Dockle Scan (SARIF)")
  - **OpenReports**: crea tipi di test separati per ogni fonte trovata nel report

**Regole di denominazione dei Tipi di Test definiti dal report:**
- Se il campo `type` del report è uguale al tipo di scansione → utilizza direttamente il tipo di scansione (ad es. "Generic Findings Import")
- Se il campo `type` del report è diverso → crea il formato "{type} Scan ({scan_type})" (ad es. "Tool1 Scan (Generic Findings Import)")
- Se il campo `type` del report termina già con il suffisso " ({scan_type})" → viene utilizzato così com'è, in modo che il suffisso non venga mai duplicato (ad es. "Tool1 (Generic Findings Import)" resta "Tool1 (Generic Findings Import)")
- Se non viene fornito alcun campo `type` → utilizza direttamente il tipo di scansione

**Considerazioni importanti:**
- I tipi di test definiti dal report vengono creati automaticamente quando viene rilevato un nuovo tipo durante l'importazione o la reimportazione.
- Per le reimportazioni, il nome del tipo di test deve corrispondere esattamente: eventuali discrepanze genereranno un errore di validazione
- Le impostazioni di deduplicazione (`HASHCODE_FIELDS_PER_SCANNER`) utilizzano i nomi dei tipi di test come chiavi, quindi i nomi definiti dal report devono essere configurati di conseguenza se si desidera un comportamento di deduplicazione personalizzato

#### **In che modo i Test interagiscono tra loro?**

I Test prendono i tuoi dati di test e li raggruppano in Riscontri. Generalmente, i team di sicurezza eseguono ripetutamente lo stesso sforzo di test, e i Test in DefectDojo ti consentono di gestire questo processo in modo efficiente.

**I test importati in precedenza possono essere reimportati** \- Se stai eseguendo lo stesso tipo di test all'interno dello stesso contesto di Engagement, puoi reimportare i risultati del test dopo ogni scansione completata. DefectDojo confronterà i dati reimportati con il risultato esistente e non creerà nuovi Riscontri se nei dati di scansione sono presenti duplicati.

**I test possono essere importati separatamente** \- Se esegui lo stesso test su un Asset all'interno di Engagement separati, DefectDojo confronterà comunque i dati con i Test precedenti per individuare i Riscontri duplicati. Questo ti consente di tenere traccia dei Riscontri precedentemente mitigati o con rischio accettato.

Se un Test viene aggiunto direttamente a un Asset senza un Engagement, verrà creato automaticamente un Engagement generico per contenerlo. Questo consente importazioni di dati ad\-hoc.

**Esempi di Test:**

* Burp Scan dal 29 ott. 2015 al 29 ott. 2015
* Nessus Scan dal 31 ott. 2015 al 31 ott. 2015
* API Test dal 15 ott. 2015 al 20 ott. 2015

## **Riscontri**

Una volta che i dati sono stati caricati in un Test, i risultati di tali dati verranno elencati nel Test come singoli **Riscontri** da esaminare.

Un riscontro rappresenta una falla specifica scoperta durante il test.

I Riscontri hanno sempre:

* un **Nome del Riscontro** univoco
* la **Data** in cui sono stati scoperti
* più **Stati** associati, come Attivo, Verificato o Falso positivo
* un **Test** associato
* un livello di **Gravità**: Critica, Alta, Media, Bassa e Informativo (Info).

I Riscontri possono essere aggiunti tramite un'importazione di dati, ma possono anche essere aggiunti manualmente a un Test.

**Esempi di Riscontri:**

* Potenziale vulnerabilità MiTM OpenSSL 'ChangeCipherSpec'
* Applicazione web potenzialmente vulnerabile al Clickjacking
* Protezione XSS del browser web non abilitata

## **Endpoint**

I dati di scansione generalmente contengono riferimenti agli host o agli endpoint interessati da un determinato Riscontro.  DefectDojo aggrega automaticamente i Riscontri per endpoint, quindi puoi utilizzare la visualizzazione Endpoint per esaminare tutti i Riscontri che interessano un determinato Endpoint o Hostname.

Esempi:
-   https://www.example.com
-   https://www.example.com:8080/products
-   192.168.0.36
