---
title: Introduzione ai Riscontri
description: Il flusso di lavoro principale e il sistema di tracciamento delle vulnerabilità
  di DefectDojo
weight: 1
aliases:
- /it/en/working_with_findings/intro_to_findings
---

I Riscontri sono il modo principale in cui DefectDojo standardizza e guida il processo di segnalazione e correzione dei tuoi strumenti di sicurezza. Che una vulnerabilità sia stata segnalata in SonarQube, Acunetix o dallo strumento personalizzato del tuo team, i Riscontri ti danno la possibilità di gestire ogni vulnerabilità nello stesso modo.

## Cosa sono i Riscontri?

I Riscontri in DefectDojo sono composti dai seguenti elementi: 

* I dati della vulnerabilità segnalata in questione
* Lo 'stato' del Riscontro, utilizzato per tracciare la correzione, l'accettazione del rischio o altre decisioni prese riguardo alla vulnerabilità
* Altri metadati relativi al Riscontro. Ad esempio, questi possono includere la posizione di un Riscontro nella tua rete, i suggerimenti di correzione forniti da uno strumento, o i link a un CWE o punteggio EPSS associato.

Oltre a memorizzare i dati della vulnerabilità e fornire un framework di correzione, DefectDojo migliora anche i tuoi Riscontri nei seguenti modi:

* Aggiungendo automaticamente i punteggi EPSS correlati a un Riscontro per descriverne la sfruttabilità
* Traducendo automaticamente la metrica di gravità di uno strumento di sicurezza in un punteggio di Gravità per ogni Riscontro, che assegna una SLA al Riscontro in base alla Configurazione SLA del tuo Prodotto.

Nel complesso, i Riscontri di DefectDojo sono progettati per funzionare con la Gerarchia dei Prodotti, in modo da standardizzare i tuoi sforzi e applicare un metodo coerente a ogni Prodotto.

## Una Pagina del Riscontro

La Pagina del Riscontro contiene vari elementi. Ognuno viene popolato dal processo di importazione quando il Riscontro viene creato.

![image](images/Introduction_to_Findings.png)

1. **Il Titolo del Riscontro:** Solitamente è una forma abbreviata descrittiva che identifica la vulnerabilità o il problema rilevato. In questa sezione vengono visualizzati anche i tag creati dall'utente, se presenti.  
​
2. **Panoramica del Riscontro:** Questa sezione contiene cinque pagine separate di informazioni rilevanti per il Riscontro: Descrizione, Mitigazione, Impatto, Riferimenti e Note. Questi campi possono essere popolati automaticamente in base ai dati della vulnerabilità in arrivo, oppure possono essere modificati da un utente DefectDojo per fornire ulteriore contesto.  
​  
- ​**Descrizione** è un riepilogo più dettagliato e una spiegazione del Riscontro in questione.  
- ​**Mitigazione** è un metodo suggerito per mitigare il Riscontro in modo che non sia più presente nel tuo sistema.  
- ​**Impatto** descrive l'impatto della vulnerabilità sulla tua postura di sicurezza. Questa pagina può contenere testo descrittivo, oppure può includere una [Stringa Vettoriale CVSS](https://qualysguard.qualys.com/qwebhelp/fo_portal/setup/cvss_vector_strings.htm), che è un modo abbreviato per comunicare la sfruttabilità complessiva della vulnerabilità e le conseguenze di uno sfruttamento per la tua organizzazione. L'Impatto è strettamente correlato al campo Gravità di un Riscontro.  
- ​**Riferimenti** elenca eventuali link o informazioni aggiuntive rilevanti per questo Riscontro, se inclusi.  
- ​**Note** è una pagina in cui puoi registrare qualsiasi altra informazione rilevante per questo Riscontro. Le Note sono metadati 'esclusivi di DefectDojo' e non vengono create al momento dell'importazione. Usa questo campo per tracciare i progressi della mitigazione o per aggiungere dettagli più specifici al Riscontro.  
​
3. **Dettagli Aggiuntivi:** Questa sezione elenca altri dettagli relativi a questo Riscontro, se rilevanti:


	* Coppie Richiesta/Risposta associate alla vulnerabilità
	* Passaggi per Riprodurre la vulnerabilità
	* Giustificazione della Gravità dove puoi registrare una spiegazione più dettagliata della gravità o dell'impatto del Riscontro.  
	​  

4. **Metadati: Questa sezione contiene metadati filtrabili relativi al Riscontro:**


	* **ID:** il valore ID del Riscontro in DefectDojo
	* **Gravità:** il valore di Gravità del Riscontro. Può essere Info, Bassa, Media, Alta o Critica. Le Gravità dei Riscontri sono direttamente correlate alla SLA calcolata del Riscontro, in base al Prodotto in cui il Riscontro è memorizzato.
	* **Stato:** lo stato del Riscontro. Può essere Attivo o Inattivo. Oltre a questi, i Riscontri possono anche avere uno Stato di Duplicato, Mitigato, Falso positivo, Fuori ambito, Rischio accettato o In Revisione del Difetto. Questi Stati spiegano in modo più dettagliato lo Stato del Riscontro.
	* **Tipo:** questo campo descrive come è stato trovato il Riscontro, tramite una valutazione Statica (SAST) del codice sorgente, oppure tramite una valutazione Dinamica (DAST) del Prodotto mentre era in esecuzione. Questo campo è definito dal tipo di strumento.
	* **Posizione:** questo campo descrive il percorso del file relativo alla tua vulnerabilità, se rilevante.
	* **Linea:** questo campo descrive la riga di codice che contiene la vulnerabilità, se rilevante.
	* **Data di Scoperta:** questo campo mostra la data in cui il Riscontro è stato importato in DefectDojo, oppure la data in cui il Riscontro è stato scoperto dallo Strumento.
	* **Età:** questo campo calcolato mostra il numero di giorni in cui il Riscontro è stato attivo.
	* **Autore della Segnalazione:** questo è il nome utente dell'account DefectDojo che ha creato questo Riscontro.
	* **CWE:** questo campo è un link alla definizione CWE esterna (Common Weakness Enumeration) che si applica a questo Riscontro.
	* **ID Vulnerabilità:** se esiste un particolare valore ID per questa vulnerabilità all'interno dello strumento stesso, verrà tracciato qui.
	* **Punteggio EPSS / Percentile:** se i dati di origine hanno un valore CWE, DefectDojo recupererà automaticamente un [Punteggio EPSS](https://www.first.org/epss/) e Percentile (Exploit Prediction Scoring System). L'EPSS rappresenta la probabilità che una vulnerabilità software possa essere sfruttata, sulla base di dati reali di sfruttamento. I punteggi EPSS vengono aggiornati continuamente, utilizzando gli ultimi dati di sfruttamento provenienti da First.
	* **Trovato Da:** Questo elenca lo scanner utilizzato per trovare questa vulnerabilità.  
	​

## Note e @menzioni

La pagina **Note** di un Riscontro è dove il tuo team registra il contesto che non fa parte dei dati di scansione importati — progressi della mitigazione, decisioni di triage o qualsiasi altro commento. Le Note sono metadati esclusivi di DefectDojo e non vengono mai create al momento dell'importazione.

Le Note appaiono come un feed, dalle più recenti alle più vecchie, e puoi invertire l'ordine per visualizzare prima le più vecchie. Ogni nota mostra il suo autore, quando è stata scritta, il suo tipo di nota e un badge **Privata** quando la nota è privata. Una nota privata viene mostrata solo alla persona che l'ha scritta.

### Scrivere note in markdown

Le voci delle note supportano il markdown, quindi puoi usare intestazioni, testo in **grassetto** e in *corsivo*, elenchi puntati e numerati, citazioni, tabelle, link e blocchi di codice. L'editor delle note è lo stesso usato per la descrizione di un Riscontro, con una barra degli strumenti per le opzioni di formattazione comuni. Per leggere una nota esattamente come è stata digitata anziché come testo formattato, usa l'interruttore in alto a destra del corpo della nota.

### Modifica, eliminazione e cronologia

Ogni nota dispone di un menu azioni con **Modifica**, **Visualizza Cronologia** ed **Elimina**, e ogni voce compare solo quando sei autorizzato a usarla:

* Puoi sempre modificare, eliminare e leggere la cronologia di una nota scritta da te.
* Per gestire la nota di qualcun altro è necessario il permesso di ruolo corrispondente sull'oggetto a cui appartiene la nota: Modifica Nota, Elimina Nota o Visualizza Cronologia Nota.
* Aggiungere una nota richiede il permesso Aggiungi Nota, che ogni ruolo superiore a Lettore possiede, e che anche i Lettori possiedono.

Una nota modificata viene etichettata come **(modificata)** e registra chi l'ha cambiata e quando. **Visualizza Cronologia** elenca ogni revisione della nota, dalla più recente alla più vecchia, così nulla va perso quando una nota viene riscritta. Può essere modificato solo il testo della voce stessa: il tipo di una nota e il suo flag di privacy sono fissi una volta creata la nota.

### Menzionare un utente con @

Quando aggiungi una nota, puoi **@menzionare** un altro utente DefectDojo per notificarlo. Digita `@` seguito immediatamente dal suo nome utente (ad esempio `@alice`) in qualsiasi punto della nota. Quando salvi la nota, ogni utente menzionato riceve una notifica **user-mentioned** che rimanda alla nota.

Alcuni dettagli utili da conoscere:

* La `@` deve trovarsi **all'inizio della nota o subito dopo uno spazio**. Questo è intenzionale — impedisce che indirizzi email scritti a metà frase (come `alice@example.com`) generino menzioni accidentali.
* Il nome dopo la `@` deve corrispondere a un nome utente DefectDojo **esistente e attivo**. Le menzioni di utenti sconosciuti o disattivati vengono ignorate.
* Un punto finale viene ignorato, quindi una menzione che conclude una frase (`thanks @alice.`) viene comunque risolta.
* Puoi menzionare più di un utente in una singola nota.

Puoi @menzionare utenti dall'interfaccia nelle note su **Riscontri**, **Test**, **Engagement** e **Accettazioni del rischio**. Digitando `@` si apre un elenco di utenti corrispondenti; selezionarne uno da quell'elenco è il modo affidabile per menzionare qualcuno, perché inserisce il nome utente esattamente come previsto dalla ricerca delle notifiche.

La menzione viene recapitata tramite l'evento di notifica `user_mentioned`. Consulta [Notifiche](/admin/notifications/about_notifications/) per sapere come vengono recapitate e configurate le notifiche — in particolare, `user_mentioned` è uno degli eventi che un'impostazione a livello di sistema può comunque recapitare anche quando un utente ha altrimenti silenziato le proprie notifiche (vedi [Override specifici](/admin/notifications/about_notifications/#specific-overrides)).

## Esempi di Flussi di Lavoro dei Riscontri

Il modo in cui lavori con i Riscontri in DefectDojo dipende dalle responsabilità del tuo team all'interno della tua organizzazione. Ecco alcuni esempi di questi processi e di come DefectDojo può aiutarti:

### Scoprire e segnalare le vulnerabilità

Se sei responsabile della reportistica di sicurezza per molti contesti diversi, Prodotti software o team, DefectDojo può generare report sulle vulnerabilità scoperte. Utilizzando la Gerarchia dei Prodotti, puoi organizzare i dati dei tuoi Riscontri nel contesto appropriato. Ad esempio:

* Ogni Prodotto in DefectDojo può avere una configurazione SLA diversa, in modo da poter contrassegnare istantaneamente i Riscontri scoperti in Produzione o in altri ambienti altamente sensibili.
* Puoi creare un report direttamente da un **Tipo di Prodotto, Prodotto, Engagement o Test** per 'ingrandire o ridurre' il tuo contesto di sicurezza. I **Test** contengono i risultati di un singolo strumento, gli **Engagement** possono combinare più Test, i **Prodotti** possono contenere più Engagement, i **Tipi di Prodotto** possono contenere più Prodotti.

Per maggiori informazioni sulla creazione di un Report, consulta le nostre guide su **[Report Personalizzati](/metrics_reports/reports/)**.

### Eseguire il triage delle vulnerabilità utilizzando lo Stato del Riscontro

Se il tuo team ha bisogno di convalidare i Riscontri scoperti, può farlo applicando manualmente lo stato **Verificato** ai Riscontri man mano che li esamina. Puoi anche applicare altri stati, come:

* **Falso positivo:** Uno strumento ha rilevato la minaccia, ma la minaccia non è attiva nell'ambiente.
* **Fuori ambito:** Attivo, ma irrilevante per lo sforzo di test attuale.
* **Rischio accettato:** Attivo, ma ritenuto non prioritario da affrontare fino alla scadenza dell'Accettazione del rischio.
* **In Revisione:** può essere Attivo o meno - il tuo team sta ancora indagando.
* **Mitigato:** Questo problema è stato risolto da quando il Riscontro è stato creato.

Se uno strumento segnala nuovamente un Riscontro già sottoposto a triage in una successiva importazione, DefectDojo ricorderà lo stato precedente del Riscontro e lo aggiornerà di conseguenza. I Riscontri con stato **Falso positivo**, **Fuori ambito, Rischio accettato e In Revisione** rimarranno invariati, ma qualsiasi Riscontro che sia stato **Mitigato** verrà **riattivato** per farti sapere che il Riscontro è tornato nell'ambiente di Test.

### Garantire il consenso e la responsabilità a livello di team con le Accettazioni del rischio

Parte della responsabilità di un team di sicurezza è collaborare con gli sviluppatori per stabilire le priorità nella correzione dei problemi di sicurezza. È qui che entrano in gioco le Accettazioni del rischio. Aggiungere un'Accettazione del rischio a un Riscontro ti permette di:

* Archiviare record e file 'artefatto' su DefectDojo - questi potrebbero essere email di colleghi che confermano l'Accettazione del rischio, note di riunioni, o semplicemente una giustificazione scritta per l'accettazione del rischio da parte del tuo stesso team di sicurezza.
* Aggiungere una data di scadenza all'Accettazione del rischio, in modo che la vulnerabilità possa essere riesaminata dopo un determinato periodo di tempo.

Qualsiasi membro di un team Appsec sa che la mitigazione dei problemi non può essere gestita esclusivamente dai team di sviluppo, quindi le Accettazioni del rischio ti aiutano a registrare queste decisioni delicate nel momento in cui vengono prese.

### Monitorare le vulnerabilità attuali utilizzando i CVE e i punteggi EPSS (Funzionalità Pro)

A volte, la sfruttabilità e la minaccia rappresentata da una vulnerabilità nota possono cambiare in base a nuovi dati. Per mantenere aggiornato il tuo lavoro, DefectDojo Pro ha stretto una partnership con First.org per mantenere un database dei punteggi EPSS più recenti relativi ai Riscontri. Qualsiasi Riscontro in DefectDojo Pro viene mantenuto automaticamente aggiornato in base al suo EPSS, che si basa direttamente sul CVE del Riscontro.

Se il punteggio EPSS di un Riscontro cambia (ad esempio, il Riscontro correlato diventa più o meno sfruttabile), la Gravità del Riscontro si adeguerà di conseguenza.
