---
title: Questionari
description: Capire i Questionari in OS DefectDojo
audience: opensource
weight: 2
---

In DefectDojo, un Questionario è un insieme riutilizzabile di domande che raccoglie informazioni da sviluppatori, team e stakeholder sia interni che esterni. Possono essere utilizzati per raccogliere input prima dell'inizio del lavoro, garantire l'allineamento tra individui e team durante l'avanzamento del lavoro e consentire un'analisi retrospettiva una volta completato il lavoro. 

## Modelli di Questionario 

Un modello di Questionario definisce la struttura e il contenuto del Questionario, incluso il suo nome, la descrizione e le Domande associate. Creare un modello di Questionario non lo rende automaticamente disponibile per le risposte. Per raccogliere risposte, un modello di Questionario deve essere distribuito come **Questionario Generale** oppure come **Questionario Collegato**.

### Questionari Generali e Collegati 

I Questionari Generali e Collegati differiscono per diversi aspetti, tra cui il modo in cui vengono distribuiti, chi può rispondere e dove vengono archiviate le risposte.

| Questionari Generali | Questionari Collegati |
|---|---|
| Richiedono la pubblicazione | Non richiedono la pubblicazione |
| Richiedono una data di scadenza | Rimangono attivi se l'Engagement è ancora attivo |
| Consentono risposte anonime | Non consentono risposte anonime |
| Sono condivisibili sia internamente che esternamente | Sono condivisibili solo internamente |
| Non consentono di modificare le risposte | Consentono di modificare le risposte |
| Le risposte sono visibili solo dopo la scadenza | Le risposte sono visibili immediatamente |
| Le risposte sono visibili in "Tutti i Questionari" | Le risposte sono visibili all'interno dell'Engagement |
| Possono essere convertiti in un Engagement | Sono già collegati a un Engagement |

#### Ciclo di vita della distribuzione del Questionario

I modelli di Questionario seguono cicli di vita diversi a seconda del tipo di distribuzione:

**Questionari Generali** 
Modello → Pubblicato → Accetta Risposte → Scade → Conversione opzionale in Engagement

**Questionari Collegati**
Modello → Collegato all'Engagement → Accetta Risposte → Rimane attivo finché l'Engagement è attivo

#### Separazione delle risposte

Un singolo modello di Questionario può essere distribuito più volte contemporaneamente, sia come Questionario Generale che Collegato. Ogni distribuzione crea il proprio set indipendente di risposte.

Se lo stesso modello di Questionario viene distribuito come Questionario Generale ed è anche collegato a un Engagement, le risposte inviate tramite ciascuna distribuzione vengono archiviate in modo indipendente e non vengono combinate. Questo consente di riutilizzare lo stesso modello di Questionario in contesti diversi mantenendo separati i set di risposte.

## Accedere a Questionari e Domande 

È possibile accedere a Questionari e Domande dalla barra laterale facendo clic sull'opzione **Questionnaires**. Il sottomenu offre accesso a **All Questionnaires** e **All Questions**.

![image](images/q_ss1.png)

È importante notare che l'accesso alle viste All Questionnaires e All Questions è riservato agli Utenti con stato di Superuser. Solo i Superuser possono creare modelli di Questionario, creare Domande e distribuire Questionari. Gli Utenti senza stato di Superuser possono comunque rispondere ai Questionari Generali condivisi con loro e rispondere anche ai Questionari Collegati degli Engagement a cui hanno accesso, ma non possono crearli né gestirli.

### Questionari 

La vista All Questionnaires include due tabelle:
- **Questionnaires**
    - Questa sezione include tutti i modelli di Questionario esistenti.
- **General Questionnaires**
    - Questa sezione include tutti i Questionari Generali attualmente aperti alle risposte. 

Entrambe le sezioni possono essere filtrate per nome, descrizione o stato attivo.

### Domande 

La vista All Questions include una tabella delle Domande che possono attualmente essere aggiunte a un Questionario. Può anche essere filtrata in base allo stato opzionale di ciascuna Domanda, al contenuto o al tipo di domanda (ad esempio, domanda testuale o domanda a scelta multipla).

## Gestire i modelli di Questionario 

### Creare Questionari 

È possibile creare nuovi Questionari utilizzando il pulsante Create Questionnaire nella vista All Questionnaires. 

![image](images/q_ss2.png)

Dopo aver inserito un nome e una descrizione, il Questionario può essere creato senza Domande (che possono essere aggiunte in seguito) oppure le Domande possono essere aggiunte immediatamente. 

#### Aggiungere immediatamente Domande a un nuovo Questionario 

Se le Domande vengono aggiunte immediatamente, selezionare tutte le Domande applicabili dal menu a discesa successivo. È anche possibile creare una nuova Domanda da aggiungere al Questionario facendo clic sul segno + a destra del menu a discesa. 

![image](images/q_ss12.png)

Una volta selezionate tutte le Domande applicabili, fare clic su **Update Questionnaire Questions** per aggiungere tutte le Domande selezionate al Questionario. 

#### Aggiungere Domande a un Questionario preesistente 

Per aggiungere Domande a un Questionario preesistente, fare clic sul nome del Questionario nella tabella Questionnaires, fare clic su **Edit Questions**, selezionare eventuali nuove Domande da aggiungere al Questionario dal menu a discesa, quindi fare clic su **Update Questionnaire Questions**.

### Creare Domande 

È possibile creare nuove Domande utilizzando il pulsante **Create Question** nella vista All Questions. 

![image](images/q_ss3.png)

Inoltre, le Domande possono anche essere create al momento di decidere quali Domande aggiungere a un Questionario, facendo clic sul segno + a destra del menu a discesa. 

#### Tipi di Domanda 

Quando si crea una nuova Domanda, questa può essere formattata come domanda testuale o come domanda a scelta multipla selezionando **Text** oppure **Choice** dal menu a discesa.

#### Consentire risposte multiple e risposte facoltative 

Il numero massimo di risposte consentite in una domanda a scelta multipla è sei. Selezionando la casella **Multichoice** è possibile scegliere più risposte (disponibile solo per le domande a scelta multipla). Le Domande possono anche essere contrassegnate come **Optional** selezionando la casella corrispondente. 

Consultare la sezione [Editing Questions](#editing-questions) per sapere come aggiungere ulteriori risposte a una domanda a scelta multipla. 

#### Ordine delle Domande 

Determinare l'ordine di una Domanda assegnandole un numero d'ordine. Ad esempio, se una Domanda ha 1 nel campo Order, quella Domanda apparirà sopra una Domanda con 2 nel campo Order. 

![image](images/q_ss13.png)

### Modificare le Domande

Una volta creata, una Domanda può essere modificata accedendo al sottomenu All Questions e facendo clic sulla Domanda da modificare. Le Domande non possono essere eliminate. 

È importante evitare di modificare Domande che fanno parte di Questionari attivi. Se una qualsiasi parte di una Domanda viene modificata (ad esempio l'ordine, lo stato facoltativo, la correzione di un errore di battitura, l'aggiunta di una possibile risposta, ecc.) e quella Domanda faceva parte di un Questionario attivo per il quale erano già state inviate risposte, tutte le risposte precedentemente inviate verranno invalidate e sarà necessario inviarle nuovamente.

#### Modificare le Domande testuali

Dopo la creazione, le uniche modifiche che possono essere apportate alle Domande testuali sono l'ordine, lo stato facoltativo e la formulazione della domanda. 

#### Modificare le Domande a scelta multipla 

Sebbene il numero predefinito di possibili risposte a una domanda a scelta multipla sia sei, questo può essere aumentato dopo la creazione del Questionario. Per farlo, fare clic sulla Domanda nella vista All Questions, fare clic sul segno **+** a destra del menu a discesa Choices, aggiungere la nuova risposta e fare clic su **Submit**. 

![image](images/q_ss16.png)

![image](images/q_ss17.png)

La nuova opzione creata non verrà aggiunta automaticamente al Questionario. Per aggiungerla, fare clic sul menu a discesa **Choices** e selezionare l'opzione appena aggiunta. Accanto ad essa apparirà un segno di spunta che indica che è ora inclusa come possibile risposta nel Questionario.

![image](images/q_ss18.png)

## Distribuire i Questionari 

Una volta creato correttamente un modello di Questionario, può essere distribuito per accettare risposte. Il processo di distribuzione è leggermente diverso a seconda del tipo di Questionario. 

### Distribuzione di un Questionario Generale

Per distribuire un Questionario Generale: 
1. Accedere alla vista All Questionnaires.
2. Fare clic sul segno **+** sul lato destro della tabella General Questionnaires.
3. Selezionare il Questionario da distribuire.
4. Impostare la data di scadenza.
5. Fare clic su **Add Questionnaire**. 

#### Condividere un Questionario Generale 

Una volta distribuito, un Questionario Generale può essere condiviso facendo clic su **Share Questionnaire** all'interno della colonna Actions della tabella General Questionnaires. Questo genererà un link che può essere condiviso con i destinatari previsti, consentendo anche di confermare che il Questionario sia formattato come previsto prima di procedere. 

![image](images/q_ss14.png)

Notare quanto segue: 
- Le eventuali risposte a un Questionario Generale non saranno visibili finché il Questionario non sarà scaduto. 
- Non è possibile modificare la data di scadenza una volta che il Questionario è stato pubblicato. 
- L'orario predefinito in cui un Questionario scade è mezzanotte (ad esempio, un Questionario con scadenza il 31 dicembre 2026 sarà visibile solo fino alle 23:59:59 di quella data). 
- Non è possibile impostare un orario di scadenza personalizzato. 

Vedere [Enabling Anonymous Responses](#enabling-anonymous-responses) qui sotto riguardo alla possibilità di consentire risposte da Utenti esterni. 

### Distribuzione di un Questionario Collegato

Per distribuire un Questionario Collegato:
1. Accedere all'Engagement a cui verrà collegato il Questionario. 
2. Fare clic sulla freccia verso il basso nella tabella **Additional Features**. 
3. Fare clic sul segno **+** sul lato destro della sottotabella Questionnaires. 
4. Selezionare il Questionario da collegare dal menu a discesa. 
5. Fare clic su **Add Questionnaire** oppure **Add Questionnaire and Respond**.

Il Questionario Collegato sarà ora attivo per tutti gli Utenti con accesso all'Engagement. 

#### Condividere un Questionario Collegato 

Per condividere il Questionario Collegato direttamente con gli Utenti interni di DefectDojo, fare clic sul menu kebab ⋮ e selezionare **Share Questionnaire** dal menu a discesa. Apparirà un link che può essere copiato e inoltrato al destinatario previsto.

![image](images/q_ss10.png)

Come già accennato, i Questionari Collegati possono essere condivisi solo con Utenti DefectDojo.

## Rispondere ai Questionari 

Il flusso di lavoro delle risposte differisce leggermente a seconda che il Questionario sia Generale o Collegato. 

### Rispondere a un Questionario Generale 

Per rispondere a un Questionario Generale, gli utenti non Superuser devono ricevere il link direttamente da un Superuser, come descritto [qui](#sharing-a-general-questionnaire). 

#### Abilitare le risposte anonime 

Per impostazione predefinita, i Questionari Generali sono accessibili solo dagli Utenti DefectDojo. Per consentire a soggetti esterni di rispondere ai Questionari DefectDojo, assicurarsi che l'opzione **Allow Anonymous Survey Responses** sia stata attivata nelle System Settings, che si trovano all'interno della sezione **Configurations** della barra laterale.

![image](images/q_ss4.png)

![image](images/q_ss5.png)

Le risposte esterne appariranno come anonime poiché non è associato alla risposta alcun ID utente DefectDojo. 

Se l'ambito di un Questionario include sia Utenti interni che esterni, creare un Questionario Generale e specificare il nome dell'Engagement nella descrizione al momento della creazione, il che consentirà di filtrare i risultati.

![image](images/q_ss8.png)

![image](images/q_ss9.png)

### Rispondere ai Questionari Collegati 

Per rispondere a un Questionario Collegato: 
1. Accedere alla vista dell'Engagement.
2. Espandere la tabella Additional Features.
3. Espandere la sottotabella Questionnaires.
4. Fare clic sul menu kebab ⋮ del Questionario Collegato. 
5. Fare clic su **Answer Questionnaire**.

![image](images/q_ss15.png)

I Questionari Collegati non consentono risposte esterne/anonime poiché per accedere all'Engagement è necessario l'accesso a DefectDojo.

## Risposte 

Come già accennato, ogni distribuzione di un modello di Questionario crea il proprio contenitore di risposte. Collegare lo stesso modello di Questionario a più Engagement produce set di risposte separati, e la pubblicazione di un Questionario Generale non influisce sui set di risposte dei Questionari Collegati.

### Risposte del Questionario Generale 

Una volta trascorsa la scadenza di un Questionario Generale:
- Non sarà più possibile inviare ulteriori risposte.
- Tutte le risposte precedenti verranno salvate e diventeranno visibili.
- Il Questionario verrà elencato come Unassigned Answered Engagement Questionnaire nella dashboard di DefectDojo.

Ci sono tre azioni che possono essere intraprese quando la finestra di risposta di un Questionario si è chiusa: **View Responses**, **Create Engagement** e **Assign User**.

#### Visualizzare le risposte del Questionario 

Selezionando **View Responses** verranno visualizzate tutte le risposte del Questionario.

#### Creare un Engagement da un Questionario 

Alla scadenza, un Questionario Generale può essere collegato a un Asset tramite un Engagement selezionando l'azione **Create Engagement**. Selezionare un Asset dall'elenco a discesa successivo e fare clic su **Create Engagement**. Sarà quindi possibile creare un nuovo Engagement e fornirgli dettagli specifici simili ad altri Engagement in DefectDojo, come Description, Version, Status, Tags, ecc.

![image](images/q_ss6.png)

![image](images/q_ss7.png)

#### Assegnare Utente 

L'azione Assign User richiederà di selezionare un Utente dal menu a discesa degli Utenti disponibili. Selezionare un Utente dal menu a discesa e fare clic su **Assign Questionnaire**, il che lo renderà il proprietario di quel Questionario.

### Risposte del Questionario Collegato 

I Questionari Collegati rimangono disponibili finché l'Engagement associato è attivo. Pertanto, le risposte sono visibili in qualsiasi momento. 

Il menu kebab ⋮ di un Questionario Collegato include diverse funzioni per gestire il Questionario e le relative risposte:
- **Answer Questionnaire**: Questa opzione apparirà se un Utente non ha ancora risposto al Questionario Collegato. Una volta risposto, appariranno View Responses e Edit Responses. 
- **View responses**: Consente agli Utenti di vedere tutte le risposte al Questionario fino a quel momento. 
- **Edit Responses**: Consente ai singoli Utenti di modificare le proprie Risposte precedenti.
- **Assign User**: Assegna il questionario a un Utente. 
- **Link to a Different Engagement**: Apre un menu a discesa di altri Engagement a cui assegnare il Questionario. 
- **Share Questionnaire**: Genera un link per condividere il Questionario con gli Utenti interni. 
- **Delete Questionnaire**: Scollegherà il Questionario dall'Engagement ed eliminerà tutte le risposte raccolte in precedenza.

## Eliminare i Questionari 

L'eliminazione dei Questionari Generali e Collegati ha effetti a valle diversi a seconda del risultato previsto dell'eliminazione.

### Eliminare i Questionari Generali 

L'eliminazione di un Questionario Generale dalla tabella General Questionnaires nella sezione All Questionnaires eliminerà tutte le risposte raccolte da quella distribuzione prima dell'eliminazione. Eventuali Questionari Collegati che utilizzavano lo stesso modello di Questionario non verranno eliminati. 

### Eliminare i Questionari Collegati 

L'eliminazione di un Questionario Collegato scollegherà il Questionario dall'Engagement. Tutte le risposte raccolte all'interno dell'Engagement prima dell'eliminazione andranno perse. I Questionari Generali che erano stati distribuiti in precedenza utilizzando lo stesso modello di Questionario non ne risentiranno. 

### Eliminare i modelli di Questionario

Per eliminare completamente un modello di Questionario, selezionarlo dalla tabella Questionnaires nella vista All Questionnaires e fare clic su **Delete Questionnaire**. Questo eliminerà definitivamente il modello di Questionario e tutte le risposte associate da tutte le distribuzioni. Questa azione non può essere annullata.
