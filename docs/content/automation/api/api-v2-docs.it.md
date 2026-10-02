---
title: API DefectDojo v2
description: L'API di DefectDojo consente di automatizzare le attività, ad es. il
  caricamento dei report di scansione nelle pipeline CI/CD.
draft: false
weight: 2
aliases:
- /it/en/api/api-v2-docs
---

L'API di DefectDojo è creata utilizzando [Django Rest
Framework](http://www.django-rest-framework.org/). La documentazione di
ogni endpoint è disponibile in ogni installazione di DefectDojo su
[`/api/v2/oa3/swagger-ui`](https://demo.defectdojo.org/api/v2/oa3/swagger-ui/) ed è accessibile selezionando il link API v2
Docs nel menu a tendina dell'utente nell'intestazione.

![image](images/api_v2_1.png)

La documentazione è generata utilizzando [drf-spectacular](https://drf-spectacular.readthedocs.io/) su [`/api/v2/oa3/swagger-ui/`](https://demo.defectdojo.org/api/v2/oa3/swagger-ui/), ed è
interattiva. Nella parte superiore della documentazione API v2 è presente un link che genera una specifica OpenAPI v3.

Per interagire con la documentazione, è necessario un valore valido dell'header Authorization.
Visita la vista `/api/key-v2` per generare la tua
API Key (`Token <api_key>`) e copia il valore dell'header fornito.

![image](images/api_v2_2.png)

Ogni sezione consente di effettuare chiamate all'API e visualizzare la Request
URL, il Response Body, il Response Code e i Response Headers.

![image](images/api_v2_3.png)

Se hai effettuato l'accesso alla web UI di Defect Dojo, non è necessario fornire il token di autorizzazione.

## Autenticazione

L'API utilizza l'autenticazione tramite header con API key. Il formato dell'
header dovrebbe essere: :

    Authorization: Token <api.key>

Ad esempio: :

    Authorization: Token c8572a5adf107a693aa6c72584da31f4d1f1dcff

### Metodo di autenticazione alternativo

Se utilizzi [un metodo di autenticazione alternativo](/admin/sso/) per gli utenti, potresti voler disabilitare i token API di DefectDojo perché potrebbero aggirare il tuo sistema di autenticazione.
L'uso dei token API di DefectDojo può essere disabilitato impostando la variabile d'ambiente `DD_API_TOKENS_ENABLED` su `False`.
Oppure è possibile disabilitare solo l'endpoint `api/v2/api-token-auth/` impostando `DD_API_TOKEN_AUTH_ENDPOINT_ENABLED` su `False`.

## Codice di esempio

Ecco alcuni semplici esempi in python e i loro risultati prodotti contro
l'endpoint `/users`: :

{{< highlight python >}}
import requests

url = 'http://127.0.0.1:8000/api/v2/users'
headers = {'content-type': 'application/json',
            'Authorization': 'Token c8572a5adf107a693aa6c72584da31f4d1f1dcff'}
r = requests.get(url, headers=headers, verify=True) # set verify to False if ssl cert is self-signed

for key, value in r.__dict__.items():
  print(f"'{key}': '{value}'")
  print('------------------')
{{< /highlight >}}

Questo codice restituirà l'elenco di tutti gli utenti definiti in DefectDojo.
Il risultato dell'oggetto json è simile a questo: :

{{< highlight json >}}
    [
        {
          "first_name": "Tyagi",
          "id": 22,
          "last_login": "2019-06-18T08:05:51.925743",
          "last_name": "Paz",
          "username": "dev7958"
        },
        {
          "first_name": "saurabh",
          "id": 31,
          "last_login": "2019-06-06T11:44:32.533035",
          "last_name": "",
          "username": "saurabh.paz"
        }
    ]
{{< /highlight >}}

Ecco un altro esempio contro l'endpoint `/users`, questa
volta filtreremo i risultati per includere solo gli utenti il cui nome
utente include `jay`:

{{< highlight python >}}
import requests

url = 'http://127.0.0.1:8000/api/v2/users/?username__contains=jay'
headers = {'content-type': 'application/json',
            'Authorization': 'Token c8572a5adf107a693aa6c72584da31f4d1f1dcff'}
r = requests.get(url, headers=headers, verify=True) # set verify to False if ssl cert is self-signed

for key, value in r.__dict__.items():
  print(f"'{key}': '{value}'")
  print('------------------')
{{< /highlight >}}

Il risultato dell'oggetto json è: :

{{< highlight json >}}
[
    {
        "first_name": "Jay",
        "id": 22,
        "last_login": "2015-10-28T08:05:51.925743",
        "last_name": "Paz",
        "username": "jay7958"
    },
    {
        "first_name": "",
        "id": 31,
        "last_login": "2015-10-13T11:44:32.533035",
        "last_name": "",
        "username": "jay.paz"
    }
]
{{< /highlight >}}

Consulta la [documentazione di Django Rest Framework
sull'interazione con un'API](https://www.django-rest-framework.org/) per
ulteriori esempi e suggerimenti.

## Chiamare manualmente l'API

Strumenti come Postman possono essere utilizzati per testare l'API.

Esempio per l'importazione di un risultato di scansione:

-   Verbo: POST
-   URI: <http://localhost:8080/api/v2/import-scan/>
-   Scheda Headers:

    aggiungi l'header di autenticazione
    :   -   Key: Authorization
        -   Value: Token c8572a5adf107a693aa6c72584da31f4d1f1dcff

-   Scheda Body

    -   seleziona "form-data", clicca su "bulk edit". Esempio per una scansione ZAP:

<!-- -->

    engagement:3
    verified:true
    active:true
    lead:1
    tags:test
    scan_type:ZAP Scan
    minimum_severity:Info
    close_old_findings:false

-   Scheda Body

       -   Clicca sulla modalità "Key-value"
       -   Aggiungi un parametro "file" di tipo "file". Questo attiverà
            i dati multi-part form per l'invio del contenuto del file
       -   Sfoglia per trovare il file da caricare

-   Clicca su invia

## Client / Wrapper API

| Wrapper                      | Stato                   | Note |
| -----------------------------| ------------------------| ------------------------|
| [Wrapper python specifico](https://github.com/DefectDojo/defectdojo_api)      | funzionante (2021-01-21)    | Wrapper API che include script per il caricamento continuo CI/CD. È leggermente indietro rispetto alle ultime funzionalità dell'API poiché prevediamo di rinnovare il wrapper API |
| [Wrapper python Openapi](https://github.com/alles-klar/defectdojo-api-v2-client)       | | solo proof of concept, dove abbiamo scoperto che la specifica OpenAPI non è ancora perfetta |
| [Libreria Java](https://github.com/secureCodeBox/defectdojo-client-java)                 | funzionante (2021-08-30)    | Creata dalle gentili persone di [SecureCodeBox](https://github.com/secureCodeBox/secureCodeBox) |
| [Immagine che utilizza la libreria Java](https://github.com/SDA-SE/defectdojo-client) | funzionante (2021-08-30)    | |
| [Libreria .Net/C#](https://www.nuget.org/packages/DefectDojo.Api/)              | funzionante (2021-06-08)    | |
| [dd-import](https://github.com/MaibornWolff/dd-import)                    | funzionante (2021-08-24)    | dd-import non è direttamente un wrapper API. Offre alcune funzioni di comodità per semplificare l'importazione di riscontri e dati sui linguaggi dalle pipeline CI/CD. |

Alcuni dei wrapper API contengono una discreta quantità di logica per facilitare la scansione e l'importazione negli ambienti CI/CD. Siamo nel processo di semplificare questo aspetto rendendo l'API di DefectDojo più intelligente (in modo che i wrapper/script API possano essere più semplici).

## Note sull'API

### Importazione / Reimportazione

**Reimport** è in realtà il modo più semplice per iniziare, poiché creerà al volo qualsiasi entità se necessario e rileverà automaticamente se si tratta di un primo caricamento o di un nuovo caricamento.

## Importazione
L'importazione tramite API viene eseguita tramite l'endpoint [import-scan](https://demo.defectdojo.org/api/v2/doc/).

Come descritto in [Gerarchia dei Prodotti](/asset_modelling/os_hierarchy/product_hierarchy/), il Test viene creato all'interno di un Engagement, all'interno di un Prodotto, all'interno di un Product Type.

Un'importazione può essere eseguita specificando i nomi di queste entità nella richiesta API:


```JSON
{
    "minimum_severity": 'Info',
    "active": True,
    "verified": True,
    "scan_type": 'ZAP Scan',
    "test_title": 'Manual ZAP Scan by John',
    "product_type_name": 'Good Products',
    "product_name": 'My little product',
    "engagement_name": 'Important import',
    "auto_create_context": True,
}
```

Quando `auto_create_context` è `True`, il prodotto, l'engagement e l'ambiente verranno creati se necessario. Assicurati che il tuo utente disponga di [permessi](/admin/user_management/about_perms_and_roles/) sufficienti per farlo.

Un modo classico per importare una scansione è specificare invece l'ID dell'engagement:

```JSON
{
    "minimum_severity": 'Info',
    "active": True,
    "verified": True,
    "scan_type": 'ZAP Scan',
    "test_title": 'Manual ZAP Scan by John',
    "engagement": 123,
}
```

## Reimportazione
La reimportazione tramite API viene eseguita tramite l'endpoint [reimport-scan](https://demo.defectdojo.org/api/v2/doc/).

Una reimportazione può essere eseguita specificando i nomi di queste entità nella richiesta API:


```JSON
{
    "minimum_severity": 'Info',
    "active": True,
    "verified": True,
    "scan_type": 'ZAP Scan',
    "test_title": 'Manual ZAP Scan by John',
    "product_type_name": 'Good Products',
    "product_name": 'My little product',
    "engagement_name": 'Important import',
    "auto_create_context": True,
    "do_not_reactivate": False,
}
```

Quando `auto_create_context` è `True`, il Product Type, il Prodotto e l'Engagement verranno creati se non esistono già. Assicurati che il tuo utente disponga di [permessi](/admin/user_management/about_perms_and_roles/) sufficienti per creare un Prodotto/Product Type.

Quando `do_not_reactivate` è `True`, l'importazione/reimportazione ignorerà i riscontri attivi caricati e non riattiverà i riscontri precedentemente chiusi, pur creando comunque nuovi riscontri se ce ne sono di nuovi. Riceverai una nota sul riscontro per spiegare che non è stato riattivato per questo motivo.

Una reimportazione selezionerà automaticamente l'ultimo test all'interno dell'engagement fornito che soddisfa lo `scan_type` fornito e (facoltativamente) il `test_title` fornito.

Se non viene trovato alcun Test esistente, l'endpoint di reimportazione utilizzerà la funzione di importazione per importare il report fornito in un nuovo Test. Questo significa che uno script (CI/CD) che utilizza l'API non ha bisogno di sapere se un Test esiste già, o se si tratta di un primo caricamento per questo Prodotto / Engagement.

Un modo classico per reimportare una scansione è specificare invece l'ID del test:

```JSON
{
    "minimum_severity": 'Info',
    "active": True,
    "verified": True,
    "scan_type": 'ZAP Scan',
    "test": 123,
}
```

## Generazione dei Report

DefectDojo può generare un report dei riscontri tramite l'API nei formati **JSON**, **HTML**, **CSV** o **Excel**.

Un report viene generato con una richiesta `POST` a un'azione `generate_report/`. L'endpoint findings genera report sull'intera istanza, e la maggior parte degli altri oggetti espone un'azione per\-oggetto:

| Endpoint | Ambito |
|---|---|
| `POST /api/v2/findings/generate_report/` | Ogni riscontro che hai il permesso di visualizzare |
| `POST /api/v2/products/{id}/generate_report/` | Un prodotto |
| `POST /api/v2/engagements/{id}/generate_report/` | Un engagement |
| `POST /api/v2/tests/{id}/generate_report/` | Un test |
| `POST /api/v2/product_types/{id}/generate_report/` | Un product type |
| `POST /api/v2/endpoints/{id}/generate_report/` | Un endpoint |

Gli alias degli oggetti Pro espongono la stessa azione: `/api/v2/assets/{id}/generate_report/`, `/api/v2/organizations/{id}/generate_report/` e `/api/v2/location/{id}/generate_report/`.

### Opzioni della richiesta

Tutti i campi sono opzionali — inviare un corpo vuoto (`{}`) restituisce un report JSON.

| Campo | Tipo | Predefinito | Descrizione |
|---|---|---|---|
| `report_type` | string | `JSON` | Uno tra `JSON`, `HTML`, `CSV`, `Excel`. |
| `include_finding_notes` | boolean | `false` | Include le note di ogni riscontro. |
| `include_finding_images` | boolean | `false` | Include le immagini allegate ai riscontri. |
| `include_executive_summary` | boolean | `false` | Include una sezione di riepilogo esecutivo. |
| `include_table_of_contents` | boolean | `false` | Include un indice. |

Un `report_type` non supportato (ad esempio `PDF`) restituisce `400 Bad Request` con un errore sul campo `report_type`.

### Esempio

Genera un report CSV di tutti i riscontri che puoi visualizzare e salvalo in un file:

```bash
curl -X POST \
  -H "Authorization: Token <your-api-token>" \
  -H "Content-Type: application/json" \
  -d '{"report_type": "CSV"}' \
  https://<your-instance>/api/v2/findings/generate_report/ \
  -o findings.csv
```

### Formati di risposta

| `report_type` | Content type | Risposta |
|---|---|---|
| `JSON` (predefinito) | `application/json` | Corpo del report nella risposta |
| `HTML` | `text/html` | Pagina del report renderizzata |
| `CSV` | `text/csv` | Allegato file |
| `Excel` | `application/vnd.openxmlformats-officedocument.spreadsheetml.sheet` | Allegato file `.xlsx` |

CSV ed Excel vengono restituiti come allegati file con un header `Content-Disposition` anziché come corpo JSON. Il nome del file viene ricavato dall'oggetto da cui è stato generato il report — ad esempio `product_1_findings.csv` o `test_42_findings.xlsx`. L'endpoint `/findings/generate_report/` non è associato a un singolo oggetto, quindi i suoi download sono chiamati `findings.csv` e `findings.xlsx`.

### Note e limitazioni

* Le opzioni `include_*` influiscono solo sui report **JSON** e **HTML**. Le esportazioni **CSV** ed **Excel** contengono sempre le righe dei riscontri.
* La generazione dei report richiede il permesso di **visualizzazione** sugli oggetti coinvolti, e un report contiene sempre e solo i riscontri che sei autorizzato a vedere.
* **I filtri standard tramite parametri di query non vengono applicati a questa azione.** A differenza di `GET /api/v2/findings/`, l'azione `generate_report/` non applica i filtri dei riscontri, quindi una richiesta come `POST /api/v2/findings/generate_report/?severity=High` genererà comunque un report su tutti i riscontri che puoi visualizzare. Per restringere un report, generalo invece da un prodotto, engagement o test specifico.

## Comportamento di eliminazione asincrona

Le eliminazioni in DefectDojo (sia tramite API che UI) vengono elaborate in modo **asincrono** dai worker in background di Celery. Quando elimini un Engagement, un Test o un altro oggetto, l'API o la UI restituiscono immediatamente una risposta di successo, ma l'eliminazione effettiva viene eseguita in background.

Questo significa che:
- Gli oggetti potrebbero continuare ad apparire nelle query per un certo periodo di tempo dopo che l'eliminazione è stata confermata.
- Le eliminazioni a cascata (ad es. l'eliminazione di un Engagement elimina anche i suoi Test e Riscontri) vengono elaborate come una catena di attività in background. Gli oggetti figli vengono rimossi in ordine di dipendenza: prima i Riscontri, poi i Test, poi gli Engagement.
- Per Engagement di grandi dimensioni con molti Riscontri, questo processo può richiedere diversi minuti per completarsi.

Non è necessario creare script personalizzati per eliminare gli oggetti in ordine di dipendenza. Una singola richiesta `DELETE` su un Engagement si propagherà automaticamente a cascata su tutti gli oggetti figli. Basta lasciare il tempo necessario alle attività in background per completarsi.

## Limiti di paginazione dell'API

DefectDojo Pro impone una dimensione massima della pagina di **250** risultati per richiesta API. Impostare `limit` a un valore superiore a 250 può causare errori HTTP 502 dovuti a timeout delle query.

Le istanze Open Source di DefectDojo possono anch'esse riscontrare timeout con dimensioni di pagina molto grandi, a seconda delle dimensioni del dataset e delle risorse del server.

Per set di risultati di grandi dimensioni, utilizza la paginazione con una dimensione di pagina compresa tra 50 e 250 e aggiungi brevi ritardi tra le richieste paginate per evitare di saturare il pool di worker.

## Best practice per l'importazione su larga scala

Quando importi risultati di scansione su larga scala (ad es. pipeline SBOM con migliaia di componenti), considera quanto segue:

- **Usa `background_import=true`** per payload di grandi dimensioni. Le importazioni sincrone occupano un worker uwsgi per l'intera durata dell'importazione, il che può degradare le prestazioni per tutti gli utenti.
- **Punta a dimensioni del payload inferiori a 1 MB per importazione**, quando possibile. Suddividi gli SBOM di grandi dimensioni in file più piccoli per prodotto o gruppo di componenti.
- **Aggiungi ritardi tra chiamate API consecutive** per evitare l'esaurimento del pool di worker, che causa errori HTTP 502.
- **Usa Reimport** (`/api/v2/reimport-scan/`) per le scansioni ricorrenti, per aggiornare i riscontri esistenti invece di crearne di duplicati.

## Risposte dell'importazione in background (API: `background_import`)

Un'importazione in background viene restituita non appena il report caricato è stato analizzato, prima che
qualsiasi riscontro sia stato scritto. La sua risposta descrive quindi un lavoro *pianificato*, ed è
strutturata diversamente rispetto a una sincrona. Questo vale per `/api/v2/import-scan/` e
`/api/v2/reimport-scan/` ogni volta che `background_import` è `true`, oppure ogni volta che
l'impostazione di sistema `api_async_import` la attiva per ogni importazione.

Una risposta in background contiene:

- `background_import` — `true`. Questo è il campo su cui basare la logica.
- `status` — lo stato del ciclo di vita del test nel momento in cui la risposta è stata prodotta:
  `Processing`, `Post Processing - Deduplication`,
  `Post Processing - False Positive History`, `Processed` o `Failed`.
- `findings_parsed` — quanti riscontri sono stati letti dal report. Questo è un conteggio di analisi,
  non un conteggio di creazione: la deduplicazione e le opzioni di importazione fornite determinano
  quanti riscontri vengono effettivamente scritti.
- `test_id` (e `engagement_id`, `product_id`, `product_type_id`) — gli identificatori da
  interrogare periodicamente.
- `message` — le stesse informazioni di `status` e `findings_parsed`, in forma discorsiva. Preferisci
  i campi strutturati.

**Non** contiene `statistics`, e non contiene `deduplication_complete`.
Queste chiavi sono assenti anziché pari a zero, perché a quel punto non è stato creato alcun riscontro
e riportare degli zeri descriverebbe erroneamente l'importazione. Un client che legge
`response["statistics"]` incondizionatamente fallirà su un'importazione in background — leggi prima
`background_import`, oppure usa `statistics` solo nel percorso sincrono.

Per seguire un'importazione in background fino al completamento, interroga periodicamente il test:

```
POST /api/v2/import-scan/        (background_import=true)  -> test_id, status, findings_parsed
GET  /api/v2/tests/{test_id}/                              -> status, processing
```

Ripeti la `GET` finché `status` non è `Processed` (l'importazione è terminata, e i conteggi dei riscontri
del test sono ora significativi) o `Failed` (l'importazione non si è completata). Mentre
l'importazione è in corso, `processing` è `true` e `status` indica in quale fase si trova. Usa
alcuni secondi tra un'interrogazione e l'altra; un report di grandi dimensioni può richiedere minuti nella post-elaborazione.

Un'importazione sincrona (`background_import` omesso o `false`) è invariata: restituisce
la risposta una volta che i riscontri sono stati scritti, include `statistics` e non include `status`
né `findings_parsed`.

## Utilizzo del campo Data di completamento scansione (API: `scan_date`)

DefectDojo offre una pletora di report di scanner supportati, ma non tutti contengono le
informazioni più importanti per un utente. Il campo `scan_date` è una funzionalità intelligente e flessibile che
consente agli utenti di impostare la data di completamento di un determinato report di scansione, e di propagarla
a tutti i riscontri importati. Questo campo **non** è obbligatorio, ma il valore predefinito per
questo campo è la data di importazione (quando la richiesta viene elaborata e viene restituita una risposta positiva).

Ecco i seguenti casi d'uso per l'utilizzo di questo campo:

1. Il report **non** imposta la data, e `scan_date` **non** è impostato all'importazione
    - La data del riscontro sarà il valore predefinito di `scan_date`
2. Il report **imposta** la data, e `scan_date` **non** è impostato all'importazione
    - La data del riscontro sarà quella impostata dal report
3. Il report **non** imposta la data, e `scan_date` **è** impostato all'importazione
    - La data del riscontro sarà quella impostata dall'utente per `scan_date`
4. Il report **imposta** la data, e `scan_date` **è** impostato all'importazione
    - La data del riscontro sarà quella impostata dall'utente per `scan_date`
