---
title: Contribuire ai Parser
description: Come contribuire ai parser
draft: false
weight: 1
audience: opensource
aliases:
- /it/en/open_source/contributing/how-to-write-a-parser
---

Tutti i comandi presuppongono che tu ti trovi nella radice del repository clonato django-DefectDojo.

## Prerequisiti

- Hai eseguito il fork di https://github.com/DefectDojo/django-DefectDojo e lo hai clonato localmente.
- Esegui il checkout di `dev` e assicurati di essere aggiornato con le ultime modifiche.
- Si consiglia di creare un branch dedicato per il tuo sviluppo, come `git checkout -b parser-name`.

È più semplice utilizzare il deployment con docker compose poiché offre la capacità di hot-reload per uWSGI.
Configura il tuo ambiente per utilizzare l'ambiente dev:

`$ docker/setEnv.sh dev`

Dai un'occhiata a [DOCKER.md](https://github.com/DefectDojo/django-DefectDojo/blob/master/readme-docs/DOCKER.md) per maggiori dettagli.

### Immagini Docker

Ti consigliamo di creare le tue immagini docker localmente, e infine passare l'`uid` del tuo utente locale per poter scrivere nell'immagine (utile per i file di migrazione del database). Supponendo che l'`uid` del tuo utente sia `1000`, allora:

{{< highlight bash >}}
$ docker compose build --build-arg uid=1000
{{< /highlight >}}

## Quali file devi modificare?

| File                                          | Scopo
|-------                                        |--------
|`dojo/tools/<parser_dir>/__init__.py`          | File vuoto per l'inizializzazione della classe
|`dojo/tools/<parser_dir>/parser.py`            | La parte principale. Qui scrivi il tuo parser vero e proprio. Il nome della classe deve essere il nome del modulo Python senza underscore più `Parser`. **Esempio:** Quando il nome del modulo Python è `dependency_check`, il nome della classe deve essere `DependencyCheckParser`
|`unittests/scans/<parser_dir>/{many_vulns,no_vuln,one_vuln}.json` | File di esempio contenenti dati significativi per gli unit test. Il set minimo.
|`unittests/tools/test_<parser_name>_parser.py` | Unit test del parser.
|`dojo/settings/settings.dist.py`               | Se vuoi utilizzare un algoritmo di deduplicazione moderno basato su hashcode
|`docs/content/supported_tools/<file/api>/<parser_file>.md` | Documentazione, quale tipo di formato file è richiesto e come dovrebbe essere ottenuto


## Contratto della Factory

I parser vengono caricati dinamicamente con un pattern factory. Per far sì che il tuo parser venga caricato e funzioni correttamente, devi implementare il contratto.

1. il tuo parser **DEVE** trovarsi in un sotto-modulo del modulo `dojo.tools`
   - es: modulo `dojo.tools.my_tool.parser`
2. il tuo parser **DEVE** essere una classe in questo sotto-modulo.
   - es: `dojo.tools.my_tool.parser.MyToolParser`
3. Il nome di questa classe **DEVE** essere il nome del modulo Python senza underscore e con il suffisso `Parser`.
   - es: `dojo.tools.my_tool.parser.MyToolParser`
4. Questa classe **DEVE** avere un costruttore vuoto o nessun costruttore
5. Questa classe **DEVE** implementare 4 metodi:
   1. `def get_scan_types(self)` Questa funzione restituisce un elenco di tutti gli *scan_type* supportati dal tuo parser. Questi identificatori sono utilizzati internamente. Il tuo parser può supportare più di uno *scan_type*. Ad esempio alcuni parser utilizzano identificatori diversi per modificare il comportamento del parser (aggregazione, filtro, ecc...)
   2. `def get_label_for_scan_types(self, scan_type):` Questa funzione restituisce una stringa usata per fornire del testo nell'interfaccia (etichetta breve)
   3. `def get_description_for_scan_types(self, scan_type):` Questa funzione restituisce una stringa usata per fornire del testo nell'interfaccia (descrizione lunga)
   4. `def get_findings(self, file, test)` Questa funzione restituisce un elenco di riscontri
6. Se il tuo parser ha più di 1 scan_type (per la modalità dettagliata) **DEVI** implementare il metodo `def set_mode(self, mode)`
7. L'istanza del parser viene riutilizzata per tutte le importazioni eseguite per questo scan_type, quindi non memorizzare alcun dato a livello di classe

Esempio:

```Python

class MyToolParser(object):
    def get_scan_types(self):
        return ["My Tool Scan", "My Tool Scan detailed"]

    def get_label_for_scan_types(self, scan_type):
        if scan_type == "My Tool Scan":
            return "My Tool XML Scan aggregated by ..."
        else:
            return "My Tool XML Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Aggregates findings per cwe, title, description, file_path. SonarQube output file can be imported in HTML format. Generate with https://github.com/soprasteria/sonar-report version >= 1.1.0"

    def requires_file(self, scan_type):
        return False

    # mode:
    # None (default): aggregates vulnerabilites per sink filename (legacy behavior)
    # 'detailed' : No aggregation
    mode = None

    def set_mode(self, mode):
        self.mode = mode

    def get_findings(self, file, test):
        <...>

```

## Parser API

DefectDojo ha un numero limitato di parser API. Anche se non rimuoveremo questi connector, l'aggiunta di connector API si è rivelata problematica e quindi al momento non possiamo accettare nuovi parser / connector API dalla community per motivi di supportabilità. Per mantenere un connector API di alta qualità, è necessario disporre di una licenza per lo strumento. Ottenere tale licenza richiede una partnership con l'autore o il vendor. Siamo vicini ad annunciare un nuovo programma per aiutare a risolvere questo problema e portare i connector API in DefectDojo.

## Generatore di Template

Utilizza il parser [template](https://github.com/DefectDojo/cookiecutter-scanner-parser)  per generare rapidamente i file necessari. Per iniziare dovrai installare [cookiecutter](https://github.com/cookiecutter/cookiecutter).

{{< highlight bash >}}
$ pip install cookiecutter
{{< /highlight >}}

Quindi genera il tuo parser dello scanner dalla radice di django-DefectDojo:

{{< highlight bash >}}
$ cookiecutter https://github.com/DefectDojo/cookiecutter-scanner-parser
{{< /highlight >}}

Leggi [maggiori informazioni](https://github.com/DefectDojo/cookiecutter-scanner-parser) sulle variabili di configurazione del template.

## Cose a cui prestare attenzione

Ecco un elenco di considerazioni che renderanno il parser robusto sia per i casi comuni che per i casi limite.

### Non analizzare gli URL manualmente

Utilizziamo 2 moduli per gestire gli endpoint:
 - `hyperlink`
 - `dojo.models` con una classe specifica per gestire l'elaborazione degli URL per creare endpoint `Endpoint`.

Tutti i parser esistenti utilizzano lo stesso codice per analizzare gli URL e creare gli endpoint.
Utilizzare `Endpoint.from_uri()` è il modo migliore per creare gli endpoint.
Se hai davvero bisogno di analizzare un URL, utilizza il modulo `hyperlink`.

Buon esempio:

```python
    if "url" in item:
        endpoint = Endpoint.from_uri(item["url"])
        finding.unsaved_endpoints = [endpoint]
```

Esempio molto negativo:

```python
    u = urlparse(item["url"])
    endpoint = Endpoint(host=u.host)
    finding.unsaved_endpoints = [endpoint]
```

### Utilizzare le librerie giuste per analizzare le informazioni
Vari formati di file vengono gestiti tramite librerie. Per mantenere DefectDojo snello e anche per non estendere la superficie di attacco, mantieni al minimo il numero di librerie utilizzate e prendi come esempio altri parser.

#### defusedXML al posto di lxml
Poiché xml è per impostazione predefinita un formato non sicuro, le informazioni analizzate da vari output xml devono essere analizzate in modo sicuro. Nell'ambito di una valutazione, abbiamo stabilito che defusedXML è la libreria che utilizzeremo in futuro per analizzare i file xml nei parser, poiché questa libreria è considerata più sicura. Pertanto, accetteremo PR solo con la libreria defusedxml.

### Non tutti gli attributi sono obbligatori

I parser possono avere molti campi, di cui molti possono essere opzionali.
È meglio non impostare un attributo se non hai i dati, invece di riempirlo con valori come `NA`, `No data` ecc...

Controlla la classe `dojo.models.Finding`

### I dati potrebbero mancare nel report di origine

Assicurati sempre di includere controlli per evitare potenziali errori `KeyError` (ad esempio, il campo non esiste), per quei campi di cui non sei assolutamente certo che saranno sempre presenti nel file che verrà caricato. Questi si traducono in errori 500, e non fanno una bella impressione.

Buon esempio:

```python
   if "mykey" in data:
       finding.cwe = data["mykey"]
```

```python
   finding.cwe = data.get("mykey", 123)
```

```python
   some_list = data.get("key_of_the_list") or []
```

L'ultimo esempio protegge dai casi in cui `key_of_the_list` è presente, ma `null`.


### Analisi dei vettori CVSS

I dati possono avere vettori o punteggi `CVSS`. Defect Dojo utilizza il modulo `cvss` fornito da RedHat Security.
Esiste anche un metodo di supporto per validare il vettore ed estrarne il punteggio base e la gravità.

```python
    from dojo.utils import parse_cvss_data

    cvss_vector = <get CVSS3 or CVSS4 vector from the report>
    cvss_data = parse_cvss_data(cvss_vector)
    if cvss_data:
        finding.severity = cvss_data["severity"]
        finding.cvssv3 = cvss_data["cvssv3"]
        finding.cvssv4 = cvss_data["cvssv4"]
        # we don't set any score fields as those will be overwritten by Defect Dojo
```
Non è necessario utilizzare tutti i valori, poiché i report di scansione di solito forniscono il proprio valore per `severity`.
E talvolta anche per `cvss_score`. Defect Dojo non sovrascriverà alcun `cvss3_score` o `cvss4_score`.
Se non è impostato alcun punteggio, Defect Dojo utilizzerà la libreria `cvss` per calcolare il punteggio.
La risposta contiene anche la versione principale rilevata del vettore CVSS in `cvss_data["major_version"]`.


Se hai bisogno di un'elaborazione più manuale, puoi analizzare direttamente il vettore `CVSS`.

Esempio di utilizzo:

```python
    import cvss.parser
    from cvss import CVSS2, CVSS3, CVSS4

    # TEMPORARY: Use Defect Dojo implementation of `parse_cvss_from_text` white waiting for https://github.com/RedHatProductSecurity/cvss/pull/75 to be released
    vectors = cvss.parser.parse_cvss_from_text("CVSS:3.0/S:C/C:H/I:H/A:N/AV:P/AC:H/PR:H/UI:R/E:H/RL:O/RC:R/CR:H/IR:X/AR:X/MAC:H/MPR:X/MUI:X/MC:L/MA:X")
        if len(vectors) > 0 and type(vectors[0]) is CVSS3:
            print(vectors[0].severities())  # this is the 3 severities

            cvssv3 = vectors[0].clean_vector()
            severity = vectors[0].severities()[0]
            vectors[0].compute_base_score()
            cvssv3_score = vectors[0].scores()[0]
            finding.severity = severity
            finding.cvssv3_score = cvssv3_score
```

Non fare qualcosa del genere:

```
    def get_severity(self, cvss, cvss_version="2.0"):
        cvss = float(cvss)
        cvss_version = float(cvss_version[:1])
        # If CVSS Version 3 and above
        if cvss_version >= 3:
            if cvss > 0 and cvss < 4:
                return "Low"
            elif cvss >= 4 and cvss < 7:
                return "Medium"
            elif cvss >= 7 and cvss < 9:
                return "High"
            elif cvss >= 9:
                return "Critical"
            else:
                return "Informational"
        # If CVSS Version prior to 3
        else:
            if cvss > 0 and cvss < 4:
                return "Low"
            elif cvss >= 4 and cvss < 7:
                return "Medium"
            elif cvss >= 7 and cvss <= 10:
                return "High"
            else:
                return "Informational"
```

## Algoritmo di deduplicazione

Per impostazione predefinita, un nuovo parser utilizza l'algoritmo di deduplicazione 'legacy' documentato in [Informazioni sulla deduplicazione](/triage_findings/finding_deduplication/about_deduplication/)

Utilizza un algoritmo di deduplicazione predefinito laddove applicabile. Quando utilizzi i campi `unique_id_from_tool` o `vuln_id_from_tool` nella configurazione dell'hash code, è importante che questi siano univoci per il riscontro e costanti nel tempo tra scansioni successive. Se non è questo il caso, i valori possono comunque essere utili da impostare sul modello del riscontro senza utilizzarli per la deduplicazione.
I valori devono provenire direttamente dal report e non devono essere qualcosa calcolato internamente dal parser.

## Unit test

Ogni parser deve avere unit test, almeno per testare 0 vulnerabilità, 1 vulnerabilità e molte vulnerabilità. Per iniziare, puoi dare un'occhiata a come li hanno altri parser. Più test di qualità ci sono, meglio è.

È importante aggiungere controlli sugli attributi dei riscontri.
Ad esempio:

```python
        with self.subTest(i=0):
            finding = findings[0]
            self.assertEqual("test title", finding.title)
            self.assertEqual(True, finding.active)
            self.assertEqual(True, finding.verified)
            self.assertEqual(False, finding.duplicate)
            self.assertIn(finding.severity, Finding.SEVERITIES)
            self.assertEqual("CVE-2020-36234", finding.vulnerability_ids[0])
            self.assertEqual(261, finding.cwe)
            self.assertEqual("CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N", finding.cvssv3)
            self.assertIn("security", finding.tags)
            self.assertIn("network", finding.tags)
            self.assertEqual("3287f2d0-554f-491b-8516-3c349ead8ee5", finding.unique_id_from_tool)
            self.assertEqual("TEST1", finding.vuln_id_from_tool)
```

### Utilizzare with per aprire i file di esempio

Per assicurarti che gli handle dei file vengano chiusi correttamente, utilizza il pattern with per aprire i file.
Invece di:
```python
    testfile = open("path_to_file.json")
    ...
    testfile.close()
```

usa:
```python
    with open("path_to_file.json") as testfile:
        ...
```

Questo garantisce che il file venga chiuso alla fine dell'istruzione with, anche se si verifica un'eccezione da qualche parte nel blocco.

### Database di test

Django utilizza un database di test separato per l'esecuzione degli unit test, chiamato `test_defectdojo`. Viene creato e inizializzato automaticamente con un set di base di dati di test.

### Esegui i tuoi test

Questo comando locale avvierà l'unit test per il tuo nuovo parser

{{< highlight bash >}}
$ docker compose exec uwsgi bash -c 'python manage.py test unittests.tools.<your_unittest_py_file>.<main_class_name> -v2'
{{< /highlight >}}

oppure così:

{{< highlight bash >}}
$ ./run-unittest.sh --test-case unittests.tools.<your_unittest_py_file>.<main_class_name>
{{< /highlight >}}

Esempio per il parser aqua:

{{< highlight bash >}}
$ docker compose exec uwsgi bash -c 'python manage.py test unittests.tools.test_aqua_parser.TestAquaParser -v2'
{{< /highlight >}}

oppure così:

{{< highlight bash >}}
$ ./run-unittest.sh --test-case unittests.tools.test_aqua_parser.TestAquaParser
{{< /highlight >}}

Se vuoi eseguire tutti gli unit test dei parser, esegui semplicemente `$ docker-compose exec uwsgi bash -c 'python manage.py test -p "test_*_parser.py" -v2'`

### Validazione degli endpoint

Alcuni tipi di parser creano un elenco di endpoint vulnerabili (vengono memorizzati in `finding.unsaved_endpoints`). DefectDojo richiede che gli endpoint vengano memorizzati in un formato specifico (che segue gli RFC). Gli endpoint che non seguono questo formato possono comunque essere memorizzati, ma verranno contrassegnati come non validi (bandierina rossa 🚩nell'interfaccia). Per assicurarti che il tuo parser memorizzi gli endpoint nel formato corretto, esegui la funzione `.clean()` su tutti gli endpoint negli unit test

```python
findings = parser.get_findings(testfile, Test())
for finding in findings:
    for endpoint in finding.unsaved_endpoints:
        endpoint.clean()
```

### Test dei parser API

Non solo il parser, ma anche l'importer dovrebbe essere testato.
Il metodo `patch` di `unittest.mock` è solitamente utile per simulare le risposte API.
Se ne consiglia vivamente l'uso.

## Altri file che potrebbero essere coinvolti

### Modifiche al modello

Nel caso in cui tu debba modificare il modello, ad esempio per aumentare la dimensione di una colonna del database per adattarla a una stringa di dati più lunga da salvare
* Modifica ciò che ti serve in `dojo/models.py`
* Crea un nuovo file di migrazione in dojo/db_migrations eseguendo il comando seguente e includendolo come parte della tua PR

    {{< highlight bash >}}
    $ docker compose exec uwsgi bash -c 'python manage.py makemigrations -v2'
    {{< /highlight >}}

### Accettare un diverso tipo di file da caricare

Se vuoi essere in grado di accettare un nuovo tipo di file per il tuo parser, dai un'occhiata a `dojo/forms.py` intorno alla riga 436 (al momento della stesura di questo testo) oppure individua i 2 punti (per import e re-import) in cui trovi la stringa `attrs={"accept":`.

Formati attualmente accettati: .xml, .csv, .nessus, .json, .html, .js, .zip.

### La necessità di qualcosa in più del semplice parser.py

Ovviamente, nulla ti impedisce di avere più file oltre al file `parser.py`. È python :-)

## Esempi di pull request

Se vuoi dare un'occhiata ai parser precedenti che ora fanno parte di DefectDojo, consulta https://github.com/DefectDojo/django-DefectDojo/pulls?q=is%3Apr+sort%3Aupdated-desc+label%3A%22Import+Scans%22+is%3Aclosed

## Aggiornare la documentazione della pagina di importazione

Aggiungi un nuovo file .md in [`docs/content/en/connecting_your_tools/parsers`] con i dettagli del tuo nuovo parser.  Includi le seguenti intestazioni di contenuto:

* Tipo(i) di file accettabili - includi come generare questo tipo di file dallo strumento correlato, poiché alcuni strumenti hanno più metodi o richiedono comandi specifici.
* Un blocco di esempio di unit test, se applicabile.
* Un link alla cartella degli unit test pertinenti in modo che gli utenti possano navigare rapidamente lì dalla Documentazione.
* Un link allo scanner stesso - (ad es. link a GitHub o al vendor)

Ecco un esempio di una pagina di documentazione di un Parser completata: [https://github.com/DefectDojo/django-DefectDojo/blob/master/docs/content/supported_tools/file/acunetix.md](https://github.com/DefectDojo/django-DefectDojo/blob/master/docs/content/supported_tools/file/acunetix.md)
