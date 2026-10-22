---
title: Modello di documentazione del parser
toc_hide: true
weight: 2
audience: opensource
aliases:
- /it/en/open_source/contributing/parser-documentation-template
---

Questo modello è pensato per documentare un parser nuovo o esistente. Sentiti libero di migliorarlo con qualsiasi informazione aggiuntiva che possa aiutare i tuoi colleghi professionisti della sicurezza.

* Copia questo file .md e aggiungilo a `/docs/content/supported_tools/file` nel repository GitHub.
* Aggiorna il titolo in modo che corrisponda al nome del tuo parser nuovo o esistente.
* Compila tutte le sezioni elencate di seguito. Rimuovi eventuali istruzioni o esempi presenti in ciascuna sezione.

### Tipi di file
_Specifica tutti i tipi di file accettati dal tuo parser (ad es. CSV, JSON, XML)._
_Includi le istruzioni su come creare o esportare il formato di file accettabile dallo strumento di sicurezza correlato._

### Numero totale di campi in [Formato file]
Campi dati totali:  _Numero totale di campi contenuti nel file di esportazione dello strumento di sicurezza._
Campi dati totali analizzati:  _Numero totale di campi analizzati nel riscontro DefectDojo._
Campi dati totali NON analizzati: _Numero totale di campi NON analizzati nel riscontro DefectDojo._

_Utilizzando il formato seguente, fornisci una breve descrizione di ciascun campo e di come viene mappato al modello dati di DefectDojo._
_Includi tutti i campi presenti nel file di esportazione dello strumento di sicurezza, in ordine di comparsa, indicando eventuali campi che non vengono analizzati._

Campi in ordine di comparsa:
1. **Campo 1** - _Descrizione di come viene mappato questo campo (ad es. viene mappato sul titolo del riscontro, sull'host dell'endpoint.)_
2. **Campo 2** - _Descrizione di come viene mappato / non mappato questo campo._
3. **Campo 3** - _Descrizione di come viene mappato / non mappato questo campo._
4. **Campo 4** - _Descrizione di come viene mappato / non mappato questo campo._
_(continua per ogni campo nel file.)_

### Dettagli sulla mappatura dei campi
_Per ogni riscontro creato, includi i dettagli su come il parser analizza dati specifici. Ad esempio:_
- Come vengono creati gli endpoint (ad es. combinando i campi IP, Dominio, Porta e Protocollo).
- Come vengono gestite le occorrenze (ad es. `nb_occurences` predefinito impostato a 1, incrementato per i duplicati).
- Come viene gestita la deduplicazione (ad es. utilizzando un hash di gravità + titolo + descrizione).
- Descrive la gravità predefinita se non viene trovata alcuna corrispondenza di mappatura.

### Dati di scansione di esempio o Unit test
_Aggiungi un link alla cartella degli unit test o dei dati di scansione di esempio nel repository GitHub. Ad esempio:_
- [Cartella dei dati di scansione di esempio](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/[parser-name])

### Link allo strumento
_Fornisci un link allo scanner o allo strumento stesso (ad es. repository GitHub, sito web del vendor o documentazione). Ad esempio:_
- [Nome dello strumento](https://www.example.com/)
