---
title: Dimensionamento hardware per DefectDojo Pro self-hosted
description: Linee guida generali per dimensionare risorse di calcolo, memoria e storage
  per una distribuzione self-hosted di DefectDojo Pro
draft: false
weight: 4
audience: pro
---

Dimensionare una distribuzione DefectDojo si riduce a due domande. Quanti dati stai conservando, e quante persone ci lavorano contemporaneamente. Questa pagina fornisce punti di partenza per entrambe.

Considera quanto segue come una linea guida generale e non come una specifica. Le cifre sono deliberatamente prudenti e presuppongono una distribuzione che effettua il triage quotidiano insieme a importazioni regolari di scansioni. I tuoi numeri effettivi varieranno a seconda di come utilizzi il prodotto, quindi leggi le note sotto la tabella prima di predisporre qualsiasi risorsa.

Le specifiche sono espresse come cifre generiche di vCPU e memoria, in modo da applicarsi a qualsiasi provider cloud o hardware on-premise. Le indicazioni sui nodi applicativi presuppongono Kubernetes. Se esegui Docker Compose su un singolo host, usa gli stessi totali.

## Tabella di dimensionamento

| Riscontri | Utenti concorrenti | Database | Nodi applicativi |
| --- | --- | --- | --- |
| Fino a 100K | Fino a ~25 | 2–4 vCPU / 16–32 GB | 2 × (2–4 vCPU / 8–16 GB) |
| 100K–500K | ~25–50 | 4–8 vCPU / 32–64 GB | 2–3 × (4 vCPU / 16 GB) |
| 500K–1M | ~50–100 | 8 vCPU / 64–96 GB | 2–3 × (8 vCPU / 32 GB) |
| 1M–5M | ~100–250 | 8–16 vCPU / 96–128 GB | 5–6 × (8 vCPU / 32 GB) |
| 5M–10M | ~250–500 | 16–32 vCPU / 128–192 GB | 9–10 × (8 vCPU / 32 GB) |
| 500M | 500+ | 192 vCPU / 768 GB+ | 50+ × (8 vCPU / 32 GB) |

Dove ti collochi all'interno di un intervallo dipende dal tuo carico di lavoro. Parti dall'estremità superiore di un intervallo se ti riguarda qualcosa in [Cosa ti fa salire di livello](#what-pushes-you-up-a-tier).

La riga da 500M è un punto di riferimento all'estremità opposta, non una continuazione dello schema sopra, quindi non interpolare tra essa e il livello 10M. Una distribuzione che si colloca tra questi due valori deve essere dimensionata individualmente. Presuppone inoltre un lavoro che l'hardware da solo non svolge per te, trattato in [Distribuzioni molto grandi](#very-large-deployments).

## Come leggere questi numeri

### La memoria del database conta più della CPU del database

DefectDojo esegue query pesanti di aggregazione sui tuoi riscontri. Queste restano veloci finché il working set e i relativi indici vengono serviti dalla memoria, e degradano rapidamente non appena il database inizia a rivolgersi al disco. Quando devi scegliere, acquista memoria prima dei core. La tabella riflette questo principio. La memoria raddoppia approssimativamente da un livello all'altro, mentre il numero di CPU cresce molto più lentamente.

### I nodi applicativi seguono gli utenti, non i riscontri

Le cifre sugli utenti concorrenti nella tabella presuppongono che dataset più piccoli appartengano a team più piccoli. Questa ipotesi si rivela spesso errata. Se conservi 200K riscontri ma hai 100 persone contemporaneamente nell'interfaccia, dimensiona il livello applicativo per gli utenti e lascia il database dove lo colloca il tuo numero di riscontri. I due elementi scalano in modo indipendente.

C'è un'eccezione, all'estremità opposta della tabella. L'importazione e la deduplicazione vengono eseguite sul livello applicativo anziché nel database, quindi una volta che un dataset è abbastanza grande da far dominare quel lavoro, il numero di nodi segue il volume di ingestione anziché il numero di utenti. Questo è il motivo per cui la riga 500M si colloca ben al di sopra di ciò che la sua sola cifra sugli utenti suggerirebbe.

### La forma dei nodi è flessibile

Kubernetes distribuirà il carico sia che tu gli fornisca pochi nodi grandi sia molti nodi piccoli, quindi i conteggi dei nodi sopra riportati rappresentano una disposizione praticabile e non un requisito. Due aspetti vale la pena rispettare. Mantieni almeno due nodi in modo che la perdita di uno non blocchi l'applicazione, ed evita nodi più piccoli di 2 vCPU / 8 GB in modo che i singoli pod vengano pianificati senza difficoltà.

## Storage

Prevedi 20–30 GB di storage del database per milione di riscontri. Dove ti collochi in questo intervallo dipende da quanto colleghi a ciascun riscontro. Descrizioni lunghe e conteggi elevati di endpoint ti spingono verso l'estremità superiore. Le righe dei riscontri in sé rappresentano una piccola parte di questo spazio. La maggior parte va agli indici e alle tabelle correlate collegate a ciascun riscontro, quindi dimensionare basandosi solo sui dati delle righe ti lascerebbe ben al di sotto del necessario.

Ogni livello fino a 10M rientra in poche centinaia di GB di SSD general-purpose. Lo storage costa poco rispetto al costo di rimanerne privi, quindi predisponi le risorse per dove prevedi di trovarti tra un anno anziché per dove ti trovi ora. Se il tuo provider offre l'autoscaling dello storage, attivalo.

La riga 500M è dimensionata a 2,5 TB. Questa cifra presuppone che il dataset attivo sia gestito attivamente, con i riscontri più vecchi archiviati fuori dal percorso attivo anziché accumularsi indefinitamente. Applicato in modo ingenuo, il tasso per milione sopra riportato collocherebbe una distribuzione 500M non gestita diverse volte più in alto. Se ti stai dirigendo verso questa scala, tratta la strategia di archiviazione come parte dell'esercizio di dimensionamento e non come qualcosa da risolvere in seguito.

Lo storage a questa scala richiede attenzione anche al throughput, non solo alla capacità. Una volta che il working set non entra più in memoria, gli IOPS di base predefiniti sui volumi general-purpose diventano il limite ben prima della capacità.

Lo storage dei media è separato e di solito molto più piccolo. Contiene gli artefatti caricati come screenshot e documenti di accettazione del rischio, quindi dimensionalo in base alle tue abitudini di caricamento.

## Cosa ti fa salire di livello

Il numero di riscontri è la cifra principale, ma diversi fattori ti porteranno a dimensionare verso l'alto prima di quanto il solo conteggio suggerirebbe.

- **Volume e frequenza di importazione.** Scansioni di grandi dimensioni che arrivano spesso, specialmente diverse contemporaneamente, mettono un carico costante sia sul database sia sui worker asincroni. Le pipeline CI che importano a ogni build sono la causa abituale.
- **Deduplicazione.** La deduplicazione confronta i riscontri in arrivo con quelli già presenti. Più riscontri hai e più ampia è la tua configurazione di deduplicazione, più lavoro comporta ogni importazione.
- **Reportistica e dashboard.** Le viste delle metriche e la generazione di report di grandi dimensioni sono ad alta intensità di lettura, e gravano sul database più del triage quotidiano.
- **Traffico API.** Le integrazioni che effettuano polling o recuperano set di risultati di grandi dimensioni aggiungono un carico concorrente che non compare mai nel tuo conteggio di utenti interattivi.
- **Conservazione dei dati.** Le distribuzioni che conservano tutto per sempre crescono nel livello successivo secondo programma. Archiviare o eliminare i dati vecchi ti mantiene dove sei più a lungo.

## Distribuzioni molto grandi

Oltre il livello 10M, l'hardware smette di essere l'unica risposta. Due cose cambiano.

Il vincolo determinante si sposta dalla lettura alla scrittura. La deduplicazione confronta ogni riscontro in arrivo con quelli già presenti, quindi il costo di un'importazione cresce con la dimensione del dataset sottostante. Alla sommità della tabella questo è di solito ciò che si incontra per primo, prima di qualsiasi cosa gli utenti notino nell'interfaccia. Qualunque volume di importazione abbia costruito un dataset di quella dimensione è generalmente ancora in esecuzione, quindi si paga quel costo continuamente e non una sola volta.

Le cifre sulla memoria presuppongono che l'insieme attivo resti piccolo. Una distribuzione lavora sui riscontri recenti e lascia in gran parte intatti quelli più vecchi, ed è ciò che consente a un database di contenere molti più dati di quanti ne abbia in memoria e continuare comunque a funzionare bene. Se il tuo pattern di accesso è realmente distribuito sull'intero dataset, avrai bisogno di più memoria di quella elencata nella tabella, e oltre un certo punto nessuna singola istanza ne avrà a sufficienza.

Entrambi questi aspetti indicano lo stesso lavoro. Il partizionamento e l'archiviazione dei riscontri inattivi fuori dal dataset attivo contano, a questa scala, più di un ulteriore incremento di vCPU, e la reportistica pesante va collocata su una read replica anziché sulla primaria. Pianifica questo aspetto insieme all'hardware e non dopo, e parlane con noi prima di predisporre le risorse.

## In caso di dubbio, arrotonda per eccesso

Le cifre qui riportate sono già deliberatamente prudenti, ed essere una taglia troppo grande costa molto meno che essere una taglia troppo piccola. La pressione sulla memoria del database in particolare non degrada in modo graduale. Le prestazioni reggono bene finché non reggono più.

Aggiungere capacità applicativa in seguito è semplice, poiché basta aggiungere nodi. Ridimensionare un database comporta tipicamente downtime, quindi è quello su cui vale la pena fare le scelte giuste fin dall'inizio.

## Domande o supporto

Questi sono punti di partenza, non limiti. Se la tua distribuzione si colloca al vertice della tabella, o il tuo carico di lavoro non assomiglia alle ipotesi qui descritte, parlane con noi prima di predisporre le risorse. Contatta il tuo referente account oppure [support@defectdojo.com](mailto:support@defectdojo.com).
