---
title: Global Locations Deduplication
description: Deduplica i riscontri in base a una posizione condivisa (URL o dipendenza)
  in tutti i Prodotti
weight: 6
audience: pro
---

Global Locations Deduplication è un algoritmo di DefectDojo Pro che identifica i riscontri duplicati in **tutti i Prodotti** basandosi esclusivamente su una **posizione condivisa**: un URL, oppure una dipendenza (identificata tramite il suo Package URL). Due riscontri che condividono una posizione di un tipo selezionato sono trattati come duplicati indipendentemente da titolo, gravità, CWE o vulnerability ID — la posizione da sola costituisce l'identità.

È la controparte basata sulla posizione di [Global Component Deduplication](/triage_findings/finding_deduplication/pro__global_component_deduplication/), applicata al modello di dati Locations di DefectDojo. Mentre Global Component effettua la corrispondenza solo su nome e versione del componente, Global Locations effettua la corrispondenza sulla stessa dipendenza **tramite il Package URL completo** *e* su **URL** condivisi — potendo così deduplicare i riscontri DAST/web tra i Prodotti, cosa che Global Component non può fare.

A differenza degli algoritmi con ambito limitato, la corrispondenza di Global Locations **non è limitata a un singolo Prodotto o Engagement**. Un riscontro importato nel Prodotto B può essere contrassegnato come duplicato di un riscontro più vecchio nel Prodotto A, anche se i due Prodotti non sono correlati.

## Requisiti

Global Locations è definito sopra il modello di dati **Locations** di DefectDojo ed è disponibile solo quando la funzionalità **Locations** è abilitata. Sulle istanze in cui Locations è disattivata, il feature flag di Global Locations viene mostrato come bloccato ("Requires Locations to be enabled") e l'algoritmo non compare nel Tuner.

## Abilitazione dell'algoritmo Global Locations

Global Locations Deduplication è controllata da un feature flag ed è **disattivata per impostazione predefinita**. Una volta abilitata Locations, un superuser può attivarla da **Settings > Feature Flags** sia sulle istanze Cloud che On-Premise. Vedere [Feature Flags](/admin/feature_flags/pro__feature_flags/).

Una volta abilitata la funzionalità, **Global Locations** diventa disponibile come opzione nel menu a tendina **Deduplication Algorithm** sia per le impostazioni di Same Tool sia di Cross Tool Deduplication nel Tuner.

## Configurazione di Global Locations Deduplication

Global Locations può essere applicato a Same-Tool Deduplication, Cross-Tool Deduplication o a entrambe, e viene configurato per singolo strumento di sicurezza da **Settings > Finding Workflow** (**Settings > Pro Settings > Deduplication Settings** nelle istanze che utilizzano ancora il layout di menu precedente; vedere [The Settings Menu](/navigation/pro__settings_menu/)).

Quando si seleziona **Global Locations**, il selettore Hash Code Fields viene nascosto (non è applicabile) e al suo posto compare un selettore **Location Types**.

### Location Types

Scegliere quali tipi di posizione partecipano alla corrispondenza:

- **URLs** — due riscontri corrispondono quando condividono un URL (confrontato sui campi endpoint configurati, `DEDUPE_ALGO_ENDPOINT_FIELDS`).
- **Dependencies** — due riscontri corrispondono quando fanno riferimento alla stessa dipendenza, tramite l'identità completa del Package URL.

Deve essere selezionato almeno un tipo; per impostazione predefinita sono selezionati entrambi. Uno strumento configurato solo per **URLs** ignora le dipendenze condivise, e uno strumento configurato solo per **Dependencies** ignora gli URL condivisi.

### Same-Tool

Utilizzare Same-Tool Deduplication con l'algoritmo Global Locations quando si desidera deduplicare i riscontri di un singolo strumento su più Prodotti in base a una posizione condivisa.

1. Aprire la scheda **Same Tool Deduplication**.
2. Selezionare lo strumento dal menu a tendina **Security Tool**.
3. Impostare il **Deduplication Algorithm** su **Global Locations**.
4. Scegliere i **Location Types** su cui basare la corrispondenza.
5. Inviare il modulo.

### Cross-Tool

Utilizzare Cross-Tool Deduplication con l'algoritmo Global Locations quando si desidera deduplicare i riscontri che condividono una posizione tra strumenti e Prodotti **diversi**.

La corrispondenza cross-tool legge la selezione dei tipi di posizione dello strumento che effettua l'importazione, quindi configurare Global Locations su **ogni** strumento che deve partecipare, con gli stessi Location Types.

1. Aprire la scheda **Cross Tool Deduplication**.
2. Per ogni strumento da includere: selezionarlo dal menu a tendina **Security Tool**, impostare l'algoritmo su **Global Locations**, scegliere i Location Types e inviare.

## Come funziona la corrispondenza

Un nuovo riscontro viene contrassegnato come duplicato di un riscontro esistente in qualsiasi punto dell'istanza quando i due condividono **almeno una posizione concreta di un tipo selezionato**:

- **un URL** i cui campi endpoint configurati (`DEDUPE_ALGO_ENDPOINT_FIELDS`) corrispondono tutti, **oppure**
- **una dipendenza** con lo stesso Package URL (una corrispondenza purl esatta, quindi `pkg:npm/timespan@2.3.0` **non** corrisponde a `pkg:npm/timespan@2.3.1`).

La corrispondenza è **rigorosa e non vacua**: due riscontri privi di posizioni di un tipo selezionato **non** vengono mai deduplicati (a differenza della corrispondenza per posizione con ambito limitato, "entrambi vuoti" non costituisce una corrispondenza). Se il confronto sui campi endpoint è disattivato (`DEDUPE_ALGO_ENDPOINT_FIELDS = []`), gli URL non possono in alcun modo stabilire una corrispondenza: solo una dipendenza condivisa può farlo.

La corrispondenza Same-Tool resta all'interno di un singolo strumento (tipo di test). La corrispondenza Cross-Tool attraversa intenzionalmente gli strumenti. L'impostazione di deduplicazione a livello di Engagement viene ignorata per questo algoritmo; la corrispondenza è sempre globale, e il campo `service` continua a suddividere la deduplicazione come avviene per gli altri algoritmi globali.

## Esempio

Supponiamo che Global Locations (entrambi i tipi di posizione) sia abilitato su uno strumento DAST (Same Tool) e, per la riga cross-tool, su un secondo strumento DAST:

| Step | Import | Nel Prodotto | Risultato |
| --- | --- | --- | --- |
| 1 | Riscontro DAST su `https://shared.example.com/login` | Application 0 | Creato 1 riscontro attivo |
| 2 | Stesso URL, vulnerabilità **diversa** (titolo + gravità) | Application 1 | Creato 1 riscontro, contrassegnato come duplicato del riscontro di Application 0 (corrisponde solo la posizione) |
| 3 | Secondo strumento DAST, stesso URL | Application 2 | Creato 1 riscontro, contrassegnato come duplicato del riscontro di Application 0 (corrispondenza cross-tool) |
| 4 | Riscontro DAST su `https://other.example.com/admin` | Application 3 | Creato 1 riscontro attivo — URL diverso, nessuna posizione condivisa |
| 5 | Riscontro senza URL e senza dipendenza | Application 4 | Creato 1 riscontro attivo — nessuna posizione da condividere |

Ogni riscontro duplicato mostra il proprio originale nella parte inferiore della pagina del riscontro, nella catena dei duplicati.

## Global Component rispetto a Global Locations

Entrambi sono algoritmi globali (cross-prodotto) che ignorano l'ambito Engagement ed effettuano la corrispondenza su un'unica identità anziché sui campi hash. La scelta dipende da cosa identifica un duplicato per il proprio strumento:

| | Global Component | Global Locations |
| --- | --- | --- |
| Corrispondenza su | Componente **nome + versione** | Una **posizione** condivisa: un URL e/o una dipendenza |
| Identità della dipendenza | Nome e versione | **Package URL** completo (tipo, namespace, nome, versione, qualificatori) |
| Riscontri URL / DAST | Non corrispondono | Corrispondono (sui campi endpoint configurati) |
| Configurabile | No | Sì — scegliere URLs, Dependencies o entrambi per strumento |
| Modello di dati | Funziona con o senza Locations | Richiede **Locations** (Pro) |
| Più adatto a | Strumenti SCA in cui l'identità è nome+versione del pacchetto | Strumenti Web/DAST e SCA nel modello Locations, dove l'identità è l'URL o la dipendenza esatta |

Per una nuova istanza che utilizza il modello di dati Locations, Global Locations è il successore più preciso di Global Component: identifica le dipendenze tramite il Package URL esatto e deduplica inoltre i riscontri basati su URL. Global Component resta disponibile e invariato per gli strumenti in cui l'identità desiderata è nome + versione del componente.

## Visibilità cross-prodotto

Poiché la corrispondenza di Global Locations attraversa i confini tra Prodotti, il riscontro originale in una catena di duplicati potrebbe trovarsi in un Prodotto a cui l'utente che visualizza il duplicato non ha accesso.

In tal caso, il riscontro è visibile ed etichettato come duplicato, ma l'utente non potrà aprirlo né accedere all'originale. Tenerne conto prima di abilitare Global Locations su strumenti i cui riscontri sono sensibili ai controlli di accesso a livello di Prodotto.

## Ripristino

Per smettere di utilizzare Global Locations per un determinato strumento, aprire le sue Deduplication Settings e riportare l'algoritmo a una delle opzioni con ambito limitato.

Per **Same Tool** Deduplication:

- Hash Code
- Unique ID From Tool
- Unique ID From Tool or Hash Code

Per **Cross Tool** Deduplication:

- Hash Code
- Disabled

La modifica dell'algoritmo avvia un ricalcolo in background degli hash di deduplicazione per i riscontri esistenti dello strumento.
