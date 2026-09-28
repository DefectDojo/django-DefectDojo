---
title: Feature Flags
description: Attiva e disattiva le funzionalità opzionali di DefectDojo Pro dall'interfaccia
  di DefectDojo
weight: 1
audience: pro
---

I Feature Flags ti permettono di attivare e disattivare le funzionalità opzionali di DefectDojo Pro per la tua istanza — le funzionalità che in precedenza potevano essere abilitate solo contattando il supporto DefectDojo ora possono essere gestite autonomamente dall'interfaccia.

La pagina Feature Flags è visibile solo ai **superuser**. Gli altri utenti, inclusi i Global Owner, non la vedono.

## Apertura della pagina Feature Flags

Vai su **Settings > Feature Flags** nella barra laterale sinistra.

La pagina elenca ogni funzionalità opzionale con:

* **Name** — il nome della funzionalità, con un tag **BETA** se è ancora in beta
* **Description** — cosa fa la funzionalità
* **Documentation link** — il collegamento alla documentazione, se disponibile per quella funzionalità
* **Toggle** — se la funzionalità è attualmente attiva

Usa la casella di ricerca per filtrare l'elenco per nome o descrizione della funzionalità.

### Funzionalità non elencate

La pagina elenca le funzionalità che puoi scegliere di adottare. Due tipi di funzionalità non vi compaiono.

**Sempre attive.** Una volta che una funzionalità raggiunge la disponibilità generale, è attiva per ogni istanza e smette di essere elencata, perché non c'è più alcuna decisione da prendere:

* **Downstream Connectors** — vedi [Downstream Connectors](/connectors/downstream/about/)
* **Universal Parser** — vedi [Universal Parser](/import_data/pro/specialized_import/universal_parser/)
* **Asset Hierarchy** — vedi [Asset Hierarchy](/asset_modelling/pro_hierarchy/asset_hierarchy/)
* **Appearance** e **Feature Flags** — le due pagine Settings con lo stesso nome

Non cambia nulla per la tua istanza se una di queste era già attiva. Se invece era disattivata, ora è attiva: queste funzionalità fanno parte di DefectDojo Pro anziché essere opzionali. Contatta il [supporto DefectDojo](mailto:support@defectdojo.com) se questo rappresenta un problema per la tua istanza.

**Abilitate da DefectDojo su richiesta.** Alcune funzionalità dipendono da infrastrutture fornite per singola istanza, quindi vengono attivate da DefectDojo anziché da questa pagina:

* **Scheduling Service** — vedi [Scheduling Rules](/automation/rules_engine/scheduling/)

Contatta il [supporto DefectDojo](mailto:support@defectdojo.com) per farne abilitare una. Se è già attiva sulla tua istanza, rimane attiva.

## Attivare o disattivare una funzionalità

1. Trova la funzionalità nell'elenco.
2. Fai clic sul relativo toggle.
3. La modifica ha effetto immediatamente. Gli altri utenti la vedranno al successivo caricamento della pagina.

Alcune funzionalità mostrano una finestra di conferma prima che la modifica venga applicata. Questo accade quando si abilita una funzionalità che comporta un avviso (ad esempio una che richiede un riavvio o può influire sui dati esistenti), oppure una che non può più essere disattivata.

Disattivare una funzionalità è normalmente l'operazione inversa di attivarla. Le eccezioni sono indicate in [Quando un toggle è bloccato](#when-a-toggle-is-locked).

### Organization / Asset Relabeling

**Organization / Asset Relabeling** rinomina "Product Type" in "Organization" e "Product" in "Asset". È attiva per impostazione predefinita e si attiva/disattiva da questa pagina come qualsiasi altra funzionalità, ma è utile sapere quali parti di DefectDojo governa:

* La **Pro UI** segue questo toggle. Le nuove etichette compaiono al successivo caricamento della pagina.
* Le pagine della **Classic UI**, i loro URL e i report generati prendono la denominazione dall'impostazione di deployment `DD_ENABLE_V3_ORGANIZATION_ASSET_RELABEL` (anch'essa attiva per impostazione predefinita), che viene letta all'avvio di DefectDojo. Questo toggle non le modifica, e nemmeno un riavvio le fa cambiare.

Il toggle memorizzato è stato inizializzato a partire da quell'impostazione di deployment, quindi i due valori coincidono finché non ne modifichi uno. Se disattivi la rietichettatura qui e usi anche la Classic UI, imposta `DD_ENABLE_V3_ORGANIZATION_ASSET_RELABEL=False` sul tuo deployment e riavvia in modo che entrambe le interfacce corrispondano. Su [DefectDojo Pro (Cloud)](/get_started/pro/cloud/), contatta il [supporto DefectDojo](mailto:support@defectdojo.com) per far modificare l'impostazione di deployment.

Per questo motivo la funzionalità ha un tag **Restart Recommended** nella pagina Feature Flags: la denominazione usata al di fuori della Pro UI viene fissata all'avvio del processo. In ogni caso la rietichettatura è puramente estetica. I modelli del database, i nomi dei campi e gli endpoint API restano invariati, quindi le automazioni esistenti continuano a funzionare. Vedi [Asset Hierarchy](/asset_modelling/pro_hierarchy/asset_hierarchy/).

## Quando un toggle è bloccato

Una funzionalità che non puoi modificare viene mostrata con un badge di blocco che ne spiega il motivo:

| Badge | Cosa significa | Cosa fare |
| --- | --- | --- |
| **Managed by DefectDojo** | DefectDojo ha impostato questa funzionalità a livello centrale per la tua istanza. La tua impostazione non può sovrascriverla. | Contatta il [supporto DefectDojo](mailto:support@defectdojo.com) se hai bisogno di modificarla. |
| **Unavailable on This Deployment** | La funzionalità non è offerta per il tuo tipo di installazione. Vedi [Disponibilità delle funzionalità](#feature-availability) più sotto. | Nessuna azione. La funzionalità non è applicabile alla tua istanza. |
| **Cannot Be Disabled** | La funzionalità è già attiva ed è irreversibile. Non esiste un meccanismo per disattivarla. | Nessuna azione. È previsto. |
| **Managed by deployment** | La funzionalità è controllata dalla configurazione di deployment anziché da questa pagina. | Vedi [DefectDojo Pro (On-Premise)](#defectdojo-pro-on-premise) più sotto. |

## DefectDojo Pro (Cloud)

Su [DefectDojo Pro (Cloud)](/get_started/pro/cloud/), **Settings > Feature Flags** è l'unico punto di cui hai bisogno. Attiva una funzionalità ed è subito operativa.

Due cose sono gestite da DefectDojo anziché da te:

* **Managed by DefectDojo** — la funzionalità è fissata a livello centrale. Contatta il [supporto DefectDojo](mailto:support@defectdojo.com) per farla modificare.
* **Managed by deployment** — la funzionalità fa parte di come viene provisionata la tua istanza. Contatta il supporto anche per queste, poiché le istanze Cloud non espongono la configurazione di deployment ai clienti.

Le istanze Cloud hanno inoltre accesso a funzionalità non offerte on-premise. Vedi [Disponibilità delle funzionalità](#feature-availability).

## DefectDojo Pro (On-Premise)

Su [DefectDojo Pro (On-Premise)](/get_started/pro/onprem/), la maggior parte delle funzionalità funziona esattamente come su Cloud: apri **Settings > Feature Flags** e attivale o disattivale.

Un piccolo numero di funzionalità viene invece letto dalla configurazione di deployment. Queste modificano il modo in cui l'applicazione si avvia, quindi non possono essere commutate a runtime. Compaiono nella pagina come sola lettura, etichettate **Managed by deployment**, e indicano la variabile d'ambiente che le controlla, ad esempio `DD_V3_FEATURE_LOCATIONS` per [Locations](/asset_modelling/locations/pro__locations_overview/).

Poiché queste funzionalità richiedono un riavvio, e alcune non possono essere annullate una volta abilitate, controlla la documentazione specifica della funzionalità prima di modificarne una. Per diverse di esse è consigliabile farsi aiutare dal [supporto DefectDojo](mailto:support@defectdojo.com).

Per modificare una di queste funzionalità:

1. Imposta la variabile d'ambiente sul tuo deployment DefectDojo. La pagina indica quale variabile impostare.
2. Riavvia DefectDojo in modo che il nuovo valore venga letto all'avvio.
3. Ricarica la pagina Feature Flags per confermare il nuovo stato.

Poiché questi valori vengono letti all'avvio, non è possibile modificarli dall'interfaccia, e commutarli nel tuo ambiente senza un riavvio non ha alcun effetto.

Le funzionalità offerte solo su Cloud compaiono come **Unavailable on This Deployment** su un'istanza on-premise. È previsto e non è un problema di licenza.

## Disponibilità delle funzionalità

La maggior parte delle funzionalità è disponibile su entrambi i tipi di installazione. Le eccezioni sono:

| Funzionalità | Disponibilità | Come viene controllata |
| --- | --- | --- |
| Request a New Connector | Solo [DefectDojo Pro (Cloud)](/get_started/pro/cloud/) | Pagina Feature Flags. Mostrata come **Unavailable on This Deployment** on-premise. |
| Locations | Entrambe | Pagina Feature Flags. Nota che Locations non può essere disattivata una volta abilitata. Vedi [Locations Overview](/asset_modelling/locations/pro__locations_overview/). |
| Organization / Asset Relabeling | Entrambe | Pagina Feature Flags per la Pro UI; la Classic UI, i suoi URL e i report generati seguono l'impostazione di deployment `DD_ENABLE_V3_ORGANIZATION_ASSET_RELABEL`. Vedi [sopra](#organization--asset-relabeling). |

Ogni altra funzionalità opzionale si attiva o disattiva direttamente dalla pagina Feature Flags sia sulle istanze Cloud che On-Premise.

## Leggere i feature flag al di fuori dell'interfaccia

Non è necessario aprire la pagina Feature Flags per scoprire quali funzionalità sono abilitate — lo stato dei flag può anche essere letto in modo programmatico, il che è utile quando un'automazione deve verificare che una funzionalità sia disponibile prima di farvi affidamento.

```
GET /api/v2/defectdojo_information/feature_flags/
```

Questo restituisce un array JSON con un oggetto per ogni feature flag. Oltre a `key`, `title` e `description` del flag, ogni oggetto riporta i valori che di solito servono all'automazione: `effective` (se la funzionalità è effettivamente attiva per questa istanza), `default`, `application_value` (l'impostazione specifica dell'istanza, o `null` se non impostata), `editable` e `locked_reason` per i flag che non possono essere modificati. I flag ritirati dal prodotto vengono omessi.

Qualsiasi utente **autenticato** può leggerlo — non è richiesto il ruolo di superuser. Per lo schema esatto della risposta nella tua versione, consulta la documentazione API interattiva della tua istanza all'indirizzo `/api/v2/oa3/swagger-ui/`, generata a partire dalla build in esecuzione. Vedi anche la [documentazione API v2](/automation/api/api-v2-docs/).

Lo stesso elenco in sola lettura viene pubblicato anche sulla superficie `/api/mcp/` dell'istanza, all'indirizzo `/api/mcp/defectdojo_information/feature_flags/`.

Questo endpoint è di **sola lettura**. Attivare o disattivare una funzionalità si fa comunque dalla pagina Feature Flags, oppure — per le funzionalità configurate a livello di deployment indicate sopra — nelle impostazioni di deployment.

## Domande frequenti

**Una funzionalità che cerco non è nell'elenco.**
L'elenco mostra solo le funzionalità opzionali. Le funzionalità sempre attive non compaiono. Se ti aspettavi una funzionalità che manca, verifica che la tua licenza la includa, quindi contatta il [supporto DefectDojo](mailto:support@defectdojo.com).

**Ho attivato una funzionalità ma non la vedo.**
Ricarica la pagina — le voci di menu e i percorsi vengono valutati al caricamento della pagina, quindi una funzionalità appena abilitata compare al caricamento successivo anziché istantaneamente nella vista corrente.

**L'aggiornamento modificherà le mie impostazioni?**
No. L'aggiornamento mantiene invariate sia le funzionalità che hai attivato sia quelle che hai disattivato.
