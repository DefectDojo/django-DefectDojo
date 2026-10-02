---
title: Scadenze di remediation
description: I preset SLA di FedRAMP Rev 5 e FedRAMP VDR
weight: 4
audience: pro
---

La funzionalità include due configurazioni SLA già pronte. Assegnane una ai tuoi Prodotti dalle impostazioni di
configurazione SLA, oppure copiane una e personalizzala.

## FedRAMP Rev 5

| Gravità | Entro |
| --- | --- |
| Critica | 30 giorni dalla scoperta |
| Alta | 30 giorni dalla scoperta |
| Moderata | 90 giorni |
| Bassa | 180 giorni |

Le scadenze sono vincolanti e un riscontro presente nel catalogo CISA KEV non viene mai pianificato oltre la sua
data di scadenza CISA.

## FedRAMP VDR

Le stesse finestre di base, ulteriormente ridotte in base a sfruttabilità ed esposizione:

| Condizione | Entro |
| --- | --- |
| Sfruttabile in modo credibile **e** raggiungibile da internet | 4 giorni |
| Solo sfruttabile in modo credibile | 14 giorni |
| Solo raggiungibile da internet | 30 giorni |
| Nessuna delle due | Le finestre FedRAMP Rev 5 indicate sopra |

**Sfruttabile in modo credibile** significa che il riscontro è presente nell'elenco KEV, oppure che il suo punteggio
EPSS è pari o superiore alla soglia impostata. **Raggiungibile da internet** è segnalato da un tag del riscontro —
`internet-reachable` per impostazione predefinita.

Tutte le soglie, i nomi dei tag e i conteggi dei giorni sono modificabili nella configurazione SLA.

**FedRAMP VDR diventa obbligatorio dal 7 dicembre 2026.** Lo standard Vulnerability Detection and
Response di FedRAMP diventa obbligatorio per i cloud service provider a partire da quella data. Adottare in anticipo il preset VDR
è il percorso consigliato.

## Relazione con il registro

Le scadenze SLA determinano le date di completamento pianificate degli elementi POA&M e stabiliscono quali elementi vengono conteggiati
come in ritardo nelle metriche mese su mese di uno snapshot. Determinano anche cosa include una policy degli elementi di scansione
**solo scaduti** — vedi [Profilo di conformità](../compliance_profile).

Per informazioni su come funzionano priorità e SLA al di fuori di un contesto federale, vedi
[Assegna priorità, rischio e SLA](/asset_modelling/pro_hierarchy/priority_sla/).
