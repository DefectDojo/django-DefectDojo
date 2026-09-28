---
title: Il registro POA&M
description: Come vengono creati gli elementi POA&M a partire dai riscontri, e le
  convenzioni seguite dal registro
weight: 2
audience: pro
---

Gli elementi POA&M vengono creati e aggiornati automaticamente a partire dai riscontri. La
sincronizzazione viene eseguita poco dopo le importazioni e le modifiche ai riscontri, e una
scansione notturna intercetta tutto ciò che fosse sfuggito. Puoi anche aggiungere elementi
manualmente, per le vulnerabilità che nessuno scanner segnala.

![Il registro POA&M](images/02-poam-items.png)

## Convenzioni del registro

Il registro segue le convenzioni FedRAMP:

* **Numerazione stabile.** Ogni elemento mantiene un numero di sequenza all'interno del proprio
  sistema, e i numeri non vengono mai riutilizzati.
* **I riscontri raggruppati confluiscono insieme.** La stessa CVE su molti host diventa un unico
  elemento, con ogni asset interessato elencato su di esso.
* **I riscontri di configurazione possono consolidarsi sotto CM-6**, invece di inondare il registro
  con un elemento per ogni regola di benchmark. Nello screenshot sopra, `V-4` è quell'elemento
  consolidato.
* **Gli elementi chiusi non si riaprono mai.** Se la stessa vulnerabilità si ripresenta, il registro
  apre un nuovo elemento che fa riferimento a quello vecchio, così la tua cronologia di remediation
  resta intatta.

## Modificare un elemento

L'icona a matita su qualsiasi riga apre l'elemento per la modifica.

![Modifica di un elemento POA&M](images/03-poam-item-detail.png)

Da qui imposti il punto di contatto, le risorse richieste e il piano di remediation, e registri
eventuali deviazioni.

### Deviazioni

Le deviazioni vengono tracciate come tre stati separati su ogni elemento:

| Deviazione | Valori |
| --- | --- |
| Falso positivo | No, In sospeso o Sì |
| Adeguamento del rischio | No, In sospeso o Sì |
| Requisito operativo | No, In sospeso o Sì |

Ognuna riporta una **Deviation Rationale** condivisa. Un adeguamento del rischio registra anche
l'**Adjusted Risk Rating** accanto a quello originale, ed entrambi compaiono sui deliverable
generati.

### Dipendenze dal fornitore

Gli elementi possono riportare un flag **Vendor Dependency** e il nome **Vendor Product**, per le
vulnerabilità che non puoi correggere direttamente. La data dell'ultimo check-in con il fornitore
viene tracciata insieme all'elemento.

## Tracciamento KEV

Gli elementi collegati a una CISA Known Exploited Vulnerability riportano la data di scadenza KEV.
Quella data limita anche la scadenza di remediation — vedi
[Scadenze di remediation](../remediation_slas).

## Milestone

Le milestone riportano una descrizione con date pianificate e di completamento, e compaiono sia
negli output Excel che OSCAL. Vengono gestite tramite l'API di conformità piuttosto che sul form
dell'elemento.

## Aggiungere un elemento manualmente

Aggiungi un elemento per una vulnerabilità che nessuno scanner segnala. Gli elementi creati
manualmente si comportano come quelli sincronizzati: prendono il numero di sequenza successivo,
accettano deviazioni e milestone, e compaiono nel prossimo snapshot.

## Tracciabilità

Gli elementi POA&M, le milestone e le deviazioni sono tutti soggetti a cronologia delle modifiche.
Ogni modifica registra chi, cosa e quando.
