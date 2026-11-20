---
title: "Threat Intelligence: punteggio basato sulle evidenze (Rubric v2)"
description: "Come le evidenze di sfruttamento verificate alimenteranno la soglia minima di Priorità della Threat Intelligence"
weight: 3
audience: pro
---

> **Non ancora disponibile.** Questa pagina descrive una funzionalità in fase di sviluppo. Non è
> presente nella pagina **Feature Flags** e non può ancora essere attivata, né su DefectDojo Cloud
> né su un'istanza self-hosted. Oggi ogni riscontro riceve il punteggio descritto in
> [Threat Intelligence](../threat_intelligence/).

La [Threat Intelligence](../threat_intelligence/#come-cambia-il-punteggio) trasforma le evidenze di
exploit in una **soglia minima** sulla scala EPSS: il punteggio esterno di un riscontro è almeno pari
alla soglia raggiunta dalla sua evidenza più forte. La tabella delle soglie si chiama **rubrica**
(rubric). Rubric v2 ne è la versione successiva. Mantiene il valore di ogni soglia e aggiunge un tipo
di evidenza: **le segnalazioni di sfruttamento che gli analisti di DefectDojo hanno esaminato e
confermato**.

## Cosa cambia

| Evidenza | Soglia minima di Priorità (equivalente EPSS) |
|---|---|
| Evidenza di sfruttamento confermata **e** un attore della minaccia confermato e identificato per nome dietro di essa (novità) | 45% |
| Nel CISA KEV **e** utilizzato in ransomware | 30% |
| Nel KEV, sfruttato in the wild o **qualsiasi evidenza di sfruttamento confermata**, compresa un'osservazione canary confermata (novità) | 20% |
| Exploit pubblico weaponized (Metasploit / Exploit-DB) | 15% |
| Esiste un template di rilevamento Nuclei | 12% |
| Solo proof-of-concept pubblico | 8% |
| Nessuna evidenza di exploit | nessuna modifica |

Le soglie hanno gli stessi valori di oggi e il punteggio esterno del riscontro resta il maggiore tra
il suo valore derivato da EPSS e la sua soglia più alta, quindi la rubrica può solo aumentare un
punteggio.

In pratica:

- **Più riscontri raggiungono la soglia di "sfruttamento noto".** Un CVE che non è nel CISA KEV ma
  ha un'evidenza di sfruttamento verificata (un report di incidente, un advisory del fornitore che lo
  dichiara, un'osservazione di honeypot o canary) riceve la stessa soglia del 20% di una voce del KEV.
- **La soglia più alta diventa raggiungibile.** Con Rubric v1 la soglia del 45% richiedeva telemetria
  dei fornitori che il feed non contiene, per cui nessun riscontro l'ha mai raggiunta. Con Rubric v2
  la si raggiunge con un'evidenza confermata dietro cui c'è un attore della minaccia confermato e
  identificato per nome, e con nulla di meno.
- **Nulla si indebolisce.** Senza evidenze verificate una vulnerabilità riceve esattamente lo stesso
  punteggio di oggi. Una voce del KEV con uso in ransomware resta al 30%: l'indicatore ransomware
  della CISA non nomina alcun attore.

Cosa **non** aumenta una soglia: una segnalazione non verificata o respinta, un proof-of-concept da
solo e l'indicatore "exploit disponibile" di uno scanner o di un fornitore (vengono mostrati come
oggi e non contano come evidenza).

## Prima dell'attivazione

Passare un'istanza a Rubric v2 può aumentare la Priorità dei riscontri, perciò DefectDojo misura il
passaggio prima di farlo: per ogni istanza, quanti riscontri passerebbero da quale soglia a quale e,
per ogni passaggio, le vulnerabilità dietro il maggior numero di riscontri. Le tue priorità attuali
restano su Rubric v1 finché Rubric v2 non viene rilasciato.
