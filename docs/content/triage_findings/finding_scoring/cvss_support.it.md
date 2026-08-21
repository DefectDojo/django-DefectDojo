---
title: Supporto delle versioni CVSS
description: Quali versioni CVSS DefectDojo memorizza, visualizza e accetta sui Riscontri
weight: 1
---

DefectDojo supporta i metadati CVSS sui Riscontri, incluso lo standard CVSS 4.0. Questa pagina
descrive quali versioni CVSS vengono memorizzate end-to-end, dove è possibile inserirle o visualizzarle,
e cosa aspettarsi in termini di copertura da parte dei parser.

## Cosa memorizza DefectDojo

I Riscontri possono contenere i seguenti dati CVSS:

| Versione | Vettore memorizzato | Punteggio memorizzato | Generatore di vettori e calcolatore nell'interfaccia utente |
| --- | --- | --- | --- |
| **CVSS v4.0** | ✅ | ✅ | ✅ (Pro UI) |
| **CVSS v3 (v3.0 / v3.1)** | ✅ | ✅ | ✅ (Pro UI) |
| **CVSS v2** | Memorizzato implicitamente tramite il campo **Gravità** del Riscontro; non viene memorizzato un campo vettore v2 separato | N/D | N/D |

Ogni Riscontro dispone di campi dedicati `cvssv3` / `cvssv3_score` e `cvssv4` / `cvssv4_score` nel
modello sottostante. Questi sono accessibili sia tramite l'API sia tramite l'interfaccia utente.

## Dove inserire manualmente i dati CVSS

Sia CVSSv3 che CVSSv4 possono essere inseriti manualmente su un Riscontro:

- **Modulo di modifica del Riscontro** — incollare una stringa vettoriale CVSS completa nel campo
  corrispondente. Al salvataggio, DefectDojo analizza il vettore e calcola automaticamente il
  punteggio.
- **Generatore di vettori (Pro UI)** — fare clic sul pulsante 🛠️ accanto alla voce CVSSv3 o CVSSv4 nel
  modulo di modifica del Riscontro per aprire il generatore di vettori. Costruire il vettore in modo
  interattivo, quindi fare clic sul pulsante del calcolatore per ottenere un punteggio a partire dal
  vettore risultante.

> Le stringhe vettoriali CVSSv4 e il generatore di vettori sono stati aggiunti alla Pro UI nella
> v2.50.3 (22 settembre 2025), mentre il pulsante esplicito del calcolatore è arrivato nella v2.51.1
> (14 ottobre 2025).

## Impostazioni di visualizzazione

La visualizzazione del Riscontro rispetta due impostazioni di sistema che controllano se i dati
CVSSv3 e CVSSv4 vengono mostrati agli utenti:

- **Enable CVSS 3 Display** — mostra i vettori e i punteggi CVSSv3 sui Riscontri.
- **Enable CVSS 4 Display** — mostra i vettori e i punteggi CVSSv4 sui Riscontri.

Entrambe possono essere impostate in modo indipendente in Impostazioni di sistema. Se sono entrambe
abilitate, le due versioni vengono visualizzate una accanto all'altra sui Riscontri che le contengono
entrambe.

## Copertura dei parser e degli strumenti

DefectDojo può memorizzare i dati CVSSv4 su qualsiasi Riscontro, ma **se un determinato parser popoli i
campi CVSSv4 dipende dallo strumento a monte**:

- Se lo strumento a monte emette vettori o punteggi CVSSv4 nel proprio formato di esportazione, il
  parser normalmente mappa tali campi.
- Se lo strumento emette solo dati CVSSv2 o CVSSv3, il parser non sintetizza un vettore v4 — non è
  integrata alcuna conversione da v3 a v4.
- Alcuni parser meno recenti potrebbero non mappare ancora i campi CVSSv4 anche se lo strumento a monte
  li emette. Se si individua un parser che omette i campi CVSSv4 provenienti da uno strumento che
  invece li emette, si prega di segnalare un issue.

Nel frattempo, due percorsi garantiscono una copertura CVSSv4 completa indipendentemente dal supporto
del parser:

1. **[Generic Findings Import](/supported_tools/parsers/generic_findings_import/)** — accetta le
   colonne `CVSSV4` (vettore) e `CVSSV4_score` in CSV, e le chiavi `cvssv4` / `cvssv4_score` in JSON.
2. **[Universal Parser](/import_data/pro/specialized_import/universal_parser/)** (Pro) — supporta i
   vettori CVSSv4 come campo mappabile (aggiunto nella v2.57.0, 7 aprile 2026). Utilizzarlo quando lo
   strumento emette JSON o CSV con nomi di campo personalizzati che i parser integrati non mappano.

L'inserimento manuale nel modulo di modifica del Riscontro rimane disponibile come soluzione di
ripiego universale per qualsiasi strumento o report che non trasmetta automaticamente i dati CVSSv4.
