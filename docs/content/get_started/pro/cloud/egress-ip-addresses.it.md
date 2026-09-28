---
title: Indirizzi IP di Egress
description: Gli indirizzi IP in uscita da cui si connette DefectDojo Cloud, da inserire
  nelle liste consentite dei firewall esterni.
weight: 5
audience: pro
---

Quando DefectDojo Cloud contatta i tuoi sistemi — i Connector che sincronizzano l'API di uno scanner,
l'invio di issue a Jira o ServiceNow, l'invio di webhook di notifica o la consegna di email
tramite SMTP — queste connessioni vengono **avviate in uscita** dal tuo ambiente
DefectDojo. Se il sistema di destinazione si trova dietro un firewall, dovrai
consentire gli indirizzi IP in uscita (egress) di DefectDojo affinché queste
connessioni non vengano bloccate.

Questa pagina indica dove trovare questi indirizzi IP di egress.

## Egress e ingress

Si tratta di due concetti diversi, e questa pagina tratta solo il primo:

- **Egress (questa pagina)** — gli indirizzi IP sorgente **da cui** si connette
  DefectDojo Cloud quando raggiunge **verso l'esterno** i sistemi esterni *di tua
  proprietà*. Inseriscili nella lista consentita dei **tuoi** firewall in modo che
  DefectDojo possa raggiungere i sistemi con cui si integra.
- **Ingress** — le regole che controllano chi può raggiungere la **tua** istanza
  DefectDojo. Queste vengono gestite come Regole Firewall nel Cloud Manager, non
  qui. Consulta [Risoluzione dei problemi di connettività](../connectivity-troubleshooting/) e il
  passaggio sulle Regole Firewall in
  [Configurare un'istanza Cloud aggiuntiva](../additional-cloud-instance/).

## Distribuzioni multi-tenant

Le istanze Standard, Pay-as-you-go e Premium vengono eseguite su cluster
Google Kubernetes Engine (GKE) regionali condivisi. Le connessioni in uscita
provengono dagli indirizzi IP esterni dei nodi nella regione in cui viene
eseguita la tua istanza.

L'insieme attuale degli IP di egress dei nodi è pubblicato come feed JSON,
raggruppato per regione:

<https://storage.googleapis.com/defectdojo-node-ips/node_ips.json>

Il feed ha il seguente aspetto:

```json
{
  "description": "External IPs for DefectDojo Cloud GKE nodes, grouped by region",
  "generated_at": "2026-08-06T20:17:26.372476+00:00",
  "regions": {
    "us-east4": [
      "34.21.115.236/32",
      "34.48.120.182/32"
    ],
    "europe-west3": [
      "34.40.61.46/32",
      "34.89.189.26/32"
    ]
  }
}
```

Per inserire nella lista consentita il traffico di egress di DefectDojo:

1. Identifica la regione in cui viene eseguita la tua istanza (la Posizione del
   Server che hai selezionato al momento del provisioning dell'istanza).
2. Consenti tutti gli indirizzi IP elencati per quella regione. Ogni voce è un
   CIDR `/32` (singolo host).

**Questo elenco cambia nel tempo.** I nodi vengono aggiunti e sostituiti man
mano che la piattaforma esegue l'autoscaling, quindi l'insieme degli IP di
egress per una regione non è fisso. Considera il feed JSON come fonte
autorevole piuttosto che copiare gli indirizzi una sola volta:

- Recupera il feed in modo programmatico e aggiorna periodicamente la lista
  consentita del tuo firewall in base ad esso, oppure
- Ricontrolla il feed e riconcilia le tue regole periodicamente.

Se il tuo firewall non è in grado di gestire un elenco variabile e hai bisogno
di un insieme piccolo e stabile di indirizzi, parla con il tuo referente
DefectDojo di un'istanza **Dedicated** (vedi sotto).

## Distribuzioni single-tenant (Dedicated)

Un'istanza di livello **Dedicated** viene eseguita nel proprio progetto GCP e
nella propria VPC, e il suo indirizzo IP di egress è **stabile** — viene
assegnato al momento del provisioning dell'istanza e non cambia con il
ridimensionamento della piattaforma.

Poiché è legato alla tua specifica istanza, l'IP di egress stabile non viene
pubblicato nel feed pubblico. Contatta [support@defectdojo.com](mailto:support@defectdojo.com)
per ottenere gli indirizzi IP di egress assegnati alla tua istanza Dedicated,
e inseriscili nella lista consentita dei tuoi firewall esterni.

*Hai una domanda a cui questa pagina non risponde? Contatta il tuo referente
DefectDojo.*
