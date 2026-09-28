---
title: Configurazione SLA
description: Configura gli Accordi sul Livello di Servizio per Prodotti diversi
weight: 2
audience: opensource
aliases:
- /it/en/working_with_findings/sla_configuration
---

Ogni Prodotto in DefectDojo può avere una propria configurazione di Service Level Agreement (SLA), che rappresenta i giorni a disposizione della tua organizzazione per correggere o comunque gestire un Riscontro.

Lo SLA può essere impostato in base alla **[Gravità del Riscontro](/asset_modelling/os_hierarchy/product_hierarchy/#findings)** oppure al **[Rischio del Riscontro](/asset_modelling/pro_hierarchy/priority_sla/)** (in DefectDojo Pro).

![image](images/sla_multiple.png)

Gli SLA applicano un conto alla rovescia di giorni a un Riscontro in base al giorno in cui il Riscontro è stato creato in DefectDojo.  Se un Riscontro non viene chiuso entro il conto alla rovescia, verrà etichettato come in violazione dello SLA.

## Utilizzo degli SLA

Puoi utilizzare gli SLA come un modo per rappresentare le politiche di correzione della tua organizzazione.  Puoi anche utilizzarli come un modo per dare priorità ai Riscontri attivi da più tempo e più critici nella tua istanza DefectDojo.

* Puoi ordinare o filtrare le tabelle dei Riscontri in base ai giorni di SLA.
* Le violazioni dello SLA possono essere configurate per attivare [Notifiche](/admin/notifications/about_notifications/) agli utenti DefectDojo assegnati al Prodotto correlato.
* In **DefectDojo Pro**, le prestazioni dello SLA vengono monitorate anche nelle Dashboard delle metriche [Executive Insights and Remediation](/metrics_reports/pro_metrics/pro__overview/).
* La conformità allo SLA può anche essere mostrata su una [dashboard](/metrics_reports/dashboards/custom-dashboards/) personalizzata in **DefectDojo Pro** — ad esempio con un SLA Burndown o un widget Count filtrato.

### Stato Mitigated Within SLA

Se un Riscontro viene Mitigato con successo entro la scadenza dello SLA, il Riscontro registrerà un segno di spunta verde ✅ nella colonna Mitigated Within SLA.

![image](images/sla_mitigated_within.png)

Se un Riscontro è stato Mitigato, ma non prima che lo SLA venisse violato, il Riscontro registrerà una X rossa ❌ nella colonna Mitigated Within SLA.

### Violazione degli SLA

Quando lo SLA di un determinato Riscontro viene violato (il Riscontro non viene chiuso entro i tempi previsti dallo SLA), il segno di spunta verde ✅ si trasformerà in una X rossa ❌.  Lo SLA continuerà a essere monitorato con un numero negativo, per rappresentare da quanti giorni è stato violato.

![image](images/sla_breached.png)

## Gestione delle Configurazioni SLA (Pro)

In DefectDojo Pro, una o più Configurazioni SLA vengono gestite nella sezione **Configuration > Service Level Agreements** della barra laterale.  Puoi creare un **New Service Level Agreement** oppure lavorare con le configurazioni SLA esistenti dalla pagina **All Service Level Agreements**.

![image](images/pro_sla_risk.png)

Le Configurazioni SLA possono essere modificate solo dai Superuser o da un utente con la [Configuration Permission](/admin/user_management/user_permission_chart/#configuration-permission-chart) corrispondente.

### Configurazione dello SLA

Le configurazioni SLA contengono i giorni assegnati a ciascun valore di **Gravità** o **Rischio** di DefectDojo.

![image](images/pro_new_sla.png)

Ogni Service Level Agreement può avere un nome univoco, insieme a una descrizione opzionale.

**Restart SLA on Finding Reactivation**: se abilitata, questa opzione riavvia lo SLA da capo quando un Riscontro viene Riaperto.  In caso contrario, lo SLA si baserà sulla data di creazione del Riscontro.

Quando modifichi uno SLA, puoi scegliere se utilizzare la **Gravità** o il **Rischio** come parametro di riferimento per assegnare i Days To Remediate.  Questo si effettua selezionando l'opzione corrispondente nella sezione **Service Level configuration Type** del modulo.

Da qui, puoi impostare il numero di giorni consentiti per ciascun livello di **Gravità** o **Rischio**.  Puoi anche applicare gli SLA in modo selettivo; deselezionando **Enforce ___ Finding Days** puoi escludere il calcolo dello SLA per quei livelli di Gravità o Rischio.

## Applicare una Configurazione SLA a un Prodotto (Pro)

I Prodotti appena creati in DefectDojo applicheranno sempre la **Default SLA Configuration**, che può essere impostata su valori diversi se lo desideri.

Se disponi di configurazioni SLA, puoi scegliere quale applicare al tuo Prodotto dal modulo **Edit Product**.

![image](images/pro_sla_product.png)

### Ricalcolo dello SLA

Una volta selezionato un nuovo SLA per un Prodotto, DefectDojo dovrà ricalcolare gli SLA di tutti i Riscontri associati.  Durante l'esecuzione di questo processo, non è possibile modificare lo SLA di un Prodotto.

## Note sugli SLA

* Gli SLA possono essere facoltativamente riavviati quando un Riscontro con [Rischio accettato](/triage_findings/findings_workflows/os__risk_acceptance/) si riattiva.  Questo viene impostato durante la creazione dell'Accettazione del rischio tramite il campo **Restart SLA Expired**.
* La reimportazione di un Riscontro non riavvia lo SLA: gli SLA vengono sempre calcolati a partire dal momento in cui il Riscontro è stato rilevato per la prima volta, a meno che non sia abilitata l'opzione **Restart SLA on Finding Reactivation**.
* La scadenza dell'Accettazione del rischio o la riattivazione di un Riscontro chiuso sono gli unici modi per reimpostare o ricalcolare lo SLA di un Riscontro una volta creato (senza modificare la configurazione SLA del Prodotto).
