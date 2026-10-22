---
title: Integrazione con il sistema di issue tracking
description: Sincronizza i riscontri di DefectDojo con il tuo sistema di issue tracking
  per semplificare la remediation e la responsabilità.
weight: 5
aliases:
- /it/issue_tracking/
- /it/issue_tracking/intro/
- /it/issue_tracking/intro/intro/
---

## Panoramica

Le integrazioni di issue tracking di DefectDojo collegano i tuoi flussi di lavoro di vulnerability management al tuo sistema di issue tracking esistente. Creando e aggiornando automaticamente i ticket a partire dai riscontri di sicurezza, DefectDojo contribuisce a garantire che le vulnerabilità siano visibili, assegnate e gestite negli stessi strumenti già utilizzati dai team di sviluppo e operations.

| Edizione      | Integrazioni di issue tracking supportate |
|--------------|---------------------------------------|
| Community Edition  | * [Jira](/connectors/os_jira/os__jira_guide/)                          |
| Pro          | * [Jira](/connectors/downstream/downstream_toolreference/#jira) ([guida legacy](/connectors/downstream/pro__jira_guide/))<br>* [Azure DevOps](/connectors/downstream/downstream_toolreference/#azure-devops-boards)<br>* [Bitbucket](/connectors/downstream/downstream_toolreference/#bitbucket)<br>* [Freshservice](/connectors/downstream/downstream_toolreference/#freshservice)<br>* [GitHub](/connectors/downstream/downstream_toolreference/#github)<br>* [GitLab Boards](/connectors/downstream/downstream_toolreference/#gitlab)<br>* [Linear](/connectors/downstream/downstream_toolreference/#linear)<br>* [PagerDuty](/connectors/downstream/downstream_toolreference/#pagerduty)<br>* [ServiceDesk Plus](/connectors/downstream/downstream_toolreference/#servicedesk-plus)<br>* [ServiceNow](/connectors/downstream/downstream_toolreference/#servicenow)<br>* [Shortcut](/connectors/downstream/downstream_toolreference/#shortcut)<br>* [Zendesk](/connectors/downstream/downstream_toolreference/#zendesk) |


Quando abilitata, DefectDojo può creare i ticket automaticamente, oppure in modo selettivo a partire da Prodotti o Engagement. Quando i Riscontri vengono aggiornati in DefectDojo—risolti, mitigati o riattivati—i ticket corrispondenti possono essere mantenuti sincronizzati, garantendo che entrambi i sistemi riflettano lo stato attuale del rischio.

## Cosa viene tracciato

Ogni ticket può includere i dettagli chiave della vulnerabilità, come gravità, descrizione, evidenze e indicazioni per la remediation. I collegamenti tra DefectDojo e il sistema di issue tracking garantiscono la tracciabilità dalla scoperta fino alla risoluzione, supportando reportistica, audit e miglioramento continuo.

## Perché le integrazioni di issue tracking sono importanti

I riscontri di sicurezza sono più efficaci quando sono attuabili. Integrare DefectDojo con un sistema di issue tracking colma il divario tra rilevamento e remediation, inserendo il lavoro di sicurezza direttamente nei flussi di lavoro di ingegneria già consolidati. Questo riduce il context switching, migliora la responsabilità e aiuta i team a risolvere i problemi più rapidamente.
