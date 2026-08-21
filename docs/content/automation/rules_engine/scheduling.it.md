---
title: Pianificazione delle regole
description: Esegui automaticamente le regole di Rules Engine secondo una pianificazione
  ricorrente o una tantum
weight: 2
audience: pro
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Nota: la pianificazione di Rules Engine è una funzionalità disponibile solo in DefectDojo Pro.</span>

Le Regole possono essere pianificate per l'esecuzione automatica invece di essere attivate manualmente ogni volta. Una regola pianificata verrà eseguita su tutti i Finding che corrispondono alle sue condizioni di filtro, all'orario configurato.

La pianificazione è disattivata per impostazione predefinita e viene abilitata per singola istanza da DefectDojo, anziché dalla pagina Feature Flags. Contatta [DefectDojo Support](mailto:support@defectdojo.com) per far attivare lo **Scheduling Service**; l'opzione **Schedule Rule** compare una volta attivato. Vedere [Feature Flags](/admin/feature_flags/pro__feature_flags/) per come vengono mostrate le funzionalità che DefectDojo gestisce a livello centrale.

L'utente che imposta la pianificazione deve disporre del permesso di configurazione **Change Scheduling Service Schedule**.

## Tipi di pianificazione

### Esecuzione singola

Una pianificazione Single Run esegue la regola una sola volta in una data e ora specifiche. Al termine dell'esecuzione, la pianificazione non viene ripetuta.

### Esecuzione ripetuta

Una pianificazione Repeated Run consente di attivare una regola su base ricorrente — ad esempio, ogni giorno alle 9:00, oppure ogni lunedì alle 15:00.

**Nota:** le pianificazioni di Rules Engine sono limitate ai quarti d'ora. Il campo dei minuti di una pianificazione cron deve essere uno tra: **0, 15, 30 o 45**. Altri valori dei minuti non sono ammessi.

Esempi di pianificazioni valide:
- Ogni ora, allo scoccare dell'ora: `0 * * * *`
- Ogni giorno alle 9:15: `15 9 * * *`
- Ogni lunedì alle 15:00: `0 15 * * 1`
- Ogni 15 minuti: `0,15,30,45 * * * *`

## Creare una pianificazione per una Regola

1. Vai alla pagina **All Rules** dal menu **Rules Engine** nella barra laterale.
2. Trova la regola che vuoi pianificare e apri il suo menu delle azioni (**⋮**).
3. Fai clic su **Schedule Rule**. Questa opzione è visibile solo se lo Scheduling Service è abilitato e disponi del permesso richiesto.
4. Nella finestra modale **Schedule Rule**, compila i seguenti campi:

| Campo | Descrizione |
|---|---|
| **Name** | Un nome univoco per questa pianificazione (obbligatorio, massimo 100 caratteri). |
| **Description** | Descrizione facoltativa dello scopo della pianificazione. |
| **Trigger Type** | Scegli **Single Run** per un'esecuzione una tantum, oppure **Repeated Run** per una pianificazione cron ricorrente. |
| **Frequency** | Per Repeated Run: usa il generatore cron per selezionare il periodo (orario, giornaliero, settimanale, ecc.) e i valori specifici di minuto, ora e giorno. Per Single Run: seleziona una data e un'ora usando il selettore di data. |
| **Enable Schedule** | Attiva o disattiva la pianificazione. Una pianificazione disattivata non verrà eseguita finché non viene riattivata. |

5. Fai clic su **Submit** per salvare la pianificazione. La regola verrà eseguita automaticamente al prossimo orario pianificato.


## Permessi

L'accesso alla pianificazione all'interno di Rules Engine richiede i permessi Superuser oppure l'appropriato Permesso di Configurazione. Vedere [User Permission Chart](/admin/user_management/user_permission_chart) per i dettagli.  
