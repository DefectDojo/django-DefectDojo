---
title: Ruoli RBAC personalizzati
description: Crea i tuoi ruoli scegliendo singole autorizzazioni, utilizzando i cinque
  ruoli predefiniti come punti di partenza clonabili
weight: 5
audience: pro
---

> **Funzionalità di DefectDojo Pro.** Il sistema RBAC Members / Groups / Global Roles descritto in questa pagina fa parte di DefectDojo Pro. DefectDojo open source utilizza il modello [Authorized Users](../os__authorized_users/). Consulta quella pagina per il controllo degli accessi in open source e le [note di aggiornamento alla 3.0](/releases/os_upgrading/3.0/#authorized-users-panel-replaces-membersgroups-under-legacy-authorization) se stai passando da un'edizione all'altra.

DefectDojo Pro include cinque ruoli: **Reader**, **Writer**, **Maintainer**, **Owner** e **API Importer**. Se nessuno di questi è adatto, ora puoi creare un tuo ruolo scegliendo esattamente quali autorizzazioni concede.

Un ruolo personalizzato funziona ovunque funzioni un ruolo predefinito: come Global Role, come ruolo di un Group, come ruolo di gruppo predefinito e come ruolo di membro su una singola Organization o Asset.

I cinque ruoli predefiniti diventano **preset bloccati e clonabili**. Le loro autorizzazioni restano invariate (consulta le [tabelle delle autorizzazioni per azione](../user_permission_chart/) per sapere cosa concede ciascuno), non possono essere modificati o eliminati, e clonarne uno è il modo consigliato per creare un nuovo ruolo.

## Prima di iniziare

La gestione dei ruoli personalizzati è disattivata per impostazione predefinita. Un **superuser** la attiva da **Settings > Feature Flags**, abilitando **Custom Roles**. Consulta [Feature Flags](/admin/feature_flags/pro__feature_flags/) per sapere come funziona quella pagina.

Quando la funzionalità è disattivata, la pagina Roles resta comunque leggibile: puoi visualizzare i ruoli predefiniti e le relative autorizzazioni, ma non puoi creare, modificare, clonare o eliminare nulla.

La gestione dei ruoli richiede lo stato di **superuser** o il Global Role predefinito **Owner**. Questa scelta è intenzionale e non può essere delegata a un ruolo personalizzato: consulta [Cosa sblocca un Global Role personalizzato](#what-a-custom-global-role-unlocks).

## Apertura della pagina Roles

Vai su **👤 Utenti > Roles** nella barra laterale sinistra. La voce di menu è visibile ai superuser e a chi detiene il Global Role predefinito Owner.

![La pagina Roles con l'elenco dei ruoli predefiniti e personalizzati](images/pro_roles_list.png)

La tabella elenca tutti i ruoli della tua istanza:

| Colonna | Cosa mostra |
| --- | --- |
| **ID** | L'ID numerico del ruolo. Utile per filtrare la tabella Users o per chiamare l'API. |
| **Name** | Il nome del ruolo. |
| **Description** | Una tua nota su a cosa serve il ruolo. Facoltativa, vuota a meno che qualcuno non la compili. I ruoli predefiniti vengono forniti senza. |
| **Permissions** | Un conteggio delle autorizzazioni concesse. Fai clic per aprire una vista di sola lettura della griglia completa. |
| **Users** | Quanti utenti detengono questo ruolo come Global Role. Fai clic per vederli nella tabella Users. |
| **Type** | **Built-in** per i cinque preset, **Custom** per i ruoli creati da te. |

Ogni colonna è ordinabile e filtrabile, e la ricerca per parole chiave trova corrispondenze su nome e descrizione.

## Creazione di un ruolo

### Clonare un ruolo predefinito (consigliato)

Clonare permette di partire da un set di autorizzazioni già collaudato invece che da una griglia vuota, il che rende molto più difficile dimenticare per errore un'autorizzazione di cui il ruolo ha bisogno.

1. Trova il ruolo più vicino a quello che desideri.
2. Apri il suo menu **⋮** e scegli **Clone Role**.
3. Viene creata immediatamente una copia, denominata `<original> (copy)`, con le stesse autorizzazioni e descrizione del ruolo di origine.
4. Apri il menu **⋮** della copia, scegli **Edit Role**, quindi rinominala e modifica le sue autorizzazioni.

I ruoli predefiniti possono essere clonati anche se non possono essere modificati. Il clone registra da quale ruolo proviene.

### Partire da zero

1. Fai clic su **New Role**.
2. Assegnagli un **Name** (obbligatorio) e facoltativamente una **Description**.
3. Scegli le sue autorizzazioni nella griglia sottostante (vedi la sezione successiva).
4. Fai clic su **Save Role**.

I nomi dei ruoli devono essere univoci e il controllo ignora la distinzione tra maiuscole e minuscole: se `Triage Lead` esiste già, `triage lead` viene rifiutato.

## Scelta delle autorizzazioni

![La griglia delle autorizzazioni nel modulo del ruolo](images/pro_role_permission_grid.png)

Le autorizzazioni sono raggruppate in tre tabelle più una checklist.

**Object Permissions** si applicano alle Organization e agli Asset a cui il ruolo è assegnato, e a tutto ciò che è annidato al loro interno.

| Riga | View | Add | Edit | Delete |
| --- | --- | --- | --- | --- |
| Organization | ☑️ | ☑️ | ☑️ | ☑️ |
| Asset | ☑️ | ☑️ ¹ | ☑️ | ☑️ |
| Engagement | ☑️ | ☑️ | ☑️ | ☑️ |
| Test | ☑️ | ☑️ | ☑️ | ☑️ |
| Finding | ☑️ | ☑️ | ☑️ | ☑️ |
| Finding Group | ☑️ | ☑️ | ☑️ | ☑️ |
| Risk Acceptance | ☑️ | ☑️ | ☑️ | ☑️ |
| Location | ☑️ | ☑️ | ☑️ | ☑️ |
| Component | ☑️ | | | |
| Note | ² | ☑️ | ☑️ | ☑️ |
| Benchmark | ² | | ☑️ | ☑️ |
| Language | ☑️ | ☑️ | ☑️ | ☑️ |
| Technology | ☑️ | ☑️ | ☑️ | ☑️ |
| Asset API Scan Configuration | ☑️ | ☑️ | ☑️ | ☑️ |
| Asset Tracking Files | ☑️ | ☑️ | ☑️ | ☑️ |
| Group | ☑️ | | ☑️ | ☑️ |

1. **Asset > Add** significa creare un nuovo Asset all'interno di un'Organization a cui il ruolo è assegnato.
2. La View per Note e Benchmark è ereditata: un ruolo che può vedere l'Engagement, il Test, il Finding o l'Asset padre può vedere le sue Note e i suoi Benchmark. Queste celle mostrano un'icona **?** invece di una casella di controllo.

**Group & Member Permissions** controllano chi può gestire le appartenenze. Le colonne qui sono View, Manage, Add, Add Owner, Edit e Delete.

| Riga | Azioni disponibili |
| --- | --- |
| Gruppo dell'Organization, Gruppo dell'Asset | View, Add, Add Owner, Edit, Delete |
| Membro dell'Organization, Membro dell'Asset, Membro del Gruppo | Manage, Add Owner, Delete |

**Global Feature Permissions** condizionano funzionalità Pro a livello di istanza anziché singole Organization o Asset, quindi **hanno effetto solo quando il ruolo viene detenuto come Global Role**. Concederle su un ruolo usato solo come appartenenza a un Asset non ha alcun effetto.

| Riga | Azioni disponibili |
| --- | --- |
| Report Template | View, Add, Edit, Delete |
| Generated Report | View, Add, Delete |
| Connector, Sensei, Asset Hierarchy, Version Manager, Tuner, Universal Parser, Rule, Integration | View, Edit |
| Mitigation Policy | Edit |
| Audit Log, Metering | View |

**Additional Permissions** è una checklist di funzionalità che non rientrano in uno schema View/Add/Edit/Delete:

* **Configure Asset Notifications**: scegli quali notifiche invia un singolo Asset e dove.
* **Import Scan Result**: importa e reimporta i risultati delle scansioni, creando e aggiornando i Riscontri.
* **Share Dashboard Layout**: pubblica un layout della dashboard per altri utenti. Solo Global Role.
* **Share Table Preference**: pubblica una vista tabellare salvata (colonne, filtri, ordinamento). Solo Global Role.
* **View Note History**: vedi chi ha modificato una nota e quando.

### Come leggere la griglia

![La vista di sola lettura delle autorizzazioni di un ruolo](images/pro_role_permissions_modal.png)

| Cosa vedi | Cosa significa |
| --- | --- |
| Una casella di controllo vuota | L'autorizzazione esiste e non è concessa. Fai clic per concederla. |
| Una casella di controllo selezionata | Concessa. |
| Una cella vuota e ombreggiata | L'autorizzazione non esiste per quella riga e azione. Non selezionabile. |
| Un'icona **?** | La View è ereditata da un oggetto padre, quindi qui non c'è nulla da concedere. |
| Un ✔ verde (vista di sola lettura) | Concessa. |
| Una ✘ rossa (vista di sola lettura) | Non concessa. |

In ogni riga, l'autorizzazione più a sinistra (**View**, o **Manage** nelle righe dei membri) condiziona il resto della riga. Devi concederla prima che le altre celle di quella riga diventino disponibili, perché un ruolo non può modificare o eliminare in modo significativo ciò che non può vedere. Rimuovere questa condizione azzera anche il resto della riga.

## Modifica, clonazione ed eliminazione

Il menu **⋮** di ogni riga offre **Edit Role**, **Clone Role**, **Delete Role** e **Role History**.

I ruoli predefiniti offrono solo **Clone Role**. Non possono essere modificati o eliminati da nessuno, superuser inclusi. Questo mantiene una base di riferimento nota e rende gli aggiornamenti prevedibili.

L'eliminazione di un ruolo ancora assegnato a qualcuno fallirà. Riassegna o rimuovi prima quelle assegnazioni, poi elimina il ruolo. Le assegnazioni che contano a questo scopo sono le appartenenze a Organization e Asset (sia utente che gruppo), i Global Role, le appartenenze a Group e il ruolo di gruppo predefinito in System Settings.

L'API può eseguire la riassegnazione per te con una singola chiamata. Consulta [Gestire i ruoli tramite l'API](#managing-roles-through-the-api).

## Assegnazione di un ruolo personalizzato

I ruoli personalizzati compaiono in ogni menu a discesa dei ruoli, insieme a quelli predefiniti:

| Dove | Come |
| --- | --- |
| **Global Role su un utente** | Il campo **Global Role** nel modulo dell'utente. Solo superuser. Consulta [Impostare le autorizzazioni di un Utente](../set_user_permissions/). |
| **Global Role su un gruppo** | Il campo **Global Role** nel modulo del gruppo. Consulta [Condividere le autorizzazioni: gruppi di utenti](../create_user_group/). |
| **Appartenenza a Organization o Asset** | La finestra di dialogo Permissions sull'Organization o sull'Asset, sia per gli utenti che per i gruppi. Consulta [Impostare le autorizzazioni in Pro](../pro_permissions_overhaul/). |
| **Ruolo di gruppo predefinito** | **Default group role** in System Settings, applicato ai nuovi utenti creati. Consulta [Gestire le autorizzazioni predefinite](../about_perms_and_roles/#manage-default-permissions). |
| **Ruolo all'interno di un gruppo** | Il menu a discesa dei ruoli nell'elenco dei membri di un gruppo. Questo menu a discesa offre solo i ruoli che concedono almeno un'autorizzazione Group, quindi un ruolo senza autorizzazioni Group non vi comparirà. |

Vale la pena conoscere due vincoli:

* **Il livello Owner è riservato.** Un ruolo personalizzato non può mai essere un ruolo di livello owner. Solo l'Owner predefinito lo è, quindi solo lui possiede il potere implicito di gestire altri Owner.
* **Concedere il ruolo Owner a qualcun altro richiede comunque l'autorizzazione Add Owner corrispondente**, che tu lo faccia su un'Organization, un Asset o un Group.

## Cosa sblocca un Global Role personalizzato

Alcune parti dell'interfaccia sono condizionate da un Global Role minimo anziché da una singola autorizzazione. Per far funzionare i ruoli personalizzati con queste condizioni, DefectDojo classifica un Global Role personalizzato rispetto ai livelli predefiniti: un ruolo personalizzato ottiene il livello più alto le cui autorizzazioni copre **completamente**.

* Un ruolo personalizzato che copre tutto ciò che concede Maintainer viene trattato come Maintainer per quelle condizioni.
* Copri tutto ciò che concede Writer, e viene trattato come Writer. Lo stesso vale per Reader.
* Se non ne copre completamente nessuno, non ottiene alcun livello. Le sue singole autorizzazioni funzionano comunque esattamente come concesse; solo le restrizioni dell'interfaccia basate sul livello restano chiuse.
* **Owner non può mai essere ottenuto in questo modo.** La gestione dei ruoli, e tutto ciò che è condizionato dal Global Role Owner, resta riservata ai superuser e all'Owner predefinito.

La copertura deve essere completa, il che a volte sorprende. Un ruolo clonato da Maintainer ottiene il livello Maintainer. Se ricostruisci a mano le autorizzazioni di Maintainer e ne ometti una, il ruolo finisce invece al livello Writer. Se a un Global Role personalizzato manca un'interfaccia che ti aspettavi, confrontalo con il livello predefinito nelle [tabelle delle autorizzazioni per azione](../user_permission_chart/).

## Cronologia dei ruoli

I ruoli personalizzati mantengono una traccia di audit. Apri **Role History** dal menu **⋮** di un ruolo per vedere quali autorizzazioni sono state concesse o revocate, da chi e quando, insieme alle modifiche su chi detiene il ruolo.

Ci sono due cose che questa cronologia non mostra: le modifiche al nome e alla descrizione di un ruolo, e le autorizzazioni dei ruoli predefiniti (questi sono precaricati, non vengono mai modificati e quindi non generano mai cronologia).

La cronologia dei ruoli è un'operazione di lettura, quindi è disponibile indipendentemente dal fatto che la funzionalità Custom Roles sia attiva o meno.

## Gestire i ruoli tramite l'API

I ruoli sono disponibili su `/api/v2/roles/`. Le letture sono aperte a qualsiasi utente autenticato, perché i client hanno bisogno dell'elenco dei ruoli per popolare i menu a discesa. Le scritture richiedono lo stato di superuser o il Global Role predefinito Owner, oltre al feature flag Custom Roles.

| Operazione | Richiesta |
| --- | --- |
| Elenca i ruoli | `GET /api/v2/roles/` |
| Recupera un ruolo | `GET /api/v2/roles/{id}/` |
| Elenca tutte le autorizzazioni assegnabili | `GET /api/v2/roles/permissions_catalog/` |
| Crea un ruolo | `POST /api/v2/roles/` con `name`, `description` facoltativa, e un elenco `permissions` |
| Sostituisce le autorizzazioni di un ruolo | `PATCH /api/v2/roles/{id}/` con un elenco `permissions` |
| Clona un ruolo | `POST /api/v2/roles/{id}/clone/` con `name` e `description` facoltativi |
| Elimina un ruolo | `DELETE /api/v2/roles/{id}/` |
| Elimina un ruolo e sposta le sue assegnazioni | `DELETE /api/v2/roles/{id}/?reassign_to={other_role_id}` |
| Legge la cronologia di un ruolo | `GET /api/v2/roles/{id}/history/` |

Note:

* `permissions` **sostituisce** l'elenco delle concessioni del ruolo invece di aggiungersi ad esso. Invia l'intero set con cui vuoi che il ruolo finisca.
* `?reassign_to=` sposta ogni assegnazione del ruolo eliminato al ruolo che indichi, in un'unica transazione. È l'unico modo per riassegnare in blocco: l'interfaccia non lo offre.
* Tentare di modificare o eliminare un ruolo predefinito restituisce `403`. Modificare un valore di autorizzazione sconosciuto, riutilizzare un nome di ruolo esistente o eliminare un ruolo in uso senza `reassign_to` restituisce `400` con una spiegazione.
* `is_owner` non può essere impostato tramite l'API. Inviarlo viene accettato ma ignorato.

## Cose da sapere

* **Più ruoli sullo stesso oggetto concedono l'unione delle rispettive autorizzazioni.** Se un utente detiene un ruolo direttamente su un Asset e ne eredita un altro tramite un gruppo, ottiene tutto ciò che entrambi i ruoli concedono. I ruoli aggiungono soltanto autorizzazioni, non le rimuovono mai.
* **Le modifiche alle autorizzazioni vengono recepite al caricamento successivo della pagina**, non istantaneamente nella vista corrente. I job in background possono impiegare fino a 30 secondi, e i dati di autorizzazione in cache fino a 5 minuti, per riflettere una modifica.
* **I menu a discesa dei ruoli elencano fino a 250 ruoli.** Oltre questo limite, alcuni ruoli non compariranno nei menu a discesa, anche se continuano a funzionare.
* **Maintainer e Owner possono aggiungere Organization, ma la griglia non lo mostra.** Per questi due ruoli, quella concessione è memorizzata come concessione a livello globale, e la griglia legge solo le concessioni a livello di oggetto, quindi la loro cella **Organization > Add** risulta come non concessa. Clonare uno dei due ruoli preserva la concessione.
* **La terminologia segue la tua istanza.** Questi documenti usano Organization e Asset, le etichette predefinite. Se nella tua istanza la rietichettatura Organization / Asset è disattivata, le stesse righe riportano invece Product Type e Product.
* **La pagina Roles è di sola lettura per chiunque altro.** Un utente che accede direttamente a `/settings/roles` può vedere i ruoli e le relative autorizzazioni ma non può modificare nulla. I dati sulle autorizzazioni non sono sensibili, e il server applica il vero limite a ogni scrittura.
