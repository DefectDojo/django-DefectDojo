---
title: Collega i Riscontri al codice sorgente
description: Integrazione dei repository per accedere alla posizione dei riscontri
  nel codice sorgente.
draft: false
weight: 5
audience: opensource
aliases:
- /it/en/working_with_findings/organizing_engagements_tests/source-code-repositories
---

Alcuni strumenti (in particolare gli strumenti SAST) includono il nome del file e il numero di riga associati nei dati sulla vulnerabilità. Se il repository del codice sorgente è specificato nell'Engagement, DefectDojo presenterà il percorso del file come link e l'utente potrà accedere direttamente alla posizione della vulnerabilità.

## Impostare il repository nell'Engagement e nel Test

### Engagement

Durante la modifica dell'Engagement, gli utenti possono impostare l'URL dello specifico repository di Source Code Management.  **(Nell'interfaccia Pro, questo campo può essere impostato in Edit Engagement > Optional Fields > Repo)**.

Per un Engagement Interattivo, deve essere un URL che specifica il branch:
- per GitHub - come https://github.com/DefectDojo/django-DefectDojo/tree/dev
![Edit Engagement (GitHub)](images/source-code-repositories_1.png)
- per GitLab - come https://gitlab.com/gitlab-org/gitlab/-/tree/master
![Edit Engagement (Gitlab)](images/source-code-repositories-gitlab_1.png)
- per BitBucket pubblico - come    (come l'URL di git clone)
![Edit Engagement (Bitbucket public)](images/source-code-repositories-bitbucket_1.png)
- per BitBucket standalone/onpremise https://bb.example.com/scm/some-project/some-repo.git oppure https://bb.example.com/scm/some-user-name/some-repo.git per un repository pubblico dell'utente (come l'URL di git clone)
![Edit Engagement (Bitbucket standalone)](images/source-code-repositories-bitbucket-onpremise_1.png)

Per gli Engagement CI/CD, l'hash del commit, il branch/tag e la riga di codice possono variare, quindi è necessario includere solo l'URL del repository.
- per GitHub - come `https://github.com/DefectDojo/django-DefectDojo`
- per GitLab - come `https://gitlab.com/gitlab-org/gitlab`
- per BitBucket pubblico, Gitea e Codeberg - come `https://bitbucket.org/some-user/some-project.git` (come l'URL di git clone)
- per BitBucket standalone/onpremise `https://bb.example.com/scm/some-project.git` oppure `https://bb.example.com/scm/some-user-name/some-repo.git` per un repository pubblico dell'utente (come l'URL di git clone)

In un Engagement CI/CD, è possibile specificare un hash di commit o un branch/tag nel form **Edit Engagement**, che verrà aggiunto a tutti i link generati da DefectDojo.  Se questi non sono impostati, l'URL SCM dovrà contenere un link completo che includa il branch del codice. 

L'URL di navigazione SCM viene composto a partire dall'URL del Repo utilizzando il tipo di SCM. Un tipo di SCM specifico può essere impostato nel campo personalizzato dell'Asset "scm-type". Se non viene impostato alcun "scm-type" e l'URL contiene "https://github.com", viene assunto un tipo di SCM "github".

Campi personalizzati dell'Asset:

![Asset custom fields](images/asset-custom-fields_1.png)

Aggiunta del tipo SCM dell'Asset:

![Asset scm type](images/asset-scm-type_1.png)

I possibili tipi di SCM sono 'github', 'gitlab', 'bitbucket', 'bitbucket-standalone', 'gitea', 'codeberg' oppure nessuno (per il valore predefinito github).


## Link al codice sorgente nei Riscontri

Durante la visualizzazione di un riscontro, la posizione verrà presentata come un link, se il repository del codice sorgente è stato impostato nell'Engagement:

![Link to location](images/source-code-repositories_2.png)

Facendo clic su questo link si aprirà una nuova scheda nel browser, con il file sorgente della vulnerabilità alla riga corrispondente:

![View in repository](images/source-code-repositories_3.png)
