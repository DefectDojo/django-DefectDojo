---
title: Befunde mit Quellcode verknüpfen
description: Integration von Repositories, um zur Stelle der Befunde im Quellcode
  zu navigieren.
draft: false
weight: 5
audience: opensource
aliases:
- /de/en/working_with_findings/organizing_engagements_tests/source-code-repositories
---

Bestimmte Tools (insbesondere SAST-Tools) geben in den Schwachstellendaten den zugehörigen Dateinamen und die Zeilennummer an. Wenn das Repository des Quellcodes im Engagement angegeben ist, stellt DefectDojo den Dateipfad als Link dar, sodass der Benutzer direkt zur Stelle der Schwachstelle navigieren kann.

## Festlegen des Repositorys im Engagement und Test

### Engagement

Beim Bearbeiten des Engagements können Benutzer die URL des spezifischen Source-Code-Management-Repositorys festlegen.  **(In der Pro-UI kann dieses Feld unter Engagement bearbeiten > Optionale Felder > Repo festgelegt werden)**.

Bei einem Interactive Engagement muss es sich um eine URL handeln, die den Branch angibt:
- für GitHub - z. B. https://github.com/DefectDojo/django-DefectDojo/tree/dev
![Engagement bearbeiten (GitHub)](images/source-code-repositories_1.png)
- für GitLab - z. B. https://gitlab.com/gitlab-org/gitlab/-/tree/master
![Engagement bearbeiten (Gitlab)](images/source-code-repositories-gitlab_1.png)
- für öffentliches BitBucket - z. B.    (wie eine Git-Clone-URL)
![Engagement bearbeiten (Bitbucket öffentlich)](images/source-code-repositories-bitbucket_1.png)
- für eigenständiges/On-Premise-BitBucket https://bb.example.com/scm/some-project/some-repo.git oder https://bb.example.com/scm/some-user-name/some-repo.git für ein öffentliches Benutzer-Repository (wie eine Git-Clone-URL)
![Engagement bearbeiten (Bitbucket eigenständig)](images/source-code-repositories-bitbucket-onpremise_1.png)

Bei CI/CD-Engagements können Commit-Hash, Branch/Tag und Codezeile variieren, sodass Sie nur die URL des Repositorys angeben müssen.
- für GitHub - z. B. `https://github.com/DefectDojo/django-DefectDojo`
- für GitLab - z. B. `https://gitlab.com/gitlab-org/gitlab`
- für öffentliches BitBucket, Gitea und Codeberg - z. B. `https://bitbucket.org/some-user/some-project.git` (wie eine Git-Clone-URL)
- für eigenständiges/On-Premise-BitBucket `https://bb.example.com/scm/some-project.git` oder `https://bb.example.com/scm/some-user-name/some-repo.git` für ein öffentliches Benutzer-Repository (wie eine Git-Clone-URL)

In einem CI/CD-Engagement können Sie im Formular **Edit Engagement** einen Commit-Hash oder Branch/Tag angeben, der an alle von DefectDojo dargestellten Links angehängt wird.  Wenn diese nicht festgelegt sind, muss die SCM-URL einen vollständigen Link enthalten, der den Code-Branch einschließt.

Die SCM-Navigations-URL wird anhand des SCM-Typs aus der Repo-URL zusammengesetzt. Ein bestimmter SCM-Typ kann im benutzerdefinierten Asset-Feld „scm-type“ festgelegt werden. Ist kein „scm-type“ festgelegt und enthält die URL „https://github.com“, wird der SCM-Typ „github“ angenommen.

Benutzerdefinierte Asset-Felder:

![Benutzerdefinierte Asset-Felder](images/asset-custom-fields_1.png)

SCM-Typ zum Asset hinzufügen:

![Asset-SCM-Typ](images/asset-scm-type_1.png)

Mögliche SCM-Typen sind 'github', 'gitlab', 'bitbucket', 'bitbucket-standalone', 'gitea', 'codeberg' oder keine Angabe (für den Standard github).


## Quellcode-Links in Befunden

Beim Anzeigen eines Befunds wird die Stelle als Link dargestellt, sofern das Repository des Quellcodes im Engagement festgelegt wurde:

![Link zur Stelle](images/source-code-repositories_2.png)

Durch Klicken auf diesen Link wird ein neuer Tab im Browser geöffnet, in dem die Quelldatei der Schwachstelle bei der entsprechenden Zeilennummer angezeigt wird:

![Im Repository anzeigen](images/source-code-repositories_3.png)
