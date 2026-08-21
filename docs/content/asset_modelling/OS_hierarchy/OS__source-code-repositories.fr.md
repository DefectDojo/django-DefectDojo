---
title: Associer les constatations au code source
description: Intégration des dépôts pour accéder directement à l'emplacement des constatations
  dans le code source.
draft: false
weight: 5
audience: opensource
aliases:
- /fr/en/working_with_findings/organizing_engagements_tests/source-code-repositories
---

Certains outils (notamment les outils SAST) incluent le nom de fichier et le numéro de ligne associés dans les données de vulnérabilité. Si le dépôt du code source est spécifié dans l'Engagement, DefectDojo affiche le chemin du fichier sous forme de lien et l'utilisateur peut accéder directement à l'emplacement de la vulnérabilité.

## Définir le dépôt dans l'Engagement et le Test

### Engagement

Lors de la modification de l'Engagement, les utilisateurs peuvent définir l'URL du dépôt de gestion de code source spécifique.  **(Dans l'interface Pro, ce champ se trouve sous Edit Engagement > Optional Fields > Repo)**.

Pour un Engagement interactif, il doit s'agir d'une URL qui précise la branche :
- pour GitHub - par exemple https://github.com/DefectDojo/django-DefectDojo/tree/dev
![Modifier l'Engagement (GitHub)](images/source-code-repositories_1.png)
- pour GitLab - par exemple https://gitlab.com/gitlab-org/gitlab/-/tree/master
![Modifier l'Engagement (Gitlab)](images/source-code-repositories-gitlab_1.png)
- pour BitBucket public - par exemple    (comme une URL de clonage git)
![Modifier l'Engagement (Bitbucket public)](images/source-code-repositories-bitbucket_1.png)
- pour BitBucket autonome/sur site https://bb.example.com/scm/some-project/some-repo.git ou https://bb.example.com/scm/some-user-name/some-repo.git pour un dépôt public utilisateur (comme une URL de clonage git)
![Modifier l'Engagement (Bitbucket autonome)](images/source-code-repositories-bitbucket-onpremise_1.png)

Pour les Engagements CI/CD, le hash de commit, la branche/tag et la ligne de code peuvent varier ; il suffit donc d'indiquer l'URL du dépôt.
- pour GitHub - par exemple `https://github.com/DefectDojo/django-DefectDojo`
- pour GitLab - par exemple `https://gitlab.com/gitlab-org/gitlab`
- pour BitBucket public, Gitea et Codeberg - par exemple `https://bitbucket.org/some-user/some-project.git` (comme une URL de clonage git)
- pour BitBucket autonome/sur site `https://bb.example.com/scm/some-project.git` ou `https://bb.example.com/scm/some-user-name/some-repo.git` pour un dépôt public utilisateur (comme une URL de clonage git)

Dans un Engagement CI/CD, vous pouvez indiquer un hash de commit ou une branche/tag dans le formulaire **Edit Engagement**, qui sera ajouté à tous les liens générés par DefectDojo.  Si ces informations ne sont pas définies, l'URL SCM devra contenir un lien complet incluant la branche de code.

L'URL de navigation SCM est construite à partir de l'URL du dépôt en fonction du type de SCM. Un type de SCM spécifique peut être défini dans le champ personnalisé de l'Actif « scm-type ». Si aucun « scm-type » n'est défini et que l'URL contient « https://github.com », un type de SCM « github » est présumé.

Champs personnalisés de l'Actif :

![Champs personnalisés de l'Actif](images/asset-custom-fields_1.png)

Ajout du type SCM de l'Actif :

![Type SCM de l'Actif](images/asset-scm-type_1.png)

Les types de SCM possibles sont 'github', 'gitlab', 'bitbucket', 'bitbucket-standalone', 'gitea', 'codeberg' ou aucun (github par défaut).


## Liens vers le code source dans les Constatations

Lors de la consultation d'une constatation, l'emplacement est présenté sous forme de lien si le dépôt du code source a été défini dans l'Engagement :

![Lien vers l'emplacement](images/source-code-repositories_2.png)

Cliquer sur ce lien ouvre un nouvel onglet dans le navigateur, affichant le fichier source de la vulnérabilité à la ligne correspondante :

![Afficher dans le dépôt](images/source-code-repositories_3.png)
