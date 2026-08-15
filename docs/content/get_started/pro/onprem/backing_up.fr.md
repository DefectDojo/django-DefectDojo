---
title: Sauvegarder un déploiement autohébergé
description: Les quatre éléments à capturer, leur emplacement pour les déploiements
  Compose et Kubernetes, et comment vérifier qu'une sauvegarde peut réellement être
  restaurée
draft: false
weight: 12
audience: pro
---

Un déploiement est plus que sa base de données. Une sauvegarde qui ne capture que la base de données restaure un système qui fonctionne, mais auquel il manque les fichiers téléversés et qui ne peut pas déchiffrer les identifiants qu'il conserve pour vos autres outils. Cette page présente ce qu'il faut capturer, où se trouve chaque élément, et comment vérifier que le résultat est restaurable.

## Les quatre éléments à capturer

La base de données contient vos organisations, vos actifs, vos engagements, vos tests, vos constatations, vos utilisateurs et votre configuration.

Les fichiers téléversés se trouvent en dehors de la base de données. Les captures d'écran, les modèles de menace, les documents d'acceptation du risque et autres pièces jointes similaires sont sur un système de fichiers, et la base de données n'en conserve que les chemins.

La configuration du déploiement est ce qui permet à l'application de redémarrer de la même façon, y compris vos propres personnalisations et vos certificats TLS.

Les clés de chiffrement sont l'élément le plus souvent oublié. La clé de chiffrement des identifiants est ce qui permet de lire les identifiants stockés pour vos outils connectés. Restaurer une base de données sans elle laisse ces identifiants intacts mais indéchiffrables, ce qui signifie que chaque intégration doit être ressaisie manuellement.

## La base de données

La plupart des déploiements autohébergés pointent vers un service PostgreSQL managé, ce qui est la configuration par défaut du chart et la configuration recommandée. Dans ce cas, utilisez les sauvegardes automatisées et la restauration à un instant précis (point-in-time recovery) proposées par le fournisseur, plutôt que de créer votre propre système. Deux points méritent d'être vérifiés plutôt que supposés : que les sauvegardes automatisées sont réellement activées sur l'instance, car une base de données managée avec les sauvegardes désactivées n'en a aucune, et que la durée de rétention correspond aux exigences de votre organisation.

Si vous exploitez vous-même PostgreSQL, effectuez un dump compressé au format personnalisé :

```bash
pg_dump -h <db_host> -U <db_user> -Fc <db_name> > defectdojo-$(date +%F).dump
```

Restaurez-le avec `pg_restore`, en utilisant `--no-owner` et `--no-privileges` si la cible a des rôles différents de la source :

```bash
pg_restore -v --no-owner --no-privileges -h <db_host> -U <db_user> -d <db_name> defectdojo-<date>.dump
```

Effectuez le dump selon une planification régulière, stockez-le en dehors de la machine qui l'a produit, et conservez suffisamment de générations pour survivre à un problème que vous ne remarqueriez pas immédiatement.

## Fichiers téléversés

Sur un déploiement Docker Compose, les fichiers téléversés se trouvent dans le répertoire `media`, à l'intérieur de votre répertoire de déploiement sur l'hôte. Sauvegardez ce chemin avec votre système habituel de sauvegarde de fichiers. Si vous l'avez déplacé vers un stockage séparé, sauvegardez ce système de fichiers plutôt que le point de montage.

Sur Kubernetes, le volume media est provisionné selon le backend de stockage configuré, et l'emplacement physique des données détermine la façon de les protéger :

| Backend de stockage | Emplacement des données | Comment les protéger |
| --- | --- | --- |
| `efs` | Un système de fichiers Amazon EFS | AWS Backup |
| `filestore` | Une instance Google Filestore | Les sauvegardes Filestore |
| `gcsfuse` | Un bucket Cloud Storage | Le versionnement du bucket, ou une copie planifiée vers un autre bucket |
| `nfs` | Votre serveur NFS | Ce qui protège déjà ce serveur |
| `pvc` | Un volume issu de votre storage class | Un instantané de volume CSI, si votre pilote le prend en charge |

Le chart provisionne le volume, il ne protège pas son contenu. Aucune planification d'instantané n'y est intégrée : la sauvegarde doit donc provenir de la plateforme ou de vos propres outils.

## Configuration et clés

Sur Compose, capturez votre répertoire `customizations`, votre répertoire `certs`, ainsi que la configuration et les valeurs d'environnement stockées par la CLI. `config print` et `environment print` vous montreront ce qui est défini.

Sur Kubernetes, capturez vos fichiers values ainsi que le contenu des secrets référencés par votre release.

Dans les deux cas, conservez la clé de chiffrement des identifiants et la clé secrète dans un emplacement durable et distinct, dans un gestionnaire de secrets plutôt qu'avec la sauvegarde elle-même. Quiconque dispose à la fois de la base de données et de la clé de chiffrement des identifiants peut lire les identifiants de tous les outils que vous avez connectés : ils ne doivent donc pas voyager ensemble.

## Ce qui n'est pas une sauvegarde

Le chart annote ses persistent volume claims afin qu'ils survivent à `helm uninstall`, ce qui est activé par défaut. Il s'agit d'une protection contre une désinstallation accidentelle, pas d'une sauvegarde. Cela ne protège en rien contre une corruption, une suppression au sein de l'application, ou une mise à niveau qui se passe mal, car dans chacun de ces cas, le volume survit et les dégâts s'y trouvent.

Les instantanés conservés uniquement dans le même compte ou projet que le déploiement sont, de la même façon, plus fragiles qu'il n'y paraît. Tout ce qui peut supprimer le déploiement peut généralement aussi les supprimer.

## Vérifier qu'une sauvegarde est restaurable

Une sauvegarde que personne n'a jamais restaurée n'est qu'une hypothèse. Testez-la dans un environnement de test plutôt que par-dessus la production, et vérifiez les points suivants :

1. Connectez-vous, et vérifiez que vos organisations, actifs, engagements, tests et constatations sont présents dans les quantités attendues.
2. Ouvrez une constatation comportant une pièce jointe et téléchargez-la. C'est ce qui prouve que la restauration des fichiers media a fonctionné, car la base de données seule afficherait la pièce jointe dans la liste mais échouerait à la servir.
3. Ouvrez une connexion d'outil configurée et vérifiez que ses identifiants sont intacts. C'est ce qui prouve que vous avez correctement restauré la clé de chiffrement des identifiants, et c'est la vérification la plus susceptible de révéler un manque.
4. Vérifiez que les utilisateurs et les groupes ont bien été transférés. Les paramètres d'authentification comme le SSO doivent généralement être reconfigurés pour un environnement différent : considérez donc les écarts à ce niveau comme normaux plutôt que comme une restauration échouée.

Effectuez cet exercice selon une planification régulière plutôt que seulement en cas de besoin. C'est en effectuant une restauration pour la première fois pendant un incident que les plans de sauvegarde échouent le plus souvent.

## Questions ou assistance

Pour vous aider à planifier les sauvegardes de votre déploiement, ou si une restauration ne se déroule pas comme prévu, contactez [support@defectdojo.com](mailto:support@defectdojo.com).
