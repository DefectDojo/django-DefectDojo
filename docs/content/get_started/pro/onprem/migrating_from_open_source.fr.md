---
title: Migration depuis Open Source vers DefectDojo Pro autohébergé
description: Déplacez votre base de données et vos fichiers multimédias DefectDojo
  open source vers un déploiement DefectDojo Pro autohébergé
draft: false
weight: 6
audience: pro
---

Cette page décrit comment déplacer les données d'une instance DefectDojo open source vers un déploiement DefectDojo Pro autohébergé.

Les exemples utilisent Amazon Web Services, avec Docker Compose sur EC2 ou Kubernetes sur EKS, et la base de données sur Amazon RDS pour PostgreSQL. C'est la combinaison sur laquelle cette procédure a été validée. La même séquence s'applique à d'autres fournisseurs proposant du PostgreSQL managé et une puissance de calcul équivalente, ainsi qu'à du matériel sur site, en adaptant les commandes spécifiques au fournisseur.

Comme vous hébergez le déploiement, vos données restent dans votre propre environnement pendant toute la migration. Vous exécutez vous-même l'exportation et la restauration, et le support DefectDojo peut vous assister à chaque étape. Si votre instance DefectDojo Pro est hébergée dans le cloud par DefectDojo plutôt qu'autohébergée, contactez plutôt [support@defectdojo.com](mailto:support@defectdojo.com), car c'est l'équipe DefectDojo qui effectue la restauration pour vous.

Dans les grandes lignes, vous exportez la base de données et les fichiers multimédias de l'instance open source, vous les restaurez dans la base de données et le stockage utilisés par votre déploiement Pro, vous pointez Pro vers la base de données restaurée, puis vous validez le résultat.

## Avant de commencer

Vérifiez les points suivants avant d'exporter quoi que ce soit.

Votre moteur de base de données. DefectDojo prend en charge PostgreSQL. La prise en charge de MySQL a été dépréciée puis [supprimée dans la version 2.37.0](/releases/os_upgrading/2.37/), donc une instance plus ancienne encore sur MySQL doit être convertie vers PostgreSQL avant de pouvoir être migrée. Contactez le support si c'est votre cas.

L'emplacement d'exécution de votre base de données. Il peut s'agir d'un conteneur de la configuration Docker Compose par défaut, ou d'un service séparé sur le même hôte, sur une autre VM, ou sur un service managé tel qu'Amazon RDS ou Cloud SQL. La commande d'exportation diffère selon le cas.

Votre version open source. Trouvez-la dans le pied de page de l'interface, ou à partir des tags de déploiement et des versions d'image. Toutes les versions 2.x peuvent être migrées avec cette procédure. Si vous utilisez la version 3.0.0, 3.0.1, 3.0.2 ou 3.0.100, effectuez d'abord une mise à niveau vers la version [3.0.200](/releases/os_upgrading/3.0.200/) ou ultérieure. Consultez les [notes de mise à niveau](/releases/os_upgrading/upgrading_guide/) pour chaque version entre votre version actuelle et la version cible.

L'alignement des versions. Votre version open source doit correspondre, ou être aussi proche que possible, de la version DefectDojo Pro vers laquelle vous migrez. Au premier démarrage, Pro exécute les migrations de base de données qui font passer le schéma à sa propre version ; un écart de version important augmente donc le risque d'une migration longue ou échouée. Alignez les versions avant de réaliser le dump.

Votre base de données cible. Provisionnez une version majeure de PostgreSQL actuellement prise en charge, 16 ou ultérieure, et jamais antérieure à la version utilisée par votre instance open source, car un dump ne peut pas être restauré dans une version majeure plus ancienne. Sur AWS, placez l'instance RDS dans le même VPC que votre calcul Pro et autorisez le trafic entrant sur le port 5432 depuis l'hôte à partir duquel vous effectuez la restauration.

Votre hôte de restauration. Vous avez besoin d'une machine sur le même réseau que la base de données, avec les outils clients PostgreSQL `pg_restore` et `psql` installés. Sur AWS, utilisez une instance EC2 dans le même VPC, idéalement dans la même zone de disponibilité que l'instance RDS.

L'espace disque libre. Le serveur source a besoin de place pour le dump de la base de données et l'archive multimédia compressée avant que vous ne les déplaciez.

## Étape 1 : exportez votre base de données

La configuration Docker Compose par défaut utilise `defectdojo` à la fois comme nom d'utilisateur et comme nom de base de données. Ces valeurs peuvent être remplacées, donc vérifiez la valeur `DD_DATABASE_URL` dans votre fichier `docker-compose.yml` ou `.env`. La chaîne de connexion par défaut est :

```text
postgresql://defectdojo:defectdojo@postgres:5432/defectdojo
```

Dans les commandes ci-dessous, remplacez `<db_username>`, `<database_name>` et `<postgres_container_name>` par vos propres valeurs. Trouvez le nom du conteneur avec `docker ps`.

Un dump compressé au format personnalisé (custom-format) est recommandé. `pg_restore` peut le charger directement, et cela évite la plupart des problèmes de propriété et de rôles qui surviennent lors d'une restauration dans une base de données managée.

Pour un PostgreSQL conteneurisé, ce qui correspond à la configuration Docker Compose par défaut :

```bash
docker exec <postgres_container_name> pg_dump \
  -U <db_username> -Fc <database_name> > ./defectdojo-backup.dump
```

Si la base de données nécessite un mot de passe, transmettez-le via l'environnement :

```bash
docker exec -e PGPASSWORD='your_password' <postgres_container_name> pg_dump \
  -U <db_username> -Fc <database_name> > ./defectdojo-backup.dump
```

Pour un PostgreSQL externe ou distant, comme une VM séparée, Amazon RDS ou Cloud SQL :

```bash
pg_dump -h <remote_ip_or_hostname> -p 5432 \
  -U <db_username> -Fc <database_name> > ./defectdojo-backup.dump
```

Un dump SQL en texte brut, produit en omettant `-Fc`, fonctionne également. Il a tendance à intégrer des instructions `CREATE ROLE`, `ALTER ROLE` et `CREATE DATABASE` qu'une base de données managée rejettera, consultez donc la remarque de l'étape 4 si vous en utilisez un.

## Étape 2 : exportez vos fichiers multimédias

DefectDojo stocke les artefacts téléversés tels que les captures d'écran, les modèles de menace et les documents d'acceptation du risque dans un répertoire multimédia. Les fichiers de scan utilisés pour l'import et le réimport ne sont pas conservés sur disque par DefectDojo open source, puisqu'ils sont supprimés une fois analysés ; le répertoire multimédia ne contient donc que les artefacts téléversés par les utilisateurs.

L'emplacement du répertoire dépend de la méthode de déploiement utilisée :

| Méthode de déploiement | Chemin multimédia habituel |
| --- | --- |
| Docker Compose | Volume nommé `defectdojo_media`, monté sur `/app/media` |
| Bare metal | `/opt/dojo/media`, ou le chemin défini dans `DD_MEDIA_ROOT` |
| Kubernetes | Volume persistant monté sur `/app/media` |

Compressez le répertoire en une seule archive. Depuis un volume nommé :

```bash
docker run --rm \
  -v defectdojo_media:/media \
  -v $(pwd):/backup \
  alpine tar czf /backup/defectdojo_media.tar.gz -C /media .
```

Depuis un chemin sur disque :

```bash
tar czf defectdojo_media.tar.gz -C /opt/dojo/media .
```

## Étape 3 : nommez vos fichiers

Indiquez votre version open source dans les deux noms de fichiers afin que la version concernée soit sans ambiguïté lors de la restauration. Pour une instance exécutant la version 2.38.1 :

| Fichier | Renommé en |
| --- | --- |
| `defectdojo-backup.dump` | `defectdojo-v2.38.1-backup.dump` |
| `defectdojo_media.tar.gz` | `defectdojo-v2.38.1-media.tar.gz` |

Déplacez les deux fichiers vers votre hôte de restauration. Vous pouvez les copier directement avec un outil tel que `scp`, ou les déposer dans un stockage d'objets privé de votre propre compte puis les récupérer sur l'hôte de restauration. Sur AWS, cela signifie un bucket S3 privé et `aws s3 cp`. Dans les deux cas, les données restent dans votre propre environnement.

## Étape 4 : restaurez la base de données

Exécutez la restauration depuis votre hôte de restauration, en pointant vers le point de terminaison de la base de données. Les services PostgreSQL managés diffèrent sur ce point. Amazon RDS ne propose pas d'import en une étape d'un fichier dump depuis un bucket ; la voie prise en charge est donc un `pg_restore` côté client.

1. Créez la base de données et le rôle applicatif. Connectez-vous avec votre utilisateur maître et créez la base de données cible ainsi que le rôle attendu par le dump. Les valeurs par défaut sont `defectdojo` pour les deux, utilisez donc vos propres valeurs si vous les avez remplacées.

```sql
CREATE ROLE defectdojo WITH LOGIN PASSWORD '<app_db_password>';
CREATE DATABASE defectdojo OWNER defectdojo;
```

2. Restaurez le dump. Pour un dump au format personnalisé, utilisez `--no-owner` et `--no-privileges` afin que la restauration n'essaie pas de réattribuer la propriété à des rôles qui n'existent pas sur la cible. Une base de données managée n'accorde pas de véritable superutilisateur, donc une restauration qui tenterait cela échouerait.

```bash
pg_restore -v --no-owner --no-privileges \
  -h <db-endpoint> -U <master_user> -d defectdojo \
  -j 2 defectdojo-v<VERSION>-backup.dump
```

Pour un dump SQL en texte brut, commentez ou supprimez d'abord toutes les instructions `CREATE ROLE`, `ALTER ROLE`, `CREATE DATABASE` et `ALTER DATABASE ... OWNER`, puis chargez-le :

```bash
gunzip -c defectdojo-v<VERSION>-backup.sql.gz | \
  psql -h <db-endpoint> -U <master_user> -d defectdojo
```

Si la restauration signale des erreurs, capturez la sortie et contactez le support avant de retirer quoi que ce soit d'autre du dump. Supprimer trop d'éléments peut laisser la base de données dans un état incohérent plus difficile à diagnostiquer que l'erreur d'origine.

## Étape 5 : restaurez vos fichiers multimédias

Placez le contenu de l'archive multimédia à l'endroit où votre déploiement Pro lit les fichiers téléversés. L'application les recherche dans `/app/media`, que votre déploiement fait reposer sur un bind mount ou un volume persistant. Consultez la documentation d'installation fournie avec votre licence pour connaître le chemin hôte ou le volume utilisé par votre déploiement.

Pour un déploiement Docker Compose reposant sur un volume nommé :

```bash
docker run --rm \
  -v defectdojo_media:/media \
  -v $(pwd):/backup \
  alpine sh -c "tar xzf /backup/defectdojo-v<VERSION>-media.tar.gz -C /media"
```

Pour un déploiement Kubernetes, extrayez l'archive localement puis copiez-la dans le pod Django, qui écrit dans le persistent volume claim monté sur `/app/media` :

```bash
kubectl cp ./media-extracted/. <namespace>/<django-pod-name>:/app/media/
```

## Étape 6 : pointez DefectDojo Pro vers la base de données restaurée

Mettez à jour la connexion à la base de données pour que Pro utilise la base que vous venez de restaurer, puis démarrez l'application. Au premier démarrage, Pro exécute les migrations de base de données qui font passer le schéma de votre version open source à la version Pro. Selon la taille de votre base de données et l'ampleur de l'écart de version, cela peut prendre du temps, et l'application n'est pas disponible tant que ce n'est pas terminé.

Pour les déploiements Docker Compose, définissez l'URL de la base de données dans votre configuration de déploiement puis redémarrez la stack. La clé de configuration exacte et la commande dépendent de la version de `dojo-compose-cli` qui vous a été fournie ; suivez donc la documentation d'installation livrée avec votre licence. La chaîne de connexion prend la forme suivante :

```text
postgresql://defectdojo:<app_db_password>@<db-endpoint>:5432/defectdojo
```

Pour les déploiements Kubernetes, définissez l'URL de la base de données dans vos valeurs Helm puis redéployez :

```yaml
databaseUrl: postgresql://defectdojo:<app_db_password>@<db-endpoint>:5432/defectdojo
```

Les fonctionnalités Pro disponibles pour votre déploiement dépendent de votre licence et de votre mode de déploiement, certaines d'entre elles n'étant pas applicables à une installation autohébergée. DefectDojo confirme l'ensemble qui s'applique à vous pendant la migration.

## Étape 7 : validez vos données

Une fois l'application exécutée sur la base de données restaurée :

1. Connectez-vous à votre déploiement DefectDojo Pro.
2. Vérifiez que vos Actifs, Organisations, Engagements, Tests et Constatations sont présents. Les Actifs et Organisations s'appelaient Produits et Types de produit dans la version open source.
3. Téléchargez un fichier téléversé représentatif depuis l'interface, par exemple une pièce jointe sur une Constatation, un Test ou un Engagement, afin de confirmer que la restauration des fichiers multimédias a fonctionné.
4. Vérifiez que les comptes utilisateurs et les groupes sont intacts. Le SSO et les autres paramètres d'authentification doivent généralement être reconfigurés pour le nouveau déploiement.
5. Signalez tout écart à votre contact DefectDojo.

## Planifier la bascule

Le dump est un instantané figé dans le temps, donc tout ce qui est créé dans l'instance open source après sa réalisation ne se retrouvera pas dans le déploiement Pro. Pour éviter de perdre des données, gelez l'instance open source pour le dump final et la bascule, ou effectuez la migration pendant une période calme.

Un essai à blanc en vaut la peine. Migrez d'abord une copie récente, validez-la, puis répétez le processus pour la bascule réelle. La seconde exécution est plus rapide, et elle vous indique la durée que prendra la migration de schéma de l'étape 6.

## Liste de contrôle de la migration

- Moteur de base de données, emplacement de la base de données et version open source identifiés
- Version open source alignée avec la version Pro cible
- PostgreSQL cible provisionné, accessible depuis un hôte de restauration disposant des outils clients PostgreSQL
- Base de données exportée, avec un dump au format personnalisé si possible
- Répertoire multimédia localisé et compressé
- Les deux fichiers nommés avec la version open source
- Base de données et rôle applicatif créés sur la cible
- Dump restauré, avec la sortie de la restauration vérifiée pour détecter les erreurs
- Fichiers multimédias restaurés vers le chemin ou le volume utilisé par votre déploiement
- Pro pointé vers la base de données restaurée et démarré, migrations de schéma terminées
- Données validées dans le nouveau déploiement

## Questions ou assistance

DefectDojo accompagne cette migration de bout en bout. Pour obtenir de l'aide à n'importe quelle étape, contactez votre représentant de compte ou [support@defectdojo.com](mailto:support@defectdojo.com).
