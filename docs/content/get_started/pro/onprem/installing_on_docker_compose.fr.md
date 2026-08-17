---
title: Installation sur Docker Compose
description: Installez DefectDojo Pro auto-hébergé sur un hôte unique à l'aide de
  dojo-compose-cli, avec PostgreSQL sur un serveur séparé
draft: false
weight: 15
audience: pro
---

Cette page explique comment installer DefectDojo Pro sur Docker Compose, le plus simple des deux modèles d'auto-hébergement, et le bon choix si vous n'exploitez pas déjà Kubernetes.

Le résultat comprend deux hôtes. L'un exécute l'application et ses services associés sous Docker Compose, l'autre exécute PostgreSQL. Vous pouvez pointer vers une base de données managée plutôt que d'exécuter la vôtre, et pour une évaluation, vous pouvez exécuter la base de données dans un conteneur sur l'hôte applicatif, bien que cela soit déconseillé pour des données de production.

Presque tout le travail est effectué par `dojo-compose-cli`, que DefectDojo fournit avec votre licence. Sa commande `first-install` est un assistant interactif qui configure le déploiement, télécharge les images, démarre l'ensemble et enregistre un service systemd.

## Avant de commencer

Dimensionnez d'abord le déploiement. Les recommandations de dimensionnement matériel de cette section indiquent ce qu'il faut provisionner à la fois pour l'hôte applicatif et pour la base de données.

Ubuntu 24.04 LTS est le système d'exploitation pris en charge pour cette installation. Mettez-le entièrement à jour avant de commencer. L'installation exécute des commandes en tant que root ; vous avez donc besoin de `sudo` ou d'un shell root sur les deux hôtes.

Vous aurez besoin de deux fichiers fournis par DefectDojo, qui arrivent avec votre abonnement : l'archive `dojo-compose-cli` et votre fichier de licence, généralement nommé `dojopro.lic`. Contactez votre représentant de compte ou [support@defectdojo.com](mailto:support@defectdojo.com) si vous ne les avez pas.

## Configurer la base de données

DefectDojo Pro nécessite PostgreSQL 16 ou une version ultérieure.

### Utiliser une base de données managée

Si vous utilisez un service PostgreSQL managé, suivez la documentation de ce fournisseur pour créer l'instance, puis créez les éléments suivants :

- Une base de données nommée `dojodb`
- Un utilisateur de base de données nommé `dojodbusr`, disposant de tous les privilèges sur `dojodb` et défini comme son propriétaire

Notez le nom d'hôte, le port s'il n'est pas le 5432 par défaut, ainsi que les identifiants. Vous en aurez besoin pendant l'installation.

### Exécuter PostgreSQL vous-même

Sur Ubuntu 24.04, PostgreSQL 16 est disponible dans les dépôts par défaut :

```bash
apt update
apt -y install postgresql postgresql-contrib
```

Créez les bases de données et l'utilisateur applicatif. DefectDojo utilise une seconde base de données pour son service d'orchestration ; créez donc les deux :

```sql
CREATE USER dojodbusr;
CREATE DATABASE dojodb;
CREATE DATABASE "dojodb-ddorch";
ALTER USER dojodbusr WITH ENCRYPTED PASSWORD '<strong-password>';
GRANT ALL PRIVILEGES ON DATABASE dojodb TO dojodbusr;
GRANT ALL PRIVILEGES ON DATABASE "dojodb-ddorch" TO dojodbusr;
ALTER DATABASE dojodb OWNER TO dojodbusr;
ALTER DATABASE "dojodb-ddorch" OWNER TO dojodbusr;
```

Utilisez un mot de passe alphanumérique. Les caractères spéciaux devront être encodés en URL plus tard, lorsque le mot de passe sera intégré à une chaîne de connexion, et c'est une étape facile à mal exécuter.

Autorisez ensuite la base de données à écouter les connexions provenant de l'hôte applicatif. Dans `/etc/postgresql/16/main/postgresql.conf`, définissez `listen_addresses` avec l'adresse propre du serveur de base de données, ou avec `*` si vous préférez ne pas la fixer :

```bash
listen_addresses = '<db-server-address>'
```

Et dans `/etc/postgresql/16/main/pg_hba.conf`, ajoutez trois lignes autorisant l'hôte applicatif. Il vaut mieux restreindre à l'adresse de l'hôte applicatif que d'ouvrir à tout le monde :

```text
host  dojodb         dojodbusr  <app-server-address>/32  scram-sha-256
host  dojodb-ddorch  dojodbusr  <app-server-address>/32  scram-sha-256
host  postgres       dojodbusr  <app-server-address>/32  scram-sha-256
```

Redémarrez pour que les deux changements prennent effet :

```bash
systemctl restart postgresql
```

## Préparer l'hôte applicatif

### Connectivité sortante

Dans un réseau restreint, l'hôte applicatif a besoin d'un accès sortant vers les éléments suivants. Tous sont en HTTPS sur le port 443 sauf indication contraire.

| Destination | Objectif | Obligatoire |
| --- | --- | --- |
| `us-south1-docker.pkg.dev` | Le registre de conteneurs de DefectDojo Pro | Oui |
| Votre hôte de base de données, généralement le port 5432 | Application vers base de données | Oui |
| Les dépôts de paquets de votre distribution | Dépendances du système d'exploitation pendant l'installation | Oui |
| `download.docker.com` | Paquets Docker Engine pendant l'installation | Oui |
| `api.first.org` | Scores de prédiction d'exploitation EPSS | Facultatif |
| `www.cisa.gov` | Le catalogue KEV des vulnérabilités exploitées connues | Facultatif |

Autorisez par nom d'hôte plutôt que par adresse. Le registre se trouve derrière un réseau de diffusion de contenu, si bien que ses adresses varient selon la localisation et changent au fil du temps.

Si l'hôte accède à Internet via un proxy sortant, consultez [Exécuter DefectDojo derrière un proxy HTTPS sortant](/onprem_deployment/forward_proxy/). S'il n'a aucun accès à Internet, suivez plutôt la procédure d'installation en environnement isolé (air-gapped) de cette section.

### Vérifier que la base de données est accessible

Installez les outils clients et connectez-vous avant d'aller plus loin. Un problème de base de données est bien plus facile à diagnostiquer maintenant qu'en plein milieu de l'installation :

```bash
apt update
apt -y install postgresql-client-common postgresql-client-16
psql -h <db-host> -p 5432 -d dojodb -U dojodbusr -W
```

### Installer Docker Engine

Suivez les [instructions d'installation de Docker Engine pour Ubuntu](https://docs.docker.com/engine/install/ubuntu/). Utilisez la documentation officielle de Docker plutôt qu'une copie, car les étapes évoluent avec le temps. Installez le paquet `docker-compose-plugin` en même temps que le moteur, ce que ces instructions incluent par défaut.

Ajoutez ensuite votre utilisateur au groupe `docker` et prenez en compte cette nouvelle appartenance :

```bash
sudo usermod -aG docker "$USER"
newgrp docker
docker info
```

## Installer DefectDojo

Copiez l'archive du CLI et votre fichier de licence sur l'hôte applicatif, dans le même répertoire, puis extrayez le CLI :

```bash
tar -xzvf dojo-compose-cli_*.tar.gz
```

Puis exécutez l'installeur depuis ce répertoire :

```bash
sudo ./dojo-compose-cli first-install
```

L'assistant vous demande les informations suivantes.

| Invite | Description |
| --- | --- |
| `DOJO_CLI_KEY` | Une clé de chiffrement pour la configuration que le CLI stocke sur disque. Choisissez-la maintenant et conservez-la, car les commandes ultérieures en ont besoin. |
| DefectDojo Version | La version à installer. |
| Deploy Version | Les fichiers de déploiement à utiliser. Définissez-le avec la même valeur que la version. |
| Deploy Type | `separate-db` pour une base de données sur son propre hôte, ou `containerized-db` pour exécuter PostgreSQL dans un conteneur. |
| Database Connection Type | Choisissez Single Line et indiquez la chaîne de connexion complète. |
| Database URL | `postgres://<user>:<password>@<host>:5432/dojodb`. Elle doit commencer par `postgres://` et non par `postgresql://`. |
| `DD_ALLOWED_HOSTS` | Les en-têtes Host auxquels l'application répondra. |
| `DD_SITE_URL` | L'URL complète par laquelle les utilisateurs accèdent à DefectDojo, par exemple `https://defectdojo.internal.example.com`. |

Deux points à connaître au moment des invites. Fournissez la connexion à la base de données sous forme d'une seule ligne plutôt que valeur par valeur, car le mode valeur par valeur ne demande actuellement pas le nom d'utilisateur. Et si le mot de passe contient des caractères comme `!`, `@` ou `#`, encodez-les en URL dans la chaîne de connexion.

L'installeur télécharge ensuite les images, démarre la pile, crée un service systemd et affiche les identifiants administrateur générés. **Enregistrez ces identifiants avant de fermer le terminal. Ils ne seront plus affichés par la suite.**

Une fois terminé, DefectDojo est disponible à l'URL de site que vous avez indiquée.

## Ce que l'installation a créé

| Élément | Emplacement |
| --- | --- |
| Binaire du CLI | `/usr/bin/dojo-compose-cli` |
| Fichiers de l'application, fichier compose, configuration nginx, médias | `/opt/dojo/` |
| Fichier de licence | `/etc/defectdojo/dojopro.lic` |
| Configuration chiffrée du CLI | `/etc/defectdojo/compose.config` |
| Certificats TLS | `/opt/dojo/certs/` |
| Vos personnalisations | `/opt/dojo/customizations/` |
| Service systemd | `/etc/systemd/system/defectdojo-compose.service` |

Elle crée également un utilisateur et un groupe `dojosrv`, propriétaires des fichiers de l'application.

La pile en cours d'exécution comprend l'application Django, un conteneur séparé qui gère les imports de scans, nginx, un worker et un planificateur Celery, Valkey pour la mise en cache et les files d'attente, le service de connecteurs, et le serveur MCP. `docker ps` les répertorie.

Au quotidien, voici les commandes dont vous avez besoin :

```bash
systemctl status defectdojo-compose
dojo-compose-cli app start
dojo-compose-cli app stop
dojo-compose-cli app restart
docker logs dojo
```

Utilisez `app restart` après toute modification de configuration, car cela recrée les conteneurs afin que les nouvelles valeurs soient prises en compte.

## Remplacer le certificat TLS

L'installation fournit un certificat auto-signé afin que le site fonctionne immédiatement. Remplacez-le par le vôtre en écrasant deux fichiers, en conservant exactement les mêmes noms :

- `/opt/dojo/certs/dojo.crt`
- `/opt/dojo/certs/dojo.key`

Exécutez ensuite `dojo-compose-cli app restart` pour les prendre en compte.

## Réinitialiser le mot de passe administrateur

Si vous perdez le mot de passe généré, réinitialisez-le depuis l'hôte applicatif. DefectDojo doit être en cours d'exécution :

```bash
dojo-compose-cli app change-password
```

## Mise à niveau

Sauvegardez d'abord votre base de données, et lisez les notes de version de chaque version comprise entre la vôtre et votre cible, et pas seulement celles de la cible. Consultez les [notes de mise à niveau](/releases/os_upgrading/upgrading_guide/).

Le CLI peut effectuer toute la mise à niveau, en vous demandant la version :

```bash
dojo-compose-cli app upgrade
```

Si vous préférez procéder par étapes, arrêtez l'application, définissez la nouvelle version, téléchargez les fichiers de déploiement correspondants, puis redémarrez :

```bash
dojo-compose-cli app stop
dojo-compose-cli config set --version x.y.z --deploy-version x.y.z
dojo-compose-cli deploy download
dojo-compose-cli app start
```

L'étape de téléchargement compare le `docker-compose.yml`, la configuration nginx et le `local_settings.py` entrants avec ceux que vous possédez déjà, et vous signale les différences afin que vous puissiez concilier vos modifications. L'ajout de `--overwrite` accepte les nouvelles versions de ces fichiers et abandonne les modifications locales qui leur ont été apportées ; utilisez-le donc en connaissance de cause.

Conservez vos propres réglages dans `/opt/dojo/customizations/local_settings.py`. Ce fichier vous appartient et survit aux mises à niveau.

## Référence des commandes

`dojo-compose-cli --help` liste tout, et chaque sous-commande accepte également `--help`. Les commandes dont vous aurez le plus probablement besoin :

| Commande | Ce qu'elle fait |
| --- | --- |
| `first-install` | Installation initiale interactive |
| `app start`, `app stop`, `app restart` | Contrôler la pile |
| `app upgrade` | Mettre à niveau vers une version plus récente |
| `app pull-images`, `app purge-images` | Récupérer ou supprimer les images configurées |
| `app change-password` | Réinitialiser le mot de passe administrateur, l'application étant en cours d'exécution |
| `config print` | Afficher la configuration actuelle |
| `config set` | Définir la version, la version de déploiement, le type de déploiement ou le mode air-gapped |
| `config rotate-secret` | Faire tourner la clé chiffrant la configuration stockée |
| `environment print`, `environment add`, `environment remove` | Gérer les variables d'environnement |
| `deploy download` | Récupérer les fichiers de déploiement pour la version configurée |
| `license print`, `license status`, `license update` | Consulter et mettre à jour votre licence |
| `validate db-connection` | Vérifier la chaîne de connexion à la base de données |
| `validate deploy-version` | Vérifier que les fichiers de déploiement correspondent à la version configurée |
| `diagnostics collect` | Rassembler un paquet de diagnostic pour une demande de support |
| `register` | S'authentifier auprès du registre de conteneurs |
| `update-binary` | Mettre à jour le CLI lui-même |

La plupart des commandes nécessitent `DOJO_CLI_KEY`, car la configuration est chiffrée au repos. Exportez-la pour votre session, ou transmettez-la via `sudo` avec `sudo -E` :

```bash
export DOJO_CLI_KEY="your-key"
```

## Questions ou assistance

Si une installation ne se termine pas, `dojo-compose-cli diagnostics collect` rassemble un paquet de rapport qui est le moyen le plus rapide pour nous de vous aider. Envoyez-le, avec ce que vous exécutiez au moment de l'échec, à [support@defectdojo.com](mailto:support@defectdojo.com).
