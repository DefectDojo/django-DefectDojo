---
title: Installation de DefectDojo Pro dans un environnement isolé (air-gapped)
description: Préparez les artefacts d'installation de DefectDojo Pro sur un hôte disposant
  d'un accès Internet, puis transférez-les dans un réseau isolé (air-gapped)
draft: false
weight: 8
audience: pro
---

Cette page complète les instructions d'installation fournies avec votre licence DefectDojo Pro. Elle ne couvre que ce qui change lorsque l'hôte cible n'a aucun accès à Internet. Pour le reste, y compris les prérequis de l'hôte et la configuration de PostgreSQL, suivez les instructions standard.

L'approche repose sur deux hôtes. Un hôte de préparation (staging), disposant d'un accès Internet normal, télécharge les artefacts de déploiement et les images de conteneurs. Vous transférez ensuite ces artefacts dans le réseau isolé (air-gapped) via le processus de transfert autorisé par votre environnement, puis terminez l'installation sur l'hôte cible, sans accès réseau vers DefectDojo.

Prévoyez de pouvoir accéder à nouveau à l'hôte de préparation par la suite. Les mises à niveau reprennent le même processus de transfert, il est donc utile de le conserver.

## Ce dont vous avez besoin

Sur l'hôte de préparation : un hôte Linux avec accès Internet, Docker installé, et suffisamment d'espace disque libre pour le répertoire de déploiement ainsi que les images de conteneurs compressées. Les images représentent l'essentiel du volume et pèsent chacune plusieurs centaines de mégaoctets.

Sur l'hôte isolé : Docker installé et fonctionnel, ainsi qu'un serveur PostgreSQL déjà provisionné et accessible, conformément aux instructions d'installation standard.

Sur les deux hôtes : une copie de l'archive `dojo-compose-cli` et votre fichier de licence, tels que fournis par DefectDojo. Utilisez la version 2.1.0 ou ultérieure de la CLI. Les versions antérieures n'ont pas de mode air-gapped, et sans lui, la CLI tente de contacter le registre de conteneurs à chaque commande et échoue avec des erreurs de résolution de nom au lieu d'indiquer clairement le problème.

## Préparer les artefacts

Exécutez les étapes suivantes sur l'hôte de préparation.

### 1. Enregistrer la CLI

Installez d'abord Docker s'il n'est pas déjà présent. Consultez la [documentation d'installation de Docker](https://docs.docker.com/engine/install/) pour les instructions spécifiques à votre distribution.

Extrayez l'archive de la CLI, puis enregistrez-la :

```bash
sudo ./dojo-compose-cli register
```

L'enregistrement installe la CLI dans `/usr/bin`, crée le groupe `dojosrv`, ajoute votre utilisateur aux groupes `dojosrv` et `docker`, valide la licence et authentifie Docker auprès du registre de conteneurs DefectDojo.

Il vous est demandé de saisir une `DOJO_CLI_KEY`, qui chiffre la configuration stockée de la CLI sur le disque. Définissez-la dans l'environnement pour éviter que la question ne soit posée à chaque commande :

```bash
export DOJO_CLI_KEY="your-key"
```

L'appartenance aux nouveaux groupes ne s'applique pas à votre shell actuel. Ouvrez une nouvelle session, ou prenez en compte les groupes directement :

```bash
newgrp docker
```

Vérifiez avec `id` que `docker` et `dojosrv` figurent bien dans la liste. Une fois votre utilisateur dans le groupe `docker`, les commandes suivantes n'ont plus besoin de `sudo`.

Si l'hôte de préparation accède à Internet via un proxy HTTPS sortant, configurez les variables de proxy avant de télécharger quoi que ce soit. Consultez [Exécuter DefectDojo derrière un proxy HTTPS sortant](/onprem_deployment/forward_proxy/).

### 2. Définir la version

Définissez à la fois la version de déploiement et la version de l'application sur la version que vous souhaitez installer, en remplaçant `x.y.z` :

```bash
dojo-compose-cli config set --deploy-version x.y.z
dojo-compose-cli config set --version x.y.z
```

Utilisez la même version dans les deux commandes, et conservez-la pour le reste de cette procédure. Mélanger les versions entre les artefacts de déploiement et les images produit une pile qui soit ne démarre pas, soit démarre avec les mauvaises images.

### 3. Télécharger les artefacts de déploiement et les images

Téléchargez le répertoire de déploiement :

```bash
dojo-compose-cli deploy download
```

Cette commande remplit `/opt/dojo` avec le fichier compose, la configuration nginx, les modèles pour l'outil de suivi des tickets, le répertoire de personnalisations, et un sous-répertoire versionné pour la version sélectionnée.

Téléchargez ensuite les images de conteneurs :

```bash
dojo-compose-cli app pull-images
```

Vérifiez ce qui a été récupéré :

```bash
docker image ls
```

Notez le préfixe de dépôt commun aux images DefectDojo dans cette sortie. Vous en aurez besoin à l'étape suivante, et l'ensemble des images varie selon les versions, alors relevez-le à partir de votre propre sortie plutôt que de supposer une liste fixe.

### 4. Noter la configuration générée

L'installation standard génère plusieurs valeurs de configuration au premier démarrage. Dans une installation air-gapped, vous les définissez manuellement sur l'hôte cible : notez-les donc maintenant :

```bash
dojo-compose-cli environment print | head -n 9
```

Conservez la clé de chiffrement des identifiants et la clé secrète. Ce sont toutes deux des chaînes aléatoires générées de 64 caractères, et la clé de chiffrement des identifiants en particulier doit correspondre à celle utilisée lors du chiffrement des identifiants : notez-la donc avec précision et stockez-la comme un secret. Les valeurs uwsgi et celery de la même sortie sont utiles comme point de départ pour l'hôte cible.

Traitez cette sortie comme sensible. Elle contient les clés protégeant les identifiants stockés pour votre déploiement.

### 5. Tout empaqueter

Créez un répertoire pour le transfert, en incluant la version dans son nom afin que le contenu reste sans ambiguïté par la suite :

```bash
mkdir artifacts-x.y.z
cd artifacts-x.y.z
```

Archivez le répertoire de déploiement, en préservant les permissions :

```bash
sudo tar -czvpf dojo-directory.tar.gz /opt/dojo
sudo chown "$USER:$USER" dojo-directory.tar.gz
```

Enregistrez les images de conteneurs. Ce script prend le préfixe de dépôt noté à l'étape 3, enregistre chaque image correspondante et la compresse :

```bash
#!/bin/bash
set -u

REPO_FILTER="${1:?usage: save-images.bash <image-repository-prefix>}"
BACKUP_DIR="./defectdojo-pro-images"
mkdir -p "$BACKUP_DIR"

images=$(docker image ls --format "{{.Repository}}:{{.Tag}}" \
  | grep -v "<none>" | grep "$REPO_FILTER")

if [ -z "$images" ]; then
    echo "No images matched '$REPO_FILTER'."
    exit 1
fi

for full_image in $images; do
    filename_part="${full_image##*/}"
    dest_path="$BACKUP_DIR/${filename_part//:/_}.tar.gz"

    echo "Saving $full_image to $dest_path"
    docker save "$full_image" | gzip > "$dest_path"

    if [[ ${PIPESTATUS[0]} -eq 0 ]] && [[ ${PIPESTATUS[1]} -eq 0 ]]; then
        du -h "$dest_path" | awk '{print "  ok, " $1}'
    else
        echo "  failed, removing partial file"
        rm -f "$dest_path"
    fi
done
```

Rendez-le exécutable et exécutez-le avec votre préfixe :

```bash
chmod u+x save-images.bash
./save-images.bash <image-repository-prefix>
```

Vérifiez que chaque image de l'étape 3 a produit un fichier, puis empaquetez le répertoire :

```bash
cd ..
tar czvf artifacts-x.y.z.tar.gz artifacts-x.y.z
```

Transférez `artifacts-x.y.z.tar.gz` dans le réseau isolé via votre processus de transfert habituel, ainsi que l'archive de la CLI et votre fichier de licence s'ils n'y sont pas déjà.

## Installer sur l'hôte isolé

### 6. Installer la CLI et activer le mode air-gapped

Extrayez l'archive de la CLI, puis placez la licence à l'emplacement attendu par la CLI :

```bash
sudo mkdir /etc/defectdojo/
sudo cp dojopro.lic /etc/defectdojo/
```

Activez le mode air-gapped. C'est la première commande de la CLI que vous exécutez sur cet hôte : elle installe la CLI dans `/usr/bin`, valide la licence à partir du fichier, et chiffre au passage la configuration stockée :

```bash
sudo ./dojo-compose-cli config set --air-gapped true
```

Vérifiez que cela a bien pris effet :

```bash
dojo-compose-cli config print
```

La sortie inclut `Air Gapped Deploy` réglé sur true. Définissez également `DOJO_CLI_KEY` dans l'environnement ici, afin que les commandes suivantes ne vous la redemandent pas.

N'exécutez pas `register` sur cet hôte. L'enregistrement sert à s'authentifier auprès du registre de conteneurs, qui est par définition inaccessible, et en mode air-gapped la CLI refuse cette commande plutôt que de tenter de l'exécuter. Il en va de même pour les autres commandes qui contactent le registre :

| Commande | Comportement en mode air-gapped |
| --- | --- |
| `register` | Refusée. L'authentification au registre n'est pas disponible. |
| `deploy download` | Refusée. Exécutez-la sur l'hôte de préparation à la place. |
| `app pull-images` | Refusée. Exécutez-la sur l'hôte de préparation à la place. |
| `app upgrade` | Refusée. Voir la section de mise à niveau ci-dessous. |
| `app start`, `app stop`, `app restart` | Disponibles. Ces commandes ne contactent pas le registre. |

Chaque commande refusée se termine avec un message mentionnant le mode air-gapped : un refus ici signifie donc que la CLI fonctionne comme prévu, et non qu'il y a un problème à diagnostiquer.

Prenez en compte votre nouvelle appartenance aux groupes avant de continuer :

```bash
newgrp docker
```

### 7. Restaurer le répertoire de déploiement

Extrayez l'archive de transfert, puis déplacez l'archive de déploiement à l'emplacement voulu :

```bash
tar -xzvf artifacts-x.y.z.tar.gz
sudo cp artifacts-x.y.z/dojo-directory.tar.gz /opt/
```

La configuration de la CLI peut avoir créé un répertoire `/opt/dojo` presque vide ne contenant que la licence. S'il existe, supprimez-le d'abord pour éviter que l'archive ne s'y fusionne :

```bash
sudo ls -lah /opt/dojo
sudo rm -rf /opt/dojo
```

Extrayez le véritable répertoire de déploiement, puis corrigez le propriétaire et les permissions du répertoire media :

```bash
cd /opt
sudo tar xzvf dojo-directory.tar.gz --strip-components 1
sudo chown -R dojosrv:dojosrv /opt/dojo
sudo chmod -R go+w /opt/dojo/media
```

### 8. Définir la configuration manuellement

Une installation air-gapped n'utilise pas le premier démarrage interactif ; il faut donc définir les valeurs qui seraient sinon générées automatiquement. Utilisez les clés notées à l'étape 4 :

```bash
dojo-compose-cli environment add --key "DD_CREDENTIAL_AES_256_KEY" --value "<64-character-key-from-step-4>"
dojo-compose-cli environment add --key "DD_SECRET_KEY" --value "<64-character-key-from-step-4>"
```

Définissez la version pour qu'elle corresponde aux artefacts transférés :

```bash
dojo-compose-cli config set --version x.y.z
dojo-compose-cli config set --deploy-version x.y.z
```

Définissez l'URL du site et les hôtes autorisés. L'URL du site doit être l'adresse qui pointe vers cet hôte au sein de votre réseau :

```bash
dojo-compose-cli environment add --key "DD_SITE_URL" --value "https://defectdojo.internal.example.com"
dojo-compose-cli environment add --key "DD_ALLOWED_HOSTS" --value "*"
```

Définissez la connexion à la base de données, en utilisant le serveur PostgreSQL provisionné précédemment :

```bash
dojo-compose-cli environment add --key "DD_DATABASE_URL" --value "postgres://<db_user>:<db_password>@<db_host>:5432/<db_name>"
```

### 9. Charger les images de conteneurs

Ce script charge chaque fichier image du répertoire d'images :

```bash
#!/bin/bash
set -u

IMPORT_DIR="./defectdojo-pro-images"

if [ ! -d "$IMPORT_DIR" ]; then
    echo "Directory '$IMPORT_DIR' not found."
    exit 1
fi

files=$(ls "$IMPORT_DIR"/*.tar.gz 2>/dev/null)

if [ -z "$files" ]; then
    echo "No .tar.gz files found in $IMPORT_DIR."
    exit 1
fi

for file in $files; do
    echo "Loading $(basename "$file")"
    if docker load -i "$file"; then
        echo "  ok"
    else
        echo "  failed"
    fi
done
```

Exécutez-le depuis le répertoire d'artefacts extrait :

```bash
chmod u+x load-images.bash
./load-images.bash
```

Vérifiez ensuite avec `docker image ls` que toutes les images ont été chargées, dans la version attendue.

### 10. Démarrer la pile

Démarrez la pile avec la CLI. Cela fonctionne en mode air-gapped, car la commande lit la configuration définie et pilote le fichier compose local sans contacter le registre :

```bash
dojo-compose-cli app start
```

`app stop` et `app restart` sont disponibles de la même façon. Utilisez `app restart` après avoir modifié une valeur d'environnement, car cette commande recrée les conteneurs afin que les nouvelles valeurs soient prises en compte.

Deux points à vérifier si la pile ne démarre pas. La commande a besoin du répertoire de déploiement en place : vérifiez que `/opt/dojo/docker-compose.yml` existe bien, comme mis en place à l'étape 7. Et la version configurée détermine les tags d'images utilisés : elle doit donc correspondre aux images chargées à l'étape 9.

DefectDojo est alors accessible à l'adresse définie comme URL du site.

## Mettre à niveau un déploiement air-gapped

`app upgrade` télécharge depuis le registre de conteneurs : c'est donc l'une des commandes que le mode air-gapped refuse. Les mises à niveau suivent le même parcours que l'installation plutôt que d'être pilotées par une seule commande.

Sur l'hôte de préparation, définissez la nouvelle version et répétez les étapes 3 à 5 pour celle-ci. Transférez la nouvelle archive, chargez les nouvelles images, puis, sur l'hôte isolé, définissez la nouvelle version et redémarrez :

```bash
dojo-compose-cli config set --version x.y.z
dojo-compose-cli config set --deploy-version x.y.z
dojo-compose-cli app restart
```

Deux pièges fréquents. Redémarrer sans modifier la version configurée relance la pile avec les images déjà présentes, car c'est la version qui détermine les tags d'images. Et l'ensemble des images peut changer d'une version à l'autre : comparez donc ce que vous avez chargé avec ce que le téléchargement de la nouvelle version a produit, plutôt que de supposer que la liste précédente reste valable.

Votre répertoire de déploiement existant ne récupère pas de lui-même le fichier compose ni la configuration nginx de la nouvelle version : restaurez donc le nouveau contenu de `/opt/dojo` comme à l'étape 7, en conservant vos propres personnalisations, certificats et fichiers media.

Sauvegardez votre base de données avant toute mise à niveau, et consultez les [notes de mise à niveau](/releases/os_upgrading/upgrading_guide/) pour chaque version entre votre version actuelle et votre version cible. Si vous avez plusieurs versions de retard, contactez le support avant de commencer.

## Fonctionnalités nécessitant un accès sortant

Un déploiement air-gapped fonctionne sans aucune connectivité sortante, mais les fonctionnalités qui contactent des services externes ne peuvent pas fonctionner tant qu'il reste déconnecté. C'est le cas des connecteurs et intégrateurs qui récupèrent des données depuis des outils hébergés dans le cloud, des intégrations avec des outils de suivi des tickets comme Jira, des notifications sortantes vers des services comme Slack et Microsoft Teams, ainsi que des données d'enrichissement de vulnérabilités normalement récupérées selon une planification.

Ces fonctionnalités se configurent par déploiement plutôt que d'être activées par défaut : une installation air-gapped n'est donc pas compromise par leur absence. Si vous en activez une, attendez-vous à des erreurs de résolution de nom ou de connexion tant que le déploiement n'a pas de route vers ce service. Si le chemin sortant existe mais passe par un proxy, consultez [Exécuter DefectDojo derrière un proxy HTTPS sortant](/onprem_deployment/forward_proxy/).

### Données EPSS et KEV depuis un miroir interne

L'enrichissement EPSS et KEV est une exception qui mérite d'être mise en place, car elle ne nécessite pas de route vers l'Internet public. Les deux se configurent dans le Tuner, sous Enrichissement des constatations, et chacun dispose de son propre interrupteur d'activation et de sa propre URL de recherche. Les champs d'URL pointent par défaut vers les sources publiques, et vous pouvez les rediriger vers une copie hébergée au sein de votre propre réseau.

Le miroir doit servir les mêmes fichiers, dans le même format, que les sources publiques. Les recherches récupèrent un fichier précis à l'URL indiquée, plutôt que de découvrir ce qui s'y trouve : un miroir qui reconditionne ou réorganise les données ne fonctionnera donc pas. Actualisez vos copies selon le calendrier qui vous convient, car le déploiement ne lit que ce que votre miroir sert.

## Questions ou assistance

Pour toute aide concernant une installation ou une mise à niveau air-gapped, contactez votre représentant commercial ou [support@defectdojo.com](mailto:support@defectdojo.com).
