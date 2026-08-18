---
title: Ajout de stockage pour les fichiers téléversés
description: Augmenter l'espace de stockage disponible pour les fichiers téléversés
  sur un déploiement Docker Compose sans modifier le déploiement lui-même
draft: false
weight: 11
audience: pro
---

Les fichiers téléversés résident dans le répertoire media sur l'hôte, et sur un déploiement Docker Compose, l'espace disponible pour eux correspond à ce qu'il reste sur le disque de la VM. Des téléversements volumineux comme des SBOM peuvent remplir ce disque. Cette page explique comment augmenter cet espace sans modifier le déploiement lui-même.

## Pourquoi cela fonctionne au niveau du système d'exploitation

Le déploiement Docker Compose monte en bind mount le répertoire media de l'hôte dans les conteneurs qui en ont besoin, à la fois les conteneurs applicatifs et le nginx qui sert les fichiers téléversés aux utilisateurs. Les conteneurs lisent et écrivent sur un chemin de l'hôte, donc quel que soit le système de fichiers monté à cet endroit, c'est celui-ci qu'ils utilisent. Monter davantage de capacité à cet endroit est transparent pour l'application.

C'est pourquoi l'approche décrite ici est un changement au niveau du système d'exploitation plutôt qu'un changement de déploiement. Conserver le fichier Compose fourni avec votre version sans le modifier permet de garder votre installation cohérente avec les autres déploiements sur site, et évite de perdre le changement lorsqu'une mise à niveau remplace ce fichier.

## Le stockage bloc, l'option la plus simple

Monter un périphérique bloc supplémentaire est la méthode habituelle pour gérer un disque plein sous Linux, et c'est l'option à privilégier en premier lieu. Un volume NAS ou SAN fonctionne, tout comme le stockage bloc d'un fournisseur cloud tel qu'un volume Amazon EBS.

Séparer le stockage applicatif du disque du système d'exploitation est en général une bonne pratique, vous avez donc deux choix raisonnables. Montez le périphérique au niveau du répertoire media pour donner aux téléversements leur propre capacité, ou montez-le un niveau au-dessus, au niveau du répertoire de déploiement, afin que toutes les données applicatives se trouvent sur un système de fichiers distinct de la VM.

## Le stockage objet, avec quelques réserves

Adosser les téléversements à un stockage objet tel qu'Amazon S3 est envisageable et supprime entièrement le plafond de capacité, mais cela s'y prête moins naturellement qu'un périphérique bloc. Voici les points à considérer avant de faire ce choix.

Le stockage objet n'est pas un système de fichiers. S3 ne prend en charge ni les écritures aléatoires, ni l'ajout à un fichier existant, ni le verrouillage de fichiers. Une couche FUSE masque ces lacunes, mais elle ne fait qu'émuler une sémantique que le stockage sous-jacent n'a pas.

La latence est plus élevée qu'avec un périphérique bloc. Cela affecte les téléversements, et comme nginx sert les fichiers téléversés depuis le même répertoire, cela affecte aussi les téléchargements.

Cela ajoute des dépendances réseau. Selon la position de la VM dans votre réseau, atteindre le bucket peut nécessiter une traversée réseau supplémentaire, et ce chemin doit désormais être disponible pour que les téléversements fonctionnent.

Les redémarrages demandent de la prudence. Le bucket doit être monté au démarrage, ce qui introduit une relation temporelle entre la fin du montage et le démarrage de DefectDojo. Selon la latence, cela peut provoquer un redémarrage bloqué ou un démarrage alors que le montage n'est pas encore prêt.

Les permissions doivent être cohérentes entre elles. Les permissions IAM du bucket doivent concorder avec les permissions du système de fichiers dont l'application a besoin pour écrire les téléversements.

### Outils pour monter le stockage objet

Trois outils sont couramment utilisés pour monter S3 comme système de fichiers sous Linux.

`rclone mount` est stable, activement maintenu, et propose des modes de cache de système de fichiers virtuel qui gèrent bien la mise en tampon des lectures et écritures. Des trois, c'est celui que nous recommanderions si vous optez pour cette voie.

`goofys` est optimisé pour la vitesse. Il y parvient en effectuant les créations de fichiers et les écritures de manière asynchrone et en ignorant les opérations que S3 ne prend pas nativement en charge, comme les écritures aléatoires et le verrouillage de fichiers.

`s3fs-fuse` est le plus compatible POSIX des trois, prenant en charge des opérations comme le changement de propriétaire et de permissions, mais le fait d'imiter un véritable système de fichiers le rend nettement plus lent que goofys.

## Déplacer le répertoire media vers un nouveau système de fichiers

Cela nécessite une interruption de service, car l'application ne doit pas écrire de téléversements pendant qu'ils sont copiés.

1. Arrêtez DefectDojo avec `dojo-compose-cli app stop`, pour que rien ne change sous vos pieds pendant le déplacement.
2. Renommez le répertoire media existant pour le conserver comme point de retour en arrière, par exemple en déplaçant `media` vers `old-media` dans votre répertoire de déploiement.
3. Créez un répertoire vide à l'emplacement d'origine du répertoire media pour servir de point de montage.
4. Attachez le nouveau système de fichiers. Les détails dépendent de ce que vous avez choisi ci-dessus, mais cela se résume à trois choses : rendre le stockage disponible pour Linux, ce qui pour le stockage objet signifie créer le bucket et ses permissions ; le monter à l'emplacement du répertoire media ; et faire en sorte que le montage survive à un redémarrage, généralement via une entrée `/etc/fstab` ou l'équivalent pour votre outil.
5. Copiez l'ancien contenu, en conservant le propriétaire et les permissions. `rsync -Pav` de l'ancien répertoire vers le nouveau fait cela et indique la progression, ce qui est utile lorsqu'il y a beaucoup à déplacer.
6. Vérifiez que les fichiers sont bien arrivés. Pour le stockage objet, consulter le bucket dans la console de votre fournisseur est le moyen le plus rapide de vous assurer que le montage écrit bien à l'endroit prévu.
7. Démarrez DefectDojo avec `dojo-compose-cli app start` et téléversez un fichier de test. Si le téléversement échoue, les logs du conteneur en indiqueront la raison, les permissions étant la cause la plus fréquente.

Conservez l'ancien répertoire jusqu'à ce que le téléversement de test réussisse et que vous ayez confirmé que les fichiers migrés depuis celui-ci sont lisibles dans l'interface. C'est votre solution de repli si le nouveau système de fichiers ne se comporte pas comme prévu.

## Périmètre du support

Il s'agit de recommandations générales. Ajouter du stockage à une VM est une tâche relevant du système d'exploitation, et les spécificités de la méthode choisie, en particulier un stockage objet monté via FUSE, sortent du périmètre du support sur site. L'approche est délibérément conçue pour garder votre déploiement cohérent avec toute autre installation sur site, en laissant inchangé le fichier Compose que nous fournissons et en résolvant le problème de capacité au niveau du système d'exploitation, là où il doit l'être.

Si vous évaluez les options pour votre environnement, contactez [support@defectdojo.com](mailto:support@defectdojo.com) et nous pourrons discuter des compromis avant que vous ne vous engagiez sur l'une d'elles.
