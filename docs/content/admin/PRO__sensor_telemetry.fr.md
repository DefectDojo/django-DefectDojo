---
title: "Partage de la télémétrie des capteurs"
description: "Choisir de partager avec DefectDojo des événements anonymisés de détection des capteurs, et voir ce que vos capteurs ont apporté"
weight: 11
audience: pro
draft: false
---

> **Pas encore disponible :** le partage de la télémétrie des capteurs ne peut pas encore être activé, ni sur DefectDojo Cloud ni sur une instance auto-hébergée, quelle que soit sa configuration. Cette page décrit son fonctionnement une fois qu'il sera publié.

Le partage de la télémétrie des capteurs permet à une instance d'envoyer des **événements de détection des capteurs** anonymisés au service de renseignement sur les menaces de DefectDojo. Une détection est un déclenchement unique d'un capteur sur vos hôtes, rattaché à un CVE. Les détections partagées indiquent au service de renseignement quelles vulnérabilités sont exploitées en conditions réelles, et cette preuve parvient à chaque instance par le flux de renseignement sur les menaces.

Le partage est une fonctionnalité **DefectDojo Pro**. Il est **désactivé par défaut**, et rien n'est envoyé tant qu'un superutilisateur ne l'a pas activé.

## Ce qui est partagé, et ce qui ne l'est pas

Chaque événement contient quatre valeurs et rien d'autre :

| Champ | Description |
| --- | --- |
| CVE | Le CVE dont est étiquetée la règle de détection qui a correspondu |
| Heure | L'heure à laquelle la détection a été vue, en UTC. Les minutes et les secondes ne sont pas envoyées |
| Source | Au plus le pays et le réseau (ASN) d'où provenait la détection. Souvent vide |
| ID de contributeur | Un identifiant aléatoire qui change chaque mois civil |

Un événement ne contient jamais de charge utile ni de corps de requête, de nom d'hôte, d'adresse IP, de nom d'utilisateur, de ligne de commande, de nom d'actif, de nom d'entreprise, de nom ou d'identifiant de la règle de détection, ni le nom ou l'URL de votre instance. La source n'est renseignée que si votre instance est configurée pour la rechercher, et seulement pour une adresse publique. DefectDojo détermine alors le pays et le réseau sur votre instance et y supprime l'adresse, avant tout envoi.

Les identifiants de règles sont volontairement omis : une règle que vous avez écrite vous-même peut porter n'importe quel nom, y compris celui de votre entreprise, d'un hôte ou d'une personne.

Les événements sont livrés à DefectDojo avec la clé de licence de votre instance, qui permet au service de renseignement de les accepter. La clé accompagne la livraison, elle ne figure pas dans les événements.

L'ID de contributeur permet au service de renseignement de compter combien d'instances différentes ont vu un CVE au cours d'un mois. Il est tiré au hasard, remplacé chaque mois par un nouveau, et l'ancien ne peut pas être déduit du nouveau.

Seules les détections postérieures à l'activation du partage et datant des dernières 24 heures sont envoyées. Désactiver le partage supprime tous les événements encore en attente d'envoi et abandonne l'ID de contributeur ; un changement de la clause contractuelle a le même effet. Réactiver le partage commence avec un nouvel ID de contributeur.

## Avant de pouvoir l'activer

Le partage est couvert par une clause de votre contrat DefectDojo. La carte indique la **version de la clause contractuelle** que vous acceptez en activant le partage, et le partage ne peut pas être activé tant que cette version n'est pas disponible sur votre instance.

La clause contractuelle sera publiée avant que le partage ne devienne disponible.

Si DefectDojo publie ultérieurement une nouvelle version de la clause, le partage se met en pause de lui-même. La carte l'indique, les événements en attente sous l'ancienne version sont supprimés, et rien n'est envoyé tant qu'un superutilisateur n'a pas réactivé le partage sous la nouvelle version. Pendant la pause, la case est d'abord décochée : la nouvelle version n'est donc acceptée qu'en la cochant à nouveau. Le partage repart alors de zéro, avec un nouvel ID de contributeur.

Le partage n'est jamais disponible sur une instance air-gapped, sur la démo publique ni dans le sandbox.

## Activer ou désactiver le partage

1. Connectez-vous en tant que superutilisateur et ouvrez **Settings > System Settings**.
2. Faites défiler jusqu'à la carte **Sensor Telemetry**, en bas de la page.
3. Lisez ce qui est partagé et la version de la clause contractuelle indiquée par la carte. Lorsque votre instance connaît l'adresse de la clause, la carte y renvoie à côté de la version (**Read the contract term**).
4. Cochez **Share Sensor Hit Events**, puis sélectionnez **Submit**. Pour arrêter, décochez la case et sélectionnez **Submit**.

Chaque modification est enregistrée dans le journal d'audit avec l'utilisateur qui l'a effectuée.

## Ce qu'affiche la carte

* **Sharing** : Off, On, Paused (la clause contractuelle a changé), On, Not Sending (aucun point de terminaison de renseignement ou aucune clé de licence n'est configuré ; la carte précise lequel) ou Not Available.
* **Events Shared**, **Events Waiting** et **Events Dropped** : combien d'événements ont été livrés, sont en file d'attente ou ont été abandonnés. Un événement qui ne peut pas être livré est réessayé pendant une journée au plus, puis abandonné.
* **Last Shared** : la date de la dernière livraison d'événements.
* **La liste des CVE** : les CVE observés par vos capteurs, jusqu'aux 200 vus le plus récemment, avec le nombre de détections, combien ont été partagées, et la date à laquelle chacun a été vu pour la première et la dernière fois. Le titre de la carte indique combien de CVE ont été observés au total. Cette liste est conservée sur votre instance, que le partage soit activé ou non.
* **Seen Elsewhere** : si d'autres instances qui partagent ont vu le même CVE. Cette colonne n'est renseignée que lorsque le partage est activé et que le service de renseignement répond, et seulement pour les CVE que votre instance a déjà partagés : la question nomme le CVE, donc un CVE vu uniquement avant l'activation du partage n'est jamais demandé. Sinon, la ligne sous le tableau explique pourquoi elle est vide, par exemple qu'aucun point de terminaison de renseignement ou aucune clé de licence n'est configuré sur l'instance.

La carte apparaît dès que votre instance a des capteurs, a observé un CVE ou a été configurée pour le partage.

## Configuration auto-hébergée

Sur une instance auto-hébergée, l'opérateur définit ces variables d'environnement. Toutes sont vides par défaut, et vide signifie désactivé.

| Variable | Rôle |
| --- | --- |
| `DD_SENSOR_TELEMETRY_CONTRACT_TERM_VERSION` | La version de la clause contractuelle. Sans elle, le partage ne peut pas être activé |
| `DD_SENSOR_TELEMETRY_CONTRACT_TERM_URL` | Facultatif. L'adresse HTTPS où la clause contractuelle peut être lue. La carte y renvoie à côté de la version |
| `DD_SENSOR_TELEMETRY_ENDPOINT` | L'URL de base HTTPS du service de renseignement. Sans elle, aucun appel réseau n'est jamais effectué |
| `DD_THREAT_INTEL_LICENSE_KEY` | La clé de licence envoyée avec chaque livraison. Sans elle, aucun appel réseau n'est effectué |
| `DD_SENSOR_TELEMETRY_SOURCE_RESOLVER` | Facultatif. Le chemin Python pointé d'une fonction qui convertit une adresse source publique en pays et en ASN. DefectDojo ne fournit aucune base de données de pays ou d'ASN : sans elle, les événements ne portent aucune source |
