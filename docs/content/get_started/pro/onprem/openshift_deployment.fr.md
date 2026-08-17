---
title: Déployer DefectDojo Pro sur OpenShift
description: 'Ce qui est spécifique à OpenShift lors du déploiement de DefectDojo
  Pro autohébergé : security context constraints, Routes et stockage ReadWriteMany'
draft: false
weight: 8
audience: pro
---

DefectDojo Pro fonctionne sur OpenShift 4.x, y compris OpenShift Container Platform, ROSA et OKD.

Cette page complète le guide d'installation fourni avec votre licence DefectDojo Pro. Ce guide contient la procédure complète, y compris une section dédiée à OpenShift. Cette page couvre ce qui est spécifique à OpenShift, afin que vous sachiez ce qu'il faut préparer avant de commencer et à quoi vous attendre concernant les paramètres propres à la plateforme.

Un script de bootstrap OpenShift est fourni avec les éléments de votre licence. Il s'installe sur un cluster existant et prend en charge la plupart des éléments décrits sur cette page, notamment le stockage, la valeur `fsGroup`, la Route et l'installation elle-même. Il est idempotent, donc le réexécuter réutilise ce qu'il a déjà créé, et il prend en charge un mode d'essai à blanc qui affiche ce qu'il ferait sans rien modifier. Le reste de cette page s'applique que vous utilisiez ce script ou que vous réalisiez l'installation vous-même.

## Security context constraints

DefectDojo Pro s'exécute sous la SCC par défaut `restricted-v2`. Vous n'avez pas besoin d'accorder `anyuid`, `privileged`, ou toute autre SCC élevée au compte de service.

Lorsqu'il est configuré pour OpenShift, DefectDojo Pro s'exécute intégralement avec des security contexts non privilégiés. Les conteneurs s'exécutent sans privilège, ne peuvent pas élever leurs privilèges, et abandonnent toutes les capacités (capabilities). L'ID utilisateur est laissé à OpenShift, qui l'attribue depuis la plage allouée à votre namespace, plutôt que d'être fixé à un UID figé que la SCC rejetterait.

Si des pods sont rejetés pour échec de validation SCC, la cause habituelle est que le déploiement n'a pas été configuré pour OpenShift, et non qu'une contrainte doit être accordée.

## Le stockage doit être en ReadWriteMany

Les pods Django et Celery worker lisent et écrivent les mêmes fichiers multimédias, à savoir les scans téléversés, les captures d'écran et les rapports générés. Ils ont besoin d'un volume partagé, donc un stockage ReadWriteOnce n'est pas suffisant pour un déploiement multi-nœuds.

Sur OpenShift, le comportement par défaut est un PersistentVolumeClaim reposant sur la StorageClass par défaut du cluster. Cela fonctionne lorsque la classe par défaut provisionne du ReadWriteMany, ce qui est typique sur les clusters reposant sur OpenShift Data Foundation ou NFS. Pour les déploiements multi-nœuds où la classe par défaut est en ReadWriteOnce, configurez plutôt un stockage reposant sur NFS.

### fsGroup sur un stockage reposant sur NFS

OpenShift restreint `fsGroup` à la plage allouée au namespace. Lorsque vous utilisez un stockage NFS ou EFS, vous devez fournir une valeur issue de cette plage, sinon le montage du volume échoue avec une erreur de permissions.

Lisez le début de la plage depuis l'annotation du namespace et utilisez-la comme `fsGroup` :

```bash
oc get namespace <namespace> \
  -o jsonpath='{.metadata.annotations.openshift\.io/sa\.scc\.supplemental-groups}'
```

L'annotation contient une plage exprimée sous la forme d'une valeur de départ et d'une longueur. Utilisez la valeur de départ. Cela n'est nécessaire que pour le stockage NFS et EFS, pas pour le chemin PersistentVolumeClaim par défaut.

## Routes, TLS et cookies

Sur OpenShift, DefectDojo Pro est exposé via une Route plutôt qu'un Ingress, avec une terminaison TLS en périphérie (edge) et une redirection depuis HTTP.

Sur ROSA, les noms d'hôte des Routes sont générés sous la forme `<release-name>-<namespace>.apps.<cluster-domain>`, de sorte qu'une release `dojopro` dans le namespace `dojopro` obtient `dojopro-dojopro.apps.<cluster-domain>`. Récupérez le domaine apps du cluster avec :

```bash
oc get ingresses.config.openshift.io cluster -o jsonpath='{.spec.domain}'
```

Un nom d'hôte sous le domaine apps du cluster est couvert par le certificat wildcard par défaut et ne nécessite aucune configuration de certificat. Pour tout autre nom d'hôte, fournissez votre propre certificat et ajoutez un CNAME vers le nom d'hôte de la Route.

Définissez `dojo.secureCookies` sur `false` sur OpenShift. Avec une Route à terminaison TLS en périphérie, le TLS s'arrête au niveau du routeur et la connexion entre le routeur et le pod est en HTTP simple, donc les cookies marqués secure ne sont jamais renvoyés et la connexion échoue. Ce réglage est obligatoire, et non optionnel, dès lors que la Route termine le TLS en périphérie.

## Profils de ressources

Trois profils de ressources sont disponibles et vous en sélectionnez un au moment de l'installation. `minimal` est destiné au développement, à la CI et aux tests. `standard` est destiné à la production sous charge modérée. `performance` est destiné à la production à forte charge et active l'autoscaling.

Définissez votre dimensionnement via le profil plutôt qu'en remplaçant des valeurs individuelles, afin que votre propre fichier de configuration n'entre pas en conflit avec lui.

## Avant de commencer

Un cluster OpenShift 4.x sur lequel vous êtes connecté, avec `oc`, `helm`, `openssl` et `jq` disponibles localement.

Un namespace, et la valeur de son annotation supplemental-groups si vous utilisez un stockage NFS ou EFS.

Une StorageClass par défaut qui provisionne du ReadWriteMany, ou les informations d'un serveur NFS.

PostgreSQL 16 pour tout usage au-delà de l'évaluation. Un PostgreSQL embarqué est disponible pour le développement, mais passez à une base de données managée externe avant de passer en production.

Votre fichier de licence DefectDojo Pro.

Le nom d'hôte de Route que vous prévoyez d'utiliser.

## Accès réseau sortant

Dans un cluster soumis à des restrictions de sortie (egress), autorisez le trafic HTTPS sortant sur le port 443 vers le registre de conteneurs qui héberge les images DefectDojo Pro. Le nom d'hôte du registre figure dans le guide d'installation fourni avec votre licence. Les points de terminaison du registre se trouvent derrière des load balancers et leurs adresses changent, autorisez donc le nom d'hôte plutôt qu'une adresse fixe.

Le cluster doit également pouvoir atteindre votre base de données sur le port PostgreSQL.

L'enrichissement d'exploitabilité est optionnel et nécessite deux destinations supplémentaires en HTTPS sur le port 443. Les scores EPSS proviennent de `api.first.org`, et les données CISA KEV proviennent de `www.cisa.gov`. Les deux sont servis depuis des réseaux de diffusion de contenu dont les adresses changent, autorisez donc les noms d'hôte. Sans cela, DefectDojo fonctionne normalement et les constatations ne sont pas enrichies avec les données EPSS ou KEV.

Lorsque le trafic sortant passe par un proxy plutôt qu'en direct, consultez [Exécuter DefectDojo derrière un proxy HTTPS sortant](/onprem_deployment/forward_proxy/).

## Le job d'initialisation doit se terminer en premier

L'installation exécute un job Kubernetes qui applique les migrations, crée l'utilisateur admin et charge les données initiales. Cela prend environ quinze minutes. Tant qu'il n'est pas terminé, l'utilisateur admin n'existe pas et vous ne pouvez pas vous connecter, même si la Route répond déjà.

Surveillez-le :

```bash
oc get job -n <namespace>
oc logs -f -n <namespace> -l app.kubernetes.io/component=initializer
```

Le job est terminé lorsque `oc get job` indique `1/1` completions.

Les autres pods attendent l'initialiseur via un init container. Une fois la base de données initialisée, vous pouvez définir `dojo.skipInitContainer` sur `true` pour ignorer cette attente lors des mises à niveau suivantes.

## Vérification

```bash
oc get pods -n <namespace>
oc get route -n <namespace>
oc describe route -n <namespace>
```

Ouvrez ensuite le nom d'hôte de la Route et connectez-vous.

## Dépannage

### Pods rejetés par les security context constraints

Le déploiement n'a très probablement pas été configuré pour OpenShift, il est donc retombé sur des valeurs par défaut qui fixent un ID utilisateur que la SCC n'autorisera pas. Accorder `anyuid` ou `privileged` n'est pas la solution et n'est pas nécessaire.

### La connexion redirige vers la page de connexion

`dojo.secureCookies` est à `true` derrière une Route à terminaison TLS en périphérie. Définissez-le sur `false` et effectuez la mise à niveau.

### Erreurs de permissions lors du montage de volume sur NFS

Le `fsGroup` est en dehors de la plage autorisée pour le namespace. Lisez l'annotation supplemental-groups et utilisez le début de la plage.

### Erreurs Multi-Attach, ou pods bloqués en ContainerCreating

Le volume est en ReadWriteOnce et plusieurs pods tentent de le monter. Vérifiez la claim et la classe qui la sous-tend :

```bash
oc get pvc -n <namespace>
oc describe pod <pod-name> -n <namespace> | tail -30
```

Passez à une classe ReadWriteMany, ou à un stockage reposant sur NFS.

### Avertissements de certificat dans le navigateur

Le TLS par défaut de la Route utilise le certificat wildcard du cluster, qui ne couvre que les noms sous le domaine apps du cluster. Pour tout autre nom d'hôte, fournissez votre propre certificat.

### Lecture des logs

```bash
oc logs -n <namespace> -l app.kubernetes.io/component=django -c uwsgi --tail=50
oc logs -n <namespace> -l app.kubernetes.io/component=celery-worker --tail=50
```

Pour une sortie plus détaillée, `config.logLevel` et `celery.logLevel` acceptent tous deux `DEBUG`.

## Mise à niveau

Les mises à niveau suivent la procédure standard. Consultez [Mise à niveau de DefectDojo Pro (sur site)](/get_started/pro/onprem/upgrading/).

## Questions ou assistance

Pour obtenir de l'aide concernant un déploiement OpenShift, contactez votre représentant de compte ou [support@defectdojo.com](mailto:support@defectdojo.com).
