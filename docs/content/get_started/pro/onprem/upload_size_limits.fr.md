---
title: Limites de taille de téléchargement pour les fichiers de scan volumineux
description: Pourquoi le téléchargement d'un fichier de scan volumineux échoue, et
  quelle limite augmenter dans les déploiements Kubernetes et Docker Compose
draft: false
weight: 10
audience: pro
---

Un fichier de scan volumineux peut être rejeté par plusieurs limites différentes, à différents points du chemin de la requête, et l'erreur que vous obtenez indique laquelle vous avez atteinte. Cette page explique où se trouvent ces limites et comment les augmenter dans un déploiement autohébergé.

## Quelle limite ai-je atteinte

| Ce que vous voyez | D'où cela vient |
| --- | --- |
| Un simple `413 Request Entity Too Large`, sans style, sans page DefectDojo autour | Le contrôleur d'ingress a rejeté la requête avant qu'elle n'atteigne l'application |
| `Report file is too large. Maximum supported size is N MB` | La limite de l'application, signalée par DefectDojo lui-même |
| Le téléchargement s'exécute un moment puis échoue, au lieu d'être refusé immédiatement | Un délai d'expiration (timeout) plutôt qu'une limite de taille |

Procédez de l'extérieur vers l'intérieur. Il ne sert à rien d'augmenter la limite de
l'application si le contrôleur d'ingress refuse déjà la requête en premier.

## La limite de l'application

DefectDojo applique sa propre taille maximale de fichier de scan et rejette tout fichier plus
volumineux avec un message indiquant la limite actuelle. Elle est fixée par défaut à 100 Mo.

Dans le chart Helm, définissez-la dans vos valeurs :

```yaml
dojo:
  scanMaxFileSize: 100
```

Pour les déploiements Docker Compose, définissez plutôt `DD_SCAN_FILE_MAX_SIZE`, en mégaoctets.

## La limite d'ingress

C'est celle qui produit un simple `413` sans style DefectDojo, car la requête n'atteint jamais
l'application.

Le chart définit un plafond de taille de corps de requête sur l'ingress, fixé par défaut à
2400 Mo :

```yaml
django:
  ingress:
    maxBodySize: "2400m"
```

Cette valeur est émise sous forme de l'annotation `nginx.ingress.kubernetes.io/proxy-body-size`.
Elle est émise sur toutes les plateformes plutôt que sur Kubernetes générique uniquement, car le
contrôleur d'ingress nginx est souvent utilisé devant une plateforme managée. La définir avec une
chaîne vide omet l'annotation, et cela nécessite `django.ingress.platformAnnotations.enabled`,
qui est activé par défaut.

Les contrôleurs autres que nginx ignorent cette annotation ; sur ceux-ci, vous augmentez donc la
limite via le propre mécanisme du contrôleur :

| Contrôleur par défaut de la plateforme | Où se trouve la limite |
| --- | --- |
| EKS avec l'AWS Load Balancer Controller | Configuration de l'ALB |
| GKE avec le contrôleur d'ingress GCE | Configuration de l'équilibreur de charge |
| AKS avec Application Gateway | La limite de taille de corps de requête d'Application Gateway |
| OpenShift Route | `tuningOptions` HAProxy sur le routeur |

### Délais d'expiration lorsque nginx est devant une plateforme managée

Le chart émet des délais d'expiration de proxy nginx généreux, 1800 secondes pour la lecture,
l'envoi et la connexion, ainsi qu'une mise en mémoire tampon du proxy désactivée. Ces annotations
ne sont émises que lorsque la plateforme est Kubernetes générique. Sur EKS, GKE, AKS et
OpenShift, le chart émet à la place les propres annotations de cette plateforme, car c'est ce
que lit son contrôleur par défaut.

Cela compte si vous exécutez le contrôleur d'ingress nginx sur l'une de ces plateformes. Vous
obtenez l'annotation de taille de corps, puisqu'elle est émise partout, mais pas les délais
d'expiration. Un téléchargement volumineux peut alors passer le contrôle de taille et être
malgré tout coupé en cours de route par le délai d'expiration par défaut du contrôleur, ce qui
correspond à la troisième ligne du tableau ci-dessus. Indiquez vous-même les délais
d'expiration :

```yaml
django:
  ingress:
    annotations:
      nginx.ingress.kubernetes.io/proxy-read-timeout: "1800"
      nginx.ingress.kubernetes.io/proxy-send-timeout: "1800"
```

## La limite de la route d'import

Les déploiements Kubernetes exécutent les imports de scans via des pods dédiés, et le nginx
placé devant les routes d'import a son propre plafond de taille de corps. Celui-ci est dérivé
plutôt que fixe :

```yaml
django:
  uwsgiImport:
    maxBodySizeMb: null
```

Laissée à `null`, elle est calculée comme `dojo.scanMaxFileSize` plus 5 Mo, la marge couvrant la
surcharge de l'encodage multipart. Augmenter la limite de l'application augmente donc celle-ci
également, et la plupart des déploiements n'ont jamais besoin de la définir. Ne définissez un
entier que si vous souhaitez remplacer la valeur dérivée.

## Déploiements Docker Compose

Les déploiements Compose n'ont pas de contrôleur d'ingress, donc la limite d'ingress ne
s'applique pas. Le nginx fourni dans le déploiement plafonne les corps de requête à 800 Mo, ce
qui constitue le plafond pratique, et la limite de l'application s'applique en plus, comme
partout ailleurs.

Augmenter le plafond nginx implique de modifier un fichier fourni avec le déploiement, et ces
fichiers sont remplacés lors d'une mise à niveau plutôt que préservés comme votre répertoire de
personnalisations. Contactez le support avant de le modifier, afin que la modification ne
disparaisse pas lors de la prochaine mise à niveau.

## Questions ou support

Si les téléchargements échouent toujours après avoir augmenté la limite correspondant à votre
symptôme, collectez la réponse reçue par votre client ainsi que les journaux nginx ou du
contrôleur couvrant la tentative, puis contactez
[support@defectdojo.com](mailto:support@defectdojo.com).
