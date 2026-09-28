---
title: Adresses IP de sortie
description: Les adresses IP sortantes depuis lesquelles DefectDojo Cloud se connecte,
  à autoriser dans vos pare-feu externes.
weight: 5
audience: pro
---

Lorsque DefectDojo Cloud communique avec vos systèmes — les Connecteurs qui synchronisent l'API d'un scanner,
qui poussent des tickets vers Jira ou ServiceNow, qui envoient des webhooks de notification, ou qui
délivrent des e-mails via SMTP — ces connexions sont **initiées en sortie** depuis votre environnement
DefectDojo. Si le système à l'autre bout se trouve derrière un pare-feu, vous devrez autoriser les
adresses IP sortantes (egress) de DefectDojo pour que ces connexions ne soient pas bloquées.

Cette page indique où trouver ces adresses IP de sortie.

## Sortie (egress) et entrée (ingress)

Il s'agit de deux choses différentes, et cette page ne couvre que la première :

- **Sortie / egress (cette page)** — les adresses IP source depuis lesquelles DefectDojo Cloud se
  connecte **en sortant** vers *vos* systèmes externes. Autorisez-les dans **vos** pare-feu afin que
  DefectDojo puisse atteindre les systèmes avec lesquels il s'intègre.
- **Entrée / ingress** — les règles qui contrôlent qui est autorisé à atteindre **votre** instance
  DefectDojo. Elles sont gérées sous forme de règles de pare-feu dans le Cloud Manager, pas ici.
  Consultez [Dépannage de la connectivité](../connectivity-troubleshooting/) et l'étape des règles de
  pare-feu dans [Configurer une instance Cloud supplémentaire](../additional-cloud-instance/).

## Déploiements multi-tenant

Les instances Standard, Pay-as-you-go et Premium s'exécutent sur des clusters Google Kubernetes
Engine (GKE) régionaux partagés. Les connexions sortantes proviennent des adresses IP externes des
nœuds de la région où s'exécute votre instance.

L'ensemble actuel des IP de sortie des nœuds est publié sous forme de flux JSON, regroupé par région :

<https://storage.googleapis.com/defectdojo-node-ips/node_ips.json>

Le flux se présente ainsi :

```json
{
  "description": "External IPs for DefectDojo Cloud GKE nodes, grouped by region",
  "generated_at": "2026-08-06T20:17:26.372476+00:00",
  "regions": {
    "us-east4": [
      "34.21.115.236/32",
      "34.48.120.182/32"
    ],
    "europe-west3": [
      "34.40.61.46/32",
      "34.89.189.26/32"
    ]
  }
}
```

Pour autoriser le trafic sortant de DefectDojo :

1. Identifiez la région où s'exécute votre instance (le Server Location que vous avez sélectionné
   lors du provisionnement de l'instance).
2. Autorisez chaque adresse IP listée sous cette région. Chaque entrée est un CIDR `/32`
   (hôte unique).

**Cette liste évolue dans le temps.** Des nœuds sont ajoutés et remplacés au fur et à mesure que la
plateforme s'autoscale, si bien que l'ensemble des IP de sortie d'une région n'est pas figé. Traitez
le flux JSON comme source de vérité plutôt que de copier les adresses une seule fois :

- Récupérez le flux de façon programmatique et actualisez votre liste d'autorisation de pare-feu à
  partir de celui-ci selon un calendrier régulier, ou
- Revérifiez le flux et réconciliez vos règles périodiquement.

Si votre pare-feu ne peut pas suivre une liste changeante et que vous avez besoin d'un petit
ensemble stable d'adresses, parlez-en à votre représentant DefectDojo au sujet d'une instance
**Dedicated** (voir ci-dessous).

## Déploiements mono-tenant (Dedicated)

Une instance de niveau **Dedicated** s'exécute dans son propre projet GCP et son propre VPC, et son
adresse IP de sortie est **stable** — elle est attribuée lors du provisionnement de l'instance et ne
change pas à mesure que la plateforme évolue.

Comme elle est liée à votre instance spécifique, l'IP de sortie stable n'est pas publiée dans le flux
public. Contactez [support@defectdojo.com](mailto:support@defectdojo.com) pour obtenir la ou les
adresses IP de sortie attribuées à votre instance Dedicated, et autorisez-les dans vos pare-feu
externes.

*Une question à laquelle cette page ne répond pas ? Contactez votre représentant DefectDojo.*
