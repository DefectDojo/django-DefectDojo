---
title: Instantanés ConMon
description: Livrables mensuels en FedRAMP Excel et OSCAL, et le service de validation
  OSCAL optionnel
weight: 3
audience: pro
---

Dans l'onglet **Snapshots**, **Generate Snapshot** produit les livrables pour une période de reporting.
Un instantané **fige le registre** à cet instant précis : les modifications ultérieures ne changent jamais un
livrable déjà généré.

![Generated ConMon snapshots](images/04-poam-snapshots.png)

Chaque ligne affiche la période, son statut, le nombre d'éléments ouverts et en retard, la date d'achèvement, et
des liens de téléchargement pour les deux artefacts.

## Ce qu'un instantané produit

Chaque instantané produit deux artefacts :

* Le classeur Excel officiel **FedRAMP POA&M** (version de modèle 3.0), avec les éléments ouverts, clos, et de
  configuration sur leurs feuilles de calcul respectives.
* Un document **OSCAL plan-of-action-and-milestones**, fixé à OSCAL 1.0.4 — la version que les règles de
  validation actuelles de FedRAMP acceptent.

### Ce que contient la sortie OSCAL

Le document OSCAL utilise l'espace de noms d'extension de FedRAMP pour les champs recherchés par les outils FedRAMP :
les identifiants de POA&M, les identifiants de contrôle impactés, les états de dérogation, la dépendance à un
fournisseur, et le suivi KEV.

Chaque risque comporte :

* Des facettes de probabilité et d'impact — initiales, et ajustées lorsqu'un ajustement de risque a été approuvé.
* La correction recommandée et la remédiation planifiée, sous forme de réponses distinctes.
* Un journal de risque enregistrant la détection et la dernière revue de statut.

Les documents sont vérifiés par rapport au schéma NIST officiel au moment de la génération.

## Métriques mois par mois

Les instantanés calculent également les chiffres dont un dossier ConMon a besoin : ce qui est apparu, ce qui a été
résolu, ce qui est en retard, et le nombre d'éléments ouverts par niveau de risque.

## Service de validation OSCAL

Pour un contrôle plus strict, un déploiement peut exécuter le **service de validation OSCAL** fourni — un petit
conteneur enveloppant l'outil `oscal-cli` maintenu par FedRAMP.

| Validator service | What happens at generation |
| --- | --- |
| Not configured | Les documents sont validés par rapport au schéma JSON du NIST. Le contrôle approfondi est marqué **skipped**. |
| Configured | Les documents sont en plus validés via `oscal-cli`, et les résultats sont stockés avec l'instantané. |

Pour l'activer, définissez `DD_OSCAL_VALIDATOR_URL`, ou activez `oscalValidator` dans le chart Helm.

**Gardez l'URL `import-ssp` accessible.** `oscal-cli` déréférence le href `import-ssp` pendant la
validation. Si votre Compliance Profile désigne une URL SSP OSCAL que le conteneur de validation ne peut pas
atteindre, la validation échoue au lieu de simplement sauter cette étape. Rendez l'URL accessible depuis le
validateur, ou laissez-la non définie.

## Immuabilité

Les instantanés et leurs artefacts sont immuables par conception. Régénérer une période produit un nouvel
instantané ; cela ne réécrit jamais un instantané existant.
