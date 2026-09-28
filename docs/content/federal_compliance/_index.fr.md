---
title: Conformité fédérale
description: Livrables FedRAMP POA&M et ConMon, évaluations CMMC de niveau 2, et couverture
  des contrôles NIST 800-53
summary: ''
draft: false
weight: 6
chapter: true
sidebar:
  collapsed: true
seo:
  title: ''
  description: ''
  canonical: ''
  robots: ''
audience: pro
exclude_search: true
---

DefectDojo Pro peut prendre en charge le volet gestion des vulnérabilités d'un programme de conformité fédérale. Il
tient à jour un Plan of Action and Milestones (POA&M) de style FedRAMP pour chaque système, produit chaque mois
des livrables de Continuous Monitoring (ConMon) dans les formats officiels Excel et OSCAL, note les auto-évaluations CMMC
de niveau 2, et montre quels contrôles NIST 800-53 vos scanners exercent réellement.

Tout ce qui est décrit dans cette section se trouve dans l'onglet **Compliance** d'un Asset.

## Activer la fonctionnalité

La conformité fédérale est proposée derrière le feature flag **Compliance**, qui est en bêta et désactivé par
défaut. Un administrateur l'active depuis le menu des feature flags — voir
[Feature Flags](/admin/feature_flags/pro__feature_flags/). Une fois activé, un onglet Compliance
apparaît sur chaque Asset.

## Bêta : confirmez les résultats avant de vous y fier

**Cette fonctionnalité est en bêta.** Les énoncés de contrôle NIST 800-171 et 800-53 fournis, les pondérations de
points DoD SPRS, et les règles d'éligibilité au POA&M sont fournis pour vous aider à suivre et estimer votre
posture, et sont en attente de validation indépendante par rapport aux documents sources faisant autorité.

Les scores SPRS, les résultats d'éligibilité conditionnelle, et la couverture des contrôles sont **indicatifs**. Vérifiez-les
par rapport à la méthodologie d'évaluation officielle DoD NIST SP 800-171 et aux directives FedRAMP en vigueur
avant de vous y fier pour une certification, une soumission d'évaluation, ou toute autre finalité
contractuelle.

## Dans cette section

| Page | What it covers |
| --- | --- |
| [Profil de conformité](compliance_profile) | Inscrire un Asset en tant que système et définir les informations qui apparaissent sur chaque livrable |
| [Le registre POA&M](poam_ledger) | Comment les éléments du POA&M sont créés à partir des constatations, et les conventions suivies par le registre |
| [Instantanés ConMon](conmon_snapshots) | Livrables mensuels en FedRAMP Excel et OSCAL, et le service de validation OSCAL optionnel |
| [Délais de remédiation](remediation_slas) | Les préréglages de SLA FedRAMP Rev 5 et FedRAMP VDR |
| [Évaluations CMMC de niveau 2](cmmc_assessments) | Noter une auto-évaluation par rapport à NIST 800-171 Rev 2 |
| [Couverture des contrôles](control_coverage) | Quels contrôles 800-53 vos scanners testent, et les faiblesses ouvertes par contrôle |
