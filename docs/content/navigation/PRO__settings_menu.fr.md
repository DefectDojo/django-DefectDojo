---
title: Le menu Settings
description: Comment la section Settings de la barre latérale de DefectDojo Pro est
  organisée, la page d'annuaire All Settings, et comment basculer entre la disposition
  actuelle et la précédente
weight: 6
audience: pro
---

La section Settings de la barre latérale regroupe toutes les pages d'administration de DefectDojo Pro. La disposition que vous voyez dépend de la date de création de votre instance :

- Les **nouvelles installations** s'ouvrent sur la disposition réorganisée décrite ci-dessous.
- Les **installations existantes** conservent la disposition précédente jusqu'à ce qu'un administrateur active **Menu 2.0** (voir [Changer de disposition](#switching-layouts)).

Dans tous les cas, **chaque page de settings conserve la même URL**. Les favoris, liens enregistrés et tout élément de vos propres runbooks continuent de fonctionner, quelle que soit la disposition active.

## La disposition réorganisée

Settings est divisé en sept groupes, nommés d'après ce que vous cherchez à faire plutôt que d'après la partie du système concernée.

| Groupe | Ce qu'il contient |
| --- | --- |
| **System** | System Settings, Appearance, Announcement Banner, Login Banner, Email, Feature Flags |
| **Users & Permissions** | Users, Groups, Roles |
| **Finding Workflow** | Les trois pages Deduplication, Finding Enrichment, Service Level Agreements, Prioritization Engines, Mitigation Policies |
| **Configuration** | Environments, Regulations, Note Types, Test Types, CI/CD Infrastructure, Tool Types, Tool Configurations |
| **Notifications** | Notification Events, Notification Webhooks |
| **Operations** | Audit Logs, Usage Logs, Schedules, Celery Status, et — sur DefectDojo Cloud — Message Portal, Firewall Rules, Maintenance Windows |
| **License & Support** | License Manager, Version Manager, Contact Support |

Vous ne voyez que les entrées que votre compte est autorisé à ouvrir, et un groupe disparaît entièrement lorsqu'aucune de ses pages ne vous est accessible.

Deux conventions sont à connaître :

- **Il n'existe pas d'entrées « New » séparées.** Chaque page de liste possède un bouton **New** qui ouvre le formulaire de création, de sorte que le menu ne comporte qu'une seule entrée par catalogue au lieu de deux. Si votre compte peut créer un enregistrement mais pas les lister, l'entrée de menu vous amène directement au formulaire de création.
- **Rien ne s'imbrique à plus d'un niveau sous un groupe.** Atteindre une page nécessite au maximum Settings → groupe → page.

## All Settings

La première entrée de la section, **All Settings**, ouvre un annuaire de toutes les pages de settings accessibles à votre compte, organisées selon les mêmes groupes que le menu et consultable par nom ou par fonction de la page. Rechercher `deduplication` trouve les trois pages de déduplication *et* System Settings, car System Settings contient également des options de déduplication.

La dernière catégorie, **Elsewhere in the app**, répertorie les pages qui configurent DefectDojo mais se trouvent dans d'autres sections de la barre latérale — les fournisseurs d'autorisation, les paramètres Login et MFA, les instances Jira, les connecteurs Upstream et Downstream, et l'Universal Parser. Chaque vignette est étiquetée avec la section à laquelle elle appartient.

## Ce qui a changé de place

Si vous êtes habitué à la disposition précédente :

| Auparavant | Maintenant |
| --- | --- |
| Settings → *(niveau supérieur)* → Feature Flags | Settings → System → Feature Flags |
| Settings → Pro Settings → System Settings | Settings → System → System Settings |
| Settings → Pro Settings → Appearance | Settings → System → Appearance |
| Settings → Pro Settings → Banner Settings → Announcement Banner Settings | Settings → System → Announcement Banner |
| Settings → Pro Settings → Banner Settings → Login Banner Settings | Settings → System → Login Banner |
| Settings → Pro Settings → Email Settings | Settings → System → Email |
| Settings → Users → All Users / New User | Settings → Users & Permissions → Users |
| Settings → Users → All Groups / New Group | Settings → Users & Permissions → Groups |
| Settings → Users → Roles | Settings → Users & Permissions → Roles |
| Settings → Pro Settings → Deduplication Settings → *(three pages)* | Settings → Finding Workflow → Same Tool / Cross Tool / Reimport Deduplication |
| Settings → Pro Settings → Finding Enrichment Settings | Settings → Finding Workflow → Finding Enrichment |
| Settings → Configuration → Service Level Agreements | Settings → Finding Workflow → Service Level Agreements |
| Settings → Configuration → Prioritization Engines | Settings → Finding Workflow → Prioritization Engines |
| Settings → Configuration → Mitigation Policies | Settings → Finding Workflow → Mitigation Policies |
| Settings → Configuration → *(reference-data catalogs)* | Settings → Configuration → *(unchanged)* |
| Settings → Pro Settings → Notification Settings | Settings → Notifications |
| Settings → Configuration → Audit Logs | Settings → Operations → Audit Logs |
| Settings → Configuration → Usage log | Settings → Operations → Usage Logs |
| Settings → Configuration → All Schedules | Settings → Operations → Schedules |
| Settings → Pro Settings → Celery Status | Settings → Operations → Celery Status |
| Settings → Cloud Manager → *(cloud pages)* | Settings → Operations |
| Settings → License Manager / Version Manager / Contact Support | Settings → License & Support |

Le groupe qui portait le nom de votre offre de licence — **Pro Settings** sur une instance Pro, **Enterprise Settings** sur une instance Enterprise — n'existe plus. Ses pages sont réparties entre System, Finding Workflow, Notifications et Operations.

## Changer de disposition

**Menu 2.0**, sur la page [Feature Flags](/admin/feature_flags/pro__feature_flags/), contrôle quelle disposition est active. L'activer ou le désactiver remodèle immédiatement la barre latérale ; aucun redémarrage n'est nécessaire et rien d'autre ne change sur votre instance.

Les nouvelles installations démarrent avec cette option activée. Les installations existantes démarrent avec cette option désactivée, de sorte qu'une mise à niveau ne réorganise jamais le menu sous une équipe en plein travail — activez-la lorsque vos administrateurs sont prêts.

Tant qu'elle est désactivée, la page **All Settings** est indisponible et son URL renvoie Not Found.
