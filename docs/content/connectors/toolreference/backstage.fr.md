---
title: "Backstage"
description: "Comment configurer le Connecteur Upstream Backstage pour DefectDojo"
weight: 22
audience: pro
---
Le connecteur Backstage est un **connecteur d'actifs** : au lieu d'importer des constatations, il récupère votre Software Catalog [Backstage](https://backstage.io) dans DefectDojo et maintient votre hiérarchie de Produits et la propriété des équipes synchronisées avec celui-ci. Il est conçu pour les organisations qui maintiennent leur inventaire de services et leur structure organisationnelle dans Backstage et souhaitent que DefectDojo reflète cette structure au lieu de la maintenir manuellement.

#### Ce qui est mappé

| Backstage | DefectDojo |
|---|---|
| **System** | Type de produit (les Components sans System sont regroupés sous un Type de produit configurable « Backstage / Uncategorized ») |
| **Component** | Produit — nommé à partir du `title` de l'entité (avec repli sur `name`), avec la description du catalogue |
| **Owning Group** (relation `ownedBy`) | Un Groupe DefectDojo lié au Produit (rôle par défaut : Maintainer, configurable) |
| **Owner email** (e-mail du profil du Groupe, ou e-mail d'un propriétaire Utilisateur) | Un Membre de produit, lorsqu'un utilisateur DefectDojo possédant cet e-mail existe déjà (aucun utilisateur n'est jamais créé) |
| `metadata.tags`, `spec.type`, `spec.lifecycle`, namespace, domain | Étiquettes de produit sous un préfixe `backstage:` |
| `metadata.annotations` | Stocké sur l'Enregistrement (avec une limite) ; certaines annotations peuvent être promues en attributs de premier niveau ou en étiquettes via **Annotation Mappings** |

Les Enregistrements sont indexés par le `metadata.uid` attribué par le serveur de l'entité ; ainsi, les renommages effectués dans Backstage mettent à jour le Produit mappé **sur place** lors de la prochaine synchronisation — sans doublons. Le nom du Produit suit toujours le catalogue : pour renommer un Produit géré par ce connecteur, renommez le Component dans Backstage (un renommage effectué côté DefectDojo, ou un nom personnalisé attribué lors du mappage manuel, est réconcilié avec le nom du catalogue lors de la prochaine synchronisation, sauf s'il entre en collision avec un autre Produit). Les changements de propriété déplacent l'affectation de groupe du Produit. Les Components qui disparaissent du catalogue (ou qui sont signalés par l'annotation `backstage.io/orphan`) sont marqués **MISSING** — DefectDojo ne supprime jamais un Produit de lui-même. La hiérarchie de Domain et de Group (équipes parentes) est uniquement enregistrée sous forme d'étiquettes/métadonnées ; elle ne crée pas de niveaux de hiérarchie supplémentaires.

#### Prérequis

Le connecteur s'authentifie à l'aide d'un **jeton d'accès externe statique** auprès du backend Backstage. Dans la configuration de votre application Backstage, définissez un jeton et (recommandé) restreignez-le au plugin catalog :

```yaml
backend:
  auth:
    externalAccess:
      - type: static
        options:
          token: ${DEFECTDOJO_BACKSTAGE_TOKEN}
          subject: defectdojo-connector
        accessRestrictions:
          - plugin: catalog
```

Générez un jeton aléatoire fort (par exemple `openssl rand -hex 32`) et stockez-le dans l'environnement de votre déploiement Backstage. Consultez la [documentation Backstage sur l'authentification de service à service](https://backstage.io/docs/auth/service-to-service-auth) pour plus de détails.

#### Mappages du Connecteur

1. Saisissez l'**URL racine du backend Backstage** dans le champ **Location** : par exemple `https://backstage.example.com` (le connecteur ajoute `/api/catalog`). Il doit s'agir de l'URL du **backend**, et non de l'interface web frontend.
2. Saisissez le jeton d'accès externe statique dans le champ **Secret**.

Champs facultatifs (laissez vide pour les valeurs par défaut) :

* **Namespaces** — espaces de noms du catalogue à importer, séparés par des virgules ; vide importe tous les espaces de noms.
* **Component Types** — valeurs `spec.type` séparées par des virgules (par ex. `service,website`) ; vide importe tous les types.
* **Page Size** — taille de page pour les requêtes du catalogue (1\-500, valeur par défaut 250).
* **TLS Verification** — à définir sur `false` uniquement si Backstage sert un certificat que DefectDojo ne peut pas vérifier (AC interne) ; non recommandé.
* **Uncategorized Product Type** — le Type de produit utilisé pour les Components sans System (par défaut `Backstage / Uncategorized`).
* **Owner Group Role** — le rôle accordé à l'équipe propriétaire sur les Produits mappés (par défaut `Maintainer`).
* **Annotation Mappings** — un objet JSON associant des clés d'annotation à des noms d'attributs d'Enregistrement, ou à `"tag"` pour importer une annotation en tant qu'étiquette de Produit, par ex. `{"github.com/project-slug": "GITHUB_PROJECT", "example.com/tier": "tag"}`.

Lorsque **Auto\-Map** est activé, un seul cycle Discover \+ Sync construit l'intégralité de la structure Type de produit / Produit / propriété sans étape manuelle. Lorsque Auto\-Map est désactivé, les Components découverts apparaissent comme des Enregistrements en attente de votre décision de mappage.

#### Limitations (v1)

* **L'appartenance aux Groups Backstage n'est pas synchronisée** : le connecteur crée/associe l'équipe propriétaire en tant que Groupe DefectDojo, mais le peuplement des utilisateurs de ce groupe est laissé à votre fournisseur d'identité ou à vos administrateurs.
* Seuls les Components deviennent des Produits ; les API, Resources et Domains ne sont pas importés comme actifs (les domains apparaissent sous forme d'étiquettes).
* Les étiquettes et annotations sont normalisées et limitées pour respecter les contraintes de longueur des champs DefectDojo (les valeurs trop longues sont tronquées).

**Remarque sur le sens inverse :** afficher les constatations et les notes DefectDojo *à l'intérieur* de Backstage (sur les pages d'entité) constituerait un prolongement naturel, qui serait développé sous la forme d'un plugin frontend Backstage consommant l'API REST de DefectDojo — cela sort délibérément du périmètre de ce connecteur, qui se contente d'importer les données du catalogue dans DefectDojo.
