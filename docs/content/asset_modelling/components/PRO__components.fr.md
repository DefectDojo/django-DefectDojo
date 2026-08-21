---
title: Composants
description: Suivi des bibliothèques tierces et des composants logiciels dans DefectDojo
  Pro
audience: pro
weight: 1
---

Dans DefectDojo, les Composants représentent des bibliothèques tierces, des composants logiciels et des modules susceptibles de comporter des vulnérabilités.


## Vues des composants

DefectDojo Pro inclut une vue tableau dédiée aux Composants, accessible depuis la barre latérale.  Cette vue affiche les Constatations actives, les Constatations en doublon et le Total des constatations pour chaque Composant.  Ces chiffres incluent tous les Actifs de l'instance DefectDojo.

Les Composants d'un Actif donné peuvent être consultés sur la vue de cet Actif.

## Le tableau des composants

Le tableau des composants affiche les colonnes suivantes :

* **Composant** — le nom du composant, renseigné à partir des données du scan.
* **Version** — la version du composant, renseignée à partir des données du scan.
* **Constatations actives** — nombre de Constatations actives associées au composant.
* **Constatations en doublon** — nombre de Constatations en doublon associées au composant.
* **Total des constatations** — nombre total de toutes les Constatations associées au composant.

Cliquer sur le nom du composant ou sur les valeurs des Constatations actives, des Constatations en doublon ou du Total des constatations ouvre une liste filtrée des Constatations pour le champ correspondant.

Un composant **None** est affiché dans le tableau ; il regroupe toutes les Constatations qui ne sont associées à aucun composant.

Les composants importés restent dans le tableau même si toutes leurs Constatations associées sont Atténuées. Lorsque des Constatations sont importées pour un composant spécifique, le tableau des composants est mis à jour pour refléter précisément les nouveaux totaux de constatations.


### Exemple

Un composant importé à partir d'un scan Dependency-Check portant sur une application avec une dépendance `lodash` vulnérable pourrait apparaître dans le tableau comme suit :

| Composant | Version | Constatations actives | Constatations en doublon | Total des constatations |
| --- | --- | --- | --- | --- |
| npm:lodash | 4.17.15 | 3 | 1 | 5 |

Cliquer sur `npm:lodash` ouvre la liste de toutes les Constatations référençant ce composant. Cliquer sur `3` ouvre la même liste filtrée aux seules Constatations actives.

## Ajout de composants

Les composants peuvent être extraits d'une importation de scan ou ajoutés en modifiant manuellement une Constatation. Une fois qu'un nom de composant est associé à une Constatation, une entrée correspondante est automatiquement ajoutée au tableau des composants. Si le composant est déjà associé à d'autres Constatations dans DefectDojo, les totaux des Constatations actives, des Constatations en doublon et du Total des constatations sont mis à jour en conséquence.

### Comment les composants sont extraits des données de scan

Lors de l'importation d'un scan, les parseurs renseignent les champs **Nom du composant** et **Version du composant** de chaque Constatation à partir de la sortie du scan. Le tableau des composants est ensuite construit à partir de ces valeurs. Le niveau de détail et la convention de nommage dépendent de l'outil ayant produit le scan :

* Les **outils d'analyse de composition logicielle (SCA)** rapportent généralement un nom de package et une version exacte. Par exemple, OWASP Dependency-Check dérive le composant à partir du [Package URL](https://github.com/package-url/purl-spec) dans son identifiant — un purl `pkg:npm/lodash@4.17.15` devient `Component Name: npm:lodash`, `Component Version: 4.17.15`.
* Les **scanners de conteneurs et de packages OS** tels que Trivy, Anchore Grype et Anchore Engine rapportent le package OS ou langage affecté — par exemple, `Component Name: curl`, `Component Version: 7.68.0`.
* Les **scanners de dépendances spécifiques à un langage** tels que npm Audit, pip-audit, bundler-audit, Retire.js, Govulncheck et OSV-Scanner renseignent le package fautif et sa version à partir des manifestes de leur écosystème respectif.

Les scanners axés sur la configuration, l'infrastructure ou la logique du code source (comme les outils SAST et IaC) ne renseignent généralement pas les champs de composant, et leurs Constatations apparaissent sous le composant **None**.

Pour ajouter ou modifier un composant manuellement, modifiez la Constatation et définissez directement les champs **Nom du composant** et **Version du composant**. Le tableau des composants se met à jour dès que la Constatation est enregistrée.

## Mise à jour des composants

Pour mettre à jour un nom ou une version de composant, toutes les Constatations associées au composant doivent avoir leur champ Nom du composant ou Version du composant mis à jour.

## Suppression des composants

Pour supprimer un composant du tableau des composants, toutes les Constatations associées au composant doivent être mises à jour afin de retirer leurs champs Nom du composant et Version du composant. Les composants sont également supprimés si toutes leurs Constatations associées sont supprimées.

Si toutes les Constatations d'un composant sont Atténuées, le composant reste dans le tableau, mais sa valeur de Constatations actives est fixée à 0.
