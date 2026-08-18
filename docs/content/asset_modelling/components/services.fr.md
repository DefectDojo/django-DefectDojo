---
title: Services
description: Suivi des microservices
weight: 1
---

## Qu'est-ce qu'un Service ?

Les Services (abréviation de microservices) sont une fonctionnalité optionnelle au sein des Actifs qui apporte un contexte supplémentaire sur l'origine des Constatations au sein d'un Actif. Ils permettent d'isoler les Constatations à un composant particulier d'un Actif, plutôt qu'à l'Actif entier, offrant clarté et précision de reporting dans les environnements aux architectures complexes.

Les Services sont utiles lorsque vous devez segmenter davantage les résultats issus d'un Test, ou si vous prévoyez d'avoir plusieurs instances de la même Constatation au sein d'un pipeline de réimportation que vous ne souhaitez pas dédupliquer. Certains outils de scan peuvent créer des Constatations distinctes pour chaque emplacement de fichier, et si vous préférez conserver ces instances d'une Constatation comme des Constatations séparées, les services peuvent être un bon moyen d'étiqueter ces différents emplacements.

## Les Services dans Pro

Les Services sont disponibles dans la version Pro, mais sont largement remplacés par la possibilité d'établir des relations parent-enfant entre les Actifs. Les Services obtiennent le même résultat et peuvent encore être utiles lorsque la restructuration des Actifs n'est pas envisageable ou lorsqu'un périmètre de déduplication au niveau du scan est nécessaire sans modifier la hiérarchie des Actifs, mais ils suppriment le contexte. Par exemple, la criticité métier, le revenu et le personnel peuvent être attribués aux Actifs mais pas aux Services. Ainsi, les Services sont principalement utiles dans le contexte de DefectDojo Open Source.

## Comment spécifier un Service ?

L'option permettant de spécifier un Service est disponible sur les formulaires d'importation ou de réimportation de scan, dans le menu déroulant des champs optionnels. Par la suite, la déduplication est limitée aux Tests partageant la même valeur de Service.

Il est important de noter que les Services sont sensibles à la casse. Si le Service de l'importation initiale a été identifié comme « Service 1 » (S majuscule) et que vous réimportez un scan ayant résolu tous les problèmes précédents mais identifiez le Service comme « service 1 » (s minuscule), la déduplication ne s'appliquera pas au Service visé.

## Comment fonctionnent les Services ?

Les Services fonctionnent en vous permettant de spécifier à quels Tests antérieurs les règles de déduplication s'appliqueront lors de la réimportation.

Si, par exemple, vous importez un premier scan et définissez le Service comme « Service 1 », puis réimportez un second scan en définissant le Service comme « Service 2 », la déduplication ne s'appliquera pas entre ces deux scans car le Service est différent.

Toute réimportation ultérieure ne dédupliquera les résultats antérieurs du premier scan que si le Service a été défini comme « Service 1 », et ne dédupliquera les résultats antérieurs du second scan que si le Service a été défini comme « Service 2 ». Autrement dit, si le Service diffère entre deux versions d'un scan réimporté, elles seront traitées comme des Constatations différentes, même si les scans eux-mêmes sont identiques.

Dans cet exemple, si, lors de la réimportation, le Service n'est défini ni comme Service 1 ni comme Service 2, et est au contraire laissé vide, la déduplication ne s'appliquera ni au premier ni au second scan, et seules les Constatations sans Service seront clôturées.

## Comment les Services doivent-ils être utilisés ?

En pratique, les Services sont surtout utiles lorsque :

* Un seul Actif contient plusieurs composants déployés indépendamment.
* Différentes équipes possèdent différentes parties d'un même Actif.
* Les tests de sécurité sont effectués sur des services individuels (par exemple, l'analyse d'une API ou d'un microservice spécifique).
