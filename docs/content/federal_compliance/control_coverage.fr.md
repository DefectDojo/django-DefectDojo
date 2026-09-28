---
title: Couverture des contrôles
description: Quels contrôles 800-53 vos scanners testent, et les faiblesses ouvertes
  par contrôle
weight: 6
audience: pro
---

La vue de couverture des contrôles répond à une question simple : quels contrôles 800-53 mes scanners
testent-ils réellement, et où se trouvent les faiblesses ouvertes par contrôle ?

![The control coverage heatmap](images/07-control-coverage.png)

## D'où viennent les mappings

De nombreux scanners émettent déjà des références de contrôle, et DefectDojo les extrait automatiquement en
mappings de contrôle. Entre autres :

* **Prowler** écrit des listes de contrôles NIST 800-53 dans les références des constatations.
* Les plugins **Tenable** portent des références croisées 800-53.
* Les profils **InSpec** et **MITRE SAF** étiquettent leurs contrôles avec des identifiants `nist`.

L'extraction s'appuie sur le catalogue importé, si bien qu'un identifiant que le catalogue ne reconnaît pas ne
produit jamais de mapping.

Les constatations qui ne portent pas leurs propres références de contrôle sont attribuées aux contrôles de scan
par défaut définis sur le Compliance Profile — voir [Profil de conformité](../compliance_profile).

### Rattraper les constatations existantes

L'extraction s'exécute à l'arrivée des constatations. Pour mapper des constatations déjà importées avant
l'activation de la fonctionnalité, effectuez un rattrapage :

```
manage.py extract_control_mappings --product <id>
```

Utilisez `--all` pour parcourir toutes les constatations actives au lieu d'un seul produit. La commande indique
combien de mappings elle a créés, et laisse intacts les mappings manuels et supprimés.

## Corriger un mapping

Les mappings que vous créez ou corrigez manuellement l'emportent toujours sur les mappings extraits, et un
mapping que vous supprimez reste supprimé — les réimports ne le feront pas réapparaître.

## Ce que la vue affiche

* Une **carte de chaleur par famille de contrôles**.
* Par contrôle, les **constatations ouvertes qui y sont mappées**.

Les contrôles proviennent des catalogues fournis : NIST 800-53 Rev 5 et NIST 800-171 Rev 2, tous deux importés
au démarrage.

**La couverture est indicative tant que la fonctionnalité est en bêta.** La couverture des contrôles reflète ce
que rapportent vos scanners et ce que reconnaissent les catalogues fournis. Ce n'est pas une attestation qu'un
contrôle est implémenté ou efficace. Vérifiez la couverture par rapport à votre System Security Plan avant de
vous y fier pour une évaluation.

## Traçabilité

Les mappings de contrôle sont sous historique d'audit. Chaque modification enregistre qui, quoi, et quand.
