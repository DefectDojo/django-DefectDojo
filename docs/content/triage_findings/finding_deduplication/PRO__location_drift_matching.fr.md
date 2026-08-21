---
title: Correspondance de dérive d'emplacement
description: 'Suivez les constatations à mesure que leur emplacement change lors des
  réimportations : les changements de ligne, les renommages de fichiers, les déplacements
  d''URL et les mises à jour de version de dépendance ne ferment et ne recréent plus
  les constatations'
weight: 6
audience: pro
---

**Correspondance de dérive d'emplacement** permet à la réimportation de reconnaître une constatation dont l'*emplacement* a changé comme étant la **même constatation**. Sans cette fonctionnalité, la réimportation associe les constatations via un hachage d'identité exact qui inclut les champs d'emplacement — chaque déplacement d'emplacement ferme donc l'ancienne constatation et en crée une nouvelle identique :

- Un commit déplace le code et le **numéro de ligne** de la constatation change.
- Un refactoring **renomme ou déplace le fichier**.
- L'**URL, le port ou l'hôte** d'une application web change entre deux analyses DAST.
- Une **mise à jour de version** d'une dépendance change la version du paquet vulnérable signalée par un outil SCA.

Chacun de ces cas produisait auparavant une constatation fermée plus une « nouvelle » constatation — perdant le statut, les notes, le chronomètre SLA, l'acceptation du risque et le lien JIRA de l'originale, et générant de faux signaux de « nouvelle constatation critique ». Avec la Correspondance de dérive d'emplacement activée, une seule constatation est maintenue en place : son emplacement est mis à jour à partir de la dernière analyse et son historique est préservé.

> La Correspondance de dérive d'emplacement est une fonctionnalité de DefectDojo Pro. Elle est **désactivée par défaut** et s'active par outil de sécurité.

## Activer le suivi d'emplacement

Le suivi d'emplacement se configure par outil, dans :
**Paramètres > Flux de travail des constatations > Déduplication à la réimportation** (**Paramètres > Paramètres Pro > Paramètres de déduplication > Déduplication à la réimportation** sur les instances utilisant encore l'ancienne disposition des menus)

1. Sélectionnez l'**Outil de sécurité**.
2. Définissez l'**Algorithme de déduplication** sur **Hash Code**. Le suivi d'emplacement ne s'applique qu'à l'algorithme Hash Code — les outils disposant d'un **Unique ID From Tool** fiable suivent déjà les déplacements via leurs identifiants stables et n'en ont pas besoin.
3. Activez **Suivre les constatations à mesure que leurs emplacements changent**.

L'enregistrement du paramètre déclenche automatiquement un nouveau hachage en arrière-plan des constatations existantes de l'outil (voir [Activer sur des données existantes](#enabling-on-existing-data-upgrades) ci-dessous), de sorte que les constatations importées avant l'activation participent immédiatement.

## Fonctionnement de la correspondance

Lorsque le suivi est activé, la correspondance à la réimportation se déroule en deux étapes :

1. **Identité stable.** Le hachage de réimportation est calculé *sans* les champs d'emplacement volatils (ligne, chemin du fichier, description, nom/version du composant, points de terminaison) — l'identité d'une constatation capture ainsi *ce qu'elle est*, et non *où elle se trouve actuellement*. Les constatations qui n'ont pas bougé correspondent toujours exactement, en premier, et ne sont jamais perturbées.
2. **Appariement par preuves.** Au sein de chaque groupe de constatations partageant une identité stable, un outil d'appariement d'emplacement associe les constatations entrantes aux constatations existantes à l'aide de preuves d'emplacement, selon des passes déterministes de la plus forte à la plus faible. Une constatation est acheminée vers exactement un outil d'appariement selon les données d'emplacement qu'elle porte.

### Constatations de code (SAST)

| Pass | Pairs when | Notes |
|------|-----------|-------|
| Exacte | Même fichier et même ligne | Gagne toujours ; un voisin déplacé ne peut jamais « voler » la correspondance d'une constatation non déplacée |
| Flux de données | Mêmes objets source/puits (`sast_source_object` / `sast_sink_object`) | Pour les outils qui rapportent le flux de données ; insensible à la renumérotation des lignes |
| Ligne la plus proche | Même fichier, numéro de ligne le plus proche | Gloutonne, du plus proche au plus loin ; même fichier uniquement |
| Renommage de fichier | Fichier différent | Uniquement lorsqu'il ne reste exactement **qu'une** constatation entrante et **qu'une** constatation existante — l'ambiguïté échoue de façon sécurisée |

### Constatations d'URL (DAST)

| Pass | Pairs when |
|------|-----------|
| Exacte | Ensemble de points de terminaison identique |
| Dérive de l'ensemble de points de terminaison | Ensembles de points de terminaison qui se chevauchent (points de terminaison ajoutés/supprimés) |
| Déplacement de port | Même hôte et même chemin, port différent |
| Dérive de chemin | Même hôte, chemin similaire (similarité de segment mutuellement optimale) |
| Déplacement d'hôte | Hôte différent — uniquement en tant qu'appariement 1×1 non ambigu, avec une protection contre les DNS génériques (wildcard) |

### Constatations de dépendances (SCA)

| Pass | Pairs when |
|------|-----------|
| Exacte | Même paquet, même version et même manifeste |
| Mise à jour de version | Même paquet, version différente |
| Déplacement de manifeste | Même paquet, chemin de fichier de verrouillage/manifeste différent |

Lorsque le même paquet vulnérable apparaît dans **plusieurs manifestes**, la constatation de chaque manifeste est suivie indépendamment — une mise à jour de version dans un fichier de verrouillage n'absorbe jamais la constatation d'un autre.

### Réévaluations de la sévérité

Les outils de sécurité réévaluent la sévérité à mesure que leurs moteurs de règles évoluent. Avec le suivi activé, un changement de sévérité signalé par l'outil ne **divise pas** l'identité d'une constatation : la constatation correspond toujours, et sa sévérité est mise à jour à partir de l'analyse — sauf si une personne a retrié la sévérité manuellement, auquel cas la valeur humaine l'emporte toujours (voir ci-dessous).

## Ce qui est préservé, ce qui est actualisé

Une constatation appariée par dérive conserve tout ce qui compte pour son cycle de vie : statut, notes, acceptation du risque, dates de SLA, lien JIRA et son identifiant de constatation.

Ses **champs d'emplacement** (chemin du fichier, ligne, champs de flux de données, points de terminaison, version du composant) sont actualisés à partir de l'analyse entrante.

Ses **champs descriptifs** (titre, description, sévérité, version du composant) ne sont actualisés à partir de l'analyse que *lorsque l'analyse en reste propriétaire* : DefectDojo enregistre une empreinte (digest) de chaque champ tel qu'écrit pour la dernière fois par l'import ou la réimportation. Si la valeur actuelle correspond toujours à cette empreinte, c'est l'outil qui l'a écrite et l'analyse peut la mettre à jour ; si une personne a modifié le champ depuis, la valeur humaine est préservée définitivement. Les constatations créées avant cette fonctionnalité n'ont pas d'empreinte et sont considérées comme appartenant à un humain — la réimportation n'écrasera jamais leurs champs descriptifs. La seule exception est la **version du composant**, qui est une donnée télémétrique d'analyse que les personnes ne modifient pratiquement jamais à la main : elle est actualisée même sans empreinte, de sorte que les constatations SCA migrées reçoivent quand même les mises à jour de version.

### L'identité suit toujours le rapport de l'outil

Lorsqu'une constatation appariée est actualisée, ses hachages d'identité stockés sont **adoptés à partir des valeurs de l'analyse entrante** — jamais recalculés à partir des champs actuels de la constatation. Cette distinction est importante : après une actualisation, les champs de la constatation sont une *fusion* des valeurs de l'analyse et des modifications humaines, et un hachage calculé à partir de cette fusion contiendrait des valeurs qu'aucune analyse ne rapportera plus jamais, ce qui romprait silencieusement toutes les futures réimportations de cette constatation. L'adoption garantit qu'une personne qui renomme une constatation, retrie sa sévérité ou modifie sa description ne peut jamais compromettre sa capacité à correspondre à la prochaine analyse.

## Historique d'emplacement

Sous **Locations** (Bêta), chaque correspondance de dérive enregistre l'ancien emplacement de la constatation : l'emplacement de code source, l'URL ou la version de dépendance remplacés sont conservés comme référence sur la constatation, horodatés avec l'endroit où elle a déplacé et pourquoi. La chronologie d'emplacement de la constatation — « cette constatation se trouvait à `auth.py:42`, puis à `auth.py:57`, puis à `session.py:31` » — est visible sur la page de la constatation. Voir [Source Code Locations](/asset_modelling/locations/pro__source_code_locations/).

La Correspondance de dérive d'emplacement elle-même fonctionne **avec ou sans** la fonctionnalité Locations : la correspondance s'appuie sur les propres champs et points de terminaison de la constatation, de sorte que les constatations survivent au déplacement dans les deux cas. Locations ajoute par-dessus un historique enregistré et visible. L'enregistrement de l'historique commence à partir du moment où Locations est activée — les déplacements antérieurs ont été appliqués mais non enregistrés.

## Activer sur des données existantes (mises à niveau)

Cette fonctionnalité est conçue pour s'auto-migrer :

- **Rien ne change tant que vous n'activez pas l'option.** Lorsque le bouton est désactivé, les hachages de réimportation se calculent exactement comme avant.
- **L'enregistrement de l'activation recalcule le hachage des constatations existantes.** La tâche en arrière-plan recalcule les hachages de réimportation stockés de l'outil avec la nouvelle identité (sans emplacement), et crée les éventuels enregistrements de constatation Pro manquants pour les données migrées depuis l'open source. Une fois terminée, les anciennes et les nouvelles constatations parlent le même langage d'identité — une constatation importée il y a des mois est suivie exactement comme une constatation importée hier.
- **Activez entre deux analyses sur les instances volumineuses.** Le recalcul du hachage est une tâche en arrière-plan portant sur l'ensemble des constatations de l'outil. Une réimportation qui survient pendant que cette tâche est en cours peut voir un mélange d'anciens et de nouveaux hachages et perturber une fois la tranche non encore traitée. Activez l'option à un moment calme et laissez la tâche se terminer avant la prochaine réimportation planifiée.
- **Titres modifiés manuellement.** Le recalcul de hachage à l'activation se base sur les valeurs actuelles de la base de données. Chaque champ couramment modifié est exclu de l'identité suivie — les modifications de sévérité sont d'ailleurs *corrigées* par le recalcul — mais si une personne a renommé le **titre** d'une constatation (et que le titre est un champ de hachage pour cet outil), cette constatation sera perturbée une fois lors de sa prochaine réimportation avant de se stabiliser.

## Choisir les champs de hachage pour les outils suivis

Le suivi d'emplacement retire automatiquement les champs d'emplacement volatils du hachage de réimportation — vous n'avez pas besoin de retirer vous-même `line` ou `file_path` de la configuration de hachage d'un outil. Deux configurations méritent votre attention :

- **Configurations entièrement volatiles.** Si les champs de hachage d'un outil sont *entièrement* des champs d'emplacement (par exemple seulement `file_path` + `line`), les retirer ne laisse plus rien, et le hachage retombe sur l'ancienne identité titre+CWE. La correspondance fonctionne toujours — les passes de preuves assurent la discrimination — mais l'identité est bien plus grossière. Préférez des configurations qui conservent au moins un champ de contenu stable.
- **Emplacement intégré dans des champs stables.** Les exclusions de champs ne servent à rien lorsque les données d'emplacement se cachent *à l'intérieur* d'un champ qui doit rester dans le hachage. Un outil qui titre ses constatations « SQL Injection in queries.py:42 » change son titre à chaque déplacement de ligne — l'identité se scinde et le suivi ne peut pas voir la paire. Pour de tels outils, choisissez des champs de hachage qui évitent le champ fuyant ; **CWE + Content Fingerprint** est la combinaison la plus solide (voir [Content Fingerprint](/triage_findings/finding_deduplication/pro__deduplication_tuning/#content-fingerprint)).

## Interaction avec la déduplication

Le suivi d'emplacement est une fonctionnalité de **réimportation** : la déduplication Same Tool et Cross Tool reste inchangée — leurs hachages se calculent exactement comme avant, et les exclusions ne s'appliquent jamais à elles. Deux intégrations délibérées :

- **Les mises à jour de version ne bloquent plus la déduplication des dépendances.** Le filtre d'emplacement de déduplication exige normalement que deux constatations SCA référencent une version de paquet *identique*. Pour les outils avec suivi activé, une identité de paquet partagée (écosystème + nom du paquet, l'espace de noms étant comparé lorsque les deux côtés en portent un) suffit — cohérent avec le fait que la réimportation traite une mise à jour de version comme la même constatation. Ceci ne s'applique qu'à la déduplication Same Tool sous Locations.
- **Entrées d'identité propres.** Comme les constatations appariées adoptent les hachages rapportés par l'analyse, les valeurs consommées par la déduplication reflètent toujours ce que l'outil a rapporté en dernier — les modifications humaines ne peuvent plus les contaminer.

## Consolider les perturbations historiques

Les instances qui ont fonctionné pendant des années sans suivi accumulent des chaînes de fermeture-recréation : la même constatation fermée puis rouverte comme un nouvel enregistrement à chaque déplacement. Une commande de gestion retrouve ces chaînes (reliées maillon par maillon par les mêmes outils d'appariement, avec une protection de chevauchement de durée de vie pour que les constatations ayant réellement coexisté ne soient jamais fusionnées) et consolide chaque chaîne sur sa constatation la plus récente, en marquant les copies plus anciennes comme doublons du survivant :

```bash
# Dry run — reports what would be consolidated, changes nothing
./manage.py consolidate_location_churn --product <id>

# Apply, with a confirmation prompt
./manage.py consolidate_location_churn --product <id> --apply
```

La commande est en mode simulation (dry-run) par défaut, ne s'exécute jamais automatiquement, et peut être limitée avec `--test` ou `--product`. Sous Locations, l'historique d'emplacement du survivant est reconstruit à partir de la chaîne.

## Garde-fous et limites

- **Les correspondances exactes gagnent toujours.** Une constatation non déplacée s'apparie exactement avant l'exécution de toute passe approximative ; les constatations déplacées ne peuvent jamais lui voler sa correspondance.
- **L'ambiguïté échoue de façon sécurisée.** Les renommages de fichiers et les déplacements d'hôte ne s'apparient que lorsqu'il ne reste exactement qu'un candidat de chaque côté. Deux constatations qui ont toutes deux disparu alors que deux nouvelles sont apparues restent non appariées plutôt que de deviner.
- **Les très grands groupes se dégradent avec élégance.** Si un seul groupe d'identité dépasse le plafond d'appariement (40 000 comparaisons), la correspondance se dégrade en mode exact uniquement pour ce groupe, plutôt que de consommer un temps illimité.
- **Compromis accepté :** les passes de renommage/déplacement d'hôte 1×1 peuvent créer une fausse continuité lorsqu'une constatation disparaît et qu'une constatation sans rapport partageant la même identité stable apparaît dans la même réimportation. C'est le prix délibéré du suivi des renommages ; l'identité stable (même outil, titre, CWE, sévérité...) limite l'ampleur de l'erreur d'appariement possible.

## Actualisation d'emplacement sans l'activation

Indépendamment du suivi d'emplacement, la réimportation maintient à jour l'emplacement de chaque constatation appariée sur **tous** les algorithmes : une constatation appariée par Unique ID From Tool (ou tout autre algorithme) actualise ses champs `line`, `file_path`, ses champs de flux de données et `component_version` à partir du rapport entrant, et les points de terminaison rapportés sont rattachés tandis que ceux ayant disparu sont atténués. Les valeurs qu'une analyse omet n'écrasent jamais les données existantes, et une version de composant épinglée manuellement par un humain est préservée. Ceci comble une lacune de longue date où les constatations SAST appariées par uid affichaient éternellement le numéro de ligne de leur premier import. Cette actualisation peut être désactivée pour toute l'instance avec `DD_REIMPORT_REFRESH_LOCATION_FIELDS=False`.
