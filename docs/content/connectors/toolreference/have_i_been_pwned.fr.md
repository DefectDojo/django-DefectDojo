---
title: "Have I Been Pwned"
description: "Comment configurer le Connecteur Upstream Have I Been Pwned pour DefectDojo"
weight: 72
audience: pro
---
Le connecteur Have I Been Pwned (HIBP) utilise l'API REST HIBP pour signaler quels comptes des domaines de votre propre organisation sont apparus dans des fuites de données connues. DefectDojo découvre chaque domaine que vous avez vérifié auprès de HIBP et importe une constatation par fuite affectant ce domaine.

#### Prérequis

Vous aurez besoin d'une clé API Have I Been Pwned avec recherche par domaine, ce qui nécessite un abonnement de niveau **Core** ou supérieur. Vous pouvez obtenir une clé depuis votre [compte Have I Been Pwned](https://haveibeenpwned.com/API/Key).

Vous devez également **vérifier au moins un domaine** sur votre compte HIBP avant que des données de fuite soient disponibles. HIBP permet de vérifier un domaine par enregistrement DNS TXT, balise meta, téléversement de fichier ou e-mail, sous **Domain search** dans votre compte. Tant qu'aucun domaine n'est vérifié, le connecteur ne découvre aucun domaine et n'importe aucune constatation.

#### Mappages du connecteur

1. Saisissez `https://haveibeenpwned.com` dans le champ **Location**.
2. Saisissez votre clé API dans le champ **Secret**.
3. Vous pouvez éventuellement définir une **Sévérité minimale** pour limiter les constatations importées. Les constatations en dessous de la sévérité sélectionnée ne seront pas importées.

DefectDojo crée un Enregistrement distinct pour chaque domaine que vous avez vérifié auprès de HIBP, et importe une constatation par fuite affectant les comptes de ce domaine. La sévérité de chaque constatation reflète le type de données exposées par la fuite, et sa description répertorie les comptes affectés sur votre domaine afin que votre équipe puisse agir.

Consultez la [documentation de l'API Have I Been Pwned](https://haveibeenpwned.com/API/v3) pour plus d'informations.
