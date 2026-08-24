---
title: "NeuVector"
description: "Comment configurer le Connecteur Upstream NeuVector pour DefectDojo"
weight: 93
audience: pro
---
Le connecteur NeuVector utilise l'API REST du contrôleur [NeuVector](https://github.com/neuvector/neuvector) pour importer les **scans de vulnérabilités d'images** de conteneurs. DefectDojo découvre chaque image scannée par NeuVector et crée un Record pour chacune, puis importe le rapport de scan de cette image sous forme de constatations.

#### Prérequis

Vous aurez besoin d'un **nom d'utilisateur et d'un mot de passe** NeuVector pour un compte du contrôleur disposant de la permission de lire les résultats de scan. Le connecteur se connecte avec ces identifiants pour obtenir un jeton de session ; le mot de passe et le jeton ne sont jamais journalisés.

#### Correspondances du connecteur

1. Saisissez l'URL de votre contrôleur NeuVector dans le champ **Location**, en incluant le port de l'API REST — par exemple `https://neuvector.example.com:10443`.
2. Saisissez le **Username** et le **Password** du contrôleur.
3. Si votre contrôleur utilise un certificat auto\-signé, réglez **Skip TLS Verification** sur `true`.
4. Optionnellement, définissez une **Minimum Severity** pour limiter les constatations importées.

DefectDojo associe chaque **image** scannée à un Record et chaque **CVE** de son rapport de scan à une constatation. La sévérité provient de la notation propre à NeuVector, et le paquet et la version concernés, le score et le vecteur CVSSv3, la version corrigée (en tant que mitigation) et le lien de référence sont repris. Les constatations sont dédupliquées sur l'image, le CVE, le paquet, la version et la sévérité.

Consultez la [documentation de l'API NeuVector](https://open-docs.neuvector.com/automation/automation) pour plus d'informations.
