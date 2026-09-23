---
title: "SonarQube"
description: "Comment configurer le Connecteur Upstream SonarQube pour DefectDojo"
weight: 127
audience: pro
---
Le connecteur SonarQube peut récupérer des données soit depuis un compte SonarCloud, soit depuis une instance SonarQube locale.

**Pour les utilisateurs de SonarCloud :**

1. Saisissez https://sonarcloud.io/ dans le champ Location.
2. Saisissez une **clé API** valide dans le champ Secret.

**Pour les utilisateurs de SonarQube (sur site) :**

1. Saisissez l'URL de base de votre instance SonarQube dans le champ Location : par exemple `https://my.sonarqube.com/`
2. Saisissez une **clé API** valide dans le champ Secret. Il devra s'agir d'un **[User](https://docs.sonarsource.com/sonarqube/latest/user-guide/user-account/generating-and-using-tokens/)** [type de jeton API](https://docs.sonarsource.com/sonarqube/latest/user-guide/user-account/generating-and-using-tokens/).

Le jeton devra avoir accès aux Projects, Vulnerabilities et Hotspots dans Sonar.

Les clés API peuvent être trouvées et générées via **My Account \-\> Security \-\> Generate Token** dans l'application SonarQube. Pour plus d'informations, [consultez la documentation SonarQube](https://docs.sonarsource.com/sonarqube/latest/user-guide/user-account/generating-and-using-tokens/).
