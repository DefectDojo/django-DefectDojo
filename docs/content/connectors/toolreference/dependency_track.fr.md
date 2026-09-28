---
title: "Dependency-Track"
description: "Comment configurer le Connecteur Upstream Dependency-Track pour DefectDojo"
weight: 48
audience: pro
---
Ce connecteur récupère les données d'une instance Dependency\-Track sur site, via l'API REST.

​**Mappages du connecteur**

1. Saisissez l'URL de votre serveur Dependency\-Track local dans le champ **Location**.
2. Saisissez une clé d'API valide dans le champ **Secret**.

Pour générer une clé d'API Dependency\-Track :

1. **Access Management** : accédez à Administration \> Access Management \> Teams dans l'interface Dependency\-Track.
2. **Teams Setup** : vous pouvez créer une nouvelle équipe ou en sélectionner une existante. Les équipes permettent de gérer l'accès à l'API en fonction de l'appartenance à un groupe.
3. **Generate API Key** : sur la page de détails de l'équipe sélectionnée, trouvez la section « API Keys ». Cliquez sur le bouton \+ pour générer une nouvelle clé d'API.
4. **Assign Permissions** : dans la section « Permissions » de la page de l'équipe, cliquez sur le bouton \+ pour ouvrir le sélecteur de permissions. Choisissez les permissions **VIEW\_PORTFOLIO** et **VIEW\_VULNERABILITY** pour activer l'accès API aux portefeuilles de projets et aux détails des vulnérabilités.
5. Cliquez sur « **Select** » pour confirmer et enregistrer ces permissions.

Pour plus d'informations, consultez la **[documentation Dependency\-Track](https://docs.dependencytrack.org/integrations/rest-api/)**.
