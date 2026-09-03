---
title: "ServiceDesk Plus"
description: "Comment configurer le Connecteur Downstream ServiceDesk Plus pour DefectDojo"
weight: 119
audience: pro
---
L'intégration ManageEngine ServiceDesk Plus vous permet de pousser les Constatations et Groupes de constatations DefectDojo sous forme de requests ServiceDesk Plus, affectées à un Group de support de votre choix.  Les éditions **cloud** (ServiceDesk Plus OnDemand) et **on-premises** sont toutes deux prises en charge par la même intégration - les identifiants que vous fournissez déterminent le mode utilisé.

### Configuration de l'instance

- **Label** doit être l'étiquette que vous souhaitez utiliser pour identifier cette intégration.
- **Location** doit être définie sur votre URL ServiceDesk Plus : `https://sdpondemand.manageengine.com` pour l'édition cloud (ou son équivalent régional), ou l'adresse de votre serveur pour les installations on-premises.

Fournissez ensuite **un seul** des deux jeux d'identifiants :

#### On-premises : Technician Key

- **Technician Key** doit être une clé API générée pour un technicien sur votre serveur, sous **Admin > General Settings > API**.  Laissez vides les champs Zoho OAuth.

#### Cloud : Zoho OAuth

L'édition cloud s'authentifie via Zoho Accounts OAuth :

1. Ouvrez la [Zoho API Console](https://api-console.zoho.com/) et créez un **Self Client**.
2. Notez le **Client ID** et le **Client Secret**.
3. Dans l'onglet « Generate Code » du Self Client, saisissez le scope `SDPOnDemand.requests.ALL`, choisissez une durée, puis générez le code.
4. Échangez le code contre un jeton d'actualisation :

```
curl --request POST \
 --url 'https://accounts.zoho.com/oauth/v2/token' \
 --data 'grant_type=authorization_code' \
 --data 'client_id={{CLIENT_ID}}' \
 --data 'client_secret={{CLIENT_SECRET}}' \
 --data 'code={{GENERATED_CODE}}'
```

5. Saisissez le **Client ID**, le **Client Secret** et le **Refresh Token** renvoyé dans le formulaire de l'instance.  Si votre compte est hébergé en dehors du centre de données US, définissez **Token URL** sur le point de terminaison Zoho Accounts régional (par exemple `https://accounts.zoho.eu/oauth/v2/token`).

### Correspondance du suivi des tickets

- **Group Name** doit être le nom du groupe de support ServiceDesk Plus auquel les requests seront affectées, exactement comme il apparaît sous **Admin > Users > Support Groups**.

### Détails de la correspondance des sévérités

Ceci correspond, par nom, au champ **Priority** de la request ServiceDesk Plus, en utilisant les noms de priorité de votre compte :

- **Severity Field Name**: `Priority`
- **Info Mapping**: `Low`
- **Low Mapping**: `Normal`
- **Medium Mapping**: `Medium`
- **High Mapping**: `High`
- **Critical Mapping**: `High`

### Détails de la correspondance des statuts

Ceci correspond, par nom, au champ **Status** de la request.  Les valeurs par défaut utilisent les statuts intégrés :

- **Status Field Name**: `Status`
- **Active Mapping**: `Open`
- **Closed Mapping**: `Closed`
- **False Positive Mapping**: `Closed`
- **Risk Accepted Mapping**: `On Hold`

Quelques comportements spécifiques à ServiceDesk Plus à connaître :

- Les mises à jour synchronisent l'intégralité du contenu de la request - contrairement à la plupart des outils de suivi, ServiceDesk Plus permet de modifier l'objet et la description après la création.
- Les requests sont fermées plutôt que supprimées lorsqu'une Constatation est retirée ; les requests déjà Closed ou Resolved restent inchangées.
- Si votre compte rend certains champs obligatoires à la clôture (par exemple une résolution), une fermeture envoyée depuis DefectDojo peut être rejetée par ces règles et apparaîtra dans la table Integration errors.
