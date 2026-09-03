---
title: "ServiceNow"
description: "Comment configurer le Connecteur Downstream ServiceNow pour DefectDojo"
weight: 120
audience: pro
---
L'intégration ServiceNow vous permet de pousser les Constatations DefectDojo sous forme d'Incidents ServiceNow.

### Configuration de l'instance

DefectDojo s'authentifie auprès de ServiceNow via OAuth 2.0. La façon dont vous créez les identifiants OAuth dépend de votre version de ServiceNow — les versions récentes (Zurich et ultérieures) utilisent un octroi Client Credentials, tandis que les versions antérieures utilisent un jeton d'actualisation (refresh token).

#### ServiceNow Zurich et versions ultérieures (client credentials)

Les versions récentes de ServiceNow ont déprécié l'option classique « Create an OAuth API endpoint for external clients » au profit de la **New Inbound Integration Experience**, qui délivre un octroi OAuth **Client Credentials** lié à un compte de service :

1. Dans la barre de navigation de gauche, recherchez « Application Registry » et sélectionnez-le.
2. Cliquez sur **New**, puis choisissez **New Inbound Integration Experience**.
3. Sélectionnez **New Integration → OAuth - Client credentials grant**.
4. Définissez **OAuth Application User** sur le compte de service qui créera les Incidents. Les rôles de ce compte déterminent ce que DefectDojo est autorisé à écrire.
5. Enregistrez l'inscription. ServiceNow génère automatiquement le **Client ID** et le **Client Secret** (laissez ces champs vides lors de la création de l'inscription).

Ensuite, dans DefectDojo :

- **Instance Label** doit être l'étiquette que vous souhaitez utiliser pour identifier cette intégration.
- **Location** doit être définie sur l'URL de votre serveur ServiceNow, par exemple `https://your-organization.service-now.com/`.
- **Client ID** doit être le Client ID provenant de l'inscription OAuth.
- **Client Secret** doit être le Client Secret provenant de l'inscription OAuth.

Laissez vides les champs Refresh Token, Username et Password — DefectDojo demande un nouveau jeton client-credentials à chaque synchronisation.

#### Versions antérieures de ServiceNow (jeton d'actualisation)

Sur les versions qui proposent encore l'inscription classique, obtenez un Refresh Token associé au compte Utilisateur ou de Service qui poussera les Incidents vers ServiceNow :

1. Dans la barre de navigation de gauche, recherchez « Application Registry » et sélectionnez-le.
2. Cliquez sur « New ».
3. Choisissez « Create an OAuth API endpoint for external clients ».
4. Renseignez les champs requis :
    * Name : indiquez un nom explicite pour votre application (par exemple, Vulnerability Integration Client).
    * (Facultatif) Ajustez la durée de vie du jeton :
    * Access Token Lifespan : la valeur par défaut est 1800 secondes (30 minutes).
    * Refresh Token Lifespan : la valeur par défaut est 8640000 secondes (environ 100 jours).
5. Cliquez sur Submit pour créer l'enregistrement de l'application.
6. Après l'envoi, sélectionnez l'application dans la liste et notez les champs **Client ID and Client Secret**.

Vous devrez ensuite utiliser cette inscription pour obtenir un Refresh Token, qui ne peut être obtenu que via l'API ServiceNow.  Ouvrez une fenêtre de terminal et collez ce qui suit (en remplaçant les variables entourées de `{{}}` par les informations réelles de votre utilisateur)

```
curl --request POST \
 --url {{INSTANCE_HOST}}/oauth_token.do \
 --header 'content-type: application/x-www-form-urlencoded' \
 --data grant_type=password \
 --data 'client_id={{CLIENT_ID}}' \
 --data 'client_secret={{CLIENT_SECRET}}' \
 --data 'username={{USERNAME}}' \
 --data 'password={{PASSWORD}}'
 ```

Si vos identifiants ServiceNow sont corrects et permettent un accès de niveau administrateur à ServiceNow, vous devriez recevoir une réponse contenant un RefreshToken.  Vous aurez besoin de ce jeton pour terminer l'intégration avec DefectDojo.

- **Instance Label** doit être l'étiquette que vous souhaitez utiliser pour identifier cette intégration.
- **Location** doit être définie sur l'URL de votre serveur ServiceNow, par exemple `https://your-organization.service-now.com/`.
- **Refresh Token** est l'endroit où le Refresh Token doit être saisi.
- **Client ID** doit être le Client ID défini dans l'OAuth App Registration.
- **Client Secret** doit être le Client Secret défini dans l'OAuth App Registration.

### Détails de la correspondance des sévérités

Ceci correspond au champ Impact de ServiceNow.
- **Info Mapping**: `1`
- **Low Mapping**: `1`
- **Medium Mapping**: `2`
- **High Mapping**: `3`
- **Critical Mapping**: `3`

### Détails de la correspondance des statuts

- **Status Field Name**: `State`
- **Active Mapping**: `New`
- **Closed Mapping**: `Closed`
- **False Positive Mapping**: `Resolved`
- **Risk Accepted Mapping**: `Resolved`

Chaque correspondance accepte une étiquette d'état standard (`New`, `In Progress`, `On Hold`, `Resolved`, `Closed`, `Cancelled`) ou une valeur d'état numérique. Sur les instances dont les états d'Incident sont personnalisés — ou lorsque vous ciblez une table autre que `incident` — utilisez la **valeur d'état** numérique de la liste de choix de votre instance ; une valeur numérique en dehors de l'ensemble standard est envoyée à ServiceNow telle quelle. La valeur par défaut intégrée du code de résolution n'accompagne que les états résolu/fermé standard ; associez donc les valeurs d'état personnalisées aux correspondances de champs de clôture et de résolution ci-dessous.

### Champs de clôture et de résolution

Certaines instances ServiceNow appliquent une Data Policy qui rend obligatoires des champs tels que le **Resolution code** (`close_code`) dès qu'un Incident passe à un état résolu ou fermé. Si DefectDojo ferme un Incident sans ces champs, ServiceNow rejette l'écriture avec une erreur HTTP 403 *« Data Policy Exception »*, et la raison est enregistrée dans la vue Errors de l'intégration.

Associez les champs requis au changement d'état avec **Custom Field Mappings**, en définissant **Apply On** sur la disposition qui doit les porter :

- **Transition to Closed** — envoyé lorsqu'une Constatation est atténuée / fermée.
- **Transition to False Positive** — envoyé lorsqu'une Constatation est marquée comme faux positif.
- **Transition to Risk Accepted** — envoyé lorsqu'une Constatation fait l'objet d'une acceptation du risque.

Par exemple, pour satisfaire un Resolution code obligatoire :

| Source | Field Name | Value | Apply On |
|---|---|---|---|
| Static | `close_code` | `Resolved by DefectDojo` | Transition to Closed |
| Static | `close_notes` | `Reviewed by the security team` | Transition to Closed |
| Static | `close_code` | `Not a defect` | Transition to False Positive |

Remarques :

- Field Name est le nom de colonne ServiceNow — `close_code`, `close_notes`, ou un champ personnalisé `u_...`.
- Les correspondances de transition se déclenchent lorsque l'état de l'enregistrement change réellement : une Constatation déjà fermée lors de son premier envoi, une mise à jour qui ferme ou rouvre l'enregistrement, et la fermeture forcée lorsqu'un lien de ticket est supprimé. Elles ne sont pas renvoyées lors de mises à jour de routine d'un enregistrement inchangé ; les champs de journal tels que `work_notes` reçoivent donc une seule entrée par transition.
- Les champs de référence tels que `assignment_group` et `assigned_to` attendent un **sys_id**, et non un nom d'affichage.
- Les valeurs qui s'analysent comme du JSON sont envoyées typées : `true`, `42`, `[...]`, `{...}` — et `null`, qui efface le champ. Pour envoyer un tel texte comme chaîne littérale, entourez-le de guillemets doubles (par exemple `"null"`).
- `short_description`, `description`, `state`, `impact`, `urgency` et `priority` sont gérés par le modèle de description et par les correspondances de sévérité/statut ; ils ne peuvent donc pas être définis via une correspondance de champ personnalisée.
- Sur les tables autres que `incident`, les valeurs d'état qui correspondent à l'ensemble Incident standard (`1`, `2`, `3`, `6`, `7`, `8`) sont tout de même interprétées avec la sémantique Incident — y compris la valeur par défaut automatique du Resolution code sur `6`/`7`/`8`. Privilégiez des valeurs d'état en dehors de cette plage sur les tables personnalisées, ou fournissez explicitement les champs de clôture comme ci-dessus.
