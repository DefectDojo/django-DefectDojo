---
title: "ServiceNow SecOps"
description: "Comment configurer le Connecteur Downstream ServiceNow SecOps pour DefectDojo"
weight: 122
audience: pro
---
L'intégration ServiceNow SecOps (aussi appelée **ServiceNow SecOps / Vulnerability Response**) pousse les Constatations et Groupes de constatations DefectDojo vers une table de sécurité ServiceNow — un **Security Incident** (`sn_si_incident`) ou un **Vulnerable Item** (`sn_vul_vulnerable_item`) — et la maintient synchronisée à mesure que la Constatation évolue (création, mise à jour et résolution/fermeture). C'est l'équivalent côté opérations de sécurité de l'intégration ServiceNow de suivi des tickets ci-dessus ; utilisez ServiceNow SecOps lorsque vous exploitez les applications Security Incident Response (SIR) ou Vulnerability Response (VR).

### Configuration de l'instance

- **Instance Label** doit être l'étiquette que vous souhaitez utiliser pour identifier cette intégration.
- **Location** doit être définie sur l'URL de votre serveur ServiceNow, par exemple `https://your-organization.service-now.com/`.

ServiceNow SecOps prend en charge trois méthodes d'authentification ; fournissez-en **une seule** :

- **OAuth 2.0** — saisissez un **Client ID**, un **Client Secret** et un **Refresh Token**. Obtenez-les exactement comme décrit dans la section [ServiceNow](/connectors/toolreference/servicenow/) ci-dessus (créez un point de terminaison API OAuth dans l'Application Registry, puis échangez vos identifiants sur `/oauth_token.do` contre un jeton d'actualisation). Vous pouvez aussi fournir le **Client ID** et le **Client Secret** avec un **Username** et un **Password** pour utiliser l'octroi OAuth par mot de passe au lieu d'un jeton d'actualisation.
- **API Key** — saisissez une **API Key**, envoyée dans l'en-tête `x-sn-apikey`. La clé n'authentifie rien tant qu'un Inbound Authentication Profile et une REST API Access Policy ne lui sont pas associés sur l'instance.
- **HTTP Basic** — saisissez le **Username** et le **Password** du compte de service.

Le compte de service (ou le client OAuth) doit disposer d'un accès en écriture à la table cible.

### Correspondance du suivi des tickets

- **Target Table** sélectionne la table ServiceNow dans laquelle les enregistrements sont écrits : **Security Incident** (`sn_si_incident`, valeur par défaut) ou **Vulnerable Item** (`sn_vul_vulnerable_item`).

### Détails de la correspondance des sévérités

Pour un Security Incident, ceci correspond au champ **Impact** ; ServiceNow dérive la Priority de l'incident à partir de l'Impact et de l'Urgency, si bien que l'Urgency reflète l'Impact mappé à moins que vous ne la mappiez vous-même. Pour un Vulnerable Item, associez la sévérité au champ de risque utilisé par votre instance. Les valeurs par défaut ci-dessous correspondent à l'échelle Impact SIR standard (`1` High, `2` Medium, `3` Low) et sont modifiables.

- **Severity Field Name**: `impact`
- **Info Mapping**: `3`
- **Low Mapping**: `3`
- **Medium Mapping**: `2`
- **High Mapping**: `1`
- **Critical Mapping**: `1`

### Détails de la correspondance des statuts

Ceci correspond au champ **State** de l'enregistrement. Les valeurs d'état sont des codes numériques qui diffèrent entre les tables Security Incident et Vulnerable Item et peuvent être personnalisées par instance ; vérifiez-les donc par rapport à votre propre configuration. Les valeurs par défaut ci-dessous utilisent les codes d'état SIR standard (`16` Analysis, `3` Closed).

- **Status Field Name**: `state`
- **Active Mapping**: `16`
- **Closed Mapping**: `3`
- **False Positive Mapping**: `3`
- **Risk Accepted Mapping**: `3`

Lorsqu'un enregistrement est fermé, DefectDojo définit également le **Close Code** et les **Close Notes** ServiceNow (`Resolved` pour les Constatations fermées, `False positive` et `Risk accepted` pour les états correspondants).

### Comportements spécifiques à ServiceNow SecOps

- **Deduplication** — chaque enregistrement est marqué avec l'identifiant DefectDojo de la Constatation ou du Groupe de constatations dans son `correlation_id`. Avant de créer un enregistrement, DefectDojo en recherche un par `correlation_id` ; une correspondance est reprise et mise à jour plutôt que dupliquée, ce qui rend les resynchronisations idempotentes.
- **Updates** sont publiées dans le journal **Work notes** de l'enregistrement (interne), jamais dans les Comments visibles par le client.
- **Resolve on delete** — la suppression d'une Constatation dans DefectDojo résout/ferme l'enregistrement ServiceNow (State + Close Code) plutôt que de le supprimer ; les enregistrements ne sont jamais supprimés définitivement.
- **Reference fields** — les valeurs facultatives `cmdb_ci`, `assignment_group` et `assigned_to` peuvent être fournies sous forme de noms d'affichage ; DefectDojo résout chacune vers son `sys_id`. Un nom qui ne se résout pas est ignoré avec un avertissement plutôt que de faire échouer l'envoi.
