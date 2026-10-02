---
title: Serveur MCP
description: Le serveur MCP de DefectDojo vous permet d'utiliser des LLM avec DefectDojo
  Pro
draft: false
audience: pro
weight: 23
aliases:
- /fr/en/ai/mcp_server_pro
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Remarque : les fonctionnalités d'IA sont réservées à DefectDojo Pro.</span>

Le serveur DefectDojo Model Context Protocol (MCP) permet aux grands modèles de langage (LLM) d'interagir intelligemment avec les données de gestion des vulnérabilités de DefectDojo. Contrairement aux intégrations API traditionnelles qui se contentent de transférer des données, le serveur MCP fournit un contexte structuré et une signification sémantique qui permettent aux assistants IA de réaliser des analyses de sécurité sophistiquées et de générer des recommandations exploitables.

- **Contexte structuré :** MCP donne une signification sémantique aux données DefectDojo, au-delà du simple transfert de données brutes
- **Données prétraitées :** les données normalisées et dédupliquées de DefectDojo suppriment la charge de prétraitement pour le LLM
- **Intégration à la Business Intelligence :** combine les données techniques de vulnérabilité avec le contexte métier
- **Analyses prêtes pour la direction :** génère des rapports adaptés aussi bien aux équipes techniques qu'à la direction générale
- **Valeur composée x10 :** l'analyse enrichie par l'IA offre une valeur exponentiellement supérieure aux requêtes manuelles

> **🔑 Important :** le point de terminaison du serveur MCP se trouve à `/mcp`, mais tous les appels de fonction utilisent l'URL de base de DefectDojo. Cette séparation garantit un accès sécurisé et structuré aux données de vulnérabilité.

## Se connecter au MCP

### Prérequis

- Une instance DefectDojo avec le serveur MCP activé (v2.51.2 ou ultérieure)
- Un jeton API DefectDojo valide avec les permissions appropriées
- Un fournisseur d'IA : Claude, ChatGPT, Gemini, ou un client compatible MCP personnalisé

> **⚠️ Avis de sécurité :** votre jeton API est une information hautement sensible utilisée pour l'authentification et l'autorisation. **N'AFFICHEZ JAMAIS LE JETON DANS LES REQUÊTES OU LES RÉPONSES** lorsque vous partagez des configurations ou des captures d'écran.

### Méthodes de connexion

Il existe **deux méthodes différentes** pour se connecter au serveur MCP de DefectDojo, selon l'interface IA que vous utilisez :

#### Méthode 1 : fichier de configuration

**Utilisée par :** Claude Desktop, MCP Inspector, et d'autres clients MCP de bureau

**Fonctionnement :**
- Le jeton et les détails de connexion sont stockés dans un fichier de configuration
- La connexion est automatique au démarrage de l'application
- Aucun besoin de coller des instructions dans les conversations
- Le serveur MCP est toujours disponible dans toutes les conversations

**Avantages :** configuré une seule fois, fonctionne partout. Plus sécurisé (le jeton n'apparaît pas dans l'historique des conversations).

#### Méthode 2 : invite manuelle

**Utilisée par :** l'interface web Claude.ai, l'interface web ChatGPT (avec plugins), l'interface web Gemini

**Fonctionnement :**
- Vous copiez/collez les instructions de connexion au début de chaque conversation
- Ou vous ajoutez les instructions à un Claude Project pour une inclusion automatique
- L'IA lit les instructions et se connecte au serveur MCP
- Chaque nouvelle conversation nécessite ces instructions

**Avantages :** fonctionne dans les navigateurs web sans installer de logiciel.

> **💡 Quelle méthode utiliser ?** Utilisez la **Méthode 1 (fichier de configuration)** si vous disposez d'une application de bureau qui la prend en charge. Utilisez la **Méthode 2 (invite manuelle)** si vous utilisez une interface de navigateur web.

### Détails de connexion au serveur MCP

Toutes les méthodes utilisent ces paramètres de base :

| Paramètre | Valeur | Remarques |
|-----------|-------|-------|
| **Type de transport** | `Streamable HTTP` | ⚠️ SSE (Server-Sent Events) est obsolète |
| **URL du point de terminaison MCP** | `https://[YOUR-INSTANCE].defectdojo.com/mcp` | Utilisée pour établir la connexion MCP |
| **URL de base pour les fonctions** | `https://[YOUR-INSTANCE].defectdojo.com/` | Utilisée dans tous les appels de fonction des outils |
| **Authentification** | `Authorization: Token [YOUR_API_TOKEN]` | ⚠️ Utilisez le préfixe « Token », pas « Bearer » |

## Guides de démarrage rapide par fournisseur d'IA

<details>
<summary><h3>🖥️ Claude Desktop (Méthode 1 : fichier de configuration)</h3></summary>

**Étape 1 : localisez votre fichier de configuration**

- **macOS :** `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows :** `%APPDATA%\Claude\claude_desktop_config.json`
- **Linux :** `~/.config/Claude/claude_desktop_config.json`

**Étape 2 : modifiez le fichier de configuration**

Ajoutez ou mettez à jour la section `mcpServers` avec les détails de votre instance DefectDojo :

```json
{
  "mcpServers": {
    "DefectDojo-MCP": {
      "command": "npx",
      "args": [
        "mcp-remote",
        "https://your-instance.defectdojo.com/mcp",
        "--header",
        "Authorization: Token YOUR_API_TOKEN"
      ]
    }
  }
}
```

> **⚠️ Important :** l'indicateur `--header` avec l'authentification est obligatoire. Remplacez `YOUR_API_TOKEN` par votre jeton API DefectDojo réel.

**Étape 3 : redémarrez Claude Desktop**

Fermez et rouvrez Claude Desktop pour que les modifications prennent effet.

**Étape 4 : vérifiez la connexion**

Démarrez une nouvelle conversation et demandez : `"Can you connect to DefectDojo?"`

En cas de succès, Claude confirmera qu'il a accès aux outils du serveur MCP de DefectDojo.

> **✅ Terminé !** Le serveur MCP de DefectDojo est désormais disponible dans toutes les conversations. Aucun besoin de coller des instructions.

</details>

<details>
<summary><h3>🌐 Interface web Claude.ai (Méthode 2 : invite manuelle)</h3></summary>

L'interface web Claude.ai ne prend pas en charge les fichiers de configuration. Vous devrez fournir les instructions de connexion dans chaque conversation, ou utiliser un Claude Project.

#### Option A : coller les instructions à chaque conversation

**Étape 1 : copiez les instructions ci-dessous**

```
For this project, use the DefectDojo MCP server with these parameters in ALL function calls:

- **URL:** https://your-instance.defectdojo.com/ (base URL, NOT the /mcp endpoint)
- **Token:** YOUR_API_TOKEN
- **IMPORTANT:** DO NOT SHOW THE TOKEN IN ANY REQUESTS OR RESPONSES

The MCP server connects to https://your-instance.defectdojo.com/mcp but function calls must use the base URL.

**Do not show any of the API requests or responses.**
```

**Étape 2 : démarrez une nouvelle conversation**

Collez les instructions au début de votre conversation, puis posez vos questions de sécurité.

**Étape 3 : répétez pour chaque nouvelle conversation**

Ces instructions doivent être incluses au début de chaque nouvelle conversation.

#### Option B : utiliser un Claude Project (recommandé)

**Étape 1 : créez un Claude Project**

- Dans Claude.ai, cliquez sur « Projects » dans la barre latérale gauche
- Cliquez sur « Create Project »
- Nommez-le « DefectDojo Security Analysis »

**Étape 2 : ajoutez des instructions personnalisées au projet**

Dans Project Settings → Custom Instructions, collez :

```
For this project, use the DefectDojo MCP server with these parameters in ALL function calls:

- **URL:** https://your-instance.defectdojo.com/
- **Token:** YOUR_API_TOKEN
- **IMPORTANT:** DO NOT SHOW THE TOKEN IN ANY REQUESTS OR RESPONSES

The MCP server connects to https://your-instance.defectdojo.com/mcp but function calls must use the base URL.

Do not show any of the API requests or responses.
```

**Étape 3 : utilisez le projet pour toutes les conversations DefectDojo**

Toutes les conversations de ce projet auront automatiquement accès au serveur MCP de DefectDojo.

> **✅ Terminé !** Lorsque vous travaillez dans ce projet, Claude a automatiquement accès au MCP de DefectDojo.

</details>

<details>
<summary><h3>💬 ChatGPT (Méthode 2 : invite manuelle)</h3></summary>

> **⚠️ Remarque :** la prise en charge du MCP par ChatGPT est limitée par rapport à Claude. L'intégration MCP native peut nécessiter ChatGPT Plus ou Enterprise, ainsi que des configurations de plugins spécifiques.

**Étape 1 : vérifiez la disponibilité du plugin MCP**

Dans ChatGPT, vérifiez si des plugins MCP ou de connecteur API sont disponibles dans votre boutique de plugins. La prise en charge du MCP varie selon le niveau d'abonnement.

**Étape 2 : copiez les instructions de connexion**

```
I need you to connect to a DefectDojo MCP server with these details:

MCP Endpoint: https://your-instance.defectdojo.com/mcp
Base URL for API calls: https://your-instance.defectdojo.com/
Authentication: Authorization header with value "Token YOUR_API_TOKEN"

Use this connection to access DefectDojo vulnerability data. The server provides tools for:
- Getting findings with severity, status, and date filters
- Accessing products, engagements, tests
- User and group management
- Analyzing security trends

Do not show the API token in responses.
```

**Étape 3 : collez au début de chaque conversation**

Incluez ces instructions au démarrage d'une nouvelle conversation portant sur l'analyse de sécurité DefectDojo.

**Alternative : utiliser un Custom GPT**

Si vous disposez de ChatGPT Plus, créez un Custom GPT avec les détails de connexion à DefectDojo dans ses instructions, pour un accès réutilisable.

</details>

<details>
<summary><h3>💎 Google Gemini (Méthode 2 : invite manuelle)</h3></summary>

> **⚠️ Remarque :** la prise en charge du MCP par Gemini est en cours d'évolution. L'intégration native peut être limitée. Envisagez d'utiliser l'API Gemini avec des bibliothèques clientes MCP pour bénéficier de toutes les fonctionnalités.

**Étape 1 : copiez les instructions de connexion**

```
Connect to DefectDojo vulnerability management system via MCP server:

MCP Server: https://your-instance.defectdojo.com/mcp
API Base URL: https://your-instance.defectdojo.com/
Authentication: Token YOUR_API_TOKEN (use Authorization header with "Token" prefix)

Available capabilities:
- Query findings by severity (Critical, High, Medium, Low, Info)
- Filter by status (Active, Verified, False Positive, etc.)
- Filter by date ranges (Today, Past 7/30/90 days, etc.)
- Access products, engagements, tests, users, groups
- Generate security analysis and reports

Important: Do not display the authentication token in responses.
```

**Étape 2 : démarrez la conversation avec les instructions**

Commencez chaque nouvelle conversation Gemini par ces instructions lorsque vous travaillez avec des données DefectDojo.

**Pour les utilisateurs avancés :**

Envisagez d'utiliser l'API Gemini avec des bibliothèques clientes MCP (Python, JavaScript) pour un accès programmatique avec la prise en charge complète du protocole MCP.

</details>

<details>
<summary><h3>🔍 MCP Inspector (test et validation)</h3></summary>

**Cas d'usage :** testez votre connexion MCP à DefectDojo, explorez les outils disponibles et validez la configuration avant de l'utiliser avec des assistants IA.

**Étape 1 : installez MCP Inspector**

```bash
# macOS (using Homebrew)
brew install mcp-inspector

# Or using npm (all platforms)
npm install -g @modelcontextprotocol/inspector
```

**Étape 2 : exécutez MCP Inspector**

```bash
mcp-inspector
```

Cela démarre un serveur web local (généralement à l'adresse `http://localhost:6274`)

**Étape 3 : configurez la connexion dans l'interface web**

- **Type de transport :** `Streamable HTTP`
- **URL :** `https://your-instance.defectdojo.com/mcp`
- **Type de connexion :** `Via Proxy`
- **En-têtes personnalisés :**
  - Nom : `Authorization`
  - Valeur : `Token YOUR_API_TOKEN`
  - **Important :** activez le commutateur situé à côté de l'en-tête

**Étape 4 : cliquez sur « Connect »**

Une fois connecté, vous pouvez explorer :

- **Onglet Tools :** consultez les 12 outils disponibles et leurs paramètres
- **Onglet Prompts :** consultez les modèles d'invites préconfigurés
- **Onglet Resources :** vérifiez les ressources de données disponibles

> **✅ Idéal pour :** vérifier que votre configuration fonctionne avant de configurer des assistants IA, explorer les capacités des outils et résoudre les problèmes de connexion.

</details>

---

> **✅ Connexion réussie ?** Une fois connecté via l'une ou l'autre méthode, testez en demandant à votre assistant IA : `"How many active findings do we have in DefectDojo?"`

---

## Référence des outils disponibles

Le serveur MCP de DefectDojo fournit 12 outils pour accéder aux données de vulnérabilité et les analyser. Chaque outil comprend une gestion intelligente des paramètres et renvoie des données structurées optimisées pour l'analyse par un LLM.

> **💡 Remarque sur les paramètres :** tous les outils acceptent un paramètre `token` optionnel. S'il n'est pas fourni dans un appel donné, le LLM utilisera le jeton de la configuration de connexion.

---

### 🔍 Outils d'analyse des constatations

<details>
<summary><h4>get_findings</h4></summary>

**Description :** récupère les constatations de DefectDojo avec des capacités de filtrage avancées. C'est l'outil le plus puissant et le plus utilisé pour l'analyse des vulnérabilités.

**Paramètres :**

**severity** (optionnel)
- **Type :** tableau de chaînes de caractères
- **Valeurs :** `Critical`, `High`, `Medium`, `Low`, `Info`
- **Exemple :** `["Critical", "High"]`
- **Utilisation :** filtre les constatations par niveau de sévérité. Plusieurs valeurs peuvent être fournies pour des requêtes combinées.

**status** (optionnel)
- **Type :** tableau de chaînes de caractères
- **Valeurs :** `Any`, `Active`, `Open`, `Verified`, `Out of Scope`, `False Positive`, `Inactive`, `Risk Accepted`, `Closed`, `Under Review`
- **Exemple :** `["Active", "Verified"]`
- **Utilisation :** filtre les constatations selon leur statut actuel. Utilisez `Active` pour une évaluation des risques à jour.

**date** (optionnel)
- **Type :** tableau avec une seule valeur de chaîne de caractères
- **Valeurs :** `0 - Any date`, `1 - Today`, `2 - Past 7 days`, `3 - Past 30 days`, `4 - Past 90 days`, `5 - Current month`, `6 - Current year`, `7 - Past year`
- **Exemple :** `["3 - Past 30 days"]`
- **Utilisation :** filtre les constatations par date de découverte. Une seule valeur est autorisée.

**limit** (optionnel)
- **Type :** nombre
- **Valeur par défaut :** 100
- **Plage :** 1-100
- **Utilisation :** nombre de constatations à renvoyer. Pour obtenir uniquement un décompte, définissez-le à 1 et utilisez la propriété count de la réponse.

**offset** (optionnel)
- **Type :** nombre
- **Valeur par défaut :** 0
- **Utilisation :** décalage de pagination pour récupérer des résultats supplémentaires.

> **💡 Bonne pratique :** pour les requêtes d'évaluation des risques, utilisez toujours `status: ["Active"]` afin de vous concentrer sur les vulnérabilités actuelles et non résolues plutôt que sur les données historiques.

**Exemple de requête :**

**L'utilisateur demande :** « Montrez-moi toutes les constatations actives de sévérité Critique et Élevée des 30 derniers jours »

**Le LLM appelle :**
```
get_findings({
  severity: ["Critical", "High"],
  status: ["Active"],
  date: ["3 - Past 30 days"],
  limit: 100
})
```

</details>

<details>
<summary><h4>get_finding_by_id</h4></summary>

**Description :** récupère des informations détaillées sur une constatation spécifique à l'aide de son identifiant unique.

**Paramètres :**

**finding_id** (obligatoire)
- **Type :** nombre
- **Minimum :** 1
- **Utilisation :** l'identifiant unique de la constatation à récupérer.

**Exemple de requête :**

**L'utilisateur demande :** « Donnez-moi les détails de la constatation n° 1234 »

**Le LLM appelle :** `get_finding_by_id({ finding_id: 1234 })`

</details>

---

### 📦 Outils Produits et Engagements

<details>
<summary><h4>get_products</h4></summary>

**Description :** récupère tous les produits de DefectDojo. Les produits représentent les applications, services ou systèmes testés.

**Paramètres :**

**limit** (optionnel)
- **Valeur par défaut :** 100
- **Utilisation :** nombre maximal de produits à renvoyer.

**offset** (optionnel)
- **Valeur par défaut :** 0
- **Utilisation :** décalage de pagination.

</details>

<details>
<summary><h4>get_product_types</h4></summary>

**Description :** récupère les catégories de types de produits de DefectDojo. Les types de produits permettent d'organiser les produits en groupes logiques.

**Paramètres :** identiques à `get_products`

</details>

<details>
<summary><h4>get_engagements</h4></summary>

**Description :** récupère les engagements de tests de sécurité. Les engagements représentent des activités de test spécifiques ou des périodes données pour un produit.

**Paramètres :** identiques à `get_products`

</details>

<details>
<summary><h4>get_tests</h4></summary>

**Description :** récupère les tests de sécurité de DefectDojo. Les tests contiennent les résultats d'analyse d'outils de sécurité spécifiques ou de tests manuels.

**Paramètres :** identiques à `get_products`

</details>

---

### 👥 Outils de gestion des utilisateurs et des accès

<details>
<summary><h4>get_users</h4></summary>

**Description :** récupère tous les utilisateurs de DefectDojo pour l'analyse des parties prenantes et la cartographie des responsabilités.

**Paramètres :**

**limit** (optionnel)
- **Valeur par défaut :** 100

**offset** (optionnel)
- **Valeur par défaut :** 0

</details>

<details>
<summary><h4>get_user_by_id</h4></summary>

**Description :** récupère des informations détaillées sur un utilisateur spécifique.

**Paramètres :**

**user_id** (obligatoire)
- **Type :** nombre
- **Minimum :** 1

</details>

<details>
<summary><h4>get_groups</h4></summary>

**Description :** récupère les groupes d'utilisateurs pour l'analyse de la structure organisationnelle et la cartographie des permissions.

**Paramètres :** identiques à `get_users`

</details>

<details>
<summary><h4>get_group_by_id</h4></summary>

**Description :** récupère des informations détaillées sur un groupe spécifique.

**Paramètres :**

**group_id** (obligatoire)
- **Type :** nombre
- **Minimum :** 1

</details>

<details>
<summary><h4>get_dojo_group_members</h4></summary>

**Description :** récupère tous les membres d'un groupe spécifique pour l'analyse d'équipe.

**Paramètres :**

**group_id** (obligatoire)
- **Type :** nombre
- **Minimum :** 1

**limit** (optionnel)
- **Valeur par défaut :** 100

**offset** (optionnel)
- **Valeur par défaut :** 0

</details>

<details>
<summary><h4>get_roles</h4></summary>

**Description :** récupère les définitions de rôles de DefectDojo pour comprendre la structure des permissions.

**Paramètres :** identiques à `get_users`

</details>

---

## Invites préconfigurées

Le serveur MCP de DefectDojo inclut des invites préconfigurées qui illustrent les bonnes pratiques pour les scénarios d'analyse courants. Ces invites peuvent être appelées directement par votre assistant IA.

### 🛡️ Rapport d'évaluation SAST

**Objectif :** créer un rapport complet évaluant l'efficacité des outils SAST (Static Application Security Testing) à partir des données DefectDojo.

**L'analyse générée comprend :**

- Taux de faux positifs par outil et par type de vulnérabilité
- Délai moyen de remédiation par niveau de sévérité
- Vulnérabilités critiques apparaissant plusieurs fois (lacunes de déduplication)
- Comparaison des performances entre équipes de développement
- Recommandations d'amélioration de la configuration des outils
- Lacunes de formation identifiées à partir des schémas de vulnérabilités récurrents
- Analyse des coûts entre l'approche actuelle et l'approche d'outillage recommandée

**Format de sortie :** rapport d'évaluation technique au format HTML, adapté pour justifier des demandes de budget d'outillage de sécurité.

### 📊 Rapport de paysage de sécurité

**Objectif :** créer un rapport de type tableau de bord offrant une vue d'ensemble du paysage de sécurité à partir des données DefectDojo, adapté aux réunions trimestrielles du conseil d'administration.

**L'analyse générée comprend :**

- Tendances des vulnérabilités sur les 90 derniers jours
- Équipes de développement avec le plus de constatations de sévérité critique/élevée
- Exposition au risque par produit et par type de produit
- Top 5 des catégories CWE nécessitant une attention immédiate
- Actions de remédiation spécifiques avec analyse coûts-bénéfices
- Feuille de route sur 6 mois pour améliorer la posture de sécurité

**Format de sortie :** rapport HTML de niveau direction avec éléments visuels, cartes statistiques et accent sur le risque métier.

> **💡 Utilisation des invites :** pour appeler une invite, il suffit de demander à votre assistant IA : "Create a SAST Review Report" ou "Generate a Security Landscape Report using DefectDojo data"

---

## Exemples de cas d'usage

### Cas d'usage 1 : tableau de bord de sécurité pour la direction

**Scénario :** le RSSI a besoin de métriques de sécurité trimestrielles pour une présentation au conseil d'administration

**Invite utilisateur :**

```
"Create an executive security dashboard for our Q4 board meeting showing:
- Total vulnerability counts by severity
- Trends over the past 90 days  
- Which products have the highest risk exposure
- Top 5 vulnerability categories needing attention
- Specific remediation recommendations with ROI
- A 6-month roadmap for improving our security posture"
```

**Ce qui se passe en coulisses :**

1. `get_findings` - récupère le nombre total de constatations actives
2. `get_findings` - analyse des sévérités Critique et Élevée
3. `get_findings` - données de tendance sur 90 jours
4. `get_products` - répartition des vulnérabilités par produit
5. `get_engagements` - activités de test récentes

**Résultat généré :** rapport HTML de niveau direction avec les tendances des vulnérabilités, l'exposition au risque par produit, les principales catégories CWE, des actions de remédiation spécifiques avec ROI, et une feuille de route de sécurité sur 6 mois.

---

### Cas d'usage 2 : analyse des performances des équipes de développement

**Scénario :** un responsable d'ingénierie souhaite savoir quelles équipes ont besoin d'une formation de sécurité supplémentaire

**Invite utilisateur :**

```
"Which development teams have the most security findings? What types of vulnerabilities 
are they creating repeatedly? Based on this analysis, recommend specific security 
training programs for each team."
```

**Ce qui se passe en coulisses :**

1. `get_findings` - toutes les constatations actives
2. `get_products` - associe les constatations aux produits/équipes
3. `get_groups` - structure organisationnelle des équipes
4. `get_users` - responsabilité individuelle des développeurs

**Analyse fournie :** constatations regroupées par équipe, analyse des schémas CWE révélant les erreurs récurrentes, identification des lacunes de formation, et recommandations de programmes de formation à la sécurité ciblés.

---

### Cas d'usage 3 : évaluation de l'efficacité des outils

**Scénario :** une équipe de sécurité évalue le ROI de ses outils SAST actuels

**Invite utilisateur :**

```
"Analyze the effectiveness of our SAST tools. Show me false positive rates, 
mean time to remediation, which tools find the most valuable vulnerabilities, 
and recommend configuration improvements or alternative tools."
```

**Ce qui se passe en coulisses :**

1. `get_tests` - tous les tests de sécurité par outil
2. `get_findings` - analyse des faux positifs
3. `get_findings` - constatations actives par outil
4. `get_findings` - constatations clôturées pour les schémas de remédiation

**Analyse fournie :** taux de faux positifs par outil, délai moyen de remédiation par sévérité, analyse des constatations en doublon, recommandations de configuration des outils, lacunes de formation, et analyse coûts-bénéfices des approches d'outillage alternatives.

---

### Cas d'usage 4 : rapports de conformité

**Scénario :** préparation d'un audit SOC 2 nécessitant des preuves de gestion des vulnérabilités

**Invite utilisateur :**

```
"Generate a SOC 2 compliance report showing our vulnerability management processes, 
including discovery and remediation procedures, SLA compliance, continuous monitoring 
evidence, and accountability documentation."
```

**Ce qui se passe en coulisses :**

1. `get_findings` - constatations actives de sévérité Critique/Élevée
2. `get_findings` - tendances de découverte depuis le début de l'année
3. `get_engagements` - fréquence et couverture des tests
4. `get_users` - responsabilité de la remédiation

**Analyse fournie :** processus de découverte et de remédiation des vulnérabilités, suivi de la conformité aux SLA, preuves de surveillance continue, documentation des responsabilités, et lacunes à corriger avant l'audit.

---

### Cas d'usage 5 : priorisation des risques

**Scénario :** une équipe de sécurité dispose de ressources limitées et doit prioriser ses efforts de remédiation

**Invite utilisateur :**

```
"What are the highest priority vulnerabilities we should fix first? Consider severity, 
how long they've been open, exploitability, and business impact. Give me a prioritized 
remediation roadmap with effort estimates."
```

**Ce qui se passe en coulisses :**

1. `get_findings` - constatations actives de sévérité Critique/Élevée
2. `get_products` - contexte de criticité métier
3. Analyse des métriques d'ancienneté (jours depuis la découverte)
4. Recoupement avec les scores EPSS (prédiction d'exploitabilité)

**Analyse fournie :** liste des vulnérabilités classées par risque, combinant sévérité, ancienneté, exploitabilité et impact métier. Feuille de route de remédiation spécifique avec estimations d'effort et réduction de risque attendue.

---


## Bonnes pratiques et modèles de requêtes

### Stratégie de chargement progressif des données

Votre assistant IA optimise les performances en suivant automatiquement ces modèles de chargement de données :

**1. Commencer par les données de synthèse**

Demandez des décomptes avant de demander une analyse détaillée :

```
"How many critical and high severity findings do we have?"
```

Votre assistant IA utilisera l'outil `get_findings` avec `limit: 1` pour récupérer efficacement uniquement le décompte.

**2. Utiliser une pagination stratégique**

Pour les grands ensembles de données, votre assistant IA parcourt automatiquement les résultats par pages :

```
"Analyze all our active vulnerabilities"
```

L'IA effectuera plusieurs appels si nécessaire, en commençant par des limites raisonnables et en les augmentant selon les besoins.

**3. Réutilisation efficace des données**

Posez des questions liées les unes aux autres pour éviter les requêtes redondantes :

```
"Show me all critical findings, then tell me which CWE categories they fall into"
```

L'IA réutilisera les données de constatations de la première requête pour l'analyse CWE.

### Stratégies de filtrage intelligent

Formulez vos invites pour tirer parti des puissantes capacités de filtrage de DefectDojo :

#### Requêtes basées sur la sévérité

**Invite utilisateur :**
```
"Show me all Critical and High severity issues that need immediate attention"
```

**En coulisses :** l'IA utilise `get_findings` avec des filtres de sévérité et de statut

#### Requêtes basées sur la date

**Invite utilisateur :**
```
"What new vulnerabilities have been discovered in the past 30 days?"
```

**En coulisses :** l'IA applique un filtre de date « Past 30 days » avec le statut actif

#### Filtrage combiné

**Invite utilisateur :**
```
"Give me a risk assessment of all critical and high active findings from the past 90 days"
```

**En coulisses :** l'IA combine les filtres de sévérité, de statut et de date pour une analyse complète

### Analyse croisée

Votre assistant IA relie automatiquement les constatations au contexte organisationnel. Il vous suffit de poser des questions complètes :

**Invite utilisateur :**
```
"Which products have the most critical vulnerabilities and who is responsible for fixing them?"
```

**En coulisses :** l'IA relie constatations → tests → engagements → produits → utilisateurs/groupes pour obtenir un contexte complet

### Analyse de renseignement sur les vulnérabilités

**Analyse des schémas CWE**

**Invite utilisateur :**
```
"What are the most common vulnerability types in our codebase and which teams are creating them?"
```

L'IA regroupera les constatations par CWE pour identifier les schémas récurrents, les besoins de formation et les problèmes d'architecture.

**Métriques d'ancienneté**

**Invite utilisateur :**
```
"How long have our critical vulnerabilities been open? Which ones are overdue for remediation?"
```

L'IA calcule le temps écoulé depuis la découverte et signale les constatations dépassant les seuils de SLA.

**Densité de vulnérabilités**

**Invite utilisateur :**
```
"Which products have the highest vulnerability density and represent the greatest risk?"
```

L'IA calcule le nombre de constatations par produit et génère des scores de risque combinant sévérité et volume.

### Normes d'amélioration des rapports

#### Toujours inclure

- **Métriques précises :** décomptes réels par sévérité, pas de généralisations
- **Analyse CWE :** principaux types de vulnérabilités avec descriptions
- **Données d'ancienneté :** depuis combien de temps les vulnérabilités sont ouvertes
- **Recommandations exploitables :** les prochaines actions à mener, avec échéances
- **Calculs de ROI :** coût attendu par rapport au bénéfice des actions
- **Métriques de succès :** comment mesurer l'amélioration

#### Intégration du contexte sectoriel

Comparez les constatations de DefectDojo aux référentiels du secteur :

- **OWASP Top 10 :** risques de sécurité des applications web
- **SANS Top 25 :** faiblesses logicielles les plus dangereuses
- **CWE Top 25 :** faiblesses les plus courantes et les plus impactantes
- **Référentiels de conformité :** SOC 2, ISO 27001, NIST CSF

## Dépannage du MCP

### Liste de vérification diagnostique

Vérifiez les éléments suivants en cas de problème de connexion :

- ✅ Le type de transport est **Streamable HTTP** (pas SSE)
- ✅ L'URL du point de terminaison MCP est correcte : `https://[instance].defectdojo.com/mcp`
- ✅ L'en-tête Authorization est activé (le commutateur est sur ON)
- ✅ Le format du jeton inclut le préfixe `Token`
- ✅ Le jeton est valide et dispose des permissions appropriées
- ✅ L'instance DefectDojo est accessible (connexion possible via l'interface web)
- ✅ La connectivité réseau autorise les connexions HTTPS

### Problèmes de connexion courants

#### ❌ "Connection Error - Check if your MCP server is running"

**Cause :** utilisation du type de transport obsolète SSE (Server-Sent Events)

**Solution :** changez le type de transport en `Streamable HTTP`

**Pourquoi :** le serveur MCP de DefectDojo utilise le protocole moderne Streamable HTTP. SSE est obsolète et n'est pas pris en charge.

---

#### ❌ "Authentication Failed" ou "401 Unauthorized"

**Cause :** format d'en-tête d'authentification incorrect ou jeton invalide

**Solutions :**

1. Vérifiez que la valeur de l'en-tête utilise le préfixe `Token` (pas `Bearer`)
   ```
   ✅ Correct: Token 7c6cc2xxxxxxxxxxxxxxxxxxxx87fcf72ec2b3fb
   ❌ Wrong: Bearer 7c6cc2xxxxxxxxxxxxxxxxxxxx87fcf72ec2b3fb
   ```

2. Assurez-vous que le commutateur de l'en-tête Authorization est ACTIVÉ (sur ON)
3. Vérifiez que le jeton est toujours valide dans DefectDojo (Admin → API Tokens)
4. Vérifiez que le jeton dispose des permissions appropriées pour l'accès en lecture

---

#### ❌ L'outil renvoie des résultats vides

**Causes possibles :**

- Les filtres sont trop restrictifs (aucune donnée ne correspond aux critères)
- L'instance DefectDojo ne contient aucune donnée dans la catégorie demandée
- Permissions du jeton insuffisantes

**Solutions :**

1. Essayez d'abord une requête plus large : `get_findings({ limit: 10 })`
2. Retirez les filtres un par un pour identifier celui qui est trop restrictif
3. Vérifiez les permissions du jeton dans DefectDojo
4. Vérifiez si les données existent directement dans l'interface de DefectDojo

---

#### ⚠️ Temps de réponse lents

**Cause :** demande d'un trop grand volume de données à la fois

**Solutions :**

- Réduisez le paramètre `limit` (commencez par 50-100)
- Utilisez des filtres plus spécifiques pour réduire la taille du jeu de résultats
- Utilisez un chargement progressif : récupérez d'abord les décomptes, puis les détails
- Mettez en place la pagination pour les grands ensembles de données

---
