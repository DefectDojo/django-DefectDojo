---
title: "Microsoft Defender"
description: "Comment configurer le Connecteur Upstream Microsoft Defender pour DefectDojo"
weight: 89
audience: pro
---
Le connecteur Microsoft Defender importe les constatations de vulnérabilités des appareils depuis **Microsoft Defender Vulnerability Management (MDVM)** — une constatation par combinaison appareil / version logicielle / CVE, incluant la sévérité, le score CVSS, le niveau d'exploitabilité et les mises à jour de sécurité recommandées. DefectDojo découvre vos **groupes d'appareils** Defender et crée un Record pour chacun ; les appareils qui ne sont assignés à aucun groupe d'appareils sont regroupés sous un groupe synthétique **Unassigned**.

**Remarque :** ce Connecteur est distinct du type de scan basé sur fichier **« MSDefender Parser »**, qui importe des fichiers Defender exportés manuellement. Choisissez un seul chemin d'import par Produit afin d'éviter les constatations en double.

#### Prérequis

Votre tenant Microsoft doit disposer d'une licence active incluant les API d'export de vulnérabilités Defender : **Defender for Endpoint Plan 2**, **Microsoft Defender Vulnerability Management Standalone**, ou MDE P1/P2 avec l'add\-on MDVM. (Le SKU *Add\-on* MDVM seul ne suffit pas — il nécessite Defender for Endpoint Plan 2 en dessous.)

Le connecteur s'authentifie en tant qu'**app registration** Microsoft Entra ID via le flux client credentials. Pour en créer une :

1. Dans le [portail Azure](https://portal.azure.com), ouvrez **App registrations \> New registration**. Nommez\-la (par exemple `defectdojo-connector`), laissez les valeurs par défaut, puis sélectionnez **Register**.
2. Sur la page **Overview** de l'application, notez l'**Application (client) ID** et le **Directory (tenant) ID**.
3. Ouvrez **API permissions \> Add a permission \> APIs my organization uses** et recherchez **WindowsDefenderATP**. Si elle n'apparaît pas, le backend Defender de votre tenant n'a pas encore été provisionné : vérifiez que la licence est active, ouvrez une fois [security.microsoft.com](https://security.microsoft.com), puis réessayez après quelques minutes.
4. Choisissez **Application permissions** (*et non* Delegated — les permissions Delegated n'apparaissent jamais dans le jeton de service du connecteur), développez **Vulnerability**, cochez **Vulnerability.Read.All**, puis sélectionnez **Add permissions**.
5. Sélectionnez **Grant admin consent** et confirmez. La colonne Status doit afficher une coche verte — sans cette étape, chaque appel API renvoie une erreur 403.
6. Ouvrez **Certificates & secrets \> New client secret**, définissez une expiration, et copiez immédiatement la **Value** du secret (elle n'est affichée qu'une seule fois). Le Connecteur cesse de fonctionner à l'expiration du secret, notez donc la date.

#### Correspondances du connecteur

1. Saisissez `https://api.security.microsoft.com` dans le champ **Location**.
2. Saisissez le **Directory (tenant) ID** dans le champ **Tenant ID**.
3. Saisissez l'**Application (client) ID** dans le champ **Client ID**.
4. Saisissez la valeur du secret client dans le champ **Client Secret**.
5. Optionnellement, définissez une **Minimum Severity** pour limiter les constatations importées.

Chaque groupe d'appareils Defender devient un Record. Microsoft régénère l'instantané de vulnérabilités que lit le connecteur environ toutes les 6 heures, et les appareils nouvellement intégrés peuvent mettre jusqu'à ~24 heures à produire leurs premières données de vulnérabilité — un tenant tout juste créé effectuera légitimement un Sync avec zéro constatation tant que les appareils n'auront pas été intégrés et évalués. L'activation de la licence elle\-même peut aussi prendre ~20 minutes ou plus avant d'atteindre l'API (les erreurs « No active license found » pendant cette fenêtre se résolvent d'elles\-mêmes).
