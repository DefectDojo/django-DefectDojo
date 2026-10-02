---
title: Provisionnement SCIM
description: Provisionnez et déprovisionnez les utilisateurs de DefectDojo Pro depuis
  votre fournisseur d'identité
weight: 19
audience: pro
---

DefectDojo Pro prend en charge SCIM 2.0, ce qui permet à votre fournisseur d'identité de créer, mettre à jour et désactiver directement les utilisateurs DefectDojo. Sans cela, DefectDojo ne découvre un utilisateur que lorsque celui-ci se connecte ; supprimer quelqu'un de votre fournisseur d'identité empêche donc les connexions futures mais laisse son compte DefectDojo actif.

SCIM est distinct de l'authentification unique (SSO) et la complète. Le SSO détermine qui peut se connecter ; SCIM maintient la liste des comptes elle-même synchronisée avec votre annuaire. La plupart des clients configurent les deux : SAML ou OIDC pour l'authentification, SCIM pour le provisionnement.

La configuration de SCIM ne peut être effectuée que par un **Superuser**.

## Ce que SCIM fait dans DefectDojo

Lorsque vous connectez un fournisseur d'identité via SCIM, celui-ci peut :

* créer des utilisateurs DefectDojo lorsqu'une personne se voit attribuer l'application
* mettre à jour les noms et adresses e-mail lorsqu'ils changent dans l'annuaire
* désactiver les utilisateurs lorsqu'ils ne sont plus attribués ou quittent l'organisation
* créer des groupes, et ajouter ou supprimer leurs membres

La désactivation d'un utilisateur via SCIM effectue deux actions à la fois. Le compte est marqué comme inactif, de sorte que l'utilisateur ne peut plus se connecter, et les jetons API DefectDojo de l'utilisateur sont supprimés. Le départ d'un utilisateur ferme donc les deux portes en une seule étape, ce qui est la principale raison d'utiliser SCIM plutôt que de se fier uniquement à votre fournisseur d'identité.

La fiche utilisateur elle-même est conservée. Les Constatations, notes et historiques font référence aux personnes qui les ont créés ; DefectDojo désactive donc le compte plutôt que de le supprimer. Si la même personne revient, la réactiver via votre fournisseur d'identité restaure l'accès sans perturber cet historique.

## Configuration

1. Ouvrez **Connect > Authorization** et sélectionnez **SCIM Provisioning**. SCIM figure aux côtés de vos fournisseurs de connexion car il se connecte au même fournisseur d'identité, et est étiqueté **Provisioning** pour le distinguer des fournisseurs qui ajoutent un bouton sur la page de connexion.

2. Cochez **Enable SCIM Provisioning** et envoyez le formulaire. Tant que cette option est désactivée, les points de terminaison SCIM se comportent comme s'ils n'existaient pas ; un test de connexion depuis votre fournisseur d'identité signale donc que l'adresse est introuvable.

3. Copiez la **Tenant URL** affichée sur la page. Elle se présente ainsi :

   ```
   https://<your-instance>.cloud.defectdojo.com/scim/v2
   ```

4. Dans le panneau **SCIM Tokens**, donnez au jeton un nom indiquant où il sera utilisé, par exemple « Okta production », puis sélectionnez **Generate Token**.

5. Copiez le jeton depuis la boîte de dialogue et collez-le dans votre fournisseur d'identité. DefectDojo ne stocke qu'un hachage du jeton, qui ne peut donc plus être réaffiché. Si vous le perdez, générez-en un autre et révoquez l'ancien.

Vous pouvez conserver plusieurs jetons actifs simultanément. Pour effectuer une rotation, générez un nouveau jeton, mettez à jour votre fournisseur d'identité, puis révoquez l'ancien. Il n'y a aucune période pendant laquelle le provisionnement cesse de fonctionner.

Le panneau des jetons enregistre la dernière utilisation de chaque jeton, ce qui permet de vérifier rapidement que votre fournisseur d'identité atteint bien DefectDojo.

## Okta

1. Dans la console d'administration Okta, accédez à **Applications > Browse App Catalog** et ajoutez **SCIM 2.0 Test App (Header Auth)**. Si vous avez déjà une application SAML pour DefectDojo, vous pouvez activer le provisionnement sur cette application à la place.

2. Ouvrez l'onglet **Provisioning** et sélectionnez **Configure API Integration**.

3. Définissez **SCIM 2.0 Base Url** avec la Tenant URL copiée ci-dessus.

4. Définissez **API Token** avec `Bearer <your token>`, en incluant le mot `Bearer` et un seul espace. Ce type d'application envoie la valeur telle quelle dans l'en-tête Authorization.

5. Sélectionnez **Test API Credentials**, puis enregistrez.

6. Sous **Provisioning > To App**, activez **Create Users**, **Update User Attributes** et **Deactivate Users**.

7. Attribuez des personnes ou des groupes à l'application. Okta recherche d'abord chaque personne dans DefectDojo par nom d'utilisateur et ne crée un compte que s'il n'en trouve aucun ; toute personne disposant déjà d'un compte DefectDojo est donc liée plutôt que dupliquée.

Pour également pousser des groupes, ouvrez l'onglet **Push Groups** et ajoutez les groupes que vous voulez que DefectDojo reproduise. Voir [Groupes](#groups) ci-dessous pour savoir ce que DefectDojo en fait.

## Microsoft Entra ID

1. Dans le centre d'administration Entra, accédez à **Enterprise applications > New application > Create your own application**, et choisissez l'option non-gallery. Si vous avez déjà une application pour DefectDojo, utilisez celle-ci.

2. Ouvrez **Provisioning** et définissez **Provisioning Mode** sur **Automatic**.

3. Définissez **Tenant URL** avec la Tenant URL copiée ci-dessus.

4. Définissez **Secret Token** avec votre jeton SCIM. Entra l'envoie sous forme de jeton bearer ; n'ajoutez donc pas le mot `Bearer` ici.

5. Sélectionnez **Test Connection**, puis enregistrez.

6. Attribuez des utilisateurs et des groupes sous **Users and groups**, puis démarrez le provisionnement.

Entra provisionne selon un cycle d'environ 40 minutes. Pendant la configuration, **Provision on demand** applique immédiatement un seul utilisateur ou groupe, ce qui permet de vérifier bien plus rapidement que la configuration fonctionne.

## Ce que DefectDojo stocke

DefectDojo associe un petit ensemble d'attributs SCIM et ignore le reste.

| Attribut SCIM | Champ DefectDojo |
|---|---|
| `userName` | Username |
| `name.givenName` | First name |
| `name.familyName` | Last name |
| `emails` | Email address |
| `active` | Indique si le compte est activé |
| `externalId` | Conservé pour que votre fournisseur d'identité puisse retrouver la fiche ultérieurement |

Les attributs que DefectDojo ne modélise pas, notamment les numéros de téléphone, les intitulés de poste et l'extension enterprise de SCIM, sont acceptés et ignorés plutôt que rejetés. Mapper des attributs supplémentaires dans votre fournisseur d'identité est sans danger.

Deux attributs méritent une attention particulière :

**Username.** DefectDojo autorise les lettres, les chiffres et les caractères `@ . + - _` dans un nom d'utilisateur. Si votre fournisseur d'identité envoie un nom d'utilisateur contenant autre chose, DefectDojo rejette cet utilisateur avec une erreur nommant le problème plutôt que de stocker discrètement un nom d'utilisateur différent. Stocker un nom d'utilisateur modifié empêcherait ensuite votre fournisseur de retrouver le compte.

**Email address.** SCIM ne l'exige pas, et DefectDojo créera l'utilisateur sans elle. Gardez à l'esprit que les notifications DefectDojo, y compris les rapports planifiés et les alertes, n'ont nulle part où aller pour un utilisateur sans adresse e-mail. Mappez l'attribut `emails` sauf raison contraire.

SCIM ne définit jamais de mots de passe et n'accorde jamais de statut superuser ou staff. Si votre fournisseur d'identité est configuré pour envoyer des mots de passe, DefectDojo les ignore. Les utilisateurs provisionnés de cette manière se connectent via le SSO.

## Groupes

SCIM ne gère que les groupes qu'il a créés. Les groupes que vous avez créés dans l'interface DefectDojo, ou qui proviennent d'un mappage de groupes SAML ou Azure AD, sont invisibles pour SCIM et ne peuvent pas être renommés, vidés ou supprimés par votre fournisseur d'identité.

Cela importe car le push de groupe est par nature un remplacement complet. Si un fournisseur d'identité pouvait adopter un groupe existant, sa prochaine synchronisation remplacerait la composition soigneusement choisie de ce groupe par le contenu de l'annuaire. Pousser un groupe dont le nom est déjà pris échoue donc avec un message expliquant le conflit. Pour confier un groupe existant à votre fournisseur d'identité, renommez l'un des deux, ou supprimez le groupe DefectDojo et laissez le fournisseur le recréer.

Au sein d'un groupe géré par SCIM, l'appartenance appartient à votre fournisseur d'identité et les rôles appartiennent à DefectDojo :

* Un membre nouvellement ajouté se voit attribuer le rôle **Reader**.
* Si vous promouvez quelqu'un à un rôle supérieur dans DefectDojo, les synchronisations suivantes laissent ce rôle inchangé.
* Toute personne ajoutée manuellement à un groupe géré par SCIM est supprimée lors de la synchronisation suivante, car le fournisseur d'identité fait foi pour déterminer qui en fait partie.

Supprimer un groupe via SCIM supprime le groupe et ses appartenances. Cela ne supprime jamais les personnes qui en faisaient partie.

## Protection de l'accès administrateur

Par défaut, SCIM ne désactivera pas un compte superuser. Le problème courant dans toute configuration de provisionnement est un fournisseur d'identité dont le périmètre est plus large que prévu, et les superusers constituent le moyen de retrouver l'accès à DefectDojo lorsque quelque chose tourne mal.

Si vous voulez que votre fournisseur d'identité gère aussi les superusers, activez **Allow SCIM to deactivate superusers** sur la page des paramètres SCIM. Même dans ce cas, DefectDojo refuse de désactiver le dernier superuser actif restant, afin que le provisionnement ne puisse pas laisser l'instance sans administrateur.

## Limitations

* Un seul fournisseur d'identité par instance DefectDojo.
* Le filtrage est pris en charge sur `userName`, `displayName`, `externalId` et `id`, à l'aide d'une seule comparaison d'égalité. Cela couvre ce qu'Okta et Entra envoient lorsqu'ils font correspondre des fiches. Les filtres plus complexes sont rejetés avec une erreur qui l'indique.
* Les opérations en masse, le tri et le point de terminaison `/Me` ne sont pas implémentés.
* Les appartenances aux groupes sont gérées via le point de terminaison Groups. Envoyer une appartenance de groupe sur une fiche utilisateur n'a aucun effet, ce qui correspond au comportement des deux fournisseurs.

## Dépannage

**Le test de connexion signale « not found ».** SCIM est désactivé, ou l'instance n'est pas licenciée pour cela. Vérifiez que **Enable SCIM Provisioning** est activé et que votre abonnement inclut le SSO. L'ensemble de l'adresse SCIM se comporte comme si elle n'existait pas tant que les deux conditions ne sont pas réunies.

**Le test de connexion signale un échec d'authentification.** Le jeton est incorrect, ou il a été révoqué. Générez-en un nouveau et mettez à jour votre fournisseur d'identité. Dans Okta, vérifiez que la valeur commence par `Bearer ` et un espace ; dans Entra, vérifiez que ce n'est pas le cas.

**Un utilisateur ne parvient pas à être provisionné, avec une erreur concernant le nom d'utilisateur.** Le nom d'utilisateur contient des caractères que DefectDojo n'autorise pas. Modifiez l'attribut que votre fournisseur d'identité mappe sur `userName`, le plus souvent vers l'adresse e-mail de l'utilisateur ou son user principal name.

**Un groupe ne parvient pas à être poussé, avec un message indiquant qu'un groupe de ce nom existe déjà.** Un groupe DefectDojo portant ce nom a été créé ailleurs. Voir [Groupes](#groups) ci-dessus.

**Un membre de groupe ne parvient pas à être provisionné.** La personne n'a pas encore été provisionnée dans DefectDojo. Attribuez-lui l'application, et l'appartenance réussira lors du cycle suivant.

**Commencez par Diagnostics.** Les requêtes SCIM refusées sont enregistrées sous **Connect > Diagnostics**, avec le point de terminaison, le statut et le message renvoyé par DefectDojo. C'est généralement plus rapide que de lire le journal de votre fournisseur d'identité, et c'est le seul endroit qui montre les deux côtés de l'échange. Le provisionnement réussi n'y est pas enregistré ; les modifications apportées aux utilisateurs et aux groupes apparaissent dans l'historique d'audit.

**Tout est signalé comme réussi, mais rien n'apparaît dans DefectDojo.** Vérifiez que la Tenant URL se termine par `/scim/v2` sans barre oblique finale, et que votre fournisseur d'identité atteint bien votre instance. La colonne **Last Used** du panneau SCIM Tokens indique si une requête est déjà arrivée.

**Utilisateurs DefectDojo Pro :** si votre instance restreint l'accès par adresse IP, ajoutez les adresses de votre fournisseur d'identité à la liste blanche du pare-feu avant de configurer SCIM. Voir [Règles de pare-feu](/get_started/pro/cloud/using-cloud-manager/#changing-your-firewall-settings).
