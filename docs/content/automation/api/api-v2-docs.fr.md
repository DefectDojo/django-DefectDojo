---
title: API v2 de DefectDojo
description: L'API de DefectDojo vous permet d'automatiser des tâches, par exemple
  l'envoi de rapports de scan dans des pipelines CI/CD.
draft: false
weight: 2
aliases:
- /fr/en/api/api-v2-docs
---

L'API de DefectDojo est créée avec [Django Rest
Framework](http://www.django-rest-framework.org/). La documentation de
chaque endpoint est disponible dans chaque installation de DefectDojo à
l'adresse [`/api/v2/oa3/swagger-ui`](https://demo.defectdojo.org/api/v2/oa3/swagger-ui/) et est accessible en choisissant le lien API v2
Docs dans le menu déroulant utilisateur de l'en-tête.

![image](images/api_v2_1.png)

La documentation est générée avec [drf-spectacular](https://drf-spectacular.readthedocs.io/) à l'adresse [`/api/v2/oa3/swagger-ui/`](https://demo.defectdojo.org/api/v2/oa3/swagger-ui/), et elle est
interactive. En haut de la documentation API v2 se trouve un lien qui génère une spécification OpenAPI v3.

Pour interagir avec la documentation, une valeur d'en-tête Authorization valide
est nécessaire. Visitez la vue `/api/key-v2` pour générer votre
clé API (`Token <api_key>`) et copiez la valeur d'en-tête fournie.

![image](images/api_v2_2.png)

Chaque section vous permet d'effectuer des appels à l'API et de consulter l'URL de la
requête, le corps de la réponse, le code de réponse et les en-têtes de réponse.

![image](images/api_v2_3.png)

Si vous êtes connecté à l'interface web de Defect Dojo, vous n'avez pas besoin de fournir le jeton d'autorisation.

## Authentication

L'API utilise une authentification par en-tête avec une clé API. Le format de l'en-tête doit être :

    Authorization: Token <api.key>

Par exemple :

    Authorization: Token c8572a5adf107a693aa6c72584da31f4d1f1dcff

### Alternative authentication method

Si vous utilisez [une méthode d'authentification alternative](/admin/sso/) pour les utilisateurs, vous pouvez souhaiter désactiver les jetons API de DefectDojo, car cela pourrait contourner votre dispositif d'authentification. \
L'utilisation des jetons API de DefectDojo peut être désactivée en définissant la variable d'environnement `DD_API_TOKENS_ENABLED` sur `False`.
Ou seul l'endpoint `api/v2/api-token-auth/` peut être désactivé en définissant `DD_API_TOKEN_AUTH_ENDPOINT_ENABLED` sur `False`.

## Sample Code

Voici quelques exemples simples en python et les résultats produits sur
l'endpoint `/users` :

{{< highlight python >}}
import requests

url = 'http://127.0.0.1:8000/api/v2/users'
headers = {'content-type': 'application/json',
            'Authorization': 'Token c8572a5adf107a693aa6c72584da31f4d1f1dcff'}
r = requests.get(url, headers=headers, verify=True) # set verify to False if ssl cert is self-signed

for key, value in r.__dict__.items():
  print(f"'{key}': '{value}'")
  print('------------------')
{{< /highlight >}}

Ce code retourne la liste de tous les utilisateurs définis dans DefectDojo.
Le résultat de l'objet json ressemble à ceci :

{{< highlight json >}}
    [
        {
          "first_name": "Tyagi",
          "id": 22,
          "last_login": "2019-06-18T08:05:51.925743",
          "last_name": "Paz",
          "username": "dev7958"
        },
        {
          "first_name": "saurabh",
          "id": 31,
          "last_login": "2019-06-06T11:44:32.533035",
          "last_name": "",
          "username": "saurabh.paz"
        }
    ]
{{< /highlight >}}

Voici un autre exemple sur l'endpoint `/users`, cette
fois nous allons filtrer les résultats pour n'inclure que les utilisateurs
dont le nom d'utilisateur contient `jay` :

{{< highlight python >}}
import requests

url = 'http://127.0.0.1:8000/api/v2/users/?username__contains=jay'
headers = {'content-type': 'application/json',
            'Authorization': 'Token c8572a5adf107a693aa6c72584da31f4d1f1dcff'}
r = requests.get(url, headers=headers, verify=True) # set verify to False if ssl cert is self-signed

for key, value in r.__dict__.items():
  print(f"'{key}': '{value}'")
  print('------------------')
{{< /highlight >}}

Le résultat de l'objet json est :

{{< highlight json >}}
[
    {
        "first_name": "Jay",
        "id": 22,
        "last_login": "2015-10-28T08:05:51.925743",
        "last_name": "Paz",
        "username": "jay7958"
    },
    {
        "first_name": "",
        "id": 31,
        "last_login": "2015-10-13T11:44:32.533035",
        "last_name": "",
        "username": "jay.paz"
    }
]
{{< /highlight >}}

Consultez la [documentation de Django Rest Framework sur l'interaction avec une
API](https://www.django-rest-framework.org/) pour
d'autres exemples et astuces.

## Manually calling the API

Des outils comme Postman peuvent être utilisés pour tester l'API.

Exemple pour importer un résultat de scan :

-   Verbe : POST
-   URI : <http://localhost:8080/api/v2/import-scan/>
-   Onglet Headers :

    ajoutez l'en-tête d'authentification
    :   -   Clé : Authorization
        -   Valeur : Token c8572a5adf107a693aa6c72584da31f4d1f1dcff

-   Onglet Body

    -   sélectionnez « form-data », cliquez sur « bulk edit ». Exemple pour un scan ZAP :

<!-- -->

    engagement:3
    verified:true
    active:true
    lead:1
    tags:test
    scan_type:ZAP Scan
    minimum_severity:Info
    close_old_findings:false

-   Onglet Body

       -   Cliquez sur l'édition « Key-value »
       -   Ajoutez un paramètre « file » de type « file ». Cela déclenchera
            l'envoi de données multipart pour le contenu du fichier
       -   Parcourez pour sélectionner le fichier à envoyer

-   Cliquez sur send

## Clients / API Wrappers

| Wrapper                      | Statut                   | Notes |
| -----------------------------| ------------------------| ------------------------|
| [Wrapper python spécifique](https://github.com/DefectDojo/defectdojo_api)      | fonctionnel (2021-01-21)    | Wrapper API incluant des scripts pour l'envoi continu en CI/CD. Il accuse un léger retard sur les dernières fonctionnalités de l'API, car nous prévoyons de refondre le wrapper API |
| [Wrapper python Openapi](https://github.com/alles-klar/defectdojo-api-v2-client)       | | preuve de concept uniquement, où nous avons constaté que la spécification OpenAPI n'est pas encore parfaite |
| [Bibliothèque Java](https://github.com/secureCodeBox/defectdojo-client-java)                 | fonctionnel (2021-08-30)    | Créée par les sympathiques membres de [SecureCodeBox](https://github.com/secureCodeBox/secureCodeBox) |
| [Image utilisant la bibliothèque Java](https://github.com/SDA-SE/defectdojo-client) | fonctionnel (2021-08-30)    | |
| [Bibliothèque .Net/C#](https://www.nuget.org/packages/DefectDojo.Api/)              | fonctionnel (2021-06-08)    | |
| [dd-import](https://github.com/MaibornWolff/dd-import)                    | fonctionnel (2021-08-24)    | dd-import n'est pas directement un wrapper API. Il propose des fonctions pratiques pour faciliter l'import des constatations et des données de langage depuis des pipelines CI/CD. |

Certains wrappers API contiennent une bonne quantité de logique pour faciliter le scan et l'import dans des environnements CI/CD. Nous sommes en train de simplifier cela en rendant l'API DefectDojo plus intelligente (afin que les wrappers API / scripts puissent être plus simples).

## API Notes

### Import / Reimport

**Réimport** est en fait le moyen le plus simple pour démarrer, car il crée à la volée toutes les entités nécessaires et détecte automatiquement s'il s'agit d'un premier envoi ou d'un nouvel envoi.

## Import
L'import via l'API s'effectue via l'endpoint [import-scan](https://demo.defectdojo.org/api/v2/doc/).

Comme décrit dans [Hiérarchie des produits](/asset_modelling/os_hierarchy/product_hierarchy/), un Test est créé à l'intérieur d'un Engagement, lui-même à l'intérieur d'un Produit, lui-même à l'intérieur d'un Type de produit.

Un import peut être effectué en spécifiant les noms de ces entités dans la requête API :


```JSON
{
    "minimum_severity": 'Info',
    "active": True,
    "verified": True,
    "scan_type": 'ZAP Scan',
    "test_title": 'Manual ZAP Scan by John',
    "product_type_name": 'Good Products',
    "product_name": 'My little product',
    "engagement_name": 'Important import',
    "auto_create_context": True,
}
```

Lorsque `auto_create_context` est à `True`, le produit, l'engagement et l'environnement sont créés si nécessaire. Assurez-vous que votre utilisateur dispose des [permissions](/admin/user_management/about_perms_and_roles/) suffisantes pour cela.

Une façon classique d'importer un scan consiste à spécifier plutôt l'ID de l'engagement :

```JSON
{
    "minimum_severity": 'Info',
    "active": True,
    "verified": True,
    "scan_type": 'ZAP Scan',
    "test_title": 'Manual ZAP Scan by John',
    "engagement": 123,
}
```

## Reimport
Le réimport via l'API s'effectue via l'endpoint [reimport-scan](https://demo.defectdojo.org/api/v2/doc/).

Un réimport peut être effectué en spécifiant les noms de ces entités dans la requête API :


```JSON
{
    "minimum_severity": 'Info',
    "active": True,
    "verified": True,
    "scan_type": 'ZAP Scan',
    "test_title": 'Manual ZAP Scan by John',
    "product_type_name": 'Good Products',
    "product_name": 'My little product',
    "engagement_name": 'Important import',
    "auto_create_context": True,
    "do_not_reactivate": False,
}
```

Lorsque `auto_create_context` est à `True`, le Type de produit, le Produit et l'Engagement sont créés s'ils n'existent pas déjà. Assurez-vous que votre utilisateur dispose des [permissions](/admin/user_management/about_perms_and_roles/) suffisantes pour créer un Produit/Type de produit.

Lorsque `do_not_reactivate` est à `True`, l'import/réimport ignore les constatations actives envoyées et ne réactive pas les constatations précédemment clôturées, tout en créant malgré tout de nouvelles constatations s'il y en a. Une note est ajoutée à la constatation pour expliquer qu'elle n'a pas été réactivée pour cette raison.

Un réimport sélectionne automatiquement le test le plus récent au sein de l'engagement fourni qui correspond au `scan_type` fourni et, éventuellement, au `test_title` fourni.

Si aucun Test existant n'est trouvé, l'endpoint de réimport utilise la fonction d'import pour importer le rapport fourni dans un nouveau Test. Cela signifie qu'un script (CI/CD) utilisant l'API n'a pas besoin de savoir si un Test existe déjà, ni s'il s'agit d'un premier envoi pour ce Produit / Engagement.

Une façon classique de réimporter un scan consiste à spécifier plutôt l'ID du test :

```JSON
{
    "minimum_severity": 'Info',
    "active": True,
    "verified": True,
    "scan_type": 'ZAP Scan',
    "test": 123,
}
```

## Generating Reports

DefectDojo peut générer un rapport de constatations via l'API aux formats **JSON**, **HTML**, **CSV** ou **Excel**.

Un rapport est généré via une requête `POST` vers une action `generate_report/`. L'endpoint findings génère un rapport sur l'ensemble de votre instance, et la plupart des autres objets exposent une action par objet :

| Endpoint | Portée |
|---|---|
| `POST /api/v2/findings/generate_report/` | Toutes les constatations que vous avez la permission de consulter |
| `POST /api/v2/products/{id}/generate_report/` | Un produit |
| `POST /api/v2/engagements/{id}/generate_report/` | Un engagement |
| `POST /api/v2/tests/{id}/generate_report/` | Un test |
| `POST /api/v2/product_types/{id}/generate_report/` | Un type de produit |
| `POST /api/v2/endpoints/{id}/generate_report/` | Un point de terminaison |

Les alias d'objets Pro exposent la même action : `/api/v2/assets/{id}/generate_report/`, `/api/v2/organizations/{id}/generate_report/`, et `/api/v2/location/{id}/generate_report/`.

### Request options

Tous les champs sont facultatifs — l'envoi d'un corps vide (`{}`) renvoie un rapport JSON.

| Field | Type | Default | Description |
|---|---|---|---|
| `report_type` | string | `JSON` | L'une des valeurs `JSON`, `HTML`, `CSV`, `Excel`. |
| `include_finding_notes` | boolean | `false` | Inclut les notes de chaque constatation. |
| `include_finding_images` | boolean | `false` | Inclut les images jointes aux constatations. |
| `include_executive_summary` | boolean | `false` | Inclut une section de résumé exécutif. |
| `include_table_of_contents` | boolean | `false` | Inclut une table des matières. |

Un `report_type` non pris en charge (par exemple `PDF`) renvoie une erreur `400 Bad Request` sur le champ `report_type`.

### Example

Génère un rapport CSV de toutes les constatations que vous pouvez consulter, et l'enregistre dans un fichier :

```bash
curl -X POST \
  -H "Authorization: Token <your-api-token>" \
  -H "Content-Type: application/json" \
  -d '{"report_type": "CSV"}' \
  https://<your-instance>/api/v2/findings/generate_report/ \
  -o findings.csv
```

### Response formats

| `report_type` | Type de contenu | Réponse |
|---|---|---|
| `JSON` (par défaut) | `application/json` | Corps du rapport dans la réponse |
| `HTML` | `text/html` | Page du rapport rendue |
| `CSV` | `text/csv` | Pièce jointe (fichier) |
| `Excel` | `application/vnd.openxmlformats-officedocument.spreadsheetml.sheet` | Pièce jointe `.xlsx` |

CSV et Excel sont renvoyés en pièce jointe avec un en-tête `Content-Disposition`, plutôt que sous forme de corps JSON. Le nom du fichier est dérivé de l'objet à partir duquel le rapport a été généré — par exemple `product_1_findings.csv` ou `test_42_findings.xlsx`. L'endpoint `/findings/generate_report/` n'est pas rattaché à un objet unique, ses téléchargements sont donc nommés `findings.csv` et `findings.xlsx`.

### Notes and limitations

* Les options `include_*` n'affectent que les rapports **JSON** et **HTML**. Les exports **CSV** et **Excel** contiennent toujours les lignes de constatations.
* La génération de rapport nécessite la permission **view** sur les objets concernés, et un rapport ne contient jamais que les constatations que vous êtes autorisé à voir.
* **Les filtres de paramètres de requête standard ne s'appliquent pas à cette action.** Contrairement à `GET /api/v2/findings/`, l'action `generate_report/` n'applique pas les filtres de constatations : une requête telle que `POST /api/v2/findings/generate_report/?severity=High` porte donc toujours sur toutes les constatations que vous pouvez consulter. Pour restreindre un rapport, générez-le plutôt depuis un produit, un engagement ou un test spécifique.

## Asynchronous Deletion Behavior

Les suppressions dans DefectDojo (via l'API comme via l'UI) sont traitées **de façon asynchrone** par des workers Celery en arrière-plan. Lorsque vous supprimez un Engagement, un Test ou un autre objet, l'API ou l'UI renvoie immédiatement une réponse de succès, mais la suppression réelle s'exécute en arrière-plan.

Cela signifie que :
- Les objets peuvent encore apparaître dans les requêtes pendant un certain temps après la confirmation de la suppression.
- Les suppressions en cascade (par exemple, la suppression d'un Engagement supprime également ses Tests et ses Constatations) sont traitées comme une chaîne de tâches en arrière-plan. Les objets enfants sont supprimés dans l'ordre de dépendance : les Constatations, puis les Tests, puis les Engagements.
- Pour les Engagements volumineux comportant de nombreuses Constatations, ce processus peut prendre plusieurs minutes.

Il n'est pas nécessaire de créer des scripts personnalisés pour supprimer les objets dans l'ordre de dépendance. Une seule requête `DELETE` sur un Engagement se propage automatiquement à tous les objets enfants. Il suffit de laisser le temps aux tâches en arrière-plan de se terminer.

## API Pagination Limits

DefectDojo Pro impose une taille de page maximale de **250** résultats par requête API. Définir `limit` à une valeur supérieure à 250 peut entraîner des erreurs HTTP 502 dues à des délais d'attente de requête dépassés.

Les instances DefectDojo Open Source peuvent également rencontrer des délais d'attente dépassés avec des tailles de page très importantes, selon la taille du jeu de données et les ressources du serveur.

Pour les ensembles de résultats volumineux, utilisez une pagination avec une taille de page de 50 à 250 et ajoutez de courts délais entre les requêtes paginées afin d'éviter de saturer le pool de workers.

## Large-Scale Import Best Practices

Lors de l'import de résultats de scan à grande échelle (par exemple des pipelines SBOM comportant des milliers de composants), tenez compte des points suivants :

- **Utilisez `background_import=true`** pour les charges volumineuses. Les imports synchrones monopolisent un worker uwsgi pendant toute la durée de l'import, ce qui peut dégrader les performances pour tous les utilisateurs.
- **Visez des charges de moins de 1 Mo par import** lorsque c'est possible. Découpez les gros SBOM en fichiers plus petits par produit ou groupe de composants.
- **Ajoutez des délais entre les appels API consécutifs** pour éviter l'épuisement du pool de workers, qui provoque des erreurs HTTP 502.
- **Utilisez le Réimport** (`/api/v2/reimport-scan/`) pour les scans récurrents afin de mettre à jour les constatations existantes plutôt que de créer des doublons.

## Background import responses (API: `background_import`)

Un import en arrière-plan renvoie une réponse dès que le rapport envoyé a été analysé, avant que
la moindre constatation ait été écrite. Sa réponse décrit donc un travail *planifié*, et sa forme
diffère de celle d'un import synchrone. Cela s'applique à `/api/v2/import-scan/` et
`/api/v2/reimport-scan/` chaque fois que `background_import` vaut `true`, ou chaque fois que le
paramètre système `api_async_import` l'active pour tous les imports.

Une réponse en arrière-plan contient :

- `background_import` — `true`. C'est le champ sur lequel se brancher.
- `status` — le statut du cycle de vie du test au moment où la réponse a été produite :
  `Processing`, `Post Processing - Deduplication`,
  `Post Processing - False Positive History`, `Processed` ou `Failed`.
- `findings_parsed` — le nombre de constatations lues dans le rapport. Il s'agit d'un compte
  d'analyse, pas d'un compte de créations : la déduplication et les options d'import fournies
  déterminent le nombre de constatations réellement écrites.
- `test_id` (ainsi que `engagement_id`, `product_id`, `product_type_id`) — les identifiants à
  interroger.
- `message` — la même information que `status` et `findings_parsed`, sous forme de texte.
  Préférez les champs structurés.

Elle ne contient **pas** `statistics`, ni `deduplication_complete`.
Ces clés sont absentes plutôt qu'à zéro, car à ce stade aucune constatation n'a été
créée et indiquer des zéros décrirait mal l'import. Un client qui lit
`response["statistics"]` sans condition échouera sur un import en arrière-plan — lisez
`background_import` en premier, ou n'utilisez `statistics` que sur le chemin synchrone.

Pour suivre un import en arrière-plan jusqu'à son terme, interrogez le test :

```
POST /api/v2/import-scan/        (background_import=true)  -> test_id, status, findings_parsed
GET  /api/v2/tests/{test_id}/                              -> status, processing
```

Répétez le `GET` jusqu'à ce que `status` vaille `Processed` (l'import est terminé, et les
décomptes de constatations du test sont désormais significatifs) ou `Failed` (l'import ne s'est
pas terminé). Pendant que l'import est en cours, `processing` vaut `true` et `status` indique
dans quelle phase il se trouve. Laissez quelques secondes entre les interrogations ; un gros
rapport peut passer plusieurs minutes en post-traitement.

Un import synchrone (`background_import` omis ou `false`) reste inchangé : il renvoie une réponse
une fois les constatations écrites, inclut `statistics`, et n'inclut pas `status`
ni `findings_parsed`.

## Using the Scan Completion Date (API: `scan_date`) field

DefectDojo prend en charge une multitude de rapports de scanners, mais tous ne contiennent pas
l'information la plus importante pour un utilisateur. Le champ `scan_date` est une fonctionnalité
intelligente et flexible qui permet aux utilisateurs de définir la date de fin d'un rapport de
scan donné, et de la propager à toutes les constatations importées. Ce champ n'est **pas**
obligatoire, mais sa valeur par défaut est la date d'import (au moment où la requête est traitée
et où une réponse de succès est renvoyée).

Voici les cas d'usage possibles pour ce champ :

1. Le rapport **ne définit pas** la date, et `scan_date` n'est **pas** défini à l'import
    - La date de la constatation sera la valeur par défaut de `scan_date`
2. Le rapport **définit** la date, et `scan_date` n'est **pas** défini à l'import
    - La date de la constatation sera celle définie par le rapport
3. Le rapport **ne définit pas** la date, et `scan_date` **est** défini à l'import
    - La date de la constatation sera celle définie par l'utilisateur pour `scan_date`
4. Le rapport **définit** la date, et `scan_date` **est** défini à l'import
    - La date de la constatation sera celle définie par l'utilisateur pour `scan_date`
