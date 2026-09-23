---
title: "AWS Security Hub"
description: "Comment configurer le Connecteur Upstream AWS Security Hub pour DefectDojo"
weight: 117
audience: pro
---
Le connecteur AWS Security Hub utilise une clé d'accès AWS pour interagir avec les API de Security Hub.

#### Prérequis

Plutôt que d'utiliser la clé d'accès AWS d'un membre de l'équipe, nous recommandons de créer un utilisateur IAM dans votre compte AWS spécifiquement pour DefectDojo, avec des permissions limitées à celles nécessaires pour interagir avec Security Hub.

La politique AWS « **[AWSSecurityHubReadOnlyAccess](https://docs.aws.amazon.com/aws-managed-policy/latest/reference/AWSSecurityHubReadOnlyAccess.html)**policy » fournit le niveau d'accès requis pour un connecteur. Si vous souhaitez rédiger une politique personnalisée pour un Connecteur, vous devrez inclure les permissions suivantes :

* [DescribeHub](https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_DescribeHub.html)
* [GetFindingAggregator](https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_GetFindingAggregator.html)
* [GetFindings](https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_GetFindings.html)
* [ListFindingAggregators](https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_ListFindingAggregators.html)

Un exemple de politique fonctionnelle pourrait ressembler à ceci :

```
{  
    "Version": "2012-10-17",  
    "Statement": [  
        {  
            "Sid": "AWSSecurityHubConnectorPerms",  
            "Effect": "Allow",  
            "Action": [  
                "securityhub:DescribeHub",  
                "securityhub:GetFindingAggregator",  
                "securityhub:GetFindings",  
                "securityhub:ListFindingAggregators"  
            ],  
            "Resource": "*"  
        }  
    ]  
}
```

**Veuillez noter :** nous pourrions avoir besoin d'utiliser des actions API supplémentaires à l'avenir afin d'offrir la meilleure expérience possible, ce qui nécessitera des mises à jour de cette politique.

Une fois que vous avez créé votre utilisateur IAM et lui avez attribué les permissions nécessaires à l'aide d'une politique/d'un rôle approprié, vous devrez générer une clé d'accès, que vous pourrez ensuite utiliser pour créer un Connecteur.

#### Mappages du Connecteur

1. Saisissez le [point de terminaison de l'API AWS correspondant à votre région](https://docs.aws.amazon.com/general/latest/gr/sechub.html#sechub_region) dans le champ **Location**\ :  par exemple, pour récupérer les résultats de la région `us-east-1`, vous fourniriez

`https://securityhub.us-east-1.amazonaws.com`
2. Saisissez une **AWS Access Key** valide dans le champ **Access Key**.
3. Saisissez la **Secret Key** correspondante dans le champ **Secret Key**.

DefectDojo peut récupérer des constatations depuis plusieurs régions grâce à la fonctionnalité d'**agrégation inter-régions** de Security Hub. Si l'[agrégation inter-régions](https://docs.aws.amazon.com/securityhub/latest/userguide/finding-aggregation.html) est activée, vous devez fournir le point de terminaison de l'API pour votre « **Aggregation Region** ». Pour les régions liées supplémentaires, des Enregistrements de Produit seront créés dans DefectDojo à partir de l'ID de votre compte AWS et du nom de la région.
