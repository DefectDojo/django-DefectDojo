---
title: "AWS Security Hub"
description: "Cómo configurar el Conector Upstream de AWS Security Hub para DefectDojo"
weight: 117
audience: pro
---
El conector de AWS Security Hub usa una clave de acceso de AWS para interactuar con las API de Security Hub.

#### Prerrequisitos

En lugar de usar la clave de acceso de AWS de un miembro del equipo, recomendamos crear un IAM User en su cuenta de AWS específicamente para DefectDojo, con los permisos de ese usuario limitados a los necesarios para interactuar con Security Hub.

La política "**[AWSSecurityHubReadOnlyAccess](https://docs.aws.amazon.com/aws-managed-policy/latest/reference/AWSSecurityHubReadOnlyAccess.html)**" de AWS proporciona el nivel de acceso necesario para un conector. Si desea escribir una política personalizada para un Conector, deberá incluir los siguientes permisos:

* [DescribeHub](https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_DescribeHub.html)
* [GetFindingAggregator](https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_GetFindingAggregator.html)
* [GetFindings](https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_GetFindings.html)
* [ListFindingAggregators](https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_ListFindingAggregators.html)

Una definición de política funcional podría verse de la siguiente manera:

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

**Tenga en cuenta:** es posible que en el futuro necesitemos usar acciones de API adicionales para ofrecer la mejor experiencia posible, lo que requerirá actualizaciones de esta política.

Una vez que haya creado su usuario de IAM y le haya asignado los permisos necesarios mediante una política/rol adecuado, deberá generar una clave de acceso, que luego podrá usar para crear un Conector.

#### Asignaciones del conector

1. Ingrese el [AWS API Endpoint correspondiente a su región](https://docs.aws.amazon.com/general/latest/gr/sechub.html#sechub_region) en el campo **Location****:**  por ejemplo, para obtener resultados de la región `us-east-1`, debería usar

`https://securityhub.us-east-1.amazonaws.com`
2. Ingrese una **AWS Access Key** válida en el campo **Access Key**.
3. Ingrese una **Secret Key** correspondiente en el campo **Secret Key**.

DefectDojo puede extraer Hallazgos de más de una región mediante la función de **agregación entre regiones** de Security Hub. Si la [agregación entre regiones](https://docs.aws.amazon.com/securityhub/latest/userguide/finding-aggregation.html) está habilitada, debe proporcionar el endpoint de la API de su "**Aggregation Region**". Para las regiones adicionales vinculadas se crearán ProductRecords en DefectDojo según el ID de su cuenta de AWS y el nombre de la región.
