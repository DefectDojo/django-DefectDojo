---
title: "AWS Security Hub"
description: "Einrichtung des AWS Security Hub Upstream-Connectors für DefectDojo"
weight: 117
audience: pro
---
Der AWS-Security-Hub-Connector verwendet einen AWS-Zugriffsschlüssel, um mit den Security-Hub-APIs zu interagieren.

#### Voraussetzungen

Anstatt den AWS-Zugriffsschlüssel eines Teammitglieds zu verwenden, empfehlen wir, in Ihrem AWS-Konto speziell für DefectDojo einen IAM-Benutzer anzulegen, dessen Berechtigungen auf das für die Interaktion mit Security Hub Notwendige beschränkt sind.

Die AWS-Richtlinie „**[AWSSecurityHubReadOnlyAccess](https://docs.aws.amazon.com/aws-managed-policy/latest/reference/AWSSecurityHubReadOnlyAccess.html)**" bietet die für einen Connector erforderliche Zugriffsebene. Wenn Sie eine benutzerdefinierte Richtlinie für einen Connector schreiben möchten, müssen Sie die folgenden Berechtigungen einbeziehen:

* [DescribeHub](https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_DescribeHub.html)
* [GetFindingAggregator](https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_GetFindingAggregator.html)
* [GetFindings](https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_GetFindings.html)
* [ListFindingAggregators](https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_ListFindingAggregators.html)

Eine funktionierende Richtliniendefinition könnte wie folgt aussehen:

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

**Bitte beachten Sie:** Wir benötigen möglicherweise in Zukunft zusätzliche API-Aktionen, um die bestmögliche Erfahrung zu bieten, was Aktualisierungen dieser Richtlinie erfordern wird.

Sobald Sie Ihren IAM-Benutzer erstellt und ihm mit einer geeigneten Richtlinie/Rolle die notwendigen Berechtigungen zugewiesen haben, müssen Sie einen Zugriffsschlüssel generieren, den Sie dann zum Erstellen eines Connectors verwenden können.

#### Connector-Zuordnungen

1. Geben Sie den passenden [AWS-API-Endpunkt für Ihre Region](https://docs.aws.amazon.com/general/latest/gr/sechub.html#sechub_region) in das Feld **Location** ein**:** Um beispielsweise Ergebnisse aus der Region `us-east-1` abzurufen, würden Sie Folgendes angeben

`https://securityhub.us-east-1.amazonaws.com`
2. Geben Sie einen gültigen **AWS Access Key** in das Feld **Access Key** ein.
3. Geben Sie den passenden **Secret Key** in das Feld **Secret Key** ein.

DefectDojo kann mithilfe der Funktion **regionsübergreifende Aggregation** von Security Hub Befunde aus mehr als einer Region abrufen. Wenn die [regionsübergreifende Aggregation](https://docs.aws.amazon.com/securityhub/latest/userguide/finding-aggregation.html) aktiviert ist, sollten Sie den API-Endpunkt Ihrer „**Aggregation Region**" angeben. Für zusätzlich verknüpfte Regionen werden in DefectDojo anhand Ihrer AWS-Konto-ID und des Regionsnamens ProductRecords erstellt.
