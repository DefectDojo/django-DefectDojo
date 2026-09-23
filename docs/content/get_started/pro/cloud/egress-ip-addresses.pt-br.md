---
title: Endereços IP de Egress
description: Os endereços IP de saída (egress) a partir dos quais o DefectDojo Cloud
  se conecta, para inclusão na lista de permissões dos seus firewalls externos.
weight: 5
audience: pro
---

Quando o DefectDojo Cloud se conecta aos seus sistemas — Connectors sincronizando a
API de um scanner, enviando issues para o Jira ou ServiceNow, disparando webhooks
de notificação, ou entregando e-mails via SMTP — essas conexões são **iniciadas
de forma outbound** a partir do seu ambiente DefectDojo. Se o sistema do outro
lado estiver atrás de um firewall, você precisará permitir os endereços IP de
saída (egress) do DefectDojo para que essas conexões não sejam bloqueadas.

Esta página indica onde encontrar esses endereços IP de egress.

## Egress vs. ingress

São duas coisas diferentes, e esta página aborda apenas a primeira:

- **Egress (esta página)** — os endereços IP de origem a partir dos quais o
  DefectDojo Cloud se conecta quando ele alcança **sistemas externos** *da sua*
  organização. Inclua esses endereços na lista de permissões dos **seus**
  firewalls para que o DefectDojo consiga alcançar os sistemas com os quais ele
  se integra.
- **Ingress** — as regras que controlam quem tem permissão para acessar **sua**
  instância do DefectDojo. Essas regras são gerenciadas como Firewall Rules no
  Cloud Manager, não aqui. Consulte
  [Solução de problemas de conectividade](../connectivity-troubleshooting/) e a
  etapa de Firewall Rules em
  [Configurar uma instância adicional do Cloud](../additional-cloud-instance/).

## Implantações multi-tenant

Instâncias Standard, Pay-as-you-go e Premium são executadas em clusters
regionais compartilhados do Google Kubernetes Engine (GKE). As conexões
outbound partem dos endereços IP externos dos nós na região em que sua
instância é executada.

O conjunto atual de IPs de egress dos nós é publicado como um feed JSON,
agrupado por região:

<https://storage.googleapis.com/defectdojo-node-ips/node_ips.json>

O feed tem esta aparência:

```json
{
  "description": "External IPs for DefectDojo Cloud GKE nodes, grouped by region",
  "generated_at": "2026-08-06T20:17:26.372476+00:00",
  "regions": {
    "us-east4": [
      "34.21.115.236/32",
      "34.48.120.182/32"
    ],
    "europe-west3": [
      "34.40.61.46/32",
      "34.89.189.26/32"
    ]
  }
}
```

Para incluir na lista de permissões o tráfego de egress do DefectDojo:

1. Identifique a região em que sua instância é executada (o Server Location
   selecionado quando a instância foi provisionada).
2. Permita todos os endereços IP listados nessa região. Cada entrada é um CIDR
   `/32` (host único).

**Esta lista muda ao longo do tempo.** Nós são adicionados e substituídos
conforme a plataforma faz autoscaling, portanto o conjunto de IPs de egress de
uma região não é fixo. Trate o feed JSON como a fonte da verdade, em vez de
copiar os endereços apenas uma vez:

- Busque o feed de forma programática e atualize a lista de permissões do seu
  firewall a partir dele periodicamente, ou
- Reconsulte o feed e reconcilie suas regras periodicamente.

Se o seu firewall não conseguir acompanhar uma lista variável e você precisar
de um conjunto pequeno e estável de endereços, converse com o seu
representante DefectDojo sobre uma instância **Dedicated** (veja abaixo).

## Implantações single-tenant (Dedicated)

Uma instância de camada **Dedicated** é executada em seu próprio projeto GCP e
VPC, e seu endereço IP de egress é **estável** — ele é atribuído quando a
instância é provisionada e não muda conforme a plataforma escala.

Por estar vinculado à sua instância específica, o IP de egress estável não é
publicado no feed público. Entre em contato com
[support@defectdojo.com](mailto:support@defectdojo.com) para obter o(s)
endereço(s) IP de egress atribuído(s) à sua instância Dedicated, e inclua-os
na lista de permissões dos seus firewalls externos.

*Tem alguma dúvida que esta página não respondeu? Entre em contato com o seu
representante DefectDojo.*
