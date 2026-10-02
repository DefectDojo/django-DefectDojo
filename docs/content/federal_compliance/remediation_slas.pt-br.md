---
title: Prazos de Remediação
description: As predefinições de SLA do FedRAMP Rev 5 e do FedRAMP VDR
weight: 4
audience: pro
---

O recurso vem com duas configurações de SLA prontas para uso. Atribua qualquer uma delas aos seus produtos
nas configurações de SLA, ou copie uma delas e a ajuste.

## FedRAMP Rev 5

| Severidade | Vence em |
| --- | --- |
| Crítica | 30 dias a partir da descoberta |
| Alto | 30 dias a partir da descoberta |
| Moderada | 90 dias |
| Baixo | 180 dias |

Os prazos são aplicados, e um achado listado no catálogo CISA KEV nunca é agendado além da sua data de
vencimento da CISA.

## FedRAMP VDR

As mesmas janelas básicas, ainda mais reduzidas conforme a explorabilidade e a exposição:

| Condição | Vence em |
| --- | --- |
| Exploração crível **e** acessível pela internet | 4 dias |
| Apenas exploração crível | 14 dias |
| Apenas acessível pela internet | 30 dias |
| Nenhum dos dois | As janelas do FedRAMP Rev 5 acima |

**Exploração crível** significa que o achado está listado no KEV, ou que sua pontuação EPSS está no seu
limite ou acima dele. **Acessível pela internet** é sinalizado por uma tag de achado — `internet-reachable`
por padrão.

Todos os limites, nomes de tags e contagens de dias são editáveis na configuração de SLA.

**O FedRAMP VDR se torna obrigatório em 7 de dezembro de 2026.** O padrão Vulnerability Detection and
Response do FedRAMP se torna obrigatório para provedores de serviços em nuvem nessa data. Adotar a
predefinição VDR antes disso é o caminho recomendado.

## Relação com o ledger

Os prazos de SLA determinam as datas de conclusão programadas dos itens do POA&M, e definem quais itens
contam como atrasados nas métricas mês a mês de um snapshot. Eles também decidem o que uma política de itens
de scan **somente vencidos** inclui — consulte [Perfil de Conformidade](../compliance_profile).

Para saber como prioridade e SLAs funcionam fora de um contexto federal, consulte
[Atribuir Prioridade, Risco e SLAs](/asset_modelling/pro_hierarchy/priority_sla/).
