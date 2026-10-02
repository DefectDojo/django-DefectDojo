---
title: Perfil de Conformidade
description: Registre um Asset como um sistema e defina os fatos que aparecem em todo
  entregável
weight: 1
audience: pro
---

O Compliance Profile registra um Asset como um sistema e mantém os fatos que aparecem em todo entregável que ele produz. Abra o Asset que representa o limite do seu sistema, vá até a aba **Compliance** e depois **Profile**.

![O formulário do Compliance Profile](images/01-compliance-profile.png)

## Campos do perfil

| Campo | O que ele faz |
| --- | --- |
| **Enabled** | Ativa o rastreamento de conformidade para este produto. |
| **Automatic Sync** | Mantém os itens de POA&M sincronizados com os achados. |
| **POA&M ID Prefix** | Numeração dos itens. Obrigatório. Os itens são numerados como `V-1`, `V-2` e assim por diante por padrão. |
| **Impact Level** | LI-SaaS, Low, Moderate ou High. |
| **Cloud Service Provider** | O nome do CSP, como deve aparecer nos dados de capa do POA&M. |
| **System / Offering Name** | O nome do sistema, como deve aparecer nos dados de capa do POA&M. |
| **FedRAMP System Identifier** | O identificador do seu sistema, por exemplo `F00000042`. |
| **Default Point of Contact** | O POC aplicado aos itens que não têm um próprio. |
| **Scan Item Policy** | Incluir todos os itens abertos, ou apenas os itens de scan vencidos. |
| **OSCAL SSP Reference** | Opcional. Quando definido, os POA&Ms OSCAL gerados o referenciam através de `import-ssp`. |

### Escolhendo uma política de itens de scan

Apenas vencidos é o mínimo do ConMon do FedRAMP. **Include all open items** é a escolha mais conservadora, e é o padrão.

## Salvando e sincronizando

**Save Compliance Profile** registra o Asset. O registro de POA&M então é populado a partir dos achados existentes do Asset, e o restante da aba Compliance fica disponível.

Com **Automatic Sync** ativado, o registro se mantém atualizado sozinho — veja [O Registro de POA&M](../poam_ledger). **Sync POA&M Now** executa uma sincronização imediatamente, o que é útil logo depois que você muda o perfil ou importa um novo scan.

## Configurações disponíveis apenas pela API

Duas configurações do perfil não estão no formulário e são definidas através da API de compliance:

* **Default scan controls** — os controles atribuídos aos achados de scanner que não têm mapeamento de controle próprio. `RA-5` é a escolha comum para resultados de scan de vulnerabilidades. Achados que *têm* suas próprias referências de controle são mapeados a partir delas; veja [Cobertura de Controles](../control_coverage).
* **Configuration test types** — os tipos de teste cujos achados são tratados como itens de configuração, o que é o que impulsiona a consolidação CM-6 no registro.

## Auditabilidade

Os perfis de conformidade ficam sob o histórico de auditoria: cada mudança registra quem mudou o quê, e quando.
