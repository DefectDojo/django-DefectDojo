---
title: Conformidade Federal
description: Entregáveis de POA&M e ConMon do FedRAMP, avaliações CMMC Nível 2 e cobertura
  de controles NIST 800-53
summary: ''
draft: false
weight: 6
chapter: true
sidebar:
  collapsed: true
seo:
  title: ''
  description: ''
  canonical: ''
  robots: ''
audience: pro
exclude_search: true
---

O DefectDojo Pro consegue executar o lado de gestão de vulnerabilidades de um programa de conformidade federal. Ele mantém um Plano de Ação e Marcos (POA&M) no estilo FedRAMP para cada sistema, produz entregáveis mensais de Monitoramento Contínuo (ConMon) nos formatos oficiais Excel e OSCAL, pontua autoavaliações CMMC Nível 2 e mostra quais controles NIST 800-53 seus scanners realmente exercitam.

Tudo o que é descrito nesta seção fica na aba **Compliance** de um Asset.

## Habilitando o recurso

O Federal Compliance é entregue atrás da feature flag **Compliance**, que está em beta e desligada por padrão. Um administrador a habilita pelo menu de feature flags — veja [Feature Flags](/admin/feature_flags/pro__feature_flags/). Uma vez habilitada, uma aba Compliance aparece em cada Asset.

## Beta: confirme os resultados antes de confiar neles

**Este recurso está em beta.** As declarações de controles NIST 800-171 e 800-53 incluídas, os pesos de pontos do SPRS do DoD e as regras de elegibilidade para POA&M são fornecidos para ajudar você a acompanhar e estimar sua postura, e aguardam validação independente em relação aos documentos-fonte oficiais.

Pontuações SPRS, resultados de elegibilidade condicional e cobertura de controles são **consultivos**. Confirme-os com a Metodologia de Avaliação oficial NIST SP 800-171 do DoD e as diretrizes atuais do FedRAMP antes de confiar neles para uma certificação, uma submissão de avaliação ou qualquer finalidade contratual.

## Nesta seção

| Página | O que ela cobre |
| --- | --- |
| [Perfil de Conformidade](compliance_profile) | Registrar um Asset como um sistema e definir os fatos que aparecem em todo entregável |
| [O Registro de POA&M](poam_ledger) | Como os itens de POA&M são criados a partir dos achados, e as convenções que o registro segue |
| [Snapshots de ConMon](conmon_snapshots) | Entregáveis mensais em Excel e OSCAL do FedRAMP, e o serviço opcional de validação OSCAL |
| [Prazos de Remediação](remediation_slas) | Os presets de SLA do FedRAMP Rev 5 e do FedRAMP VDR |
| [Avaliações CMMC Nível 2](cmmc_assessments) | Pontuar uma autoavaliação em relação ao NIST 800-171 Rev 2 |
| [Cobertura de Controles](control_coverage) | Quais controles do 800-53 seus scanners testam, e as fraquezas abertas por controle |
