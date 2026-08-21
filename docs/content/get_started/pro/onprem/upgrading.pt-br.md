---
title: Atualizando o DefectDojo Pro (on-premise)
description: Procedimento de upgrade suportado para implantações autogerenciadas do
  DefectDojo Pro usando o Helm chart
draft: false
weight: 7
audience: pro
---

Esta página descreve o procedimento de upgrade suportado para implantações autogerenciadas do DefectDojo Pro que usam o Helm chart do DefectDojo Pro.

## Atualize tudo como uma única unidade

Cada release do DefectDojo Pro consiste em uma versão do Helm chart, versões de imagens de container e os arquivos de configurações do Pro. Eles são construídos e testados em conjunto, e precisam ser atualizados juntos, como uma única unidade.

Atualizar apenas as tags de imagem não é suportado e vai quebrar a sua implantação.

## Arquivos de configurações e upgrades

O DefectDojo Pro distribui um arquivo `pro_settings.py` em cada release, e o arquivo muda em praticamente todas as versões. Não carregue uma cópia antiga de `pro_settings.py` de um upgrade para outro, e não faça patch manual de uma cópia mais antiga. A aplicação sempre precisa rodar o `pro_settings.py` que corresponde à sua versão.

Coloque suas próprias customizações em `local_settings.py`, nunca em `pro_settings.py`. Seu `local_settings.py` é preservado entre os upgrades.

O Helm chart distribui e monta automaticamente o `pro_settings.py` correspondente e o seu `local_settings.py`. Quando você faz upgrade usando o chart, não há nada para copiar ou migrar manualmente.

## Procedimento de upgrade suportado

1. Revise as notas de release de cada versão entre a sua versão atual e a versão de destino, não apenas a versão de destino em si. Consulte o [Changelog do DefectDojo Pro](/releases/pro/changelog/) e as [notas de upgrade](/releases/os_upgrading/upgrading_guide/) específicas de cada versão.
2. Faça backup do seu banco de dados.
3. Atualize para o release do Helm chart que corresponde à versão de destino da aplicação, reaproveitando seus arquivos de values existentes. Não altere as tags de imagem de forma independente da versão do chart.

Se você tiver dúvidas sobre como atualizar sua implantação on-premise, entre em contato com [support@defectdojo.com](mailto:support@defectdojo.com).
