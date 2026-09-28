---
title: Benchmarks do OWASP ASVS
description: Compare um Produto com o OWASP Application Security Verification Standard
  por meio de Benchmarks
weight: 6
audience: opensource
---

O DefectDojo oferece suporte à realização de benchmark de Produtos em relação ao [OWASP Application Security Verification Standard (ASVS)](https://owasp.org/www-project-application-security-verification-standard/), que fornece uma base para testar controles técnicos de segurança de aplicações web.

Os Benchmarks permitem medir o quanto um Produto atende aos requisitos de segurança definidos pela sua organização, além de publicar uma pontuação na página do Produto para maior visibilidade.

## Acessando Benchmarks

Os Benchmarks estão disponíveis na página **Product**. Para abrir a visualização de Benchmarks, selecione o menu suspenso no canto superior direito da página do Produto e escolha **OWASP ASVS v.3.1** próximo à parte inferior do menu.

## Níveis de Benchmark

O OWASP ASVS define três níveis de cobertura de verificação:

- **Nível 1** – Para todo software. Cobre os requisitos de segurança mais críticos com o menor custo de verificação. Este é o nível padrão no DefectDojo.
- **Nível 2** – Para aplicações que contêm dados sensíveis. Adequado para a maioria das aplicações.
- **Nível 3** – Para as aplicações mais críticas, como aquelas que realizam transações de alto valor ou armazenam dados sensíveis médicos, financeiros ou de segurança.

Você pode alternar entre os níveis usando o menu suspenso no canto superior direito da visualização de Benchmarks.

## Pontuação de Benchmark

O lado esquerdo da visualização de Benchmarks exibe a pontuação atual do seu Produto no nível ASVS selecionado:

- A **pontuação desejada** que sua organização definiu como meta
- A **porcentagem de benchmarks aprovados** em direção a essa pontuação
- O **número total de benchmarks habilitados** para o nível selecionado

Habilitar a caixa de seleção **Publicar** exibirá a pontuação do ASVS diretamente na página do Produto.

## Gerenciando Entradas de Benchmark

Entradas individuais de benchmark podem ser marcadas como aprovadas ou reprovadas à medida que sua equipe avança pelos controles do ASVS. Entradas adicionais de benchmark, além do conjunto padrão do ASVS, podem ser adicionadas ou atualizadas por meio do **Django admin site**.
