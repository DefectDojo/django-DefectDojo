---
title: Serviços
description: Rastreamento de Microsserviços
weight: 1
---

## O que é um Serviço?

Serviços (abreviação de Microsserviços) são um recurso opcional dentro dos Ativos que fornece contexto adicional sobre onde os Achados se originam dentro de um Ativo. Eles ajudam a isolar Achados a um componente específico de um Ativo, em vez do Ativo inteiro, proporcionando clareza e precisão nos relatórios em ambientes com arquiteturas complexas.

Os Serviços são úteis quando você precisa segmentar ainda mais os resultados provenientes de um Teste, ou se você espera ter múltiplas instâncias do mesmo Achado dentro de um pipeline de Reimportação que você não deseja deduplicar. Algumas ferramentas de scan podem criar Achados separados para cada localização de arquivo, e se você preferir manter essas instâncias de um Achado como Achados separados, os serviços podem ser uma forma útil de rotular essas diferentes localizações.

## Serviços no Pro

Os Serviços estão disponíveis na versão Pro, mas são amplamente substituídos pela capacidade de estabelecer relações pai-filho entre Ativos. Os Serviços alcançam o mesmo resultado e ainda podem ser úteis quando reestruturar os Ativos não é viável ou quando é necessário um escopo de deduplicação em nível de scan sem alterar a hierarquia de Ativos, mas eles removem contexto. Por exemplo, criticidade de negócio, receita e pessoal podem ser atribuídos a Ativos, mas não a Serviços. Dessa forma, os Serviços são úteis principalmente no contexto do DefectDojo OS.

## Como especifico um Serviço? 

A opção para especificar um Serviço está disponível nos formulários de Import Scan ou Reimport, dentro do menu suspenso de Campos Opcionais. A partir daí, a deduplicação fica restrita aos Testes que compartilham o mesmo valor de Serviço.

É importante destacar que os Serviços diferenciam maiúsculas de minúsculas. Se o Serviço da importação inicial foi identificado como “Service 1” (S maiúsculo) e você reimportar um scan que resolveu todos os problemas anteriores, mas identificar o Serviço como “service 1” (s minúsculo), a deduplicação não será aplicada ao Serviço pretendido.

## Como os Serviços funcionam? 

Os Serviços funcionam permitindo que você especifique a quais Testes anteriores as regras de deduplicação serão aplicadas na Reimportação. 

Se, por exemplo, você importar um scan e definir o Serviço como “Service 1,” e depois reimportar um segundo scan e definir o Serviço como “Service 2,” a deduplicação não será aplicada entre esses dois scans porque o Serviço é diferente.

Quaisquer reimportações subsequentes só deduplicarão os resultados anteriores do primeiro scan se o Serviço tiver sido definido como “Service 1,” e só deduplicarão os resultados anteriores do segundo scan se o Serviço tiver sido definido como “Service 2.” Essencialmente, se o Serviço for diferente entre duas versões de um scan reimportado, eles serão tratados como Achados diferentes, mesmo que os scans em si sejam idênticos. 

Neste exemplo, se, na reimportação, o Serviço não for definido como Service 1 nem como Service 2, e for deixado em branco, a deduplicação não será aplicada nem ao primeiro nem ao segundo scan, e apenas os Achados sem Serviço serão encerrados.

## Como os Serviços devem ser usados?

Na prática, os Serviços são mais úteis quando:

* Um único Ativo contém múltiplos componentes implantados de forma independente.
* Equipes diferentes são responsáveis por partes diferentes do mesmo Ativo.
* Os testes de segurança são realizados contra serviços individuais (por exemplo, ao escanear uma API específica ou um microsserviço).
