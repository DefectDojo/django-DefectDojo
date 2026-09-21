---
title: Sobre o DefectDojo
date: 2021-02-02 20:46:29+01:00
draft: false
type: docs
weight: 1
aliases:
- /pt-br/en/about_defectdojo/about_docs
---

<div class="version-opensource">

![image](images/dashboard.png)

</div>
<div class="version-pro">

![image](images/Introduction_to_Dashboard_Features.png)

</div>


<span style="background-color:rgba(242, 86, 29, 0.3)">A DefectDojo, Inc. e colaboradores open-source mantêm esta documentação para dar suporte às edições Community e Pro do DefectDojo.</span>

## O que é o DefectDojo?

O DefectDojo é uma plataforma de Developer Security Operations (DevSecOps). O DefectDojo simplifica o DevSecOps ao atuar como um agregador automático para o seu conjunto de ferramentas de segurança, permitindo que você organize facilmente o seu trabalho de segurança e reporte a postura de segurança da sua organização para outras partes interessadas.

Embora a automação de processos de segurança e os pipelines de desenvolvimento integrados sejam os objetivos finais do DefectDojo, no seu núcleo este software é um rastreador de bugs para vulnerabilidades de segurança, projetado para ingerir, organizar e padronizar relatórios de diversas ferramentas de segurança.

### O que o DefectDojo faz?

O DefectDojo possui recursos inteligentes para aprimorar e ajustar os resultados das suas ferramentas de segurança, incluindo a capacidade de:

- Rastrear e reportar Achados de segurança em contexto
- Aplicar SLAs em contexto
- Lidar com Falsos positivos, Riscos aceitos e outras decisões de triagem
- Eliminar duplicados usando o algoritmo de deduplicação do DefectDojo
- Integrar-se com softwares externos de rastreamento de projetos.
- Fornecer métricas/relatórios entre repositórios e branches de desenvolvimento usando integração com CI/CD.
- Coordenar o gerenciamento tradicional de Pen tests.
- Definir e aplicar SLAs para procedimentos de remediação de vulnerabilidades.
- Criar e rastrear Aceitações de risco para vulnerabilidades de segurança.

Em última análise, o modelo Produto:Engajamento do DefectDojo permite que você faça o inventário do seu ambiente de desenvolvimento e coloque imediatamente novos Achados de segurança em contexto.

---
Aqui estão alguns exemplos de como o DefectDojo pode ser implementado, com o cofundador e CTO do DefectDojo, Matt Tesauro:
<iframe width="560" height="315" src="https://www.youtube.com/embed/44vv-KspHBs?si=OwfGHs2VTQ886-FB" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" referrerpolicy="strict-origin-when-cross-origin" allowfullscreen></iframe>

---

## DefectDojo Open-Source

A funcionalidade principal do DefectDojo está disponível na edição DefectDojo Open-Source.

Esta edição do DefectDojo inclui:

- Import/Reimport para mais de 500 ferramentas suportadas
- API REST
- Recursos de deduplicação
- Recursos limitados de UI, métricas e relatórios
- Capacidade de integração com o Jira

Para equipes que gerenciam um volume menor de Achados, o DefectDojo Open-Source é um ótimo ponto de partida.

### Guias de instalação

Existem algumas formas suportadas de instalar a edição Open-Source do DefectDojo ([disponível no Github](https://github.com/DefectDojo/django-DefectDojo)):

O [Docker Compose](https://github.com/DefectDojo/django-DefectDojo/blob/master/readme-docs/DOCKER.md) é o método mais fácil para instalar o programa principal e os serviços necessários para executar o DefectDojo.
Nosso guia de [Arquitetura](/get_started/open_source/architecture/) oferece uma visão geral de cada serviço e componente usado pelo DefectDojo.
[Executando em produção](/get_started/open_source/running-in-production/) lista os requisitos de sistema, ajustes de performance e processos de manutenção para executar o DefectDojo em um servidor de produção (com Docker Compose).

O Kubernetes não é totalmente suportado no nível Open-Source, mas este guia pode ser consultado e usado como ponto de partida para integrar o DefectDojo em uma arquitetura Kubernetes.

Se você encontrar problemas com uma instalação Open-Source, recomendamos fortemente que faça perguntas no [OWASP Slack](https://owasp.org/slack/invite). Os membros da nossa comunidade estão ativos no canal #defectdojo e podem ajudá-lo com os problemas que você está enfrentando.

## 🟧 Edição DefectDojo Pro

<iframe width="560" height="315" src="https://www.youtube.com/embed/XUES0mCCGOI?si=2GEnd1iHlLcQE0R3" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" referrerpolicy="strict-origin-when-cross-origin" allowfullscreen></iframe>

A DefectDojo, Inc. hospeda uma edição Pro deste software para fins comerciais. Além de uma UI moderna e elegante, o DefectDojo Pro inclui:

* [Connectors](/connectors/upstream/about/): integrações de API prontas para uso com scanners de nível empresarial (como Checkmarx One, BurpSuite, Semgrep e outros)
* **Métodos de importação configuráveis**: [Universal Parser](/supported_tools/parsers/universal_parser/), [Smart Upload](/import_data/pro/specialized_import/smart_upload/)
* **[Ferramentas de CLI](/import_data/pro/specialized_import/external_tools/)** para integração rápida com seus sistemas
* **[Integrações adicionais de rastreamento de projetos](/connectors/issue_tracking/)**: ServiceNow, Azure DevOps, GitHub e GitLab
* **[Métricas aprimoradas](/metrics_reports/pro_metrics/pro__overview/)** para relatórios executivos e análises de alto nível
* **[Prioridade e risco](/asset_modelling/pro_hierarchy/priority_sla/)** para identificar os Achados de maior urgência em todo o sistema
* **Suporte premium** e orientação de implementação para sua organização

A edição Pro está disponível como uma oferta SaaS hospedada na nuvem, e também está disponível para instalação on-premises.

Para mais informações sobre o DefectDojo Pro, confira nossa [página de preços](https://defectdojo.com/pricing).

## Demonstrações online

Demonstrações online estão disponíveis para as versões Open-Source e Pro do DefectDojo. Ambas podem ser acessadas usando as seguintes credenciais:

- Usuário: `admin`
- Senha: `1Defectdojo@demo#appsec`

Essas demonstrações vêm carregadas com dados de exemplo e são reiniciadas diariamente.

### Demonstração Open-Source

Um exemplo em execução do DefectDojo (edição Open-Source) está disponível em [https://demo.defectdojo.org/](https://demo.defectdojo.org/).

### Demonstração Pro

Um exemplo em execução do DefectDojo Pro está disponível em
[https://pro.demo.defectdojo.com/](https://pro.demo.defectdojo.com/).

## Aprendendo o DefectDojo

Seja você um usuário Pro ou Open-Source, temos muitos recursos para ajudá-lo a começar com o DefectDojo.

* Revise nossas [integrações de ferramentas de segurança](/supported_tools/) suportadas para ajudar a encaixar o DefectDojo no seu programa de DevSecOps.
* Nossa equipe mantém um [canal no YouTube](https://www.youtube.com/@defectdojo) que hospeda tutoriais, eventos de Office Hours arquivados e outros conteúdos.

## Fale conosco

Para entrar em contato com a equipe da DefectDojo, Inc., você sempre pode falar com [hello@defectdojo.com](mailto:hello@defectdojo.com).

Publicamos regularmente no [LinkedIn](https://www.linkedin.com/company/33245534) e também organizamos apresentações on-line para profissionais de AppSec que podem ser acessadas ao vivo ou sob demanda. Você pode saber mais sobre os próximos eventos na nossa [página de eventos](https://defectdojo.com/events) ou assistir a apresentações anteriores no nosso [canal do YouTube](https://www.youtube.com/@defectdojo).

### Adesivos

Procurando adesivos legais do DefectDojo para o seu laptop? Como forma de agradecimento por fazer parte da comunidade DefectDojo, você pode se cadastrar para receber adesivos gratuitos do DefectDojo. Para mais informações, confira [este link](https://defectdojo.com/defectdojo-sticker-request).
