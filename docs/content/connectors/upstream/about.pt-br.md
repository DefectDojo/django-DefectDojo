---
title: Conectores Upstream
description: Conecte o DefectDojo ao seu conjunto de ferramentas de segurança sem
  esforço
summary: ''
date: 2023-09-07 16:06:50+02:00
lastmod: 2023-09-07 16:06:50+02:00
draft: false
weight: 0
chapter: true
sidebar:
  collapsed: true
seo:
  title: ''
  description: ''
  canonical: ''
  robots: ''
pro-feature: true
aliases:
- /pt-br/import_data/pro/connectors/about_connectors/
- /pt-br/en/connecting_your_tools/connectors/about_connectors
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Nota: Conectores Upstream são um recurso exclusivo do DefectDojo Pro.</span>

O DefectDojo permite que os usuários criem integrações de API sofisticadas e oferece controle total sobre como seus dados de vulnerabilidade são organizados.

Mas todo mundo precisa de um ponto de partida, e é aí que entram os Conectores Upstream. Os Conectores Upstream (anteriormente conhecidos como **API Connectors**) foram projetados para conectar suas ferramentas de segurança e importar dados para o DefectDojo o mais rápido possível.

Atualmente oferecemos suporte a Conectores Upstream para as seguintes ferramentas, com mais a caminho:

* **Acunetix 360**
* **Akamai API Security**
* **Anchore**
* **AWS Security Hub**
* **Azure DevOps**
* **Backstage**
* **Bitbucket**
* **Black Duck**
* **Bright Security**
* **Bugcrowd**
* **BurpSuite**
* **Censys**
* **Checkmarx ONE**
* **Cloudflare**
* **Cobalt.io**
* **Contrast**
* **Coverity**
* **CrowdStrike Falcon**
* **Deepfence ThreatMapper**
* **Dependency-Track**
* **Docker Scout**
* **Edgescan**
* **Endor Labs**
* **Escape**
* **Fairwinds Insights**
* **Fortify**
* **GitGuardian**
* **GitHub**
* **GitHub Advanced Security**
* **GitLab**
* **Google Cloud Security Command Center**
* **Group-IB ASM**
* **HackerOne**
* **Harbor**
* **Have I Been Pwned**
* **HCL AppScan**
* **Intigriti**
* **Intruder**
* **IriusRisk**
* **JFrog Xray**
* **Jira Service Management Assets**
* **Kubescape**
* **Lacework / FortiCNAPP**
* **Mend**
* **Microsoft Defender**
* **Microsoft Defender for Cloud**
* **MobSF**
* **NeuVector**
* **Nuclei (ProjectDiscovery Cloud)**
* **OpenVAS / Greenbone**
* **Probely**
* **Prowler**
* **Qualys**
* **Quay**
* **Rapid7 InsightAppSec**
* **Rapid7 InsightVM**
* **runZero**
* **Semgrep**
* **ServiceNow CMDB**
* **Shodan**
* **Snyk**
* **Socket**
* **SonarQube**
* **Sonatype IQ**
* **Sysdig Secure**
* **Tenable**
* **Tenable Web App Scanning**
* **Veracode**
* **Wazuh**
* **Wiz**
* **YesWeHack**

Para instruções de configuração passo a passo de cada ferramenta, veja a referência [Configuração de Conectores por Ferramenta](../toolreference/).

A maioria dos Conectores importa **achados**. Alguns são **Asset Connectors** que, em vez disso, importam seu **inventário de ativos** — construindo e mantendo sua hierarquia de Produto (Ativo) e Tipo de Produto (Organização) em vez de importar achados: **Azure DevOps**, **Backstage**, **Bitbucket**, **GitHub**, **GitLab**, **Jira Service Management Assets** e **ServiceNow CMDB**. (O **runZero** é principalmente um Asset Connector, mas também pode, opcionalmente, importar vulnerabilidades como achados.)

Essas conexões oferecem uma integração com o DefectDojo na velocidade de uma API, e podem ser usadas para ingerir e organizar automaticamente os dados de vulnerabilidade da ferramenta.

## Se orientando na página de Conectores

Os Conectores são listados em duas seções, cada uma com uma contagem ao lado do título, e ambas ordenadas alfabeticamente:

* **Configured Connectors** — todas as configurações de conector existentes nesta instância. Uma ferramenta pode aparecer várias vezes, uma para cada configuração, e cada bloco é intitulado `<Tool> - <label>` para que possam ser diferenciados. Quando várias configurações compartilham a mesma ferramenta, elas são ordenadas pelo label.
* **Available Connectors** — todas as ferramentas suportadas que você ainda não configurou.

A contagem ao lado do título é o número de conectores exibidos no momento, portanto ela acompanha a caixa de busca e o filtro de tipo **Asset / Finding**, em vez de sempre exibir o total. No DefectDojo Pro Cloud, o bloco **Request Upstream Connector** não é um conector e não é contabilizado.

Ambas as seções têm sua própria caixa de busca, que faz a correspondência pelo nome da ferramenta.

![A página de Conectores, com uma contagem ao lado do título de cada seção](images/upstream_counts.png)

As páginas [Downstream Connectors](/connectors/downstream/about/) e [Authorization Connectors](/admin/sso/pro__authorization_connectors/) seguem o mesmo layout.

## Início Rápido dos Conectores Upstream

Se você estiver usando as configurações de **Auto-Map** do DefectDojo, pode deixar seu primeiro Conector funcionando rapidamente.

1. Configure um [Conector](../add_edit/) a partir de uma ferramenta suportada.
2. Faça o [Discover](../manage_operations/#discover-operations) da hierarquia de dados da sua ferramenta.
3. Faça o [Sync](../manage_operations/#sync-operations) das vulnerabilidades encontradas pela sua ferramenta com o DefectDojo.

É só isso, sério! E lembre-se: mesmo que você crie seu Conector da forma 'fácil', é possível alterar facilmente a configuração depois, sem perder nenhum trabalho já feito.

## Como Funcionam os Conectores Upstream

Contanto que você tenha a chave de API da ferramenta que está tentando conectar, um conector pode ser adicionado em poucos minutos. Assim que a conexão estiver funcionando, o DefectDojo vai fazer o **Discover** do ambiente da sua ferramenta para ver como você está organizando seus dados de scan.

Digamos que você tenha uma ferramenta BurpSuite, configurada para escanear cinco repositórios diferentes em busca de vulnerabilidades. Seu Conector vai identificar essa estrutura organizacional e configurar **Records** para ajudar a traduzir esses repositórios separados na hierarquia de Produto / Engajamento / Teste do DefectDojo. Se você tiver o **'Auto-Map Records'** habilitado, o DefectDojo aprenderá e copiará essa estrutura automaticamente.

![image](images/_index.png)

Assim que os mapeamentos de **Record** estiverem configurados, o DefectDojo começará a importar dados de scan regularmente. Você será mantido atualizado sobre quaisquer novas vulnerabilidades detectadas pela ferramenta, e pode começar a trabalhar com as vulnerabilidades existentes imediatamente, usando o sistema de **Findings** do DefectDojo.

Quando estiver pronto para adicionar mais ferramentas ao DefectDojo, você pode facilmente reorganizar seus mapeamentos de importação para outro destino. Várias ferramentas podem ser configuradas para importar vulnerabilidades para o mesmo destino, e você sempre pode reorganizar sua configuração para se adequar melhor, sem perder nenhum trabalho.

## Meu Conector não é suportado

### Solicitar um conector pela interface (DefectDojo Pro Cloud)

No DefectDojo Pro Cloud, você pode pedir à nossa equipe para criar um conector para uma ferramenta que ainda não suportamos — diretamente pela interface:

1. Vá em **Connectors → Upstream Connectors** (para ferramentas que importam dados *para* o DefectDojo). Integrações com rastreadores de issues e outras integrações de saída podem ser solicitadas da mesma forma em **Connectors → Downstream Connectors**.
2. Na seção **Available Connectors**, clique em **Request a Connector**.
3. Preencha o formulário de solicitação. Os campos **Tool / Product Name**, **Tool API Base URL**, **Authentication Type** e as credenciais para esse tipo de autenticação são todos obrigatórios, porque nossa equipe precisa de um endereço acessível e de uma credencial funcional para criar um conector e confirmar que ele funciona com sua ferramenta. As credenciais são armazenadas com segurança. Você pode, opcionalmente, adicionar o site do fornecedor, um link para a documentação da API da ferramenta e uma nota descrevendo seu caso de uso.
4. Clique em **Submit Request**. Você verá uma confirmação de que sua solicitação foi recebida. Nossa equipe analisa cada solicitação para avaliar a viabilidade de construção — enviar uma solicitação não é garantia de que o conector será desenvolvido.

Solicitar um conector requer permissões globais de **Maintainer** e está disponível apenas no **DefectDojo Pro Cloud** — a opção não aparece em instâncias self-hosted (on-premise).

### Importação manual

Mesmo sem um conector, o DefectDojo ainda consegue lidar com a importação manual de uma ampla variedade de ferramentas de segurança. Consulte nossa [Lista de Ferramentas Suportadas](/supported_tools), além do nosso guia de Importação de dados.

# **Próximos Passos**

* Confira a página de **Upstream Connectors** alternando para a **Pro UI** do DefectDojo e abrindo **Connectors \> Upstream Connectors** no cabeçalho **Import**.
* Siga nosso guia para [criar seu primeiro Conector Upstream](../add_edit/).
* Confira o processo de [Executar Operações](../manage_operations/) com suas ferramentas de segurança conectadas e veja como elas podem ser configuradas para importar dados.
