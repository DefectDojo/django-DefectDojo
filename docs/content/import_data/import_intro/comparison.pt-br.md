---
title: Comparação de Métodos de Importação
description: Aprenda a importar dados manualmente, pela API, ou via um connector
weight: 1
aliases:
- /pt-br/en/connecting_your_tools/import_intro
---

Uma das coisas que entendemos aqui no DefectDojo é que as necessidades de segurança de cada empresa são completamente diferentes. Não existe uma abordagem única que sirva para todos. À medida que sua organização muda, ter uma abordagem flexível é fundamental, e o DefectDojo permite que você conecte suas ferramentas de segurança de forma flexível para acompanhar essas mudanças.

## Métodos de Envio de Scan

Quando o DefectDojo recebe um relatório de vulnerabilidades de uma ferramenta de segurança, ele cria Achados com base nas vulnerabilidades contidas nesse relatório. O DefectDojo atua como o repositório central para esses Achados, onde podem ser triados, corrigidos ou tratados de outra forma por você e sua equipe.

Existem duas formas principais pelas quais o DefectDojo pode receber relatórios de Achados.

* Via **importação** direta pela UI
* Via endpoint de **API** (permitindo a ingestão automatizada de dados): Consulte a [Documentação da API](/automation/api/api-v2-docs/)

#### Métodos do DefectDojo Pro

Usuários do <span style="background-color:rgba(242, 86, 29, 0.3)">DefectDojo Pro</span> têm três métodos adicionais para lidar com relatórios e dados:

* Via **Universal Importer** ou **DefectDojo CLI**, ferramentas de linha de comando que utilizam a API do DefectDojo: Consulte os [guias do Universal Importer e DefectDojo-CLI](/import_data/pro/specialized_import/external_tools/)
* Via **Connectors** para determinadas ferramentas, uma integração de dados "pronta para uso": Consulte o [Guia de Connectors](/connectors/upstream/about/)
* Via **Smart Upload** para determinadas ferramentas, um importador projetado para lidar com scans de infraestrutura: Consulte o [Guia do Smart Upload](/import_data/pro/specialized_import/smart_upload/)

### Comparando Métodos de Envio

|  | **Importação via UI** | **API** | **Connectors** <span style="background-color:rgba(242, 86, 29, 0.3)">(Pro)</span> | **Smart Upload**  <span style="background-color:rgba(242, 86, 29, 0.3)">(Pro)</span>|
| --- | --- | --- | --- | --- |
| **Tipos de Scan Compatíveis** | Todos: veja [Ferramentas Compatíveis](/supported_tools/) | Todos: veja [Ferramentas Compatíveis](/supported_tools/) | Akamai API Security, Anchore, AWS Security Hub, BurpSuite, Checkmarx ONE, Dependency-Track, IriusRisk, JFrog Xray, Probely, Semgrep, SonarQube, Snyk, Tenable, Wiz | Nexpose, NMap, OpenVas, Qualys, Tenable |
| **Automação?** | Disponível via API: endpoints `/reimport` `/import` | Disparado a partir de [Ferramentas de CLI](/import_data/pro/specialized_import/external_tools/) ou código externo | Connectors é um recurso inerentemente automatizado | Disponível via API: endpoint `/smart_upload_import` |

### Hierarquia de Produtos e organização

Cada um desses métodos pode criar Hierarquia de Produtos na hora. Hierarquia de Produtos se refere aos Tipos de Produto, Produtos, Engajamentos ou Testes do DefectDojo: objetos no DefectDojo que ajudam a organizar seus dados em um contexto relevante.

* **Os dados de vulnerabilidade podem ser importados para uma Hierarquia de Produtos existente**. Tipos de Produto, Produtos, Engajamentos e Testes podem todos ser criados com antecedência, e então os dados podem ser importados para esse local no DefectDojo.
* **A Hierarquia de Produtos contextual pode ser criada no momento da Importação.** Ao importar um relatório, você pode criar um novo Tipo de Produto, Produto, Engajamento e/ou Teste. Isso é tratado pelo DefectDojo através da opção 'auto-create context'.  No DefectDojo OS, essa opção só pode ser acessada através da API.  As importações via UI no DefectDojo OS exigirão que a Hierarquia de Produtos seja criada previamente.
