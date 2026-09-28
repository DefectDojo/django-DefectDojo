---
title: 'Hierarquia de Ativos: Visão Geral'
description: Entenda Organizações, Ativos, Engajamentos, Testes e Achados
weight: 1
audience: opensource
aliases:
- /pt-br/en/working_with_findings/organizing_engagements_tests/product_hierarchy
- /pt-br/asset_modelling/os_hierarchy/product_hierarchy/
- /pt-br/en/asset_modelling/os_hierarchy/product_hierarchy/
---

O DefectDojo usa cinco classes principais de dados para organizar seu trabalho: **Organizações, Ativos**, **Engajamentos**, **Testes**, e **Achados**.

O DefectDojo foi criado para se adaptar à sua equipe, em vez de exigir que sua equipe se adapte à ferramenta. Você poderá projetar um ambiente de trabalho robusto e adaptável assim que entender como essas classes de dados podem ser usadas para organizar seu trabalho.

### Diagrama de Hierarquia de Ativos
![image](images/Asset_Hierarchy_Full.png)


## **Organizações**

A primeira categoria de dados que você precisará configurar no DefectDojo é uma Organização. As Organizações têm como objetivo categorizar Ativos de uma maneira específica. Isso pode ser:

* por domínio de negócio
* por equipe de desenvolvimento
* por equipe de segurança

![image](images/Asset_Hierarchy_Overview.png)
*Os Ativos são agrupados e aninhados sob sua Organização.*

Organizações podem ter regras de Controle de Acesso Baseado em Função aplicadas, que limitam a capacidade dos membros da equipe de visualizar e interagir com seus dados (incluindo quaisquer Ativos subjacentes com dados de Engajamento, Teste e Achado). Para mais informações sobre funções de usuário, consulte nosso artigo **Introdução às Funções**.

#### O que uma Organização pode representar?

* Se um determinado projeto de software tiver várias implantações ou versões distintas, pode valer a pena criar uma única Organização que cubra o escopo de todo o projeto, com cada versão existindo como Ativos individuais.
​
* Você também pode considerar o uso de Organizações para representar estágios do seu processo de desenvolvimento de software: uma Organização para 'Em Desenvolvimento', uma Organização para 'Em Produção', etc.
​
* No final das contas, a decisão de como organizar seus Ativos, e o que você deseja que suas Organizações representem, é sua. Sua hierarquia do DefectDojo pode precisar mudar para atender às necessidades da sua equipe de segurança.

## **Ativos**

Um **Ativo** no DefectDojo tem como objetivo representar qualquer projeto, programa ou aplicação que você esteja testando no momento. O Ativo hospeda todo o trabalho de segurança e o histórico de testes relacionados ao objetivo subjacente.

![image](images/Asset_Hierarchy_Overview_2.png)

* um **Nome** único
* uma **Descrição**
* uma **Organização**
* uma **Configuração de SLA** atribuída

Os Ativos podem ter um escopo tão amplo ou específico quanto você desejar. Por padrão, os Ativos são objetos completamente separados na hierarquia, mas podem ser agrupados por **Organização**.

Os Ativos são 'isolados' e não interagem com outros Ativos. Os Recursos Inteligentes do DefectDojo, como a **Deduplicação**, se aplicam apenas no contexto de um único Ativo.

Assim como as **Organizações**, os **Ativos** podem ter regras de Controle de Acesso Baseado em Função aplicadas, que limitam a capacidade dos membros da equipe de visualizar e interagir com eles (bem como com quaisquer dados subjacentes de Engajamento, Teste e Achado). Para mais informações sobre funções de usuário, consulte nosso artigo **Introdução às Funções**.

#### O que um Ativo pode representar?

O conceito de 'Ativo' do DefectDojo não corresponde necessariamente 1:1 ao que sua organização chamaria de 'Produto'. O desenvolvimento de software é complexo, e as necessidades de segurança podem variar muito mesmo dentro do escopo de um único software.

Os cenários a seguir são bons motivos para considerar a criação de um Ativo separado no DefectDojo:

* "**ExampleAsset**" tem uma versão para Windows, uma versão para Mac e uma versão para Cloud
* "**ExampleAsset 1.0**" usa componentes de software completamente diferentes de "**ExampleAsset 2.0**", e ambas as versões são ativamente suportadas pela sua empresa.
* A equipe designada para trabalhar em "**ExampleAsset version A**" é diferente da equipe de Ativo designada para trabalhar em "**ExampleAsset version B**", e por isso precisa ter permissões de segurança diferentes atribuídas.

Essas variações dentro de um único Ativo também podem ser tratadas no nível do Engajamento. Observe que os Engajamentos não têm controle de acesso da mesma forma que os Ativos e as Organizações.

## **Engajamentos**

Depois que um Ativo é configurado, você pode começar a criar e agendar Engajamentos. Os Engajamentos têm como objetivo representar momentos no tempo em que os testes estão ocorrendo, e contêm um ou mais **Testes**.

Os Engajamentos sempre têm:

* um **Nome** único
* **Datas de início e término** previstas
* **Status** (Not Started, In Progress, Cancelled, Completed...)
* um **Testing Lead** atribuído
* um **Ativo** associado

Existem dois tipos de Engajamento: **Interactive** e **CI/CD**.

* Um **Interactive Engagement** é normalmente executado por um engenheiro. Os Interactive Engagements se concentram em testar a aplicação enquanto ela está em execução, usando um teste automatizado, um testador humano ou qualquer atividade que "interaja" com a funcionalidade da aplicação. Veja [a definição de IAST da OWASP](https://owasp.org/www-project-devsecops-guideline/latest/02c-Interactive-Application-Security-Testing#:~:text=Interactive%20Application%20Security%20Testing,interacting%E2%80%9D%20with%20the%20application%20functionality.).
* Um **CI/CD Engagement** é destinado à integração automatizada com um pipeline de CI/CD. Os CI/CD Engagements têm como objetivo importar dados como uma ação automatizada, disparada por uma etapa do processo de release.

Os Engajamentos podem ser acompanhados usando a visualização de **Calendar** do DefectDojo.

#### O que um Engajamento pode representar?

Os Engajamentos têm como objetivo representar grupos de esforços de teste relacionados. A forma como você deseja agrupar seus esforços de teste depende da sua abordagem.

Se você tem um esforço de teste planejado e agendado, um Engajamento oferece um local para armazenar todos os resultados relacionados. Aqui está um exemplo desse tipo de Engajamento:

#### **Engajamento:** ExampleSoftware 1.5.2 - Esforço de Teste Interativo

*Neste exemplo, uma equipe de segurança executa múltiplos testes no mesmo dia como parte de um release de software.*

* **Teste:** Resultados do Nessus Scan (12 de março)
* **Teste:** Resultados do NPM Scan Audit (12 de março)
* **Teste:** Resultados do Snyk Scan (12 de março)
​
Você também pode organizar resultados de Teste de CI/CD dentro de um Engajamento. Esse tipo de Engajamento é 'Open-Ended' (sem prazo definido), o que significa que eles não têm uma data e, em vez disso, adicionam dados adicionais toda vez que as ações de CI/CD associadas são executadas.

#### Engajamento: ExampleSoftware CI/CD Testing

*Neste exemplo, vários scans de CI/CD são importados automaticamente como Testes toda vez que um novo release de software é criado.*

* Teste: Resultados do Scan 1.5.2 (12 de março)
* Teste: Resultados do Scan 1.5.1 (3 de março)
* Teste: Resultados do Scan 1.5.0 (14 de fevereiro)

Os Engajamentos podem ser organizados da forma que funcionar melhor para sua equipe. Todos os Engajamentos aninhados sob um Ativo podem ser visualizados pela equipe designada para trabalhar nesse Ativo.

## **Testes**

Os Testes são um agrupamento de atividades realizadas por engenheiros na tentativa de descobrir falhas em um Ativo.

Os Testes sempre têm:

* um **Título de Teste** único
* um **Tipo de Teste** específico (API Test, Nessus Scan etc.)
* um **Ambiente** de teste associado
* um **Engajamento** associado

Os Testes podem ser criados de diferentes maneiras.  Eles podem ser criados automaticamente quando os dados de um scan são importados diretamente em um Engajamento, resultando em um novo Teste contendo os dados do scan. Os Testes também podem ser criados antecipadamente, para planejar futuros engajamentos, ou para achados de segurança inseridos manualmente que exijam acompanhamento e remediação.

### **Tipos de Teste**

O DefectDojo oferece suporte a duas categorias de Tipos de Teste:

1. **Tipos de Teste baseados em parser**: Correspondem a scanners de segurança específicos que produzem saída em formatos como XML, JSON ou CSV. Ao importar resultados de scan, o DefectDojo usa parsers especializados para converter a saída do scanner em Achados.

2. **Tipos de Teste sem parser**: São usados para Achados criados manualmente, não importados de arquivos de scan.  Esses Tipos de Teste usam o método [Generic Findings Import](/supported_tools/parsers/generic_findings_import/) para renderizar Achados e metadados.

Os seguintes Tipos de Teste aparecem no menu suspenso "Scan Type" ao criar um novo teste.
   * API Test
   * Static Check
   * Pen Test
   * Web Application Test
   * Security Research
   * Threat Modeling
   * Manual Code Review

Os Tipos de Teste sem parser devem ser usados quando você precisa criar manualmente achados que exigem remediação, mas que não se originam da saída de um scanner automatizado.

#### **Tipos de Teste baseados em parser**

Os tipos de teste baseados em parser podem ser categorizados pela forma como o nome do tipo de teste é determinado:

- **Nomes de Tipo de Teste fixos**: O nome do tipo de teste é predefinido e conhecido antes da importação (por exemplo, "ZAP Scan", "Nessus Scan").

- **Nomes de Tipo de Teste definidos pelo relatório**: O nome do tipo de teste é extraído do conteúdo do relatório de scan no momento da importação.

Exemplos incluem:
  - **Generic Findings Import**: Cria tipos de teste com base no campo `type` em relatórios JSON
  - **SARIF**: Cria tipos de teste com base nos nomes das ferramentas no relatório SARIF (por exemplo, "Dockle Scan (SARIF)")
  - **OpenReports**: Cria tipos de teste separados para cada origem encontrada no relatório

**Regras de Nomenclatura de Tipo de Teste Definido pelo Relatório:**
- Se o campo `type` do relatório for igual ao tipo de scan → usa o tipo de scan diretamente (por exemplo, "Generic Findings Import")
- Se o campo `type` do relatório for diferente → cria o formato "{type} Scan ({scan_type})" (por exemplo, "Tool1 Scan (Generic Findings Import)")
- Se o campo `type` do relatório já terminar com o sufixo " ({scan_type})" → ele é usado literalmente, de modo que o sufixo nunca é duplicado (por exemplo, "Tool1 (Generic Findings Import)" permanece "Tool1 (Generic Findings Import)")
- Se nenhum campo `type` for fornecido → usa o tipo de scan diretamente

**Considerações Importantes:**
- Tipos de teste definidos pelo relatório são criados automaticamente quando um novo tipo é detectado durante a importação ou reimportação.
- Para reimportações, o nome do tipo de teste deve corresponder exatamente - divergências gerarão um erro de validação
- As configurações de Deduplicação (`HASHCODE_FIELDS_PER_SCANNER`) usam os nomes dos tipos de teste como chaves, portanto, os nomes definidos pelo relatório devem ser configurados adequadamente caso você deseje um comportamento de deduplicação personalizado

#### **Como os Testes interagem entre si?**

Os Testes pegam seus dados de teste e os agrupam em Achados. Geralmente, as equipes de segurança executam o mesmo esforço de teste repetidamente, e os Testes no DefectDojo permitem lidar com esse processo de forma elegante.

**Testes previamente importados podem ser reimportados** - Se você estiver executando o mesmo tipo de teste dentro do mesmo contexto de Engajamento, você pode Reimportar os resultados do teste após cada scan concluído. DefectDojo comparará os dados Reimportados com o resultado existente, e não criará novos Achados se houver duplicatas nos dados do scan.

**Testes podem ser importados separadamente** - Se você executar o mesmo teste em um Ativo dentro de Engajamentos separados, DefectDojo ainda comparará os dados com Testes anteriores para encontrar Achados duplicados. Isso permite acompanhar Achados previamente mitigados ou com risco aceito.

Se um Teste for adicionado diretamente a um Ativo sem um Engajamento, um Engajamento genérico será criado automaticamente para contê-lo. Isso permite importações de dados ad-hoc.

**Exemplos de Testes:**

* Burp Scan de 29 de out. de 2015 a 29 de out. de 2015
* Nessus Scan de 31 de out. de 2015 a 31 de out. de 2015
* API Test de 15 de out. de 2015 a 20 de out. de 2015

## **Achados**

Depois que os dados forem enviados para um Teste, os resultados desses dados serão listados no Teste como **Achados** individuais para revisão.

Um achado representa uma falha específica descoberta durante o teste.

Os Achados sempre têm:

* um **Nome de Achado** único
* a **Data** em que foram descobertos
* múltiplos **Status** associados, como Ativo, Verificado ou Falso positivo
* um **Teste** associado
* um nível de **Severidade**: Crítica, Alto, Médio, Baixo e Informativa (Info).

Os Achados podem ser adicionados por meio de uma importação de dados, mas também podem ser adicionados manualmente a um Teste.

**Exemplos de Achados:**

* OpenSSL 'ChangeCipherSpec' MiTM Potential Vulnerability
* Web Application Potentially Vulnerable to Clickjacking
* Web Browser XSS Protection Not Enabled

## **Endpoints**

Os dados de scan geralmente contêm referências aos hosts ou endpoints afetados por um determinado Achado.  DefectDojo agrega automaticamente os Achados por endpoint, para que você possa usar a visualização de Endpoint para ver todos os Achados que afetam um determinado Endpoint ou Hostname.

Exemplos:
-   https://www.example.com
-   https://www.example.com:8080/products
-   192.168.0.36
