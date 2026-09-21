---
title: Importar via API
description: ''
aliases:
- /pt-br/en/connecting_your_tools/import_scan_files/api_pipeline_modelling
---

A API do DefectDojo permite soluções robustas de pipeline, que ingerem automaticamente novos scans na sua instância. Uma automação como essa pode assumir algumas formas diferentes:

* Uma importação diária que escaneia seu ambiente diariamente e depois importa os resultados do scan para o DefectDojo (similar ao nosso recurso de **Connectors**)
* Um pipeline de CI/CD que escaneia código novo à medida que é implantado, e importa os resultados para o DefectDojo como uma ação disparada

Esses pipelines podem ser criados chamando diretamente o endpoint **/reimport** da nossa API com um arquivo de scan anexado, de uma forma que se assemelha muito ao nosso **Formulário de Importação de Scan**. 

## A API do DefectDojo

A API do DefectDojo é documentada dentro do próprio aplicativo usando o framework OpenAPI. Você pode acessar essa documentação a partir do Menu do Usuário no canto superior direito, em **'API v2 OpenAPI3'**.

A documentação pode ser usada para testar chamadas de API com vários parâmetros, e faz isso usando o Token de API do seu próprio usuário.

Se você precisar acessar um token de API para um script ou outra integração, pode encontrar essa informação na opção **API v2 Token** no mesmo menu.

![image](images/api_pipeline_modelling.png)

### Considerações Gerais sobre a API

* Embora nossa documentação OpenAPI seja detalhada em relação aos parâmetros que podem ser usados em cada endpoint, ela pressupõe que o leitor tenha um bom entendimento dos conceitos-chave do DefectDojo (Hierarquia de Produtos, Achados, Deduplicação, etc.).
* Usuários que desejam uma integração de importação funcional, mas estão menos familiarizados com o DefectDojo como um todo, devem considerar nosso **Universal Importer**.
* A API do DefectDojo pode, às vezes, criar objetos de dados não intencionais, especialmente se 'Auto-Create Context' for usado no endpoint **/import** ou **/reimport**.
* Felizmente, é muito difícil excluir dados acidentalmente usando a API. A maioria dos objetos só pode ser removida usando uma chamada **DELETE** dedicada ao endpoint relevante.

### Notas específicas sobre os endpoints /import e /reimport

O endpoint **/reimport** pode ser usado tanto para uma Importação inicial quanto para um "Reimport" que estende um Teste com Achados adicionais. Você não precisa criar primeiro um Teste com **/import** antes de poder usar o endpoint **/reimport**. Desde que 'Auto Create Context' esteja habilitado, o endpoint /reimport pode criar um novo Teste, Engajamento, Produto ou Tipo de Produto. Em quase todos os casos, você pode usar exclusivamente o endpoint **/reimport** ao adicionar dados via API.

No entanto, o endpoint **/import** pode ser usado em vez disso para um pipeline em que você sempre deseja armazenar cada resultado de scan em um objeto de Teste distinto, em vez de usar **/reimport** para lidar com o diff dentro de um único objeto de Teste. Ambas as opções são aceitáveis, e o endpoint escolhido depende da sua estrutura de relatórios, ou se você precisa inspecionar uma execução isolada de um Pipeline.

### Usando o campo de Data de Conclusão do Scan (API: `scan_date`)

O DefectDojo oferece uma infinidade de relatórios de scanners compatíveis, mas nem todos os relatórios contêm a informação mais importante para um usuário. O campo `scan_date` é um recurso inteligente e flexível que permite aos usuários definir a data de conclusão de um determinado relatório de scan, e propagá-la para todos os achados importados.

Este campo **não** é obrigatório, mas o valor padrão para este campo é a data da importação (sempre que a requisição é processada e uma resposta de sucesso é retornada).

Aqui estão os seguintes casos de uso para este campo, e os resultados aplicados ao Teste:

1. Se o relatório **não** define a data, e `scan_date` **não** é definido na importação
    - A data do Achado será o valor padrão de `scan_date`
2. Se o relatório **define** a data, e `scan_date` **não** é definido na importação
    - A data do Achado será o que o relatório definir
3. Se o relatório **não** define a data, e `scan_date` **é** definido na importação
    - A data do Achado será o que o usuário definir para `scan_date`
4. Se o relatório **define** a data, e `scan_date` **é** definido na importação
    - A data do Achado será o que o usuário definir para `scan_date`
