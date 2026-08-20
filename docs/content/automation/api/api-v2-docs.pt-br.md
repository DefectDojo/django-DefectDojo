---
title: DefectDojo API v2
description: A API do DefectDojo permite automatizar tarefas, por exemplo, enviar
  relatórios de scan em pipelines de CI/CD.
draft: false
weight: 2
aliases:
- /pt-br/en/api/api-v2-docs
---

A API do DefectDojo é criada usando o [Django Rest
Framework](http://www.django-rest-framework.org/). A documentação de
cada endpoint está disponível em cada instalação do DefectDojo em
[`/api/v2/oa3/swagger-ui`](https://demo.defectdojo.org/api/v2/oa3/swagger-ui/) e pode ser acessada escolhendo o link API v2
Docs no menu suspenso do usuário no cabeçalho.

![image](images/api_v2_1.png)

A documentação é gerada usando o [drf-spectacular](https://drf-spectacular.readthedocs.io/) em [`/api/v2/oa3/swagger-ui/`](https://demo.defectdojo.org/api/v2/oa3/swagger-ui/) e é
interativa. No topo da documentação da API v2 há um link que gera uma especificação OpenAPI v3.

Para interagir com a documentação, é necessário um valor válido de
cabeçalho Authorization. Acesse a view `/api/key-v2` para gerar sua
API Key (`Token <api_key>`) e copie o valor de cabeçalho fornecido.

![image](images/api_v2_2.png)

Cada seção permite que você faça chamadas à API e visualize a Request
URL, o Response Body, o Response Code e os Response Headers.

![image](images/api_v2_3.png)

Se você estiver logado na interface web do Defect Dojo, não é necessário fornecer o token de autorização.

## Autenticação

A API usa autenticação por cabeçalho com API key. O formato do
cabeçalho deve ser: :

    Authorization: Token <api.key>

Por exemplo: :

    Authorization: Token c8572a5adf107a693aa6c72584da31f4d1f1dcff

### Método de autenticação alternativo

Se você usa [um método de autenticação alternativo](/admin/sso/) para os usuários, talvez queira desabilitar os tokens de API do DefectDojo, pois isso pode contornar seu esquema de autenticação. \
A utilização dos tokens de API do DefectDojo pode ser desabilitada especificando a variável de ambiente `DD_API_TOKENS_ENABLED` como `False`.
Ou apenas o endpoint `api/v2/api-token-auth/` pode ser desabilitado definindo `DD_API_TOKEN_AUTH_ENDPOINT_ENABLED` como `False`.

## Código de exemplo

Seguem alguns exemplos simples em python e seus resultados produzidos
contra o endpoint `/users`: :

{{< highlight python >}}
import requests

url = 'http://127.0.0.1:8000/api/v2/users'
headers = {'content-type': 'application/json',
            'Authorization': 'Token c8572a5adf107a693aa6c72584da31f4d1f1dcff'}
r = requests.get(url, headers=headers, verify=True) # set verify to False if ssl cert is self-signed

for key, value in r.__dict__.items():
  print(f"'{key}': '{value}'")
  print('------------------')
{{< /highlight >}}

Esse código retornará a lista de todos os usuários definidos no DefectDojo.
O objeto json resultante se parece com: :

{{< highlight json >}}
    [
        {
          "first_name": "Tyagi",
          "id": 22,
          "last_login": "2019-06-18T08:05:51.925743",
          "last_name": "Paz",
          "username": "dev7958"
        },
        {
          "first_name": "saurabh",
          "id": 31,
          "last_login": "2019-06-06T11:44:32.533035",
          "last_name": "",
          "username": "saurabh.paz"
        }
    ]
{{< /highlight >}}

Aqui está outro exemplo contra o endpoint `/users`; desta vez
filtraremos os resultados para incluir apenas os usuários cujo nome de
usuário contém `jay`:

{{< highlight python >}}
import requests

url = 'http://127.0.0.1:8000/api/v2/users/?username__contains=jay'
headers = {'content-type': 'application/json',
            'Authorization': 'Token c8572a5adf107a693aa6c72584da31f4d1f1dcff'}
r = requests.get(url, headers=headers, verify=True) # set verify to False if ssl cert is self-signed

for key, value in r.__dict__.items():
  print(f"'{key}': '{value}'")
  print('------------------')
{{< /highlight >}}

O objeto json resultante é: :

{{< highlight json >}}
[
    {
        "first_name": "Jay",
        "id": 22,
        "last_login": "2015-10-28T08:05:51.925743",
        "last_name": "Paz",
        "username": "jay7958"
    },
    {
        "first_name": "",
        "id": 31,
        "last_login": "2015-10-13T11:44:32.533035",
        "last_name": "",
        "username": "jay.paz"
    }
]
{{< /highlight >}}

Consulte a [documentação do Django Rest Framework sobre como interagir
com uma API](https://www.django-rest-framework.org/) para
exemplos e dicas adicionais.

## Chamando a API manualmente

Ferramentas como o Postman podem ser usadas para testar a API.

Exemplo de importação de um resultado de scan:

-   Verbo: POST
-   URI: <http://localhost:8080/api/v2/import-scan/>
-   Aba Headers:

    adicione o cabeçalho de autenticação
    :   -   Chave: Authorization
        -   Valor: Token c8572a5adf107a693aa6c72584da31f4d1f1dcff

-   Aba Body

    -   selecione \"form-data\", clique em \"bulk edit\". Exemplo para um scan ZAP:

<!-- -->

    engagement:3
    verified:true
    active:true
    lead:1
    tags:test
    scan_type:ZAP Scan
    minimum_severity:Info
    close_old_findings:false

-   Aba Body

       -   Clique em \"Key-value\" edit
       -   Adicione um parâmetro \"file\" do tipo \"file\". Isso acionará o
            envio de dados de formulário multi-part para enviar o conteúdo do arquivo
       -   Navegue até o arquivo a ser enviado

-   Clique em enviar

## Clientes / Wrappers de API

| Wrapper                      | Status                   | Notes |
| -----------------------------| ------------------------| ------------------------|
| [Specific python wrapper](https://github.com/DefectDojo/defectdojo_api)      | funcionando (2021-01-21)    | Wrapper de API incluindo scripts para envio contínuo em CI/CD. Está um pouco atrasado em relação aos recursos mais recentes da API, pois planejamos reformular o wrapper |
| [Openapi python wrapper](https://github.com/alles-klar/defectdojo-api-v2-client)       | | apenas prova de conceito, na qual descobrimos que a especificação OpenAPI ainda não está perfeita |
| [Java library](https://github.com/secureCodeBox/defectdojo-client-java)                 | funcionando (2021-08-30)    | Criado pelas gentis pessoas do [SecureCodeBox](https://github.com/secureCodeBox/secureCodeBox) |
| [Image using the Java library](https://github.com/SDA-SE/defectdojo-client) | funcionando (2021-08-30)    | |
| [.Net/C# library](https://www.nuget.org/packages/DefectDojo.Api/)              | funcionando (2021-06-08)    | |
| [dd-import](https://github.com/MaibornWolff/dd-import)                    | funcionando (2021-08-24)    | dd-import não é diretamente um wrapper de API. Ele oferece algumas funções de conveniência para facilitar a importação de achados e dados de linguagem a partir de pipelines de CI/CD. |

Alguns dos wrappers de API contêm bastante lógica para facilitar o escaneamento e a importação em ambientes de CI/CD. Estamos no processo de simplificar isso tornando a API do DefectDojo mais inteligente (para que os wrappers/scripts de API possam ser mais simples).

## Notas sobre a API

### Import / Reimport

**Reimport** é, na verdade, a forma mais fácil de começar, pois ele cria as entidades necessárias dinamicamente e detecta automaticamente se é o primeiro upload ou um novo envio.

## Importação
A importação via API é realizada através do endpoint [import-scan](https://demo.defectdojo.org/api/v2/doc/).

Conforme descrito em [Product Hierarchy](/asset_modelling/os_hierarchy/product_hierarchy/), o Teste é criado dentro de um Engajamento, dentro de um Produto, dentro de um Tipo de Produto.

Uma importação pode ser realizada especificando os nomes dessas entidades na requisição da API:


```JSON
{
    "minimum_severity": 'Info',
    "active": True,
    "verified": True,
    "scan_type": 'ZAP Scan',
    "test_title": 'Manual ZAP Scan by John',
    "product_type_name": 'Good Products',
    "product_name": 'My little product',
    "engagement_name": 'Important import',
    "auto_create_context": True,
}
```

Quando `auto_create_context` é `True`, o produto, o engajamento e o ambiente serão criados se necessário. Certifique-se de que seu usuário tenha [permissões](/admin/user_management/about_perms_and_roles/) suficientes para isso.

Uma forma clássica de importar um scan é especificando o ID do engajamento em vez disso:

```JSON
{
    "minimum_severity": 'Info',
    "active": True,
    "verified": True,
    "scan_type": 'ZAP Scan',
    "test_title": 'Manual ZAP Scan by John',
    "engagement": 123,
}
```

## Reimportação
A reimportação via API é realizada através do endpoint [reimport-scan](https://demo.defectdojo.org/api/v2/doc/).

Uma reimportação pode ser realizada especificando os nomes dessas entidades na requisição da API:


```JSON
{
    "minimum_severity": 'Info',
    "active": True,
    "verified": True,
    "scan_type": 'ZAP Scan',
    "test_title": 'Manual ZAP Scan by John',
    "product_type_name": 'Good Products',
    "product_name": 'My little product',
    "engagement_name": 'Important import',
    "auto_create_context": True,
    "do_not_reactivate": False,
}
```

Quando `auto_create_context` é `True`, o Tipo de Produto, o Produto e o Engajamento serão criados caso ainda não existam. Certifique-se de que seu usuário tenha [permissões](/admin/user_management/about_perms_and_roles/) suficientes para criar um Produto/Tipo de Produto.

Quando `do_not_reactivate` é `True`, a importação/reimportação ignorará os achados ativos enviados e não reativará achados anteriormente fechados, embora ainda crie novos achados caso haja novidades. Você receberá uma nota no achado explicando que ele não foi reativado por esse motivo.

Uma reimportação selecionará automaticamente o teste mais recente dentro do engajamento fornecido que satisfaça o `scan_type` informado e (opcionalmente) o `test_title` informado.

Se nenhum Teste existente for encontrado, o endpoint de reimportação usará a função de importação para importar o relatório fornecido em um novo Teste. Isso significa que um script (de CI/CD) que usa a API não precisa saber se um Teste já existe, ou se é o primeiro upload para esse Produto/Engajamento.

Uma forma clássica de reimportar um scan é especificando o ID do teste em vez disso:

```JSON
{
    "minimum_severity": 'Info',
    "active": True,
    "verified": True,
    "scan_type": 'ZAP Scan',
    "test": 123,
}
```

## Gerando relatórios

O DefectDojo pode gerar um relatório de achados através da API nos formatos **JSON**, **HTML**, **CSV** ou **Excel**.

Um relatório é gerado com uma requisição `POST` para uma ação `generate_report/`. O endpoint de achados gera relatórios em toda a sua instância, e a maioria dos outros objetos expõe uma ação por objeto:

| Endpoint | Scope |
|---|---|
| `POST /api/v2/findings/generate_report/` | Todo achado que você tenha permissão para visualizar |
| `POST /api/v2/products/{id}/generate_report/` | Um produto |
| `POST /api/v2/engagements/{id}/generate_report/` | Um engajamento |
| `POST /api/v2/tests/{id}/generate_report/` | Um teste |
| `POST /api/v2/product_types/{id}/generate_report/` | Um tipo de produto |
| `POST /api/v2/endpoints/{id}/generate_report/` | Um endpoint |

Os aliases de objeto do Pro expõem a mesma ação: `/api/v2/assets/{id}/generate_report/`, `/api/v2/organizations/{id}/generate_report/` e `/api/v2/location/{id}/generate_report/`.

### Opções da requisição

Todos os campos são opcionais — enviar um corpo vazio (`{}`) retorna um relatório JSON.

| Field | Type | Default | Description |
|---|---|---|---|
| `report_type` | string | `JSON` | Um de `JSON`, `HTML`, `CSV`, `Excel`. |
| `include_finding_notes` | boolean | `false` | Inclui as notas de cada achado. |
| `include_finding_images` | boolean | `false` | Inclui as imagens anexadas aos achados. |
| `include_executive_summary` | boolean | `false` | Inclui uma seção de resumo executivo. |
| `include_table_of_contents` | boolean | `false` | Inclui um sumário. |

Um `report_type` não suportado (por exemplo, `PDF`) retorna `400 Bad Request` com um erro no campo `report_type`.

### Exemplo

Gere um relatório CSV de todos os achados que você pode visualizar e salve-o em um arquivo:

```bash
curl -X POST \
  -H "Authorization: Token <your-api-token>" \
  -H "Content-Type: application/json" \
  -d '{"report_type": "CSV"}' \
  https://<your-instance>/api/v2/findings/generate_report/ \
  -o findings.csv
```

### Formatos de resposta

| `report_type` | Content type | Response |
|---|---|---|
| `JSON` (default) | `application/json` | Corpo do relatório na resposta |
| `HTML` | `text/html` | Página de relatório renderizada |
| `CSV` | `text/csv` | Anexo de arquivo |
| `Excel` | `application/vnd.openxmlformats-officedocument.spreadsheetml.sheet` | Anexo de arquivo `.xlsx` |

CSV e Excel são retornados como anexos de arquivo com um cabeçalho `Content-Disposition`, em vez de um corpo JSON. O nome do arquivo é derivado do objeto a partir do qual o relatório foi gerado — por exemplo, `product_1_findings.csv` ou `test_42_findings.xlsx`. O endpoint `/findings/generate_report/` não está restrito a um único objeto, portanto seus downloads recebem os nomes `findings.csv` e `findings.xlsx`.

### Notas e limitações

* As opções `include_*` afetam apenas os relatórios **JSON** e **HTML**. As exportações **CSV** e **Excel** sempre contêm as linhas de achados.
* A geração de relatórios requer permissão de **visualização** nos objetos envolvidos, e um relatório sempre contém apenas os achados que você está autorizado a ver.
* **Os filtros de parâmetros de consulta padrão não são aplicados a esta ação.** Diferente de `GET /api/v2/findings/`, a ação `generate_report/` não aplica os filtros de achados, portanto uma requisição como `POST /api/v2/findings/generate_report/?severity=High` ainda gera relatório sobre todos os achados que você pode visualizar. Para restringir um relatório, gere-o a partir de um produto, engajamento ou teste específico.

## Comportamento de exclusão assíncrona

As exclusões no DefectDojo (tanto pela API quanto pela UI) são processadas de forma **assíncrona** por workers em segundo plano do Celery. Quando você exclui um Engajamento, Teste ou outro objeto, a API ou a UI retorna uma resposta de sucesso imediatamente, mas a exclusão de fato é executada em segundo plano.

Isso significa que:
- Os objetos ainda podem aparecer em consultas por um período após a exclusão ser confirmada.
- As exclusões em cascata (por exemplo, excluir um Engajamento também exclui seus Testes e Achados) são processadas como uma cadeia de tarefas em segundo plano. Os objetos filhos são removidos em ordem de dependência: Achados, depois Testes, depois Engajamentos.
- Para Engajamentos grandes com muitos Achados, esse processo pode levar vários minutos para ser concluído.

Não há necessidade de criar scripts personalizados para excluir objetos em ordem de dependência. Uma única requisição `DELETE` em um Engajamento se propagará automaticamente em cascata para todos os objetos filhos. Basta aguardar o tempo necessário para que as tarefas em segundo plano sejam concluídas.

## Limites de paginação da API

O DefectDojo Pro impõe um tamanho máximo de página de **250** resultados por requisição de API. Definir `limit` acima de 250 pode resultar em erros HTTP 502 devido a timeouts de consulta.

Instâncias do DefectDojo Open Source também podem apresentar timeouts com tamanhos de página muito grandes, dependendo do tamanho do conjunto de dados e dos recursos do servidor.

Para conjuntos de resultados grandes, use paginação com um tamanho de página de 50 a 250 e adicione pequenos atrasos entre as requisições paginadas para evitar sobrecarregar o pool de workers.

## Boas práticas para importação em grande escala

Ao importar resultados de scan em grande escala (por exemplo, pipelines de SBOM com milhares de componentes), considere o seguinte:

- **Use `background_import=true`** para payloads grandes. Importações síncronas ocupam um worker uwsgi durante toda a importação, o que pode degradar o desempenho para todos os usuários.
- **Direcione tamanhos de payload abaixo de 1 MB por importação**, sempre que possível. Divida SBOMs grandes em arquivos menores por produto ou grupo de componentes.
- **Adicione atrasos entre chamadas de API consecutivas** para evitar o esgotamento do pool de workers, o que causa erros HTTP 502.
- **Use a Reimportação** (`/api/v2/reimport-scan/`) para scans recorrentes, a fim de atualizar achados existentes em vez de criar duplicatas.

## Respostas de importação em segundo plano (API: `background_import`)

Uma importação em segundo plano retorna assim que o relatório enviado é analisado (parsed), antes que qualquer achado tenha sido gravado. Sua resposta, portanto, descreve um trabalho *agendado*, e tem um formato diferente do de uma importação síncrona. Isso se aplica a `/api/v2/import-scan/` e `/api/v2/reimport-scan/` sempre que `background_import` é `true`, ou sempre que a configuração de sistema `api_async_import` ativa esse comportamento para todas as importações.

Uma resposta em segundo plano contém:

- `background_import` — `true`. Este é o campo em que se deve basear a lógica condicional.
- `status` — o status de ciclo de vida do teste no momento em que a resposta foi produzida:
  `Processing`, `Post Processing - Deduplication`,
  `Post Processing - False Positive History`, `Processed` ou `Failed`.
- `findings_parsed` — quantos achados foram lidos a partir do relatório. Esta é uma contagem de análise (parse), não uma contagem de criação: a deduplicação e as opções de importação fornecidas por você determinam quantos achados são de fato gravados.
- `test_id` (e `engagement_id`, `product_id`, `product_type_id`) — os identificadores para consulta.
- `message` — a mesma informação de `status` e `findings_parsed`, em forma de texto. Prefira os campos estruturados.

Ela **não** contém `statistics`, nem contém `deduplication_complete`. Essas chaves ficam ausentes em vez de zeradas, pois, nesse momento, nenhum achado foi criado, e informar zeros descreveria a importação de forma incorreta. Um cliente que lê `response["statistics"]` incondicionalmente falhará em uma importação em segundo plano — leia `background_import` primeiro, ou use `statistics` apenas no caminho síncrono.

Para acompanhar uma importação em segundo plano até sua conclusão, consulte o teste:

```
POST /api/v2/import-scan/        (background_import=true)  -> test_id, status, findings_parsed
GET  /api/v2/tests/{test_id}/                              -> status, processing
```

Repita o `GET` até que `status` seja `Processed` (a importação terminou, e as contagens de achados do teste agora são significativas) ou `Failed` (a importação não foi concluída). Enquanto a importação está em execução, `processing` é `true` e `status` informa em qual fase ela se encontra. Use alguns segundos entre as consultas; um relatório grande pode levar minutos no pós-processamento.

Uma importação síncrona (`background_import` omitido ou `false`) permanece inalterada: ela retorna assim que os achados foram gravados, inclui `statistics` e não inclui `status` nem `findings_parsed`.

## Usando o campo de data de conclusão do scan (API: `scan_date`)

O DefectDojo oferece uma infinidade de relatórios de scanner suportados, mas nem todos contêm a informação mais importante para o usuário. O campo `scan_date` é um recurso inteligente e flexível que permite ao usuário definir a data de conclusão de um determinado relatório de scan, propagando-a para todos os achados importados. Este campo **não** é obrigatório, mas o valor padrão para esse campo é a data da importação (quando a requisição é processada e uma resposta de sucesso é retornada).

Seguem os casos de uso para esse campo:

1. O relatório **não** define a data, e `scan_date` **não** é definido na importação
    - A data do achado será o valor padrão de `scan_date`
2. O relatório **define** a data, e `scan_date` **não** é definido na importação
    - A data do achado será o que quer que o relatório definir
3. O relatório **não** define a data, e `scan_date` **é definido** na importação
    - A data do achado será o que quer que o usuário tenha definido para `scan_date`
4. O relatório **define** a data, e `scan_date` **é definido** na importação
    - A data do achado será o que quer que o usuário tenha definido para `scan_date`
