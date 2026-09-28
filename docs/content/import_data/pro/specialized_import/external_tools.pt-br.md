---
title: Universal Importer & DefectDojo-CLI
description: Importe arquivos para o DefectDojo pela linha de comando
draft: false
weight: 2
audience: pro
aliases:
- /pt-br/en/connecting_your_tools/external_tools
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Nota: as ferramentas externas a seguir são recursos exclusivos do DefectDojo Pro. Esses binários não funcionarão a menos que estejam conectados a uma instância com uma licença do DefectDojo Pro.</span>

## Sobre as ferramentas externas

`defectdojo-cli` e `universal-importer` são ferramentas de linha de comando criadas para simplificar os processos de importação e reimportação de Achados e objetos associados, sendo ideais para usuários que desejam configurar rapidamente essas interações com a API do DefectDojo.

O DefectDojo-CLI tem a mesma funcionalidade do Universal Importer, mas também inclui a capacidade de exportar Achados do DefectDojo para JSON ou CSV.

## Instalação

1. Localize “External Tools” no menu do seu perfil de usuário:

2. Baixe o binário adequado para o seu sistema operacional na plataforma.

![image](images/external-tools.png)

3. Extraia o arquivo baixado em um diretório de sua escolha. Opcionalmente, adicione o diretório que contém o binário extraído ao $PATH do seu sistema para acesso repetido.

**Observe que usuários de Macintosh podem ser bloqueados de executar o DefectDojo-CLI ou o Universal Importer, pois são aplicativos de um desenvolvedor não identificado.  Consulte a [Apple Support](https://support.apple.com/en-ca/guide/mac-help/mh40616/mac) para instruções sobre como contornar o bloqueio da Apple.**  

**Usuários do Windows: se você receber o erro "Couldn't download - virus detected", desativar o Smartscreen pode resolver. Caso contrário, use um navegador diferente para baixar a ferramenta pelo portal Cloud.**

## Configuração

O Universal Importer e o DefectDojo-CLI podem ser configurados usando flags, variáveis de ambiente ou um arquivo de configuração. A configuração mais importante é o token de API, que precisa ser definido como uma variável de ambiente:

1. Adicione sua chave de API às suas variáveis de ambiente. 
Você pode obter sua chave de API em: `https://YOUR_INSTANCE.cloud.defectdojo.com/api/key-v2`

ou 

Pela interface de usuário do DefectDojo 
no menu suspenso do usuário, no canto superior direito:

![image](images/api-token.png)

2. Defina a variável de ambiente para o token de API.

**Para o DefectDojo-CLI:**
	`export DD_CLI_API_TOKEN=YOUR_API_KEY`

**Para o Universal Importer:**
	`export DD_IMPORTER_DOJO_API_TOKEN=YOUR_API_KEY`

Nota: no Windows, use `set` em vez de `export`.

### Windows: usando o PowerShell

1. Abra o PowerShell (tecla Windows, então pesquise por "PowerShell").
2. Defina as variáveis de ambiente:
   - **Temporária:**
     ```powershell
     $env:DD_IMPORTER_DOJO_API_TOKEN = "[VALUE_FROM_DEFECTDOJO_API]"
     $env:DD_IMPORTER_DEFECTDOJO_URL=”[e.g. http://localhost:8080/defectdojo]”
     ```
   - **Permanente:**
     ```powershell
     [Environment]::SetEnvironmentVariable("DD_IMPORTER_DOJO_API_TOKEN", "[VALUE_FROM_DEFECTDOJO_API]", "Machine")
     ```
3. Reinicie sua sessão do PowerShell.
4. Verifique a configuração:
   ```powershell
   echo $env:DD_IMPORTER_DOJO_API_TOKEN
   echo $env:DD_IMPORTER_DEFECTDOJO_URL
   ```

### Windows: usando o Prompt de Comando (contas administrativas)
1. Abra o Prompt de Comando (tecla Windows, então pesquise por "Command Prompt").
2. Defina as variáveis de ambiente:
   - **Temporária:**
     ```cmd
     set DD_IMPORTER_DOJO_API_TOKEN = "[VALUE_FROM_DEFECTDOJO_API]"
     set DD_IMPORTER_DEFECTDOJO_URL=”[e.g. http://localhost:8080/defectdojo]”
     ```
   - **Permanente:**
     ```cmd
     setx DD_IMPORTER_DOJO_API_TOKEN = "[VALUE_FROM_DEFECTDOJO_API]"
     setx DD_IMPORTER_DEFECTDOJO_URL=”[e.g. http://localhost:8080/defectdojo]”
     ```

### Usando as configurações do Windows (contas não administrativas)
1. Pressione `Win + I` para abrir a caixa de diálogo de configurações do sistema.
2. Na caixa de pesquisa, digite "environment".
3. Escolha "Edit Environment variables for your account".
4. Em "User variables for [username]", clique no botão "New…".
5. Defina a variável:
   - **Nome da variável:** `DD_IMPORTER_DOJO_API_TOKEN`
   - **Valor da variável:** `[VALUE_FROM_DEFECTDOJO_API]`
6. Clique em "OK".
7. Repita os passos de 4 a 6 para a variável DD_IMPORTER_DEFECTDOJO_URL
8. Reinicie todas as janelas de comando abertas.
9. Verifique as configurações:
   ```cmd
   echo %DD_IMPORTER_DOJO_API_TOKEN%
   echo %DD_IMPORTER_DEFECTDOJO_URL%
   ```

## DefectDojo-CLI

`defectdojo-cli` integra os resultados de scans ao DefectDojo de forma transparente, simplificando os processos de importação e reimportação de Achados e objetos associados. Projetada para facilidade de uso, a ferramenta oferece suporte a vários endpoints, atendendo tanto importações iniciais quanto reimportações subsequentes — ideal para usuários que precisam de uma interação robusta e flexível com a API do DefectDojo. O DefectDojo-CLI pode realizar as mesmas funções que o `universal-importer`, além de adicionar a funcionalidade de exportação de Achados.

### Comandos

- [`import`](./#import)       Importa achados para o DefectDojo.
- [`reimport`](./#reimport)     Reimporta achados para o DefectDojo.
- [`export`](./#export)	Exporta achados do DefectDojo.
- [`interactive`](./#interactive)   Inicia um modo interativo para configurar o processo de importação e reimportação, passo a 

### Opções globais

`--help, -h`     
* exibe a ajuda

`--version, -v`
* exibe a versão

#### Formatação da CLI

`--no-color`
* Desativa a saída colorida. (padrão: false) `[$DD_CLI_NO_COLOR]`
`--no-emojis, --no-emoji`

* Desativa emojis na saída. (padrão: false) `[$DD_CLI_NO_EMOJIS]`

* `--verbose`
Ativa a saída detalhada. (padrão: false) `[$DD_CLI_VERBOSE]`

### Import

Use o comando import para importar novos achados para o DefectDojo.

#### Uso

```
defectdojo-cli [global options] import <required flags> [optional flags]
	or: defectdojo-cli [global options] import  --config ./config-file-path
	or: defectdojo-cli import [-h | --help]
	or: defectdojo-cli import example [subcommand options]
	or: defectdojo-cli import example [-h | --help]

>> The API token must be set in the environment variable `DD_CLI_API_TOKEN`.
```

O comando `import` pode importar Achados de duas maneiras:

**Por ID:**
* Crie um Produto (ou use um produto existente)
* Crie um Engajamento dentro do produto
* Informe o id do Engajamento no parâmetro engagement

Nesse cenário, um novo Teste será criado dentro do Engajamento.

**Por nome:**

* Crie um Produto (ou use um produto existente)
* Crie um Engajamento dentro do produto
* Informe o product-name
* Informe o engagement-name
* Opcionalmente, informe o product-type-name

Nesse cenário, o DefectDojo procurará o Engajamento pelos detalhes fornecidos.

Ao usar nomes, você pode permitir que o importador crie automaticamente Engajamentos, Produtos e Product-types usando `auto-create-context=true`.
Você pode usar `deduplication-on-engagement` para restringir a deduplicação dos Achados importados ao Engajamento recém-criado.


**Sintaxe básica do import:**
```
defectdojo-cli import [options]
```

#### **Exemplo de import:**
```
defectdojo-cli import \
--defectdojo-url "https://YOUR_INSTANCE.cloud.defectdojo.com/" \
--scan-type "burp scan" \
--report-path "./examples/burp_findings.xml" \
--product-name "dev" \
--engagement-name "dev" \
--product-type-name "Research and Development" \
--test-name "burp-test-dev" \
--verified \
--active \
--minimum-severity "info" \
--tag "dev" --tag "tools" --tag "burp" --tag "test-dev" \
--test-version "0.0.1" \
--auto-create-context
```

#### Comandos
`example, x`
* Mostra um exemplo de flags obrigatórias e opcionais para a operação de import

#### Opções

`--active, -a` 
* Determina se os Achados devem ser forçados para Ativo ou Inativo na importação. Um valor True força os Achados para Ativo, enquanto um valor False força todos os Achados para Inativo. Se nenhum valor for definido, o status Ativo dependerá do arquivo de relatório de entrada. (padrão: unset) `[$DD_CLI_ACTIVE]`

`--api-scan-configuration value, --asc value`
* O ID do objeto de Configuração de Scan de API a ser usado na importação ou reimportação. (padrão: 0) `[$DD_CLI_API_SCAN_CONFIGURATION]`

`--apply-tags-endpoints, --te`
* Se definido como true, as tags (da opção --tag) serão aplicadas aos endpoints (padrão: false) 
`[$DD_CLI_APPLY_TAGS_ENDPOINTS]`

`--apply-tags-findings, --tf`
* Se definido como true, as tags (da opção --tag) serão aplicadas aos achados (padrão: false) `[$DD_CLI_APPLY_TAGS_FINDINGS]`

`--auto-create-context, --acc`
* Se definido como true, o importador cria automaticamente Engajamentos, Produtos e Product_Types (padrão: false) `[$DD_CLI_AUTO_CREATE_CONTEXT]`

`--close-old-findings, --cof`
* Se True, Achados antigos que não estiverem mais presentes no relatório serão Fechados como Mitigado durante a importação. Se o Service tiver sido definido, apenas os Achados desse Service serão fechados. [$DD_CLI_CLOSE_OLD_FINDINGS]

`--close-old-findings-product-scope, --cofps`
* Define se --close-old-findings se aplica a **todos** os Achados do mesmo tipo no Produto. Por padrão, isso é definido como false, o que significa que apenas Achados antigos do mesmo tipo no Engajamento estão no escopo (e serão fechados pelo Close Old Findings). [$DD_CLI_CLOSE_OLD_FINDINGS_PRODUCT_SCOPE]

`--deduplication-on-engagement, --doe`
* Se definido como true, o importador restringe a deduplicação dos achados importados ao Engajamento recém-criado. (padrão: false) `[$DD_CLI_DEDUPLICATION_ON_ENGAGEMENT]`

`--engagement-id value, --ei value`
* O ID do Engajamento no qual importar os achados. (padrão: 0) `[$DD_CLI_ENGAGEMENT_ID]`

`--engagement-name value, -e value`
* O nome do Engajamento no qual importar os achados. `[$DD_CLI_ENGAGEMENT_NAME]`

`--minimum-severity value, --ms value`
* Determina o nível de severidade mais baixo que deve ser importado. Os valores válidos são: Critical, High, Medium, Low, Info. (padrão: "Info") `[$DD_CLI_MINIMUM_SEVERITY]`

`--product-name value, -p value`
* O nome do Produto no qual importar os achados. `[$DD_CLI_PRODUCT_NAME]`

`--product-type-name value, --pt value`
* O nome do Tipo de Produto no qual importar os achados. `[$DD_CLI_PRODUCT_TYPE_NAME]`

`--report-path value, -r value`
* O caminho do relatório a ser importado. (obrigatório). `[$DD_CLI_REPORT_PATH]`

`--scan-type value, -s value`
* O tipo de scan da ferramenta (obrigatório). `[$DD_CLI_SCAN_TYPE]`

`--tag value, -t value [ --tag value, -t value ]`
* Quaisquer tags a serem aplicadas ao objeto Test `[$DD_CLI_TAGS]`

`--test-name value, --tn value`
* O nome do Teste no qual importar os achados - o padrão é o nome do tipo de scan. `[$DD_CLI_TEST_NAME]`

`--test-version value, -V value`
* A versão do teste. `[$DD_CLI_TEST_VERSION]`

`--verified, -v`
* Determina se os Achados devem ser definidos como Verificado na importação. Um valor True força os Achados para Verificado. Se nenhum valor for definido, o status Verificado dependerá do arquivo de relatório de entrada. `[$DD_CLI_VERIFIED]`

**Configurações:**

`--config value, -c value`          
* O caminho do arquivo de configuração TOML é usado para definir valores para as opções. Se a opção estiver definida no arquivo de configuração e na CLI, a opção usará o valor definido na CLI. `[$DD_CLI_CONFIG_FILE]`
`--defectdojo-url value, -u value`
* A URL da instância do DefectDojo na qual importar os achados. (obrigatório). `[$DD_CLI_DEFECTDOJO_URL]`
* --insecure-tls, --no-tls          ignora erros de validação de TLS ao se conectar à instância do DefectDojo fornecida. A maioria dos usuários não deve ativar esta flag. (padrão: false) `[$DD_CLI_INSECURE_TLS]`

### Reimport

Use o comando `reimport` para estender um Teste existente com Achados de um novo relatório de uma das duas maneiras a seguir:

Por ID:
- Crie um Produto (ou use um produto existente)
- Crie um Engajamento dentro do produto
- Importe um relatório de scan e encontre o id do Teste
- Informe esse id no parâmetro test-id

Por nomes:
- Crie um Produto (ou use um produto existente)
- Crie um Engajamento dentro do produto
- Importe um relatório, o que criará um Teste
- Informe o product-name
- Informe o engagement-name
- Opcional: informe o test-name

Nesse cenário, o DefectDojo procurará o Teste pelos detalhes fornecidos. Se nenhum test-name for informado, o teste mais recente dentro do engagement será escolhido com base no scan-type.

Ao usar nomes, você pode permitir que o importador crie automaticamente Engajamentos, Produtos e Product-types usando `auto-create-context=true`.
Você pode usar `deduplication-on-engagement` para restringir a deduplicação dos Achados importados ao Engajamento recém-criado.

#### Uso

```
defectdojo-cli [global options] reimport <required flags> [optional flags]
   or: defectdojo-cli [global options] reimport  --config ./config-file-path
   or: defectdojo-cli reimport [-h | --help]
   or: defectdojo-cli reimport example [subcommand options]
   or: defectdojo-cli reimport example [-h | --help]

>> The API token must be set in the environment variable `DD_CLI_API_TOKEN`.
```

#### **Exemplo de reimport:**

```
defectdojo-cli reimport \
--defectdojo-url "https://YOUR_INSTANCE.cloud.defectdojo.com/" \
--scan-type "Nancy Scan" \
--report-path "./examples/nancy_findings.json" \
--test-id 11 \
--verified \
--active \
--minimum-severity "info" \
--tag "dev" --tag "tools" --tag "nancy" --tag "test-dev" \
--test-version "1.0" \
--auto-create-context
```

#### Comandos

```
example, x  Shows an example of required and optional flags for reimport operation
```

#### Opções

`--active, -a`                                    
* Determina se os Achados devem ser forçados para Ativo ou Inativo na importação. Um valor True força os Achados para Ativo, enquanto um valor False força todos os Achados para Inativo. Se nenhum valor for definido, o status Ativo dependerá do arquivo de relatório de entrada. `[$DD_CLI_ACTIVE]`

`--api-scan-configuration value, --asc value`

* O ID do objeto de Configuração de Scan de API a ser usado na importação ou reimportação. (padrão: 0) `[$DD_CLI_API_SCAN_CONFIGURATION]`

`--apply-tags-endpoints, --te`                     
* Se definido como true, as tags (da opção --tag) serão aplicadas aos endpoints (padrão: false) `[$DD_CLI_APPLY_TAGS_ENDPOINTS]`

`--apply-tags-findings, --tf`                      
* Se definido como true, as tags (da opção --tag) serão aplicadas aos achados (padrão: false) `[$DD_CLI_APPLY_TAGS_FINDINGS]`

`--auto-create-context, --acc`                 
* Se definido como true, o importador cria automaticamente Engajamentos, Produtos e Product_Types (padrão: false) `[$DD_CLI_AUTO_CREATE_CONTEXT]`

`--close-old-findings, --cof`
* Se True, Achados antigos que não estiverem mais presentes no relatório serão Fechados como Mitigado durante a importação. Se o Service tiver sido definido, apenas os achados desse Service serão fechados.[$DD_CLI_CLOSE_OLD_FINDINGS]

`--close-old-findings-product-scope, --cofps`
* Define se --close-old-findings se aplica a **todos** os Achados do mesmo tipo no Produto. Por padrão, isso é definido como false, o que significa que apenas Achados antigos do mesmo tipo no Engajamento estão no escopo (e serão fechados pelo Close Old Findings). [$DD_CLI_CLOSE_OLD_FINDINGS_PRODUCT_SCOPE]

`--deduplication-on-engagement, --doe`          
* Se definido como true, o importador restringe a deduplicação dos achados importados ao Engajamento recém-criado. (padrão: false) `[$DD_CLI_DEDUPLICATION_ON_ENGAGEMENT]`

`--engagement-name value, -e value`               
* O nome do Engajamento no qual importar os achados. `[$DD_CLI_ENGAGEMENT_NAME]`

`--minimum-severity value, --ms value`          
* Determina o nível de severidade mais baixo que deve ser importado. Os valores válidos são: Critical, High, Medium, Low, Info. (padrão: "Info") `[$DD_CLI_MINIMUM_SEVERITY]`

`--product-name value, -p value`                   
* O nome do Produto no qual importar os achados. `[$DD_CLI_PRODUCT_NAME]`

`--product-type-name value, --pt value`         
* O nome do Tipo de Produto no qual importar os achados. `[$DD_CLI_PRODUCT_TYPE_NAME]`

`--report-path value, -r value`                    
* O caminho do relatório a ser importado. (obrigatório). `[$DD_CLI_REPORT_PATH]`

`--scan-type value, -s value`                      
* O tipo de scan da ferramenta (obrigatório). `[$DD_CLI_SCAN_TYPE]`

`--tag value, -t value [ --tag value, -t value ]`  
* Quaisquer tags a serem aplicadas ao objeto Test `[$DD_CLI_TAGS]`

`--test-id value, --ti value`                      
* O ID do Teste no qual reimportar os achados. (padrão: 0) `[$DD_CLI_TEST_ID]`

`--test-name value, --tn value`                    
* O nome do Teste no qual importar os achados - o padrão é o nome do tipo de scan. `[$DD_CLI_TEST_NAME]`

`--test-version value, -V value`                   
* A versão do teste. `[$DD_CLI_TEST_VERSION]`

`--verified, -v`                                   
* Determina se os Achados devem ser definidos como Verificado na importação. Um valor True força os Achados para Verificado. Se nenhum valor for definido, o status Verificado dependerá do arquivo de relatório de entrada. `[$DD_CLI_VERIFIED]`

**Configurações:**

`--config value, -c value`
* O caminho do arquivo de configuração TOML é usado para definir valores para as opções. Se a opção estiver definida no arquivo de configuração e na CLI, a opção usará o valor definido na CLI. `[$DD_CLI_CONFIG_FILE]`

`--defectdojo-url value, -u value`  
* A URL da instância do DefectDojo na qual importar os achados. (obrigatório). `[$DD_CLI_DEFECTDOJO_URL]`

`--insecure-tls, --no-tls`
* ignora erros de validação de TLS ao se conectar à instância do DefectDojo fornecida. A maioria dos usuários não deve ativar esta flag. (padrão: false) `[$DD_CLI_INSECURE_TLS]`

### Export

#### Uso

```
defectdojo-cli export <required options> [optional options]
	or: defectdojo-cli [global options] export --defectdojo-url <https://YOUR_INSTANCE.cloud.defectdojo.com/> --json ./output_file_path.json [optional filters]
	or: defectdojo-cli [global options] export --defectdojo-url <https://YOUR_INSTANCE.cloud.defectdojo.com/> --csv ./output_file_path.csv [optional filters]
	or: defectdojo-cli [global options] export --defectdojo-url <https://YOUR_INSTANCE.cloud.defectdojo.com/> --json ./output_file_path.json --csv ./output_file_path.csv [optional filters]
	or: defectdojo-cli [global options] export --config ./config-file-path
	or: defectdojo-cli [global options] export --config ./config-file-path --json ./output_file_path.json
	or: defectdojo-cli [global options] export --config ./config-file-path --csv ./output_file_path.csv
	or: defectdojo-cli export [-h | --help]
	or: defectdojo-cli export example [subcommand options]
	or: defectdojo-cli export example [-h | --help]

>> The API token must be set in the environment variable `DD_CLI_API_TOKEN`.
```

Para exportar Achados do DefectDojo-CLI, você precisará fornecer um arquivo de configuração contendo os detalhes que especificam quais Achados deseja exportar.  Isso é semelhante ao método GET Findings via API.

Para obter ajuda, use `defectdojo-cli export --help`.

#### **Exemplo de export**

Este exemplo especifica a URL, o formato de exportação e alguns parâmetros de filtro para criar uma lista de Achados.

```
defectdojo-cli export \
--defectdojo-url "https://your-dojo-instance.cloud.defectdojo.com/"
--json "./path/to/findings.json" \
--active "true" \
--created "Past 90 days"
```

#### Comandos

`example, x`
* Mostra um exemplo de flags obrigatórias e opcionais para a operação de export

`help, h`
* Mostra uma lista de comandos ou ajuda para um comando

#### Opções

**Filtros de Achados:**

`--active true|false, -a true|false`
* Achados por status Ativo. `[$DD_CLI_FINDINGS_FILTERS_ACTIVE]`

`--created value`
* Achados por data de criação. Valores suportados: None, Today, Past 7 days, Past 30 days, Past 90 days, Current month, Current year, Past year `[$DD_CLI_FINDINGS_FILTERS_CREATED]`

`--cvssv3-score value`
* Achados por pontuação CVSS v3. (padrão: ignored) `[$DD_CLI_FINDINGS_FILTERS_CVSSV3_SCORE]`

`--cwe value` 
* Achados por ID de CWE. (padrão: ignored) `[$DD_CLI_FINDINGS_FILTERS_CWE]`

`--date value`
* Achados por data. Valores suportados: None, Today, Past 7 days, Past 30 days, Past 90 days, Current month, Current year, Past year `[$DD_CLI_FINDINGS_FILTERS_DATE]`

`--discovered-after value`
* Achados descobertos após a data especificada. Formato: YYYY-MM-DD `[$DD_CLI_FINDINGS_FILTERS_DISCOVERED_AFTER]`

`--discovered-before value`
* Achados descobertos antes da data especificada. Formato: YYYY-MM-DD `[$DD_CLI_FINDINGS_FILTERS_DISCOVERED_BEFORE]`

`--discovered-on value`
* Achados por data de descoberta. Formato: YYYY-MM-DD `[$DD_CLI_FINDINGS_FILTERS_DISCOVERED_ON]`

`--duplicate true|false`
* Achados por status de duplicidade. `[$DD_CLI_FINDINGS_FILTERS_DUPLICATE]`

`--engagement-ids value [ --engagement-ids value ]`
* Achados por IDs de engagement. Esta flag pode ser usada várias vezes ou como uma lista separada por vírgulas. `[$DD_CLI_FINDINGS_FILTERS_ENGAGEMENT]`

`--epss-percentile value`
* Achados por percentil EPSS. (padrão: ignored) `[$DD_CLI_FINDINGS_FILTERS_EPSS_PERCENTILE]`

`--epss-score value`
* Achados por pontuação EPSS. (padrão: ignored) `[$DD_CLI_FINDINGS_FILTERS_EPSS_SCORE]`

`--false-positive true|false`
* Achados por status de Falso positivo. `[$DD_CLI_FINDINGS_FILTERS_FALSE_POSITIVE]`

`--is-mitigated true|false`
* Achados por status de mitigação. `[$DD_CLI_FINDINGS_FILTERS_IS_MITIGATED]`

`--mitigated value`
* Achados pelo intervalo de datas em que foram marcados como mitigados. Valores suportados: None, Today, Past 7 days, Past 30 days, Past 90 days, Current month, Current year, Past year `[$DD_CLI_FINDINGS_FILTERS_MITIGATED]`

`--mitigated-after value`
* Achados mitigados após a data especificada. Formato: YYYY-MM-DD `[$DD_CLI_FINDINGS_FILTERS_MITIGATED_AFTER]`

`--mitigated-before value`
* Achados mitigados antes da data especificada. Formato: YYYY-MM-DD `[$DD_CLI_FINDINGS_FILTERS_MITIGATED_BEFORE]`

`--mitigated-by-ids value [ --mitigated-by-ids value ]`
* Achados por IDs de usuário mitigated_by. Esta flag pode ser usada várias vezes ou como uma lista separada por vírgulas. Pode ser combinada com --mitigated-by-names. `[$DD_CLI_FINDINGS_FILTERS_MITIGATED_BY_IDS]`

`--mitigated-by-names value [ --mitigated-by-names value ]`
* Achados por nomes de usuário mitigated_by. Esta flag pode ser usada várias vezes ou como uma lista separada por vírgulas. Pode ser combinada com --mitigated-by-ids. `[$DD_CLI_FINDINGS_FILTERS_MITIGATED_BY_NAMES]`

`--mitigated-on value`
* Achados por data de mitigação. Formato: YYYY-MM-DD `[$DD_CLI_FINDINGS_FILTERS_MITIGATED_ON]`

`--not-tags value [ --not-tags value ]`
* Achados por tags que não devem estar presentes. Esta flag pode ser usada várias vezes ou como uma lista separada por vírgulas. `[$DD_CLI_FINDINGS_FILTERS_NOT_TAGS]`

`--out-of-scope true|false`
* Achados por status Fora do escopo ou dentro do escopo. `[$DD_CLI_FINDINGS_FILTERS_OUT_OF_SCOPE]`

`--out-of-sla true|false`
* Achados por status dentro ou fora do SLA. `[$DD_CLI_FINDINGS_FILTERS_OUT_OF_SLA]`

`--product-name value`
* Achados por nome do produto. `[$DD_CLI_FINDINGS_FILTERS_PRODUCT_NAME]`

`--product-name-contains value`
* Achados cujo nome do produto contém o valor informado. `[$DD_CLI_FINDINGS_FILTERS_PRODUCT_NAME_CONTAINS]`

`--product-type-ids value [ --product-type-ids value ]`
* Achados por IDs de tipo de produto. Esta flag pode ser usada várias vezes ou como uma lista separada por vírgulas. Pode ser combinada com --product-type-names `[$DD_CLI_FINDINGS_FILTERS_PRODUCT_TYPE_IDS]`

`--product-type-names value [ --product-type-names value ]`
* Achados por nomes de tipo de produto. Esta flag pode ser usada várias vezes ou como uma lista separada por vírgulas. Pode ser combinada com --product-type-ids `[$DD_CLI_FINDINGS_FILTERS_PRODUCT_TYPE_NAMES]`

`--risk-accepted true|false`
* Achados por status de Risco aceito. `[$DD_CLI_FINDINGS_FILTERS_RISK_ACCEPTED]`

`--severity value [ --severity value ]`
* Achados por severidade. Os valores válidos são: Critical, High, Medium, Low, Info. Esta flag pode ser usada várias vezes ou como uma lista separada por vírgulas. `[$DD_CLI_FINDINGS_FILTERS_SEVERITY]`

`--tags value [ --tags value ]`
* Achados por tags que devem estar presentes. Esta flag pode ser usada várias vezes ou como uma lista separada por vírgulas. `[$DD_CLI_FINDINGS_FILTERS_TAGS]`

`--test-id value`
* Achados por ID de teste. (padrão: ignored) `[$DD_CLI_FINDINGS_FILTERS_TEST_ID]`

`--title-contains value`
* Achados cujo título contém a string informada. `[$DD_CLI_FINDINGS_FILTERS_TITLE_CONTAINS]`

`--under-review true|false`
* Achados por status em revisão. `[$DD_CLI_FINDINGS_FILTERS_UNDER_REVIEW]`

`--verified true|false`
* Achados por status Verificado. (padrão: ignored) `[$DD_CLI_FINDINGS_FILTERS_VERIFIED]`

`--vulnerability-id value [ --vulnerability-id value ]`
* Achados por ID de vulnerabilidade. Esta flag pode ser usada várias vezes ou como uma lista separada por vírgulas. `[$DD_CLI_FINDINGS_FILTERS_VULNERABILITY_ID]`

**Saída de Achados**

`--csv value`
* Caminho do arquivo onde o arquivo CSV dos achados será gravado. `[$DD_CLI_FINDINGS_OUTPUT_CSV_PATH_FILE]`

`--json value`  Caminho do arquivo onde o arquivo JSON dos achados será gravado. `[$DD_CLI_FINDINGS_OUTPUT_JSON_PATH_FILE]`

**Configurações**

`--config value, -c value`
O caminho do arquivo de configuração TOML é usado para definir valores para as opções. Se a opção estiver definida no arquivo de configuração e na CLI, a opção usará o valor definido na CLI. `[$DD_CLI_CONFIG_FILE]`

`--defectdojo-url value, -u value`
A URL da instância do DefectDojo na qual importar os achados. (obrigatório). `[$DD_CLI_DEFECTDOJO_URL]`

`--insecure-tls, --no-tls`
ignora erros de validação de TLS ao se conectar à instância do DefectDojo fornecida. A maioria dos usuários não deve ativar esta flag. (padrão: false) `[$DD_CLI_INSECURE_TLS]`

#### Exemplo de export:

```
defectdojo-cli export \
--defectdojo-url "https://your-dojo-instance.cloud.defectdojo.com/"
```

### Interactive

O modo interativo permite configurar o processo de importação e reimportação, passo a passo.

#### Uso

```
defectdojo-cli interactive
	or: defectdojo-cli interactive  [--skip-intro] [--no-full-screen] [--log-path]
	or: defectdojo-cli interactive [-h | --help]
```

#### Opções

`--skip-intro `    
* Pula a tela de introdução (padrão: false)

`--no-full-screen`
* Desativa o modo tela cheia (padrão: false)

`--log-path value`
* Caminho para o arquivo de log

`--help, -h`
* exibe a ajuda

## Universal Importer

`universal-importer` integra os resultados de scans ao DefectDojo de forma transparente, simplificando os processos de importação e reimportação de achados e objetos associados. Projetada para facilidade de uso, a ferramenta oferece suporte a vários endpoints, atendendo tanto importações iniciais quanto reimportações subsequentes — ideal para usuários que precisam de uma interação robusta e flexível com a API do DefectDojo.

Embora semelhante ao DefectDojo-CLI, o Universal Importer não possui a funcionalidade de exportação, e as variáveis de ambiente são codificadas de forma diferente.

### Comandos

- [`import`](./#import-1)       Importa achados para o DefectDojo.
- [`reimport`](./#reimport-1)     Reimporta achados para o DefectDojo.
- [`interactive`](./#interactive-1)   Inicia um modo interativo para configurar o processo de importação e reimportação, passo a 

### Opções globais

`--help, -h`     
* exibe a ajuda

`--version, -v`
* exibe a versão

#### Formatação da CLI

`--no-color`
* Desativa a saída colorida. (padrão: false) `[$DD_IMPORTER_NO_COLOR]`

`--no-emojis, --no-emoji`
* Desativa emojis na saída. (padrão: false) `[$DD_IMPORTER_NO_EMOJIS]`

`--verbose`
* Ativa a saída detalhada. (padrão: false) `[$DD_IMPORTER_VERBOSE]`

### Import

Use o comando import para importar novos achados para o DefectDojo.

#### Uso

```
universal-importer [global options] import <required flags> [optional flags]
	or: universal-importer [global options] import  --config ./config-file-path
	or: universal-importer import [-h | --help]
	or: universal-importer import example [subcommand options]
	or: universal-importer import example [-h | --help]

>> The API token must be set in the environment variable `DD_IMPORTER_DOJO_API_TOKEN`.
```

`import` pode importar Achados de duas maneiras:

**Por ID:**
* Crie um Produto (ou use um produto existente)
* Crie um Engajamento dentro do produto
* Informe o id do Engajamento no parâmetro engagement

Nesse cenário, um novo Teste será criado dentro do Engajamento.

**Por nome:**
* Crie um Produto (ou use um produto existente)
* Crie um Engajamento dentro do produto
* Informe o product-name
* Informe o engagement-name
* Opcionalmente, informe o product-type-name

Nesse cenário, o DefectDojo procurará o Engajamento pelos detalhes fornecidos.

Ao usar nomes, você pode permitir que o importador crie automaticamente Engajamentos, Produtos e Product-types usando `auto-create-context=true`.
Você pode usar `deduplication-on-engagement` para restringir a deduplicação dos Achados importados ao Engajamento recém-criado.


**Sintaxe básica do import:**

```
universal-importer import [options]
```

#### **Exemplo de import:**

```
universal-importer import \
--defectdojo-url "https://YOUR_INSTANCE.cloud.defectdojo.com/" \
--scan-type "burp scan" \
--report-path "./examples/burp_findings.xml" \
--product-name "dev" \
--engagement-name "dev" \
--product-type-name "Research and Development" \
--test-name "burp-test-dev" \
--verified \
--active \
--minimum-severity "info" \
--tag "dev" --tag "tools" --tag "burp" --tag "test-dev" \
--test-version "0.0.1" \
--auto-create-context
```

#### Comandos

`example, x`
* Mostra um exemplo de flags obrigatórias e opcionais para a operação de import

#### Opções

`--active, -a` 
* Determina se os Achados devem ser forçados para Ativo ou Inativo na importação. Um valor True força os Achados para Ativo, enquanto um valor False força todos os Achados para Inativo. Se nenhum valor for definido, o status Ativo dependerá do arquivo de relatório de entrada. `[$DD_IMPORTER_ACTIVE]`

`--api-scan-configuration value, --asc value`
* O ID do objeto de Configuração de Scan de API a ser usado na importação ou reimportação. (padrão: 0) `[$DD_IMPORTER_API_SCAN_CONFIGURATION]`

`--apply-tags-endpoints, --te`
* Se definido como true, as tags (da opção --tag) serão aplicadas aos endpoints (padrão: false) 
`[$DD_IMPORTER_APPLY_TAGS_ENDPOINTS]`

`--apply-tags-findings, --tf`
* Se definido como true, as tags (da opção --tag) serão aplicadas aos achados (padrão: false) `[$DD_IMPORTER_APPLY_TAGS_FINDINGS]`

`--auto-create-context, --acc`
* Se definido como true, o importador cria automaticamente Engajamentos, Produtos e Product_Types (padrão: false) `[$DD_IMPORTER_AUTO_CREATE_CONTEXT]`

`--close-old-findings, --cof`
* Se True, Achados antigos que não estiverem mais presentes no relatório serão Fechados como Mitigado durante a importação. Se o Service tiver sido definido, apenas os achados desse Service serão fechados. [$DD_IMPORTER_CLOSE_OLD_FINDINGS]

`--close-old-findings-product-scope, --cofps`
* Define se --close-old-findings se aplica a **todos** os Achados do mesmo tipo no Produto. Por padrão, isso é definido como false, o que significa que apenas Achados antigos do mesmo tipo no Engajamento estão no escopo (e serão fechados pelo Close Old Findings). [$DD_IMPORTER_CLOSE_OLD_FINDINGS_PRODUCT_SCOPE]

`--deduplication-on-engagement, --doe`
* Se definido como true, o importador restringe a deduplicação dos achados importados ao Engajamento recém-criado. (padrão: false) `[$DD_IMPORTER_DEDUPLICATION_ON_ENGAGEMENT]`

`--engagement-id value, --ei value`
* O ID do Engajamento no qual importar os achados. (padrão: 0) `[$DD_IMPORTER_ENGAGEMENT_ID]`

`--engagement-name value, -e value`
* O nome do Engajamento no qual importar os achados. `[$DD_IMPORTER_ENGAGEMENT_NAME]`

`--minimum-severity value, --ms value`
* Determina o nível de severidade mais baixo que deve ser importado. Os valores válidos são: Critical, High, Medium, Low, Info. (padrão: "Info") `[$DD_IMPORTER_MINIMUM_SEVERITY]`

`--product-name value, -p value`
* O nome do Produto no qual importar os achados. `[$DD_IMPORTER_PRODUCT_NAME]`

`--product-type-name value, --pt value`
* O nome do Tipo de Produto no qual importar os achados. `[$DD_IMPORTER_PRODUCT_TYPE_NAME]`

`--report-path value, -r value`
* O caminho do relatório a ser importado. (obrigatório). `[$DD_IMPORTER_REPORT_PATH]`

`--scan-type value, -s value`
* O tipo de scan da ferramenta (obrigatório). `[$DD_IMPORTER_SCAN_TYPE]`

`--tag value, -t value [ --tag value, -t value ]`
* Quaisquer tags a serem aplicadas ao objeto Test `[$DD_IMPORTER_TAGS]`

`--test-name value, --tn value`
* O nome do Teste no qual importar os achados - o padrão é o nome do tipo de scan. `[$DD_IMPORTER_TEST_NAME]`

`--test-version value, -V value`
* A versão do teste. `[$DD_IMPORTER_TEST_VERSION]`

`--verified, -v`
* Determina se os Achados devem ser definidos como Verificado na importação. Um valor True força os Achados para Verificado. Se nenhum valor for definido, o status Verificado dependerá do arquivo de relatório de entrada. `[$DD_IMPORTER_VERIFIED]`

**Configurações:**

`--config value, -c value`          
* O caminho do arquivo de configuração TOML é usado para definir valores para as opções. Se a opção estiver definida no arquivo de configuração e na CLI, a opção usará o valor definido na CLI. `[$DD_IMPORTER_CONFIG_FILE]`
`--defectdojo-url value, -u value`
* A URL da instância do DefectDojo na qual importar os achados. (obrigatório). `[$DD_IMPORTER_DEFECTDOJO_URL]`
* --insecure-tls, --no-tls          ignora erros de validação de TLS ao se conectar à instância do DefectDojo fornecida. A maioria dos usuários não deve ativar esta flag. (padrão: false) `[$DD_IMPORTER_INSECURE_TLS]`

### Reimport

Use o comando `reimport` para estender um Teste existente com Achados de um novo relatório de uma das duas maneiras a seguir:

By ID:
- Crie um Produto (ou use um produto existente)
- Crie um Engajamento dentro do produto
- Importe um relatório de scan e encontre o id do Teste
- Informe esse id no parâmetro test-id

By Names:
- Crie um Produto (ou use um produto existente)
- Crie um Engajamento dentro do produto
- Importe um relatório, o que criará um Teste
- Informe o product-name
- Informe o engagement-name
- Opcional: informe o test-name

Nesse cenário, o DefectDojo procurará o Teste pelos detalhes fornecidos. Se nenhum test-name for informado, o teste mais recente dentro do engagement será escolhido com base no scan-type.

Ao usar nomes, você pode permitir que o importador crie automaticamente Engajamentos, Produtos e Product-types usando `auto-create-context=true`.
Você pode usar `deduplication-on-engagement` para restringir a deduplicação dos Achados importados ao Engajamento recém-criado.

#### Uso

```
universal-importer [global options] reimport <required flags> [optional flags]
   or: universal-importer [global options] reimport  --config ./config-file-path
   or: universal-importer reimport [-h | --help]
   or: universal-importer reimport example [subcommand options]
   or: universal-importer reimport example [-h | --help]

>> The API token must be set in the environment variable `DD_IMPORTER_DOJO_API_TOKEN`.
```

#### **Exemplo de reimport:**

```
universal-importer reimport \
--defectdojo-url "https://YOUR_INSTANCE.cloud.defectdojo.com/" \
--scan-type "Nancy Scan" \
--report-path "./examples/nancy_findings.json" \
--test-id 11 \
--verified \
--active \
--minimum-severity "info" \
--tag "dev" --tag "tools" --tag "nancy" --tag "test-dev" \
--test-version "1.0" \
--auto-create-context
```

#### Comandos

```
example, x  Shows an example of required and optional flags for reimport operation
```

#### Opções

`--active, -a`                                    
* Determina se os Achados devem ser forçados para Ativo ou Inativo na importação. Um valor True força os Achados para Ativo, enquanto um valor False força todos os Achados para Inativo. Se nenhum valor for definido, o status Ativo dependerá do arquivo de relatório de entrada. `[$DD_IMPORTER_ACTIVE]`

`--api-scan-configuration value, --asc value`
* O ID do objeto de Configuração de Scan de API a ser usado na importação ou reimportação. (padrão: 0) `[$DD_IMPORTER_API_SCAN_CONFIGURATION]`

`--apply-tags-endpoints, --te`                     
* Se definido como true, as tags (da opção --tag) serão aplicadas aos endpoints (padrão: false) `[$DD_IMPORTER_APPLY_TAGS_ENDPOINTS]`

`--apply-tags-findings, --tf`                      
* Se definido como true, as tags (da opção --tag) serão aplicadas aos achados (padrão: false) `[$DD_IMPORTER_APPLY_TAGS_FINDINGS]`

`--auto-create-context, --acc`                 
* Se definido como true, o importador cria automaticamente Engajamentos, Produtos e Product_Types (padrão: false) `[$DD_IMPORTER_AUTO_CREATE_CONTEXT]`

`--close-old-findings, --cof`
* Se True, Achados antigos que não estiverem mais presentes no relatório serão Fechados como Mitigado durante a importação. Se o Service tiver sido definido, apenas os Achados desse Service serão fechados. [$DD_IMPORTER_CLOSE_OLD_FINDINGS]

`--close-old-findings-product-scope, --cofps`
* Define se --close-old-findings se aplica a **todos** os Achados do mesmo tipo no Produto. Por padrão, isso é definido como false, o que significa que apenas Achados antigos do mesmo tipo no Engajamento estão no escopo (e serão fechados pelo Close Old Findings). [$DD_IMPORTER_CLOSE_OLD_FINDINGS_PRODUCT_SCOPE]

`--deduplication-on-engagement, --doe`          
* Se definido como true, o importador restringe a deduplicação dos achados importados ao Engajamento recém-criado. (padrão: false) `[$DD_IMPORTER_DEDUPLICATION_ON_ENGAGEMENT]`

`--engagement-name value, -e value`               
* O nome do Engajamento no qual importar os achados. `[$DD_IMPORTER_ENGAGEMENT_NAME]`

`--minimum-severity value, --ms value`          
* Determina o nível de severidade mais baixo que deve ser importado. Os valores válidos são: Critical, High, Medium, Low, Info. (padrão: "Info") `[$DD_IMPORTER_MINIMUM_SEVERITY]`

`--product-name value, -p value`                   
* O nome do Produto no qual importar os achados. `[$DD_IMPORTER_PRODUCT_NAME]`

`--product-type-name value, --pt value`         
* O nome do Tipo de Produto no qual importar os achados. `[$DD_IMPORTER_PRODUCT_TYPE_NAME]`

`--report-path value, -r value`                    
* O caminho do relatório a ser importado. (obrigatório). `[$DD_IMPORTER_REPORT_PATH]`

`--scan-type value, -s value`                      
* O tipo de scan da ferramenta (obrigatório). `[$DD_IMPORTER_SCAN_TYPE]`

`--tag value, -t value [ --tag value, -t value ]`  
* Quaisquer tags a serem aplicadas ao objeto Test `[$DD_IMPORTER_TAGS]`

`--test-id value, --ti value`                      
* O ID do Teste no qual reimportar os achados. (padrão: 0) `[$DD_IMPORTER_TEST_ID]`

`--test-name value, --tn value`                    
* O nome do Teste no qual importar os achados - o padrão é o nome do tipo de scan. `[$DD_IMPORTER_TEST_NAME]`

`--test-version value, -V value`                   
* A versão do teste. `[$DD_IMPORTER_TEST_VERSION]`

`--verified, -v`                                   
* Determina se os Achados devem ser definidos como Verificado na importação. Um valor True força os Achados para Verificado. Se nenhum valor for definido, o status Verificado dependerá do arquivo de relatório de entrada. (padrão: unset) `[$DD_IMPORTER_VERIFIED]`

**Configurações:**

`--config value, -c value`
* O caminho do arquivo de configuração TOML é usado para definir valores para as opções. Se a opção estiver definida no arquivo de configuração e na CLI, a opção usará o valor definido na CLI. `[$DD_IMPORTER_CONFIG_FILE]`

`--defectdojo-url value, -u value`  
* A URL da instância do DefectDojo na qual importar os achados. (obrigatório). `[$DD_IMPORTER_DEFECTDOJO_URL]`

`--insecure-tls, --no-tls`
* ignora erros de validação de TLS ao se conectar à instância do DefectDojo fornecida. A maioria dos usuários não deve ativar esta flag. (padrão: false) `[$DD_IMPORTER_INSECURE_TLS]`

### Interactive
O modo interativo permite configurar o processo de importação e reimportação, passo a passo.

#### Uso

```
universal-importer interactive
	or: universal-importer interactive  [--skip-intro] [--no-full-screen] [--log-path]
	or: universal-importer interactive [-h | --help]
```

#### Opções

`--skip-intro `    
* Pula a tela de introdução (padrão: false)

`--no-full-screen`
* Desativa o modo tela cheia (padrão: false)
`--log-path value`
* Caminho para o arquivo de log
`--help, -h`
* exibe a ajuda


## Solução de problemas

Se você encontrar algum problema com essas ferramentas, verifique o seguinte:
- Certifique-se de estar usando o binário correto para o seu sistema operacional e arquitetura de CPU.
- Verifique se a chave de API está definida corretamente nas suas variáveis de ambiente.
- Confira se a URL do DefectDojo está correta e acessível.
- Ao importar, confirme se o arquivo de relatório existe e está no formato suportado para o tipo de scan especificado.  Você pode consultar os scanners suportados pelo DefectDojo em nossa [lista de ferramentas suportadas](/supported_tools). 
