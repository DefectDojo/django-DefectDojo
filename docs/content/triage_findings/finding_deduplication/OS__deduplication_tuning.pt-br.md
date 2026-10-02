---
title: Ajuste de Deduplicação
description: 'Configure a deduplicação no DefectDojo Open Source: algoritmos, campos
  de hash, endpoints e serviço'
weight: 5
audience: opensource
aliases:
- /pt-br/en/working_with_findings/finding_deduplication/deduplication_tuning_os
- /pt-br/en/working_with_findings/finding_deduplication/deduplication_algorithms
---

A edição Open Source do DefectDojo usa arquivos de configuração e variáveis de ambiente para ajustar a deduplicação.

Veja também: [Configuração do Open Source](/get_started/open_source/configuration/) para detalhes sobre variáveis de ambiente e substituições em `local_settings.py`.

## O que você pode configurar

- **Algoritmo por parser**: Escolha entre Unique ID From Tool, Hash Code, Unique ID From Tool or Hash Code, ou Legacy (somente OS).
- **Campos de hash por scanner**: Decida quais campos contribuem para o hash de cada parser.
- **Permitir CWE nulo**: Controle se um CWE ausente/zero é aceitável ao gerar o hash.
- **Consideração de endpoint**: Opcionalmente, use endpoints para deduplicação quando eles não fizerem parte do hash.
- **Campos sempre incluídos**: Adicione campos (por exemplo, `service`) a todos os hashes, independentemente das configurações por scanner.

## Configurações principais (padrões exibidos)

Todos os padrões são definidos em `dojo/settings/settings.dist.py`. Substitua por meio de variáveis de ambiente ou de `local_settings.py`.

### Algoritmo por parser

- Configuração: `DEDUPLICATION_ALGORITHM_PER_PARSER`
- Valores por parser: um de `unique_id_from_tool`, `hash_code`, `unique_id_from_tool_or_hash_code`, `legacy`.
- Exemplo (string JSON de variável de ambiente):

```bash
DD_DEDUPLICATION_ALGORITHM_PER_PARSER='{"Trivy Scan": "hash_code", "Veracode Scan": "unique_id_from_tool_or_hash_code"}'
```

### Campos de hash por scanner

- Configuração: `HASHCODE_FIELDS_PER_SCANNER`
- Exemplo de padrão para o Trivy no OS:

```startLine:endLine:dojo/settings/settings.dist.py
1318:1321:dojo/settings/settings.dist.py
    "Trivy Operator Scan": ["title", "severity", "vulnerability_ids", "description"],
    "Trivy Scan": ["title", "severity", "vulnerability_ids", "cwe", "description"],
    "TFSec Scan": ["severity", "vuln_id_from_tool", "file_path", "line"],
    "Snyk Scan": ["vuln_id_from_tool", "file_path", "component_name", "component_version"],
```

- Exemplo de substituição (string JSON de variável de ambiente):

```bash
DD_HASHCODE_FIELDS_PER_SCANNER='{"ZAP Scan":["title","cwe","severity"],"Trivy Scan":["title","severity","vulnerability_ids","description"]}'
```

### Permitir CWE nulo por scanner

- Configuração: `HASHCODE_ALLOWS_NULL_CWE`
- Controla, por parser, se um CWE nulo/zero é aceitável no cálculo do hash. Se False e o achado tiver `cwe = 0`, o hash recorre ao cálculo legado (legacy) para esse achado.

### Campos sempre incluídos no hash

- Configuração: `HASH_CODE_FIELDS_ALWAYS`
- Padrão: `["service"]`
- Impacto: Anexado ao hash de todos os scanners. Remover `service` daqui impede que ele afete os hashes de forma geral.

```startLine:endLine:dojo/settings/settings.dist.py
1464:1466:dojo/settings/settings.dist.py
# Adding fields to the hash_code calculation regardless of the previous settings
HASH_CODE_FIELDS_ALWAYS = ["service"]
```

### Deduplicação opcional baseada em endpoint

- Configuração: `DEDUPE_ALGO_ENDPOINT_FIELDS`
- Padrão: `["host", "path"]`
- Propósito: Se os endpoints não fizerem parte dos campos de hash, você ainda pode exigir uma correspondência mínima de endpoint para deduplicar. Se a lista estiver vazia `[]`, os endpoints são ignorados no fluxo de deduplicação.

```startLine:endLine:dojo/settings/settings.dist.py
1491:1499:dojo/settings/settings.dist.py
# Allows to deduplicate with endpoints if endpoints is not included in the hashcode.
# Possible values are: scheme, host, port, path, query, fragment, userinfo, and user.
# If a finding has more than one endpoint, only one endpoint pair must match to mark the finding as duplicate.
DEDUPE_ALGO_ENDPOINT_FIELDS = ["host", "path"]
```

## Endpoints: como ajustar

Os endpoints podem afetar a deduplicação por meio de dois mecanismos:

1) Inclua `endpoints` em `HASHCODE_FIELDS_PER_SCANNER` para um parser. Assim, os endpoints passam a fazer parte do hash e devem corresponder exatamente de acordo com as regras de hashing do parser.
2) Se os endpoints não estiverem nos campos de hash, use `DEDUPLE_ALGO_ENDPOINT_FIELDS` para especificar os atributos a comparar. Exemplos:
   - `[]`: os endpoints são ignorados para a deduplicação.
   - `["host"]`: os achados são deduplicados se qualquer par de endpoint corresponder por host.
   - `["host", "port"]`: os achados são deduplicados se qualquer par de endpoint corresponder por host E port.

Observações:

- Para o algoritmo Legacy, achados estáticos e dinâmicos têm regras diferentes de correspondência de endpoint (veja a página de algoritmos). A configuração `DEDUPLE_ALGO_ENDPOINT_FIELDS` se aplica ao fluxo baseado em hash-code, não à lógica intrínseca do algoritmo Legacy.
- Para a correspondência `unique_id_from_tool` (baseada em ID), os endpoints são ignorados na decisão de deduplicação.

## Campo service: deduplicação e reimportação

- Com o padrão `HASH_CODE_FIELDS_ALWAYS = ["service"]`, o campo `service` é anexado ao hash. Dois achados que seriam iguais, mas com valores de `service` diferentes, não serão deduplicados nos fluxos baseados em hash.
- Durante a importação pela interface/API, o campo `Service` pode substituir o serviço fornecido pelo parser. Alterá-lo muda o hash e pode alterar o comportamento de deduplicação e a correspondência de reimportação.
- Se você quiser uma deduplicação independente do serviço, remova `service` de `HASH_CODE_FIELDS_ALWAYS` ou deixe o campo `Service` vazio durante a importação.

## Após alterar as configurações de deduplicação

Depois de alterar os algoritmos ou o cálculo de Hash, você precisará **recalcular os hashes** para o parser/tipo de teste afetado antes que o novo comportamento de correspondência se aplique de forma consistente aos dados existentes.

Observação: Recalcular os hashes pode gerar longos tempos de espera em instâncias grandes. Planeje janelas de manutenção adequadamente.

- Alterações na configuração de deduplicação (por exemplo, `HASHCODE_FIELDS_PER_SCANNER`, `HASH_CODE_FIELDS_ALWAYS`, `DEDUPLICATION_ALGORITHM_PER_PARSER`) não são aplicadas retroativamente de forma automática. Para reavaliar os achados existentes, você deve executar o comando de gerenciamento abaixo.

### Executando a deduplicação em um backlog de dados pré-existentes

Quando você configura as configurações de deduplicação pela primeira vez (ou as altera depois), os Achados importados antes da alteração mantêm seus hashes antigos até que você execute a deduplicação novamente de forma explícita. Use o comando de gerenciamento `dedupe` para recalcular o hash e/ou reavaliar os Achados existentes.

Execute dentro do container uwsgi. Exemplo (apenas hash codes, sem deduplicação):

```bash
docker compose exec uwsgi /bin/bash -c "python manage.py dedupe --hash_code_only"
```

Para **recalcular hashes e executar a deduplicação** de todos os parsers (o fluxo típico de “acabei de ativar a deduplicação e quero limpar o backlog”):

```bash
docker compose exec uwsgi /bin/bash -c "python manage.py dedupe"
```

Para focar apenas em um parser específico:

```bash
docker compose exec uwsgi /bin/bash -c "python manage.py dedupe --parser 'Trivy Scan'"
```

Ajuda/uso:
```
options:
  --parser PARSER       List of parsers for which hash_code needs recomputing
                        (defaults to all parsers)
  --hash_code_only      Only compute hash codes
  --dedupe_only         Only run deduplication
  --dedupe_sync         Run dedupe in the foreground, default false
```

Se você enviar a deduplicação para o Celery (sem `--dedupe_sync`), aguarde o tempo necessário para que as tarefas sejam concluídas antes de avaliar os resultados. Em instâncias grandes, isso pode levar um tempo considerável — monitore os logs dos workers do Celery para acompanhar o progresso.

## Onde configurar

- Prefira variáveis de ambiente em implantações. Para desenvolvimento local ou substituições avançadas, use `local_settings.py`.
- Consulte `configuration.md` para detalhes sobre como definir variáveis de ambiente e configurar substituições locais.

### Solução de problemas

Para ajudar na solução de problemas de deduplicação, use as seguintes ferramentas:

- Observe a saída de log na categoria `dojo.specific-loggers.deduplication`. Este é um logger independente de classe que emite detalhes sobre o processo e as configurações de deduplicação ao processar os achados.
- Observe os valores de `unique_id_from_tool` e `hash_code` passando o mouse sobre o campo `ID` ou a coluna `Status`:

![Unique ID from Tool e Hash Code na página View Finding](images/hash_code_id_field.png)

![Unique ID from Tool e Hash Code na Coluna Status da Lista de Achados](images/hash_code_status_column.png)
