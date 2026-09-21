---
title: Contribuir com Parsers
description: Como contribuir com parsers
draft: false
weight: 1
audience: opensource
aliases:
- /pt-br/en/open_source/contributing/how-to-write-a-parser
---

Todos os comandos assumem que você está na raiz do repositório clonado django-DefectDojo.

## Pré-requisitos

- Você fez um fork de https://github.com/DefectDojo/django-DefectDojo e clonou localmente.
- Faça checkout de `dev` e certifique-se de estar atualizado com as últimas mudanças.
- É recomendável criar um branch dedicado para o seu desenvolvimento, como `git checkout -b parser-name`.

A forma mais fácil é usar a implantação via docker compose, pois ela tem capacidade de hot-reload para o uWSGI.
Configure seu ambiente para usar o ambiente de dev:

`$ docker/setEnv.sh dev`

Consulte [DOCKER.md](https://github.com/DefectDojo/django-DefectDojo/blob/master/readme-docs/DOCKER.md) para mais detalhes.

### Imagens Docker

Você vai querer construir suas imagens docker localmente e, eventualmente, passar o `uid` do seu usuário local para poder gravar na imagem (útil para arquivos de migração de banco de dados). Supondo que o `uid` do seu usuário seja `1000`, então:

{{< highlight bash >}}
$ docker compose build --build-arg uid=1000
{{< /highlight >}}

## Quais arquivos você precisa modificar?

| File                                          | Purpose
|-------                                        |--------
|`dojo/tools/<parser_dir>/__init__.py`          | Arquivo vazio para inicialização da classe
|`dojo/tools/<parser_dir>/parser.py`            | O núcleo. É aqui que você escreve seu parser propriamente dito. O nome da classe deve ser o nome do módulo Python sem underscores, mais `Parser`. **Exemplo:** Quando o nome do módulo Python é `dependency_check`, o nome da classe deve ser `DependencyCheckParser`
|`unittests/scans/<parser_dir>/{many_vulns,no_vuln,one_vuln}.json` | Arquivos de exemplo contendo dados relevantes para os testes unitários. O conjunto mínimo.
|`unittests/tools/test_<parser_name>_parser.py` | Testes unitários do parser.
|`dojo/settings/settings.dist.py`               | Caso você queira usar um algoritmo moderno de deduplicação baseado em hashcode
|`docs/content/supported_tools/<file/api>/<parser_file>.md` | Documentação: que tipo de formato de arquivo é exigido e como obtê-lo


## Contrato da factory

Os parsers são carregados dinamicamente com um padrão factory. Para que o seu parser seja carregado e funcione corretamente, você precisa implementar o contrato.

1. seu parser **DEVE** estar em um submódulo do módulo `dojo.tools`
   - ex: módulo `dojo.tools.my_tool.parser`
2. seu parser **DEVE** ser uma classe nesse submódulo.
   - ex: `dojo.tools.my_tool.parser.MyToolParser`
3. O nome dessa classe **DEVE** ser o nome do módulo Python sem underscores e com o sufixo `Parser`.
   - ex: `dojo.tools.my_tool.parser.MyToolParser`
4. Essa classe **DEVE** ter um construtor vazio ou não ter construtor
5. Essa classe **DEVE** implementar 4 métodos:
   1. `def get_scan_types(self)` Esta função retorna uma lista de todos os *scan_type* suportados pelo seu parser. Esses identificadores são usados internamente. Seu parser pode suportar mais de um *scan_type*. Por exemplo, alguns parsers usam identificadores diferentes para alterar o comportamento do parser (agregação, filtro, etc...)
   2. `def get_label_for_scan_types(self, scan_type):` Esta função retorna uma string usada para exibir um texto na UI (rótulo curto)
   3. `def get_description_for_scan_types(self, scan_type):` Esta função retorna uma string usada para exibir um texto na UI (descrição longa)
   4. `def get_findings(self, file, test)` Esta função retorna uma lista de findings
6. Se o seu parser tiver mais de 1 scan_type (para o modo detalhado) você **DEVE** implementar o método `def set_mode(self, mode)`
7. A instância do parser é reutilizada em todas as importações realizadas para esse scan_type, portanto não armazene nenhum dado em nível de classe

Exemplo:

```Python

class MyToolParser(object):
    def get_scan_types(self):
        return ["My Tool Scan", "My Tool Scan detailed"]

    def get_label_for_scan_types(self, scan_type):
        if scan_type == "My Tool Scan":
            return "My Tool XML Scan aggregated by ..."
        else:
            return "My Tool XML Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Aggregates findings per cwe, title, description, file_path. SonarQube output file can be imported in HTML format. Generate with https://github.com/soprasteria/sonar-report version >= 1.1.0"

    def requires_file(self, scan_type):
        return False

    # mode:
    # None (default): aggregates vulnerabilites per sink filename (legacy behavior)
    # 'detailed' : No aggregation
    mode = None

    def set_mode(self, mode):
        self.mode = mode

    def get_findings(self, file, test):
        <...>

```

## Parsers de API

O DefectDojo possui um número limitado de parsers de API. Embora não vamos remover esses connectors, adicionar connectors de API tem se mostrado problemático e, por isso, no momento não podemos aceitar novos parsers/connectors de API vindos da comunidade, por motivos de suportabilidade. Para manter um connector de API de alta qualidade, é necessário ter uma licença da ferramenta. Obter essa licença exige parceria com o autor ou fornecedor. Estamos perto de anunciar um novo programa para ajudar a resolver isso e trazer connectors de API para o DefectDojo.

## Gerador de Template

Use o parser de [template](https://github.com/DefectDojo/cookiecutter-scanner-parser) para gerar rapidamente os arquivos necessários. Para começar, você precisará instalar o [cookiecutter](https://github.com/cookiecutter/cookiecutter).

{{< highlight bash >}}
$ pip install cookiecutter
{{< /highlight >}}

Depois, gere o parser do seu scanner a partir da raiz do django-DefectDojo:

{{< highlight bash >}}
$ cookiecutter https://github.com/DefectDojo/cookiecutter-scanner-parser
{{< /highlight >}}

Leia [mais](https://github.com/DefectDojo/cookiecutter-scanner-parser) sobre as variáveis de configuração do template.

## Pontos de atenção

Aqui está uma lista de considerações que tornarão o parser robusto tanto para casos comuns quanto para edge cases.

### Não faça o parsing de URLs manualmente

Usamos 2 módulos para tratar endpoints:
 - `hyperlink`
 - `dojo.models`, com uma classe específica para tratar o processamento de URLs na criação de endpoints, `Endpoint`.

Todos os parsers existentes usam o mesmo código para fazer o parsing de URL e criar endpoints.
Usar `Endpoint.from_uri()` é a melhor forma de criar endpoints.
Se você realmente precisar fazer o parsing de uma URL, use o módulo `hyperlink`.

Bom exemplo:

```python
    if "url" in item:
        endpoint = Endpoint.from_uri(item["url"])
        finding.unsaved_endpoints = [endpoint]
```

Exemplo muito ruim:

```python
    u = urlparse(item["url"])
    endpoint = Endpoint(host=u.host)
    finding.unsaved_endpoints = [endpoint]
```

### Use as bibliotecas corretas para fazer o parsing de informações
Vários formatos de arquivo são tratados por meio de bibliotecas. Para manter o DefectDojo enxuto e também não ampliar a superfície de ataque, mantenha o número de bibliotecas usadas ao mínimo e use outros parsers como exemplo.

#### defusedXML em vez de lxml
Como o XML é, por padrão, um formato inseguro, as informações extraídas de várias saídas em xml precisam ser processadas de forma segura. Em uma avaliação, determinamos que o defusedXML é a biblioteca que usaremos no futuro para fazer o parsing de arquivos xml nos parsers, pois essa biblioteca é considerada mais segura. Assim, só aceitaremos PRs que usem a biblioteca defusedxml.

### Nem todos os atributos são obrigatórios

Os parsers podem ter muitos campos, e boa parte deles pode ser opcional.
É melhor não definir um atributo quando você não tem o dado, em vez de preenchê-lo com valores como `NA`, `No data` etc...

Consulte a classe `dojo.models.Finding`

### Dados podem estar ausentes no relatório de origem

Sempre inclua verificações para evitar possíveis erros `KeyError` (por exemplo, quando um campo não existe), para os campos sobre os quais você não tem certeza absoluta de que sempre estarão presentes no arquivo enviado. Isso resulta em um erro 500, e não fica bom.

Bom exemplo:

```python
   if "mykey" in data:
       finding.cwe = data["mykey"]
```

```python
   finding.cwe = data.get("mykey", 123)
```

```python
   some_list = data.get("key_of_the_list") or []
```

O último exemplo protege contra os casos em que `key_of_the_list` está presente, mas é `null`.


### Parsing de vetores CVSS

Os dados podem ter vetores ou scores `CVSS`. O Defect Dojo usa o módulo `cvss` fornecido pela RedHat Security.
Também há um método auxiliar para validar o vetor e extrair dele o score base e a severidade.

```python
    from dojo.utils import parse_cvss_data

    cvss_vector = <get CVSS3 or CVSS4 vector from the report>
    cvss_data = parse_cvss_data(cvss_vector)
    if cvss_data:
        finding.severity = cvss_data["severity"]
        finding.cvssv3 = cvss_data["cvssv3"]
        finding.cvssv4 = cvss_data["cvssv4"]
        # we don't set any score fields as those will be overwritten by Defect Dojo
```
Nem todos os valores precisam ser usados, já que os relatórios de scan geralmente fornecem seu próprio valor para `severity`.
E às vezes também para `cvss_score`. O Defect Dojo não sobrescreverá nenhum `cvss3_score` ou `cvss4_score`.
Se nenhum score for definido, o Defect Dojo usará a biblioteca `cvss` para calcular o score.
A resposta também contém a versão principal detectada do vetor CVSS em `cvss_data["major_version"]`.


Se você precisar de um processamento mais manual, pode fazer o parsing do vetor `CVSS` diretamente.

Exemplo de uso:

```python
    import cvss.parser
    from cvss import CVSS2, CVSS3, CVSS4

    # TEMPORARY: Use Defect Dojo implementation of `parse_cvss_from_text` white waiting for https://github.com/RedHatProductSecurity/cvss/pull/75 to be released
    vectors = cvss.parser.parse_cvss_from_text("CVSS:3.0/S:C/C:H/I:H/A:N/AV:P/AC:H/PR:H/UI:R/E:H/RL:O/RC:R/CR:H/IR:X/AR:X/MAC:H/MPR:X/MUI:X/MC:L/MA:X")
        if len(vectors) > 0 and type(vectors[0]) is CVSS3:
            print(vectors[0].severities())  # this is the 3 severities

            cvssv3 = vectors[0].clean_vector()
            severity = vectors[0].severities()[0]
            vectors[0].compute_base_score()
            cvssv3_score = vectors[0].scores()[0]
            finding.severity = severity
            finding.cvssv3_score = cvssv3_score
```

Não faça algo como isto:

```
    def get_severity(self, cvss, cvss_version="2.0"):
        cvss = float(cvss)
        cvss_version = float(cvss_version[:1])
        # If CVSS Version 3 and above
        if cvss_version >= 3:
            if cvss > 0 and cvss < 4:
                return "Low"
            elif cvss >= 4 and cvss < 7:
                return "Medium"
            elif cvss >= 7 and cvss < 9:
                return "High"
            elif cvss >= 9:
                return "Critical"
            else:
                return "Informational"
        # If CVSS Version prior to 3
        else:
            if cvss > 0 and cvss < 4:
                return "Low"
            elif cvss >= 4 and cvss < 7:
                return "Medium"
            elif cvss >= 7 and cvss <= 10:
                return "High"
            else:
                return "Informational"
```

## Algoritmo de deduplicação

Por padrão, um novo parser usa o algoritmo de deduplicação 'legacy', documentado em [About Deduplication](/triage_findings/finding_deduplication/about_deduplication/)

Use um algoritmo de deduplicação pré-definido sempre que aplicável. Ao usar os campos `unique_id_from_tool` ou `vuln_id_from_tool` na configuração do hash code, é importante que eles sejam únicos para o finding e constantes ao longo do tempo entre scans subsequentes. Se não for o caso, os valores ainda podem ser úteis para definir no modelo de finding, mesmo sem usá-los para deduplicação.
Os valores devem vir diretamente do relatório e não devem ser algo calculado internamente pelo parser.

## Testes unitários

Cada parser deve ter testes unitários, pelo menos para testar 0 vuln, 1 vuln e muitas vulns. Você pode dar uma olhada em como outros parsers já fazem isso, para começar. Quanto mais testes de qualidade, melhor.

É importante adicionar verificações sobre os atributos dos findings.
Por exemplo:

```python
        with self.subTest(i=0):
            finding = findings[0]
            self.assertEqual("test title", finding.title)
            self.assertEqual(True, finding.active)
            self.assertEqual(True, finding.verified)
            self.assertEqual(False, finding.duplicate)
            self.assertIn(finding.severity, Finding.SEVERITIES)
            self.assertEqual("CVE-2020-36234", finding.vulnerability_ids[0])
            self.assertEqual(261, finding.cwe)
            self.assertEqual("CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N", finding.cvssv3)
            self.assertIn("security", finding.tags)
            self.assertIn("network", finding.tags)
            self.assertEqual("3287f2d0-554f-491b-8516-3c349ead8ee5", finding.unique_id_from_tool)
            self.assertEqual("TEST1", finding.vuln_id_from_tool)
```

### Use with para abrir arquivos de exemplo

Para garantir que os file handles sejam fechados corretamente, use o padrão with para abrir arquivos.
Em vez de:
```python
    testfile = open("path_to_file.json")
    ...
    testfile.close()
```

use:
```python
    with open("path_to_file.json") as testfile:
        ...
```

Isso garante que o arquivo seja fechado ao final do bloco with, mesmo que ocorra uma exceção em algum ponto do bloco.

### Banco de dados de teste

O Django usa um banco de dados de teste separado para executar os testes unitários, chamado `test_defectdojo`. Ele é criado e inicializado automaticamente com um conjunto básico de dados de teste.

### Execute seus testes

Este comando local executará o teste unitário do seu novo parser

{{< highlight bash >}}
$ docker compose exec uwsgi bash -c 'python manage.py test unittests.tools.<your_unittest_py_file>.<main_class_name> -v2'
{{< /highlight >}}

ou desta forma:

{{< highlight bash >}}
$ ./run-unittest.sh --test-case unittests.tools.<your_unittest_py_file>.<main_class_name>
{{< /highlight >}}

Exemplo para o parser aqua:

{{< highlight bash >}}
$ docker compose exec uwsgi bash -c 'python manage.py test unittests.tools.test_aqua_parser.TestAquaParser -v2'
{{< /highlight >}}

ou desta forma:

{{< highlight bash >}}
$ ./run-unittest.sh --test-case unittests.tools.test_aqua_parser.TestAquaParser
{{< /highlight >}}

Se você quiser executar todos os testes unitários dos parsers, basta rodar `$ docker-compose exec uwsgi bash -c 'python manage.py test -p "test_*_parser.py" -v2'`

### Validação de endpoint

Alguns tipos de parser criam uma lista de endpoints vulneráveis (armazenados em `finding.unsaved_endpoints`). O DefectDojo exige que os endpoints sejam armazenados em um formato específico (que segue as RFCs). Endpoints que não seguem esse formato podem ser armazenados, mas serão marcados como quebrados (bandeira vermelha 🚩na UI). Para garantir que seu parser armazene os endpoints no formato correto, execute a função `.clean()` para todos os endpoints nos testes unitários

```python
findings = parser.get_findings(testfile, Test())
for finding in findings:
    for endpoint in finding.unsaved_endpoints:
        endpoint.clean()
```

### Testes de Parsers de API

Não apenas o parser, mas também o importer devem ser testados.
O método `patch` de `unittest.mock` costuma ser bastante útil para simular respostas de API.
É altamente recomendado usá-lo.

## Outros arquivos que podem estar envolvidos

### Mudança no model

Caso você precise alterar o model, por exemplo para aumentar o tamanho de uma coluna do banco de dados a fim de acomodar uma string de dados mais longa a ser salva
* Altere o que for necessário em `dojo/models.py`
* Crie um novo arquivo de migração em dojo/db_migrations executando o comando abaixo e incluindo-o como parte do seu PR

    {{< highlight bash >}}
    $ docker compose exec uwsgi bash -c 'python manage.py makemigrations -v2'
    {{< /highlight >}}

### Aceitar um tipo diferente de arquivo para upload

Se você quiser que seu parser aceite um novo tipo de arquivo, dê uma olhada em `dojo/forms.py` por volta da linha 436 (no momento em que este texto foi escrito) ou localize os 2 locais (para import e re-import) onde aparece a string `attrs={"accept":`.

Formatos atualmente aceitos: .xml, .csv, .nessus, .json, .html, .js, .zip.

### A necessidade de mais do que apenas o parser.py

Claro, nada impede que você tenha mais arquivos além do arquivo `parser.py`. Afinal, é python :-)

## Exemplos de pull request

Se você quiser dar uma olhada em parsers anteriores que hoje fazem parte do DefectDojo, veja https://github.com/DefectDojo/django-DefectDojo/pulls?q=is%3Apr+sort%3Aupdated-desc+label%3A%22Import+Scans%22+is%3Aclosed

## Atualize a documentação da página de import

Adicione um novo arquivo .md em [`docs/content/en/connecting_your_tools/parsers`] com os detalhes do seu novo parser.  Inclua os seguintes títulos de conteúdo:

* Tipo(s) de Arquivo Aceitável(is) - inclua como gerar esse tipo de arquivo a partir da ferramenta relacionada, já que algumas ferramentas têm múltiplos métodos ou exigem comandos específicos.
* Um bloco de exemplo de teste unitário, se aplicável.
* Um link para a pasta de testes unitários relevante, para que os usuários consigam navegar rapidamente até lá a partir da Documentação.
* Um link para o próprio scanner - (por exemplo, link do GitHub ou do fornecedor)

Aqui está um exemplo de uma página de documentação de Parser completa: [https://github.com/DefectDojo/django-DefectDojo/blob/master/docs/content/supported_tools/file/acunetix.md](https://github.com/DefectDojo/django-DefectDojo/blob/master/docs/content/supported_tools/file/acunetix.md)
