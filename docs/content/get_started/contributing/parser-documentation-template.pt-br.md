---
title: Template de Documentação de Parser
toc_hide: true
weight: 2
audience: opensource
aliases:
- /pt-br/en/open_source/contributing/parser-documentation-template
---

Este template foi criado para documentar um parser novo ou existente. Sinta-se à vontade para melhorá-lo com qualquer informação adicional que possa ajudar seus colegas profissionais de segurança.

* Copie este arquivo .md e adicione-o em `/docs/content/supported_tools/file` no repositório do GitHub.
* Atualize o título para corresponder ao nome do seu parser novo ou existente.
* Preencha todas as seções listadas abaixo. Remova quaisquer instruções ou exemplos encontrados em cada seção.

### File Types
_Especifique todos os tipos de arquivo aceitos pelo seu parser (por exemplo, CSV, JSON, XML)._
_Inclua instruções sobre como criar ou exportar o formato de arquivo aceitável a partir da ferramenta de segurança relacionada._

### Total Fields in [File Format]
Total data fields:  _Número total de campos contidos no arquivo de exportação da ferramenta de segurança._
Total data fields parsed:  _Número total de campos parseados para o finding do DefectDojo._
Total data fields NOT parsed: _Número total de campos NÃO parseados para o finding do DefectDojo._

_Usando o formato abaixo, forneça uma breve descrição de cada campo e como ele é mapeado para o modelo de dados do DefectDojo._
_Inclua todos os campos encontrados no arquivo de exportação da ferramenta de segurança, na ordem em que aparecem, indicando quaisquer campos que não sejam parseados._

Fields in order of appearance:
1. **Field 1** - _Descrição de como esse campo é mapeado (por exemplo, mapeia para o título do finding, host do endpoint.)_
2. **Field 2** - _Descrição de como esse campo é mapeado / não mapeado._
3. **Field 3** - _Descrição de como esse campo é mapeado / não mapeado._
4. **Field 4** - _Descrição de como esse campo é mapeado / não mapeado._
_(continue para cada campo do arquivo.)_

### Field Mapping Details
_Para cada finding criado, inclua detalhes de como o parser processa dados específicos. Por exemplo:_
- Como os endpoints são criados (por exemplo, combinando os campos IP, Domain, Port e Protocol).
- Como as ocorrências são tratadas (por exemplo, `nb_occurences` padrão definido como 1, incrementado para duplicatas).
- Como a deduplicação é tratada (por exemplo, usando um hash de severity + title + description).
- Descreve a severidade padrão caso nenhum mapeamento seja correspondido.

### Sample Scan Data or Unit Tests
_Adicione um link para a pasta de testes unitários ou de dados de scan de exemplo no repositório do GitHub. Por exemplo:_
- [Sample Scan Data Folder](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/[parser-name])

### Link To Tool
_Forneça um link para o próprio scanner ou ferramenta (por exemplo, repositório do GitHub, site do fornecedor ou documentação). Por exemplo:_
- [Tool Name](https://www.example.com/)
