---
title: Anexando Arquivos
description: Faça upload de capturas de tela, relatórios ou outros arquivos de apoio
  para um Achado, Engajamento ou Teste no DefectDojo OS
audience: opensource
weight: 3
aliases:
- /pt-br/triage_findings/findings_workflows/add_files/
---

Você pode anexar arquivos a um **Achado**, um **Engajamento** ou um **Teste** para
fornecer contexto de apoio — por exemplo, uma captura de tela de prova de
conceito, um relatório bruto de scanner, um diagrama de rede, ou uma planilha
que sustente um resultado.

Cada objeto mantém seu próprio conjunto de arquivos, e você pode anexar **até
10 arquivos** a um único objeto.

## Tipos de Arquivo Suportados

Por padrão, as seguintes extensões são aceitas:

```
.txt  .pdf  .json  .xml  .csv  .yml  .png  .jpeg
.sarif  .xlsx  .doc  .html  .js  .nessus  .zip  .fpr
```

Os administradores podem alterar essa lista com a variável de ambiente
`DD_FILE_UPLOAD_TYPES`. O upload de um arquivo cuja extensão não esteja na
lista é rejeitado pelo formulário.

Arquivos de imagem (como `.png` e `.jpeg`) são exibidos como uma miniatura de
pré-visualização, enquanto outros tipos de arquivo são exibidos com um ícone
genérico. Em ambos os casos, clicar no arquivo faz o download dele.

## Como Anexar um Arquivo a um Achado

1. Abra o Achado ao qual você deseja anexar um arquivo.
2. Abra o menu de ações (o botão **☰** no canto superior direito do Achado) e
   clique em **Manage Files**.

   ![Manage Files no menu de ações do Achado](images/OS_manage_files_menu.png)

3. Na página **Add files**, digite um **Title** para o arquivo e escolha o
   arquivo no seu computador. Você pode adicionar até três arquivos por vez;
   salve e volte para adicionar mais, se necessário.

   ![O formulário de upload do Manage Files](images/OS_manage_files_form.png)

4. Clique em **Save**.

O arquivo é então listado no painel **Files** do Achado. Arquivos de imagem
aparecem como uma miniatura:

![Painel Files em um Achado mostrando uma captura de tela anexada](images/OS_finding_files_panel.png)

## Anexando Arquivos a Engajamentos e Testes

Engajamentos e Testes usam o mesmo fluxo de trabalho **Manage Files**:

- Na página de detalhes de um **Engajamento** ou **Teste**, abra o painel
  **Files** e clique no botão de edição (lápis), depois adicione arquivos
  exatamente como faria para um Achado.

Assim como com Achados, os anexos de imagem são exibidos como miniatura e
outros tipos de arquivo mostram um ícone genérico.

## Visualizando e Baixando Arquivos

Os arquivos anexados aparecem no painel **Files** na página de detalhes do
objeto. Clique em qualquer arquivo para baixá-lo. O acesso é verificado por
permissão: um usuário precisa ter permissão de **view** no Achado,
Engajamento ou Teste pai para baixar seus arquivos.

## Excluindo Arquivos

Para remover um arquivo, abra **Manage Files** para o objeto, marque a caixa
de seleção **Delete** ao lado do arquivo que deseja remover e clique em
**Save**.
