---
title: Anexando Arquivos
description: Faça upload de capturas de tela, relatórios ou outros arquivos de apoio
  a um Achado, Engajamento ou Teste no DefectDojo Pro
audience: pro
weight: 3
---

Você pode anexar arquivos a um **Achado**, um **Engajamento** ou um **Teste** para fornecer
contexto de apoio — por exemplo, uma captura de tela de prova de conceito, um relatório bruto de scanner, um
diagrama de rede ou uma planilha que embase um resultado.

Cada objeto mantém seu próprio conjunto de arquivos, e você pode anexar **até 10 arquivos** a um único
objeto.

## Tipos de Arquivo Suportados

Por padrão, as seguintes extensões são aceitas:

```
.txt  .pdf  .json  .xml  .csv  .yml  .png  .jpeg
.sarif  .xlsx  .doc  .html  .js  .nessus  .zip  .fpr
```

Administradores podem alterar essa lista por meio da variável de ambiente `DD_FILE_UPLOAD_TYPES`.
O upload de um arquivo cuja extensão não esteja na lista será rejeitado.

## Como Anexar um Arquivo a um Achado

1. Abra o Achado ao qual deseja anexar um arquivo.
2. Clique no **menu de engrenagem (⚙)** no canto superior direito do Achado e escolha **Add File**.
3. Digite um **Title** para o arquivo e selecione o arquivo no seu computador, depois salve.

   ![A ação Add File no menu de engrenagem do Achado, com a aba Files abaixo](images/PRO_attach_files_menu.png)

O mesmo menu de engrenagem está disponível nas páginas de **Engagement** e **Test**, de modo que arquivos podem
ser anexados a qualquer um desses objetos da mesma maneira.

## Visualizando e Baixando Arquivos

Os arquivos anexados são listados na aba **Files** da **Finding Overview** (e na
seção equivalente em Engajamentos e Testes). Clique no título de um arquivo para baixá-lo.

![A aba Files em um Achado, listando um arquivo anexado](images/PRO_finding_files_tab.png)

O acesso é verificado por permissão: um usuário precisa ter permissão de **view** no Achado, Engajamento
ou Teste pai para baixar seus arquivos.

## Excluindo Arquivos

Para remover um arquivo, abra o menu da linha do arquivo (o ícone **⋮**) na aba **Files** e escolha
**Delete File**. O mesmo menu também oferece **Edit File Name** para renomear um anexo.
