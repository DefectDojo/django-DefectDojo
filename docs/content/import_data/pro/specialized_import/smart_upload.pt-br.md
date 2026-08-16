---
title: Varreduras de infraestrutura / Smart Upload
description: Direcione automaticamente os Achados recebidos para o Produto correto
weight: 3
audience: pro
aliases:
- /pt-br/en/connecting_your_tools/import_scan_files/smart_upload
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Nota: o Smart Upload está disponível apenas no DefectDojo Pro.</span>

O Smart Upload é um importador especializado que ingere relatórios de **ferramentas de varredura de infraestrutura**, incluindo:

* Nexpose
* NMap
* OpenVas
* Qualys
* Tenable

O Smart Upload é único porque pode dividir os Achados de um arquivo de varredura em Produtos separados. Isso é relevante em um contexto de varredura de infraestrutura, no qual os Achados podem se aplicar a diversas equipes diferentes, ter SLAs implícitos distintos ou precisar ser incluídos em relatórios separados devido ao local onde foram descobertos em sua infraestrutura.

O Smart Upload lida com isso classificando os achados recebidos com base nos Endpoints descobertos na varredura. No início, esses Achados precisarão ser atribuídos manualmente, ou direcionados para o Produto correto a partir de uma lista de Achados Não Atribuídos. No entanto, uma vez que um Achado tenha sido atribuído a um Produto, todos os Achados subsequentes que compartilharem um Endpoint ou Host serão enviados para o mesmo Produto.

## Opções de menu do Smart Upload

O menu do Smart Upload fica em uma seção recolhível da barra lateral.

* **Add Findings permite importar um novo arquivo de varredura, de forma semelhante ao método Import Scan do DefectDojo**
* **Unassigned Findings lista todos os Achados do Smart Upload que ainda não foram atribuídos a um Produto.**

![image](images/smart_upload.png)

### O formulário do Smart Upload

O formulário Smart Upload Import Scan é essencialmente igual ao formulário Import Scan. Consulte nossas notas sobre o **Import Scan Form** para mais detalhes.

![image](images/smart_upload_2.png)

## Unassigned Findings

Depois que um Smart Upload é concluído, todos os Achados que não são atribuídos automaticamente a um Produto (com base em seu Endpoint) são colocados na lista **Unassigned Findings**. O primeiro Smart Upload de uma determinada ferramenta ainda não possui nenhum método para atribuir Achados, portanto cada Achado desse arquivo será enviado a esta página para classificação.

Os Achados não atribuídos (Unassigned Findings) não são incluídos na Hierarquia de Produtos e não aparecerão em relatórios, filtros ou métricas até que sejam atribuídos.

### Trabalhando com Unassigned Findings

![image](images/smart_upload_3.png)

Você pode selecionar um ou mais Unassigned Findings para classificação usando a caixa de seleção, e executar uma das seguintes ações:

* **Assign to New Product, que criará um novo Produto**
* **Assign to Existing Product, que moverá o Achado para um Produto existente**
* **Disregard Selected Findings**, que removerá o Achado da lista

Sempre que um Achado é atribuído a um Produto Novo ou Existente, ele é colocado em um Engajamento dedicado chamado ‘Smart Upload’. Esse Engajamento conterá um Teste nomeado de acordo com o Scan Type (por exemplo, Tenable Scan). Achados subsequentes enviados via Smart Upload que correspondam a esses Endpoints serão colocados sob esse Engajamento \> Teste.

### Achados descartados

Se um Achado for descartado (Disregarded), ele será removido da lista Unassigned Findings. No entanto, o Achado não ficará registrado em memória, portanto envios de varredura subsequentes podem fazer com que o Achado apareça novamente na lista Unassigned Findings.
