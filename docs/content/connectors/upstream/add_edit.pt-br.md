---
title: Adicionar ou Editar Conectores Upstream
description: Conecte-se a uma ferramenta de segurança suportada
aliases:
- /pt-br/import_data/pro/connectors/add_edit_connectors/
- /pt-br/en/connecting_your_tools/connectors/add_edit_connectors
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Nota: Conectores Upstream são um recurso exclusivo do DefectDojo Pro.</span>

O processo de adicionar e configurar um Conector Upstream é semelhante, independentemente da ferramenta que você está tentando conectar. No entanto, algumas ferramentas podem exigir a criação de chaves de API ou etapas adicionais.

Antes de começar esse processo, recomendamos consultar nossa [Referência Específica por Ferramenta](../toolreference/) para encontrar os recursos de API da ferramenta que você está tentando conectar.

1. Se ainda não tiver feito isso, comece **alternando para a Pro UI** no DefectDojo.
2. No menu do lado esquerdo, abra o grupo **Connectors** aninhado sob o cabeçalho **Import**, e clique em **Upstream Connectors**.
​
![image](images/add_edit_connectors.png)

3. Escolha um novo Conector que deseja adicionar ao DefectDojo em **Available Connectors**, e clique no botão **Add Configuration** no bloco da ferramenta. Você pode usar a caixa **Search Connectors** para filtrar cada seção pelo nome da ferramenta, ou o seletor **All / Asset / Finding** no cabeçalho da página para filtrar por tipo de conector.
​
Você também pode editar um Conector existente em **Configured Connectors**. Clique em **Manage Configuration \> Edit Configuration** para o Conector Configurado que deseja editar.
​
![image](images/add_edit_connectors_2.png)

4. Você precisará de uma **Location URL** acessível para a ferramenta, junto com uma chave **Secret** de API. A localização da chave de API vai depender da ferramenta que você está configurando. Veja nossa [Referência Específica por Ferramenta](../toolreference/) para mais detalhes.
​
5. Defina um **Label** para essa conexão, para ajudar a identificá-la no DefectDojo.
​
6. Agende a descoberta e a sincronização automáticas do Conector usando as agendas de **Discovery Configuration** e **Synchronization Configuration**. Elas podem ser alteradas posteriormente.
​
7. Selecione se deseja **habilitar o Auto-Mapping (Enable Auto-Mapping)**. Habilitar o Auto-Mapping criará um novo Produto no DefectDojo para armazenar os dados desse conector. O Auto-Mapping pode ser ativado ou desativado a qualquer momento.
​
8. Clique em **Submit.**

![image](images/add_edit_connectors_3.png)

## Próximos Passos

* Agora que você adicionou um conector, pode confirmar que tudo está configurado corretamente executando uma operação de [Discover](../manage_operations/#discover-operations).
