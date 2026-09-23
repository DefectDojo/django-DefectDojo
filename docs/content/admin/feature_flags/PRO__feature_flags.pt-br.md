---
title: Feature Flags
description: Ative e desative recursos opcionais do DefectDojo Pro pela interface
  do DefectDojo
weight: 1
audience: pro
---

Os Feature Flags permitem ativar e desativar recursos opcionais do DefectDojo Pro na sua própria
instância — recursos que antes só podiam ser habilitados entrando em contato com o Suporte da DefectDojo agora
podem ser autoatendidos pela interface.

A página Feature Flags é visível apenas para **superusuários**. Outros usuários, incluindo Global Owners, não
a veem.

## Abrindo a página Feature Flags

Acesse **Settings > Feature Flags** na barra lateral esquerda.

A página lista todos os recursos opcionais com:

* **Name** — o recurso, com uma tag **BETA** quando ainda está em beta
* **Description** — o que o recurso faz
* **Documentation link** — onde existe documentação para aquele recurso
* **Toggle** — se o recurso está ativado no momento

Use a caixa de pesquisa para filtrar a lista pelo nome ou pela descrição do recurso.

### Recursos que não aparecem na lista

A página lista os recursos que você pode optar por adotar. Dois tipos de recurso estão ausentes dela.

**Sempre ativos.** Quando um recurso atinge disponibilidade geral, ele fica ativo em todas as instâncias e
deixa de ser listado, pois não há mais decisão a tomar:

* **Downstream Connectors** — consulte [Downstream Connectors](/connectors/downstream/about/)
* **Universal Parser** — consulte [Universal Parser](/import_data/pro/specialized_import/universal_parser/)
* **Asset Hierarchy** — consulte [Asset Hierarchy](/asset_modelling/pro_hierarchy/asset_hierarchy/)
* **Appearance** e **Feature Flags** — as duas páginas de Settings com o mesmo nome

Nada muda na sua instância se você já tinha um desses recursos ativado. Se você tinha algum desativado, ele
agora está ativo: esses recursos fazem parte do DefectDojo Pro em vez de serem opcionais. Entre em contato
com o [Suporte da DefectDojo](mailto:support@defectdojo.com) se isso for um problema para a sua instância.

**Habilitados pela DefectDojo mediante solicitação.** Alguns recursos dependem de infraestrutura provisionada
por instância, portanto são ativados pela DefectDojo em vez de por esta página:

* **Scheduling Service** — consulte [Scheduling Rules](/automation/rules_engine/scheduling/)

Entre em contato com o [Suporte da DefectDojo](mailto:support@defectdojo.com) para ativar um desses recursos.
Se já estiver ativo na sua instância, ele permanece ativo.

## Ativando ou desativando um recurso

1. Encontre o recurso na lista.
2. Clique no toggle dele.
3. A alteração entra em vigor imediatamente. Outros usuários recebem a alteração no próximo carregamento da
   página.

Alguns recursos exibem uma caixa de diálogo de confirmação antes que a alteração seja aplicada. Isso acontece
ao ativar um recurso que traz um aviso (por exemplo, um que exige reinicialização ou pode afetar dados
existentes), ou um que não pode ser desativado novamente.

Desativar um recurso normalmente é apenas o inverso de ativá-lo. As exceções são indicadas em
[Quando um toggle está bloqueado](#when-a-toggle-is-locked).

### Organization / Asset Relabeling

**Organization / Asset Relabeling** renomeia "Product Type" para "Organization" e "Product" para "Asset". Ele
vem ativado por padrão e é alternado nesta página como qualquer outro recurso, mas vale a pena saber quais
partes do DefectDojo ele governa:

* A **Pro UI** segue este toggle. Os novos rótulos aparecem no próximo carregamento da página.
* As páginas da **Classic UI**, suas URLs e os relatórios gerados obtêm sua nomenclatura da configuração de
  deployment `DD_ENABLE_V3_ORGANIZATION_ASSET_RELABEL` (também ativada por padrão), que é lida quando o
  DefectDojo é iniciado. Este toggle não as altera, e reiniciar também não faz com que ele as altere.

O toggle armazenado foi inicializado a partir dessa configuração de deployment, portanto os dois permanecem
alinhados até que você altere um deles. Se você desativar o relabeling aqui e também usar a Classic UI,
defina `DD_ENABLE_V3_ORGANIZATION_ASSET_RELABEL=False` no seu deployment e reinicie para que as duas
superfícies fiquem alinhadas. No [DefectDojo Pro (Cloud)](/get_started/pro/cloud/), entre em contato com o
[Suporte da DefectDojo](mailto:support@defectdojo.com) para que a configuração de deployment seja alterada.

Por esse motivo, o recurso traz uma tag **Restart Recommended** na página Feature Flags: a nomenclatura usada
fora da Pro UI é fixada quando o processo é iniciado. De qualquer forma, o relabeling é apenas cosmético. Os
modelos de banco de dados, nomes de campos e endpoints da API permanecem inalterados, portanto a automação
existente continua funcionando. Consulte [Asset Hierarchy](/asset_modelling/pro_hierarchy/asset_hierarchy/).

## Quando um toggle está bloqueado

Um recurso que você não pode alterar é exibido com um selo de bloqueio explicando o motivo:

| Badge | O que significa | O que fazer |
| --- | --- | --- |
| **Managed by DefectDojo** | A DefectDojo definiu este recurso de forma centralizada para a sua instância. Sua configuração não pode substituí-lo. | Entre em contato com o [Suporte da DefectDojo](mailto:support@defectdojo.com) se precisar alterá-lo. |
| **Unavailable on This Deployment** | O recurso não é oferecido no seu tipo de instalação. Veja [Disponibilidade de recursos](#feature-availability) abaixo. | Nada a fazer. O recurso não se aplica à sua instância. |
| **Cannot Be Disabled** | O recurso já está ativo e é de mão única. Não há mecanismo para revertê-lo. | Nada a fazer. Isso é esperado. |
| **Managed by deployment** | O recurso é controlado pela sua configuração de deployment, e não por esta página. | Veja [DefectDojo Pro (On-Premise)](#defectdojo-pro-on-premise) abaixo. |

## DefectDojo Pro (Cloud)

No [DefectDojo Pro (Cloud)](/get_started/pro/cloud/), **Settings > Feature Flags** é o único lugar que você
precisa. Ative um recurso e ele já estará em produção.

Duas coisas são tratadas pela DefectDojo, e não por você:

* **Managed by DefectDojo** — o recurso é fixado de forma centralizada. Entre em contato com o
  [Suporte da DefectDojo](mailto:support@defectdojo.com) para alterá-lo.
* **Managed by deployment** — o recurso faz parte de como sua instância é provisionada. Entre em contato com
  o Suporte também para esses casos, já que as instâncias Cloud não expõem a configuração de deployment aos
  clientes.

As instâncias Cloud também têm acesso a recursos que não são oferecidos on-premise. Veja
[Disponibilidade de recursos](#feature-availability).

## DefectDojo Pro (On-Premise)

No [DefectDojo Pro (On-Premise)](/get_started/pro/onprem/), a maioria dos recursos funciona exatamente como
no Cloud: abra **Settings > Feature Flags** e ative-os ou desative-os.

Um pequeno número de recursos, em vez disso, é lido a partir da sua configuração de deployment. Eles alteram
a forma como a aplicação é iniciada, portanto não podem ser alternados em tempo de execução. Esses recursos
aparecem na página como somente leitura, rotulados como **Managed by deployment**, e indicam a variável de
ambiente que os controla, por exemplo `DD_V3_FEATURE_LOCATIONS` para
[Locations](/asset_modelling/locations/pro__locations_overview/).

Como esses recursos exigem uma reinicialização, e alguns deles não podem ser revertidos depois de ativados,
consulte a documentação específica do recurso antes de alterá-lo. Vários são melhor ativados com a ajuda do
[Suporte da DefectDojo](mailto:support@defectdojo.com).

Para alterar um desses recursos:

1. Defina a variável de ambiente no seu deployment do DefectDojo. A página indica qual variável definir.
2. Reinicie o DefectDojo para que o novo valor seja lido na inicialização.
3. Recarregue a página Feature Flags para confirmar o novo estado.

Como esses valores são lidos na inicialização, não é possível alterá-los pela interface, e alterná-los no
seu ambiente sem uma reinicialização não tem efeito.

Recursos oferecidos apenas no Cloud aparecem como **Unavailable on This Deployment** em uma instância
on-premise. Isso é esperado e não é um problema de licenciamento.

## Disponibilidade de recursos

A maioria dos recursos está disponível nos dois tipos de instalação. As exceções são:

| Feature | Availability | How it is controlled |
| --- | --- | --- |
| Request a New Connector | Somente [DefectDojo Pro (Cloud)](/get_started/pro/cloud/) | Página Feature Flags. Exibido como **Unavailable on This Deployment** on-premise. |
| Locations | Ambos | Página Feature Flags. Observe que Locations não pode ser desativado novamente depois de ativado. Veja [Locations Overview](/asset_modelling/locations/pro__locations_overview/). |
| Organization / Asset Relabeling | Ambos | Página Feature Flags para a Pro UI; a Classic UI, suas URLs e os relatórios gerados seguem a configuração de deployment `DD_ENABLE_V3_ORGANIZATION_ASSET_RELABEL`. Veja [acima](#organization--asset-relabeling). |

Todos os demais recursos opcionais são alternados diretamente na página Feature Flags, tanto em instâncias
Cloud quanto On-Premise.

## Lendo feature flags fora da interface

Não é necessário abrir a página Feature Flags para saber quais recursos estão ativados — o estado das flags
também pode ser lido de forma programática, o que é útil quando uma automação precisa verificar se um
recurso está disponível antes de depender dele.

```
GET /api/v2/defectdojo_information/feature_flags/
```

Isso retorna um array JSON com um objeto por feature flag. Além de `key`, `title` e `description` da flag,
cada objeto informa os valores que a automação geralmente precisa: `effective` (se o recurso está de fato
ativo nesta instância), `default`, `application_value` (a configuração própria da instância, ou `null` se
não definida), `editable`, e `locked_reason` quando uma flag não pode ser alterada. Flags removidas do
produto são omitidas.

Qualquer usuário **autenticado** pode lê-lo — não é necessária função de superusuário. Para o schema exato
de resposta na sua versão, consulte a documentação interativa da API da sua instância em
`/api/v2/oa3/swagger-ui/`, gerada a partir do build em execução. Veja também a
[documentação da API v2](/automation/api/api-v2-docs/).

A mesma listagem somente leitura também é publicada na superfície `/api/mcp/` da instância, em
`/api/mcp/defectdojo_information/feature_flags/`.

Este endpoint é **somente leitura**. Ativar ou desativar um recurso ainda é feito na página Feature Flags
ou — para os recursos configurados por deployment mencionados acima — nas configurações do seu deployment.

## Perguntas frequentes

**Um recurso que eu quero não está na lista.**
A lista mostra apenas recursos opcionais. Recursos que estão sempre ativos não aparecem. Se você esperava
encontrar um recurso que está faltando, confirme se a sua licença o inclui e, em seguida, entre em contato
com o [Suporte da DefectDojo](mailto:support@defectdojo.com).

**Ativei um recurso, mas não o vejo.**
Recarregue a página — entradas de menu e rotas são avaliadas quando a página carrega, portanto um recurso
recém-ativado aparece no próximo carregamento, e não instantaneamente na visualização atual.

**Uma atualização vai alterar minhas configurações?**
Não. A atualização preserva os recursos que você ativou e os que você desativou.
