---
title: Referência de Ferramentas de Conectores Upstream
description: Nossa lista de ferramentas de Conector compatíveis e como configurá-las
  com o DefectDojo
aliases:
- /pt-br/import_data/pro/connectors/connectors_tool_reference/
- /pt-br/en/connecting_your_tools/connectors/connectors_tool_reference
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Nota: Upstream Connectors é um recurso exclusivo do DefectDojo Pro.</span>

Ao configurar um Conector para uma ferramenta compatível, você precisará fornecer ao DefectDojo informações específicas relacionadas à API da ferramenta. No nível básico, você precisará de:

* **Location** \- um campo que geralmente se refere à URL da sua ferramenta na sua rede,
* **Secret** \- geralmente uma chave de API.

Algumas ferramentas exigirão campos adicionais relacionados à API além de **Location** e **Secret**. Elas também podem exigir que você faça alterações do lado delas para acomodar um Conector de entrada vindo do DefectDojo.

![image](images/connectors_tool_reference.png)

Cada ferramenta tem uma configuração de API diferente, e este guia tem como objetivo ajudá-lo a configurar a API da ferramenta para que o DefectDojo possa se conectar.

Sempre que possível, recomendamos criar uma nova conta de "bot do DefectDojo" na sua Ferramenta de Segurança, que será usada exclusivamente pelo Conector. Isso ajudará você a diferenciar melhor as ações realizadas manualmente pela sua equipe das ações automatizadas realizadas pelo Conector.

# **Conectores de Ativos**

A maioria dos Conectores importa **achados** de uma ferramenta de segurança. Os **Conectores de Ativos** funcionam de forma diferente: eles importam seu **inventário de ativos**. Um Conector de Ativos enumera os ativos existentes em uma plataforma externa (por exemplo, os repositórios em um grupo do GitLab) e cria e mantém automaticamente os **Produtos** (Ativos) e **Tipos de Produto** (Organizações) correspondentes no DefectDojo. Nenhum achado é importado por um Conector de Ativos.

* **Discover** e **Sync** reconciliam a lista de ativos. Novos ativos aparecem como Registros `NEW`; uma vez mapeados (automaticamente, se o mapeamento automático estiver habilitado), o DefectDojo cria o Produto e o agrupa em um Tipo de Produto derivado da ferramenta — por exemplo, o namespace do GitLab ou o projeto do Azure DevOps.
* Se um ativo for posteriormente removido no sistema de origem (por exemplo, um repositório é excluído), seu Registro mapeado é sinalizado como `MISSING` na próxima Sync, para que sua equipe possa triá-lo. O DefectDojo nunca exclui silenciosamente um Produto.

Azure DevOps, Backstage, Bitbucket, GitHub, GitLab, Jira Service Management Assets e ServiceNow CMDB são Conectores de Ativos. O runZero é principalmente um Conector de Ativos, mas pode opcionalmente importar vulnerabilidades como achados. Todos os demais Conectores listados abaixo importam achados.

# **Conectores Compatíveis**

## **Acunetix 360**

O conector Acunetix 360 importa **achados de vulnerabilidade DAST** da plataforma em nuvem Acunetix 360 (a plataforma Invicti). O DefectDojo descobre os sites escaneados da sua conta e cria um Registro para cada **site**; os achados de um site vêm da sua última verificação concluída.

**Observação:** este conector é para o **Acunetix 360** (o produto em nuvem em `online.acunetix360.com`). Ele não é para o scanner Acunetix Standard/Premium local (on-premises), que possui uma API diferente.

#### Pré-requisitos

Uma conta Acunetix 360 e uma **credencial de API**: no Acunetix 360, abra o menu da sua conta \> **API Settings** e anote o **API User ID** e gere um **API Token**. O conector se autentica com esses dados como credenciais HTTP Basic, portanto, recomenda-se uma conta de serviço dedicada para distinguir a atividade automatizada das ações manuais da equipe.

#### Mapeamentos do Conector

1. Insira sua URL do Acunetix 360 no campo **Location**: `https://online.acunetix360.com`.
2. Insira o API User ID no campo **API User ID**.
3. Insira o API Token no campo **API Token**.
4. Opcionalmente, defina uma **Minimum Severity** para limitar quais achados são importados.

Cada site escaneado se torna um Registro. Os achados vêm da última verificação concluída do site; vulnerabilidades que o Acunetix 360 marcou como **Accepted Risk** ou **False Positive** ainda são importadas, mas sinalizadas como inativas (risco aceito ou falso positivo), para que o produto do DefectDojo reflita a triagem do fornecedor.

## **Akamai API Security**

O conector Akamai API Security usa uma chave de API para extrair achados de segurança da API da Akamai. O DefectDojo descobrirá seu ambiente Akamai e criará Registros separados para cada **Application** e **Host** configurados na sua conta.

#### Pré-requisitos

Você precisará de uma chave de API com acesso à API da Akamai. Recomendamos criar uma conta de serviço dedicada para o DefectDojo, a fim de diferenciar claramente a atividade automatizada das ações manuais da equipe.

#### Mapeamentos do Conector

1. Insira a URL base da API da Akamai no campo **Location**. Essa URL é específica para sua instância Akamai: por exemplo
2. Insira uma **API Key** válida no campo **Secret**.

O DefectDojo mapeará **Applications** e **Hosts** como Registros separados. Cada Application aparecerá como `{name} (application)` e cada Host como `{name} (host)` na sua lista de Registros.

## **Anchore**

O conector Anchore usa o token de API de um usuário para extrair dados do Anchore Enterprise. Os Produtos serão mapeados e descobertos com base em "Applications", que são compostas por múltiplas Images no Anchore - veja a [documentação do Anchore Enterprise](https://docs.anchore.com/current/docs/sbom_management/application_groups/application_management_anchorectl/) para mais informações.

#### Mapeamentos do Conector

1. A URL do Anchore no campo **Location**: esta é a URL onde você acessa o Anchore.
2. Insira uma API Key válida no campo Secret. Esta é a chave de API associada à sua conta de serviço do Burp.

Veja a [documentação oficial do Anchore](https://docs.anchore.com/current/docs/) para mais informações sobre como criar um token para o Anchore.

## **AWS Security Hub**

O conector AWS Security Hub usa uma chave de acesso da AWS para interagir com as APIs do Security Hub.

#### Pré-requisitos

Em vez de usar a chave de acesso da AWS de um membro da equipe, recomendamos criar um Usuário IAM na sua conta AWS especificamente para o DefectDojo, com as permissões desse usuário limitadas ao necessário para interagir com o Security Hub.

A política "**[AWSSecurityHubReadOnlyAccess](https://docs.aws.amazon.com/aws-managed-policy/latest/reference/AWSSecurityHubReadOnlyAccess.html)**" da AWS fornece o nível de acesso necessário para um conector. Se você quiser escrever uma política personalizada para um Conector, precisará incluir as seguintes permissões:

* [DescribeHub](https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_DescribeHub.html)
* [GetFindingAggregator](https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_GetFindingAggregator.html)
* [GetFindings](https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_GetFindings.html)
* [ListFindingAggregators](https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_ListFindingAggregators.html)

Uma definição de política funcional pode ser semelhante a esta:

```
{  
    "Version": "2012-10-17",  
    "Statement": [  
        {  
            "Sid": "AWSSecurityHubConnectorPerms",  
            "Effect": "Allow",  
            "Action": [  
                "securityhub:DescribeHub",  
                "securityhub:GetFindingAggregator",  
                "securityhub:GetFindings",  
                "securityhub:ListFindingAggregators"  
            ],  
            "Resource": "*"  
        }  
    ]  
}
```

**Observação:** podemos precisar usar ações de API adicionais no futuro para oferecer a melhor experiência possível, o que exigirá atualizações nesta política.

Depois de criar seu usuário IAM e atribuir a ele as permissões necessárias usando uma política/função apropriada, você precisará gerar uma chave de acesso, que poderá usar para criar um Conector.

#### Mapeamentos do Conector

1. Insira o [endpoint de API da AWS correspondente à sua região](https://docs.aws.amazon.com/general/latest/gr/sechub.html#sechub_region) no campo **Location**: por exemplo, para recuperar resultados da região `us-east-1`, você forneceria

`https://securityhub.us-east-1.amazonaws.com`
2. Insira uma **AWS Access Key** válida no campo **Access Key**.
3. Insira uma **Secret Key** correspondente no campo **Secret Key**.

O DefectDojo pode extrair Achados de mais de uma região usando o recurso de **agregação entre regiões** do Security Hub. Se a [agregação entre regiões](https://docs.aws.amazon.com/securityhub/latest/userguide/finding-aggregation.html) estiver habilitada, você deve fornecer o endpoint de API da sua "**Região de Agregação**". Regiões vinculadas adicionais terão Registros de Produto criados para elas no DefectDojo com base no ID da sua conta AWS e no nome da região.

## **Azure DevOps**

O conector Azure DevOps é um **Conector de Ativos**: ele enumera os repositórios git em todos os projetos da sua organização do Azure DevOps e cria um Ativo do DefectDojo para cada repositório, agrupado em Organizações pelo projeto do Azure DevOps. Nenhum achado é importado.

#### Pré-requisitos

Você precisará de um Personal Access Token (PAT) para a organização. Recomendamos criar o token a partir de uma conta de serviço dedicada. São necessários apenas escopos de leitura:

1. No Azure DevOps, abra **User settings \> Personal access tokens \> New Token**.
2. Clique em **Show all scopes** e selecione **Code: Read** e **Project and Team: Read**.

Apenas o Azure DevOps Services (dev.azure.com) é compatível; o Azure DevOps Server local (on-premise) não é compatível no momento.

#### Mapeamentos do Conector

1. Insira a URL da sua organização no campo **Location**: `https://dev.azure.com/{your-organization}`. URLs legadas no formato `https://{your-organization}.visualstudio.com` também são aceitas, e quaisquer segmentos de caminho extras (por exemplo, um link para um projeto específico) são ignorados.
2. Insira o PAT no campo **Secret**.

Cada repositório se torna um Registro com o nome do repositório, agrupado pelo seu **projeto** do Azure DevOps. Repositórios desabilitados são ignorados, portanto, desabilitar ou excluir um repositório sinaliza seu Registro como `MISSING` na próxima Sync.

## **Backstage**

O conector Backstage é um **conector de ativos**: em vez de importar Achados, ele extrai seu Catálogo de Software do [Backstage](https://backstage.io) para o DefectDojo e mantém sua hierarquia de Produtos e a propriedade das equipes sincronizadas com ele. Ele foi projetado para organizações que mantêm o inventário de serviços e a estrutura organizacional no Backstage e desejam que o DefectDojo espelhe essa estrutura em vez de mantê-la manualmente.

#### O que é mapeado

| Backstage | DefectDojo |
|---|---|
| **System** | Tipo de Produto (Componentes sem System são agrupados em um Tipo de Produto configurável "Backstage / Uncategorized") |
| **Component** | Produto — nomeado a partir do `title` da entidade (recorrendo ao `name` se ausente), com a descrição do catálogo |
| **Owning Group** (relação `ownedBy`) | Um Grupo do DefectDojo vinculado ao Produto (função padrão: Maintainer, configurável) |
| **Owner email** (e-mail do perfil do Group, ou e-mail de um User owner) | Um Membro do Produto, quando já existe um usuário do DefectDojo com esse e-mail (usuários nunca são criados) |
| `metadata.tags`, `spec.type`, `spec.lifecycle`, namespace, domain | Tags de Produto com o prefixo `backstage:` |
| `metadata.annotations` | Armazenado no Registro (limitado); anotações selecionadas podem ser promovidas a atributos de primeira classe ou tags via **Annotation Mappings** |

Os Registros são indexados pelo `metadata.uid` atribuído pelo servidor da entidade, portanto, renomeações no Backstage atualizam o Produto mapeado **no local** na próxima sincronização — sem duplicatas. O nome do Produto sempre acompanha o catálogo: para renomear um Produto gerenciado por este conector, renomeie o Component no Backstage (uma renomeação feita no lado do DefectDojo, ou um nome personalizado dado durante o mapeamento manual, é reconciliado de volta com o nome do catálogo na próxima sincronização, a menos que isso colida com outro Produto). Mudanças de propriedade movem a atribuição de grupo do Produto. Componentes que desaparecem do catálogo (ou são sinalizados com a anotação `backstage.io/orphan`) são marcados como **MISSING** — o DefectDojo nunca exclui um Produto por conta própria. A hierarquia de Domain e Group (equipes-mãe) é registrada apenas como tags/metadados; elas não criam níveis de hierarquia adicionais.

#### Pré-requisitos

O conector se autentica com um **token de acesso externo estático** junto ao backend do Backstage. Na configuração do seu aplicativo Backstage, defina um token e (recomendado) restrinja-o ao plugin de catálogo:

```yaml
backend:
  auth:
    externalAccess:
      - type: static
        options:
          token: ${DEFECTDOJO_BACKSTAGE_TOKEN}
          subject: defectdojo-connector
        accessRestrictions:
          - plugin: catalog
```

Gere um token aleatório forte (por exemplo, `openssl rand -hex 32`) e armazene-o no ambiente da sua implantação do Backstage. Veja a [documentação de autenticação serviço a serviço do Backstage](https://backstage.io/docs/auth/service-to-service-auth) para mais detalhes.

#### Mapeamentos do Conector

1. Insira a **URL raiz do backend do Backstage** no campo **Location**: por exemplo, `https://backstage.example.com` (o conector adiciona `/api/catalog`). Esta deve ser a URL do **backend**, não a interface web do frontend.
2. Insira o token de acesso externo estático no campo **Secret**.

Campos opcionais (deixe em branco para usar os padrões):

* **Namespaces** — namespaces de catálogo separados por vírgula a serem importados; em branco importa todos os namespaces.
* **Component Types** — valores de `spec.type` separados por vírgula (por exemplo, `service,website`); em branco importa todos os tipos.
* **Page Size** — tamanho da página de consulta ao catálogo (1-500, padrão 250).
* **TLS Verification** — defina como `false` apenas se o Backstage servir um certificado que o DefectDojo não consiga verificar (CA interna); não recomendado.
* **Uncategorized Product Type** — o Tipo de Produto usado para Components sem System (padrão `Backstage / Uncategorized`).
* **Owner Group Role** — a função concedida à equipe proprietária nos Produtos mapeados (padrão `Maintainer`).
* **Annotation Mappings** — um objeto JSON que mapeia chaves de anotação para nomes de atributos de Registro, ou para `"tag"` para importar uma anotação como uma tag de Produto, por exemplo `{"github.com/project-slug": "GITHUB_PROJECT", "example.com/tier": "tag"}`.

Com **Auto-Map** habilitado, um único Discover \+ Sync constrói toda a estrutura de Tipo de Produto / Produto / propriedade sem etapas manuais. Com o Auto-Map desabilitado, os Components descobertos aparecem como Registros aguardando sua decisão de mapeamento.

#### Limitações (v1)

* A **associação de Group do Backstage não é sincronizada**: o conector cria/vincula a equipe proprietária como um Grupo do DefectDojo, mas preencher os usuários desse grupo fica a cargo do seu provedor de identidade ou administradores.
* Apenas Components se tornam Produtos; APIs, Resources e Domains não são importados como ativos (domains aparecem como tags).
* Tags e anotações são normalizadas e limitadas para caber nos limites de campo do DefectDojo (valores muito grandes são truncados).

**Uma observação sobre o sentido inverso:** exibir os achados e notas do DefectDojo *dentro* do Backstage (nas páginas de entidade) é um desdobramento natural que seria construído como um plugin de frontend do Backstage consumindo a API REST do DefectDojo — isso está deliberadamente fora do escopo deste conector, que apenas extrai dados de catálogo para o DefectDojo.

## **Black Duck**

O conector Black Duck importa achados de **análise de composição de software (SCA)** de uma instância do Black Duck (Synopsys / Black Duck) Hub. O DefectDojo descobre todos os projetos na instância e cria um Registro para cada **projeto**; os achados de um projeto vêm dos componentes de BOM vulneráveis da sua versão selecionada.

#### Pré-requisitos

Um **token de API** do Black Duck para um usuário que possa ver os projetos que você deseja importar. No Black Duck, abra o menu do usuário \> **My Access Tokens** \> **Create New Token**, conceda a ele (pelo menos) acesso de leitura e copie o token quando ele for exibido — ele é mostrado apenas uma vez. O conector troca esse token por um bearer de curta duração a cada sincronização; ele nunca é armazenado em texto simples além do campo secreto do conector.

#### Mapeamentos do Conector

1. Insira a URL do seu hub Black Duck no campo **Location** — por exemplo, `https://your-company.app.blackduck.com`.
2. Insira o token de API no campo **Secret**.
3. Opcionalmente, defina uma **Minimum Severity** para limitar quais achados são importados.

Cada projeto do Black Duck se torna um Registro. Por padrão, o conector importa a versão **released** do projeto (recorrendo à sua primeira versão, se ausente); cada componente de BOM vulnerável dessa versão se torna um achado, intitulado `{vulnerability} in {component}:{version}`.

Este conector é distinto dos parsers baseados em arquivo do Black Duck — seus achados usam o tipo de verificação dedicado **Black Duck - Connectors Import**.

## **Bitbucket**

O conector Bitbucket é um **Conector de Ativos**: ele enumera os repositórios nos workspaces do Bitbucket Cloud que você especificar e cria um Ativo do DefectDojo para cada repositório, agrupado em Organizações pelo projeto do Bitbucket. Nenhum achado é importado.

#### Pré-requisitos

O Bitbucket Cloud exige um token de API da Atlassian com **escopo** — tokens de API clássicos (sem escopo) da Atlassian são rejeitados pelo Bitbucket com um erro "API Token provided has no Bitbucket scopes".

1. Acesse [id.atlassian.com/manage-profile/security/api-tokens](https://id.atlassian.com/manage-profile/security/api-tokens) e escolha **Create API token with scopes**.
2. Selecione o app **Bitbucket** e conceda os escopos de leitura: `read:account:bitbucket`, `read:workspace:bitbucket`, `read:repository:bitbucket` e `read:project:bitbucket`.

Apenas o Bitbucket Cloud (bitbucket.org) é compatível. O Bitbucket Server atingiu o fim de vida em 2024, e o Bitbucket Data Center não é compatível.

#### Mapeamentos do Conector

1. Insira `https://bitbucket.org` no campo **Location**.
2. Insira o e-mail da conta Atlassian à qual o token pertence no campo **Email**.
3. Insira o token de API com escopo no campo **Secret**.
4. Insira um ou mais slugs de workspace (separados por vírgula) no campo **Workspace Slugs**. Este campo é obrigatório: os tokens de API com escopo do Bitbucket não conseguem listar workspaces automaticamente, então o DefectDojo precisa ser informado sobre quais workspaces ler.

Cada repositório se torna um Registro com o nome do repositório, agrupado pelo seu **projeto** do Bitbucket.

## **Bugcrowd**

O conector Bugcrowd usa a API REST do Bugcrowd para importar submissões dos seus programas de bug bounty e divulgação de vulnerabilidades. O DefectDojo descobre os programas aos quais o seu token de API tem acesso e cria um Registro para cada um, importando as submissões desse programa como achados.

#### Pré-requisitos

Você precisará de um **token de API** do Bugcrowd com acesso aos programas que deseja importar. Recomendamos criar uma conta de serviço dedicada para o DefectDojo, para que a atividade automatizada seja facilmente diferenciada das ações manuais da equipe. Gere o token no Bugcrowd em **Organization settings \> API credentials**; acesso de leitura a submissions, programs e targets é suficiente.

#### Mapeamentos do Conector

1. Insira `https://api.bugcrowd.com` no campo **Location**.
2. Insira seu token de API do Bugcrowd no campo **Secret**. Ele é enviado como um cabeçalho `Authorization: Token`.
3. Opcionalmente, defina uma **Minimum Severity** para limitar quais achados são importados.

Cada **programa** do Bugcrowd se torna um Registro, e suas submissões são importadas como achados com a severidade do Bugcrowd preservada. Submissões duplicadas são excluídas, portanto, uma reimportação não cria achados repetidos para o mesmo problema.

## **Bright Security**

O conector Bright Security usa a API do [Bright](https://brightsec.com) (anteriormente NeuraLegion) para importar **achados de DAST**. O DefectDojo descobre todas as verificações às quais o token tem acesso e cria um Registro para cada verificação concluída, importando então os issues dessa verificação como achados.

#### Pré-requisitos

Você precisará de uma **chave de API** do Bright, criada no aplicativo Bright em **User settings → API keys** (uma chave `Org` ou pessoal). A chave é enviada no cabeçalho `Authorization: Api-Key` e nunca é registrada em log.

#### Mapeamentos do Conector

1. Deixe o campo **Location** em branco para usar `https://app.brightsec.com`, ou insira seu host Bright explicitamente.
2. Insira a chave de API do Bright no campo **Secret**.
3. Opcionalmente, defina uma **Minimum Severity** para limitar quais achados são importados.

O DefectDojo mapeia cada **verificação** concluída para um Registro e cada **issue** para um achado: a severidade vem da classificação própria do Bright (Critical/High/Medium/Low), a pontuação CVSS, o CWE e a remediação são transferidos, o ponto de entrada afetado se torna o endpoint, e a evidência de requisição/resposta é incluída na descrição. Os achados são registrados como achados dinâmicos e deduplicados pelo id do issue do Bright.

Veja a [documentação da API do Bright](https://docs.brightsec.com/) para mais informações.

## **BurpSuite**

O conector Burp do DefectDojo chama a API GraphQL do Burp para buscar dados.

#### Pré-requisitos

Antes de configurar este conector, você precisará de uma chave de API de uma Conta de Serviço do Burp. Contas de usuário do Burp não têm chaves de API por padrão, então talvez seja necessário criar um novo usuário especificamente para essa finalidade.

Veja a [documentação do Burp](https://portswigger.net/burp/documentation/enterprise/user-guide/api-documentation/create-api-user) para um guia sobre como configurar um usuário de Conta de Serviço com uma chave de API.

#### Mapeamentos do Conector

1. Insira a URL raiz do Burp no campo **Location**: esta é a URL onde você acessa a ferramenta Burp.
2. Insira uma API Key válida no campo Secret. Esta é a chave de API associada à sua conta de serviço do Burp.

Veja a [documentação oficial do Burp](https://portswigger.net/burp/extensibility/enterprise/graphql-api/index.html) para mais informações sobre a API do Burp.

## **Censys**

O conector Censys lê ativos de host da Censys Platform e importa os serviços expostos de cada host como achados. Ele usa a API de busca global da Censys Platform para enumerar os hosts aos quais você o restringir.

#### Pré-requisitos

Você precisará de uma conta **Censys Platform** com acesso à API:

* Um **Personal Access Token**, criado no Console da Censys Platform em Personal Access Tokens.
* Seu **Organization ID**, exibido na mesma página de configurações em "Current Organization". O acesso à API do endpoint de busca requer uma organização, então é necessário um plano Starter ou superior. Tokens do plano gratuito não têm ID de organização e não podem usar a API de busca.

Dados de CVE e risco por host estão disponíveis apenas nos planos Censys Core (enterprise), portanto, em planos inferiores, os achados representam serviços expostos em vez de vulnerabilidades.

Veja a [documentação da API da Censys Platform](https://docs.censys.com/reference/get-started) para mais informações.

#### Mapeamentos do Conector

1. Insira `https://api.platform.censys.io` no campo **Location**.
2. Insira seu Personal Access Token no campo **API Key**.
3. Insira seu **Organization ID**.
4. Insira uma **Search Query** que restrinja a importação aos seus próprios ativos, por exemplo `host.autonomous_system.asn: <your ASN>` ou `host.ip: 203.0.113.0/24`.
5. Opcionalmente, defina uma **Minimum Severity** para limitar quais achados são importados.

O DefectDojo cria um Registro para cada host e importa seus serviços expostos como achados.

## **Checkmarx ONE**

O conector Checkmarx ONE do DefectDojo chama a API da Checkmarx para buscar dados.

#### **Mapeamentos do Conector**

1. Insira seu **Tenant Name** no campo **Checkmarx Tenant**. Este nome deve estar visível na página de login do Checkmarx ONE, no canto superior direito:  
" Tenant: \<**your tenant name**\> "  
​
![image](images/connectors_tool_reference_2.png)

2. Insira uma chave de API válida. Talvez seja necessário gerar uma nova: veja a [documentação da API da Checkmarx](https://docs.checkmarx.com/en/34965-68618-generating-an-api-key.html#UUID-f3b6481c-47f4-6cd8-9f0d-990896e36cd6_UUID-39ccc262-c7cb-5884-52ed-e1692a635e08) para detalhes.
3. Insira a localização do seu tenant no campo **Location**. Esta URL é formatada da seguinte forma:  
​`https://<your-region>.ast.checkmarx.net/` . Sua Região pode ser encontrada no início da sua URL do Checkmarx ao usar o aplicativo Checkmarx. **<https://ast.checkmarx.net>** é o servidor primário dos EUA (que não possui prefixo de região).

#### **Tratamento de branch**

Por padrão, cada sincronização importa os achados da **verificação concluída mais recente de um projeto, independentemente do branch**. Se seu CI verifica muitos branches, o branch que por acaso verificou por último "vence" essa sincronização: achados que existem apenas em outros branches não são importados, e a reconciliação de fechamento de itens antigos da sincronização pode alternar achados entre abertos e fechados conforme diferentes branches se revezam como a verificação mais recente.

Dois campos opcionais controlam esse comportamento:

- **Branch**: fixa todos os projetos em um nome de branch — apenas verificações desse branch são importadas. Este é um único valor global para todo o conector, portanto, é adequado para frotas em que todos os projetos usam o mesmo branch de longa duração (por exemplo, `main`).
    - Um **curinga `*`** é compatível. Um valor de Branch contendo `*` seleciona em *todos* os branches correspondentes, em vez de apenas um — por exemplo, `release/*` importa cada branch de release, e `*` corresponde a todos os branches. Combinado com **Track Scanned Branches**, esta é a forma de rastrear uma família de branches sem rastreá-los todos.
    - Se um curinga não corresponder a **nenhum** branch dentro da janela de verificação, essa sincronização é **ignorada**, em vez de ser tratada como "o branch não tem achados" — assim, um padrão que temporariamente não corresponde a nada não pode fechar todos os achados do ativo.
- **Track Scanned Branches**: quando habilitado, cada sincronização localiza todos os branches com uma verificação concluída no histórico recente de verificações do projeto e importa **a verificação concluída mais recente de cada branch**, com uma reimportação por branch. Os achados de cada branch residem em seu próprio engagement no ativo mapeado, nomeado "\<engagement padrão\> \- \<branch\>", de forma que o fechamento de achados obsoletos seja escopado por branch: uma correção mesclada em um branch nunca pode fechar os achados de outro branch. O branch primário do projeto (conforme relatado pelo Checkmarx) é importado primeiro, então recorrências do mesmo achado em outros branches são deduplicadas em relação ao original do branch primário.

Observações sobre o **Track Scanned Branches**:

- **Verifique qual padrão se aplica a você.** O rastreamento de branch vem **habilitado por padrão em novas instalações**. Instalações anteriores à mudança mantêm seu comportamento anterior, então a opção fica desabilitada para elas até que alguém a habilite.
- Quando ambos os campos estão definidos, apenas o **Branch** fixado é rastreado — inclusive quando esse valor de Branch é um padrão curinga, caso em que todo branch correspondente ao padrão é rastreado.
- Um branch que para de ser verificado (mesclado ou excluído) para de receber atualizações: seu engagement permanece visível com seus últimos achados conhecidos, que você pode revisar e fechar em massa.
- Desabilitar a opção posteriormente é seguro: os engagements por branch simplesmente param de receber importações e o engagement padrão retoma na próxima sincronização.
- Os Conectores reconciliam o estado na programação de sincronização. O rastreamento de branch faz com que cada sincronização seja completa entre os branches; não torna os dados em tempo real entre sincronizações.

## **Cloudflare**

O conector Cloudflare importa **insights do Security Center** — problemas de postura de segurança que a Cloudflare identifica sobre sua conta e zonas, como um registro DMARC ausente, DNSSEC não habilitado ou um problema de certificado. O DefectDojo cria um Registro para cada zona (domínio) que tenha insights abertos, além de um Registro em nível de conta para insights que não estão vinculados a uma zona específica.

#### Pré-requisitos

Você precisará de um **token de API** da Cloudflare (não a Global API Key legada). Crie um em **My Profile > API Tokens > Create Token** no painel da Cloudflare. A opção mais rápida é o modelo **"Read all resources"**; para um token com privilégio mínimo, conceda **Zone > Zone > Read** (todas as zonas) além de acesso de leitura em nível de conta para o Security Center.

#### Mapeamentos do Conector

1. Insira `https://api.cloudflare.com/client/v4` no campo **Location**.
2. Insira o token de API no campo **Secret**.
3. Opcionalmente, defina uma **Minimum Severity** para limitar quais achados são importados.

O DefectDojo descobre automaticamente as contas e zonas às quais o token tem acesso — nenhum ID de conta é necessário. Apenas insights abertos (ativos, não descartados) são importados, então os insights que você resolve ou descarta na Cloudflare são automaticamente mitigados no DefectDojo na próxima sincronização.

## **Cobalt.io**

O conector do Cobalt.io usa a API do Cobalt.io (v2) para importar achados de pentest da sua organização no Cobalt.io. O DefectDojo descobre todas as organizações que seu token de API consegue acessar e cria um Registro separado para cada **ativo** (a unidade que o Cobalt testa via pentest).

#### Pré-requisitos

Você precisará de um **token de API pessoal** do Cobalt.io. Recomendamos criar uma conta de serviço dedicada para o DefectDojo, de modo a distinguir claramente a atividade automatizada das ações manuais da equipe. Gere um token em **Settings \> API Tokens** na interface do Cobalt.io. Os tokens de organização são descobertos automaticamente \- não é necessário fornecê-los.

#### Mapeamentos do Conector

1. Insira a URL base da API do Cobalt.io no campo **Location**: `https://api.cobalt.io` (ou o host da sua região, por exemplo, `https://api.us.cobalt.io`).
2. Insira seu **token de API pessoal** no campo **Secret**.
3. Opcionalmente, insira um **Organization Token** para fixar a sincronização a uma única organização. Se deixado em branco, o DefectDojo sincroniza todas as organizações que o token de API pessoal consegue acessar.

O DefectDojo mapeia cada **ativo** do Cobalt.io como um Registro separado. Os achados são importados para cada ativo mapeado, com o estado dele no Cobalt.io (por exemplo `valid_fix`, `wont_fix`, `invalid`) determinando o status do achado no DefectDojo.

## **Contrast**

O conector do Contrast usa a API REST do Contrast Assess para importar vulnerabilidades de aplicações. O DefectDojo descobre as aplicações da sua organização no Contrast e cria um Registro para cada uma.

#### Pré-requisitos

Você precisará de quatro valores do Contrast. Recomendamos criar uma conta de serviço dedicada para que a atividade automatizada seja facilmente distinguível das ações manuais da sua equipe. Na interface do Contrast, em **User Settings > Profile > Your Keys**, você encontra:

* Sua **API Key** de organização.
* Sua **Service Key** pessoal.
* O **username** ao qual as credenciais pertencem (o e-mail de login da conta).
* Seu **Organization ID** — o UUID da organização de onde importar, também exibido em **Organization Settings**.

#### Mapeamentos do Conector

1. Insira no campo **Location** a URL base que você usa para acessar o Contrast — no produto hospedado, isso normalmente é `https://app.contrastsecurity.com` (ou a URL do seu Team Server regional/self-hosted).
2. Insira o e-mail de login da conta no campo **Username**.
3. Insira a **API Key** da organização no campo **API Key**.
4. Insira a **Service Key** pessoal no campo **Service Key**.
5. Insira o **Organization ID** (UUID) no campo **Organization ID**.
6. Opcionalmente, defina uma **Minimum Severity** para limitar quais achados são importados.

Cada aplicação do Contrast se torna um Registro, e suas vulnerabilidades são importadas como achados.

## **Coverity**

O conector do Coverity importa achados de um servidor **Coverity Connect**. O DefectDojo cria um Registro para cada **projeto** do Coverity.

#### Mapeamentos do Conector

1. Insira a URL do seu servidor Coverity Connect no campo **Location**.
2. Insira o **username** do Coverity Connect no campo **Username**.
3. Insira a senha do usuário ou a chave de autenticação no campo **Secret**.
4. Opcionalmente, defina um **View Name** para selecionar qual view salva de issues o conector lê. Deixe em branco para usar o padrão, **Outstanding Issues**.
5. Opcionalmente, defina **Import All Issue Kinds** como `true` para ampliar a importação além do filtro padrão de issues de Security e Quality (`RESOURCE_LEAK`).

## **CrowdStrike Falcon**

O conector do CrowdStrike Falcon importa **Spotlight vulnerabilities** e **EDR detections** da plataforma Falcon, como dois tipos de achado separados (`CrowdStrike:Spotlight` e `CrowdStrike:Detections`). O DefectDojo cria um Registro para cada **host** do Falcon.

#### Pré-requisitos

Um **API client** do Falcon (Client ID e secret), criado no console do Falcon em **Support \> API Clients and Keys**. Conceda a ele os escopos para os dados que você deseja importar: **Hosts: Read** (obrigatório, para a descoberta de hosts), **Vulnerabilities (Spotlight): Read** (para achados do Spotlight) e **Alerts: Read** (para EDR detections). Os dois tipos de achado são independentes — se o client não tiver um escopo, esse tipo de achado é ignorado em vez de fazer a sincronização falhar; assim, um client sem **Alerts: Read** ainda importa as vulnerabilidades do Spotlight.

#### Mapeamentos do Conector

1. Insira a URL base da API da sua cloud do Falcon no campo **Location**, de acordo com a região do seu console — por exemplo `https://api.crowdstrike.com` (US\-1), `https://api.us-2.crowdstrike.com` (US\-2), `https://api.eu-1.crowdstrike.com` (EU\-1), ou `https://api.laggar.gcw.crowdstrike.com` (US\-GOV\-1).
2. Insira o Client ID do API client no campo **Client ID**.
3. Insira o secret do API client no campo **Client Secret**.
4. Opcionalmente, defina uma **Minimum Severity** para limitar quais achados são importados.

Cada host do Falcon se torna um Registro, nomeado a partir de seu hostname, sistema operacional e tipo. Somente as vulnerabilidades do Spotlight com status **open** e **reopened** são importadas, portanto reimportar fecha os achados remediados.

## **Deepfence ThreatMapper**

O conector do Deepfence ThreatMapper usa a API REST do console de gerenciamento do [ThreatMapper](https://github.com/deepfence/ThreatMapper) para importar resultados de **vulnerability scan**. O DefectDojo descobre todos os nós que o ThreatMapper escaneou — uma imagem de container, host ou container — e cria um Registro para cada um, depois importa a verificação concluída mais recente desse nó como achados.

#### Pré-requisitos

Você precisará de um **API token** do ThreatMapper, encontrado no console em **Settings → User Management** (a API key do seu usuário). O conector o troca por um token de acesso de curta duração a cada sincronização; o API token nunca é registrado em log.

#### Mapeamentos do Conector

1. Insira a URL do console do ThreatMapper no campo **Location** (por exemplo `https://threatmapper.example.com`).
2. No campo **Secret**, insira o API token do ThreatMapper.
3. Se o seu console usa um certificado autoassinado, defina **Skip TLS Verification** como `true`.
4. Opcionalmente, defina uma **Minimum Severity** para limitar quais achados são importados.

O DefectDojo mapeia cada **node** escaneado para um Registro e cada **CVE** presente na verificação de vulnerabilidades concluída mais recente para um achado. A severidade vem da própria classificação do ThreatMapper, e o pacote afetado, a pontuação CVSS, a versão de correção (como mitigação), links de referência e um bloco de detalhes são transportados. Os achados são registrados como achados dinâmicos e deduplicados por node, CVE, pacote e caminho do pacote.

Consulte a [documentação do ThreatMapper](https://community.deepfence.io/threatmapper/docs/v2.5/) para mais informações.

## Dependency\-Track

Este conector busca dados de uma instância on\-premise do Dependency\-Track, via API REST.

​**Mapeamentos do Conector**

1. Insira a URL do seu servidor local do Dependency\-Track no campo **Location**.
2. Insira uma API key válida no campo **Secret**.

Para gerar uma API key do Dependency\-Track:

1. **Access Management**: Navegue até Administration \> Access Management \> Teams na interface do Dependency\-Track.
2. **Teams Setup**: Você pode criar uma nova team ou selecionar uma existente. As teams permitem gerenciar o acesso à API com base na participação em grupos.
3. **Generate API Key**: Na página de detalhes da team selecionada, localize a seção "API Keys". Clique no botão \+ para gerar uma nova API key.
4. **Assign Permissions**: Na seção "Permissions" da página da team, clique no botão \+ para abrir o seletor de permissions. Escolha as permissions **VIEW\_PORTFOLIO** e **VIEW\_VULNERABILITY** para habilitar o acesso via API aos portfolios de projetos e aos detalhes de vulnerabilidades.
5. Clique em "**Select**" para confirmar e salvar essas permissions.

Para mais informações, consulte a **[documentação do Dependency\-Track](https://docs.dependencytrack.org/integrations/rest-api/)**.

## **Docker Scout**

O conector do Docker Scout usa a API do metrics exporter do Docker Scout para reportar a postura de vulnerabilidades das imagens da sua organização. O DefectDojo descobre cada stream do Docker Scout (seus ambientes de runtime) e importa um resumo das vulnerabilidades e da conformidade de política para cada um.

#### Pré-requisitos

Você precisará de um personal access token do Docker criado por um **owner** de uma organização Docker que esteja **enrolled in Docker Scout**. O metrics exporter é um recurso em nível de organização, portanto uma conta pessoal, ou uma organização que não esteja enrolled no Docker Scout, não retornará dados.

Crie o token nas configurações da sua conta Docker, em **Personal access tokens**, e anote o **organization namespace** do seu Docker, que também será necessário.

#### Mapeamentos do Conector

1. Insira `https://api.scout.docker.com` no campo **Location**.
2. Insira seu personal access token do Docker no campo **Secret**.
3. Insira o namespace da sua **Organization** do Docker.
4. Opcionalmente, defina uma **Minimum Severity** para limitar quais achados são importados. Achados abaixo da severidade selecionada não serão importados.

O DefectDojo cria um Registro separado para cada stream do Docker Scout e importa um achado por severidade para as vulnerabilidades que o Docker Scout contabiliza nesse stream, além de um achado para cada imagem que falha na sua política do Docker Scout. A API de metrics do Docker Scout reporta contagens agregadas em vez de CVEs individuais, portanto esses achados resumem a postura de um stream. Abra o stream no Docker Scout para obter detalhes por imagem e por CVE.

Consulte a [documentação do Docker Scout](https://docs.docker.com/scout/) para mais informações.

## **Endor Labs**

O conector do Endor Labs usa a API REST do Endor Labs para sincronizar um **namespace** inteiro do Endor Labs. O DefectDojo descobre cada **project** do Endor como um Registro e importa os achados desse project, carregando o veredito de **reachability** do Endor para que você possa priorizar as vulnerabilidades cujo código afetado é realmente alcançável.

#### Pré-requisitos

Você precisará de uma **API key** do Endor Labs (um identificador de chave mais seu secret) e do **namespace** que deseja sincronizar. Crie a key na plataforma do Endor Labs em **Settings \> Access \> API Keys**; a key precisa de acesso de leitura aos projects e achados desse namespace.

O conector se autentica trocando a API key e o secret por um bearer token de curta duração — o secret é usado apenas nessa troca e nunca é armazenado em texto claro.

#### Mapeamentos do Conector

1. Insira `https://api.endorlabs.com` no campo **Location**. Se o seu tenant estiver hospedado em outra região, use a URL base da API dessa região.
2. Insira o **Namespace** do Endor Labs a ser sincronizado (por exemplo `your-org` ou `your-org.team`).
3. Insira o identificador da **API Key**.
4. Insira o **API Secret** correspondente à key.
5. Opcionalmente, defina **Traverse Child Namespaces** como `true` para também importar achados dos namespaces filhos do namespace configurado.
6. Opcionalmente, defina uma **Minimum Severity** para limitar quais achados são importados. Achados abaixo da severidade selecionada não são importados.

O DefectDojo cria um Registro para cada project do Endor Labs no namespace e importa seus achados, mapeando os níveis de severidade do Endor para as severidades do DefectDojo, os identificadores CVE/GHSA e a pontuação CVSS de cada vulnerabilidade, e as tags de reachability do Endor. O veredito de reachability (por exemplo *Reachable — vulnerable function is called* ou *Unreachable*) é exibido como o Impact do achado e como uma tag.

Para mais informações, consulte a **[documentação da API REST do Endor Labs](https://docs.endorlabs.com/rest-api/)**.

## **Edgescan**

O conector do Edgescan usa a API REST do Edgescan para importar vulnerabilidades abertas em toda a sua conta Edgescan. O DefectDojo enumera todos os **ativos** do Edgescan e cria um Registro para cada um, depois importa as vulnerabilidades abertas desse ativo como achados — não há configuração por ativo.

#### Pré-requisitos

Você precisará de um API token do Edgescan. Crie um a partir da sua conta Edgescan em **Account settings \> API tokens**: informe um label, clique em **Create** e copie o token gerado (ele é exibido apenas uma vez). Recomendamos uma conta dedicada para o Conector, de modo que a atividade automatizada seja facilmente distinguível.

#### Mapeamentos do Conector

1. Insira a URL do seu Edgescan no campo **Location** — `https://live.edgescan.com` para a plataforma hospedada padrão, ou o host do seu tenant, se diferente.
2. Insira seu API token do Edgescan no campo **Secret**. Ele é enviado no header `X-API-TOKEN`.
3. Opcionalmente, defina uma **Minimum Severity** para limitar quais achados são importados.

Cada ativo do Edgescan se torna um Registro, e cada vulnerabilidade aberta nesse ativo é importada como um achado. A severidade é mapeada da escala numérica do Edgescan (1–5) para a escala Informativa–Crítica do DefectDojo, e referências de CVE, o CWE e um vetor CVSS v3 são incluídos quando o Edgescan os fornece.

## **Escape**

O conector do Escape usa a API do [Escape](https://escape.tech) para importar **achados de segurança de API (DAST)**. O DefectDojo enumera todas as organizações que o token consegue acessar e todas as aplicações dentro de cada uma, cria um Registro para cada aplicação que tem uma verificação, e importa as issues da verificação mais recente dessa aplicação como achados — não há configuração por aplicação.

#### Pré-requisitos

Você precisará de uma **API key** do Escape, criada no app do Escape em **Settings → API keys**. A key é enviada no header `Authorization: Key` e nunca é registrada em log.

#### Mapeamentos do Conector

1. Deixe o campo **Location** em branco para usar `https://public.escape.tech/v2`, ou insira explicitamente o host da API do Escape.
2. Insira a API key do Escape no campo **Secret**.
3. Opcionalmente, defina uma **Minimum Severity** para limitar quais achados são importados.

O DefectDojo mapeia cada **application** para um Registro e cada **issue** da verificação para um achado: a severidade vem da classificação do Escape (Crítica/Alto/Médio/Baixo), o CWE é transportado, a categoria OWASP e o método HTTP se tornam tags, a URL afetada se torna o endpoint, e a orientação de remediação é incluída. Os achados são registrados como achados dinâmicos e deduplicados pelo id da issue no Escape.

Consulte a [documentação da API do Escape](https://docs.escape.tech/) para mais informações.

## **Fairwinds Insights**

O conector do Fairwinds Insights usa a API REST do [Fairwinds Insights](https://insights.fairwinds.com) para importar **achados de segurança do Kubernetes** em toda a sua organização. O DefectDojo enumera todos os **clusters** ativos e cria um Registro para cada um, depois importa os **action items** de Security desse cluster (do Polaris, Trivy, Kube\-bench, OPA e dos demais relatórios do Insights) como achados — não há configuração por cluster.

#### Pré-requisitos

Você precisará de um nome de **organization** e de um **API token** do Fairwinds Insights. Crie o token no app do Insights em **Organization Settings \> Tokens**; um token `read_only` é suficiente. O token tem escopo de organização e é enviado como bearer token; ele nunca é registrado em log.

#### Mapeamentos do Conector

1. Deixe o campo **Location** em branco para usar `https://insights.fairwinds.com`, ou insira explicitamente o host do seu Insights.
2. Insira o nome da sua **Organization** no Insights (o slug exibido na URL do seu dashboard).
3. Insira o API token do Insights no campo **Secret**.
4. Opcionalmente, defina uma **Minimum Severity** para limitar quais achados são importados.

O DefectDojo mapeia cada **cluster** ativo para um Registro e cada **action item** de Security para um achado: a severidade vem da pontuação numérica do Fairwinds (mapeada para a escala Informativa–Crítica do DefectDojo), o relatório do Fairwinds que produziu o item (`polaris`, `trivy`, `kube-bench`, ...) se torna uma tag de ferramenta, o recurso Kubernetes afetado e a imagem de container são incluídos, e quaisquer identificadores de CVE são extraídos. Os achados são registrados como achados estáticos e deduplicados pelo id do action item no Fairwinds.

Consulte a [documentação da API do Fairwinds Insights](https://insights.docs.fairwinds.com/technical-details/api/) para mais informações.

## **Fortify**

O conector do Fortify importa resultados de SAST/DAST do Fortify (OpenText/Micro Focus), cobrindo as duas edições que compartilham a plataforma: **SSC** (Software Security Center, self-hosted) e **Fortify on Demand (FoD)** (SaaS). Ele sincroniza a conta inteira: o DefectDojo descobre todas as aplicações (project version do SSC / release do FoD) e cria um Registro para cada uma, depois importa as issues dessa aplicação como achados.

#### Pré-requisitos

- **SSC**: um **FortifyToken** — crie um na interface do SSC em **Administration → Token Management** (um CIToken/UnifiedLoginToken).
- **FoD**: uma **OAuth2 API key** — um Client ID e Client Secret em **Settings → API** (com o escopo `api-tenant`).

O token e o OAuth secret nunca são registrados em log.

#### Mapeamentos do Conector

1. Insira a URL base do Fortify no campo **Location**: para o SSC, o host do seu servidor (o conector acrescenta `/ssc/api/v1`); para o FoD, o host da API da sua região, por exemplo, `https://api.ams.fortify.com`.
2. Defina **Edition** como `SSC` ou `FoD`.
3. Para **FoD**, insira o **Client ID** do OAuth; deixe em branco para SSC.
4. Em **Token / Client Secret**, insira o FortifyToken do SSC ou o client secret OAuth do FoD.
5. Opcionalmente, defina uma **Minimum Severity** para limitar quais achados são importados.

O DefectDojo mapeia cada **application** do Fortify para um Registro e cada **issue** para um achado: a severidade vem da própria classificação de **friority** do Fortify (Crítica/Alto/Médio/Baixo), o título combina a categoria da issue com seu arquivo e linha, e o caminho do arquivo, a linha, o kingdom, o analyzer e o tipo de engine são transportados. Issues de engines de análise estática (SCA) são registradas como achados estáticos, e issues do WebInspect (DAST) como achados dinâmicos; issues suprimidas, removidas e ocultas são ignoradas, issues auditadas como "Not an Issue" são marcadas como Falso positivo, e issues "Exploitable"/revisadas são marcadas como Verificado.

Consulte a documentação da API do [Fortify SSC](https://www.microfocus.com/documentation/fortify-software-security-center/) e do [Fortify on Demand](https://api.ams.fortify.com/swagger/ui) para mais informações.

## **GitGuardian**

O conector do GitGuardian usa a API REST do GitGuardian para importar **incidentes de segredo** — credenciais expostas que o GitGuardian detectou em suas fontes monitoradas. O DefectDojo cria um Registro para cada fonte monitorada (repositório ou perímetro) que atualmente tem incidentes abertos, e importa cada incidente aberto como um achado.

Para sua segurança, o conector importa apenas os **metadados** do incidente — o detector, a severidade, a validade, o status e um link de volta para o GitGuardian. O valor do segredo exposto em si nunca é obtido ou armazenado pelo DefectDojo; siga o link em cada achado para revisar os locais afetados no GitGuardian.

#### Pré-requisitos

Você precisará de uma API key do GitGuardian. Recomendamos um **Service Account token** (em vez de um personal access token), de modo que a atividade automatizada seja facilmente distinguível. Crie-o em **API** no dashboard do GitGuardian e conceda estes escopos de leitura:

* `incidents:read`
* `sources:read`

#### Mapeamentos do Conector

1. Insira a URL da API do GitGuardian no campo **Location**: `https://api.gitguardian.com` para a plataforma SaaS, ou a URL da API da sua instância self-hosted.
2. Insira a API key no campo **Secret**.

Somente incidentes **open** (status `TRIGGERED` ou `ASSIGNED`) são importados; incidentes que você resolve ou ignora no GitGuardian são automaticamente mitigados no DefectDojo na próxima sincronização. Um segredo confirmado como ativo (validade *valid*) é importado como um achado Verificado.

## **GitHub**

O conector do GitHub é um **Conector de Ativos**: ele enumera os repositórios que seu token consegue acessar e cria um Ativo do DefectDojo para cada um, agrupados em Organizações pelo owner do GitHub (organização ou usuário). Nenhum achado é importado.

**Observação:** este conector importa apenas o **inventário** dos seus repositórios. Para importar alertas de segurança do GitHub — code scanning, Dependabot e secret scanning — como achados, use o conector separado **GitHub Advanced Security**, descrito abaixo. Os dois são independentes e podem ser executados juntos.

#### Pré-requisitos

O conector se autentica com um **personal access token** do GitHub e lê apenas os **metadados** do repositório (nome, descrição, URL e owner) — ele não acessa seu código, issues ou alertas de segurança. Ele importa todos os repositórios que a conta do token possui, dos quais colabora, ou dos quais é membro da organização; portanto, confirme que a conta do token consegue ver os repositórios que você deseja espelhar. Recomendamos uma conta de serviço dedicada.

O token precisa apenas de acesso somente leitura aos metadados do repositório:

- Um token *fine-grained* precisa de **Repository permissions → Metadata: Read-only**, concedido aos repositórios (ou a toda a organização) que você deseja importar.
- Um token *classic* precisa do escopo **`repo`** para incluir repositórios privados (use **`public_repo`** se precisar apenas dos públicos), além de **`read:org`** para que os repositórios pertencentes a organizações sejam resolvidos.

Somente o GitHub.com (incluindo o GitHub Enterprise Cloud) é compatível. O GitHub Enterprise **Server** não é compatível com este conector no momento.

#### Mapeamentos do Conector

1. Insira `https://api.github.com` no campo **Location**.
2. Insira o personal access token no campo **Secret**.

Não é necessário informar nenhuma lista de organizações ou repositórios — o DefectDojo importa todos os repositórios que o token consegue ver. Cada repositório se torna um Registro nomeado a partir do repositório, agrupado pelo **owner** do GitHub (organização ou usuário). Se um repositório for excluído posteriormente, ou o token perder o acesso a ele, o Registro mapeado é sinalizado como `MISSING` na próxima Sync, em vez de ser removido — o DefectDojo nunca exclui um Produto silenciosamente.

## **GitHub Advanced Security**

O conector do GitHub Advanced Security importa alertas de **code scanning**, **Dependabot** e **secret scanning** do GitHub, como três tipos de achado separados (`GitHub:CodeScanning`, `GitHub:Dependabot` e `GitHub:SecretScanning`). O DefectDojo descobre todos os repositórios não arquivados na organização configurada e cria um Registro para cada um.

#### Pré-requisitos

Os recursos do GitHub Advanced Security precisam estar habilitados para os repositórios que você deseja importar. O conector se autentica com um **personal access token** do GitHub:

1. No GitHub, abra **Settings \> Developer settings \> Personal access tokens** e crie um token pertencente a (ou com acesso a) a organização de destino.
2. Conceda a ele acesso de leitura aos alertas de segurança: um token *fine\-grained* precisa de acesso **Read\-only** a **Code scanning alerts**, **Dependabot alerts** e **Secret scanning alerts** nos repositórios da organização; um token *classic* precisa dos escopos **`repo`** e **`security_events`**.
3. Confirme que o owner do token consegue ver os repositórios que você pretende importar — o conector só enxerga os repositórios que o token consegue acessar.

#### Mapeamentos do Conector

1. Insira `https://api.github.com` no campo **Location**. Para GitHub Enterprise Server, use `https://<your-host>/api/v3`.
2. Insira o login da organização no campo **Organization**.
3. Insira o personal access token no campo **Secret**.
4. Opcionalmente, defina uma **Minimum Severity** para limitar quais achados são importados.

Cada repositório não arquivado se torna um Registro, consultado nas três famílias de alertas em busca de alertas abertos. Uma família de alertas que não está habilitada para um repositório é ignorada em vez de ser reportada como resolvida, de modo que recursos desabilitados não causam fechamentos falsos.

## **GitLab**

O conector do GitLab é um **Conector de Ativos**: ele enumera todos os projects (repositórios) que seu token consegue acessar e cria um Ativo do DefectDojo para cada um, agrupados em Organizações pelo namespace do GitLab (grupo ou usuário). Nenhum achado é importado.

#### Pré-requisitos

Você precisará de um Personal Access Token com o escopo **read_api**. Recomendamos criar o token a partir de uma conta de serviço dedicada; o conector lista os projects dos quais essa conta é membro.

#### Mapeamentos do Conector

1. Insira a URL do seu GitLab no campo **Location**: `https://gitlab.com`, ou a URL base da sua instância self-hosted.
2. Insira o Personal Access Token no campo **Secret**.

Cada project se torna um Registro nomeado a partir do project, agrupado pelo seu **namespace**. Projects que estão pendentes de exclusão no GitLab (excluídos por um usuário, mas ainda não removidos definitivamente pelo job em segundo plano do GitLab) são excluídos automaticamente; assim, excluir um project sinaliza seu Registro como `MISSING` na próxima Sync, em vez de deixar para trás um ativo fantasma renomeado.

## **Google Cloud Security Command Center**

O conector do Google Cloud SCC usa a API REST do Security Command Center v2 para importar achados de segurança ativos da sua organização, folder ou project do Google Cloud. O DefectDojo cria um Registro para cada **project** do Google Cloud que tenha achados abertos.

#### Pré-requisitos

O Security Command Center precisa estar **ativado** na sua organização (o tier Standard é gratuito). Em seguida, você precisará de uma service account que consiga listar os achados, e de uma JSON key para ela:

1. No Google Cloud, crie uma service account — recomenda-se uma dedicada para o DefectDojo.
2. Conceda a ela o papel **Security Center Findings Viewer** (`roles/securitycenter.findingsViewer`) no escopo que você deseja importar (organização, folder ou project).
3. Crie uma **JSON key** para a service account e faça o download.

#### Mapeamentos do Conector

1. Deixe o campo **Location** com o padrão `https://securitycenter.googleapis.com`, a menos que você use um endpoint não padrão.
2. No campo **Parent Resource**, insira o escopo de onde importar: `organizations/{id}`, `folders/{id}` ou `projects/{id}`.
3. Cole o conteúdo completo do arquivo **JSON key** da service account no campo **Service Account Key**.
4. Opcionalmente, defina uma **Minimum Severity** para limitar quais achados são importados.

Somente achados `ACTIVE` e não silenciados (un-muted) são importados; portanto, achados que você desativa ou silencia no SCC são automaticamente mitigados no DefectDojo na próxima sincronização. O project do GCP afetado por cada achado se torna seu Registro.

## **Group-IB ASM**

O conector do Group-IB ASM (Attack Surface Management) usa a API REST do Group-IB ASM para trazer **issues** (achados) de superfície de ataque externa para o DefectDojo. O DefectDojo descobre cada **empresa/tenant** do Group-IB como um Record separado e importa os issues dessa empresa de forma agendada e incremental. O ativo ao qual cada issue se relaciona (um domínio, IP ou URL) é anexado ao achado resultante como um **Endpoint**.

#### Pré-requisitos

Você precisará do seu login do Group-IB ASM e de uma chave de API. Recomendamos criar uma conta de serviço dedicada para o DefectDojo, para que a atividade automatizada possa ser diferenciada das ações manuais da equipe.

Para gerar uma chave de API:

1. Abra o Group-IB Attack Surface Management, clique em **Help** no canto inferior esquerdo e selecione **API**.
2. Clique em **Generate API Key** (canto superior direito, abaixo do seu nome de usuário).
3. Digite sua senha de SSO e clique em **Next**, depois clique em **Copy token**.
4. Armazene a chave em um gerenciador de segredos e planeje uma rotação regular.

#### Mapeamentos do Conector

O Group-IB ASM autentica com HTTP Basic Auth, em que o nome de usuário é seu login do ASM e a senha é sua chave de API. **Ambos os valores são obrigatórios** — a chave de API sozinha não é suficiente.

1. Digite `https://asm.group-ib.com` no campo **Location**. Isso é o mesmo para todos os tenants do Group-IB ASM.
2. Digite seu login do ASM (geralmente um endereço de e-mail) no campo **Username**.
3. Digite sua chave de API no campo **API Key** (Secret).
4. Opcionalmente, defina uma **Minimum Severity** para limitar quais achados são importados. Achados abaixo da severidade selecionada não são importados.

O DefectDojo mapeia cada **empresa** do Group-IB como um Record separado, usando o ID da empresa como identificador. Na primeira Sync, o DefectDojo preenche retroativamente o histórico recente de issues; as Syncs seguintes são incrementais, trazendo apenas os issues alterados desde a última Sync (rastreados pelo timestamp `lastSeen` mais recente de cada issue).

#### Restringindo a uma única empresa (opcional)

Por padrão, o conector descobre automaticamente as empresas disponíveis para suas credenciais de API (via o endpoint `clients` do ASM) e cria um Record por empresa. Essa é a configuração recomendada e não exige configuração adicional.

Se o endpoint `clients` não estiver disponível para o seu tenant — por exemplo, quando ele é restrito a contas parceiras/MSP — o conector pode ser restrito a uma única empresa fornecendo o **ID da empresa** como um campo específico da ferramenta `company_id` na configuração do conector. Quando `company_id` é definido, o DefectDojo usa essa empresa diretamente em vez de enumerar as empresas. Deixe-o em branco para usar a descoberta automática.

Consulte o manual da API REST do Group-IB ASM (disponível no produto em **Help → API**) para mais informações.

## **HackerOne**

O conector do HackerOne usa a API REST do HackerOne para importar relatórios do seu programa de bug bounty ou de divulgação de vulnerabilidades. O DefectDojo cria um Record para cada programa ao qual o token tem acesso e importa seus relatórios como achados.

#### Pré-requisitos

O conector usa a API **customer** do HackerOne, que exige um **token de API da organização** — um token pessoal das configurações de usuário funciona apenas com a API hacker e não autenticará aqui.

1. No HackerOne, vá em **Organization Settings > API Tokens**.
2. Crie um token e anote tanto o **identifier** quanto o valor do **token**. Acesso de leitura ao programa é suficiente.

#### Mapeamentos do Conector

1. Digite `https://api.hackerone.com` no campo **Location**.
2. Digite o **identifier** do token no campo **API Token Identifier**.
3. Digite o valor do token no campo **API Token**.
4. Opcionalmente, defina uma **Minimum Severity** para limitar quais achados são importados.

Cada programa se torna um Record, e seus relatórios são importados como achados com a classificação de severidade do HackerOne preservada.

## **Harbor**

O conector do Harbor usa a API REST v2.0 do Harbor para importar vulnerabilidades de imagens de contêiner em todo o seu registro. O DefectDojo enumera cada **projeto** do Harbor e cria um Record para cada um, depois percorre os repositórios e artefatos do projeto e importa as vulnerabilidades de cada artefato **escaneado** — carregando a imagem (repositório + tag/digest) como contexto do achado. Não há configuração por imagem.

#### Pré-requisitos

Você precisará de uma conta do Harbor (ou uma **robot account**) com acesso de pull/leitura aos projetos que deseja importar. Recomendamos uma robot account dedicada: no Harbor, abra um projeto (ou **Administration > Robot Accounts** para um robot de sistema), crie um robot com a permissão **pull** em repositórios e artefatos, e copie seu nome completo e o secret. Nomes de robot começam com `robot$` por padrão, mas o prefixo é configurável por instância do Harbor (algumas usam `robot_`) — copie o nome exatamente como o Harbor o exibe. Um usuário/senha comum também funciona.

#### Mapeamentos do Conector

1. Digite a URL do seu Harbor no campo **Location** — por exemplo, `https://harbor.example.com`. O DefectDojo acrescenta automaticamente o caminho de API `/api/v2.0`.
2. Digite o nome de usuário do Harbor, ou o nome de uma robot account exatamente como o Harbor o exibe (`robot$<name>` por padrão), no campo **Username**.
3. Digite a senha ou o secret da robot account no campo **Secret**. Ela é enviada usando autenticação HTTP Basic.
4. Opcionalmente, defina uma **Minimum Severity** para limitar quais achados são importados.

Cada projeto do Harbor se torna um Record. Para cada artefato que tenha um scan concluído, suas vulnerabilidades são importadas como achados; o pacote/versão afetado, uma severidade derivada de CVSS, o CVE, o CWE e uma correção (versão corrigida) são incluídos onde o Harbor os fornece. Apenas artefatos escaneados são importados — dispare um scan no Harbor para imagens que ainda não foram escaneadas.

## **Have I Been Pwned**

O conector do Have I Been Pwned (HIBP) usa a API REST do HIBP para relatar quais contas nos domínios da sua organização apareceram em vazamentos de dados conhecidos. O DefectDojo descobre cada domínio que você verificou com o HIBP e importa um achado por vazamento que afete esse domínio.

#### Pré-requisitos

Você precisará de uma chave de API do Have I Been Pwned com busca por domínio, o que exige um nível de assinatura **Core** ou superior. Você pode obter uma chave na sua [conta do Have I Been Pwned](https://haveibeenpwned.com/API/Key).

Você também deve **verificar pelo menos um domínio** na sua conta HIBP antes que qualquer dado de vazamento fique disponível. O HIBP permite verificar um domínio por registro DNS TXT, meta tag, upload de arquivo ou e-mail, em **Domain search** na sua conta. Até que um domínio seja verificado, o conector não descobre nenhum domínio e não importa nenhum achado.

#### Mapeamentos do Conector

1. Digite `https://haveibeenpwned.com` no campo **Location**.
2. Digite sua chave de API no campo **Secret**.
3. Opcionalmente, defina uma **Minimum Severity** para limitar quais achados são importados. Achados abaixo da severidade selecionada não serão importados.

O DefectDojo cria um Record separado para cada domínio que você verificou com o HIBP, e importa um achado por vazamento que afete contas nesse domínio. A severidade de cada achado reflete o tipo de dado que o vazamento expôs, e sua descrição lista as contas afetadas no seu domínio para que sua equipe possa agir sobre elas.

Consulte a [documentação da API do Have I Been Pwned](https://haveibeenpwned.com/API/v3) para mais informações.

## **HCL AppScan**

O conector do HCL AppScan usa a API REST v4 do AppScan para importar issues do **AppScan on Cloud (ASoC)** ou de um **AppScan 360°** auto-hospedado (ambos compartilham a mesma API). Ele sincroniza a conta inteira: o DefectDojo descobre cada aplicação e cria um Record para cada uma, depois importa os issues dessa aplicação (DAST, SAST e IAST) como achados.

#### Pré-requisitos

Você precisará de uma **chave de API** do AppScan — um Key ID e um Key Secret gerados nas configurações da sua conta AppScan (API Key). O conector os troca por um token de sessão de curta duração a cada execução; o Key ID, o Key Secret e o token nunca são registrados em log.

#### Mapeamentos do Conector

1. Digite a URL do console do AppScan no campo **Location**: para ASoC use `https://cloud.appscan.com` (ou `https://eu.cloud.appscan.com` para a região UE); para AppScan 360° use o host da sua instância.
2. Defina **Provider** como `ASOC` para AppScan on Cloud, ou `A360` para um AppScan 360° auto-hospedado.
3. Digite o **API Key ID** e o **API Key Secret**.
4. Opcionalmente, defina uma **Minimum Severity** para limitar quais achados são importados.

O DefectDojo mapeia cada **aplicação** do AppScan para um Record (VEP) e cada **issue** para um achado: o título é o tipo do issue com seu domínio / entidade / cause-id / URL / caminho anexados; a severidade mapeia Informational → Info (Low/Medium/High/Critical passam sem alteração); o CWE, uma descrição rotulada, a correção e o aviso (advisory), e o endpoint de host/porta são preservados. Issues de análise estática são registrados como achados estáticos e issues dinâmicos/interativos como achados dinâmicos; issues abertos ficam ativos e issues corrigidos/aprovados ficam mitigados.

Consulte a [documentação da API REST do AppScan](https://help.hcl-software.com/appscan/ASoC/appseccloud_rest_apis.html) para mais informações.

## **Intigriti**

O conector do Intigriti usa a API externa de empresas do Intigriti para trazer **submissions** de bug bounty / pentest para o DefectDojo. Ele sincroniza a conta da empresa inteira: o DefectDojo descobre cada programa ao qual o token tem acesso e cria um Record para cada um, depois importa as submissions desse programa como achados.

#### Pré-requisitos

Você precisará de um **token de API de empresa** do Intigriti. No portal da empresa no Intigriti, em **Company Settings > API** (o escopo `company_external_api`), gere um token de acesso com leitura aos seus programas e submissions. Recomenda-se um token dedicado para o DefectDojo. O token é enviado como um Bearer token e nunca é registrado em log.

#### Mapeamentos do Conector

1. Digite a URL base da API externa de empresas do Intigriti no campo **Location**: `https://api.intigriti.com/external/company`. A URL deve ser HTTPS.
2. Digite o token de API da empresa no campo **Secret**.
3. Opcionalmente, defina uma **Minimum Severity** para limitar quais achados são importados.

O DefectDojo mapeia cada **programa** do Intigriti para um Record e cada **submission** para um achado, indexado pelo código da submission. A severidade do achado segue a classificação do Intigriti (Exceptional/Critical → Critical, depois High/Medium/Low, caso contrário Informational), e o estado do ciclo de vida da submission mapeia para o status do achado: submissions abertas/em triagem ficam ativas, submissions aceitas ficam verificadas, e submissions fechadas se tornam mitigadas, duplicadas, fora do escopo, falso positivo ou risco aceito de acordo com o motivo do fechamento. A descrição do achado carrega o tipo de vulnerabilidade do relatório, o ativo afetado, a prova de conceito e as respostas do pesquisador.

Consulte a [documentação da API do Intigriti](https://kb.intigriti.com/en/articles/6117846-intigriti-api) para mais informações.

## **Intruder**

O conector do Intruder usa a [API REST do Intruder](https://developers.intruder.io/) para trazer a postura de toda a sua conta para o DefectDojo. Cada **target** do Intruder é descoberto como um Record (Produto); cada **occurrence** de um issue em um target se torna um Finding.

#### Mapeamentos do Conector

1. Deixe o campo **Location** como `https://api.intruder.io/` (o servidor de API padrão do Intruder).
2. Digite um **token de acesso de API** do Intruder no campo **Secret**.

Gere um token de acesso no Intruder em **My account > API Access Tokens** (você precisará da senha da sua conta para criá-lo, e o token é exibido apenas uma vez). Consulte a [documentação da API do Intruder](https://developers.intruder.io/docs/creating-an-access-token) para detalhes.

Os achados são derivados por occurrence: a severidade vem da severidade do issue, os CVEs e o CVSS vêm da occurrence, a localização vem do target/porta, e uma occurrence em snooze é importada como um achado inativo (falso positivo ou risco aceito).

## **IriusRisk**

O conector do IriusRisk usa um token de API para trazer dados de modelagem de ameaças da sua instância do IriusRisk.

#### Pré-requisitos

Você precisará de um token de API da sua conta do IriusRisk. Recomendamos criar uma conta de serviço dedicada para o DefectDojo, para distinguir claramente a atividade automatizada das ações manuais da equipe.

Para gerar um token de API no IriusRisk:

1. Faça login na sua instância do IriusRisk.
2. Navegue até seu **User Profile** no menu superior direito.
3. Selecione **API Token** e gere um novo token.

Consulte a [documentação da API do IriusRisk](https://support.iriusrisk.com/hc/en-us/categories/360001148511) para mais informações.

#### Mapeamentos do Conector

1. Digite a URL da sua instância do IriusRisk no campo **Location URL**. Para instâncias hospedadas na nuvem, isso normalmente é `https://{your-subdomain}.iriusrisk.com`. Para instalações on-premise, use a URL base da sua instância.
2. Digite seu **API Token** no campo **Secret**.
3. Opcionalmente, defina uma **Minimum Severity** para limitar quais achados são importados. Achados abaixo da severidade selecionada não serão importados.

## **JFrog Xray**

O conector do JFrog Xray usa a API REST do JFrog Xray para buscar dados de vulnerabilidade dos seus repositórios do Artifactory. O DefectDojo descobrirá todos os repositórios da sua instância JFrog e gerará relatórios de vulnerabilidade via Xray, importando achados de forma agendada.

#### Pré-requisitos

Você precisará de um token de API com acesso às APIs do Artifactory e do Xray. Recomendamos criar uma conta de serviço dedicada para o DefectDojo. A conta requer:

* Acesso de leitura aos repositórios do Artifactory
* Permissão para gerar e visualizar relatórios de vulnerabilidade do Xray (permissão `Apply on Watches` no Xray, ou equivalente)

#### Mapeamentos do Conector

1. Digite a URL base da sua instância JFrog no campo **Location**. Deve ser a URL raiz da sua instância JFrog, por exemplo `https://your-instance.jfrog.io`. Não inclua um caminho no final — o DefectDojo construirá automaticamente os caminhos de API apropriados.
2. Digite um **Reference Token** válido no campo **Secret**. Tokens podem ser gerados em **User Management > Access Tokens** na interface do JFrog Platform.
Você precisará gerar um **Reference Token** e usar esse valor.

Escopos de token obrigatórios para o JFrog Xray:

- **All Services**, já que o DefectDojo precisa de acesso tanto aos serviços do XRay quanto do Artifactory
- **Manage Reports + Manage Resources**, no mínimo.

Por padrão, o DefectDojo mapeia cada **repositório** do Artifactory como um Record separado. Cada Sync gera um relatório de vulnerabilidade completo por repositório via Xray, então os status dos achados no DefectDojo sempre refletem o estado atual do repositório.

#### Filtro de Repositório (opcional)

Por padrão, o conector descobre **todos** os repositórios da sua instância JFrog. Em instâncias com um grande número de repositórios — muitos dos quais podem não ser relevantes para revisão de segurança — a descoberta pode ser restringida com o campo opcional **Repository Filter**, em **Import Filters** no formulário do conector.

O filtro é aplicado durante a descoberta, **antes de qualquer trabalho por repositório ser feito**. Um repositório fora do filtro não custa nada: nenhum relatório do Xray é gerado para ele e, no modo de artefato, nenhum de seus artefatos de primeiro nível é enumerado. Isso faz dele a forma mais eficaz de reduzir tanto o tempo de Sync quanto a carga que o DefectDojo impõe à sua instância JFrog — mais do que qualquer configuração aplicada posteriormente na Sync. É especialmente recomendado junto com **Artifact-Level Records** em instâncias grandes.

**Sintaxe:** uma lista de chaves de repositório separadas por vírgula. Cada entrada pode usar curingas `*`:

* Uma entrada contendo `*` é comparada como um padrão — `releases-*` corresponde a todo repositório cuja chave comece com `releases-`, e `*docker-pr-local*` corresponde a qualquer chave que contenha `docker-pr-local`. Um `*` corresponde a qualquer sequência de caracteres, incluindo `/`.
* Uma entrada sem `*` deve corresponder **exatamente** a uma chave de repositório.
* Um repositório é descoberto se corresponder a **qualquer** entrada da lista. Espaços ao redor das vírgulas são ignorados.

```
releases-*, snapshots
```

O exemplo acima descobre todo repositório cuja chave comece com `releases-`, mais o único repositório chamado exatamente `snapshots`.

Observações:

* O filtro é uma **lista de permissão (allow-list)** — uma correspondência seleciona um repositório. Não há sintaxe de exclusão ou negação, então você não pode expressar "tudo exceto X" diretamente.
* A correspondência é **sensível a maiúsculas e minúsculas**, tanto para entradas exatas quanto para curingas. `*` é o único caractere curinga; `?` e intervalos de caracteres não são suportados.
* **Deixe em branco para descobrir todos os repositórios.** Um valor com apenas espaços ou vírgulas é tratado como em branco.
* Um filtro que não corresponde a nada simplesmente não descobre nada — não há erro. Se uma Sync inesperadamente não encontrar repositórios, verifique o log do conector em busca da entrada `repository filter scoped discovery`, que informa quantos dos repositórios totais corresponderam.
* O campo pode ser alterado depois que a conexão é criada.

**Alterando o filtro depois:** repositórios que um filtro recém-restringido agora exclui deixam de ser descobertos, e seus Records existentes seguem o ciclo de vida normal para produtos que a ferramenta não relata mais — Records **mapeados** são sinalizados como `MISSING` na próxima Sync, e Records `NEW` não mapeados são removidos. Achados já importados para o DefectDojo não são excluídos; o filtro governa apenas a descoberta.

#### Records em nível de artefato

A opção **Artifact-Level Records** muda a descoberta para um nível abaixo do repositório: cada entrada de primeiro nível sob a raiz de um repositório (para repositórios Docker, cada imagem; para repositórios genéricos, cada arquivo ou pasta de nível superior) se torna seu próprio Record. Cada Sync ainda gera um único relatório do Xray por repositório — o DefectDojo atribui cada vulnerabilidade aos artefatos que ela impacta, então a carga na sua instância JFrog não aumenta.

> **Verifique em qual modo você está antes da sua primeira Sync.** Artifact-Level Records vem **ativado por padrão para novas instalações**. Instalações anteriores ao recurso mantêm seu layout existente em nível de repositório, então a opção fica desativada para elas até que alguém a ative. Em ambos os casos, a opção pode ser alterada a qualquer momento — veja *Alternando uma conexão existente* abaixo.

Com o Artifact-Level Records ativado:

* Os repositórios permanecem como Records e se tornam **ativos pai (parent assets)**: eles não carregam achados próprios, mas quando o recurso Asset Hierarchy está ativado, o DefectDojo relaciona automaticamente cada ativo de artefato ao seu ativo de repositório com uma relação `parent`. Os ativos podem então ser filtrados por pai/filho, e os achados sobem na hierarquia.
* Uma vulnerabilidade que impacta vários artefatos é importada em cada ativo de artefato afetado, então cada ativo mostra o conjunto completo de achados que o afetam.
* Os achados são restritos ao **build mais recente** de cada artefato, então os achados de um artefato descrevem seu build atual em vez de acumular resultados de todos os builds que o Xray já escaneou.
* Relações de hierarquia criadas pelo conector nunca sobrescrevem relações que você criou manualmente. Se um ativo já tiver um pai atribuído por você, o conector o deixa como está.
* O token precisa adicionalmente de acesso de leitura à API de armazenamento do Artifactory (incluída nos escopos acima).

**Alternando uma conexão existente para Artifact-Level Records:** a opção pode ser alterada a qualquer momento. Na primeira Sync depois, novos Records de artefato aparecem para mapeamento — ative **Auto Map** na conexão ao alternar a opção para que os achados se movam sem lacuna. Os ativos em nível de repositório param de receber achados e seus achados previamente importados são fechados na próxima Sync (os mesmos achados são reimportados sob os novos ativos de artefato, com status atualizado); notas e histórico nos achados antigos em nível de repositório permanecem no ativo de repositório. Alternar de volta reverte isso: os Records de repositório voltam a carregar achados (achados previamente fechados reabrem à medida que voltam a corresponder), e os Records de artefato são marcados como MISSING — seus ativos e achados são mantidos, mas param de ser atualizados, para que você possa arquivá-los quando desejar.

Consulte a [documentação da API REST do JFrog Xray](https://jfrog.com/help/r/jfrog-rest-apis/xray-rest-apis) para mais informações.

## **Jira Service Management Assets**

O conector JSM Assets é um **Asset Connector**: ele enumera os objetos no seu workspace do Jira Service Management Assets (anteriormente Insight) e cria um Asset do DefectDojo para cada objeto, agrupados em Organizations pelo esquema do objeto. Nenhum achado é importado.

#### Pré-requisitos

* Assets exige um plano **Jira Service Management Premium ou Enterprise**. Em planos Free ou Standard, a API Assets responde com `403 "Access to Assets API was denied"`, mesmo que o restante do site funcione.
* A conta Atlassian usada deve ter **acesso ao produto Jira Service Management** (uma vaga de agente) no site — apenas o acesso ao site não é suficiente.
* Crie um token de API clássico do Atlassian em [id.atlassian.com/manage-profile/security/api-tokens](https://id.atlassian.com/manage-profile/security/api-tokens). Recomendamos uma conta de serviço dedicada.

#### Mapeamentos do Conector

1. Digite a URL do seu site Atlassian no campo **Location**: `https://{your-site}.atlassian.net`.
2. Digite o e-mail da conta Atlassian à qual o token pertence no campo **Email**.
3. Digite o token de API no campo **Secret**.

Cada objeto do Assets se torna um Record nomeado a partir do rótulo (label) do objeto, agrupado pelo seu **esquema de objeto**.

## **Kubescape**

O conector do Kubescape lê resultados de postura do Kubernetes (má configuração) produzidos pelo [operador Kubescape](https://kubescape.io/docs/install-operator/) diretamente da API do Kubernetes do cluster — nenhuma conta ARMO SaaS é necessária. Ele lê os objetos `WorkloadConfigurationScan` servidos pela API agregada de armazenamento in-cluster do operador (`spdx.softwarecomposition.kubescape.io/v1beta1`). Cada **namespace** do Kubernetes que tenha resultados de postura é mapeado para um Record (Produto); cada controle que falha em um workload se torna um Finding.

#### Pré-requisitos

- O operador Kubescape deve estar instalado no cluster alvo com o escaneamento de configuração ativado (veja [Installing in your cluster](https://kubescape.io/docs/install-operator/)). Confirme que existem resultados com `kubectl get workloadconfigurationscans -A`.
- Um **kubeconfig** concedendo acesso de leitura ao grupo de API `spdx.softwarecomposition.kubescape.io` (list/get em `workloadconfigurationscans`) para o cluster alvo.

#### Mapeamentos do Conector

1. Digite a URL do servidor de API do cluster (ou um identificador amigável do cluster) no campo **Location**.
2. Cole o **kubeconfig** do cluster alvo no campo `kubeconfig`. Opcionalmente, defina `kube_context` para selecionar um contexto dentro dele, e `cluster_name` para rotular os Produtos descobertos.
3. Cada namespace com resultados de postura é descoberto como um Record; mapeie os que você deseja importar para Produtos do DefectDojo.

Os achados são derivados por controle que falha: o nome do controle e o workload identificam o Finding, a severidade vem do fator de pontuação do controle, o ID do controle se torna o vulnerability ID, e cada Finding se vincula à sua referência de controle em `https://hub.armosec.io/docs/`.

## **Mend**

O conector do Mend (antigamente **WhiteSource**) usa a API do Mend para importar achados de segurança da sua organização Mend. O DefectDojo cria um Record para cada **projeto** do Mend.

#### Pré-requisitos

Você precisará de um usuário (de serviço) do Mend com uma **User Key** (um token de acesso pessoal) e o **Organization UUID** da sua organização Mend. Recomendamos uma conta de serviço dedicada para que a atividade automatizada seja fácil de distinguir das ações manuais da equipe. Encontre o Organization UUID no aplicativo Mend em **Administration > Organization UUID**.

#### Mapeamentos do Conector

1. Digite a URL da API do Mend no campo **Location**. Essa URL é **específica por região** — use a URL base de API da região em que sua organização Mend está hospedada.
2. Digite o e-mail de login do usuário Mend no campo **Email**.
3. Digite o **Organization UUID** da sua organização Mend no campo **Organization UUID**.
4. Digite a **User Key** do Mend no campo **User Key**.
5. Opcionalmente, defina uma **Minimum Severity** para limitar quais achados são importados.

## **Lacework / FortiCNAPP**

O conector do Lacework / FortiCNAPP usa a API v2 do Lacework para importar **vulnerabilidades de hosts e contêineres** de toda a sua conta Lacework.

#### Pré-requisitos

Você precisará de uma **chave de API** do Lacework — um id e um secret de chave de API, criados no console do Lacework em **Settings → API keys**. O conector os troca por um token de acesso de curta duração a cada sync; o id da chave, o secret e o token nunca são registrados em log.

#### Mapeamentos do Conector

1. Digite a URL da sua conta Lacework no campo **Location** — por exemplo `https://YOUR-ACCOUNT.lacework.net` (um nome de conta simples também é aceito).
2. Digite o **API Key ID** e o **API Secret**.
3. Opcionalmente, defina uma **Minimum Severity** para limitar quais achados são importados.

O DefectDojo mapeia a **conta** Lacework para um Record (o escopo da conta inteira). Cada vulnerabilidade de **contêiner** e de **host** se torna um achado: a severidade vem da própria classificação do Lacework, o pacote e a versão afetados se tornam o componente, a versão de correção se torna a mitigação, e a imagem/host afetado é registrado como tags. Vulnerabilidades de contêiner são registradas como achados estáticos (scans de imagem) e vulnerabilidades de host como achados dinâmicos (scans de host em execução).

Consulte a [documentação da API do Lacework](https://docs.lacework.net/api/v2/docs) para mais informações.

## **Microsoft Defender**

O conector do Microsoft Defender importa achados de vulnerabilidade de dispositivos a partir do **Microsoft Defender Vulnerability Management (MDVM)** — um achado por combinação de dispositivo / versão de software / CVE, incluindo severidade, pontuação CVSS, nível de explorabilidade e atualizações de segurança recomendadas. O DefectDojo descobrirá os **grupos de dispositivos** do seu Defender e criará um Registro para cada um; dispositivos que não estão atribuídos a nenhum grupo de dispositivos são reunidos em um grupo sintético **Unassigned**.

**Atenção:** este Conector é diferente do tipo de scan baseado em arquivo **"MSDefender Parser"**, que importa arquivos do Defender exportados manualmente. Escolha um único caminho de importação por Produto para evitar achados duplicados.

#### Pré-requisitos

Seu tenant da Microsoft precisa de uma licença ativa que inclua as APIs de exportação de vulnerabilidades do Defender: **Defender for Endpoint Plan 2**, **Microsoft Defender Vulnerability Management Standalone**, ou MDE P1/P2 com o add-on do MDVM. (O SKU do *Add-on* do MDVM sozinho não é suficiente — ele requer o Defender for Endpoint Plan 2 por baixo.)

O conector se autentica como um **app registration** do Microsoft Entra ID usando o fluxo de credenciais de cliente (client credentials flow). Para criar um:

1. No [portal do Azure](https://portal.azure.com), abra **App registrations > New registration**. Dê um nome a ele (por exemplo, `defectdojo-connector`), mantenha os padrões e selecione **Register**.
2. Na página **Overview** do aplicativo, anote o **Application (client) ID** e o **Directory (tenant) ID**.
3. Abra **API permissions > Add a permission > APIs my organization uses** e pesquise por **WindowsDefenderATP**. Se não aparecer, o backend do Defender do seu tenant ainda não foi provisionado: garanta que a licença esteja ativa, abra [security.microsoft.com](https://security.microsoft.com) uma vez e tente novamente após alguns minutos.
4. Escolha **Application permissions** (*não* Delegated — as permissões Delegated nunca aparecem no token de serviço do conector), expanda **Vulnerability**, marque **Vulnerability.Read.All** e selecione **Add permissions**.
5. Selecione **Grant admin consent** e confirme. A coluna Status deve exibir um marcador verde — sem essa etapa, toda chamada de API retorna um erro 403.
6. Abra **Certificates & secrets > New client secret**, defina uma expiração e copie o **Value** do segredo imediatamente (ele só é exibido uma vez). O Conector para de funcionar quando o segredo expira, então anote a data.

#### Mapeamentos do Conector

1. Digite `https://api.security.microsoft.com` no campo **Location**.
2. Digite o **Directory (tenant) ID** no campo **Tenant ID**.
3. Digite o **Application (client) ID** no campo **Client ID**.
4. Digite o valor do segredo do cliente no campo **Client Secret**.
5. Opcionalmente, defina uma **Minimum Severity** para limitar quais achados são importados.

Cada grupo de dispositivos do Defender se torna um Registro. A Microsoft regenera o snapshot de vulnerabilidades lido pelo conector aproximadamente a cada 6 horas, e dispositivos recém-integrados podem levar até ~24 horas para gerar seus primeiros dados de vulnerabilidade — um tenant totalmente novo legitimamente sincronizará zero achados até que os dispositivos sejam integrados e avaliados. A própria ativação da licença também pode levar ~20 minutos ou mais para refletir na API (erros "No active license found" durante essa janela se resolvem sozinhos).

## **Microsoft Defender for Cloud**

O conector do Microsoft Defender for Cloud importa achados de vulnerabilidade do **Microsoft Defender Vulnerability Management (MDVM)** conforme exibidos pelo Defender for Cloud — tanto achados de **servidor** (CVEs de sistema operacional e software instalado em VMs do Azure) quanto achados de **registro de contêineres** (CVEs de imagens de contêiner), incluindo severidade, pontuação CVSS, o pacote ou imagem afetado e a correção. O DefectDojo descobre as **assinaturas** do Azure que sua service principal consegue ler e cria um Registro para cada assinatura habilitada.

**Atenção:** este Conector é diferente do conector **Microsoft Defender**, que importa achados de dispositivos a partir da API do Defender for Endpoint. O Defender for Cloud é um produto do Azure com uma superfície de API diferente (Azure Resource Manager / Resource Graph) e um modelo de permissões diferente (Azure RBAC). Execute o que corresponder a onde seus achados residem — ou ambos, se você usa os dois produtos.

#### Pré-requisitos

Você precisa de uma ou mais **assinaturas do Azure com o Microsoft Defender for Cloud habilitado**, com os planos Defender relevantes ativados para os recursos que deseja escanear (em **Microsoft Defender for Cloud > Environment settings**, e então selecione sua assinatura):

* **Defender for Servers (Plan 2)** — achados de CVE de sistema operacional e software de VMs do Azure (varredura de vulnerabilidades sem agente).
* **Defender for Containers** — achados de CVE de imagens do registro de contêineres.

Achados de avaliação de vulnerabilidades de SQL e de configuração/postura intencionalmente **não** são importados — este conector importa apenas vulnerabilidades CVE.

O conector se autentica como um **app registration** do Microsoft Entra ID usando o fluxo de credenciais de cliente:

1. No [portal do Azure](https://portal.azure.com), abra **App registrations > New registration**. Dê um nome a ele (por exemplo, `defectdojo-connector`), mantenha os padrões e selecione **Register**.
2. Na página **Overview** do aplicativo, anote o **Application (client) ID** e o **Directory (tenant) ID**.
3. Abra **Certificates & secrets > New client secret**, defina uma expiração e copie o **Value** do segredo imediatamente (ele é exibido apenas uma vez). O Conector para de funcionar quando o segredo expira, então anote a data.
4. Conceda ao aplicativo acesso de leitura a cada assinatura que deseja importar: abra **Subscriptions**, selecione sua assinatura, depois **Access control (IAM) > Add > Add role assignment**. Selecione o papel **Security Reader** (ou **Reader**), e na aba **Members** atribua-o ao aplicativo que você criou — pesquise por ele pelo **name** ou **object ID** do aplicativo, já que o seletor não faz correspondência pelo client ID. Repita para cada assinatura.

Diferente do conector Microsoft Defender baseado em dispositivos, nenhuma permissão de API ou admin consent é necessária: o acesso ao Defender for Cloud é regido inteiramente pela atribuição de papel do Azure RBAC acima.

#### Mapeamentos do Conector

1. Digite `https://management.azure.com` no campo **Location**. (Para clouds soberanas, use o endpoint ARM correspondente, por exemplo `https://management.usgovcloudapi.net`.)
2. Digite o **Directory (tenant) ID** no campo **Tenant ID**.
3. Digite o **Application (client) ID** no campo **Client ID**.
4. Digite o valor do segredo do cliente no campo **Client Secret**.
5. Opcionalmente, defina uma **Minimum Severity** para limitar quais achados são importados.

Cada assinatura do Azure habilitada se torna um Registro. Os achados são lidos através do Azure Resource Graph, então eles aparecem rapidamente assim que o Defender for Cloud tiver escaneado seus recursos — mas os próprios escaneamentos seguem o cronograma da Microsoft: imagens do registro de contêineres geralmente são escaneadas dentro de uma hora após serem enviadas (push), enquanto a primeira varredura de vulnerabilidades sem agente de uma VM pode levar várias horas. Uma assinatura recém-habilitada legitimamente sincronizará zero achados até que seus recursos tenham sido escaneados.

## **MobSF**

O conector MobSF usa a API REST do [Mobile Security Framework (MobSF)](https://github.com/MobSF/Mobile-Security-Framework-MobSF) para importar resultados de análise estática de aplicativos móveis (APK/IPA). O DefectDojo descobre cada aplicativo que foi escaneado na sua instância do MobSF e cria um Registro para cada um, então importa os achados de análise estática desse aplicativo.

#### Pré-requisitos

Você precisará da sua **chave de API REST** do MobSF. Encontre-a na página inicial do MobSF em **API** (também exibida na documentação do MobSF como o valor `Authorization`). A chave é enviada em cada requisição e nunca é registrada em log.

#### Mapeamentos do Conector

1. Digite a URL base do seu MobSF no campo **Location** (por exemplo, `https://mobsf.example.com`).
2. No campo **Secret**, digite a chave de API REST do MobSF.
3. Opcionalmente, defina uma **Minimum Severity** para limitar quais achados são importados.

O DefectDojo mapeia cada **aplicativo** escaneado para um Registro e importa seus achados do relatório JSON do MobSF em várias seções — permissões do aplicativo, análise de código, o certificado de assinatura, o manifesto do Android, uso de API do Android e análise binária. Cada achado é marcado com **CWE 919** (mobile), e sua severidade vem da própria classificação do MobSF (high, warning, info, secure/good) — uma permissão *dangerous* é tratada como Alto. Os achados são registrados como achados estáticos e desduplicados pelo scan, seção, título, severidade e caminho do arquivo.

Consulte a [documentação da API REST do MobSF](https://mobsf.github.io/docs/#/rest_api) para mais informações.

## **NeuVector**

O conector NeuVector usa a API REST do controlador [NeuVector](https://github.com/neuvector/neuvector) para importar **varreduras de vulnerabilidade de imagens** de contêiner. O DefectDojo descobre cada imagem que o NeuVector escaneou e cria um Registro para cada uma, então importa o relatório de varredura dessa imagem como achados.

#### Pré-requisitos

Você precisará de um **nome de usuário e senha** do NeuVector para uma conta do controlador com permissão para ler resultados de varredura. O conector se autentica com essas credenciais para obter um token de sessão; a senha e o token nunca são registrados em log.

#### Mapeamentos do Conector

1. Digite a URL do controlador do NeuVector no campo **Location**, incluindo a porta da API REST — por exemplo, `https://neuvector.example.com:10443`.
2. Digite o **Username** e a **Password** do controlador.
3. Se o seu controlador usa um certificado autoassinado, defina **Skip TLS Verification** como `true`.
4. Opcionalmente, defina uma **Minimum Severity** para limitar quais achados são importados.

O DefectDojo mapeia cada **imagem** escaneada para um Registro e cada **CVE** em seu relatório de varredura para um achado. A severidade vem da própria classificação do NeuVector, e o pacote e versão afetados, a pontuação e o vetor CVSSv3, a versão corrigida (como mitigação) e o link de referência são transportados. Os achados são desduplicados pela imagem, CVE, pacote, versão e severidade.

Consulte a [documentação da API do NeuVector](https://open-docs.neuvector.com/automation/automation) para mais informações.

## **Nuclei (ProjectDiscovery Cloud)**

O conector Nuclei usa a API REST da ProjectDiscovery Cloud Platform (PDCP) para buscar resultados de varredura do [nuclei](https://github.com/projectdiscovery/nuclei) da sua conta PDCP. O DefectDojo descobre cada varredura na conta e cria um Registro separado para cada **varredura**.

#### Pré-requisitos

Você precisará de uma **chave de API** da ProjectDiscovery Cloud. Recomendamos criar uma conta de serviço dedicada para o DefectDojo, para distinguir claramente a atividade automatizada das ações manuais da equipe. Gere uma chave em **Settings > API Key** na interface da ProjectDiscovery Cloud ([cloud.projectdiscovery.io](https://cloud.projectdiscovery.io)). Os resultados chegam ao PDCP a partir de varreduras hospedadas ou da execução da CLI do nuclei com `-dashboard`.

#### Mapeamentos do Conector

1. Digite a URL base da API do PDCP no campo **Location**: `https://api.projectdiscovery.io`.
2. Digite sua **API key** no campo **Secret**.
3. Opcionalmente, digite um **Team ID** para restringir a sincronização a um espaço de trabalho de equipe (encontrado em **Settings > Team**). Se deixado em branco, o DefectDojo sincroniza o seu espaço de trabalho pessoal.
4. Opcionalmente, defina uma **Minimum Severity** para limitar quais achados são importados.

O DefectDojo mapeia cada **varredura** do PDCP como um Registro separado e importa os achados dessa varredura em todas as severidades, incluindo informativa.

## **OpenVAS / Greenbone**

O conector OpenVAS / Greenbone importa **achados de vulnerabilidade de rede** de uma instância Greenbone (Greenbone Community Edition ou Greenbone Enterprise). Ele se comunica com o `gvmd` via **GMP (Greenbone Management Protocol)** — um protocolo XML sobre um socket TLS, não HTTP — e sincroniza a instância inteira: ele enumera as tasks de varredura e cria um produto do DefectDojo para cada uma, importando os resultados do relatório mais recente de cada task.

#### Pré-requisitos

Um **usuário GMP** do Greenbone (usuário + senha) e acesso de rede à porta TLS GMP do gvmd (padrão **9390**). A stack Docker Compose do Greenbone Community Edition expõe o gvmd através de um socket unix, então, para alcançá-lo a partir de um conector em rede, você precisa executar o conector onde ele possa acessar o socket, ou expor a porta TLS GMP (por exemplo, uma ponte TLS `socat` para `gvmd.sock`).

#### Mapeamentos do Conector

1. Digite o host do gvmd no campo **Location** (host ou `host:port`).
2. Digite o **Username** e a **Password** do GMP.
3. Opcionalmente, defina a **GMP Port** (o padrão é 9390).
4. Para o certificado autoassinado padrão do gvmd, forneça um **CA Certificate (PEM)** para verificação, ou defina **Skip TLS Verification** como `true`.
5. Opcionalmente, defina uma **Minimum Severity** para limitar quais achados são importados.

Cada task do Greenbone se torna um Registro. Os achados vêm do relatório mais recente finalizado da task — um por `<result>`. A severidade é obtida a partir do nível de ameaça (threat level) do resultado (os níveis informativos `Log`/`Debug` do Greenbone são mapeados para Informativa), com a pontuação CVSS numérica sendo registrada; referências de CVE se tornam ids de vulnerabilidade, a solução do NVT se torna a mitigação, e o host/porta de cada resultado se torna um endpoint.

## Probely

Este conector usa a API REST do Probely para buscar dados.

**Mapeamentos do Conector**

1. Digite o endereço apropriado do servidor de API no campo **Location**. (seja <https://api.us.probely.com/> ou <https://api.eu.probely.com/>)
2. Digite uma chave de API válida no campo **Secret**.

Você pode encontrar uma chave de API no menu User > API Keys no Probely.  
Consulte a [documentação do Probely](https://help.probely.com/en/articles/8592281-how-to-generate-an-api-key) para mais informações.

## Prowler

O conector Prowler usa a API REST do **Prowler App** para importar achados de postura de segurança em nuvem (CSPM) de uma instância self-hosted do Prowler App. O DefectDojo descobre cada **provider** (conta de nuvem) do Prowler como um Registro e importa os achados **FAIL** da varredura mais recente concluída desse provider.

#### Pré-requisitos

Você precisará de uma instância self-hosted em execução do **Prowler App** e de um e-mail + senha de usuário (para autenticação JWT) ou de uma **API key** do Prowler App. Os achados só aparecem depois que você conectar uma conta de nuvem (AWS, GCP, Azure, Kubernetes, ...) no Prowler App e executar uma varredura.

#### Mapeamentos do Conector

1. Digite a URL do seu Prowler App no campo **Location** (por exemplo, `https://prowler.your-company.com`).
2. Para autenticação JWT, digite o **Email** e a **Password** do usuário do Prowler App. Alternativamente, deixe esses campos em branco e digite uma **API Key** do Prowler App. Se ambos forem fornecidos, o e-mail/senha (JWT) é utilizado.
3. Opcionalmente, defina uma **Minimum Severity** para limitar quais achados são importados. Achados abaixo da severidade selecionada não são importados.

O DefectDojo cria um Registro para cada provider do Prowler e importa os achados FAIL da sua varredura mais recente concluída, mapeando as severidades do Prowler para as severidades do DefectDojo, o recurso de nuvem afetado (ARN/resource id) como o componente, e a remediação e o risco da verificação (check) no achado. Achados silenciados (muted) são ignorados. Conta de nuvem, região e serviço são anexados como Tags.

Para mais informações, consulte a **[documentação da API do Prowler App](https://api.prowler.com/api/v1/docs)**.

## Qualys

O conector Qualys importa **detecções de vulnerabilidade de host do VMDR** — cada uma combinada com seus metadados do Qualys KnowledgeBase (QID) — a partir da Qualys Cloud Platform. O DefectDojo cria um Registro para cada **host** Qualys na sua assinatura.

#### Pré-requisitos

Uma conta de usuário Qualys com **acesso à API do VMDR**, e a **URL do servidor de API (platform)** da sua assinatura — isso varia por assinatura. Encontre-a na interface do Qualys em **Help > About**, ou na página [Platform Identification](https://www.qualys.com/platform-identification/) da Qualys (por exemplo, `https://qualysapi.qualys.com` para o US Platform 1, ou `https://qualysapi.qg2.apps.qualys.com` para o US Platform 2).

#### Mapeamentos do Conector

1. Digite a URL do servidor de API do Qualys no campo **Location** (por exemplo, `https://qualysapi.qualys.com`).
2. Digite o nome de usuário da API do Qualys no campo **Username**.
3. Digite a senha da API do Qualys no campo **Secret**.
4. Opcionalmente, defina uma **Minimum Severity** para limitar quais achados são importados.

Cada host Qualys se torna um Registro. Detecções que o Qualys marcou como **Fixed** são excluídas, então a reimportação fecha os achados corrigidos.

## **Quay**

O conector Quay usa a API REST do Project Quay para descobrir repositórios de contêiner e importar os relatórios de vulnerabilidade produzidos pelo scanner **Clair** embutido do Quay. O DefectDojo cria um Registro para cada **repositório** do Quay e, em cada sincronização, lê o relatório de segurança do Clair do manifesto de imagem de cada tag ativa.

#### Pré-requisitos

A varredura de segurança (Clair) deve estar habilitada na sua instância do Quay, e você precisará de um **token de acesso OAuth 2** do Quay:

* No Quay, crie (ou abra) uma Organization, vá em **Applications**, crie uma aplicação OAuth e então **Generate Token** com pelo menos o escopo **Read repositories**. Recomenda-se uma aplicação dedicada para o DefectDojo.
* O token é enviado como um Bearer token em cada requisição e nunca é registrado em log.

#### Mapeamentos do Conector

1. Digite a URL base do seu Quay no campo **Location**, por exemplo `https://quay.io` ou o seu self-hosted `https://quay.example.com`. A URL deve ser HTTPS; não inclua um caminho de API no final — o DefectDojo constrói os caminhos de API automaticamente.
2. Digite o token de acesso OAuth no campo **Secret**.
3. Opcionalmente, defina um **Namespace** para restringir a descoberta a uma única organização ou usuário do Quay. Deixe em branco para descobrir todos os repositórios que o token consegue ler.
4. Opcionalmente, defina uma **Minimum Severity** para limitar quais achados são importados.

O DefectDojo mapeia cada **repositório** do Quay para um Registro. Para cada repositório, ele lista as tags ativas, desduplica-as para seus manifestos de imagem únicos (um manifesto compartilhado por múltiplas tags é escaneado uma única vez), e lê o relatório do Clair de cada manifesto. Manifestos que o Clair ainda não terminou de escanear (por exemplo, uma lista de manifesto multi-arquitetura, ou uma imagem ainda na fila) são ignorados até uma sincronização posterior. Cada vulnerabilidade do Clair se torna um achado — o pacote afetado é o componente, a versão corrigida se torna a mitigação, e as severidades **Negligible**/**Unknown** do Clair são registradas como **Informativa**.

Consulte a [documentação da API do Project Quay](https://docs.projectquay.io/api_quay.html) e a [documentação do Clair](https://quay.github.io/clair/) para mais informações.

## **Rapid7 InsightAppSec**

O conector Rapid7 InsightAppSec importa **achados de vulnerabilidade DAST** da plataforma em nuvem InsightAppSec, enriquecidos com metadados de módulo de ataque (attack-module) (por exemplo, *SQL Injection*), pontuações CVSS, e as evidências coletadas pela varredura. O DefectDojo cria um Registro para cada **aplicativo** do InsightAppSec.

**Atenção:** este Conector é diferente do conector **Rapid7 InsightVM** abaixo — o InsightAppSec é o produto DAST em nuvem da Rapid7 na plataforma Insight, enquanto os achados do InsightVM vêm do seu próprio Security Console.

#### Pré-requisitos

Uma conta na plataforma Insight com InsightAppSec, e uma **API key** da plataforma: na [plataforma Rapid7 Insight](https://insight.rapid7.com), abra o menu de configurações (ícone de engrenagem) > **API Keys** e gere uma **User Key** (qualquer papel) ou uma **Organization Key** (administradores da plataforma). Copie a chave quando ela for exibida — ela é mostrada apenas uma vez.

Você também precisará da **região** da sua plataforma, visível na sua URL do Insight (por exemplo, `us`, `us2`, `us3`, `eu`, `ca`, `au`, ou `ap`).

#### Mapeamentos do Conector

1. Digite o endpoint regional da API no campo **Location** — por exemplo, `https://us.api.insight.rapid7.com` (substitua `us` pela sua região).
2. Digite a API key da plataforma Insight no campo **API Key**.
3. Opcionalmente, defina uma **Minimum Severity** para limitar quais achados são importados.

Cada aplicativo do InsightAppSec se torna um Registro. Apenas vulnerabilidades **abertas** (Unreviewed ou Verified) são importadas — achados que a Rapid7 marcou como Remediated, False Positive, Ignored, ou Duplicate são excluídos, então a reimportação os fecha no DefectDojo. As severidades são mapeadas diretamente (`SAFE` e `INFORMATIONAL` são importados como Informativa).

## **Rapid7 InsightVM**

O conector Rapid7 InsightVM importa achados de vulnerabilidade de ativos do seu **Security Console** do InsightVM (API v3), enriquecidos com o catálogo global de vulnerabilidades do console. O DefectDojo cria um Registro para cada **site** do InsightVM.

#### Pré-requisitos

Acesso de rede do DefectDojo ao seu Security Console, e uma **conta de usuário** do console — seu login é usado para autenticação HTTP Basic. A API do console é servida na porta **3780** por padrão.

#### Mapeamentos do Conector

1. Digite a URL do seu Security Console, incluindo a porta, no campo **Location** — por exemplo, `https://console.example.com:3780`.
2. Digite o nome de usuário do console no campo **Username**.
3. Digite a senha do console no campo **Secret**.
4. Opcionalmente, defina uma **Minimum Severity** para limitar quais achados são importados.

Cada site do InsightVM se torna um Registro; o conector percorre os ativos do site e importa seus achados de vulnerabilidade.

## **runZero**

O conector runZero usa a Export API do runZero para sincronizar o inventário de ativos de toda a sua organização no DefectDojo. É, principalmente, um conector de **ativos**: o DefectDojo descobre cada ativo e cria um Registro para cada um, agrupados em um Tipo de Produto pelo seu **site** no runZero. Opcionalmente, ele também pode importar as vulnerabilidades do runZero como achados.

#### Pré-requisitos

Você precisará de um **Export Token** de organização do runZero (Account → API), com o prefixo `XT`. O token tem escopo de organização (a organização é codificada no token), é somente leitura, e é enviado como um Bearer token — nunca é registrado em log. Um nível community/starter está disponível.

#### Mapeamentos do Conector

1. Digite a URL do seu console runZero no campo **Location**, por exemplo `https://console.runzero.com`. A URL deve ser HTTPS.
2. Digite o Export Token no campo **Secret**.
3. Opcionalmente, defina **Import Vulnerabilities** como `true` para também importar as vulnerabilidades do runZero como achados; deixe em branco para sincronizar apenas os ativos.
4. Opcionalmente, defina uma **Minimum Severity** para limitar quais achados de vulnerabilidade são importados (aplica-se apenas quando as vulnerabilidades são importadas).

O DefectDojo mapeia cada **ativo** do runZero para um Registro (VEP): o nome de exibição vem do nome ou endereço do ativo, e seu site, tipo, SO, endereços e tags são anexados como atributos; o **site** do ativo se torna seu Tipo de Produto. Os ativos são sincronizados com uma exportação completa que o DefectDojo concilia (adiciona/remove). Quando **Import Vulnerabilities** está habilitado, cada vulnerabilidade do runZero se torna um achado no seu ativo — mapeando a severidade, a pontuação CVSS, o CVE, o endpoint do serviço afetado (`protocol://address:port`) e a remediação.

Consulte a [documentação da API do runZero](https://help.runzero.com/) para mais informações.

## **Semgrep**

Este conector usa a API REST do Semgrep para buscar dados.

#### Mapeamentos do Conector

Digite `https://semgrep.dev/api/v1/` no campo **Location**.

1. Digite uma chave de API válida no campo **Secret**. Você pode encontrar isso na página Tokens:
"Settings" na barra de navegação lateral esquerda > Tokens > Create new token ([https://semgrep.dev/orgs/-/settings/tokens](https://semgrep.dev/orgs/-/settings/tokens))

Consulte a [documentação do Semgrep](https://semgrep.dev/docs/semgrep-cloud-platform/semgrep-api/#tag__badge-list) para mais informações.

## **ServiceNow CMDB**

O conector ServiceNow CMDB é um **Conector de Ativos**: em vez de importar achados, ele lê Configuration Items (CIs) do seu ServiceNow Configuration Management Database e cria um Ativo do DefectDojo para cada CI, agrupados em Organizações pela classe do CI. Nenhum achado é importado.

#### Pré-requisitos

Você precisará de uma instância do ServiceNow e de uma conta que consiga ler as tabelas do CMDB através da ServiceNow Table API. Recomendamos uma conta de serviço dedicada e somente leitura para o DefectDojo. A conta precisa de acesso de leitura às tabelas `cmdb_ci` que você deseja importar.

#### Mapeamentos do Conector

1. Digite a URL da sua instância do ServiceNow no campo **Location**: `https://{your-instance}.service-now.com`.
2. Selecione ou crie uma **Tool Configuration** do ServiceNow contendo as credenciais da instância (o nome de usuário e a senha do ServiceNow).

Cada Configuration Item se torna um Registro nomeado a partir do CI, agrupado pela sua **CI class** (por exemplo, aplicativo, servidor ou serviço de negócio). A descoberta e a sincronização conciliam a lista de CIs: novos CIs aparecem como Registros `NEW`, e um CI removido do CMDB é sinalizado como `MISSING` na próxima sincronização, para que sua equipe possa triá-lo. O DefectDojo nunca exclui um Produto silenciosamente.

## **Shodan**

O conector Shodan usa a API REST do Shodan para importar as vulnerabilidades (CVEs) que o Shodan observou nos seus hosts expostos à internet. Você fornece uma consulta de busca do Shodan que restringe a importação aos seus próprios ativos; o DefectDojo cria um Registro para cada host correspondente e importa seus CVEs como achados.

#### Pré-requisitos

Você precisará de uma chave de API do Shodan, encontrada na sua página **Account** do Shodan. A busca de hosts com dados de vulnerabilidade requer uma associação (membership) do Shodan ou um plano de API pago — o nível gratuito não consegue paginar pelos resultados de busca.

#### Mapeamentos do Conector

1. Digite `https://api.shodan.io` no campo **Location**.
2. Digite sua chave de API do Shodan no campo **API Key**.
3. No campo **Search Query**, digite uma consulta do Shodan que restrinja a importação aos ativos da sua organização — por exemplo, `hostname:example.com`, `net:203.0.113.0/24`, ou `org:"Example Inc"`. Apenas hosts que correspondem a essa consulta são importados, então mantenha-a restrita à infraestrutura que você possui.
4. Opcionalmente, defina uma **Minimum Severity** para limitar quais achados são importados.

Cada host correspondente se torna um Registro, e cada CVE que o Shodan detectou nos serviços expostos desse host é importado como um achado — a severidade é derivada da pontuação CVSS, com o contexto de EPSS e CISA KEV incluído quando disponível. Cada página de resultados de busca consome um crédito de consulta do Shodan.

## SonarQube

O Conector SonarQube pode buscar dados de uma conta SonarCloud ou de uma instância local do SonarQube.

**Para usuários do SonarCloud:**

1. Digite https://sonarcloud.io/ no campo Location.
2. Digite uma **API key** válida no campo Secret.

**Para usuários do SonarQube (on-premise):**

1. Digite a URL base da sua instância do SonarQube no campo Location: por exemplo, `https://my.sonarqube.com/`
2. Digite uma **API key** válida no campo Secret. Isso precisará ser um **[User](https://docs.sonarsource.com/sonarqube/latest/user-guide/user-account/generating-and-using-tokens/)** [API Token Type](https://docs.sonarsource.com/sonarqube/latest/user-guide/user-account/generating-and-using-tokens/).

O token precisará ter acesso a Projects, Vulnerabilities e Hotspots dentro do Sonar.

Os tokens de API podem ser encontrados e gerados em **My Account -> Security -> Generate Token** no aplicativo SonarQube. Para mais informações, [consulte a documentação do SonarQube](https://docs.sonarsource.com/sonarqube/latest/user-guide/user-account/generating-and-using-tokens/).

## **Snyk**

O conector Snyk usa a API REST do Snyk para buscar dados.

#### Mapeamentos do Conector

1. Digite **[https://api.snyk.io/rest](https://api.snyk.io/v1)** ou **[https://api.eu.snyk.io/rest](https://api.eu.snyk.io/v1)** (para uma implantação regional na UE) no campo **Location**.
2. Digite uma chave de API válida no campo **Secret**. Os API Tokens são encontrados na **[Configurações da Conta](https://docs.snyk.io/getting-started/how-to-obtain-and-authenticate-with-your-snyk-api-token)** [página](https://docs.snyk.io/getting-started/how-to-obtain-and-authenticate-with-your-snyk-api-token) de um usuário no Snyk.

Consulte a [documentação da API do Snyk](https://docs.snyk.io/snyk-api) para mais informações.

## **Socket**

O conector Socket usa a API do [Socket.dev](https://socket.dev) para importar **achados de cadeia de suprimentos de software** — os alertas do Socket sobre suas dependências (malware, typosquats, scripts de instalação, vulnerabilidades conhecidas e mais de 70 outras categorias). O DefectDojo descobre todos os repositórios nas organizações que seu token pode acessar e cria um Record para cada um, depois importa os alertas da verificação completa mais recente desse repositório.

#### Pré-requisitos

Você precisará de um **token de API** do Socket — um token de organização criado no painel do Socket em **Settings → API Tokens** (com os escopos `repo:list` e de leitura de full-scan). O token é enviado como bearer token e nunca é registrado em log.

#### Mapeamentos do conector

1. Deixe o campo **Location** em branco para usar `https://api.socket.dev/v0`, ou informe-o explicitamente.
2. Insira o token de API do Socket no campo **Secret**.
3. Opcionalmente, defina uma **Minimum Severity** para limitar quais achados são importados.

O DefectDojo mapeia cada **repositório** para um Record e importa os alertas de sua verificação completa mais recente. Cada alerta se torna um achado: a severidade vem da classificação do próprio Socket (baixo, médio, alto, crítica), o pacote afetado se torna o componente e um PURL, a categoria do alerta (supply-chain risk, quality, maintenance, vulnerability, license) é registrada como tags, e os detalhes do alerta são incluídos na descrição. Os achados são registrados como achados estáticos e desduplicados pela chave de alerta do Socket.

Consulte a [documentação da API do Socket](https://docs.socket.dev/reference) para mais informações.

## **Sonatype IQ**

O conector Sonatype IQ usa a API REST do Sonatype IQ Server (Nexus Lifecycle) para importar vulnerabilidades de componentes open-source. Ele enumera todas as aplicações da sua organização IQ e, para cada uma, importa as vulnerabilidades de componentes do relatório mais recente dessa aplicação no estágio do ciclo de vida que você configurar. O DefectDojo cria um Record para cada aplicação automaticamente — não há configuração por aplicação.

#### Pré-requisitos

Você precisará de uma conta de usuário do Sonatype IQ com a permissão **View IQ Elements** nas aplicações que deseja importar. A Sonatype recomenda autenticar com um **user token** (gerado em **My Profile > User Token** no IQ Server) em vez de uma senha; as duas partes do token correspondem aos campos Username e User Token abaixo. O conector funciona tanto com instâncias self-hosted do IQ Server quanto com instâncias hospedadas pela Sonatype (SaaS).

#### Mapeamentos do conector

1. No campo **Location**, insira a URL base do seu IQ Server — para um servidor self-hosted, `https://iq.example.com`; para uma instância hospedada pela Sonatype, `https://<tenant>.sonatype.app/platform`.
2. Insira o usuário IQ (ou a parte user-code do seu user token) no campo **Username**.
3. Insira o user token do IQ (ou a senha) no campo **User Token**.
4. Opcionalmente, defina um **Stage** para escolher o relatório de qual estágio do ciclo de vida é importado por aplicação (`build`, `stage-release`, `release`, e assim por diante). Deixe em branco para usar `build`.
5. Opcionalmente, defina uma **Minimum Severity** para limitar quais achados são importados.

Cada aplicação se torna um Record, e cada problema de segurança no relatório mais recente dessa aplicação para o estágio selecionado é importado como um achado. A severidade é derivada da pontuação numérica do problema, e as referências de CVE, o CWE, o vetor CVSS e a URL do pacote do componente afetado (PURL) são incluídos quando disponíveis.
## **Sysdig Secure**

O conector Sysdig Secure importa **achados de vulnerabilidade de container / CNAPP** da API de gerenciamento de vulnerabilidades do Sysdig Secure. Ele sincroniza a conta inteira nos escopos configurados e cria um produto do DefectDojo para cada agrupamento de ativos verificado.

#### Pré-requisitos

Um **token de API** do Sysdig Secure: no Sysdig Secure, acesse **Settings > Sysdig Secure API Token** e copie o token. Você também precisará da **URL da região** do Sysdig (por exemplo `https://us2.app.sysdig.com`, `https://eu1.app.sysdig.com`, ou seu host on-premises).

#### Mapeamentos do conector

1. Insira a URL de região/base do Sysdig no campo **Location**.
2. Insira o token de API no campo **Secret**.
3. Opcionalmente, defina **Scopes** — uma lista separada por vírgulas com `runtime`, `registry` e/ou `pipeline` (deixe em branco para `runtime`, o escopo de workloads implantados).
4. Opcionalmente, defina **Runtime Product Grouping** — como os resultados de runtime são mapeados para produtos: `cluster`, `namespace`, `workload` ou `image` (deixe em branco para `namespace`). Os resultados de registry e pipeline sempre são agrupados por repositório de imagem.
5. Opcionalmente, defina uma **Minimum Severity** para limitar quais achados são importados.

Cada agrupamento de ativos se torna um Record. Para cada resultado de verificação, o conector importa cada pacote vulnerável como um achado. Os achados de **Runtime** (workloads implantados) são registrados como achados dinâmicos e marcados com o contexto de cluster / namespace / workload / container do Kubernetes; os achados de **registry** e **pipeline** são registrados como achados estáticos de verificação de imagem. A severidade `NEGLIGIBLE` do Sysdig é mapeada para Informativa.

## Tenable

O conector Tenable usa a API REST do **Tenable.io** para buscar dados.  As verificações são obtidas do endpoint `/scans` do Tenable VM.

Conectores Tenable on-premise não estão disponíveis no momento.

#### **Mapeamentos do conector**

1. Insira <https://cloud.tenable.com> no campo Location.
2. Insira uma **API key** válida no campo Secret.

Consulte a [documentação da API do Tenable](https://docs.tenable.com/vulnerability-management/Content/Settings/my-account/GenerateAPIKey.htm) para mais informações.

## **Tenable Web App Scanning**

O conector Tenable Web App Scanning importa **achados de aplicação web (DAST)** do Tenable Web App Scanning. É um conector separado do Tenable (Vulnerability Management): os dois produtos cobrem ativos diferentes e são configurados de forma independente, então você pode usar um, outro, ou ambos.

O DefectDojo cria um Record para cada **aplicação web verificada**. As aplicações são descobertas a partir das configurações de verificação do Web App Scanning; uma configuração que nunca foi executada não produz um Record até que sua primeira verificação seja concluída. Quando mais de uma configuração verifica a mesma aplicação, elas compartilham um único Record.

#### Pré-requisitos

**API keys** do Tenable (uma access key e uma secret key) para um usuário com permissões de Web App Scanning. No Tenable, acesse **My Account > API Keys** para gerá-las, e confirme que o usuário pode visualizar as verificações que você deseja importar — chaves limitadas ao Vulnerability Management não conseguem ler dados do Web App Scanning.

Conectores Tenable on-premise não estão disponíveis no momento.

#### Mapeamentos do conector

1. Insira <https://cloud.tenable.com> no campo **Location**.
2. Insira sua **Access Key** e **Secret Key**.
3. Opcionalmente, defina uma **Minimum Severity** para limitar quais achados são importados.

Os achados são importados com a severidade que o Tenable reporta para sua conta, incluindo qualquer severidade que sua equipe tenha reclassificado. Cada achado traz a URL afetada como um endpoint, o parâmetro de requisição e o payload que o disparou, e a prova e a saída do Tenable como passos para reproduzir, além dos valores de CWE, CVE, CVSS e EPSS quando o plugin de detecção os fornece.

Somente achados que estão atualmente abertos ou reabertos são importados. Um achado que o Tenable marcou como corrigido é fechado no DefectDojo na próxima sincronização.

## **Veracode**

O conector Veracode importa achados de aplicações da plataforma Veracode, divididos por tipo de verificação nos tipos de achado **SAST**, **DAST**, **SCA** e **Manual**. O DefectDojo cria um Record para cada **aplicação** do Veracode.

#### Pré-requisitos

Gere uma **credencial de API** do Veracode para uma conta que possa ver as aplicações que você deseja importar: na Veracode Platform, abra o menu da sua conta > **API Credentials** e selecione **Generate API Credentials** (veja [Managing Veracode API credentials](https://docs.veracode.com/r/c_api_credentials3)). Copie tanto o **API ID** quanto o **API Secret Key** — o secret é exibido apenas uma vez.

#### Mapeamentos do conector

1. Insira a URL base da API do Veracode no campo **Location**: `https://api.veracode.com` (região comercial), `https://api.veracode.eu` (região europeia), ou `https://api.veracode.us` (região federal dos EUA).
2. Insira o API ID no campo **API ID**.
3. Insira a API secret key no campo **Secret**.
4. Opcionalmente, defina uma **Minimum Severity** para limitar quais achados são importados.

Cada aplicação do Veracode se torna um Record. Somente achados **abertos** são importados, então a reimportação fecha os achados que o Veracode reporta como resolvidos.

## **Wazuh**

O conector Wazuh usa o Wazuh Indexer (OpenSearch) para buscar achados de vulnerabilidade. O Wazuh 4.8 e versões posteriores armazenam os CVEs detectados no Indexer em vez de na API do servidor Wazuh, então este conector os lê diretamente do índice `wazuh-states-vulnerabilities-*`.

O DefectDojo cria um Record para cada agente (endpoint) do Wazuh e importa os CVEs detectados desse agente como achados de forma agendada.

#### Pré-requisitos

Você precisará de:

* A URL base do seu Wazuh Indexer, incluindo a porta (o Indexer escuta na porta 9200 por padrão). O DefectDojo se conecta ao Indexer diretamente, então esse endpoint deve estar acessível a partir do DefectDojo. Para implantações self-managed, esse é o host que executa o Wazuh Indexer. Para o Wazuh Cloud, use o endpoint do Indexer exibido no seu console do Wazuh Cloud, que é diferente da URL do dashboard do Wazuh.
* Um usuário e senha do Indexer com acesso de leitura ao índice `wazuh-states-vulnerabilities-*`. Recomendamos criar um usuário dedicado para o DefectDojo.

A detecção de vulnerabilidades deve estar habilitada no Wazuh para que o índice de estado de vulnerabilidades seja populado. Consulte a [documentação de detecção de vulnerabilidades do Wazuh](https://documentation.wazuh.com/current/user-manual/capabilities/vulnerability-detection/index.html) para mais informações.

#### Mapeamentos do conector

1. Insira a URL base do seu Wazuh Indexer no campo **Location**, incluindo o esquema e a porta, por exemplo `https://your-indexer.example.com:9200`. Não inclua um caminho final. O DefectDojo constrói os caminhos de busca automaticamente.
2. Insira o nome de usuário do Indexer no campo **Username**.
3. Insira a senha do Indexer no campo **Password**.
4. Opcionalmente, defina uma **Minimum Severity** para limitar quais achados são importados. Achados abaixo da severidade selecionada não serão importados.

## Wiz

Usar o conector Wiz exige que você crie uma service account: consulte a [documentação do Wiz](https://docs.wiz.io/wiz-docs/docs/service-accounts-settings#add-a-service-account) para mais informações.  Você precisará de uma conta Wiz para acessar a documentação.

A service account deve atender a todos os requisitos a seguir. Uma service account que não atenda a algum deles ainda pode se autenticar com sucesso, mas não importará nada:

* **Type**: Custom Integration (GraphQL API).
* **API scopes**: no mínimo `read:projects`, `read:issues`, e `read:vulnerabilities`.
* **Project visibility**: a service account deve ter escopo para todo Wiz Project que você deseja importar (ou para todos os Projects). O conector primeiro descobre seus Wiz Projects e depois busca os achados de cada Project — uma conta que pode ler issues mas não tem visibilidade de Project descobre zero Projects, então não há nada para importar e nenhum erro é reportado por nenhum dos lados.

#### **Mapeamentos do conector**

1. Insira seu Wiz Client ID no campo Client ID.
2. Insira o Wiz Client Secret no campo Secret.

## **YesWeHack**

O conector YesWeHack usa a API REST do YesWeHack para importar relatórios dos seus programas de bug bounty e de divulgação de vulnerabilidades. O DefectDojo cria um Record para cada programa que seu token pode acessar e importa seus relatórios como achados.

#### Pré-requisitos

Você precisará de um **Personal Access Token (PAT)** do YesWeHack. Acesso de leitura aos seus programas é suficiente. Algumas contas exigem TOTP/MFA ao criar um token; uma vez criado, o valor do token em si é o que o conector usa.

1. No YesWeHack, abra as configurações da sua conta e acesse **API / Personal Access Tokens**.
2. Crie um token e copie seu valor. Ele é exibido apenas uma vez.

#### Mapeamentos do conector

1. Insira `https://api.yeswehack.com/` no campo **Location**.
2. Insira seu Personal Access Token no campo **Secret**.
3. Opcionalmente, defina uma **Minimum Severity** para limitar quais achados são importados. Achados abaixo da severidade selecionada não serão importados.

O DefectDojo cria um Record separado para cada programa que seu token pode acessar, e importa cada relatório como um achado. A severidade do achado é obtida a partir da classificação CVSS do relatório (usando a prioridade de triagem como alternativa), e seu status reflete o estado de workflow do relatório — por exemplo, relatórios resolvidos são importados como mitigados, e relatórios marcados como inválidos ou fora do escopo são importados como inativos.
