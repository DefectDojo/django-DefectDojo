---
title: Jira (Legado)
description: Trabalhe com a integração do Jira
weight: 1
audience: pro
aliases:
- /pt-br/issue_tracking/jira/pro__jira_guide/
- /pt-br/en/share_your_findings/jira_guide
---

> **Esta página documenta a integração legada do Jira.** A integração do Jira por produto descrita aqui foi substituída pelo **[Conector Downstream do Jira](/connectors/downstream/about/)**, que está disponível de forma geral em todas as instâncias do DefectDojo Pro e é a forma recomendada de enviar Achados para o Jira. Na barra lateral do Pro, **Connect > Jira** traz um selo `LEGACY` por esse motivo — veja [Menu Badges](/navigation/pro__menu_badges/).
>
> **Se você está configurando o Jira pela primeira vez, comece pelo [Conector Downstream](/connectors/downstream/about/) em vez deste guia.**
>
> **Já usa a integração legada?** O DefectDojo Pro inclui uma migração integrada que move sua configuração clássica existente do Jira para os Conectores Downstream, incluindo os tickets que você já enviou — veja [Migrando para o Conector Downstream do Jira](#migrating-to-the-jira-downstream-connector) abaixo.
>
> A integração legada continua funcionando, e este guia permanece válido para ela.

A integração do Jira do DefectDojo pode ser usada para enviar dados de Achados para um ou mais Espaços do Jira. Ao fazer isso, você pode integrar o DefectDojo ao seu fluxo de trabalho de desenvolvimento padrão. Aqui estão alguns exemplos de como isso pode funcionar:

* A equipe de AppSec pode enviar seletivamente Achados para um Espaço do Jira usado pelos desenvolvedores, para que a correção de problemas possa ser adequadamente priorizada junto com o desenvolvimento normal. Os desenvolvedores nesse quadro não precisam acessar o DefectDojo - eles podem manter todo o trabalho deles em um só lugar.
* O DefectDojo pode enviar TODOS os Achados para um Espaço do Jira bidirecional que a equipe de AppSec usa, o que permite que eles dividam a validação de problemas. Esse quadro se mantém sincronizado com o DefectDojo e permite fluxos de correção complexos.
* O DefectDojo pode enviar seletivamente Achados de Produtos e/ou Engajamentos separados para Espaços do Jira separados, para manter as coisas em seu contexto adequado.

## Migrando para o Conector Downstream do Jira

O DefectDojo Pro pode converter uma configuração clássica existente do Jira em uma configuração de Conector Downstream para você, em vez de exigir que você a reconstrua manualmente.

**Onde encontrar:** acesse **Connect \> Downstream** para abrir a página **Downstream Connectors**, e use o cartão **Classic Jira Migration**. Clique em **Migrate from classic Jira** e depois confirme.

O cartão só aparece se houver configuração clássica do Jira para migrar, ou uma execução anterior a reportar — então uma instância que nunca usou o Jira clássico não vai vê-lo. Depois que tudo tiver sido migrado, o cartão permanece, mas o botão fica desabilitado, porque não há mais nada a fazer.

Executar a migração exige **permissões globais de nível Maintainer** (especificamente, permissão para editar integrações), e ela precisa ser executada a partir de uma sessão de navegador autenticada — não pode ser feita com um token de API.

### O que acontece com os tickets que você já enviou

**Seus tickets existentes do Jira são mantidos e vinculados novamente — eles não ficam órfãos, e o conector não abre duplicatas.** Cada Achado que o Jira clássico já havia enviado mantém seu ticket, e o conector passa a atualizar esse mesmo ticket a partir de então. Os links em Grupos de Achados são transferidos da mesma forma.

A única exceção são os **epics de Engajamento**. O Conector Downstream não tem o conceito de epics, então os problemas do tipo epic são reportados nos avisos da migração e deixados intocados.

### O que é migrado

* Sua conexão de **instância** do Jira — URL e credenciais — se torna uma instância de integração de Conector Downstream, mantendo seu nome.
* Os **mapeamentos de severidade** e os **mapeamentos de status** (suas chaves de transição de abertura e fechamento) são transferidos.
* Cada configuração de **Projeto do Jira** se torna um mapeamento de rastreador de problemas, mantendo sua chave de projeto e tipo de issue, e permanece atribuída ao mesmo Produto ou Engajamento.
* **Push All Issues** é preservado: projetos que tinham essa opção habilitada continuam enviando automaticamente.
* **Campos personalizados**, **campos de transição de fechamento/reabertura**, **componente**, **responsável padrão** e **labels** são convertidos em mapeamentos de campo. Onde você usava *Add Vulnerability Id as a Jira label*, isso também se torna um mapeamento de label.
* Um diretório de **modelo de issue personalizado** se torna um modelo de ticket. Os modelos padrão não são copiados, porque o conector já traz equivalentes.

### O que não é transferido

Esses itens são reportados como avisos na execução da migração — eles não a interrompem. Procure pela lista *"things the connector cannot carry over"* nos resultados.

* **Sincronização reversa do Jira → DefectDojo.** Esse é o ponto importante. O Conector Downstream não sincroniza alterações *de volta* a partir do Jira, então os mapeamentos de resolução que aplicam Risco aceito ou Falso positivo a partir de uma resolução do Jira não são migrados. **Se você depende da sincronização reversa, mantenha a instância clássica do Jira configurada** — a migração não a remove.
* **Engagement Epic Mapping** — o conector não tem o conceito de epic.
* **Push Notes**, **comentários de notificação de SLA** e **comentários de expiração de aceitação de risco** — o conector não publica esses itens no Jira.
* Campos personalizados chamados `summary`, `description`, `project`, `issuetype` ou `status` — esses são reservados pelo conector, e um mapeamento de campo que use um deles é ignorado.
* Valores de campo personalizado com mais de 512 caracteres — são ignorados em vez de truncados.
* Um Projeto do Jira que não está vinculado a nenhum Produto nem Engajamento não gera nenhuma atribuição.

### O que acontece com a integração clássica depois

**Nada é enviado duas vezes.** Para cada projeto que migra, a migração desativa o projeto clássico do Jira, de modo que somente o conector envia a partir desse ponto. Você não precisa desabilitar nada manualmente.

Sua configuração clássica é **mantida, não excluída** — a instância, o projeto e os registros de issue permanecem todos, apenas com as configurações de envio desativadas. Isso é proposital: é o que torna a mudança reversível, e é o que mantém a sincronização reversa funcionando caso você dependa dela.

**Para reverter**, reative as configurações do projeto clássico do Jira e remova a configuração do conector criada pela migração. Não existe um desfazer com um clique.

**Executar novamente é seguro.** A migração registra o que já foi convertido e ignora isso em uma segunda execução, então nada é duplicado. Se um projeto ou instância falhar, o restante ainda é migrado — um projeto com falha é deixado em execução na integração clássica em vez de ser desativado, para que continue funcionando enquanto você investiga.

### Enquanto ela é executada

A migração é executada em segundo plano e reporta o progresso conforme avança. Quando termina, você recebe um resumo — quantos conectores, mapeamentos, atribuições, modelos e vínculos de ticket foram criados, quantos projetos clássicos foram desativados, e o que foi ignorado — junto com os avisos descritos acima. Apenas uma migração é executada por vez.

# Configurando o Jira

Configurar o Jira exige as seguintes etapas:
1. Habilite a integração do Jira em System Settings. Até que você faça isso, o restante das configurações do Jira fica oculto em todo o DefectDojo.
2. Conecte uma Instância do Jira, seja com um nome de usuário / senha ou com um token de API. Múltiplas instâncias podem ser vinculadas.
3. Adicione essa Instância do Jira a um ou mais Produtos ou Engajamentos dentro do DefectDojo.
4. Se desejar usar sincronização bidirecional, crie um Webhook do Jira que enviará atualizações ao DefectDojo.

## Etapa 1: Habilitar a integração do Jira em System Settings

A integração do Jira fica desativada por padrão, e enquanto estiver desativada o DefectDojo oculta todos os demais controles do Jira na interface. Isso é a primeira coisa a configurar: nenhuma das etapas abaixo fica disponível até que ela seja habilitada.

Enquanto a integração está desabilitada, não há uma entrada **Jira Instances** na barra lateral, então não há onde adicionar uma Instância do Jira:

![image](images/jira-menu-hidden-pro.png)

### Habilitar a integração

1. Navegue até **Settings \> System \> System Settings** a partir da barra lateral do DefectDojo. Em instâncias que ainda usam o layout de menu anterior, isso fica em um grupo nomeado de acordo com seu pacote de licença — **Pro Settings** ou **Enterprise Settings**. Veja [The Settings Menu](/navigation/pro__settings_menu/).
​
2. Na seção **Jira Integration Settings**, marque **Enable Jira Integration**.
​
3. Clique em **Submit**. **Jira Instances** aparece na barra lateral imediatamente, sem recarregar a página:

![image](images/jira-enable-system-settings-pro.png)

### O que a configuração controla

Habilitar **Enable Jira Integration** é o que faz o restante da interface do Jira aparecer. Com ela ativada, você obtém:

* o menu **Jira Instances**, onde as Instâncias do Jira são adicionadas e editadas
* a página **Jira Project Settings** no menu ⚙️ do Ativo, e as configurações do Jira nos Engajamentos
* as ações **Push to Jira** em Achados e Grupos de Achados, os campos do Jira nos formulários de Achado e edição em massa, e as colunas do Jira nas listas de Ativo, Engajamento, Achado e Grupo de Achados (incluindo exportações CSV)

A configuração também controla a integração fora da interface: enquanto estiver desativada, o DefectDojo não enviará Achados para o Jira (incluindo requisições `push_to_jira` enviadas pela API), e os webhooks recebidos do Jira são ignorados.

Os demais campos do Jira em **Jira Integration Settings** (**Add Vulnerability ID as Jira Label**, **Enable Jira Web Hook**, **Disable Jira Web Hook Secret**, **Jira Web Hook Secret**, **Jira Minimum Severity**) permanecem visíveis independentemente de a integração estar ativada ou desativada, mas não têm efeito até que ela seja habilitada.

## Etapa 2: Conectar uma Instância do Jira

Com a integração habilitada, conectar uma Instância do Jira é a próxima etapa na configuração da integração do Jira no DefectDojo. Observe que o Jira Service Management não é suportado atualmente.

#### Informações necessárias do Jira

A Atlassian usa formas diferentes de autenticação entre o Jira Cloud e o Jira Data Center.

para **Jira Cloud**, você precisará de:
* uma URL do Jira, ex.: https://yourcompany.atlassian.net/
* uma conta com permissões para criar e atualizar issues na sua instância do Jira. Isso pode ser:
    * Uma combinação padrão de **usuário / senha**
    * Uma combinação de **usuário / Token de API**

para **Jira Data Center (ou Server)**, você precisará de:
* uma URL do Jira, ex.: https://jira.yourcompany.com
* uma conta com permissões para criar e atualizar issues na sua instância do Jira. Isso pode ser:
    * Uma combinação padrão de **usuário / senha**
    * Uma combinação de **endereço de e-mail / Personal Access Token**

Opcionalmente, você pode mapear:
* Transições do Jira para acionar a Reabertura e o Fechamento de Achados
* Resoluções do Jira que podem aplicar os status de Risco aceito e Falso positivo aos Achados (opcional)

Múltiplos Espaços do Jira podem ser tratados por uma única conexão de Instância do Jira, desde que a conta / token do Jira usado pelo DefectDojo tenha permissão para criar Issues no Espaço do Jira associado.

### Adicionar uma Instância do Jira

1. Certifique-se de que **Enable Jira Integration** esteja marcado em System Settings, conforme descrito na [Etapa 1](#step-1-enable-the-jira-integration-in-system-settings). O menu **Jira Instances** não aparece na barra lateral até que isso ocorra.

2. Navegue até a página **Enterprise Settings \> Jira Instances \> + New Jira Instance** a partir da barra lateral do DefectDojo.

![image](images/jira-instance-beta.png)

3. Selecione um **Configuration Name** para essa Instância do Jira usar no DefectDojo. Esse nome é simplesmente um rótulo para a conexão da Instância no DefectDojo, e não precisa estar relacionado a nenhum dado do Jira.

4. Selecione a URL da instância do Jira da sua empresa \- provavelmente semelhante a `https://**yourcompany**.atlassian.net` se você estiver usando uma instalação do Jira Cloud.

5. Informe um método de autenticação apropriado nos campos Username / Password do Jira:
    * Para a **autenticação padrão de usuário / senha do Jira**, informe um Nome de Usuário do Jira e a Senha correspondente nesses campos.
    * Para autenticação com um **token de API do usuário (Jira Cloud)**, informe o Nome de Usuário com o **token de API** correspondente no campo de senha.
    * Para autenticação com um **Personal Access Token** do Jira (também conhecido como PAT, usado apenas no Jira Data Center e no Jira Server), informe o PAT no campo de senha. O Nome de Usuário não é usado para autenticação com um PAT do Jira, mas o campo ainda é obrigatório neste formulário, então você pode usar um valor de referência aqui para identificar seu PAT.

Observe que o usuário associado a essa conexão precisa ter permissão para criar Issues e acessar dados na sua instância do Jira.

6. Você precisará fornecer valores para um Epic Name ID, Re-open Transition ID e Close Transition ID. Esses valores podem ser alterados depois. Estando conectado ao Jira, você pode acessar esses valores a partir das seguintes URLs:
- **Epic Name ID**: visite `https://<YOUR JIRA URL>/rest/api/2/field` e procure por Epic Name. Copie o número em `number` e cole aqui. Se você não tiver um Epic Name ID associado ao seu Espaço no Jira (por usar um Espaço Gerenciado por Equipe, por exemplo), informe 0 nesse campo.
- **Re-open Transition ID**: visite `https://<YOUR JIRA URL>/rest/api/latest/issue/<ANY VALID ISSUE KEY>/transitions?expand-transitions.fields` para encontrar o ID da sua instância do Jira. Cole no campo Reopen Transition ID.
- **Close Transition ID**: Visite `https://<YOUR JIRA URL>/rest/api/latest/issue/<ANY VALID ISSUE KEY>/transitions?expand-transitions.fields` para encontrar o ID da sua instância do Jira. Cole no campo Close Transition ID.

7. Selecione o tipo de issue padrão que você deseja usar ao criar Issues no Jira. As opções são **Bug, Task, Story** e **Epic** (que são tipos de issue padrão do Jira), além de **Spike** e **Security**, que são tipos de issue personalizados. Se você tiver um Tipo de Issue diferente que deseja usar, entre em contato com [support@defectdojo.com](mailto:support@defectdojo.com) para obter assistência.

8. Selecione seu Modelo de Issue, que determinará a Descrição da Issue quando as Issues forem criadas no Jira.

Os dois tipos são:
- **Jira\_full**, que incluirá todas as informações do Achado nas Issues do Jira
- **Jira\_limited**, que incluirá uma quantidade menor de informações e metadados do Achado.

Se você deixar esse campo em branco, o padrão será **Jira\_full.** Se precisar de um tipo diferente de modelo, entre em contato com [support@defectdojo.com](mailto:support@defectdojo.com).

9. Se desejar, informe o nome de uma Resolução do Jira que alterará o status de um Achado para Aceito ou para Falso positivo (quando a Resolução for acionada na Issue).

O formulário pode ser enviado a partir daqui. Se desejar, você pode personalizar ainda mais sua integração do Jira em Optional Fields. Clicar nesse botão permitirá aplicar texto genérico às Issues do Jira ou alterar o mapeamento de Jira Severity Mappings.

## Etapa 3: Conectar um Produto ou Engajamento ao Jira

Cada Produto ou Engajamento no DefectDojo tem suas próprias configurações que determinam como os Achados são convertidos em Issues do JIRA. A partir daqui, você pode decidir o Espaço do Jira associado e definir o comportamento padrão para criação de Issues, Epics, Labels e outros metadados do JIRA.

### Adicionar o Jira a um Produto

Você pode encontrar essa página clicando no menu de Engrenagem em um Produto ⚙️ e abrindo a página **Jira Project Settings**.

![image](images/jira-project-settings.png)

#### Instância do Jira

Se você tiver múltiplas instâncias do Jira configuradas, para produtos ou equipes separados dentro da sua organização, você pode indicar em qual Espaço do Jira deseja que o DefectDojo crie Issues. Selecione um Espaço no menu suspenso.

Se esse menu não listar nenhuma instância do Jira, confirme que esses Espaços estão conectados na sua Configuração Global do Jira para o DefectDojo \- yourcompany.defectdojo.com/jira.

#### Chave do projeto

Essa é a chave do Espaço que você deseja usar com o DefectDojo. A Chave do Espaço para um determinado Espaço pode ser encontrada na URL. (Isso antes era chamado de **Jira Project Key**, mas a partir de setembro de 2025, isso agora é chamado no Jira de **Space Key**).

![image](images/Add_a_Connected_Jira_Project_to_a_Product_3.png)

#### Nome do tipo de issue Epic

O nome do tipo de issue Epic no Jira. O padrão é "Epic", mas pode ser alterado se sua instância do Jira usar um nome diferente.

#### Modelo de issue

Aqui você pode determinar quantos metadados do DefectDojo deseja enviar ao Jira. Selecione uma das duas opções:

* **jira\_full**: as Issues rastrearão todos os parâmetros do DefectDojo \- uma Descrição completa, CVE, Severidade, etc. Útil se você precisar de contexto completo do Achado no Jira (por exemplo, se alguém está trabalhando nessa Issue e não tem acesso ao DefectDojo).

Aqui está um exemplo de uma Issue **jira\_full**:
​
![image](images/Add_a_Connected_Jira_Project_to_a_Product_4.png)

* **Jira\_limited:** as Issues rastrearão apenas o link do DefectDojo, os links de Produto/Engajamento/Teste, os campos Reporter e Environment. Todos os outros campos são rastreados apenas no DefectDojo. Útil se você não precisar de contexto completo do Achado no Jira (por exemplo, se alguém está trabalhando nessa Issue e trabalha principalmente no DefectDojo, sem precisar do quadro completo também no JIRA).

​Aqui está um exemplo de uma Issue **jira\_limited**:

![image](images/Add_a_Connected_Jira_Project_to_a_Product_5.png)

#### Componente

Se você gerencia seu Espaço do Jira usando Componentes, pode atribuir aqui o Componente apropriado para o DefectDojo. Para atribuir mais de um Componente, informe uma lista separada por vírgulas (por exemplo, `Security, DevSecOps`); cada valor é enviado ao Jira como um componente separado.

#### Campos personalizados

Se você não precisar usar Campos Personalizados com issues do DefectDojo, pode deixar esse campo como 'null'.

No entanto, se as Configurações do seu Espaço do Jira **exigirem** que você use Campos Personalizados em novas Issues, você precisará codificar esses mapeamentos.

Observe que o DefectDojo não consegue enviar metadados específicos de uma Issue como Campos Personalizados, apenas um valor padrão. Essa seção só deve ser configurada se o seu Espaço do Jira **exigir que esses Campos Personalizados existam** em todas as Issues do seu Espaço.

Siga **[este guia](#custom-fields-in-jira)** para começar a trabalhar com Campos Personalizados.

#### Campos de transição de fechamento / reabertura

Alguns fluxos de trabalho do Jira **exigem** que determinados campos sejam definidos como parte de uma transição — por exemplo, um fluxo de trabalho que se recusa a fechar uma Issue a menos que um campo de Resolução e um campo de Justificativa sejam fornecidos na tela de fechamento. A configuração de Campos personalizados acima só se aplica quando uma Issue é *criada*, então ela não consegue atender a esses fluxos de trabalho.

Sem essas configurações, o DefectDojo envia transições de fechamento / reabertura sem nenhum campo. Um fluxo de trabalho que exige campos rejeitará essa transição, e o Achado e a Issue do Jira ficam dessincronizados: o Achado aparece como Mitigado no DefectDojo enquanto a Issue permanece aberta no Jira.

As configurações **Close Transition fields** e **Reopen Transition fields** aceitam um objeto JSON que é enviado como o payload `fields` da chamada de transição de fechamento / reabertura. Por exemplo, para fechar Issues com uma Resolução de *Won't Fix* mais um valor de justificativa:

```json
{
    "resolution": {"name": "Won't Fix"},
    "customfield_10200": "Risk accepted by security team #report-false-positive"
}
```

Deixe essas configurações como 'null' se o seu fluxo de trabalho do Jira não exigir campos nas transições.

**Quais campos você precisa?**

* Pergunte ao seu administrador do Jira quais campos estão nas **telas de transição** de fechamento / reabertura, e quais deles são exigidos por um validador. O JSON configurado precisa atender **todos** os campos obrigatórios: se algum campo obrigatório estiver ausente do payload, o Jira rejeita toda a transição e não define nada — fornecer apenas alguns dos campos obrigatórios não ajuda.
* Por outro lado, os campos precisam estar presentes **na tela de transição** para serem enviados: o Jira rejeita transições que tentam definir campos que não estão na tela dessa transição.
* Em fluxos de trabalho construídos com o editor de fluxo de trabalho atual do Jira Cloud, o Jira preenche automaticamente a Resolução padrão do site quando uma Issue passa para um status da categoria concluído. Assim, uma Resolução obrigatória sozinha não bloqueará uma transição simples nesse caso, e o uso prático de `"resolution"` neste payload é escolher um valor *significativo* (por exemplo, *False Positive*) em vez do padrão do site. Fluxos de trabalho construídos com o editor clássico, ou com aplicativos validadores do marketplace, ainda podem exigir a Resolução de forma obrigatória.
* As transições de reabertura tipicamente limpam a Resolução através do próprio fluxo de trabalho, então **Reopen Transition fields** geralmente só precisa dos campos personalizados que seu fluxo de trabalho exige.

**Observações:**

* O mesmo JSON é enviado para *toda* transição de fechamento (ou reabertura) do Produto ou Engajamento — os valores são estáticos e não variam por Achado. Se você precisar de campos diferentes por disposição (por exemplo, uma Resolução diferente para achados Falso positivo do que para achados corrigidos), use o DefectDojo Pro Jira Integrator, que suporta mapeamentos de campo de transição por status.
* Os valores usam o mesmo formato da API REST do Jira: strings para campos de texto, `{"name": ...}` para resoluções, `[{"name": ...}]` para campos de múltipla seleção, e assim por diante.
* Se as transições foram rejeitadas enquanto essas configurações estavam ausentes ou incompletas, corrigir as configurações repara a divergência: o próximo envio de status para o Achado tenta novamente a transição com os campos configurados.
* Ambas as configurações também estão disponíveis no endpoint REST `/api/v2/jira_projects/` (`close_transition_fields` / `reopen_transition_fields`), então podem ser gerenciadas via API.
* Esses campos também são aplicados quando o DefectDojo fecha uma Issue porque seu Achado foi **excluído** — os valores são capturados no momento em que o fechamento é enfileirado.

#### Labels do Jira

Selecione os labels relevantes com os quais você deseja que a Issue seja criada no Jira, ex.: **DefectDojo**, **YourProductName..**

![image](images/Add_a_Connected_Jira_Project_to_a_Product_6.png)

#### Responsável padrão

O nome do responsável padrão no Jira. Se deixado em branco, o DefectDojo seguirá o comportamento padrão do seu Espaço do Jira ao criar Issues.

### Jira Project Settings

#### Habilitado

Esse alternador controla se o DefectDojo envia Achados para o Jira nesse Produto. Desabilitar isso não excluirá nem alterará nenhum ticket do Jira existente criado pelo DefectDojo, mas impedirá quaisquer atualizações adicionais ou a criação de novas Issues.

As integrações do Jira só podem ser removidas da sua instância se nenhuma Issue relacionada tiver sido criada. Se Issues já foram criadas, não há como remover completamente uma Instância do Jira do DefectDojo.

#### Adicionar o Vulnerability Id como um label do Jira

Isso permite adicionar automaticamente os dados de Vulnerability ID como um Label do Jira. Os IDs de Vulnerabilidade são adicionados aos Achados por ferramentas de segurança individuais \- podem ser IDs de Common Vulnerabilities and Exposures (CVE) ou um formato diferente, específico da ferramenta que reporta o Achado.

#### Push All Issues

Se marcado, o DefectDojo enviará automaticamente todos os Achados Ativos e Verificados ao Jira como Issues. Se deixado desmarcado, todos os Achados precisarão ser enviados ao Jira manualmente (individualmente ou por envio em massa).

Quando essa configuração está habilitada, as Issues do Jira continuarão sincronizadas com o DefectDojo mesmo se o status do Achado mudar.

#### Habilitar Engagement Epic Mapping

No DefectDojo, os Engajamentos representam uma coleção de trabalho. Cada Engajamento contém um ou mais testes, que contêm um ou mais Achados que precisam ser mitigados. Os Epics no Jira funcionam de forma semelhante, e essa caixa de seleção permite enviar Engajamentos ao Jira como Epics.

* Um Engajamento no DefectDojo \- observe os três achados listados na parte inferior.
​
![image](images/Add_a_Connected_Jira_Project_to_a_Product_8.png)
* Como o mesmo Engajamento se torna um Epic quando enviado ao JIRA \- os Achados do Engajamento também são enviados, e residem dentro do Epic como Issues filhas.

![image](images/Add_a_Connected_Jira_Project_to_a_Product_9.png)

#### Push Notes

Se habilitado, os comentários do Jira serão exibidos no Achado associado no DefectDojo, em Notas, e vice-versa; Notas em Achados serão adicionadas à Issue do Jira associada como Comentários.

#### Enviar Notificações de SLA Como Comentários

Se habilitado, qualquer Issue que viole as regras de Acordo de Nível de Serviço do DefectDojo terá comentários adicionados na issue do Jira indicando isso. Esses comentários serão publicados diariamente até que a Issue seja resolvida.

Os Acordos de Nível de Serviço podem ser configurados em **Configuration \> SLA Configuration** no DefectDojo e atribuídos a cada Produto.

#### Enviar Notificações de Expiração de Aceitação de Risco Como Comentário

Se habilitado, qualquer Issue cuja Aceitação de Risco associada no DefectDojo expire terá um comentário adicionado na issue do Jira indicando isso. Esses comentários serão publicados diariamente até que a Issue seja resolvida.

### Configurações de Jira em Nível de Engajamento

Por padrão, os Engajamentos **herdam as configurações do Jira do seu Produto**. No entanto, você pode sobrepor as configurações do Jira para Engajamentos individuais.

Para acessar as configurações de Jira em nível de Engajamento, clique no menu de Engrenagem ⚙️ em um Engajamento e abra a página **Jira Project Settings**.

A partir daqui, você pode desmarcar **Inherit from Product** e fornecer valores específicos do Engajamento para: **Project Key**, **Issue Template, Custom Fields, Jira Labels, Default Assignee**, e outras configurações.

Observe que, uma vez que um Engajamento tenha seu próprio projeto do Jira atribuído, ele não pode mais herdar do Produto.

![image](images/Creating_Issues_in_Jira_5.png)

## Etapa 4: Configurar Sincronização Bidirecional: Webhook do Jira

A integração com o Jira permite sincronização bidirecional via webhook. O DefectDojo recebe notificações do Jira em um endereço exclusivo, o que permite que comentários do Jira sejam recebidos nos Achados, ou que Achados sejam resolvidos via Jira, dependendo da sua configuração.

### Localizando a URL do seu Webhook do Jira

Seu Webhook do Jira está localizado no formulário de Configurações do Sistema, em **Configurações de Integração do Jira**: **Configurações Corporativas \> Configurações do Sistema** na barra lateral.

Você também precisa marcar **Habilitar Webhook do Jira** na mesma página antes que o DefectDojo processe as notificações recebidas do Jira. Os webhooks recebidos são ignorados se essa caixa ou **Habilitar Integração com o Jira** (veja a [Etapa 1](#step-1-enable-the-jira-integration-in-system-settings)) estiver desmarcada.

![image](images/Configuring_the_Jira_DefectDojo_Webhook.png)

### Criando o Webhook do Jira

1. Acesse `**https:// \<YOUR JIRA URL\> /plugins/servlet/webhooks**`
2. Clique em 'Create a Webhook'.
3. No campo chamado 'URL', insira: `https:// \<**YOUR DOJO DOMAIN**\> /jira/webhook/ \<**YOUR GENERATED WEBHOOK SECRET**\>`. O Web Hook Secret está listado em Configurações de Integração do Jira, conforme mencionado acima.
4. Em 'Comments', habilite 'Created'. Em 'Issue', habilite 'Updated'.
5. Certifique-se de que sua instância do JIRA confia no certificado SSL usado pela sua instância do DefectDojo. Para o JIRA Cloud, o DefectDojo deve usar [um certificado SSL/TLS válido, assinado por uma autoridade certificadora globalmente confiável](https://developer.atlassian.com/cloud/jira/platform/deprecation-notice-registering-webhooks-with-non-secure-urls/)

Observe que você não precisa criar um Secret dentro do Jira para usar esse webhook. O Secret já está embutido na URL do DefectDojo, portanto basta adicionar a URL completa ao formulário de Webhook do Jira.

As requisições de webhook recebidas são autenticadas pelo secret contido nessa URL, portanto trate a URL completa como uma credencial e mantenha-a privada.

#### Testando o Webhook

Depois de ter uma ou mais Issues criadas a partir de Achados do DefectDojo, você pode testar o Webhook adicionando um Comentário a um desses Achados. O Comentário deve ser recebido pelo webhook do Jira como uma nota.

Se isso não funcionar corretamente, pode ser devido a um problema de firewall na sua instância do Jira bloqueando o Webhook.

* As Regras de Firewall do DefectDojo incluem uma caixa de seleção para o **Jira Cloud,** que precisa ser habilitada antes que o DefectDojo possa receber mensagens de Webhook do Jira.

### Alternativa: Usando o Jira Automation (Send web request)

Algumas instâncias do Jira não permitem webhooks de sistema em `/plugins/servlet/webhooks` — por exemplo, quando essa área de administração é restrita e somente regras do **Jira Automation** são permitidas. Nesse caso, você pode obter a mesma sincronização bidirecional usando a ação **Send web request** do Automation, que envia os dados para o mesmo endpoint de webhook do DefectDojo.

O endpoint de webhook do DefectDojo aceita qualquer `POST` HTTP com `Content-Type: application/json` e um secret válido no caminho da URL. Ele **não** exige que a requisição venha do mecanismo de webhook de sistema do Jira, portanto a ação "Send web request" do Automation funciona como uma alternativa direta.

#### Pré-requisitos

Aplicam-se os mesmos pré-requisitos do webhook de sistema:

* **Enable JIRA integration** e **Enable JIRA web hook** estão ambas marcadas na página ⚙️ **Configuration \> System Settings**.
* Um **Jira webhook secret** não vazio está definido nessa página. O secret pode conter apenas os caracteres `A-Z`, `a-z`, `0-9`, `_` e `-`.
* O Achado (ou Grupo de Achados) já está vinculado à issue do Jira. Se a issue não estiver vinculada a um Achado do DefectDojo, a requisição ainda é aceita (HTTP `200`), mas nenhuma ação é executada.

#### Como o DefectDojo processa a requisição

* O DefectDojo direciona o processamento com base em um campo `webhookEvent` de nível superior. Somente `"jira:issue_updated"` e `"comment_created"` são processados; qualquer outro valor é aceito e ignorado. O Automation **não** adiciona esse campo automaticamente, portanto você precisa incluí-lo você mesmo no corpo da requisição.
* Por isso, defina o **Body** da requisição como **Custom data** e forneça o JSON abaixo. As opções de body **Empty** e **Jira issue data** não incluem o campo `webhookEvent` obrigatório, portanto o DefectDojo as ignorará.
* O endpoint sempre retorna HTTP `200`, independentemente de uma atualização ter sido aplicada ou não. O sucesso ou a falha só ficam visíveis no corpo da resposta e nos logs do DefectDojo — um `200` no log de auditoria do Automation **não** confirma, por si só, que a atualização chegou a um Achado.

#### Rule 1 — Issue atualizada

Crie uma regra do Automation com:

* **Trigger:** *Issue transitioned* (ou outro trigger que seja disparado quando os campos que você sincroniza mudarem, por exemplo *Field value changed* em Status).
* **Action:** *Send web request*
  * **Web request URL:** `https://<YOUR DOJO DOMAIN>/jira/webhook/<YOUR WEBHOOK SECRET>`
  * **HTTP method:** `POST`
  * **Web request body:** *Custom data*
  * **Headers:** `Content-Type: application/json`
  * **Custom data:**

```json
{
  "webhookEvent": "jira:issue_updated",
  "issue": {
    "id": "{{issue.id}}",
    "fields": {
      "updated": "{{issue.updated}}",
      "resolution": null,
      "status": { "statusCategory": { "key": "{{issue.status.statusCategory.key}}" } },
      "assignee": { "name": "{{issue.assignee.accountId}}", "displayName": "{{issue.assignee.displayName}}" }
    }
  }
}
```

Restrições para atualizações de issue:

* `issue.id` deve ser o **ID numérico interno da issue no Jira** (`{{issue.id}}`), não a chave da issue (por exemplo, `PROJ-123`). O DefectDojo associa a atualização a um Achado por meio desse ID numérico.
* Os campos `resolution` e `updated` devem sempre estar presentes. `resolution` pode ser `null`, mas se qualquer um dos dois campos estiver ausente, a requisição é aceita (`200`) e silenciosamente não processada.
* A sincronização de status e a auto-mitigação são controladas por `status.statusCategory.key`, cujos valores no Jira são `new` (To Do), `indeterminate` (In Progress) e `done` (Done). Um Achado só é mitigado quando a issue é realmente fechada, e não apenas porque um valor de resolution está presente.

#### Rule 2 — Issue comentada

Crie uma segunda regra do Automation com:

* **Trigger:** *Issue commented*
* **Action:** *Send web request* — mesma URL, método, header e opção de body *Custom data* que na Rule 1, com este body:

```json
{
  "webhookEvent": "comment_created",
  "comment": {
    "self": "https://<your-jira-host>/rest/api/2/issue/{{issue.id}}/comment/{{comment.id}}",
    "body": "{{comment.body}}",
    "updateAuthor": { "name": "{{comment.author.accountId}}", "displayName": "{{comment.author.displayName}}" }
  }
}
```

Restrições para comentários:

* Tanto `body` quanto `updateAuthor` devem estar presentes.
* O DefectDojo deriva a issue de destino a partir da URL `comment.self` — especificamente o `<id>` no segmento `.../issue/<id>/comment/...` — portanto `{{issue.id}}` (o ID numérico) precisa aparecer ali.
* **Prevenção de loop:** se o autor do comentário corresponder à conta do Jira que o DefectDojo usa para postar seus próprios comentários, o DefectDojo ignora o comentário para evitar um loop de eco. Se você quiser que *todos* os comentários sejam ingeridos, execute a regra do Automation como um usuário do Jira **diferente** daquele configurado na instância do Jira do DefectDojo.

#### Uma observação sobre smart values

Os smart values mostrados acima (`{{issue.id}}`, `{{issue.status.statusCategory.key}}`, `{{comment.author.accountId}}`, e assim por diante) são os nomes padrão do Jira Cloud, mas podem variar entre instâncias. Antes de colocar em produção, use o payload preview do Automation para confirmar que cada smart value resolve para o valor esperado.

## Testando a integração com o Jira

#### Teste 1: os Achados são enviados corretamente para o Jira?

Para testar se a integração com o Jira está funcionando corretamente, você pode adicionar um novo Achado em branco ao Produto associado ao Jira no DefectDojo. **Product \> Findings \> Add New Finding.**

Adicione o título, a severidade e a descrição que desejar, e clique em "Finished". O Achado deve aparecer como uma Issue no Jira com todos os metadados relevantes.

Se as Issues do Jira não estiverem sendo criadas corretamente, verifique suas Notificações para códigos de erro.

* Confirme que o Usuário do Jira associado à Configuração do Jira do DefectDojo tem permissão para criar e atualizar issues naquele Jira Space específico.

#### Teste 2: os Webhooks do Jira enviam dados para o DefectDojo

Para testar os webhooks do Jira, adicione uma Nota a um Achado que também exista no JIRA como uma Issue (por exemplo, a issue de teste da seção acima).

Se os webhooks estiverem configurados corretamente, você deverá ver a Nota no Jira como um Comentário na issue.

Se isso não funcionar corretamente, pode ser devido a um problema de firewall na sua instância do Jira bloqueando o Webhook.

* As Regras de Firewall do DefectDojo incluem uma caixa de seleção para o **Jira Cloud,** que precisa ser habilitada antes que o DefectDojo possa receber mensagens de Webhook do Jira.

## Desconectando do Jira

As integrações com o Jira só podem ser removidas da sua instância se nenhuma Issue relacionada tiver sido criada.  Se Issues já tiverem sido criadas, não há como remover completamente uma instância do Jira do DefectDojo.

No entanto, você pode desabilitar sua integração com o Jira desabilitando-a no nível do Produto.  Na página **Jira Project Settings** (acessível pelo menu ⚙️ Engrenagem em um Produto), desmarque a opção **Enabled**.  Isso não excluirá nem alterará nenhum ticket do Jira já criado pelo DefectDojo, mas desabilitará futuras atualizações.

# Enviando Achados para o Jira

Um Produto com um mapeamento do JIRA pode enviar Achados para o Jira como Issues usando vários métodos.  Você pode enviar Achados individualmente, em massa, como Grupos de Achados, ou automaticamente.

## Enviar um Único Achado

1. Abra o Achado que deseja enviar.
2. Clique no **☰ Finding Menu** e selecione **Push to Jira**.
3. Confirme o envio quando solicitado. O DefectDojo criará uma Issue no Jira e a vinculará ao Achado.

Depois que a Issue for criada, o DefectDojo exibirá um link para a Issue do Jira na página do Achado.

![image](images/Creating_Issues_in_Jira_2.png)

Você também pode marcar a caixa de seleção **Push to Jira** ao editar um Achado pelo formulário **Edit Finding**. Quando o Achado for salvo, ele será enviado para o Jira.

### Atualizando uma Issue do Jira Vinculada

Se um Achado já tiver uma Issue do Jira vinculada, selecionar **Push to Jira** novamente atualizará a Issue existente no Jira com quaisquer alterações feitas no DefectDojo. Se **Push All Issues** estiver habilitado no Produto, essa sincronização acontece automaticamente.

### Desvinculando um Achado do Jira

Para remover a associação entre um Achado e sua Issue do Jira, clique no **☰ Finding Menu** e selecione **Unlink From Jira**. Isso remove o vínculo no DefectDojo, mas não exclui a Issue do Jira em si.

## Enviar Achados em Massa

Você pode enviar vários Achados para o Jira de uma vez usando o formulário **Bulk Update**:

1. Em uma lista de Achados, selecione os Achados que deseja enviar usando as caixas de seleção.
2. Abra o formulário **Bulk Update**.
3. Em **Jira Settings**, marque a caixa de seleção **Push to Jira**.
4. Clique em **Submit**.

Os Achados selecionados serão colocados na fila para envio ao Jira. O DefectDojo exibirá uma mensagem de confirmação indicando quantos Achados foram enfileirados.

## Enviar Engajamentos como Epics

Se **Enable Engagement Epic Mapping** estiver ativado nas **Jira Project Settings**, você pode enviar um Engajamento para o Jira como um Epic. Os Achados do Engajamento serão enviados como Issues filhas dentro desse Epic.

Para enviar um Engajamento como um Epic:

1. Abra o Engajamento que deseja enviar.
2. Clique no **☰ Engagement Menu** e selecione **Push to Jira**.
3. Opcionalmente, forneça um **Epic Name** (o padrão é o nome do Engajamento, se deixado em branco) e uma **Epic Priority**.
4. Marque **Push to Jira (Create Epic)** e envie o formulário.

## Enviar Grupos de Achados como Issues do Jira

Se você tiver Finding Groups habilitados, pode enviar um Grupo de Achados para o Jira como uma única Issue, em vez de Issues separadas para cada Achado.

Para enviar um Grupo de Achados:

1. Abra o Finding Group.
2. Clique no **☰ Finding Group Menu** e selecione **Push to Jira**, ou marque a caixa de seleção **Push to Jira** ao editar o Finding Group.

A Issue do Jira associada a um Grupo de Achados deve ser excluída diretamente na instância do Jira, caso a remoção seja necessária.

### Criar e Enviar Grupos de Achados Automaticamente

Com **Push All Issues** habilitado no Produto, e uma opção de **Group By** selecionada na importação:

Desde que os Finding Groups sejam criados com sucesso, é o Grupo de Achados que será enviado automaticamente para o Jira como uma Issue, e não os Achados individuais.

![image](images/Creating_Issues_in_Jira_4.png)

## Comportamento de Envio Automático

O DefectDojo pode enviar Achados e atualizações automaticamente para o Jira em vários cenários:

### Push All Issues

Quando a configuração **Push All Issues** está habilitada nas Jira Project Settings de um Produto, o DefectDojo criará automaticamente Issues no Jira para todos os Achados Ativos e Verificados. Isso inclui Achados criados por importação de scan. Depois que uma Issue do Jira é criada, ela continuará sincronizada com o DefectDojo mesmo que o status do Achado mude.

### Auto-Sincronização em Mudanças de Status

Quando **Push All Issues** ou a configuração de nível de sistema **Finding Jira Sync** está habilitada, o DefectDojo atualizará automaticamente as Issues do Jira vinculadas quando determinadas ações forem realizadas nos Achados:

* **Request Review** \- Um comentário é adicionado à Issue do Jira vinculada (ou à Issue do Jira do Finding Group, se o Achado pertencer a um grupo).
* **Clear Review** \- Um comentário é adicionado à Issue do Jira vinculada.
* **Close Finding** \- A Issue do Jira vinculada é atualizada para refletir o fechamento. Se **Push Notes** estiver habilitado, um comentário também é adicionado.

## Comentários e Notas do Jira

Quando **Push Notes** está habilitado nas Jira Project Settings:

* Se um comentário for adicionado a uma Issue do Jira, o mesmo comentário será adicionado ao Achado, na seção **Notes**.
* Da mesma forma, se uma Nota for adicionada a um Achado, a Nota será adicionada à issue do Jira como um comentário.

## Mudanças de Status no Jira

A configuração da Jira Instance tem entradas para duas Jira Transitions que acionarão uma mudança de status em um Achado.

* Quando a **'Close' Transition** é executada no Jira, o Achado associado também será fechado, e ficará marcado como **Inactive** e **Mitigated** no DefectDojo. O DefectDojo registrará essa mudança na página do Achado, no campo **Mitigated By**.
​
![image](images/Creating_Issues_in_Jira_3.png)

* Quando a **'Reopen' Transition** é executada na Issue do Jira, o Achado associado será definido como **Active** no DefectDojo, e perderá seu status de **Mitigated**.

## Mapeando Resoluções do Jira para Aceitação de Risco / Falso Positivo

A configuração da Jira Instance inclui dois campos opcionais que permitem mapear uma **Resolution** do Jira para um status de Achado no DefectDojo:

* **Risk Accepted Finding Mapping Resolution** — quando uma issue do Jira é fechada com essa Resolution, o Achado vinculado se torna Risco Aceito no DefectDojo.
* **False Positive Finding Mapping Resolution** — quando uma issue do Jira é fechada com essa Resolution, o Achado vinculado se torna Falso Positivo no DefectDojo.

### Status vs Resolution: um Ponto Comum de Confusão

Esses campos mapeiam a **Resolution** do Jira, não o **Status** do Jira.  Status e Resolution são dois conceitos independentes no Jira: Status descreve em que ponto do fluxo de trabalho a issue está (Open, In Progress, Done), enquanto Resolution descreve como ela foi resolvida (Fixed, Won't Do, Duplicate, False Positive, etc.).

### Pré-requisito: uma pós-função "Set issue resolution" na transição do fluxo de trabalho do Jira

O motor de fluxo de trabalho do Jira não preenche o campo Resolution automaticamente.  Cada transição que deve fechar uma issue com uma Resolution específica precisa de uma pós-função **Set issue resolution** configurada na própria transição.  Sem essa pós-função, a issue passa para o novo Status, mas a Resolution permanece em branco, e o mapeamento do DefectDojo não tem com o que fazer a correspondência.

Um administrador do Jira pode adicionar essa pós-função em **Project Settings → Workflows → (edit workflow) → (selecione a transição de fechamento) → Post Functions → Add post function → Set issue resolution**.

# Custom Fields no Jira

<span style="background: rgba(243, 122, 78,0.5">Atualmente, o DefectDojo não oferece suporte para passar informações específicas de uma Issue para esses Custom Fields \- esses campos precisarão ser atualizados manualmente no Jira depois que a issue for criada. Cada Custom Field só será criado a partir do DefectDojo com um valor padrão.</span>

<span style="background: rgba(0, 207, 83, 0.44)"> O Jira Cloud agora permite criar um valor padrão de Custom Field diretamente no aplicativo. [Consulte a documentação da Atlassian sobre Custom Fields](https://support.atlassian.com/jira-cloud-administration/docs/configure-a-custom-field/) para mais informações sobre como configurar isso.</span>

Os Jira Issue Types integrados ao DefectDojo (**Bug, Task, Story** e **Epic)** são configurados para funcionar 'prontos para uso'. Os campos de dados no DefectDojo serão mapeados automaticamente para os campos correspondentes no Jira. Por padrão, o DefectDojo atribuirá Priority, Labels e um Reporter a qualquer nova Issue que criar.

Algumas configurações do Jira exigem que campos personalizados adicionais sejam levados em conta antes que uma issue possa ser criada. Este processo permitirá que você contemple esses custom fields na sua integração DefectDojo \-\> Jira, garantindo que as issues sejam criadas com sucesso. Esses custom fields serão adicionados a todas as chamadas de API enviadas do DefectDojo para uma instância do Jira vinculada.

Se você ainda não usa Custom Fields no Jira, não há necessidade de seguir este processo.

1. Registrar os nomes dos seus Custom Fields no Jira (**Jira UI**)
2. Determinar os valores de Key para os novos Custom Fields (Jira Field Spec Endpoint)
3. Localizar os dados aceitáveis para cada Custom Field, usando os valores de Key como referência (Jira Issue Endpoint)
4. Criar um bloco JSON de referência de campos para rastrear todas as Keys dos Custom Fields e os dados aceitáveis (Jira Issue Endpoint)
5. Armazenar o bloco JSON no Product do DefectDojo associado, para permitir que os Custom Fields sejam criados a partir do Jira (DefectDojo UI)
6. Testar seu trabalho e garantir que todos os dados obrigatórios estejam fluindo corretamente a partir do Jira

#### Etapa 1: Registre os nomes dos seus Custom Fields no Jira

O Jira oferece suporte a uma variedade de Context Fields diferentes, incluindo Date Pickers, Custom Labels, Radio Buttons. Cada um desses Context Fields terá um valor de Key diferente, que pode ser encontrado na API do Jira.

Anote os nomes de cada Custom Field necessário, pois você precisará pesquisar na API do Jira para encontrá-los na próxima etapa.

**Exemplo de uma lista de Custom Fields (os nomes dos seus Custom Fields serão diferentes):**

* DefectDojo Custom URL Field
* Outro exemplo de Custom Field
* ...

#### Etapa 2: Encontrando os Valores de Key dos seus Jira Custom Fields

Comece este processo navegando até a URL de Field Spec da sua instância inteira do Jira.

Aqui está um exemplo de uma URL de Field Spec:

`https://yourcompany-example.atlassian.net/rest/api/2/field`

A API retornará uma longa string de JSON, que deve ser formatada em texto legível (usando um editor de código, uma extensão de navegador ou <https://jsonformatter.org/>).

O JSON retornado por essa URL conterá todos os seus custom fields do Jira, a maioria dos quais é irrelevante para o DefectDojo e tem valores `"Null"`. Cada objeto nessa resposta da API corresponde a um campo diferente no Jira. Você precisará procurar os objetos cujos atributos `"name"` correspondam aos nomes de cada Custom Field que você criou na Jira UI, e então anotar o valor do atributo "key" deles.

![image](images/Using_Custom_Fields.png)

Depois de encontrar o objeto correspondente na saída JSON, você pode determinar o valor de "key" \- neste caso, é `customfield_10050`.

O Jira gera valores de key diferentes para cada Custom Field, mas esses valores de key não mudam depois de criados. Se você criar outro Custom Field no futuro, ele terá um novo valor de key.

**Expandindo nossa lista de Custom Fields:**

* "DefectDojo Custom URL Field" \= customfield\_10050
* "Outro exemplo de Custom Field" \= customfield\_12345
* ...

#### Etapa 3 \- Encontrando os Custom Fields em uma Jira Issue

Localize uma Issue no Jira que contenha os Custom Fields que você registrou na Etapa 2\. Copie a Issue Key do título (deve se parecer com "`EXAMPLE-123`") e navegue até a seguinte URL:

`https://yourcompany-example.atlassian.net/rest/api/2/issue/EXAMPLE-123`

Isso retornará outra string de JSON.

Como antes, a saída da API conterá muitos parâmetros de objeto `customfield_##` com valores `null` \- esses são custom fields que o Jira adiciona por padrão, que não são relevantes para essa issue. Ela também conterá valores `customfield_##` que correspondem aos valores de Key dos Custom Fields que você encontrou na etapa anterior. Diferente da saída do Field Spec, você não verá nomes identificando nenhum desses custom fields, e é por isso que você precisou registrar os valores de key na Etapa 2\.

![image](images/Using_Custom_Fields_2.png)

**Exemplo:**
Sabemos que `customfield_10050` representa o DefectDojo Custom URL Field porque o registramos na Etapa 2\. Agora podemos ver que `customfield_10050` contém o valor `"https://google.com"` na issue `EXAMPLE-123`.

#### Etapa 4 \- Criando uma Referência de Campos JSON a partir de cada Jira Custom Field Key

Agora você precisará pegar o valor de cada um dos Custom Fields da sua lista e armazená-los em um objeto JSON (para usar como referência). Você pode ignorar quaisquer Custom Fields que não correspondam à sua lista.

Esse objeto JSON conterá todos os valores padrão para novas Issues do Jira. Recomendamos usar nomes que sejam fáceis para sua equipe reconhecer como valores 'padrão' que precisam ser alterados: '`change-me.com`', '`Change this paragraph.`' etc.

**Exemplo:**

Da etapa 3, agora sabemos que o Jira espera uma string de URL para "`customfield_10050`". Podemos usar isso para construir nosso objeto JSON de exemplo.

Digamos que também tivéssemos localizado um campo de texto curto relacionado ao DefectDojo, que identificamos como "`customfield_67890`". Nós observaríamos esse campo na nossa segunda saída de API, veríamos o valor associado, e referenciaríamos o valor armazenado no nosso objeto JSON de exemplo também.
​
Seu objeto JSON começará a ficar assim, à medida que você adiciona mais Custom Fields a ele.

```
{
	"customfield_10050": "https://change-me.com",
	"customfield_67890": "This is the short text custom field."
}
```

Repita esse processo até que todos os custom fields relevantes do DefectDojo no Jira tenham sido adicionados à sua Referência de Campos JSON.

#### Tipos de Dados e Sintaxe do Jira

Alguns campos, como campos de Date, podem estar relacionados a múltiplos custom fields no Jira. Se for esse o caso, você precisará adicionar ambos os campos à sua Referência de Campos JSON.

```
  "customfield_10040": "1970-01-01",
  "customfield_10041": "1970-01-01T03:30:00.000+0200",
```

Outros campos, como o campo Label, podem ser rastreados como uma lista de strings \- certifique-se de que sua Referência de Campos JSON use um formato que corresponda à saída da API do Jira.

```
// a list of custom labels on a Jira object
  "customfield_10042": [
    "custom-label-one",
    "this-is-default",
    "change-me-please"
  ],
```

Outros custom fields podem conter informações contextuais adicionais que devem ser removidas da Referência de Campos. Por exemplo, o Custom Multichoice Field contém um bloco extra na saída da API, que você precisará remover, pois esse bloco armazena o valor atual do campo.

* você deve remover o objeto extra deste campo:

```
"customfield_10047": [
    {
      "value": "A"
    },
    {
      "self": "example.url...",
      "value": "C",
      "id": "example ID"
    }
]
```
* em vez disso, você pode reduzir isso para o seguinte e desconsiderar a segunda parte:

```
"customfield_10047": [
   {
      "value": "A"
   }
]
```

#### Exemplo de Referência de Campos Completa

Aqui está uma Referência de Campos JSON completa, com comentários inline explicando a que cada custom field se refere. Isso serve como um exemplo abrangente. Seu JSON conterá valores de key e dados diferentes, dependendo dos Custom Values que você deseja usar durante a criação da issue.

```
{
  "customfield_10050": "https://change-me.com",

  "customfield_10049": "This is a short text custom field",

// two different fields, but both correspond to the same custom date attribute
  "customfield_10040": "1970-01-01",
  "customfield_10041": "1970-01-01T03:30:00.000+0200",

// a list of custom labels on a Jira object
  "customfield_10042": [
    "custom-label-one",
    "this-is-default",
    "change-me-please"
  ],

// custom number field
  "customfield_10043": 0,

// custom paragraph field
  "customfield_10044": "This is a very long winded way to say CHANGE ME PLEASE",

// custom radio button field
  "customfield_10045": {
    "value": "radio button option"
  },

// custom multichoice field
  "customfield_10047": [
    {
      "value": "A"
    }
  ],

// custom checkbox field
  "customfield_10039": [
    {
      "value": "A"
    }
  ],

// custom select list (singlechoice) field
  "customfield_10048": {
    "value": "1"
  }
}
```

#### Etapa 5 \- Adicionando os Custom Fields a um Product do DefectDojo

Agora você pode adicionar esses custom fields ao Product associado no DefectDojo, na página Jira Project Settings (acessível pelo menu ⚙️ Engrenagem no Product). Cole a Referência de Campos JSON como texto simples na caixa **Custom Fields** e salve.

#### Etapa 6 \- Testando seus Jira Custom Fields a partir de um novo Achado:

Agora, quando você criar um novo Achado no Product associado ao Jira, o Jira criará automaticamente todos esses Custom Fields de acordo com o bloco JSON contido nele. Esses Custom Fields serão criados com os valores padrão ("change\-me\-please", etc.).

Dentro do Product no DefectDojo, navegue até a página Findings \> Add New Finding. Certifique-se de que o Achado esteja Active e Verified para garantir que ele seja enviado ao Jira, e então confirme, no lado do Jira, que os Custom Fields foram criados com sucesso, sem inconsistências.
