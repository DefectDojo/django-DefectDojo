---
title: Jira
description: Trabalhe com a integração do Jira
weight: 2
audience: opensource
aliases:
- /pt-br/issue_tracking/jira/os__jira_guide/
---

A integração do DefectDojo com o Jira pode ser usada para enviar dados de Achados para um ou mais Espaços do Jira. Ao fazer isso, você pode integrar o DefectDojo ao seu fluxo de trabalho de desenvolvimento padrão. Veja alguns exemplos de como isso pode funcionar:

* A equipe de AppSec pode enviar Achados seletivamente para um Espaço do Jira usado pelos desenvolvedores, para que a remediação dos problemas possa ser priorizada de forma adequada junto com o desenvolvimento normal. Os desenvolvedores nesse board não precisam acessar o DefectDojo - eles podem manter todo o seu trabalho em um só lugar.
* O DefectDojo pode enviar TODOS os Achados para um Espaço do Jira bidirecional usado pela equipe de AppSec, o que permite dividir a validação dos problemas. Esse board permanece sincronizado com o DefectDojo e permite fluxos de trabalho de remediação complexos.
* O DefectDojo pode enviar Achados seletivamente de Produtos e/ou Engajamentos separados para Espaços do Jira separados, para manter tudo em seu devido contexto.

# Configurando o Jira

Configurar o Jira exige as seguintes etapas:
1. Habilite a integração do Jira em Configurações do Sistema. Até que isso seja feito, o restante das configurações do Jira fica oculto em todo o DefectDojo.
2. Conecte uma Instância do Jira, seja com um nome de usuário/senha ou com um token de API. É possível vincular várias instâncias.
3. Adicione essa Instância do Jira a um ou mais Produtos ou Engajamentos dentro do DefectDojo.
4. Se quiser usar sincronização bidirecional, crie um Webhook do Jira que enviará atualizações para o DefectDojo.

## Etapa 1: Habilite a integração do Jira em Configurações do Sistema

A integração do Jira vem desativada por padrão e, enquanto estiver desativada, o DefectDojo oculta todos os outros controles do Jira na interface. Essa é a primeira coisa a configurar: nenhuma das etapas abaixo fica disponível até que ela seja habilitada.

Enquanto a integração estiver desativada, a entrada ⚙️ **Configuration \> JIRA** não aparece na barra lateral, portanto não há onde adicionar uma Instância do Jira:

![image](images/jira-config-menu-hidden-os.png)

### Habilite a integração

1. Navegue até ⚙️ **Configuration \> System Settings** na barra lateral do DefectDojo.
​
2. Marque **Enable JIRA integration**.
​
3. Um **Jira webhook secret** é exigido assim que a integração é habilitada. Clique no ícone 🔄 ao lado do campo para gerar um. Se você enviar o formulário sem um secret, o formulário será rejeitado com *"This field is required when enable Jira Integration is True"*:

![image](images/jira-webhook-secret-required-os.png)

O secret faz parte da URL do webhook para a qual o Jira envia solicitações (`https://<YOUR DOJO DOMAIN>/jira/webhook/<SECRET>`), portanto trate o valor gerado como uma credencial. Você só precisa fornecê-lo ao Jira se configurar a sincronização bidirecional na [Etapa 4](#step-4-configure-bidirectional-sync-jira-webhook); gerá-lo agora apenas satisfaz o formulário.

4. Clique em **Submit**. ⚙️ **Configuration \> JIRA** agora aparece na barra lateral:

![image](images/jira-enable-system-settings-os.png)

### O que essa configuração controla

Habilitar **Enable JIRA integration** é o que faz o restante da interface do Jira aparecer. Com ela ativada, você tem acesso a:

* a página ⚙️ **Configuration \> JIRA**, onde as Instâncias do Jira são adicionadas e editadas
* a seção **JIRA** nos formulários Edit Product (Asset) e Edit Engagement, usada para vincular um Produto ou Engajamento a um Espaço do Jira
* os controles **Push to Jira** em Achados, Grupos de Achados e formulários de edição em massa, além das colunas e filtros do Jira nas listas de Achados, Engajamentos e Produtos

Por exemplo, a seção **JIRA** só aparece na parte inferior do formulário Edit Product depois que a integração é habilitada:

![image](images/jira-asset-settings-visible-os.png)

Essa configuração também controla a integração fora da interface: enquanto estiver desativada, o DefectDojo não enviará Achados para o Jira (incluindo solicitações `push_to_jira` enviadas pela API), e os webhooks recebidos do Jira são ignorados.

Os demais campos do Jira na página System Settings (**Enable JIRA web hook**, **Jira minimum severity**, **Jira labels**, **Add vulnerability Id as a JIRA label**) permanecem visíveis esteja a integração ativada ou não, mas não têm efeito até que ela seja habilitada.

## Etapa 2: Conecte uma Instância do Jira

Com a integração habilitada, conectar uma Instância do Jira é a próxima etapa na configuração da integração do DefectDojo com o Jira. Observe que o Jira Service Management não é compatível no momento.

#### Informações necessárias do Jira

A Atlassian usa métodos de autenticação diferentes entre o Jira Cloud e o Jira Data Center.

para o **Jira Cloud**, você precisará de:
* uma URL do Jira, por exemplo, https://yourcompany.atlassian.net/
* uma conta com permissões para criar e atualizar issues na sua instância do Jira. Isso pode ser:
    * Uma combinação padrão de **username / password**
    * Uma combinação de **username / API Token**

para o **Jira Data Center (ou Server)**, você precisará de:
* uma URL do Jira, por exemplo, https://jira.yourcompany.com
* uma conta com permissões para criar e atualizar issues na sua instância do Jira. Isso pode ser:
    * Uma combinação padrão de **username / password**

Opcionalmente, você pode mapear:
* Transitions do Jira para acionar a Reabertura e o Fechamento de Achados
* Resolutions do Jira que podem aplicar os status Risco aceito e Falso positivo aos Achados (opcional)

Vários Espaços do Jira podem ser gerenciados por uma única conexão de Instância do Jira, desde que a conta/token do Jira usado pelo DefectDojo tenha permissão para criar Issues no Espaço do Jira associado.

### Adicione uma Instância do Jira

1. Certifique-se de que **Enable JIRA integration** esteja marcada em System Settings, conforme descrito na [Etapa 1](#step-1-enable-the-jira-integration-in-system-settings). A opção ⚙️ **Configuration \> JIRA** não aparece na barra lateral até que isso ocorra.
​
2. Navegue até a página ⚙️ **Configuration \> JIRA** na barra lateral do DefectDojo.
​
![image](images/Connect_DefectDojo_to_Jira.png)

3. Você verá uma lista de todos os Espaços do Jira atualmente configurados que estão vinculados ao DefectDojo. Para adicionar uma nova Project Configuration, clique no ícone de chave inglesa e escolha as opções **Add Jira Configuration (Express)** ou **Add Jira Configuration**.

#### Add Jira Configuration (Express)

O método Express permite uma forma mais rápida de vincular um Espaço. Use o método Express se você quiser simplesmente conectar um Espaço do Jira rapidamente, sem lidar com um fluxo de trabalho complexo do Jira.

![image](images/Connect_DefectDojo_to_Jira_2.png)

1. Selecione um nome para essa Jira Configuration a ser usado no DefectDojo. Esse nome é apenas um rótulo para a conexão da Instância no DefectDojo e não precisa estar relacionado a nenhum dado do Jira.
​
2. Selecione a URL da instância do Jira da sua empresa \- provavelmente semelhante a `https://**yourcompany**.atlassian.net` se você estiver usando uma instalação do Jira Cloud.
​
3. Insira um método de autenticação apropriado nos campos Username / Password do Jira:
    * Para a autenticação padrão **username / password Jira authentication**, insira um Username do Jira e a Password correspondente nesses campos.
    * Para autenticação com um **user's API token (Jira Cloud)**, insira o Username com o **API token** correspondente no campo de senha.
​
4. Selecione o Default issue type com o qual você deseja criar as Issues no Jira. As opções são **Bug, Task, Story** e **Epic** (que são tipos padrão de issue do Jira), além de **Spike** e **Security**, que são tipos de issue personalizados. Se você tiver um Issue Type diferente que deseja usar, entre em contato com [support@defectdojo.com](mailto:support@defectdojo.com) para obter ajuda.
​
5. Selecione seu Issue Template, que determinará a Issue Description quando as Issues forem criadas no Jira.

Os dois tipos são:
- **Jira\_full**, que incluirá todas as informações do Achado nas Issues do Jira
- **Jira\_limited**, que incluirá uma quantidade menor de informações e metadados do Achado.

Se você deixar esse campo em branco, o padrão será **Jira\_full.**

6. Selecione um ou mais tipos de Jira Resolution que mudarão o status de um Achado para Accepted (quando a Resolution for acionada na Issue). Se você não quiser usar essa automação, pode deixar o campo em branco.
​
7. Selecione um ou mais tipos de Jira Resolution que mudarão o status de um Achado para Falso positivo (quando a Resolution for acionada na Issue). Se você não quiser usar essa automação, pode deixar o campo em branco.
​
8. Decida se deseja enviar SLA Notifications como um comentário em uma issue do Jira.
​
9. Decida se deseja sincronizar automaticamente os Achados com o Jira. Se isso estiver habilitado, as Issues do Jira serão mantidas automaticamente em sincronia com os Achados relacionados. Se não estiver habilitado, você precisará enviar manualmente qualquer alteração feita em um Achado depois que a Issue tiver sido criada no Jira.
​
10. Selecione sua Issue key. No Jira, essa é a string associada a uma Issue (por exemplo, a palavra **'EXAMPLE'** em uma issue chamada **EXAMPLE\-123**). Se você não souber sua issue key, crie uma nova Issue no Espaço do Jira. Na captura de tela abaixo, podemos ver que a issue key do nosso Espaço do Jira é **DEF**.
​
![image](images/Connect_DefectDojo_to_Jira_3.png)
​
11. Clique em **Submit.** O DefectDojo procurará automaticamente os mapeamentos apropriados no Jira e os adicionará à configuração. Agora você está pronto para vincular essa configuração a um ou mais Produtos no DefectDojo.

#### Add Jira Configuration (Standard)

A Standard Jira Configuration adiciona algumas etapas extras para permitir um controle mais preciso sobre os mapeamentos e as interações do Jira. Isso pode ser alterado depois que uma configuração do Jira tiver sido adicionada, mesmo que ela tenha sido criada usando o método Express.
​
### Opções adicionais do formulário

* **Epic Name ID:** Se você tiver vários tipos de Epic no Jira, pode especificar o que deseja usar encontrando seu ID na Jira Field Spec.
​
Para obter o 'Epic name id', acesse `https://<YOUR JIRA URL>/rest/api/2/field` e procure por Epic Name. Copie o número de dentro de `number` e cole aqui.
​  ​
* **Reopen Transition ID:** Se você quiser uma Transition específica do Jira para Reabrir uma issue, pode especificar o Transition ID aqui. Se estiver usando a Express Jira Configuration, o DefectDojo encontrará automaticamente uma Transition apropriada e criará o mapeamento.
​
Acesse `https://<YOUR JIRA URL>/rest/api/latest/issue/<ANY VALID ISSUE KEY>/transitions?expand-transitions.fields` para encontrar o ID da sua instância do Jira. Cole-o no campo Reopen Transition ID.
​
* **Close Transition ID:** Se você quiser uma Transition específica do Jira para Fechar uma issue, pode especificar o Transition ID aqui. Se estiver usando a **Express Jira Configuration**, o DefectDojo encontrará automaticamente uma Transition apropriada e criará o mapeamento.
​
Acesse `https://<YOUR JIRA URL>/rest/api/latest/issue/<ANY VALID ISSUE KEY>/transitions?expand-transitions.fields` para encontrar o ID da sua instância do Jira. Cole-o no campo Close Transition ID.
​
* **Mapping Severity Fields:** Cada Issue do Jira tem uma Priority associada, que o DefectDojo atribuirá automaticamente com base na Severidade de um Achado. Insira os nomes de cada Priority para a qual você deseja mapear as Severidades Informativa, Baixo, Médio, Alto e Crítica.

* **Finding Text** \- se você quiser adicionar um texto padronizado extra a cada Issue criada, pode inserir esse texto aqui. Não é um texto que é mapeado para nenhum campo no Jira, mas sim um texto adicional que é incluído na Issue Description. Por exemplo, "**Created by DefectDojo**".

Comments (no Jira) e Notas (no DefectDojo) podem ser mantidos em sincronia. Essa configuração pode ser habilitada depois que a configuração do Jira tiver sido adicionada a um Produto, por meio do formulário **Edit Product**.

## Etapa 3: Conecte um Produto ou Engajamento ao Jira

Cada Produto ou Engajamento no DefectDojo tem suas próprias configurações que determinam como os Achados são convertidos em Issues do JIRA. A partir daqui, você pode decidir o Espaço do Jira associado e definir o comportamento padrão para a criação de Issues, Epics, Labels e outros metadados do JIRA.

### Adicione o Jira a um Produto ou Engajamento

Na Classic UI, você encontra as configurações do Jira abrindo o formulário Edit Product ou Edit Engagement. Botão "**📝 Edit**" em **Settings** na página:

![image](images/Add_a_Connected_Jira_Project_to_a_Product.png)

#### Lista de configurações do Jira

As configurações do Jira ficam perto da parte inferior da página Product Settings.

![image](images/Add_a_Connected_Jira_Project_to_a_Product_2.png)

#### Jira Instance

Se você tiver várias instâncias do Jira configuradas, para produtos ou equipes separados dentro da sua organização, pode indicar em qual Espaço do Jira deseja que o DefectDojo crie as Issues. Selecione um Project no menu suspenso.

Se esse menu não listar nenhuma instância do Jira, confirme se esses Projects estão conectados na sua Jira Configuration global do DefectDojo \- yourcompany.defectdojo.com/jira.

#### Project key

Essa é a chave do Espaço que você deseja usar com o DefectDojo. A Space Key de um determinado project pode ser encontrada na URL, ou em "Space key", listada em Space Settings.

![image](images/Add_a_Connected_Jira_Project_to_a_Product_3.png)

#### Issue template

Aqui você pode determinar quanto de metadados do DefectDojo deseja enviar para o Jira. Selecione uma das duas opções:

* **jira\_full**: as Issues rastrearão todos os parâmetros do DefectDojo \- uma Description completa, CVE, Severidade, etc. Útil se você precisar do contexto completo do Achado no Jira (por exemplo, se alguém sem acesso ao DefectDojo estiver trabalhando nessa Issue).

Aqui está um exemplo de uma Issue **jira\_full**:
​
![image](images/Add_a_Connected_Jira_Project_to_a_Product_4.png)

* **Jira\_limited:** as Issues rastrearão apenas o link do DefectDojo, os links de Product/Engagement/Test, e os campos Reporter e Environment. Todos os outros campos são rastreados apenas no DefectDojo. Útil se você não precisar do contexto completo do Achado no Jira (por exemplo, se alguém que trabalha principalmente no DefectDojo estiver na Issue e não precisar do panorama completo também no JIRA.)

​Aqui está um exemplo de uma Issue **jira\_limited**:​

![image](images/Add_a_Connected_Jira_Project_to_a_Product_5.png)

#### Component

Se você gerenciar seu Espaço do Jira usando Components, pode atribuir o Component apropriado para o DefectDojo aqui. Para atribuir mais de um Component, insira uma lista separada por vírgulas (por exemplo, `Security, DevSecOps`); cada valor é enviado ao Jira como um component separado.

**Custom fields**

Se você não precisar usar Custom Fields com as issues do DefectDojo, pode deixar esse campo como 'null'.

No entanto, se as Jira Space Settings **exigirem** o uso de Custom Fields em novas Issues, você precisará codificar (hard\-code) esses mapeamentos.

**Agora o Jira Cloud permite que você crie um valor padrão de Custom Field diretamente no aplicativo. [Consulte a documentação da Atlassian sobre Custom Fields](https://support.atlassian.com/jira-cloud-administration/docs/configure-a-custom-field/) para mais informações sobre como configurar isso.**

Observe que o DefectDojo não pode enviar nenhum metadado específico da Issue como Custom Fields, apenas um valor padrão. Essa seção só deve ser configurada se o seu Espaço do Jira **exigir que esses Custom Fields existam** em todas as Issues do seu Espaço.

Siga **[este guia](#custom-fields-in-jira)** para começar a trabalhar com Custom Fields.

**Jira labels**

Selecione as labels relevantes com as quais você deseja que a Issue seja criada no Jira, por exemplo, **DefectDojo**, **YourProductName..**

![image](images/Add_a_Connected_Jira_Project_to_a_Product_6.png)

#### Default assignee

O nome do assignee padrão no Jira. Se deixado em branco, o DefectDojo seguirá o comportamento padrão do seu Espaço do Jira ao criar Issues.

### Opções adicionais do formulário

#### Enable Connection With Jira Space

As integrações do Jira só podem ser removidas da sua instância se nenhuma Issue relacionada tiver sido criada. Se Issues já tiverem sido criadas, não há como remover completamente uma Instância do Jira do DefectDojo.

No entanto, você pode desativar sua integração do Jira desativando-a no nível do Produto. Isso não excluirá nem alterará nenhum ticket existente do Jira criado pelo DefectDojo, mas desativará futuras atualizações.

#### Add Vulnerability Id as a Jira label

Isso permite adicionar automaticamente os dados de Vulnerability ID como uma Jira Label. Os Vulnerability IDs são adicionados aos Achados por ferramentas de segurança individuais \- podem ser IDs de Common Vulnerabilities and Exposures (CVE) ou um formato diferente, específico da ferramenta que reporta o Achado.

#### Enable Engagement Epic Mapping (For Products)

No DefectDojo, os Engajamentos representam um conjunto de trabalho. Cada Engajamento contém um ou mais testes, que contêm um ou mais Achados que precisam ser mitigados. As Epics no Jira funcionam de forma semelhante, e essa checkbox permite enviar Engajamentos para o Jira como Epics.

* Um Engajamento no DefectDojo \- observe os três achados listados na parte inferior.
​
![image](images/Add_a_Connected_Jira_Project_to_a_Product_8.png)
* Como o mesmo Engajamento se torna uma Epic quando enviado para o JIRA \- os Achados do Engajamento também são enviados e ficam dentro do Engajamento como Child Issues.

![image](images/Add_a_Connected_Jira_Project_to_a_Product_9.png)

#### Push All Issues

Se marcada, o DefectDojo enviará automaticamente para o Jira, como Issues, todos os Achados Ativos e Verificados. Se não estiver marcada, todos os Achados precisarão ser enviados manualmente para o Jira.

#### Push Notes

Se habilitado, os comentários do Jira serão exibidos no Achado associado no DefectDojo, em Notas na issue (captura de tela), e vice-versa; as Notas nos Achados serão adicionadas à Issue do Jira associada como Comments.

#### Send SLA Notifications As Comments

Se habilitado, qualquer Issue que viole as regras de Service Level Agreement do DefectDojo terá comentários adicionados à issue do Jira indicando isso. Esses comentários serão publicados diariamente até que a Issue seja resolvida.

Os Service Level Agreements podem ser configurados em **Configuration \> SLA Configuration** no DefectDojo e atribuídos a cada Produto.

#### Send Risk Acceptance Expiration Notifications As Comment?

Se habilitado, qualquer Issue cuja Aceitação de risco associada no DefectDojo expirar terá um comentário adicionado à issue do Jira indicando isso. Esses comentários serão publicados diariamente até que a Issue seja resolvida.

### Configurações de Jira em nível de Engajamento

Como resultado, Engajamentos diferentes dentro de um Produto podem ter configurações de Jira subjacentes diferentes. Por padrão, os Engajamentos vão '**inherit Jira settings from product**', ou seja, compartilharão as mesmas configurações de Jira do Produto ao qual pertencem.

No entanto, você pode alterar o **Product Key**, **Issue Template, Custom Fields, Jira Labels, Default Assignee** de um Engajamento para que sejam diferentes das configurações padrão do Produto

Você pode acessar essa página a partir da página **Edit Engagement**: **your\-instance.defectdojo.com/engagement/\[id]/edit**.

A página Edit Engagement pode ser encontrada a partir da página do Engajamento, clicando no menu ☰ ao lado da Description do engajamento.

![image](images/Creating_Issues_in_Jira_5.png)

## Etapa 4: Configure a sincronização bidirecional: Webhook do Jira

A integração do Jira permite sincronização bidirecional via webhook. O DefectDojo recebe notificações do Jira em um endereço exclusivo, o que pode permitir que comentários do Jira sejam recebidos nos Achados, ou que Achados sejam resolvidos via Jira, dependendo da sua configuração.

### Localizando a URL do seu Webhook do Jira

Seu Webhook do Jira é formado pela URL do seu DefectDojo e pelo **Jira webhook secret** que você gerou na [Etapa 1](#step-1-enable-the-jira-integration-in-system-settings). Ambos são exibidos na página ⚙️ **Configuration \> System Settings**, ao lado do campo **Jira webhook secret** (veja a captura de tela na Etapa 1).

Você também precisa marcar **Enable JIRA web hook** na mesma página antes que o DefectDojo processe as notificações recebidas do Jira. Os webhooks recebidos são ignorados se essa caixa ou **Enable JIRA integration** estiver desmarcada.

### Criando o Webhook do Jira

1. Acesse `**https:// \<YOUR JIRA URL\> /plugins/servlet/webhooks**`
2. Clique em 'Create a Webhook'.
3. No campo chamado 'URL', insira: `https:// \<**YOUR DOJO DOMAIN**\> /jira/webhook/ \<**YOUR GENERATED WEBHOOK SECRET**\>`. O Web Hook Secret está listado ao lado do campo **Jira webhook secret**, conforme mostrado acima.
4. Em 'Comments', habilite 'Created'. Em Issue, habilite 'Updated'.
5. Certifique-se de que sua instância do JIRA confie no certificado SSL usado pela sua instância do DefectDojo. Para o JIRA Cloud, o DefectDojo deve usar [um certificado SSL/TLS válido, assinado por uma autoridade certificadora globalmente confiável](https://developer.atlassian.com/cloud/jira/platform/deprecation-notice-registering-webhooks-with-non-secure-urls/)

Observe que não é necessário criar um Secret dentro do Jira para usar esse webhook. O Secret já está embutido na URL do DefectDojo, portanto basta adicionar a URL completa ao formulário Jira Webhook.

As solicitações de webhook recebidas são autenticadas pelo secret contido nessa URL, portanto trate a URL completa como uma credencial e mantenha-a privada.

#### Testando o Webhook

Depois de ter uma ou mais Issues criadas a partir de Achados do DefectDojo, você pode testar o Webhook adicionando um Comment a um desses Achados. O Comment deve ser recebido pelo webhook do Jira como uma nota.

Se isso não funcionar corretamente, pode ser devido a um problema de Firewall na sua instância do Jira bloqueando o Webhook.

* As Firewall Rules do DefectDojo incluem uma checkbox para **Jira Cloud,** que precisa ser habilitada antes que o DefectDojo possa receber mensagens de Webhook do Jira.

### Alternativa: Usando o Jira Automation (Send web request)

Algumas instâncias do Jira não permitem webhooks de sistema em `/plugins/servlet/webhooks` — por exemplo, quando essa área de administração é restrita e apenas regras do **Jira Automation** são permitidas. Nesse caso, você pode obter a mesma sincronização bidirecional usando a ação **Send web request** do Automation, que envia solicitações para o mesmo endpoint de webhook do DefectDojo.

O endpoint de webhook do DefectDojo aceita qualquer `POST` HTTP com `Content-Type: application/json` e um secret válido no caminho da URL. Ele **não** exige que a solicitação venha do mecanismo de webhook de sistema do Jira, portanto a ação "Send web request" do Automation funciona como uma alternativa direta.

#### Pré-requisitos

Aplicam-se os mesmos pré-requisitos do webhook de sistema:

* **Enable JIRA integration** e **Enable JIRA web hook** estão ambas marcadas na página ⚙️ **Configuration \> System Settings**.
* Um **Jira webhook secret** não vazio está definido nessa página. O secret pode conter apenas os caracteres `A-Z`, `a-z`, `0-9`, `_` e `-`.
* O Achado (ou Grupo de Achados) já está vinculado à issue do Jira. Se a issue não estiver vinculada a um Achado do DefectDojo, a solicitação ainda é aceita (HTTP `200`), mas nenhuma ação é executada.

#### Como o DefectDojo processa a solicitação

* O DefectDojo se baseia em um campo `webhookEvent` de nível superior. Somente `"jira:issue_updated"` e `"comment_created"` são processados; qualquer outro valor é aceito e ignorado. O Automation **não** adiciona esse campo automaticamente, portanto você precisa incluí-lo no corpo da solicitação.
* Por isso, defina o **Body** da solicitação como **Custom data** e forneça o JSON abaixo. As opções de body **Empty** e **Jira issue data** não incluem o campo `webhookEvent` exigido, então o DefectDojo as ignorará.
* O endpoint sempre retorna HTTP `200`, independentemente de a atualização ter sido aplicada. O sucesso ou a falha só ficam visíveis no corpo da resposta e nos logs do DefectDojo — um `200` no audit log do Automation **não** confirma, por si só, que a atualização chegou a um Achado.

#### Rule 1 — Issue updated

Crie uma regra do Automation com:

* **Trigger:** *Issue transitioned* (ou outro trigger que dispare quando os campos que você sincroniza mudarem, por exemplo, *Field value changed* em Status).
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

Restrições para atualizações de issues:

* `issue.id` deve ser o **ID numérico interno da issue do Jira** (`{{issue.id}}`), e não a issue key (por exemplo, `PROJ-123`). O DefectDojo associa a atualização a um Achado por meio desse ID numérico.
* Os campos `resolution` e `updated` devem estar sempre presentes. `resolution` pode ser `null`, mas se algum desses campos estiver ausente, a solicitação é aceita (`200`) e silenciosamente não processada.
* A sincronização de status e a auto-mitigação são controladas por `status.statusCategory.key`, cujos valores no Jira são `new` (To Do), `indeterminate` (In Progress) e `done` (Done). Um Achado só é mitigado quando a issue é genuinamente fechada, não apenas por haver um valor de resolution presente.

#### Rule 2 — Issue commented

Crie uma segunda regra do Automation com:

* **Trigger:** *Issue commented*
* **Action:** *Send web request* — mesma URL, método, header e opção de body *Custom data* da Rule 1, com este body:

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
* O DefectDojo deriva a issue de destino a partir da URL `comment.self` — especificamente o `<id>` no segmento `.../issue/<id>/comment/...` — portanto `{{issue.id}}` (o ID numérico) deve aparecer ali.
* **Prevenção de loop:** se o autor do comentário corresponder à conta do Jira que o DefectDojo usa para publicar seus próprios comentários, o DefectDojo ignora o comentário para evitar um loop de eco. Se você quiser que *todos* os comentários sejam ingeridos, execute a regra do Automation com um usuário do Jira **diferente** daquele configurado na instância do Jira do DefectDojo.

#### Uma observação sobre smart values

Os smart values mostrados acima (`{{issue.id}}`, `{{issue.status.statusCategory.key}}`, `{{comment.author.accountId}}`, e assim por diante) são os nomes padrão do Jira Cloud, mas podem variar entre instâncias. Antes de colocar em produção, use o payload preview do Automation para confirmar que cada smart value resolve para o valor esperado.

## Testando a integração com o Jira

#### Teste 1: os achados são enviados corretamente para o Jira?

Para testar se a integração com o Jira está funcionando corretamente, você pode adicionar um novo achado em branco ao Produto associado ao Jira no DefectDojo. **Produto \> Achados \> Adicionar Novo Achado.**

Adicione o título, a severidade e a descrição que desejar e clique em "Finished". O achado deve aparecer como um Issue no Jira com todos os metadados relevantes.

Se os Issues do Jira não estiverem sendo criados corretamente, verifique suas notificações em busca de códigos de erro.

* Confirme se o usuário do Jira associado à Configuração do Jira do DefectDojo tem permissão para criar e atualizar issues nesse Jira Space específico.

#### Teste 2: os webhooks do Jira enviam dados para o DefectDojo

Para testar os webhooks do Jira, adicione uma nota a um achado que também exista no Jira como um Issue (por exemplo, o issue de teste da seção anterior).

Se os webhooks estiverem configurados corretamente, você deverá ver a nota no Jira como um comentário no issue.

Se isso não funcionar corretamente, pode ser devido a um problema de firewall na sua instância do Jira que está bloqueando o webhook.

* As Regras de Firewall do DefectDojo incluem uma caixa de seleção para o **Jira Cloud**, que precisa ser habilitada antes que o DefectDojo possa receber mensagens de webhook do Jira.

## Desconectando do Jira

As integrações com o Jira só podem ser removidas da sua instância se nenhum Issue relacionado tiver sido criado. Se Issues já tiverem sido criados, não há como remover completamente uma instância do Jira do DefectDojo.

No entanto, você pode desabilitar sua integração com o Jira desativando-a no nível do Produto. No formulário **Edit Product**, você pode desmarcar a opção "Enable Connection With Jira Space". Isso não excluirá nem alterará nenhum ticket do Jira já existente criado pelo DefectDojo, mas desabilitará quaisquer atualizações futuras.

# Enviando achados para o Jira

## Enviando achados para o Jira
Um Produto com um mapeamento do Jira pode enviar achados para o Jira como Issues. Isso pode ser gerenciado de duas formas diferentes:

* Os achados podem ser criados como Issues manualmente, achado por achado.
* Os achados podem ser enviados automaticamente caso a configuração '**Push All Issues**' esteja habilitada em um Produto. (Isso se aplica apenas a achados com status **Ativo** e **Verificado**).

Além disso, você tem a opção de enviar Grupos de achados para o Jira em vez de achados individuais. Isso criará um único Issue contendo vários achados relacionados do DefectDojo.

### Enviando um achado manualmente

1. Na página de um achado no DefectDojo, navegue até o cabeçalho **JIRA**. Se o achado ainda não existir no Jira como um Issue, o cabeçalho JIRA terá o valor '**None**'.
​
2. Clicar na seta ao lado do valor **None** criará um novo issue no Jira. O estado em que o issue é criado dependerá do workflow da sua equipe e da configuração do Jira com o DefectDojo. Se o achado não aparecer, atualize a página.
​
![imagem](images/Creating_Issues_in_Jira.png)

3. Depois que o Issue for criado, o DefectDojo criará um link para o issue composto pela chave do Jira e pelo ID do Issue. Esse link também terá uma lixeira vermelha ao lado, permitindo que você exclua o Issue do Jira.
​
![imagem](images/Creating_Issues_in_Jira_2.png)

4. Clicar na seta novamente enviará todas as alterações feitas em um issue para o Jira, atualizando o Issue do Jira de acordo. Se a configuração '**Push All Issues**' estiver habilitada no Produto associado ao achado, esse processo acontecerá automaticamente.

### Comentários do Jira

* Se um comentário for adicionado a um Issue do Jira, o mesmo comentário será adicionado ao achado, na seção **Notas**.
* Da mesma forma, se uma nota for adicionada a um achado, ela será adicionada ao issue do Jira como um comentário.

### Alterações de status no Jira

A Configuração do Jira no DefectDojo possui entradas para duas Transições do Jira que acionam uma alteração de status em um achado.

* Quando a **transição 'Close'** é executada no Jira, o achado associado também será fechado e marcado como **Inativo** e **Mitigado** no DefectDojo. O DefectDojo registrará essa alteração na página do achado, no cabeçalho **Mitigated By**.
​
![imagem](images/Creating_Issues_in_Jira_3.png)

* Quando a **transição 'Reopen'** é executada no Issue do Jira, o achado associado será definido como **Ativo** no DefectDojo e perderá seu status de **Mitigado**.

### Mapeando resoluções do Jira para Aceitação de risco / Falso positivo

Além das transições Close / Reopen, a Configuração do Jira inclui campos opcionais que permitem mapear uma **Resolution** do Jira para um status de achado no DefectDojo. Esses campos são definidos durante o fluxo **Add Jira Configuration (Express)** (etapas 6 e 7) e podem ser editados posteriormente na Configuração do Jira:

* **Risk Accepted Finding Mapping Resolution** — quando um issue do Jira é fechado com essa Resolution, o achado vinculado se torna Risco aceito no DefectDojo.
* **False Positive Finding Mapping Resolution** — quando um issue do Jira é fechado com essa Resolution, o achado vinculado se torna Falso positivo no DefectDojo.

#### Status vs Resolution: um ponto comum de confusão

Esses campos mapeiam a **Resolution** do Jira, não o **Status** do Jira. Status e Resolution são dois conceitos independentes no Jira: o Status descreve em que ponto do workflow o issue está (Open, In Progress, Done), enquanto a Resolution descreve como ele foi resolvido (Fixed, Won't Do, Duplicate, False Positive, etc.).

Um ponto comum de confusão é que uma transição de workflow do Jira pode alterar o Status para "Done" *sem* definir nenhuma Resolution. Quando isso acontece, o mapeamento de resolução do DefectDojo nunca é acionado — em vez disso, o achado é marcado como **Mitigado** pelo comportamento padrão da **transição 'Close'** descrito acima, e não como Risco aceito ou Falso positivo.

#### Pré-requisito: uma post-function "Set issue resolution" na transição de workflow do Jira

O motor de workflow do Jira não preenche o campo Resolution automaticamente. Cada transição que deve fechar um issue com uma Resolution específica precisa de uma post-function **Set issue resolution** configurada na própria transição. Sem essa post-function, o issue passa para o novo Status, mas a Resolution permanece em branco, e o mapeamento do DefectDojo não tem nada para comparar.

Um administrador do Jira pode adicionar essa post-function em **Project Settings → Workflows → (edit workflow) → (select the closing transition) → Post Functions → Add post function → Set issue resolution**.

## Enviando Grupos de achados como Issues do Jira

Se você tiver os Grupos de achados habilitados, poderá enviar um Grupo de achados para o Jira como um único Issue, em vez de Issues separados para cada achado.

No entanto, o Issue do Jira associado a um Grupo de achados não pode ser manipulado nem excluído pelo DefectDojo. Ele deve ser excluído diretamente na instância do Jira.

### Criando e enviando Grupos de achados automaticamente

Com a opção Auto-Push To Jira habilitada e uma opção Group By selecionada na importação:

Desde que os Grupos de achados estejam sendo criados com sucesso, é o Grupo de achados que será enviado automaticamente para o Jira como um Issue, e não os achados individuais.

![imagem](images/Creating_Issues_in_Jira_4.png)

## Campos personalizados no Jira
<span style="background: rgba(243, 122, 78,0.5">Atualmente, o DefectDojo não oferece suporte para passar informações específicas do Issue para esses Custom Fields \- esses campos precisarão ser atualizados manualmente no Jira após a criação do issue. Cada Custom Field será criado pelo DefectDojo apenas com um valor padrão.</span>

<span style="background: rgba(0, 207, 83, 0.44)"> O Jira Cloud agora permite criar um valor padrão de Custom Field diretamente no aplicativo. [Consulte a documentação da Atlassian sobre Custom Fields](https://support.atlassian.com/jira-cloud-administration/docs/configure-a-custom-field/) para mais informações sobre como configurar isso.</span>

Os Issue Types nativos do Jira no DefectDojo (**Bug, Task, Story** e **Epic)** já vêm configurados para funcionar 'prontos para uso'. Os campos de dados do DefectDojo são mapeados automaticamente para os campos correspondentes no Jira. Por padrão, o DefectDojo atribui Priority, Labels e um Reporter a qualquer novo Issue que criar.

Algumas configurações do Jira exigem que campos personalizados adicionais sejam considerados antes que um issue possa ser criado. Este processo permite que você considere esses campos personalizados na sua integração DefectDojo \-\> Jira, garantindo que os issues sejam criados com sucesso. Esses campos personalizados serão adicionados a todas as chamadas de API enviadas do DefectDojo para uma instância do Jira vinculada.

Se você ainda não usa Custom Fields no Jira, não há necessidade de seguir este processo.

1. Registre os nomes dos seus Custom Fields no Jira (**interface do Jira**)
2. Determine os valores de Key para os novos Custom Fields (Jira Field Spec Endpoint)
3. Localize os dados aceitáveis para cada Custom Field, usando os valores de Key como referência (Jira Issue Endpoint)
4. Crie um bloco JSON de referência de campos para rastrear todas as Keys dos Custom Fields e os dados aceitáveis (Jira Issue Endpoint)
5. Armazene o bloco JSON no Produto associado do DefectDojo, para permitir que os Custom Fields sejam criados a partir do Jira (interface do DefectDojo)
6. Teste seu trabalho e garanta que todos os dados necessários estejam fluindo corretamente a partir do Jira

#### Etapa 1: registre os nomes dos seus Custom Fields no Jira

O Jira oferece suporte a uma variedade de Context Fields diferentes, incluindo Date Pickers, Custom Labels e Radio Buttons. Cada um desses Context Fields terá um valor de Key diferente, que pode ser encontrado na API do Jira.

Anote os nomes de cada Custom Field necessário, pois você precisará pesquisar na API do Jira para encontrá-los na próxima etapa.

**Exemplo de uma lista de Custom Fields (os nomes dos seus Custom Fields serão diferentes):**

* DefectDojo Custom URL Field
* Another example of a Custom Field
* ...

#### Etapa 2: encontrando os valores de Key dos seus Custom Fields no Jira

Comece esse processo navegando até a URL do Field Spec de toda a sua instância do Jira.

Veja um exemplo de URL de Field Spec:

`https://yourcompany-example.atlassian.net/rest/api/2/field`

A API retornará uma longa string em JSON, que deve ser formatada em texto legível (usando um editor de código, uma extensão de navegador ou <https://jsonformatter.org/>).

O JSON retornado por essa URL conterá todos os seus custom fields do Jira, a maioria dos quais é irrelevante para o DefectDojo e possui valores `"Null"`. Cada objeto nessa resposta da API corresponde a um campo diferente no Jira. Você precisará procurar os objetos que tenham atributos `"name"` correspondentes aos nomes de cada Custom Field que você criou na interface do Jira e, em seguida, anotar o valor do respectivo atributo "key".

![imagem](images/Using_Custom_Fields.png)

Depois de encontrar o objeto correspondente na saída do JSON, você pode determinar o valor de "key" \- neste caso, é `customfield_10050`.

O Jira gera valores de key diferentes para cada Custom Field, mas esses valores de key não mudam depois de criados. Se você criar outro Custom Field no futuro, ele terá um novo valor de key.

**Expandindo nossa lista de Custom Fields:**

* "DefectDojo Custom URL Field" \= customfield\_10050
* "Another example of a Custom Field" \= customfield\_12345
* ...

#### Etapa 3 \- localizando os Custom Fields em um Issue do Jira

Localize um Issue no Jira que contenha os Custom Fields que você registrou na Etapa 2\. Copie a Issue Key do título (deve ser algo parecido com "`EXAMPLE-123`") e navegue até a seguinte URL:

`https://yourcompany-example.atlassian.net/rest/api/2/issue/EXAMPLE-123`

Isso retornará outra string em JSON.

Assim como antes, a saída da API conterá muitos parâmetros de objeto `customfield_##` com valores `null` \- esses são custom fields que o Jira adiciona por padrão e que não são relevantes para esse issue. Ela também conterá valores `customfield_##` que correspondem aos valores de Key dos Custom Fields que você encontrou na etapa anterior. Diferentemente da saída do Field Spec, você não verá nomes identificando nenhum desses custom fields, motivo pelo qual foi necessário registrar os valores de key na Etapa 2\.

![imagem](images/Using_Custom_Fields_2.png)

**Exemplo:**
Sabemos que `customfield_10050` representa o DefectDojo Custom URL Field porque registramos isso na Etapa 2\. Agora podemos ver que `customfield_10050` contém o valor `"https://google.com"` no issue `EXAMPLE-123`.

#### Etapa 4 \- criando uma referência JSON de campos a partir de cada Key de Custom Field do Jira

Agora você precisará pegar o valor de cada um dos Custom Fields da sua lista e armazená-los em um objeto JSON (para usar como referência). Você pode ignorar quaisquer Custom Fields que não correspondam à sua lista.

Esse objeto JSON conterá todos os valores padrão para os novos Issues do Jira. Recomendamos usar nomes que sejam fáceis para sua equipe reconhecer como valores 'padrão' que precisam ser alterados: '`change-me.com`', '`Change this paragraph.`' etc.

**Exemplo:**

A partir da etapa 3, agora sabemos que o Jira espera uma string de URL para "`customfield_10050`". Podemos usar isso para construir nosso objeto JSON de exemplo.

Suponha que também tenhamos localizado um campo de texto curto relacionado ao DefectDojo, identificado como "`customfield_67890`". Verificaríamos esse campo na nossa segunda saída de API, observaríamos o valor associado e também faríamos referência ao valor armazenado no nosso objeto JSON de exemplo.
​
Seu objeto JSON começará a ficar parecido com isto à medida que você adicionar mais Custom Fields a ele.

```
{
	"customfield_10050": "https://change-me.com",
	"customfield_67890": "This is the short text custom field."
}
```

Repita esse processo até que todos os custom fields relevantes para o DefectDojo do Jira tenham sido adicionados à sua referência JSON de campos.

#### Tipos de dados \& sintaxe do Jira

Alguns campos, como os campos de Date, podem estar relacionados a vários custom fields no Jira. Se for esse o caso, você precisará adicionar ambos os campos à sua referência JSON de campos.

```
  "customfield_10040": "1970-01-01",
  "customfield_10041": "1970-01-01T03:30:00.000+0200",
```

Outros campos, como o campo Label, podem ser rastreados como uma lista de strings \- certifique-se de que sua referência JSON de campos use um formato que corresponda à saída da API do Jira.

```
// a list of custom labels on a Jira object
  "customfield_10042": [
    "custom-label-one",
    "this-is-default",
    "change-me-please"
  ],
```

Outros custom fields podem conter informações contextuais adicionais que devem ser removidas da referência de campos. Por exemplo, o Custom Multichoice Field contém um bloco extra na saída da API, que você precisará remover, pois esse bloco armazena o valor atual do campo.

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
* em vez disso, você pode reduzir para o seguinte e desconsiderar a segunda parte:

```
"customfield_10047": [
   {
      "value": "A"
   }
]
```

#### Exemplo de referência de campos completa

Aqui está uma referência JSON de campos completa, com comentários em linha explicando a que cada custom field se refere. Este é um exemplo abrangente. Seu JSON conterá valores de key e dados diferentes, dependendo dos Custom Values que você deseja usar durante a criação do issue.

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

#### Etapa 5 \- adicionando os Custom Fields a um Produto do DefectDojo

Agora você pode adicionar esses custom fields ao Produto associado do DefectDojo, na seção Custom Fields. Mais uma vez,

* Navegue até Edit Product \- defectdojo.com/product/ID/edit .
* Navegue até Custom fields e cole a referência JSON de campos como texto simples na caixa Custom Fields.
* Clique em 'Submit'.

#### Etapa 6 \- testando seus Custom Fields do Jira a partir de um novo achado:

Agora, quando você criar um novo achado no Produto associado ao Jira, o Jira criará automaticamente todos esses Custom Fields de acordo com o bloco JSON contido nele. Esses Custom Fields serão criados com os valores padrão ("change\-me\-please", etc.).

No Produto, no DefectDojo, navegue até a página Achados \> Adicionar Novo Achado. Certifique-se de que o achado esteja Ativo e Verificado para garantir que seja enviado ao Jira e, em seguida, confirme no lado do Jira que os Custom Fields foram criados com sucesso, sem nenhuma inconsistência.
