---
title: Conectores de Mensagens
description: Envie alertas do DefectDojo para Slack, Microsoft Teams, e-mail ou Amazon
  SNS.
weight: 4
audience: pro
---

**Disponibilidade:** Messaging Connectors é um recurso beta. Habilite **Messaging Connectors** na página Feature Flags. Como os alertas são roteados por regras, o **Rules Engine 2.0** também precisa estar habilitado.

O Messaging Connectors envia alertas do DefectDojo para um serviço de chat, para um endereço de e-mail ou para um tópico do Amazon SNS. Ele fica ao lado dos conectores de ticketing e de gestão de incidentes na mesma página **Downstream Connectors**, e é configurado da mesma forma: crie uma conexão uma vez e depois decida o que deve ser enviado para ela.

Conectores de ticketing e conectores de mensagens respondem a perguntas diferentes. Um conector de ticketing cria e atualiza um ticket que acompanha um Achado ao longo do tempo. Um conector de mensagens publica uma mensagem sobre algo que acabou de acontecer, como uma importação que trouxe novos Achados de severidade Alta e Crítica. Uma mensagem não tem status para transicionar nem ticket para manter sincronizado, então os dois são configurados separadamente e nenhum afeta o outro.

## O que você pode enviar

Os alertas são roteados pelo Rules Engine 2.0. Uma regra decide **quando** enviar (um gatilho), **quais** Achados se qualificam (condições) e **para onde** a mensagem vai (um nó de notificação endereçando sua conexão e canal).

Isso significa que os filtros disponíveis para um alerta são os mesmos disponíveis para uma regra: severidade, escopo, tags, status e qualquer outra coisa que uma condição de regra possa expressar. Vários alertas diferentes indo para vários canais diferentes são simplesmente várias regras.

## Os quatro fornecedores

| Fornecedor | O que você fornece | Quantos destinos por conexão |
| --- | --- | --- |
| Slack | Um bot token de um app do Slack | Vários. Cada destino nomeia um ID de canal. |
| Microsoft Teams | Uma URL de workflow do Power Automate | Um. A URL decide o canal. |
| E-mail | Nada. É usado o servidor de e-mail da instância. | Vários. Cada destino nomeia destinatários. |
| Amazon SNS | Uma chave de acesso da AWS autorizada a publicar | Vários. Cada destino nomeia um ARN de tópico. |

Cada um é configurado da mesma forma: adicione a conexão em **Connect > Downstream** e depois crie um alerta que a endereça.

## Configurar uma conexão do Slack

Você precisa de um app do Slack com um bot token. Se seu workspace já tiver um para o DefectDojo, você pode reutilizá-lo.

### 1. Criar um app do Slack

1. Acesse [https://api.slack.com/apps](https://api.slack.com/apps) e selecione **Create New App**, depois **From scratch**.
2. Dê um nome ao app (por exemplo, DefectDojo) e escolha o workspace no qual ele deve publicar.
3. Abra **OAuth & Permissions** e adicione estes **Bot Token Scopes**:
   - `chat:write` (obrigatório): permite que o app publique mensagens.
   - `chat:write.public` (opcional): permite que o app publique em qualquer canal público sem precisar ser convidado antes. Sem esse escopo, você precisa convidar o bot para cada canal que quiser usar.
4. Selecione **Install to Workspace** e aprove o app.
5. Copie o **Bot User OAuth Token**. Ele começa com `xoxb-`.

### 2. Adicionar a conexão no DefectDojo

1. Acesse **Connect > Downstream**.
2. Na seção **Messaging**, encontre o bloco do Slack e selecione **Add Configuration**.
3. Preencha:
   - **Location**: a URL do seu workspace do Slack, por exemplo `https://your-workspace.slack.com`. Isso é usado apenas para exibição e links.
   - **Identifier**: um rótulo que diferencia esta conexão das demais, por exemplo `Security workspace`.
   - **Bot Token**: o token `xoxb-` que você copiou.
4. Salve. O DefectDojo valida o token junto ao Slack imediatamente, então um token incorreto ou revogado é reportado aqui, em vez de somente na primeira vez que um alerta disparar.

Você pode adicionar quantas conexões do Slack precisar. Conexões separadas são a forma de alcançar mais de um workspace.

### 3. Encontrar o ID do canal

Os destinos do Slack usam o **ID** do canal, não o nome do canal.

1. No Slack, abra o canal e selecione o nome dele no topo.
2. Role até o final da aba **About**.
3. Copie o **Channel ID**. Ele se parece com `C0123456789`.

Se o app não tiver o escopo `chat:write.public`, convide-o também para o canal: digite `/invite @your-app-name` no canal.

## Configurar uma conexão do Microsoft Teams

O Teams usa uma **URL de workflow do Power Automate**. Os conectores clássicos do Office 365 foram descontinuados, e esse caminho não exige registro de app nem consentimento do administrador do tenant: alguém com permissões no canal cria o flow e cola a URL que ele retorna.

**Uma conexão publica em um canal.** A URL do workflow decide para onde a mensagem vai, então um segundo canal significa uma segunda conexão, e não um segundo destino.

### 1. Criar o workflow

1. No Teams, abra o canal em que deseja publicar, selecione o menu **...** ao lado do nome do canal e depois **Workflows**.
2. Escolha o modelo **Post to a channel when a webhook request is received**.
3. Confirme o time e o canal, depois selecione **Add workflow**.
4. Copie a URL que o workflow fornece. É um endereço `https://` longo em um host do Microsoft Power Automate.

Trate essa URL como uma senha. Qualquer pessoa que a possua pode publicar naquele canal.

### 2. Adicionar a conexão no DefectDojo

1. Acesse **Connect > Downstream**.
2. Na seção **Messaging**, encontre o bloco do Microsoft Teams e selecione **Add Configuration**.
3. Preencha:
   - **Location**: a URL do seu Teams ou Microsoft 365. Isso é usado apenas para exibição e links.
   - **Instance Label**: um rótulo nomeando o canal que esta conexão alcança, por exemplo `Security / Alerts`.
   - **Workflow URL**: a URL que você copiou.
4. Salve.

O DefectDojo verifica o formato da URL ao salvar (ela precisa ser `https://` e estar em um host de workflow da Microsoft), mas não publica nela. Uma URL de workflow não tem como ser testada a não ser enviando uma mensagem, e uma mensagem surpresa em um canal no momento de salvar é pior do que descobrir isso depois. Use **Send test message** quando estiver pronto.

Um destino do Teams tem um campo opcional, um rótulo de canal, que apenas identifica o registro de entrega. A URL do workflow já decide o destino.

## Configurar uma conexão de e-mail

O e-mail não precisa de credencial. O DefectDojo envia através do servidor de e-mail que esta instância já usa para notificações, então não há nada novo para configurar e nenhum segundo lugar em que o SMTP possa estar errado.

1. Acesse **Connect > Downstream**.
2. Na seção **Messaging**, encontre o bloco de Email e selecione **Add Configuration**.
3. Preencha:
   - **Location**: a identidade do remetente a exibir, por exemplo `mailto:defectdojo@example.com`.
   - **Instance Label**: um rótulo que diferencia esta conexão das demais.
4. Salve.

Salvar falha se esta instância não tiver servidor de e-mail ou endereço de remetente configurado, porque nada enviado pela conexão sairia do lugar. Configure o SMTP em **Settings > System Settings** primeiro.

Os destinatários são definidos no alerta, não na conexão, então uma única conexão de Email atende a todos os alertas. Um destino de e-mail aceita até 50 endereços; além disso, use um endereço de distribuição.

## Configurar uma conexão do Amazon SNS

O SNS é de natureza diferente dos outros três: o DefectDojo publica uma mensagem em um tópico, e a AWS a distribui para tudo que estiver inscrito, o que pode ser endereços de e-mail, números de SMS, uma função Lambda, um endpoint HTTPS ou uma fila SQS. O DefectDojo não sabe nem se importa com qual deles.

### 1. Criar uma chave de acesso que possa publicar

1. No console da AWS, crie (ou escolha) um usuário ou role do IAM para o DefectDojo.
2. Anexe uma política permitindo `sns:Publish` nos tópicos que você pretende usar. Nomear os ARNs dos tópicos explicitamente é melhor do que permitir todos eles.
3. Crie uma chave de acesso para ele e copie as duas partes. A AWS mostra a secret access key apenas uma vez.

Se o tópico for criptografado com uma chave KMS, o mesmo principal também precisa de `kms:GenerateDataKey` e `kms:Decrypt` nessa chave, ou toda publicação será recusada.

### 2. Adicionar a conexão no DefectDojo

1. Acesse **Connect > Downstream**.
2. Na seção **Messaging**, encontre o bloco do Amazon SNS e selecione **Add Configuration**.
3. Preencha:
   - **Location**: uma URL apenas para exibição e links, por exemplo a URL do seu console da AWS.
   - **Instance Label**: um rótulo que diferencia esta conexão das demais, por exemplo `Production AWS account`.
   - **Access Key ID**: o ID da chave, que se parece com `AKIAIOSFODNN7EXAMPLE`.
   - **Secret Access Key**: a parte secreta.
4. Salve.

O DefectDojo verifica a credencial junto à AWS imediatamente, então uma chave errada ou excluída é reportada aqui, em vez de somente na primeira vez que um alerta disparar. Essa verificação confirma apenas que a credencial é válida; se ela pode publicar em um determinado tópico é verificado quando você define o destino.

**Não há região para informar.** A região faz parte do ARN do tópico, então uma conexão pode publicar em tópicos em mais de uma região, e não existe uma segunda configuração que possa divergir do ARN.

### 3. Encontrar o ARN do tópico

Um destino do SNS usa o ARN do tópico.

1. No console do SNS, abra o tópico.
2. Copie o **ARN** no topo da página. Ele se parece com `arn:aws:sns:us-east-1:123456789012:security-alerts`.

Ao contrário de uma URL de workflow do Teams, um ARN não é um segredo: ele nomeia um tópico, e publicar nele exige a credencial da conexão. É por isso que uma conexão do SNS pode atender a vários tópicos.

Tópicos FIFO (um ARN terminado em `.fifo`) não são suportados. Eles exigem um grupo de mensagens e um ID de deduplicação, que são regras de ordenação que um alerta não tem como fornecer. Use um tópico padrão.

## Enviar uma mensagem de teste

Em qualquer lugar onde um destino de mensagem esteja configurado, **Send test message** entrega uma mensagem curta pelo mesmo caminho exato que um alerta real usa, e reporta o que o fornecedor respondeu.

Use isso para confirmar os pontos fáceis de errar: no Slack, que o ID do canal está correto e que o bot pode publicar ali; no Teams, que a URL do workflow ainda funciona; no e-mail, que o endereço é entregável; no SNS, que a chave pode publicar naquele tópico. A própria resposta do fornecedor é repassada, então um convite faltando no Slack aparece como uma mensagem dizendo para convidar o bot, em vez de uma falha genérica.

Um teste bem-sucedido também libera uma conexão que foi desabilitada automaticamente (veja [Quando uma conexão para de funcionar](#when-a-connection-stops-working)).

## Criar um alerta

Há duas formas de fazer isso. Ambas produzem a mesma coisa: uma regra do Rules Engine 2.0.

### A página de alertas

O caminho curto, para o caso comum de anunciar novos achados a partir de uma importação.

1. Acesse **Connect > Downstream** e selecione **Create Alert** em uma conexão de mensagens, ou abra **Messaging Alerts** diretamente.
2. Selecione **New Alert** e preencha:
   - **Name**: para que serve este alerta, por exemplo `New highs to the security channel`.
   - **Alert**: sobre o que ele é. **New findings from an import** é atualmente a única opção.
   - **Send over**: a conexão de mensagens.
   - **Where it delivers**: o campo de destino próprio do fornecedor, ou seja, um ID de canal do Slack, um rótulo de canal opcional do Teams, uma lista de endereços de e-mail, ou um ARN de tópico do SNS.
   - **Severity**: o piso, de **Critical only** até **Every severity**.
   - **Mode**: **Simulate** registra o que seria enviado sem enviar de fato, **Live** envia de verdade.
3. Selecione **Create Alert**.

A página lista os alertas que criou, com o gatilho, o piso de severidade e um alternador para habilitar ou desabilitar cada um.

Comece em **Simulate** se quiser ver o que um alerta teria capturado antes que qualquer canal saiba a respeito. A regra roda, as entregas são registradas e nada é enviado.

Alertas são regras, então também podem ser abertos no editor de regras a partir da mesma lista. Assim que uma regra é editada para algo que o formulário não consegue expressar, como uma segunda ramificação ou uma segunda mensagem, a lista oferece o editor de regras em vez do formulário, em vez de um formulário que silenciosamente descartaria o trabalho extra.

### O editor de regras

O caminho completo, para qualquer coisa que o formulário não cubra.

1. Acesse **Automation > Rules Engine 2.0** e crie uma regra.
2. Adicione um gatilho. Para alertas sobre Achados recém-importados, use o gatilho de evento de Achado em **created**. As importações são feitas em lote, então uma importação produz um alerta, em vez de um por Achado.
3. Adicione condições para o que deve se qualificar, por exemplo uma severidade mínima de Alto.
4. Adicione um nó de mensagem para o fornecedor desejado (**Send a Slack Message**, **Send a Microsoft Teams Message**, **Send an Email**, ou **Publish to an SNS Topic**) e defina:
   - **Connection**: a conexão de mensagens que você criou.
   - **Destination**: o destino do fornecedor, ou seja, um ID de canal para o Slack, um rótulo de canal opcional para o Teams, destinatários para e-mail, ou um ARN de tópico para o SNS.
5. Salve a regra e habilite-a.

Nada é enviado quando nenhum Achado corresponde às condições, então uma regra filtrada para Alto e acima permanece em silêncio em uma importação que só trouxe Achados de severidade Baixa.

### Regras escritas antes do Messaging Connectors

Um nó de mensagem envia através de uma conexão, e somente através de uma conexão. Os nós de Slack, Teams e e-mail antes recorriam às configurações de toda a instância em **Settings > Notifications** quando nenhuma conexão era escolhida. Isso não acontece mais.

Uma regra escrita daquela forma continua rodando, e seu nó de mensagem registra uma entrega ignorada informando que não nomeia nenhuma conexão. Para corrigir, abra a regra, escolha uma conexão e um destino no nó, e salve. Uma entrega que já havia sido registrada pode ser reproduzida a partir da lista de entregas assim que o nó nomear uma conexão.

A conexão é um campo obrigatório em todo nó de mensagem, então o editor de regras exige um antes que a regra possa ser salva.

## Quando uma conexão para de funcionar

Um bot token revogado, um workflow excluído ou uma chave de acesso da AWS excluída faz falhar todo alerta que ela atende. Em vez de registrar a mesma falha para cada evento, o DefectDojo conta falhas de credencial consecutivas por destino e para de enviar depois de algumas delas. A conexão reporta qual destino foi desabilitado e por quê.

Para recuperar: corrija a credencial (reinstale o app do Slack e cole o novo token, recrie o workflow do Teams e cole a nova URL, ou crie uma nova chave de acesso da AWS), depois envie uma mensagem de teste para aquele destino, o que o reabilita em caso de sucesso, ou use a ação de reabilitação diretamente.

Somente falhas de credencial causam isso. Uma mensagem rejeitada porque um ID de canal do Slack está errado, o bot não foi convidado, um endereço de e-mail não existe, ou uma política do IAM não permite publicar em um tópico não desabilita nada, porque a credencial está correta e corrigir o destino ou a política deve funcionar imediatamente.

## Alertas e notificações juntos

O Messaging Connectors não substitui as notificações. As configurações de Slack, Teams e e-mail de toda a instância em **Settings > Notifications**, as notificações pessoais e a matriz de notificações continuam funcionando exatamente como configuradas. Elas são o que anuncia os próprios eventos do DefectDojo; um Messaging Connector é o que uma regra que você escreveu envia.

Um ponto de atenção: se um alerta publicar no mesmo canal ou endereço para o qual a configuração de toda a instância já anuncia, aquele destino recebe as duas mensagens. Configure uma coisa ou outra para um determinado destino.

## Limitações

- A redação das mensagens ainda não é personalizável. Os alertas usam a redação padrão do DefectDojo.
- As mensagens são de mão única. O DefectDojo não lê respostas, e não há botões ou elementos interativos na mensagem.
- Threads, edição de mensagens e mensagens diretas para usuários individuais não são suportados. As notificações pessoais continuam usando o sistema de notificações existente.
- Uma conexão do Teams alcança um canal, porque é a URL do workflow que endereça o canal.
- As mensagens do SNS são em texto simples. Um tópico pode distribuir para assinantes de e-mail, SMS, Lambda e HTTPS ao mesmo tempo, então não existe um formato único que sirva para todos eles, e nenhuma variante por protocolo é publicada.
- Tópicos FIFO do SNS não são suportados.
- Relatórios e outros anexos ainda não podem ser enviados. Os alertas são mensagens com links de volta para o DefectDojo.
- A página de alertas cobre novos achados a partir de uma importação. Qualquer outra coisa é montada no editor de regras.
