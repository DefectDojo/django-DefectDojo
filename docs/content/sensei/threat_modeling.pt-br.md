---
title: Modelagem de Ameaças
description: Gere um modelo de ameaças, caminhos de ataque e requisitos de segurança
  a partir do design de uma funcionalidade, antes que o código exista
draft: false
audience: pro
weight: 4
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Nota: a Modelagem de Ameaças é um recurso exclusivo do DefectDojo Pro e atualmente está em BETA.</span>

A **Modelagem de Ameaças** transforma o design de uma funcionalidade em um modelo de ameaças revisado. Você fornece o design — texto colado, um documento de design e, opcionalmente, um diagrama de arquitetura — e o DefectDojo produz os componentes e fluxos de dados que ele descreve, as ameaças contra eles e os requisitos de segurança que mitigam essas ameaças. Os requisitos podem então ser enviados ao DefectDojo como achados, de modo que o trabalho da etapa de design passe pelo mesmo mecanismo de triagem, SLA, Jira e relatórios que tudo o mais.

Esta é a capacidade **pré-código** do Sensei. Enquanto o [scan-and-fix](/sensei/about_sensei/) atua sobre um repositório que já existe, a modelagem de ameaças atua sobre o design, antes de haver código para escanear.

> **🔎 BETA:** a Modelagem de Ameaças está em desenvolvimento ativo e é identificada como **BETA** em toda a interface. O comportamento e as telas podem mudar entre versões. Durante o BETA, ela é habilitada por instância pelo DefectDojo — entre em contato com seu representante DefectDojo para ativá-la.

> **📍 Onde encontrar:** abra **Threat Modeling** na navegação à esquerda, logo abaixo de Sensei.

## O que você precisa

- O recurso licenciado **Sensei**. A modelagem de ameaças é disponibilizada sob o mesmo direito de uso (entitlement) do scan-and-fix.
- Uma função global de **Maintainer** ou **Owner**. Usuários sem essa função não veem a página.
- Um produto ao qual anexar o modelo de ameaças. Instâncias que usam a nomenclatura 3.0 veem os produtos chamados de **assets**; esta página usa *produto* ao longo do texto, e a interface segue a nomenclatura configurada na sua instância.

Nada é instalado e nenhum repositório é conectado. A modelagem de ameaças lê apenas o design que você fornece.

## Gerando um modelo de ameaças

Escolha **New threat model**, selecione o produto, dê um nome a ele e forneça o design na forma que você tiver:

- **Cole a descrição** diretamente, ou
- **Faça upload de um documento de design** — `.md`, `.markdown`, `.txt`, `.text` ou `.pdf`. A extração de texto de PDF é feita em base de melhor esforço; se um PDF for majoritariamente composto de imagens, cole o texto em vez disso.
- **Opcionalmente, adicione um diagrama de arquitetura** — PNG, JPEG, WebP ou GIF. O diagrama é lido junto com o texto, então um componente que aparece apenas na imagem ainda assim é identificado.

Você pode combiná-los: um resumo curto colado junto com um diagrama costuma produzir um modelo melhor do que qualquer um dos dois isoladamente.

A geração roda em segundo plano e passa por quatro etapas, mostradas na execução conforme ela avança:

1. **Extraindo a arquitetura** — componentes, limites de confiança, ativos de dados e fluxos de dados.
2. **Enumerando ameaças** — ameaças por categoria STRIDE.
3. **Escrevendo requisitos de segurança** — requisitos testáveis, cada um vinculado às ameaças que mitiga.
4. **Montando os resultados** — o diagrama e as verificações finais de consistência.

Uma execução normalmente leva vários minutos. Você pode sair da página; o progresso e os resultados ficam salvos na execução.

## Lendo os resultados

### Arquitetura

A aba **Architecture** renderiza o que foi extraído como um diagrama de fluxo de dados: componentes agrupados por limite de confiança, com fluxos rotulados por protocolo. Fluxos que **cruzam um limite de confiança** são desenhados de forma diferente, porque são os mais relevantes. Selecionar um componente mostra as ameaças que o visam.

O modelo também registra o que ele **não** conseguiu determinar — premissas que precisou assumir e pontos que ficaram pouco claros no design. Leia esses pontos primeiro: eles indicam onde o próprio design é ambíguo, o que muitas vezes é o resultado mais útil do exercício.

### Ameaças

Cada ameaça traz:

- Sua **categoria STRIDE** (spoofing, tampering, repudiation, information disclosure, denial of service, elevation of privilege) e uma **severidade**.
- O **perfil do atacante** — por exemplo, um atacante externo não autenticado, um insider ou um comprometimento de supply chain — e o nível de habilidade exigido.
- Um **caminho de ataque** ordenado: os passos que um atacante seguiria, com pré-requisitos.
- Um **CWE**, quando aplicável, extraído de uma lista fixa em vez de inventado.
- Os **componentes, fluxos e ativos de dados** que ela visa.

### Requisitos de segurança

Cada requisito é escrito como uma afirmação testável, com uma etapa de **verificação** descrevendo como confirmar que ele se sustenta, uma categoria (autenticação, autorização, validação de entrada, criptografia, e assim por diante) e uma prioridade. Todo requisito nomeia as ameaças que mitiga.

A cobertura é registrada explicitamente: uma ameaça ou é mitigada por pelo menos um requisito, ou é listada como uma **lacuna de cobertura**. As lacunas são exibidas em vez de ocultadas, de modo que uma ameaça nunca é descartada silenciosamente.

## Evidências, e no que confiar

Todo componente, ameaça e requisito traz a **evidência** da qual se originou, e a evidência é rotulada por fonte:

- **Do texto do design** — uma citação que foi correspondida, palavra por palavra, com o texto que você forneceu.
- **Do diagrama** — lida a partir da imagem, então não há texto para citar.
- **Inferida** — não declarada no design de forma alguma.

Uma citação que não pôde ser correspondida ao texto fornecido é mantida, mas **sinalizada como não verificada**, com a citação alegada exibida para que você mesmo possa avaliá-la. Os itens são sinalizados em vez de removidos, porque uma ameaça descartada silenciosamente é um risco do qual ninguém fica sabendo. Itens estruturalmente quebrados — uma ameaça referenciando um componente que nunca foi extraído — são descartados, e a contagem do que foi descartado é registrada na execução.

**Trate o resultado como um rascunho para revisão, não como um artefato finalizado.** Ele é gerado a partir de um documento de design por um modelo de linguagem; os rótulos de evidência existem para que você possa ver quais partes estão fundamentadas no que você escreveu e quais são inferência.

## Enviando requisitos para achados

Os requisitos se tornam acionáveis por meio de **Push to findings**. Selecione os requisitos desejados e o DefectDojo cria um achado por requisito, em um engajamento dedicado chamado **Sensei Threat Modeling** nesse produto, com um teste por versão do modelo de ameaças.

Cada achado traz:

- A declaração do requisito, além da narrativa de cada ameaça que ele mitiga — categoria STRIDE, atacante e o caminho de ataque numerado — para que quem pegar o ticket tenha o contexto sem precisar abrir o modelo de ameaças.
- A etapa de verificação como mitigação.
- A severidade e o CWE do requisito.
- A tag `sensei-threat-model`, uma tag `tm-v<version>` e uma tag STRIDE.

Os achados são criados **ativos, porém não verificados**: um requisito gerado é uma proposta para um humano confirmar.

O envio (push) é **idempotente**. Cada requisito é dono do seu achado, então enviar o mesmo modelo novamente atualiza no lugar em vez de criar duplicatas — e se você editar um requisito e enviar de novo, o achado acompanha a mudança. Reenviar não reescreve quem levantou o achado originalmente.

## Versões e substituição

Os modelos de ameaças são **versionados por produto**. Regenerar a partir de um design atualizado cria uma nova versão em vez de sobrescrever a antiga, então você mantém o histórico de como o design estava quando uma decisão foi tomada.

Quando você envia uma versão mais recente, os achados da versão anterior que não correspondem mais a um requisito atual são marcados como **mitigados** em vez de deixados em aberto, para que o engajamento reflita o design atual.

## Exportação

Um modelo de ameaças pode ser baixado como **Markdown** para uma revisão de design ou ticket, ou como **JSON** para qualquer uso programático. Ambos estão disponíveis a partir do próprio modelo de ameaças.

## Atividade de geração

A aba **Activity** lista todas as gerações, seu status e a etapa alcançada. Execuções em andamento podem ser **canceladas**. Uma execução malsucedida mostra **por que** falhou — um problema de configuração, uma entrada longa demais ou um erro temporário de serviço — e as etapas concluídas ficam registradas (checkpoint), de modo que tentar novamente retoma de onde parou em vez de começar do zero.

## Custos

A modelagem de ameaças chama um modelo de linguagem de grande porte (LLM), e cada geração tem um custo. Uma geração faz aproximadamente oito chamadas, e o uso é registrado por execução junto com os demais usos de LLM do Sensei, então você pode ver quanto custou produzir um modelo. Cancelar uma execução interrompe chamadas adicionais no próximo limite de etapa.
