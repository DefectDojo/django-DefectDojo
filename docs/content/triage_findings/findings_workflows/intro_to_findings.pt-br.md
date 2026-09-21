---
title: Introdução aos Achados
description: O principal fluxo de trabalho e sistema de rastreamento de vulnerabilidades
  do DefectDojo
weight: 1
aliases:
- /pt-br/en/working_with_findings/intro_to_findings
---

Os Achados são a principal forma pela qual o DefectDojo padroniza e orienta o processo de relatório e remediação das suas ferramentas de segurança. Independentemente de uma vulnerabilidade ter sido relatada no SonarQube, no Acunetix ou na ferramenta personalizada da sua equipe, os Achados oferecem a capacidade de gerenciar cada vulnerabilidade da mesma forma.

## O que são Achados?

Os Achados no DefectDojo são compostos pelos seguintes componentes: 

* Os dados da vulnerabilidade relatada em questão
* O “status” do Achado, usado para acompanhar a remediação, a aceitação de risco ou outras decisões tomadas em relação à vulnerabilidade
* Outros metadados relacionados ao Achado. Por exemplo, isso pode incluir a localização de um Achado na sua rede, sugestões de remediação de uma ferramenta, ou links para uma CWE ou pontuação EPSS associada.

Além de armazenar os dados da vulnerabilidade e fornecer uma estrutura de remediação, o DefectDojo também aprimora seus Achados das seguintes formas:

* Adicionando automaticamente pontuações EPSS relacionadas a um Achado para descrever a explorabilidade
* Traduzindo automaticamente a métrica de severidade de uma ferramenta de segurança em uma pontuação de Severidade para cada Achado, o que atribui um SLA ao Achado de acordo com a Configuração de SLA do seu Produto.

No geral, os Achados do DefectDojo são projetados para funcionar com a Hierarquia de Produtos, padronizando seus esforços e aplicando um método consistente a cada Produto.

## Uma Página de Achado

A Página de Achado contém vários componentes. Cada um deles será preenchido pelo processo de Importação quando o Achado for criado.

![image](images/Introduction_to_Findings.png)

1. **O Título do Achado:** Normalmente, é um resumo descritivo que identifica a vulnerabilidade ou o problema detectado. Esta seção também é onde as Tags criadas pelo usuário são exibidas, caso existam.  
​
2. **Visão Geral do Achado:** Esta seção contém cinco páginas separadas com informações relevantes sobre o Achado: Descrição, Mitigação, Impacto, Referências e Notas. Esses campos podem ser preenchidos automaticamente com base nos dados de vulnerabilidade recebidos, ou podem ser editados por um usuário do DefectDojo para fornecer contexto adicional.  
​  
- ​**Descrição** é um resumo mais detalhado e uma explicação do Achado em questão.  
- ​**Mitigação** é um método sugerido para mitigar o Achado, de modo que ele deixe de estar presente no seu sistema.  
- ​**Impacto** descreve o impacto da vulnerabilidade na sua postura de segurança. Esta página pode conter texto descritivo, ou pode incluir uma [String de Vetor CVSS](https://qualysguard.qualys.com/qwebhelp/fo_portal/setup/cvss_vector_strings.htm), que é uma forma resumida de comunicar a explorabilidade geral da vulnerabilidade e as consequências de uma exploração para a sua organização. O Impacto está diretamente relacionado ao campo de Severidade de um Achado.  
- ​**Referências** lista quaisquer links ou informações adicionais relevantes para este Achado, caso tenham sido incluídos.  
- ​**Notas** é uma página onde você pode registrar qualquer outra informação relevante para este Achado. As Notas são metadados “exclusivos do DefectDojo”, e não são criadas no momento da importação. Use este campo para acompanhar seu progresso de mitigação ou para adicionar detalhes mais específicos ao Achado.  
​
3. **Detalhes Adicionais:** Esta seção lista outros detalhes relacionados a este Achado, se relevantes:


	* Pares de Requisição/Resposta associados à vulnerabilidade
	* Passos para Reproduzir a vulnerabilidade
	* Justificativa de Severidade, onde você pode registrar uma explicação mais detalhada da severidade ou do impacto do Achado.  
	​  

4. **Metadados: Esta seção contém metadados filtráveis relacionados ao Achado:**


	* **ID:** o valor de ID do Achado no DefectDojo
	* **Severidade:** o valor de Severidade do Achado. Pode ser Informativa, Baixo, Médio, Alto ou Crítica. As Severidades dos Achados estão diretamente relacionadas ao SLA calculado do Achado, com base no Produto em que o Achado está armazenado.
	* **Status:** o status do Achado. Pode ser Ativo ou Inativo. Além desses, os Achados também podem ter o status Duplicado, Mitigado, Falso positivo, Fora do escopo, Risco aceito ou Em Revisão de Defeito. Esses Status explicam o Estado do Achado com mais detalhes.
	* **Tipo:** este campo descreve como o Achado foi encontrado, seja por meio de uma avaliação Estática (SAST) do código-fonte, seja por meio de uma avaliação Dinâmica (DAST) do Produto em execução. Este campo é definido pelo tipo de ferramenta.
	* **Localização:** este campo descreve o Caminho de Arquivo relacionado à sua vulnerabilidade, se relevante.
	* **Linha:** este campo descreve a linha de código que contém a vulnerabilidade, se relevante.
	* **Data de Descoberta:** este campo mostra a data em que o Achado foi importado para o DefectDojo, ou a data em que o Achado foi descoberto pela Ferramenta.
	* **Idade:** este campo calculado mostra o número de dias em que o Achado esteve ativo.
	* **Relator:** este é o nome de usuário da conta do DefectDojo que criou este Achado.
	* **CWE:** este campo é um link para a definição externa de CWE (Common Weakness Enumeration) aplicável a este Achado.
	* **ID da Vulnerabilidade:** se houver um valor de ID específico para esta vulnerabilidade dentro da própria ferramenta, ele será registrado aqui.
	* **Pontuação EPSS / Percentil:** se os dados de origem tiverem um valor de CWE, o DefectDojo buscará automaticamente uma [Pontuação EPSS](https://www.first.org/epss/) e o Percentil (Exploit Prediction Scoring System). O EPSS representa a probabilidade de uma vulnerabilidade de software ser explorada, com base em dados reais de exploração. As pontuações EPSS são atualizadas continuamente, usando os dados de exploração mais recentes do First.
	* **Encontrado Por:** Isso lista o scanner usado para encontrar esta vulnerabilidade.  
	​

## Notas e @menções

A página de **Notas** de um Achado é onde sua equipe registra o contexto que não faz parte dos dados do scan importado — progresso de mitigação, decisões de triagem ou qualquer outro comentário. As Notas são metadados exclusivos do DefectDojo e nunca são criadas no momento da importação.

As Notas aparecem como um feed, das mais recentes para as mais antigas, e você pode inverter a ordem para mostrar as mais antigas primeiro. Cada nota exibe seu autor, quando foi escrita, seu tipo de nota, e um selo de **Private** quando a nota é privada. Uma nota privada só é exibida para a pessoa que a escreveu.

### Escrevendo notas em markdown

As entradas de notas suportam markdown, então você pode usar títulos, texto em **negrito** e *itálico*, listas com marcadores e numeradas, citações em bloco, tabelas, links e blocos de código. O editor de notas é o mesmo usado para a descrição de um Achado, com uma barra de ferramentas para as opções de formatação mais comuns. Para ler uma nota exatamente como foi digitada, em vez de como texto formatado, use o alternador no canto superior direito do corpo da nota.

### Edição, exclusão e histórico

Toda nota possui um menu de ações com **Edit**, **View History** e **Delete**, e cada item só aparece quando você tem permissão para usá-lo:

* Você sempre pode editar, excluir e ler o histórico de uma nota que você mesmo escreveu.
* Para gerenciar a nota de outra pessoa, você precisa da permissão de papel correspondente no objeto ao qual a nota pertence: Note Edit, Note Delete ou Note View History.
* Adicionar uma nota requer Note Add, permissão que todo papel acima de Reader possui, assim como o Reader também possui.

Uma nota editada é rotulada como **(edited)** e registra quem a alterou e quando. **View History** lista todas as revisões da nota, das mais recentes para as mais antigas, para que nada se perca quando uma nota é reescrita. Apenas o próprio texto pode ser alterado: o tipo da nota e sua marcação de privada são fixos após a criação da nota.

### Mencionando um usuário com @

Ao adicionar uma nota, você pode **@mencionar** outro usuário do DefectDojo para notificá-lo. Digite `@` imediatamente seguido do nome de usuário dele (por exemplo, `@alice`) em qualquer lugar da nota. Ao salvar a nota, cada usuário mencionado recebe uma notificação de **user-mentioned** que aponta de volta para a nota.

Alguns detalhes que vale a pena conhecer:

* O `@` deve estar no **início da nota ou logo após um espaço**. Isso é proposital — evita que endereços de e-mail escritos no meio de uma frase (como `alice@example.com`) disparem menções acidentais.
* O nome após o `@` deve corresponder a um nome de usuário do DefectDojo **existente e ativo**. Menções a usuários desconhecidos ou desativados são ignoradas.
* Um ponto final é ignorado, portanto uma menção que encerra uma frase (`thanks @alice.`) ainda é resolvida corretamente.
* Você pode mencionar mais de um usuário em uma única nota.

Você pode @mencionar usuários pela interface em notas de **Achados**, **Testes**, **Engajamentos** e **Aceitações de Risco**. Digitar `@` abre uma lista de usuários correspondentes; selecionar um dessa lista é a forma confiável de mencionar alguém, pois insere o nome de usuário exatamente como a busca de notificação espera.

A menção é entregue por meio do evento de notificação `user_mentioned`. Consulte [Notifications](/admin/notifications/about_notifications/) para saber como as notificações são entregues e configuradas — em particular, `user_mentioned` é um dos eventos que uma configuração em nível de sistema ainda pode entregar mesmo quando um usuário silenciou suas notificações (veja [Specific overrides](/admin/notifications/about_notifications/#specific-overrides)).

## Exemplos de Fluxos de Trabalho de Achados

A forma como você trabalha com Achados no DefectDojo depende das responsabilidades da sua equipe dentro da organização. Aqui estão alguns exemplos desses processos e como o DefectDojo pode ajudar:

### Descobrir e Relatar vulnerabilidades

Se você é responsável pelos relatórios de segurança de diversos contextos, Produtos de software ou equipes, o DefectDojo pode gerar relatórios sobre as vulnerabilidades descobertas. Usando a Hierarquia de Produtos, você pode organizar seus dados de Achados no contexto adequado. Por exemplo:

* Cada Produto no DefectDojo pode ter uma configuração de SLA diferente, para que você possa sinalizar instantaneamente os Achados descobertos em Produção ou em outros ambientes altamente sensíveis.
* Você pode criar um relatório diretamente a partir de um **Tipo de Produto, Produto, Engajamento ou Teste** para “aproximar e afastar” seu contexto de segurança. **Testes** contêm resultados de uma única ferramenta, **Engajamentos** podem combinar vários Testes, **Produtos** podem conter vários Engajamentos, **Tipos de Produto** podem conter vários Produtos.

Para mais informações sobre como criar um Relatório, consulte nossos guias de **[Relatórios Personalizados](/metrics_reports/reports/)**.

### Triagem de Vulnerabilidades usando o Status do Achado

Se sua equipe precisa validar os Achados descobertos, você pode fazer isso aplicando manualmente o status **Verificado** aos Achados à medida que os revisa. Você também pode aplicar outros status, como:

* **Falso positivo:** Uma ferramenta detectou a ameaça, mas ela não está ativa no ambiente.
* **Fora do escopo:** Ativo, mas irrelevante para o esforço de teste atual.
* **Risco aceito:** Ativo, mas determinado como não prioritário para resolução até que a Aceitação de Risco expire.
* **Em Revisão:** pode ou não estar Ativo \- sua equipe ainda está investigando.
* **Mitigado:** Este problema foi resolvido desde a criação do Achado.

Se uma ferramenta relatar um Achado previamente triado em uma importação subsequente, o DefectDojo lembrará o status anterior do Achado e o atualizará de acordo. Os Achados com status **Falso positivo**, **Fora do escopo, Risco aceito e Em Revisão** permanecerão como estão, mas qualquer Achado que tenha sido **Mitigado** será **reativado** para informar que o Achado retornou ao ambiente de Teste.

### Garanta Consenso e Responsabilidade em Toda a Equipe com Aceitações de Risco

Parte da responsabilidade de uma equipe de segurança é colaborar com os desenvolvedores para priorizar e despriorizar a remediação de problemas de segurança. É aí que entram as Aceitações de Risco. Adicionar uma Aceitação de Risco a um Achado permite que você:

* Armazene registros e arquivos de “artefato” no DefectDojo \- estes podem ser e-mails de colegas reconhecendo a Aceitação de Risco, notas de reunião, ou simplesmente uma justificativa escrita da sua própria equipe de segurança para aceitar o risco.
* Adicione uma data de expiração à Aceitação de Risco, para que a vulnerabilidade possa ser reexaminada após um determinado período de tempo.

Qualquer membro de uma equipe de Appsec entende que a mitigação de problemas não pode ser priorizada exclusivamente pelas equipes de desenvolvimento, então as Aceitações de Risco ajudam a registrar essas decisões sensíveis no momento em que são tomadas.

### Monitore vulnerabilidades atuais usando CVEs e pontuações EPSS (Recurso Pro)

Às vezes, a explorabilidade e a ameaça representada por uma vulnerabilidade conhecida podem mudar com base em novos dados. Para manter seu trabalho atualizado, o DefectDojo Pro fez uma parceria com a First.org para manter um banco de dados com as pontuações EPSS mais recentes relacionadas aos Achados. Todos os Achados no DefectDojo Pro serão mantidos atualizados automaticamente de acordo com seu EPSS, que é baseado diretamente na CVE do Achado.

Se a pontuação EPSS de um Achado mudar (ou seja, o Achado relacionado se tornar mais ou menos explorável), a Severidade do Achado será ajustada de acordo.
