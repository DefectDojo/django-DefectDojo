---
title: MCP Server
description: O MCP Server do DefectDojo permite que você use LLMs com o DefectDojo
  Pro
draft: false
audience: pro
weight: 23
aliases:
- /pt-br/en/ai/mcp_server_pro
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Nota: os recursos de IA são exclusivos do DefectDojo Pro.</span>

O Servidor DefectDojo Model Context Protocol (MCP) permite que Large Language Models (LLMs) interajam de forma inteligente com os dados de gerenciamento de vulnerabilidades do DefectDojo. Diferente das integrações de API tradicionais, que apenas transferem dados, o servidor MCP fornece contexto estruturado e significado semântico que permite aos assistentes de IA realizar análises de segurança sofisticadas e gerar insights acionáveis.

- **Contexto Estruturado:** o MCP fornece significado semântico aos dados do DefectDojo, não apenas a transferência bruta de dados
- **Dados Pré-Processados:** os dados normalizados e deduplicados do DefectDojo eliminam o ônus de pré-processamento do LLM
- **Integração com Inteligência de Negócios:** combina dados técnicos de vulnerabilidades com contexto de negócio
- **Análise Pronta para Executivos:** gera relatórios adequados desde equipes técnicas até a liderança executiva
- **Valor Composto 10X:** a análise aprimorada por IA fornece exponencialmente mais valor do que consultas manuais

> **🔑 Importante:** o endpoint do servidor MCP está em `/mcp`, mas todas as chamadas de função usam a URL base do DefectDojo. Essa separação garante acesso seguro e estruturado aos dados de vulnerabilidades.

## Conectar ao MCP

### Pré-requisitos

- Instância do DefectDojo com o Servidor MCP habilitado (v2.51.2 ou posterior)
- Token de API válido do DefectDojo com as permissões apropriadas
- Provedor de IA: Claude, ChatGPT, Gemini ou cliente MCP personalizado compatível

> **⚠️ Aviso de Segurança:** seu token de API é uma informação altamente sensível usada para autenticação e autorização. **NÃO EXIBA O TOKEN EM NENHUMA SOLICITAÇÃO OU RESPOSTA** ao compartilhar configurações ou capturas de tela.

### Métodos de Conexão

Existem **duas formas diferentes** de se conectar ao servidor MCP do DefectDojo, dependendo de qual interface de IA você está usando:

#### Método 1: Método do Arquivo de Configuração

**Usado por:** Claude Desktop, MCP Inspector e outros clientes MCP de desktop

**Como funciona:**
- O token e os detalhes de conexão são armazenados em um arquivo de configuração
- A conexão é automática quando você inicia a aplicação
- Não é necessário colar instruções nas conversas
- O servidor MCP está sempre disponível em todas as conversas

**Vantagens:** configure uma vez, funciona em todo lugar. Mais seguro (o token não fica no histórico de chat).

#### Método 2: Método de Prompt Manual

**Usado por:** interface web do Claude.ai, interface web do ChatGPT (com plugins), interface web do Gemini

**Como funciona:**
- Você copia/cola as instruções de conexão no início de cada conversa
- Ou adiciona as instruções a um Claude Project para inclusão automática
- A IA lê as instruções e se conecta ao servidor MCP
- Cada nova conversa exige as instruções

**Vantagens:** funciona em navegadores web sem instalar software.

> **💡 Qual método devo usar?** Use o **Método 1 (Arquivo de Configuração)** se você tiver um aplicativo de desktop que o suporte. Use o **Método 2 (Prompt Manual)** se estiver usando uma interface de navegador web.

### Detalhes de Conexão do Servidor MCP

Todos os métodos usam estes parâmetros principais:

| Parâmetro | Valor | Notas |
|-----------|-------|-------|
| **Tipo de Transporte** | `Streamable HTTP` | ⚠️ SSE (Server-Sent Events) está descontinuado |
| **URL do Endpoint MCP** | `https://[YOUR-INSTANCE].defectdojo.com/mcp` | Usado para estabelecer a conexão MCP |
| **URL Base para Funções** | `https://[YOUR-INSTANCE].defectdojo.com/` | Usado em todas as chamadas de função de ferramenta |
| **Autenticação** | `Authorization: Token [YOUR_API_TOKEN]` | ⚠️ Use o prefixo "Token", não "Bearer" |

## Guias de Início Rápido por Provedor de IA

<details>
<summary><h3>🖥️ Claude Desktop (Método 1: Arquivo de Configuração)</h3></summary>

**Passo 1: Localize seu arquivo de configuração**

- **macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows:** `%APPDATA%\Claude\claude_desktop_config.json`
- **Linux:** `~/.config/Claude/claude_desktop_config.json`

**Passo 2: Edite o arquivo de configuração**

Adicione ou atualize a seção `mcpServers` com os detalhes da sua instância do DefectDojo:

```json
{
  "mcpServers": {
    "DefectDojo-MCP": {
      "command": "npx",
      "args": [
        "mcp-remote",
        "https://your-instance.defectdojo.com/mcp",
        "--header",
        "Authorization: Token YOUR_API_TOKEN"
      ]
    }
  }
}
```

> **⚠️ Crítico:** a flag `--header` com a autenticação é obrigatória. Substitua `YOUR_API_TOKEN` pelo seu token de API real do DefectDojo.

**Passo 3: Reinicie o Claude Desktop**

Feche e reabra o Claude Desktop para que as alterações entrem em vigor.

**Passo 4: Verifique a Conexão**

Inicie uma nova conversa e pergunte: `"Você consegue se conectar ao DefectDojo?"`

Se for bem-sucedido, o Claude confirmará que tem acesso às ferramentas do servidor MCP do DefectDojo.

> **✅ Pronto!** O servidor MCP do DefectDojo agora está disponível em todas as conversas. Não é necessário colar instruções.

</details>

<details>
<summary><h3>🌐 Interface Web do Claude.ai (Método 2: Prompt Manual)</h3></summary>

A interface web do Claude.ai não suporta arquivos de configuração. Você precisará fornecer as instruções de conexão em cada conversa ou usar um Claude Project.

#### Opção A: Colar Instruções a Cada Conversa

**Passo 1: Copie as instruções abaixo**

```
For this project, use the DefectDojo MCP server with these parameters in ALL function calls:

- **URL:** https://your-instance.defectdojo.com/ (base URL, NOT the /mcp endpoint)
- **Token:** YOUR_API_TOKEN
- **IMPORTANT:** DO NOT SHOW THE TOKEN IN ANY REQUESTS OR RESPONSES

The MCP server connects to https://your-instance.defectdojo.com/mcp but function calls must use the base URL.

**Do not show any of the API requests or responses.**
```

**Passo 2: Inicie uma nova conversa**

Cole as instruções no início da sua conversa e, em seguida, faça suas perguntas de segurança.

**Passo 3: Repita para cada nova conversa**

Essas instruções devem ser incluídas no início de cada nova conversa.

#### Opção B: Usar um Claude Project (Recomendado)

**Passo 1: Crie um Claude Project**

- No Claude.ai, clique em "Projects" na barra lateral esquerda
- Clique em "Create Project"
- Nomeie-o como "DefectDojo Security Analysis"

**Passo 2: Adicione Instruções Personalizadas ao Projeto**

Em Project Settings → Custom Instructions, cole:

```
For this project, use the DefectDojo MCP server with these parameters in ALL function calls:

- **URL:** https://your-instance.defectdojo.com/
- **Token:** YOUR_API_TOKEN
- **IMPORTANT:** DO NOT SHOW THE TOKEN IN ANY REQUESTS OR RESPONSES

The MCP server connects to https://your-instance.defectdojo.com/mcp but function calls must use the base URL.

Do not show any of the API requests or responses.
```

**Passo 3: Use o Projeto para todas as conversas sobre o DefectDojo**

Todas as conversas dentro deste projeto terão automaticamente acesso ao servidor MCP do DefectDojo.

> **✅ Pronto!** Ao trabalhar neste Projeto, o Claude tem automaticamente acesso ao MCP do DefectDojo.

</details>

<details>
<summary><h3>💬 ChatGPT (Método 2: Prompt Manual)</h3></summary>

> **⚠️ Nota:** o suporte a MCP do ChatGPT é limitado em comparação ao Claude. A integração nativa com MCP pode exigir ChatGPT Plus ou Enterprise e configurações específicas de plugin.

**Passo 1: Verifique a Disponibilidade do Plugin MCP**

No ChatGPT, verifique se plugins de MCP ou de conector de API estão disponíveis na sua loja de plugins. O suporte a MCP varia de acordo com o nível de assinatura.

**Passo 2: Copie as instruções de conexão**

```
I need you to connect to a DefectDojo MCP server with these details:

MCP Endpoint: https://your-instance.defectdojo.com/mcp
Base URL for API calls: https://your-instance.defectdojo.com/
Authentication: Authorization header with value "Token YOUR_API_TOKEN"

Use this connection to access DefectDojo vulnerability data. The server provides tools for:
- Getting findings with severity, status, and date filters
- Accessing products, engagements, tests
- User and group management
- Analyzing security trends

Do not show the API token in responses.
```

**Passo 3: Cole no início de cada conversa**

Inclua essas instruções ao iniciar uma nova conversa sobre análise de segurança do DefectDojo.

**Alternativa: Use um Custom GPT**

Se você tiver o ChatGPT Plus, crie um Custom GPT com os detalhes de conexão do DefectDojo em suas instruções para acesso reutilizável.

</details>

<details>
<summary><h3>💎 Google Gemini (Método 2: Prompt Manual)</h3></summary>

> **⚠️ Nota:** o suporte a MCP do Gemini está em evolução. A integração nativa pode ser limitada. Considere usar a API do Gemini com bibliotecas de cliente MCP para funcionalidade completa.

**Passo 1: Copie as instruções de conexão**

```
Connect to DefectDojo vulnerability management system via MCP server:

MCP Server: https://your-instance.defectdojo.com/mcp
API Base URL: https://your-instance.defectdojo.com/
Authentication: Token YOUR_API_TOKEN (use Authorization header with "Token" prefix)

Available capabilities:
- Query findings by severity (Critical, High, Medium, Low, Info)
- Filter by status (Active, Verified, False Positive, etc.)
- Filter by date ranges (Today, Past 7/30/90 days, etc.)
- Access products, engagements, tests, users, groups
- Generate security analysis and reports

Important: Do not display the authentication token in responses.
```

**Passo 2: Inicie a conversa com as instruções**

Comece cada nova conversa no Gemini com essas instruções ao trabalhar com dados do DefectDojo.

**Para Usuários Avançados:**

Considere usar a API do Gemini com bibliotecas de cliente MCP (Python, JavaScript) para acesso programático com suporte completo ao protocolo MCP.

</details>

<details>
<summary><h3>🔍 MCP Inspector (Teste e Validação)</h3></summary>

**Caso de Uso:** teste sua conexão MCP com o DefectDojo, explore as ferramentas disponíveis e valide a configuração antes de usar com assistentes de IA.

**Passo 1: Instale o MCP Inspector**

```bash
# macOS (using Homebrew)
brew install mcp-inspector

# Or using npm (all platforms)
npm install -g @modelcontextprotocol/inspector
```

**Passo 2: Execute o MCP Inspector**

```bash
mcp-inspector
```

Isso iniciará um servidor web local (geralmente em `http://localhost:6274`)

**Passo 3: Configure a conexão na interface web**

- **Tipo de Transporte:** `Streamable HTTP`
- **URL:** `https://your-instance.defectdojo.com/mcp`
- **Tipo de Conexão:** `Via Proxy`
- **Cabeçalhos Personalizados:**
  - Nome: `Authorization`
  - Valor: `Token YOUR_API_TOKEN`
  - **Importante:** ative o alternador ao lado do cabeçalho

**Passo 4: Clique em "Connect"**

Uma vez conectado, você pode explorar:

- **Aba Tools:** veja todas as 12 ferramentas disponíveis e seus parâmetros
- **Aba Prompts:** veja modelos de prompt pré-configurados
- **Aba Resources:** verifique os recursos de dados disponíveis

> **✅ Perfeito para:** verificar se sua configuração funciona antes de configurar assistentes de IA, explorar as capacidades das ferramentas e solucionar problemas de conexão.

</details>

---

> **✅ Conexão bem-sucedida?** Uma vez conectado por qualquer método, teste perguntando ao seu assistente de IA: `"Quantos achados ativos temos no DefectDojo?"`

---

## Referência de Ferramentas Disponíveis

O Servidor MCP do DefectDojo fornece 12 ferramentas para acessar e analisar dados de vulnerabilidades. Cada ferramenta inclui tratamento inteligente de parâmetros e retorna dados estruturados otimizados para análise por LLM.

> **💡 Nota sobre Parâmetro:** todas as ferramentas aceitam um parâmetro `token` opcional. Se não for fornecido em chamadas individuais, o LLM usará o token da configuração de conexão.

---

### 🔍 Ferramentas de Análise de Achados

<details>
<summary><h4>get_findings</h4></summary>

**Descrição:** recupera achados do DefectDojo com recursos sofisticados de filtragem. Esta é a ferramenta mais poderosa e frequentemente usada para análise de vulnerabilidades.

**Parâmetros:**

**severity** (Opcional)
- **Tipo:** Array de strings
- **Valores:** `Critical`, `High`, `Medium`, `Low`, `Info`
- **Exemplo:** `["Critical", "High"]`
- **Uso:** filtra achados por nível de severidade. Múltiplos valores podem ser fornecidos para consultas compostas.

**status** (Opcional)
- **Tipo:** Array de strings
- **Valores:** `Any`, `Active`, `Open`, `Verified`, `Out of Scope`, `False Positive`, `Inactive`, `Risk Accepted`, `Closed`, `Under Review`
- **Exemplo:** `["Active", "Verified"]`
- **Uso:** filtra achados pelo status atual. Use `Active` para avaliação de risco atual.

**date** (Opcional)
- **Tipo:** Array com um único valor string
- **Valores:** `0 - Any date`, `1 - Today`, `2 - Past 7 days`, `3 - Past 30 days`, `4 - Past 90 days`, `5 - Current month`, `6 - Current year`, `7 - Past year`
- **Exemplo:** `["3 - Past 30 days"]`
- **Uso:** filtra achados pela data de descoberta. Apenas um valor é permitido.

**limit** (Opcional)
- **Tipo:** Número
- **Padrão:** 100
- **Intervalo:** 1-100
- **Uso:** número de achados a retornar. Para apenas contagens, defina como 1 e use a propriedade count na resposta.

**offset** (Opcional)
- **Tipo:** Número
- **Padrão:** 0
- **Uso:** deslocamento de paginação para recuperar resultados adicionais.

> **💡 Boa Prática:** para consultas de avaliação de risco, sempre use `status: ["Active"]` para focar em vulnerabilidades atuais e não resolvidas, em vez de dados históricos.

**Exemplo de Consulta:**

**O usuário pergunta:** "Mostre todos os achados ativos de severidade Crítica e Alta dos últimos 30 dias"

**O LLM chama:**
```
get_findings({
  severity: ["Critical", "High"],
  status: ["Active"],
  date: ["3 - Past 30 days"],
  limit: 100
})
```

</details>

<details>
<summary><h4>get_finding_by_id</h4></summary>

**Descrição:** recupera informações detalhadas sobre um achado específico usando seu identificador único.

**Parâmetros:**

**finding_id** (Obrigatório)
- **Tipo:** Número
- **Mínimo:** 1
- **Uso:** o ID único do achado a recuperar.

**Exemplo de Consulta:**

**O usuário pergunta:** "Obtenha os detalhes do achado #1234"

**O LLM chama:** `get_finding_by_id({ finding_id: 1234 })`

</details>

---

### 📦 Ferramentas de Produto e Engajamento

<details>
<summary><h4>get_products</h4></summary>

**Descrição:** recupera todos os produtos do DefectDojo. Produtos representam aplicações, serviços ou sistemas em teste.

**Parâmetros:**

**limit** (Opcional)
- **Padrão:** 100
- **Uso:** número máximo de produtos a retornar.

**offset** (Opcional)
- **Padrão:** 0
- **Uso:** deslocamento de paginação.

</details>

<details>
<summary><h4>get_product_types</h4></summary>

**Descrição:** recupera categorias de tipo de produto do DefectDojo. Os tipos de produto ajudam a organizar produtos em agrupamentos lógicos.

**Parâmetros:** iguais a `get_products`

</details>

<details>
<summary><h4>get_engagements</h4></summary>

**Descrição:** recupera engajamentos de teste de segurança. Engajamentos representam atividades de teste específicas ou períodos de tempo para um produto.

**Parâmetros:** iguais a `get_products`

</details>

<details>
<summary><h4>get_tests</h4></summary>

**Descrição:** recupera testes de segurança do DefectDojo. Testes contêm resultados de varredura de ferramentas de segurança específicas ou testes manuais.

**Parâmetros:** iguais a `get_products`

</details>

---

### 👥 Ferramentas de Gerenciamento de Usuários e Acesso

<details>
<summary><h4>get_users</h4></summary>

**Descrição:** recupera todos os usuários do DefectDojo para análise de stakeholders e mapeamento de responsabilidades.

**Parâmetros:**

**limit** (Opcional)
- **Padrão:** 100

**offset** (Opcional)
- **Padrão:** 0

</details>

<details>
<summary><h4>get_user_by_id</h4></summary>

**Descrição:** recupera informações detalhadas sobre um usuário específico.

**Parâmetros:**

**user_id** (Obrigatório)
- **Tipo:** Número
- **Mínimo:** 1

</details>

<details>
<summary><h4>get_groups</h4></summary>

**Descrição:** recupera grupos de usuários para análise de estrutura organizacional e mapeamento de permissões.

**Parâmetros:** iguais a `get_users`

</details>

<details>
<summary><h4>get_group_by_id</h4></summary>

**Descrição:** recupera informações detalhadas sobre um grupo específico.

**Parâmetros:**

**group_id** (Obrigatório)
- **Tipo:** Número
- **Mínimo:** 1

</details>

<details>
<summary><h4>get_dojo_group_members</h4></summary>

**Descrição:** recupera todos os membros de um grupo específico para análise de equipe.

**Parâmetros:**

**group_id** (Obrigatório)
- **Tipo:** Número
- **Mínimo:** 1

**limit** (Opcional)
- **Padrão:** 100

**offset** (Opcional)
- **Padrão:** 0

</details>

<details>
<summary><h4>get_roles</h4></summary>

**Descrição:** recupera definições de papéis do DefectDojo para entender as estruturas de permissão.

**Parâmetros:** iguais a `get_users`

</details>

---

## Prompts Pré-Configurados

O Servidor MCP do DefectDojo inclui prompts pré-configurados que demonstram boas práticas para cenários comuns de análise. Esses prompts podem ser invocados diretamente pelo seu assistente de IA.

### 🛡️ Relatório de Revisão SAST

**Propósito:** criar um relatório abrangente avaliando a eficácia das ferramentas de SAST (Static Application Security Testing) com base nos dados do DefectDojo.

**A Análise Gerada Inclui:**

- Taxas de falso positivo por ferramenta e tipo de vulnerabilidade
- Tempo médio até a remediação por nível de severidade
- Vulnerabilidades críticas que aparecem múltiplas vezes (lacunas de deduplicação)
- Comparação de desempenho entre equipes de desenvolvimento
- Recomendações para melhorias na configuração das ferramentas
- Lacunas de treinamento identificadas a partir de padrões recorrentes de vulnerabilidade
- Análise de custo da abordagem de ferramentas atual vs. recomendada

**Formato de Saída:** relatório de avaliação técnica em HTML, adequado para justificar solicitações de orçamento de ferramentas de segurança.

### 📊 Relatório de Panorama de Segurança

**Propósito:** criar um relatório em estilo painel fornecendo uma visão geral do panorama de segurança com base nos dados do DefectDojo, adequado para reuniões trimestrais do conselho.

**A Análise Gerada Inclui:**

- Tendências de vulnerabilidade nos últimos 90 dias
- Equipes de desenvolvimento com os achados de severidade crítica/alta mais elevados
- Exposição a risco por produto e tipo de produto
- Top 5 categorias de CWE que exigem atenção imediata
- Ações de remediação específicas com análise de custo-benefício
- Roteiro de 6 meses para melhorar a postura de segurança

**Formato de Saída:** relatório em HTML de nível executivo com elementos visuais, cartões de estatísticas e foco em risco de negócio.

> **💡 Usando Prompts:** para invocar um prompt, basta perguntar ao seu assistente de IA: "Create a SAST Review Report" ou "Generate a Security Landscape Report using DefectDojo data"

---

## Exemplos de Casos de Uso

### Caso de Uso 1: Painel Executivo de Segurança

**Cenário:** o CISO precisa de métricas trimestrais de segurança para uma apresentação ao conselho

**Prompt do Usuário:**

```
"Create an executive security dashboard for our Q4 board meeting showing:
- Total vulnerability counts by severity
- Trends over the past 90 days  
- Which products have the highest risk exposure
- Top 5 vulnerability categories needing attention
- Specific remediation recommendations with ROI
- A 6-month roadmap for improving our security posture"
```

**O que acontece nos bastidores:**

1. `get_findings` - obtém as contagens totais de achados ativos
2. `get_findings` - análise de severidade Crítica e Alta
3. `get_findings` - dados de tendência dos últimos 90 dias
4. `get_products` - distribuição de vulnerabilidades por produto
5. `get_engagements` - atividades de teste recentes

**Saída Gerada:** relatório em HTML de nível executivo com tendências de vulnerabilidade, exposição a risco por produto, principais categorias de CWE, ações de remediação específicas com ROI e roteiro de segurança de 6 meses.

---

### Caso de Uso 2: Análise de Desempenho das Equipes de Desenvolvimento

**Cenário:** um gerente de engenharia quer entender quais equipes precisam de treinamento adicional em segurança

**Prompt do Usuário:**

```
"Which development teams have the most security findings? What types of vulnerabilities 
are they creating repeatedly? Based on this analysis, recommend specific security 
training programs for each team."
```

**O que acontece nos bastidores:**

1. `get_findings` - todos os achados ativos
2. `get_products` - vincula achados a produtos/equipes
3. `get_groups` - estrutura organizacional das equipes
4. `get_users` - responsabilidade individual dos desenvolvedores

**Análise Entregue:** achados agrupados por equipe, análise de padrões de CWE mostrando erros repetidos, identificação de lacunas de treinamento e recomendações de programas de treinamento de segurança direcionados.

---

### Caso de Uso 3: Avaliação da Eficácia das Ferramentas

**Cenário:** a equipe de segurança está avaliando o ROI das ferramentas de SAST atuais

**Prompt do Usuário:**

```
"Analyze the effectiveness of our SAST tools. Show me false positive rates, 
mean time to remediation, which tools find the most valuable vulnerabilities, 
and recommend configuration improvements or alternative tools."
```

**O que acontece nos bastidores:**

1. `get_tests` - todos os testes de segurança por ferramenta
2. `get_findings` - análise de falsos positivos
3. `get_findings` - achados ativos por ferramenta
4. `get_findings` - achados fechados para padrões de remediação

**Análise Entregue:** taxas de falso positivo por ferramenta, tempo médio até a remediação por severidade, análise de achados duplicados, recomendações de configuração de ferramentas, lacunas de treinamento e análise de custo-benefício de abordagens alternativas de ferramentas.

---

### Caso de Uso 4: Relatório de Conformidade

**Cenário:** preparação para uma auditoria SOC 2 que exige evidências de gerenciamento de vulnerabilidades

**Prompt do Usuário:**

```
"Generate a SOC 2 compliance report showing our vulnerability management processes, 
including discovery and remediation procedures, SLA compliance, continuous monitoring 
evidence, and accountability documentation."
```

**O que acontece nos bastidores:**

1. `get_findings` - achados ativos Críticos/Altos
2. `get_findings` - tendências de descoberta desde o início do ano
3. `get_engagements` - frequência e cobertura de testes
4. `get_users` - responsabilidade pela remediação

**Análise Entregue:** processos de descoberta e remediação de vulnerabilidades, rastreamento de conformidade com SLA, evidências de monitoramento contínuo, documentação de responsabilidade e lacunas que exigem remediação antes da auditoria.

---

### Caso de Uso 5: Priorização de Risco

**Cenário:** a equipe de segurança tem recursos limitados e precisa priorizar os esforços de remediação

**Prompt do Usuário:**

```
"What are the highest priority vulnerabilities we should fix first? Consider severity, 
how long they've been open, exploitability, and business impact. Give me a prioritized 
remediation roadmap with effort estimates."
```

**O que acontece nos bastidores:**

1. `get_findings` - achados ativos Críticos/Altos
2. `get_products` - contexto de criticidade de negócio
3. Análise de métricas de idade (dias desde a descoberta)
4. Referência cruzada com pontuações EPSS (previsão de exploração)

**Análise Entregue:** lista de vulnerabilidades classificadas por risco combinando severidade, idade, explorabilidade e impacto de negócio. Roteiro de remediação específico com estimativas de esforço e redução de risco esperada.

---


## Boas Práticas e Padrões de Consulta

### Estratégia de Carregamento Progressivo de Dados

Seu assistente de IA otimiza o desempenho seguindo automaticamente estes padrões de carregamento de dados:

**1. Comece com Dados Resumidos**

Peça contagens antes de solicitar análises detalhadas:

```
"How many critical and high severity findings do we have?"
```

Seu assistente de IA usará a ferramenta `get_findings` com `limit: 1` para recuperar de forma eficiente apenas a contagem.

**2. Use Paginação Estratégica**

Para grandes conjuntos de dados, seu assistente de IA percorre os resultados automaticamente por páginas:

```
"Analyze all our active vulnerabilities"
```

A IA fará múltiplas chamadas se necessário, começando com limites razoáveis e aumentando conforme exigido.

**3. Reaproveitamento Eficiente de Dados**

Faça perguntas relacionadas em sequência para evitar consultas redundantes:

```
"Show me all critical findings, then tell me which CWE categories they fall into"
```

A IA reaproveitará os dados de achados da primeira consulta para a análise de CWE.

### Estratégias de Filtragem Inteligente

Elabore seus prompts para aproveitar os poderosos recursos de filtragem do DefectDojo:

#### Consultas Baseadas em Severidade

**Prompt do Usuário:**
```
"Show me all Critical and High severity issues that need immediate attention"
```

**Nos bastidores:** a IA usa `get_findings` com filtros de severidade e status

#### Consultas Baseadas em Tempo

**Prompt do Usuário:**
```
"What new vulnerabilities have been discovered in the past 30 days?"
```

**Nos bastidores:** a IA aplica o filtro de data "Past 30 days" com status ativo

#### Filtragem Combinada

**Prompt do Usuário:**
```
"Give me a risk assessment of all critical and high active findings from the past 90 days"
```

**Nos bastidores:** a IA combina filtros de severidade, status e data para uma análise abrangente

### Análise de Referência Cruzada

Seu assistente de IA vincula automaticamente os achados ao contexto organizacional. Basta fazer perguntas abrangentes:

**Prompt do Usuário:**
```
"Which products have the most critical vulnerabilities and who is responsible for fixing them?"
```

**Nos bastidores:** a IA vincula achados → testes → engajamentos → produtos → usuários/grupos para um contexto completo

### Análise de Inteligência de Vulnerabilidades

**Análise de Padrões de CWE**

**Prompt do Usuário:**
```
"What are the most common vulnerability types in our codebase and which teams are creating them?"
```

A IA agrupará os achados por CWE para identificar padrões recorrentes, necessidades de treinamento e problemas arquiteturais.

**Métricas de Idade**

**Prompt do Usuário:**
```
"How long have our critical vulnerabilities been open? Which ones are overdue for remediation?"
```

A IA calcula o tempo desde a descoberta e sinaliza achados que excedem os limites de SLA.

**Densidade de Vulnerabilidades**

**Prompt do Usuário:**
```
"Which products have the highest vulnerability density and represent the greatest risk?"
```

A IA calcula achados por produto e gera pontuações de risco combinando severidade e volume.

### Padrões de Aprimoramento de Relatórios

#### Sempre Inclua

- **Métricas específicas:** contagens reais por severidade, não generalizações
- **Análise de CWE:** principais tipos de vulnerabilidade com descrições
- **Dados de idade:** há quanto tempo as vulnerabilidades estão abertas
- **Recomendações acionáveis:** o que fazer a seguir, com prazos
- **Cálculos de ROI:** custo esperado vs. benefício das ações
- **Métricas de sucesso:** como medir a melhoria

#### Integração de Contexto do Setor

Compare os achados do DefectDojo com frameworks do setor:

- **OWASP Top 10:** riscos de segurança de aplicações web
- **SANS Top 25:** fraquezas de software mais perigosas
- **CWE Top 25:** fraquezas mais comuns e impactantes
- **Frameworks de conformidade:** SOC 2, ISO 27001, NIST CSF

## Solução de Problemas do MCP

### Lista de Verificação de Diagnóstico

Verifique estes itens ao enfrentar problemas de conexão:

- ✅ o Tipo de Transporte é **Streamable HTTP** (não SSE)
- ✅ a URL do endpoint MCP está correta: `https://[instance].defectdojo.com/mcp`
- ✅ o cabeçalho Authorization está habilitado (o alternador está ON)
- ✅ o formato do token inclui o prefixo `Token`
- ✅ o token é válido e possui as permissões apropriadas
- ✅ a instância do DefectDojo está acessível (é possível fazer login pela interface web)
- ✅ a conectividade de rede permite conexões HTTPS

### Problemas de Conexão Comuns

#### ❌ "Connection Error - Check if your MCP server is running"

**Causa:** uso do tipo de transporte SSE (Server-Sent Events), que está descontinuado

**Solução:** altere o Tipo de Transporte para `Streamable HTTP`

**Por quê:** o Servidor MCP do DefectDojo usa o protocolo moderno Streamable HTTP. O SSE está descontinuado e não é suportado.

---

#### ❌ "Authentication Failed" ou "401 Unauthorized"

**Causa:** formato incorreto do cabeçalho de autenticação ou token inválido

**Soluções:**

1. Verifique se o valor do cabeçalho usa o prefixo `Token` (não `Bearer`)
   ```
   ✅ Correct: Token 7c6cc2xxxxxxxxxxxxxxxxxxxx87fcf72ec2b3fb
   ❌ Wrong: Bearer 7c6cc2xxxxxxxxxxxxxxxxxxxx87fcf72ec2b3fb
   ```

2. Certifique-se de que o alternador do cabeçalho Authorization esteja HABILITADO (ligado)
3. Verifique se o token ainda é válido no DefectDojo (Admin → API Tokens)
4. Verifique se o token tem as permissões apropriadas para acesso de leitura

---

#### ❌ A Ferramenta Retorna Resultados Vazios

**Possíveis Causas:**

- Os filtros são restritivos demais (nenhum dado corresponde aos critérios)
- A instância do DefectDojo não tem dados na categoria solicitada
- Permissões insuficientes do token

**Soluções:**

1. Tente primeiro uma consulta mais ampla: `get_findings({ limit: 10 })`
2. Remova os filtros um de cada vez para identificar o filtro restritivo
3. Verifique as permissões do token no DefectDojo
4. Verifique se os dados existem diretamente na interface do DefectDojo

---

#### ⚠️ Tempos de Resposta Lentos

**Causa:** solicitação de dados em excesso de uma só vez

**Soluções:**

- Reduza o parâmetro `limit` (comece com 50-100)
- Use filtros mais específicos para reduzir o tamanho do conjunto de resultados
- Use carregamento progressivo: obtenha as contagens primeiro, depois os detalhes
- Implemente paginação para grandes conjuntos de dados

---
