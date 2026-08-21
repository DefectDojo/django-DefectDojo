---
title: Glossário
weight: 1
---

Abaixo está um glossário simples para ajudar a entender os diversos recursos do DefectDojo, junto com uma indicação de se cada recurso definido está presente/aplicável na versão Pro do DefectDojo, na versão OS, ou em ambas.

## Hierarquia de Produtos (Ambos)
O modelo estrutural usado para organizar dados de segurança dentro do DefectDojo, composto por Organizações → Ativos → Engajamentos → Testes → Achados.
## Organização (Ambos)
Um objeto hierárquico de nível superior que serve como objeto pai dos Ativos no DefectDojo Pro. Ele fornece um contexto compartilhado para governança, controle de acesso e geração de relatórios em todos os Ativos filhos.
## Ativo (Ambos)
Um objeto de primeira classe que representa uma entidade de sistema implantável ou lógica (por exemplo, aplicação, host, ambiente) dentro das Organizações. Os Ativos oferecem suporte a relacionamentos pai-filho e a metadados de negócio mais completos na versão Pro, mas não oferecem suporte a relacionamentos pai-filho na versão OS.
### Hierarquia de Ativos (Pro)
Um modelo de relacionamento pai-filho entre Ativos que permite a herança de contexto e a agregação de Achados.
## Engajamento (Ambos)
Uma atividade de segurança delimitada que representa uma janela de testes, um pipeline ou um contexto de avaliação.
## Teste (Ambos)
Uma única execução de um scanner ou de uma avaliação manual dentro de um Engajamento. Os Testes armazenam metadados de execução e atuam como o ponto de ingestão dos Achados.
## Serviço (Ambos)
Um subobjeto opcional usado para atribuir Achados a um componente ou interface específica dentro de um Ativo. Os Serviços são mais úteis no DefectDojo OS, já que sua funcionalidade é replicada e aprimorada pela Hierarquia de Ativos na versão Pro.
## Componentes (Ambos)
Uma biblioteca de terceiros, módulo de software ou dependência externa rastreada no DefectDojo Pro. Os Componentes importados são derivados dos dados do scan e associados a Achados. Na UI do Pro, a Tabela de Componentes agrega as contagens de Achados Ativo, Duplicado e Total por Componente, e permanece populada mesmo quando todos os Achados associados estão Mitigado.
## Achado (Ambos)
O objeto de vulnerabilidade mais granular na Hierarquia de Produtos do DefectDojo, que representa um problema de segurança específico.
### Status do Achado (Ambos)
O estado atual do ciclo de vida de um Achado (por exemplo, Ativo, Verificado, Inativo/Mitigado, Em Revisão, Risco aceito, Falso positivo, Fora do escopo). O Status do Achado determina a inclusão em métricas e painéis.
### Prioridade/Risco do Achado (Pro)
Um valor calculado ou derivado que representa a urgência de remediação, combinando a Severidade com fatores contextuais, como a criticidade do ativo ou a explorabilidade. A Prioridade é distinta da severidade bruta e é usada para a tomada de decisões baseada em risco.
### Grupos de Achados (Ambos)
Um mecanismo para agrupar Achados relacionados entre Organizações, Ativos ou ferramentas. Os Grupos de Achados permitem uma análise consolidada e relatórios de nível mais alto.
## Endpoint (Ambos)
Um local acessível pela rede (URL, IP, porta) associado a um Achado. Os Endpoints fornecem o contexto técnico de exploração.
## Importação (Ambos)
O processo de ingestão de resultados de scan ou achados manuais no DefectDojo, geralmente por meio do envio de um arquivo ou do envio de dados pela API. Durante a importação, o DefectDojo analisa, normaliza, deduplica e associa os achados ao Ativo, Engajamento, Teste e demais objetos relacionados apropriados.
## Reimportação (Ambos)
A ação de ingerir novos resultados de scan em um Teste existente. A reimportação atualiza os estados dos Achados com base na presença ou ausência nos novos dados.
## Deduplicação (Ambos)
O processo de correlacionar Achados recebidos com os já existentes usando hashes e lógica de correspondência, permitindo o rastreamento histórico entre execuções de scan.
## Falso positivo (Ambos)
Um estado de Achado que indica que o problema é inválido ou não explorável. Os falsos positivos são mantidos para fins de auditoria, mas excluídos dos cálculos de risco.
## Aceitação de risco (Ambos)
Um estado de fluxo de trabalho que indica um Achado reconhecido, porém não resolvido. Os riscos aceitos permanecem visíveis, mas são excluídos da aplicação de SLA.
## Metadados (Ambos)
Dados-chave anexados a Testes ou Achados, como o nome da branch ou o ID do build, geralmente fornecidos por pipelines de CI/CD.
## Integração de CI/CD (Ambos)
Ingestão automatizada de resultados de scan durante fluxos de trabalho de build ou deployment. As integrações geralmente dependem da API e do framework de importação.
## API (Ambos)
Uma interface RESTful usada para gerenciar programaticamente os objetos do DefectDojo. A API é o principal mecanismo para automação e integração de pipelines.
## Webhook (Pro)
Um callback HTTP de saída acionado por eventos específicos (por exemplo, a criação de um Achado). Os Webhooks permitem integração em tempo real com sistemas externos.
## Configuração de SLA (Pro)
Definições de política que atribuem prazos de remediação com base em atributos de severidade ou risco. Os SLAs permitem a aplicação de prazos e a medição de desempenho.
## Função de Usuário (Ambos)
Um conjunto de permissões que define as ações permitidas dentro do DefectDojo. As Funções aplicam o controle de acesso em Ativos e Engajamentos.
## Universal Importer (Pro)
Um mecanismo de ingestão flexível que permite importar dados de scan sem um importador específico para cada ferramenta. Ele depende de um mapeamento de campos normalizado, em vez de esquemas de scanner predefinidos.
## DefectDojo-CLI (Pro)
Uma interface de linha de comando usada para interagir com o DefectDojo de forma programática. A CLI é comumente usada em pipelines de CI/CD para automatizar o envio de scans e o gerenciamento de objetos.
## Connectors (Pro)
A área unificada da UI do Pro (em Import) para todas as ferramentas com as quais o DefectDojo se comunica. Os Upstream Connectors trazem achados de scanners; os Downstream Connectors enviam achados para sistemas de rastreamento de issues.
## Upstream Connectors / API Connectors (Pro)
Conectores pré-criados e gerenciados que trazem achados e inventário de ativos para o DefectDojo a partir de scanners externos e ferramentas de segurança por meio de suas APIs, reduzindo a necessidade de scripts personalizados. Anteriormente chamados de API Connectors.
## Downstream Connectors (Pro)
Integrações gerenciadas que enviam Achados e Grupos de Achados do DefectDojo para sistemas de rastreamento de issues e tickets (por exemplo, Jira, Azure DevOps, GitHub). Anteriormente chamados de Integrations.
## Universal Parser (Pro)
Um mecanismo de análise generalizado usado pelo Universal Importer para interpretar os dados de scan recebidos. Ele aplica uma lógica consistente de normalização e deduplicação em formatos não suportados.
## Smart Upload (Pro)
Um fluxo de trabalho de ingestão inteligente que determina automaticamente como os resultados de scan devem ser mapeados para Ativos ou Engajamentos, reduzindo a configuração manual durante a importação.
## Executive Insights (Pro)
Análises de alto nível, voltadas para o negócio, projetadas para o público de liderança, com foco em tendências, exposição e saúde do programa, em vez de Achados individuais.
## Priority Insights (Pro)
Visualizações analíticas que destacam os riscos mais críticos com base em uma pontuação de prioridade, e não apenas na severidade, apoiando o planejamento de remediação baseado em risco.
## Program Insights (Pro)
Métricas e visualizações que avaliam a eficácia e a maturidade de um programa de segurança ao longo do tempo. O Program Insights enfatiza tendências, cobertura e desempenho operacional.
## Tool Insights (Pro)
Análises focadas no desempenho, na cobertura e na contribuição dos scanners para os Achados, ajudando as equipes a otimizar o uso das ferramentas e reduzir ruído.
## Rules Engine (Pro)
Um sistema de automação orientado por políticas que aplica lógica condicional aos Achados durante eventos de ingestão ou de ciclo de vida, automatizando alterações de severidade, atribuições ou fluxos de trabalho.
## Integrações (Ambos)
Conexões entre o DefectDojo e ferramentas ou plataformas externas para ingestão de dados, notificações ou automação de fluxos de trabalho. O Pro inclui integrações mais profundas e gerenciadas, além dos importadores básicos e do uso da API.
