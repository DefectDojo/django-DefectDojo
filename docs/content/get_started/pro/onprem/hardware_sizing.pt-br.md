---
title: Dimensionamento de hardware para o DefectDojo Pro autogerenciado
description: Orientação geral para dimensionar processamento, memória e armazenamento
  em uma implantação autogerenciada do DefectDojo Pro
draft: false
weight: 4
audience: pro
---

Dimensionar uma implantação do DefectDojo se resume a duas perguntas. Quantos dados você está armazenando e quantas pessoas trabalham nela ao mesmo tempo. Esta página traz pontos de partida para ambas.

Trate o que segue como orientação geral, não como uma especificação. Os números são deliberadamente conservadores e partem do princípio de uma implantação que faz triagem cotidiana junto com importações regulares de scans. Seus próprios números vão variar dependendo de como você usa o produto, então leia as notas abaixo da tabela antes de provisionar qualquer coisa.

As especificações são dadas em números genéricos de vCPU e memória, para que se apliquem a qualquer provedor de nuvem ou hardware on-premise. A orientação para os nós de aplicação parte do princípio de Kubernetes. Se você executa o Docker Compose em um único host, use os mesmos totais.

## Tabela de dimensionamento

| Achados | Usuários simultâneos | Banco de dados | Nós de aplicação |
| --- | --- | --- | --- |
| Até 100K | Até ~25 | 2–4 vCPU / 16–32 GB | 2 × (2–4 vCPU / 8–16 GB) |
| 100K–500K | ~25–50 | 4–8 vCPU / 32–64 GB | 2–3 × (4 vCPU / 16 GB) |
| 500K–1M | ~50–100 | 8 vCPU / 64–96 GB | 2–3 × (8 vCPU / 32 GB) |
| 1M–5M | ~100–250 | 8–16 vCPU / 96–128 GB | 5–6 × (8 vCPU / 32 GB) |
| 5M–10M | ~250–500 | 16–32 vCPU / 128–192 GB | 9–10 × (8 vCPU / 32 GB) |
| 500M | 500+ | 192 vCPU / 768 GB+ | 50+ × (8 vCPU / 32 GB) |

Onde você se encaixa dentro de uma faixa depende da sua carga de trabalho. Comece pela extremidade superior de uma faixa se algo em [What pushes you up a tier](#what-pushes-you-up-a-tier) se aplicar a você.

A linha de 500M é um ponto de referência no extremo distante, e não uma continuação do padrão das linhas acima, portanto não interpole entre ela e o patamar de 10M. Uma implantação situada entre esses dois pontos precisa ser dimensionada individualmente. Ela também pressupõe um trabalho que o hardware sozinho não resolve, tratado em [Very large deployments](#very-large-deployments).

## Como interpretar esses números

### A memória do banco de dados importa mais do que a CPU do banco de dados

O DefectDojo executa consultas pesadas de agregação sobre seus achados. Elas permanecem rápidas enquanto o working set e seus índices são servidos a partir da memória, e degradam rapidamente assim que o banco de dados começa a recorrer ao disco. Quando precisar escolher, compre memória antes de comprar núcleos. A tabela reflete isso. A memória praticamente dobra de um patamar para o outro, enquanto a contagem de CPU cresce muito mais devagar.

### Os nós de aplicação acompanham os usuários, não os achados

Os números de usuários simultâneos na tabela pressupõem que conjuntos de dados menores pertencem a equipes menores. Essa suposição costuma falhar. Se você tem 200 mil achados, mas 100 pessoas na UI ao mesmo tempo, dimensione a camada de aplicação para os usuários e deixe o banco de dados no patamar que sua quantidade de achados indica. As duas coisas escalam de forma independente.

Há uma exceção, no extremo final da tabela. A importação e a deduplicação são executadas na camada de aplicação, não no banco de dados, então, quando um conjunto de dados é grande o suficiente para que esse trabalho predomine, a contagem de nós passa a acompanhar o volume de ingestão em vez da contagem de usuários. É por isso que a linha de 500M fica bem acima do que seu número de usuários, isoladamente, sugeriria.

### O formato dos nós é flexível

O Kubernetes distribui a carga tanto se você fornecer poucos nós grandes quanto mais nós pequenos, portanto as contagens de nós acima são um arranjo viável, não um requisito. Duas coisas valem a pena manter. Mantenha pelo menos dois nós, para que a perda de um não derrube a aplicação, e evite nós menores que 2 vCPU / 8 GB, para que os pods individuais sejam agendados sem dificuldades.

## Armazenamento

Planeje 20–30 GB de armazenamento de banco de dados por milhão de achados. Onde você cai dentro dessa faixa depende de quanto conteúdo você associa a cada achado. Descrições longas e grandes quantidades de endpoints o empurram para o topo dela. As linhas de achados em si representam uma pequena parte disso. A maior parte do espaço vai para os índices e para as tabelas relacionadas que se associam a cada achado, portanto dimensionar apenas a partir dos dados de linha deixará você bem aquém do necessário.

Todo patamar até 10M cabe em algumas centenas de GB de SSD de uso geral. O armazenamento é barato perto do custo de ficar sem ele, então provisione para onde você espera estar daqui a um ano, não para onde está agora. Se seu provedor oferecer autoscaling de armazenamento, ative-o.

A linha de 500M é dimensionada em 2,5 TB. Esse número pressupõe que o conjunto de dados ativo é gerenciado de forma proativa, com achados mais antigos arquivados para fora do caminho ativo em vez de se acumularem indefinidamente. Aplicada de forma ingênua, a taxa por milhão acima colocaria uma implantação de 500M não gerenciada muitas vezes mais alta. Se você está caminhando para essa escala, trate a estratégia de arquivamento como parte do exercício de dimensionamento, e não como algo para resolver depois.

Armazenamento nessa escala também exige atenção à taxa de transferência, não só à capacidade. Assim que o working set deixa de caber na memória, o IOPS de linha de base padrão de volumes de uso geral se torna o limite bem antes da capacidade.

O armazenamento de mídia é separado e geralmente muito menor. Ele guarda artefatos enviados, como capturas de tela e documentos de aceitação de risco, então dimensione-o de acordo com seus próprios hábitos de upload.

## What pushes you up a tier

A contagem de achados é o número de destaque, mas várias coisas farão você dimensionar para cima antes do que a contagem sozinha sugere.

- **Volume e frequência de importação.** Scans grandes chegando com frequência, especialmente vários ao mesmo tempo, geram carga sustentada tanto no banco de dados quanto nos workers assíncronos. Pipelines de CI que importam a cada build são a causa mais comum.
- **Deduplicação.** A deduplicação compara os achados recebidos com o que você já possui. Quanto mais achados você tem e quanto mais ampla for sua configuração de deduplicação, mais trabalho cada importação exige.
- **Relatórios e painéis.** Visualizações de métricas e a geração de relatórios grandes são intensivas em leitura, e sobrecarregam o banco de dados mais do que a triagem do dia a dia.
- **Tráfego de API.** Integrações que fazem polling ou buscam grandes conjuntos de resultados adicionam carga simultânea que nunca aparece na sua contagem de usuários interativos.
- **Retenção.** Implantações que mantêm tudo para sempre avançam para o próximo patamar conforme o esperado. Arquivar ou excluir dados antigos mantém você onde está por mais tempo.

## Very large deployments

Além do patamar de 10M, o hardware deixa de ser a resposta completa. Duas coisas mudam.

A restrição limitante passa da leitura para a escrita. A deduplicação compara cada achado recebido com o que você já possui, portanto o custo de uma importação cresce com o tamanho do conjunto de dados por trás dela. No topo da tabela, isso costuma ser o primeiro limite atingido, antes de qualquer coisa que os usuários percebam na UI. Seja qual for o volume de importação que construiu um conjunto de dados desse tamanho, ele geralmente continua em execução, então você paga esse custo continuamente, não apenas uma vez.

Os números de memória pressupõem que o hot set permanece pequeno. Uma implantação trabalha com os achados recentes e deixa os mais antigos praticamente intocados, o que é o que permite a um banco de dados manter muito mais dados do que tem memória e ainda assim ter bom desempenho. Se seu padrão de acesso está genuinamente distribuído por todo o conjunto de dados, você vai precisar de mais memória do que a tabela lista, e a partir de certo ponto nenhuma instância isolada será suficiente.

Ambos os pontos apontam para o mesmo trabalho. Particionar e arquivar achados frios para fora do conjunto de dados ativo importa mais nessa escala do que mais um incremento de vCPU, e relatórios pesados pertencem a uma read replica, não à instância primária. Planeje isso junto com o hardware, não depois dele, e fale conosco antes de provisionar.

## Em caso de dúvida, arredonde para cima

Os números aqui já são deliberadamente conservadores, e ficar um tamanho grande demais custa muito menos do que ficar um tamanho pequeno demais. A pressão de memória no banco de dados, em particular, não degrada de forma gradual. O desempenho se mantém bem até que para de repente.

Adicionar capacidade de aplicação depois é simples, já que basta adicionar nós. Redimensionar um banco de dados normalmente implica downtime, então esse é o ponto que vale a pena acertar desde o início.

## Dúvidas ou suporte

Estes são pontos de partida, não limites. Se sua implantação está no topo da tabela, ou sua carga de trabalho não se parece com as suposições feitas aqui, fale conosco antes de provisionar. Entre em contato com seu representante de conta ou [support@defectdojo.com](mailto:support@defectdojo.com).
