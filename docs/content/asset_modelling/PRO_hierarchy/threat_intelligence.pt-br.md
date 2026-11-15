---
title: Inteligência de Ameaças
description: Evidências de exploração e ameaças como entrada de primeira classe para
  Prioridade e Risco
weight: 2
audience: pro
---

O DefectDojo Pro enriquece seus achados com **inteligência de ameaças dedicada** — disponibilidade de exploit, exploração conhecida e atividade de agentes de ameaça — e leva isso em conta na Prioridade e no Risco. Isso vai muito além do EPSS e do sinalizador KEV da CISA.

## O que você obtém

Todo achado com um CVE é comparado, todas as noites, com um feed de inteligência selecionado, construído a partir do CISA KEV, Metasploit, Exploit-DB, templates do Nuclei e rastreamento de provas de conceito públicas. Quando há evidência de exploração, o achado exibe um card de **Inteligência de Ameaças**:

* um selo de **maturidade de exploração** — *Nenhum → PoC → Armado → Ativo em ambiente real*
* uma **pontuação de ameaça** (0–100)
* **chips de evidência que linkam para o comprovante** — a entrada no KEV (com sua data de listagem),
  uso em ransomware, um módulo do Metasploit, uma entrada no Exploit-DB, um template do Nuclei e
  repositórios públicos de prova de conceito
* uma linha em linguagem simples explicando **por que** a prioridade do achado aumentou

Além do card, essa inteligência é uma camada funcional em todo o aplicativo:

* uma **coluna Maturidade de Exploração** na lista de achados — ordenável e filtrável
  (por exemplo, "somente Armado ou Ativo")
* um bloco **"Urgente e Ativamente Explorado"** no painel de Layout de Prioridade, contabilizando
  achados ativos de risco Urgente com exploração em ambiente real — ao clicar, abre a
  lista exata de achados filtrados
* um **evento de notificação** (`threat_intel_alert`) quando o CVE de um achado existente ganha nova
  evidência de exploração, como entrar no CISA KEV ou ganhar um módulo do Metasploit. Apenas atualizações
  para cima — evidências que silenciosamente perdem validade nunca geram notificação.

## Achados reportados por um ID de advisory do GitHub {#findings-reported-by-a-github-advisory-id}

Alguns scanners reportam uma vulnerabilidade apenas pelo seu ID de advisory do GitHub (GHSA), e não pelo
CVE que ela representa. Quando o DefectDojo sabe que o advisory e um CVE descrevem a mesma
vulnerabilidade, seja pelo pacote de inteligência, seja por um vínculo registrado na sua instância, o
achado recebe a maturidade de exploração, as evidências e a pontuação de ameaça desse CVE, da mesma forma
que um achado que cita o CVE. O achado mantém seu próprio ID de vulnerabilidade.

Quando um advisory passa a ser vinculado a um CVE, ou quando um vínculo é rejeitado, o DefectDojo
recalcula a pontuação dos achados afetados. Os achados que já estavam na sua instância antes da inclusão
desse comportamento têm a pontuação recalculada uma única vez, em segundo plano, após o primeiro
carregamento de pacote posterior à atualização.

## Como isso muda a pontuação

O mecanismo de Prioridade já combinava severidade, contexto de negócio e uma "pontuação externa"
construída a partir de EPSS + KEV. A inteligência de ameaças generaliza essa pontuação externa: cada tipo
de evidência de exploração atua como um piso na escala do EPSS.

| Evidência | Piso de Prioridade (equivalente a EPSS) |
|---|---|
| Exploração ativa + ransomware/agente nomeado | 45% |
| No CISA KEV **e** usado em ransomware | 30% |
| No KEV ou explorado em ambiente real | 20% |
| Exploit público armado (Metasploit / Exploit-DB) | 15% |
| Existe template de detecção do Nuclei | 12% |
| Apenas prova de conceito pública | 8% |
| Sem evidência de exploração | sem alteração |

A pontuação externa do achado é o **maior** valor entre o derivado do EPSS e o piso de evidência mais alto
acima — portanto, a inteligência só *aumenta* uma pontuação, nunca a reduz, e um achado cujo EPSS já
exceda o piso não é afetado. O já conhecido **escalar de pontuação externa** por tipo de produto, nas
configurações do seu Mecanismo de Priorização, dimensiona essa contribuição exatamente como sempre
dimensionou o EPSS/KEV.

### O piso de Risco de exploração ativa

A tabela acima aumenta a **Prioridade**, mas proporcionalmente à severidade base de um achado. Isso tem
uma consequência que vale a pena declarar claramente: um achado de severidade Baixa com um CVE que está
sendo explorado em ambiente real recebe apenas um pequeno aumento absoluto, e ainda pode permanecer em
uma faixa de **Risco** baixa. A maioria das equipes considera isso errado — "ativamente explorado" nunca
deveria ser classificado como Baixo.

Por isso, existe uma segunda regra, categórica. Quando a inteligência de ameaças reporta **exploração
ativa em ambiente real**, a Prioridade do achado é elevada a, no mínimo, o nível de uma faixa de Risco
configurada, independentemente do que o cálculo ponderado sozinho produziria. Por padrão, vem definido
como **Requer Ação**; cada tipo de produto pode elevá-lo para Urgente, reduzi-lo ou desativá-lo, nas
configurações do Mecanismo de Priorização, em *Piso de Risco de Exploração Ativa*.

O piso só eleva — nunca move um achado para baixo, e um achado que já pontua mais alto por conta própria
permanece inalterado. Como isso se aplica à Prioridade, a faixa de Risco e a pontuação de Risco decorrem
automaticamente dela, de modo que toda lista, filtro, gráfico e cálculo de SLA enxergam o mesmo número
consistente.

## Achados sem CVE

A inteligência de ameaças é correlacionada por CVE. Muitos achados — a maioria dos resultados de SAST,
segredos, configurações incorretas, regras personalizadas — não têm CVE, e não existe inteligência de
ameaças por instância de vulnerabilidade para eles em lugar nenhum (isso vale para todos os fornecedores,
não só o DefectDojo). Esses achados:

* mantêm sua Prioridade e Risco atuais **exatos** — o recurso nunca reduz uma pontuação
* ainda são priorizados por todas as outras entradas do mecanismo (severidade, criticidade de negócio,
  exposição, e assim por diante)
* exibem "Nenhuma inteligência de ameaças disponível — este achado não tem CVE para correlacionar" no
  card, diferente de um achado com CVE que simplesmente ainda não tem exploit conhecido

Uma consequência honesta: em uma fila mista, à medida que achados com CVE ganham evidência de exploração,
os achados sem CVE caem em classificação *relativa*, mesmo que sua pontuação permaneça inalterada.

## Confiança e estabilidade da pontuação

* **Inteligência assinada.** Todo pacote noturno é assinado criptograficamente pelo DefectDojo; sua
  instância recusa dados adulterados ou não assinados. Instâncias air-gapped importam o mesmo pacote
  assinado com uma etapa de verificação offline.
* **Sem oscilação de pontuação.** As atualizações de evidência são aplicadas na mesma noite em que
  surgem. Se uma fonte *perde* uma evidência, as pontuações permanecem estáveis por uma janela de
  estabilidade (14 dias por padrão) — uma falha pontual no feed nunca desestabiliza sua fila, e
  desescaladas genuínas se acomodam silenciosamente após a janela.
* **Suporte a air-gapped.** O pacote diário (incluindo dados de EPSS) pode ser transferido e importado
  offline, para que instâncias isoladas recebam o mesmo enriquecimento.

## O card Intelligence Sources {#intelligence-sources-card}

Superusuários podem verificar qual inteligência a instância está usando no card somente leitura
**Intelligence Sources**, em **Settings > System Settings**. O card mostra:

* a versão do pacote carregado
* a idade do pacote, com um aviso quando ele tem 14 dias ou mais
* quando o pacote expira
* cada fonte do pacote, com sua licença e o quão atualizados estão seus dados
* a última falha de carregamento, se houver, e o motivo da falha
* as atribuições das fontes do pacote

Um pacote carregado a partir de um arquivo em uma instância air-gapped aparece no mesmo card.

## Implantações self-hosted

Instâncias do DefectDojo Cloud não precisam de nenhuma configuração. Instâncias self-hosted têm três
opções:

* **Conectado (padrão).** A instância busca o pacote assinado todas as noites em `intel.defectdojo.com`
  via HTTPS. Esse é um destino que nenhum outro recurso do DefectDojo utiliza, então geralmente precisa
  ser liberado explicitamente: abra a porta 443 de saída para esse host e, no Kubernetes, adicione-o à
  sua política de rede de egress. Observe que a busca é executada no **worker do Celery**, não no pod
  web, então as configurações de proxy também precisam alcançar essa carga de trabalho.
* **Espelho interno.** Aponte `DD_THREAT_INTEL_BUNDLE_URL` (e as URLs correspondentes de digest e
  assinatura) para um local dentro da sua rede que você mesmo sincroniza. A verificação de assinatura
  continua se aplicando, então um espelho não pode alterar os dados.
* **Air-gapped.** Transfira o pacote e sua assinatura manualmente e importe-os com
  `manage.py load_threat_intel_bundle --file <bundle>`. A assinatura é verificada na importação.

Se a instância não conseguir acessar o feed, o recurso falha de forma segura (fail closed): a execução é
registrada como falha, e suas pontuações e evidências existentes permanecem exatamente como estavam. Nada
se degrada, exceto a atualidade da inteligência.

### KEV e EPSS a partir do pacote {#kev-and-epss-from-the-bundle}

O pacote que uma instância self-hosted já baixa também traz dados do CISA KEV e do EPSS. Após cada
carregamento do pacote, o DefectDojo usa esses dados para preencher **Known Exploited (CISA KEV)**,
**Ransomware Used (CISA KEV)**, a data do KEV, a data de vencimento do CISA KEV e as pontuações EPSS nas
suas vulnerabilidades e achados, para que você os obtenha sem ativar consultas separadas de KEV e EPSS. KEV
e EPSS são tratados separadamente, e cada um só é preenchido a partir do pacote quando todas estas
condições são atendidas:

* A inteligência de ameaças está ativada.
* A consulta dessa fonte, em Finding Enrichment no Tuner, está desativada. Uma consulta ativada sempre
  prevalece, então, com uma consulta ativada, o pacote fornece apenas a outra fonte.
* O pacote traz dados atualizados dessa fonte.

O botão **Sync KEV/EPSS Data** no Vulnerability Explorer, a tarefa diária de enriquecimento e o
enriquecimento de novos CVEs no momento da importação usam os mesmos dados do pacote, nas mesmas condições.

Known Exploited e Ransomware Used significam que o CVE está listado no catálogo CISA KEV. Quando um
scanner, um conector ou uma pessoa reporta uma vulnerabilidade como explorada, esse relato é mantido como
um valor separado, **Vendor Reported Exploited**, para que não se perca quando a CISA não lista o CVE.
Veja [Achados](/asset_modelling/engagements_tests/pro__findings/#metadata).

#### O primeiro carregamento após a atualização {#the-first-load-after-upgrading}

Em uma instância self-hosted com as consultas de KEV e EPSS desativadas, esses valores ficavam vazios até
agora, ou continham o que um scanner ou uma pessoa tivesse definido. A própria atualização, antes de
qualquer carregamento do pacote, transfere toda sinalização desse tipo que nenhuma listagem do CISA KEV
sustenta para **Vendor Reported Exploited** ou **Vendor Reported Ransomware**, então as contagens de
CISA KEV já podem cair nesse momento (veja
[Achados](/asset_modelling/engagements_tests/pro__findings/#metadata)). Depois, o primeiro
carregamento do pacote após a atualização preenche os valores da CISA para todo CVE que a instância
conhece, então espere que:

* **Known Exploited (CISA KEV)**, **Ransomware Used (CISA KEV)** e a data do KEV mudem em muitos
  achados, tanto sendo definidos (a CISA lista o CVE) quanto sendo limpos (ela não lista), e que a
  Prioridade mude junto com eles. Um achado que um scanner ou uma pessoa reportou como explorado mantém
  sua Prioridade, porque a Prioridade também considera **Vendor Reported Exploited**.
* Se uma configuração de SLA tiver **Cap SLA by CISA KEV Due Date** ativado, os achados listados no KEV
  tenham o prazo do SLA antecipado para a data de vencimento da CISA. A maioria das datas de vencimento
  da CISA já passou, então muitos desses achados aparecerão em violação de SLA logo após o primeiro
  carregamento.

## Habilitando o recurso

O recurso vem desativado por padrão. Os administradores podem habilitá-lo diretamente ou, primeiro,
executá-lo em **modo shadow** — que calcula as pontuações que seriam aplicadas sem alterar nada em
produção e produz um relatório de divergência mostrando exatamente quais achados mudariam — antes de
ativá-lo de fato. Entre em contato com o suporte ou consulte o runbook de operações para a implantação
recomendada em instâncias grandes.
