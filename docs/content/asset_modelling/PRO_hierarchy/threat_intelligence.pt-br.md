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

## Habilitando o recurso

O recurso vem desativado por padrão. Os administradores podem habilitá-lo diretamente ou, primeiro,
executá-lo em **modo shadow** — que calcula as pontuações que seriam aplicadas sem alterar nada em
produção e produz um relatório de divergência mostrando exatamente quais achados mudariam — antes de
ativá-lo de fato. Entre em contato com o suporte ou consulte o runbook de operações para a implantação
recomendada em instâncias grandes.
