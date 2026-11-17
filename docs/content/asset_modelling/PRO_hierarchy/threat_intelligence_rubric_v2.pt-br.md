---
title: "Inteligência de Ameaças: pontuação baseada em evidências (Rubric v2)"
description: "Como evidências de exploração revisadas vão alimentar o piso de Prioridade da inteligência de ameaças"
weight: 3
audience: pro
---

> **Ainda não disponível.** Esta página descreve um recurso em desenvolvimento. Ele não aparece na
> página **Feature Flags** e ainda não pode ser ativado, nem no DefectDojo Cloud nem em uma
> instância self-hosted. Hoje, todo achado é pontuado como descrito em
> [Inteligência de Ameaças](../threat_intelligence/).

A [Inteligência de Ameaças](../threat_intelligence/#como-isso-muda-a-pontuação) transforma
evidências de exploração em um **piso** na escala do EPSS: a pontuação externa de um achado é, no
mínimo, o piso que sua evidência mais forte alcança. A tabela de pisos se chama **rubrica**
(rubric). O Rubric v2 é a próxima versão dela. Ele mantém o valor de cada piso e acrescenta um tipo
de evidência: **alegações de exploração que os analistas da DefectDojo revisaram e confirmaram**.

## O que muda

| Evidência | Piso de Prioridade (equivalente a EPSS) |
|---|---|
| Evidência de exploração confirmada **e** um agente de ameaça confirmado e nomeado por trás dela (novo) | 45% |
| No CISA KEV **e** usado em ransomware | 30% |
| No KEV, explorado em ambiente real ou **qualquer evidência de exploração confirmada**, incluindo uma observação de canary confirmada (novo) | 20% |
| Exploit público armado (Metasploit / Exploit-DB) | 15% |
| Existe template de detecção do Nuclei | 12% |
| Apenas prova de conceito pública | 8% |
| Sem evidência de exploração | sem alteração |

Os pisos têm os mesmos valores de hoje, e a pontuação externa do achado continua sendo o maior valor
entre o derivado do EPSS e o seu piso mais alto, então a rubrica só pode aumentar uma pontuação.

Na prática:

- **Mais achados alcançam o piso de "exploração conhecida".** Um CVE que não está no CISA KEV, mas
  tem evidência de exploração revisada (um relatório de incidente, um aviso do fornecedor que a
  declara, uma observação de honeypot ou de canary), recebe o mesmo piso de 20% que uma entrada do
  KEV.
- **O piso mais alto passa a ser alcançável.** No Rubric v1, o piso de 45% exigia telemetria de
  fornecedores que o feed não traz, então nenhum achado chegou a ele. No Rubric v2, ele é alcançado
  por evidência confirmada com um agente de ameaça confirmado e nomeado por trás dela, e por nada
  menos que isso.
- **Nada fica mais fraco.** Sem evidência revisada, uma vulnerabilidade é pontuada exatamente como
  hoje. Uma entrada do KEV com uso em ransomware continua em 30%: o indicador de ransomware da CISA
  não nomeia nenhum agente.

O que **não** aumenta um piso: uma alegação não revisada ou rejeitada, uma prova de conceito
sozinha e o indicador "exploit disponível" de um scanner ou de um fornecedor (eles continuam sendo
exibidos como hoje e não contam como evidência).

## Antes da ativação

Mover uma instância para o Rubric v2 pode aumentar a Prioridade de achados, por isso a DefectDojo
mede a mudança antes de fazê-la: para cada instância, quantos achados passariam de qual piso para
qual e, para cada mudança, as vulnerabilidades por trás da maior parte dos achados. Suas prioridades
atuais continuam no Rubric v1 até o lançamento do Rubric v2.
