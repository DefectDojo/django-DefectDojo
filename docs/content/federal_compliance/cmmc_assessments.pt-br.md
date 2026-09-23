---
title: Avaliações CMMC Nível 2
description: Pontue uma autoavaliação em relação ao NIST 800-171 Rev 2
weight: 5
audience: pro
---

A aba Compliance pode pontuar uma autoavaliação CMMC Nível 2 em relação ao NIST 800-171 Rev 2, usando os pesos de pontos da Metodologia de Avaliação do DoD.

![Um scorecard de avaliação CMMC Nível 2](images/05-cmmc-scorecard.png)

**Beta: trate a pontuação como uma estimativa.** Enquanto este recurso está em beta, os pesos de pontos incluídos e a pontuação SPRS resultante são consultivos e aguardam validação. Confirme qualquer pontuação com a Metodologia de Avaliação oficial NIST SP 800-171 do DoD antes de depender dela para uma submissão de avaliação ou finalidade contratual.

## Registrando resultados

Registre um resultado para cada um dos 110 requisitos:

* **Met**
* **Not met**
* **Not applicable**
* **Planned** (no POA&M)

![O fluxo de trabalho dos requisitos](images/06-cmmc-requirements.png)

### Crédito parcial

Alguns requisitos têm uma condição parcial documentada que a metodologia pontua com uma dedução reduzida em vez do peso total. Onde existir uma, a coluna **Partial Credit** permite registrá-la, e o requisito deduz os pontos reduzidos em vez disso. `3.13.11` é o exemplo: criptografia empregada, mas não validada por FIPS, deduz 3 em vez de 5.

Requisitos sem condição parcial documentada sempre deduzem o peso total.

## O que a avaliação calcula

### Pontuação SPRS

110 menos a dedução de cada requisito que não é atendido ou está apenas planejado. Os pesos são de 1, 3 ou 5 pontos, então as pontuações variam de 110 até -203.

O requisito 3.12.4 (o requisito de Plano de Segurança do Sistema) pontua como não aplicável, de acordo com a metodologia.

### Se um status condicional é possível

O CMMC permite certificação condicional com uma pontuação de pelo menos **88** (80 por cento), com toda lacuna aberta elegível para um POA&M.

A metodologia proíbe totalmente que certos requisitos entrem em POA&Ms. Entre os requisitos com peso acima de um ponto, apenas o **3.13.11** (criptografia validada por FIPS) pode ser adiado.

### O relógio de encerramento

Uma avaliação condicional tem **180 dias** para encerrar seus itens de POA&M. A avaliação vira expirada se o prazo se esgotar.

## Status

Os status avançam de **in progress** para **conditional** ou **final**. Avaliações condicionais mostram os dias restantes no seu relógio de encerramento.

As avaliações ficam sob o histórico de auditoria: cada mudança registra quem, o quê e quando.
