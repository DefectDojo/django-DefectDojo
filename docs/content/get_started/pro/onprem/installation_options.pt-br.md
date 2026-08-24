---
title: Auto-hospedagem do DefectDojo Pro
date: 2021-02-02 20:46:29+01:00
weight: 5
audience: pro
---

O DefectDojo Pro pode ser totalmente auto-hospedado em seu próprio ambiente, dando a você controle sobre sua infraestrutura, dados e postura de segurança. Ele é adequado para organizações com requisitos de conformidade, residência de dados ou segurança interna que descartam uma implantação hospedada, e oferece os mesmos recursos do produto hospedado na nuvem.

Esta página aborda os modelos de implantação disponíveis, o que você precisa antes de começar, e onde o restante desta seção se encaixa.

## Dois modelos de implantação

**Docker Compose em um único host** é o mais simples dos dois. A aplicação, os workers assíncronos e o cache são executados todos em uma única máquina, gerenciados por uma ferramenta de linha de comando que fornecemos. Como nada nesse arranjo escala horizontalmente, o host precisa ser dimensionado para seu pico, e não para sua média, e para a maioria das implantações o pico é uma grande importação de scan chegando enquanto as pessoas estão trabalhando na interface.

**Kubernetes, usando nosso Helm chart**, executa esses mesmos componentes como workloads separados. Isso permite provisionar para o estado estável e adicionar réplicas quando a carga chega, e permite escalar a parte que está realmente ocupada em vez da máquina inteira.

Ambos os modelos usam PostgreSQL. Para produção, recomendamos um banco de dados gerenciado externo, que é o que o Helm chart assume por padrão. As ferramentas do Compose também podem executar o PostgreSQL em um container junto com a aplicação, o que é conveniente para avaliação, mas não é o que você deseja para dados de produção.

Se você já executa Kubernetes, use-o. Um único host funciona perfeitamente bem, e muitas implantações são executadas dessa forma, mas você acaba comprando uma margem que não pode realocar. Se você não executa Kubernetes e não quer executar, o Compose é uma escolha legítima, e não um compromisso.

## Antes de começar

Dimensione a implantação primeiro. Ambos os modelos dependem de saber aproximadamente quantos achados você espera manter e quantas pessoas estarão trabalhando no produto ao mesmo tempo, e esses dois números orientam partes diferentes da implantação. As orientações de dimensionamento de hardware nesta seção abordam ambos.

Você precisará de um arquivo de licença e das ferramentas de implantação para o modelo escolhido. O DefectDojo fornece ambos quando sua assinatura começa. Se você não os tiver, ou precisar que sejam reemitidos, entre em contato com seu representante de conta ou [support@defectdojo.com](mailto:support@defectdojo.com).

Você também precisará de um local para executá-lo, um banco de dados PostgreSQL que ele possa alcançar, e um nome de host que resolva para a implantação. As páginas de instalação individuais abordam as especificidades de cada modelo.

## O que mais há nesta seção

As páginas ao lado desta abordam o restante do ciclo de vida. Há orientações de dimensionamento para escolher o hardware, instruções para migrar uma instância open source existente para uma implantação Pro auto-hospedada, e um procedimento para instalação em ambientes onde o host de destino não tem rota para a internet.

Para implantações já em execução, há páginas sobre atualização, sobre backup, sobre aumentar os limites que rejeitam uploads de scans grandes, e sobre expandir o armazenamento para arquivos enviados quando um host fica sem espaço. Use a navegação da seção para explorá-las.

## Dúvidas

Se você está avaliando os dois modelos para seu ambiente, ou se suas circunstâncias não se assemelham às suposições feitas aqui, preferimos conversar sobre isso antes de você provisionar do que depois.

Clientes existentes devem entrar em contato com seu representante de conta ou [support@defectdojo.com](mailto:support@defectdojo.com). Se você está avaliando o DefectDojo Pro e quer discutir a auto-hospedagem, fale conosco em [hello@defectdojo.com](mailto:hello@defectdojo.com).
