---
title: Adicionando Armazenamento para Arquivos Enviados
description: Expanda o armazenamento disponível para arquivos enviados em uma implantação
  com Docker Compose sem alterar a implantação em si
draft: false
weight: 11
audience: pro
---

Os arquivos enviados ficam no diretório media no host, e em uma implantação com Docker Compose o espaço disponível para eles é o que sobrar no disco da VM. Uploads grandes, como SBOMs, podem preencher esse disco. Esta página aborda como expandir esse espaço sem alterar a implantação em si.

## Por que isso funciona no nível do sistema operacional

A implantação com Docker Compose faz bind mount do diretório media do host nos contêineres que precisam dele, tanto os contêineres da aplicação quanto o nginx que devolve os arquivos enviados aos usuários. Os contêineres leem e gravam em um caminho no host, portanto, qualquer sistema de arquivos montado nesse caminho é o que eles utilizam. Montar mais capacidade ali é transparente para a aplicação.

É por isso que a abordagem aqui é uma mudança no sistema operacional, e não uma mudança na implantação. Manter inalterado o arquivo Compose que acompanha sua versão mantém sua instalação consistente com outras implantações on-premise, e evita perder a alteração quando uma atualização substituir esse arquivo.

## Armazenamento em bloco, a opção mais direta

Montar um dispositivo de bloco adicional é a forma usual de lidar com um disco cheio no Linux, e é a opção a ser considerada primeiro. Um volume NAS ou SAN funciona, assim como o armazenamento em bloco de um provedor de nuvem, como um volume Amazon EBS.

Separar o armazenamento da aplicação do disco do sistema operacional é uma boa prática de modo geral, então você tem duas escolhas razoáveis. Monte o dispositivo no diretório media para dar aos uploads sua própria capacidade, ou monte-o um nível acima, no diretório de implantação, para que todos os dados da aplicação fiquem em um sistema de arquivos separado da VM.

## Armazenamento de objetos, com ressalvas

Usar armazenamento de objetos, como o Amazon S3, para armazenar os uploads é viável e remove completamente o teto de capacidade, mas é uma opção menos natural do que um dispositivo de bloco. Considere os pontos a seguir antes de escolher essa opção.

Armazenamento de objetos não é um sistema de arquivos. O S3 não suporta gravações aleatórias, anexação a um arquivo existente ou bloqueio de arquivos. Uma camada FUSE disfarça essas lacunas, mas está emulando uma semântica que o armazenamento subjacente não possui.

A latência é maior do que em um dispositivo de bloco. Isso afeta os uploads e, como o nginx serve os arquivos enviados a partir do mesmo diretório, também afeta os downloads.

Isso adiciona dependências de rede. Dependendo de onde a VM está localizada na sua rede, alcançar o bucket pode envolver travessia de rede adicional, e esse caminho passa a precisar estar disponível para que os uploads funcionem.

As reinicializações exigem cuidado. O bucket precisa ser montado na inicialização, o que introduz uma relação de temporização entre a conclusão da montagem e a inicialização do DefectDojo. Dependendo da latência, isso pode causar uma reinicialização travada ou uma inicialização com a montagem ainda não pronta.

As permissões precisam estar alinhadas. As permissões IAM do bucket precisam ser compatíveis com as permissões do sistema de arquivos que a aplicação necessita para gravar os uploads.

### Ferramentas para montar armazenamento de objetos

Três ferramentas são comumente usadas para montar o S3 como um sistema de arquivos no Linux.

`rclone mount` é estável, mantido ativamente, e oferece modos de cache de sistema de arquivos virtual que lidam bem com o buffering de leitura e gravação. Das três, essa é a que recomendaríamos caso você opte por esse caminho.

`goofys` é otimizado para velocidade. Ele consegue isso realizando criações e gravações de arquivos de forma assíncrona e ignorando as operações que o S3 não suporta nativamente, como gravações aleatórias e bloqueio de arquivos.

`s3fs-fuse` é o mais compatível com POSIX dos três, suportando recursos como alteração de propriedade e permissões, mas o fato de imitar um sistema de arquivos real o torna consideravelmente mais lento que o goofys.

## Movendo o diretório media para um novo sistema de arquivos

Isso requer um período de indisponibilidade, já que a aplicação não pode estar gravando uploads enquanto eles estão sendo copiados.

1. Pare o DefectDojo com `dojo-compose-cli app stop`, para que nada mude por baixo dos panos durante a movimentação.
2. Renomeie o diretório media existente para mantê-lo como um ponto de rollback, por exemplo, movendo `media` para `old-media` dentro do seu diretório de implantação.
3. Crie um diretório vazio no caminho media original para atuar como ponto de montagem.
4. Anexe o novo sistema de arquivos. Os detalhes dependem do que você escolheu acima, mas se resumem a três coisas: disponibilizar o armazenamento para o Linux, o que, no caso de armazenamento de objetos, significa criar o bucket e suas permissões; montá-lo no caminho media; e fazer com que a montagem sobreviva a uma reinicialização, geralmente com uma entrada em `/etc/fstab` ou o equivalente para a sua ferramenta.
5. Copie o conteúdo antigo para o novo local, preservando a propriedade e as permissões. `rsync -Pav` do diretório antigo para o novo faz isso e relata o progresso, o que é útil quando há muito o que mover.
6. Confirme que os arquivos chegaram. No caso de armazenamento de objetos, verificar o bucket no console do seu provedor é a forma mais rápida de garantir que a montagem está realmente gravando onde você imagina.
7. Inicie o DefectDojo com `dojo-compose-cli app start` e envie um arquivo de teste. Se o upload falhar, os logs do contêiner indicarão o motivo, e as permissões costumam ser a causa mais comum.

Mantenha o diretório antigo até que o upload de teste seja bem-sucedido e você tenha confirmado que os arquivos migrados dele estão legíveis na UI. Esse é o seu caminho de volta caso o novo sistema de arquivos não se comporte como esperado.

## Escopo de suporte

Estas são recomendações gerais. Adicionar armazenamento a uma VM é uma tarefa do sistema operacional, e os detalhes específicos do método escolhido, principalmente um armazenamento de objetos montado via FUSE, estão fora do escopo do suporte on-premise. A abordagem é deliberadamente estruturada para manter sua implantação consistente com todas as outras instalações on-premise, deixando inalterado o arquivo Compose que fornecemos e resolvendo o problema de capacidade na camada do sistema operacional, onde ele pertence.

Se você estiver avaliando as opções para o seu ambiente, entre em contato com [support@defectdojo.com](mailto:support@defectdojo.com) e podemos conversar sobre as vantagens e desvantagens antes de você se comprometer com uma delas.
