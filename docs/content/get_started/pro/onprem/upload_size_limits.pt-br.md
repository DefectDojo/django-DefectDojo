---
title: Limites de Tamanho de Upload para Arquivos de Scan Grandes
description: Por que um arquivo de scan grande falha ao ser enviado, e qual limite
  aumentar em implantações Kubernetes e Docker Compose
draft: false
weight: 10
audience: pro
---

Um arquivo de scan grande pode ser rejeitado por mais de um limite, em pontos diferentes do caminho da requisição, e o erro que você recebe indica qual deles você atingiu. Esta página aborda onde esses limites ficam e como aumentá-los em uma implantação self-hosted.

## Qual limite estou atingindo

| O que você vê | De onde veio |
| --- | --- |
| Um `413 Request Entity Too Large` simples, sem estilo, sem nenhuma página do DefectDojo ao redor | O controlador de ingress rejeitou a requisição antes que ela chegasse à aplicação |
| `Report file is too large. Maximum supported size is N MB` | O limite da aplicação, reportado pelo próprio DefectDojo |
| O upload roda por um tempo e então falha, em vez de ser recusado imediatamente | Um timeout, e não um limite de tamanho |

Trabalhe de fora para dentro. Não faz sentido aumentar o limite da aplicação se o controlador de ingress já está recusando a requisição antes.

## O limite da aplicação

O DefectDojo aplica um tamanho máximo de arquivo de scan próprio, e rejeita qualquer arquivo maior com uma mensagem indicando o limite atual. O padrão é 100 MB.

No chart Helm, defina-o nos seus values:

```yaml
dojo:
  scanMaxFileSize: 100
```

Para implantações com Docker Compose, defina `DD_SCAN_FILE_MAX_SIZE` em vez disso, em megabytes.

## O limite do ingress

Esse é o que produz um `413` simples sem o estilo do DefectDojo, porque a requisição nunca chega à aplicação.

O chart define um limite de corpo de requisição no ingress, com padrão de 2400 MB:

```yaml
django:
  ingress:
    maxBodySize: "2400m"
```

Esse valor é emitido como a annotation `nginx.ingress.kubernetes.io/proxy-body-size`. Ela é emitida em todas as plataformas, e não somente no Kubernetes genérico, porque o controlador de ingress nginx costuma ser usado na frente de uma plataforma gerenciada. Defini-lo como uma string vazia omite a annotation, e isso requer `django.ingress.platformAnnotations.enabled`, que vem habilitado por padrão.

Controladores diferentes do nginx ignoram essa annotation, então neles você aumenta o limite pelo próprio mecanismo do controlador:

| Controlador padrão da plataforma | Onde o limite fica |
| --- | --- |
| EKS com o AWS Load Balancer Controller | Configuração do ALB |
| GKE com o controlador de ingress GCE | Configuração do load balancer |
| AKS com Application Gateway | O limite de corpo de requisição do Application Gateway |
| OpenShift Route | `tuningOptions` do HAProxy no router |

### Timeouts quando o nginx fica na frente de uma plataforma gerenciada

O chart emite timeouts generosos de proxy do nginx, 1800 segundos para leitura, envio e conexão, além de desabilitar o buffering de proxy. Essas annotations só são emitidas quando a plataforma é Kubernetes genérico. No EKS, GKE, AKS e OpenShift, o chart emite as annotations próprias dessa plataforma, porque é isso que o controlador padrão dela lê.

Isso importa se você roda o controlador de ingress nginx em uma dessas plataformas. Você obtém a annotation de tamanho de corpo, já que essa é emitida em todo lugar, mas não os timeouts. Um upload grande pode então passar pela verificação de tamanho e ainda assim ser cortado no meio do caminho pelo timeout padrão do controlador, que é de onde vem a terceira linha da tabela acima. Forneça os timeouts você mesmo:

```yaml
django:
  ingress:
    annotations:
      nginx.ingress.kubernetes.io/proxy-read-timeout: "1800"
      nginx.ingress.kubernetes.io/proxy-send-timeout: "1800"
```

## O limite da rota de importação

Implantações Kubernetes executam importações de scan por meio de pods dedicados, e o nginx na frente das rotas de importação tem seu próprio limite de tamanho de corpo. Ele é derivado, em vez de fixo:

```yaml
django:
  uwsgiImport:
    maxBodySizeMb: null
```

Mantido como `null`, ele é calculado como `dojo.scanMaxFileSize` mais 5 MB, a margem que cobre a sobrecarga da codificação multipart. Aumentar o limite da aplicação, portanto, aumenta esse limite junto, e a maioria das implantações nunca precisa defini-lo. Defina um inteiro somente se quiser sobrepor o valor derivado.

## Implantações com Docker Compose

Implantações com Compose não têm controlador de ingress, então o limite de ingress não se aplica. O nginx que acompanha a implantação limita os corpos de requisição a 800 MB, que é o teto prático, e o limite da aplicação se aplica sobre isso, como em qualquer lugar.

Aumentar o limite do nginx significa alterar um arquivo que acompanha a implantação, e esses arquivos são substituídos quando você atualiza, em vez de preservados como o seu diretório de personalizações. Entre em contato com o suporte antes de alterá-lo, para que a mudança não desapareça na próxima atualização.

## Dúvidas ou suporte

Se os uploads continuarem falhando depois de aumentar o limite que corresponde ao seu sintoma, reúna a resposta que seu cliente recebeu e os logs do nginx ou do controlador que cobrem a tentativa, então entre em contato com [support@defectdojo.com](mailto:support@defectdojo.com).
