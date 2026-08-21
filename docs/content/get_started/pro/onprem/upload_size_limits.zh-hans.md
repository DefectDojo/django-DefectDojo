---
title: 大型扫描文件的上传大小限制
description: 大型扫描文件上传失败的原因，以及在 Kubernetes 和 Docker Compose 部署中应调整哪个限制
draft: false
weight: 10
audience: pro
---

大型扫描文件可能会在请求路径的不同环节被多个限制中的任意一个拒绝，您收到的错误信息会告诉您具体触发了哪一个限制。本页说明这些限制分别位于何处，以及如何在自托管部署中调高它们。

## 我碰到的是哪个限制

| 您看到的现象 | 来源 |
| --- | --- |
| 纯粹的 `413 Request Entity Too Large`，没有任何样式，也没有 DefectDojo 页面包裹 | Ingress 控制器在请求到达应用程序之前就将其拒绝 |
| `Report file is too large. Maximum supported size is N MB` | 应用程序自身的限制，由 DefectDojo 报告 |
| 上传运行一段时间后才失败，而不是立即被拒绝 | 属于超时，而非大小限制 |

请由外到内排查。如果 ingress 控制器已经在最先拒绝请求，那么调高应用程序的限制也无济于事。

## 应用程序限制

DefectDojo 自身也强制执行一个最大扫描文件大小，超过该大小的文件会被拒绝，并在错误信息中给出当前的限制值。默认值为 100 MB。

在 Helm chart 中，可以在 values 里设置该值：

```yaml
dojo:
  scanMaxFileSize: 100
```

对于 Docker Compose 部署，请改为设置 `DD_SCAN_FILE_MAX_SIZE`，单位为兆字节（MB）。

## Ingress 限制

这正是产生纯粹的 `413` 错误、且没有 DefectDojo 样式的那个限制，因为请求根本没有到达应用程序。

该 chart 会在 ingress 上设置请求体大小上限，默认值为 2400 MB：

```yaml
django:
  ingress:
    maxBodySize: "2400m"
```

该值会以 `nginx.ingress.kubernetes.io/proxy-body-size` 注解的形式写出。它会在所有平台上生成，而不仅限于通用 Kubernetes，因为 nginx ingress 控制器也经常被用在托管平台之前。将其设置为空字符串会省略该注解，并且这需要 `django.ingress.platformAnnotations.enabled` 为启用状态（该项默认已启用）。

nginx 以外的控制器会忽略该注解，因此在这些控制器上，需要通过控制器自身的机制来调高限制：

| 平台默认控制器 | 限制所在位置 |
| --- | --- |
| 使用 AWS Load Balancer Controller 的 EKS | ALB 配置 |
| 使用 GCE ingress 控制器的 GKE | 负载均衡器配置 |
| 使用 Application Gateway 的 AKS | Application Gateway 的请求体限制 |
| OpenShift Route | 路由器上的 HAProxy `tuningOptions` |

### 当 nginx 位于托管平台前端时的超时问题

该 chart 会设置较为宽松的 nginx 代理超时时间，读取、发送和连接均为 1800 秒，并禁用代理缓冲。这些注解仅在平台为通用 Kubernetes 时才会生成。在 EKS、GKE、AKS 和 OpenShift 上，该 chart 会改为生成对应平台自身的注解，因为这才是各平台默认控制器所读取的内容。

如果您在上述某个平台上运行 nginx ingress 控制器，这一点就需要留意。您会得到请求体大小注解（因为它在所有平台上都会生成），但不会得到超时注解。这样一来，大文件上传可能通过了大小检查，却仍会被控制器的默认超时中途截断，这正是上表第三行现象的来源。请自行提供超时设置：

```yaml
django:
  ingress:
    annotations:
      nginx.ingress.kubernetes.io/proxy-read-timeout: "1800"
      nginx.ingress.kubernetes.io/proxy-send-timeout: "1800"
```

## 导入路由限制

Kubernetes 部署会通过专用的 Pod 来运行扫描导入，而位于导入路由前端的 nginx 有其自身的请求体大小上限，该值是推算得出的，而非固定值：

```yaml
django:
  uwsgiImport:
    maxBodySizeMb: null
```

保持为 `null` 时，其值按照 `dojo.scanMaxFileSize` 加 5 MB 计算，这部分余量用于覆盖 multipart 编码带来的开销。因此调高应用程序限制也会同步调高该值，大多数部署都无需单独设置。只有在需要覆盖推算值时，才需要设置一个整数。

## Docker Compose 部署

Compose 部署没有 ingress 控制器，因此 ingress 限制并不适用。部署自带的 nginx 会将请求体上限设为 800 MB，这就是实际的上限值，而应用程序限制会像在其他场景中一样，叠加在这之上生效。

调高 nginx 的上限，意味着要修改部署自带的一个文件，而这类文件在升级时会被替换，不像您的自定义配置目录那样会被保留。请在修改之前联系支持团队，以免该修改在下次升级时消失。

## 问题或支持

如果在调高与您的症状相匹配的限制之后，上传仍然失败，请收集客户端收到的响应内容，以及本次尝试所对应的 nginx 或控制器日志，然后联系 [support@defectdojo.com](mailto:support@defectdojo.com)。
