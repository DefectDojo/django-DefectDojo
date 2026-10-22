---
title: インストール
description: DefectDojoはさまざまなインストールオプションをサポートしています。
draft: false
weight: 1
audience: opensource
aliases:
- /ja/en/open_source/installation/installation
---

## **推奨オプション**
---

### Docker Compose

手順は[DOCKER.md](<https://github.com/DefectDojo/django-DefectDojo/blob/dev/readme-docs/DOCKER.md>)をご覧ください

### SaaS(サポートを含み、プロジェクトを支援)

[SaaSリンク](https://defectdojo.com/platform)

---
## **Dockerイメージのバリエーション**
---

DefectDojoは、複数のバリエーションでDockerイメージを公開しています。

| | AMD64 | ARM64 |
|---|---|---|
| **Debian** | ✅ サポート対象 | ⚠️ ユニットテスト済み |
| **Alpine** | ⚠️ コミュニティ | ⚠️ コミュニティ |

**AMD64上のDebian**は、公式にサポートおよびテストされている構成です。すべてのCIテスト(ユニット、統合、パフォーマンス)がこの組み合わせに対して実行されます。

**ARM64上のDebian**はビルドされ、CIでユニットテストの対象となっていますが、統合テストやパフォーマンステストは実行されません。

**Alpine**版はビルド・公開されていますが、自動テストの対象にはなっていません。自己責任でご利用ください。

---
## **勇気ある方向けのオプション(公式サポート対象外)**
---
### Kubernetes

手順は[KUBERNETES.md](<https://github.com/DefectDojo/django-DefectDojo/blob/dev/readme-docs/KUBERNETES.md>)をご覧ください

### godojoを使ったローカルインストール

手順はgodojoリポジトリの[README.md](<https://github.com/DefectDojo/godojo/blob/master/README.md>)をご覧ください

---

## 設定のカスタマイズ

[設定](../configuration)をご覧ください
