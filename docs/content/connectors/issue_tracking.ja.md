---
title: 課題管理連携
description: DefectDojo の検出事項を課題管理システムと同期させ、修復と説明責任を効率化します。
weight: 6
aliases:
- /ja/issue_tracking/
- /ja/issue_tracking/intro/
- /ja/issue_tracking/intro/intro/
---

## 概要

DefectDojo の課題管理連携は、脆弱性管理のワークフローを既存の課題管理システムと接続します。セキュリティの検出事項から課題を自動的に作成・更新することで、DefectDojo は開発チームや運用チームがすでに使用しているツール内で脆弱性が可視化され、担当者が割り当てられ、対応されることを支援します。

| エディション      | 対応する課題管理連携 |
|--------------|---------------------------------------|
| Community Edition  | * [Jira](/connectors/os_jira/os__jira_guide/)                          |
| Pro          | * [Jira](/connectors/toolreference/jira/)([旧ガイド](/connectors/downstream/pro__jira_guide/))<br>* [Azure DevOps](/connectors/toolreference/azure_devops_boards/)<br>* [Bitbucket](/connectors/toolreference/bitbucket/#downstream-connector)<br>* [Freshservice](/connectors/toolreference/freshservice/)<br>* [GitHub](/connectors/toolreference/github/#downstream-connector)<br>* [GitLab Boards](/connectors/toolreference/gitlab/#downstream-connector)<br>* [Linear](/connectors/toolreference/linear/)<br>* [PagerDuty](/connectors/toolreference/pagerduty/)<br>* [ServiceDesk Plus](/connectors/toolreference/servicedesk_plus/)<br>* [ServiceNow](/connectors/toolreference/servicenow/)<br>* [Shortcut](/connectors/toolreference/shortcut/)<br>* [Zendesk](/connectors/toolreference/zendesk/) |


有効にすると、DefectDojo は課題を自動的に、または製品やエンゲージメントから選択的に作成できます。検出事項が DefectDojo 内で更新される(解決、緩和済み、再アクティブ化される)と、対応する課題も同期を保つことができ、両方のシステムが現在のリスク状態を反映するようになります。

## 追跡される内容

各課題には、深刻度、説明、証拠、修復ガイダンスといった主要な脆弱性の詳細を含めることができます。DefectDojo と課題管理システム間のリンクにより、発見から解決までのトレーサビリティが提供され、レポート作成、監査、継続的な改善をサポートします。

## 課題管理連携が重要な理由

セキュリティの検出事項は、アクション可能な状態になって初めて効果を発揮します。DefectDojo を課題管理システムと連携させることで、検出と修復のギャップを埋め、セキュリティ対応作業を既存のエンジニアリングワークフローに直接組み込むことができます。これによりコンテキストスイッチングが減り、説明責任が向上し、チームがより迅速に問題を修復できるようになります。
