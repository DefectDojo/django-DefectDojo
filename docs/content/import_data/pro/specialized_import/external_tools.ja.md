---
title: Universal Importer & DefectDojo-CLI
description: コマンドラインからDefectDojoにファイルをインポートする
draft: false
weight: 2
audience: pro
aliases:
- /ja/en/connecting_your_tools/external_tools
---

<span style="background-color:rgba(242, 86, 29, 0.3)">注: 以下の外部ツールはDefectDojo Pro限定の機能です。これらのバイナリは、DefectDojo Proライセンスを持つインスタンスに接続されていない限り動作しません。</span>

## 外部ツールについて

`defectdojo-cli`と`universal-importer`は、検出事項と関連オブジェクトのインポートおよび再インポートのプロセスを効率化するために設計されたコマンドラインツールであり、DefectDojo APIとのこうしたやり取りを迅速にセットアップしたいユーザーに最適です。

DefectDojo-CLIはUniversal Importerと同じ機能を備えていますが、それに加えてDefectDojoから検出事項をJSONまたはCSVにエクスポートする機能も備えています。

## インストール

1. ユーザープロフィールメニューから「External Tools」を探します。

2. プラットフォームから、お使いのオペレーティングシステムに適したバイナリをダウンロードします。

![image](images/external-tools.png)

3. ダウンロードしたアーカイブを任意のディレクトリに展開します。必要に応じて、展開したバイナリが含まれるディレクトリをシステムの$PATHに追加すると、繰り返し使用する際に便利です。

**Macintoshをお使いの場合、DefectDojo-CLIやUniversal Importerは未確認の開発元によるアプリであるため、実行がブロックされることがあります。Appleによるブロックを解除する方法については、[Appleサポート](https://support.apple.com/en-ca/guide/mac-help/mh40616/mac)を参照してください。**  

**Windowsをお使いの場合: 「Couldn't download - virus detected」というエラーが表示された場合は、Smartscreenを無効にすると解決することがあります。それでも解決しない場合は、別のブラウザを使用してCloudポータルからツールをダウンロードしてください。**

## 設定

Universal ImporterとDefectDojo-CLIは、フラグ、環境変数、または設定ファイルを使用して設定できます。最も重要な設定はAPIトークンであり、これは環境変数として設定する必要があります。

1. APIキーを環境変数に追加します。 
APIキーは以下から取得できます: `https://YOUR_INSTANCE.cloud.defectdojo.com/api/key-v2`

または 

DefectDojoのユーザーインターフェースから、
右上のユーザードロップダウンで取得できます。

![image](images/api-token.png)

2. APIトークン用の環境変数を設定します。

**DefectDojo-CLIの場合:**
	`export DD_CLI_API_TOKEN=YOUR_API_KEY`

**Universal Importerの場合:**
	`export DD_IMPORTER_DOJO_API_TOKEN=YOUR_API_KEY`

注: Windowsでは、`export`の代わりに`set`を使用してください。

### Windows: PowerShellを使用する場合

1. PowerShellを開きます（Windowsキーを押して「PowerShell」を検索）。
2. 環境変数を設定します。
   - **一時的な設定:**
     ```powershell
     $env:DD_IMPORTER_DOJO_API_TOKEN = "[VALUE_FROM_DEFECTDOJO_API]"
     $env:DD_IMPORTER_DEFECTDOJO_URL=”[e.g. http://localhost:8080/defectdojo]”
     ```
   - **恒久的な設定:**
     ```powershell
     [Environment]::SetEnvironmentVariable("DD_IMPORTER_DOJO_API_TOKEN", "[VALUE_FROM_DEFECTDOJO_API]", "Machine")
     ```
3. PowerShellセッションを再起動します。
4. 設定を確認します。
   ```powershell
   echo $env:DD_IMPORTER_DOJO_API_TOKEN
   echo $env:DD_IMPORTER_DEFECTDOJO_URL
   ```

### Windows: コマンドプロンプトを使用する場合（管理者アカウント）
1. コマンドプロンプトを開きます（Windowsキーを押して「Command Prompt」を検索）。
2. 環境変数を設定します。
   - **一時的な設定:**
     ```cmd
     set DD_IMPORTER_DOJO_API_TOKEN = "[VALUE_FROM_DEFECTDOJO_API]"
     set DD_IMPORTER_DEFECTDOJO_URL=”[e.g. http://localhost:8080/defectdojo]”
     ```
   - **恒久的な設定:**
     ```cmd
     setx DD_IMPORTER_DOJO_API_TOKEN = "[VALUE_FROM_DEFECTDOJO_API]"
     setx DD_IMPORTER_DEFECTDOJO_URL=”[e.g. http://localhost:8080/defectdojo]”
     ```

### Windows設定を使用する場合（非管理者アカウント）
1. `Win + I`を押してシステム設定ダイアログを開きます。
2. 検索ボックスに「environment」と入力します。
3. 「Edit Environment variables for your account」を選択します。
4. 「User variables for [username]」の下にある「New…」ボタンをクリックします。
5. 変数を設定します。
   - **変数名:** `DD_IMPORTER_DOJO_API_TOKEN`
   - **変数値:** `[VALUE_FROM_DEFECTDOJO_API]`
6. 「OK」をクリックします。
7. DD_IMPORTER_DEFECTDOJO_URL変数についても、手順4から6を繰り返します
8. 開いているコマンドウィンドウをすべて再起動します。
9. 設定を確認します。
   ```cmd
   echo %DD_IMPORTER_DOJO_API_TOKEN%
   echo %DD_IMPORTER_DEFECTDOJO_URL%
   ```

## DefectDojo-CLI

`defectdojo-cli`は、スキャン結果をDefectDojoにシームレスに統合し、検出事項と関連オブジェクトのインポートおよび再インポートのプロセスを効率化します。使いやすさを重視して設計されたこのツールは、さまざまなエンドポイントに対応しており、初回インポートとその後の再インポートの両方に対応します。これは、DefectDojo APIとの堅牢かつ柔軟なやり取りを必要とするユーザーに最適です。DefectDojo-CLIは`universal-importer`と同じ機能を実行できるほか、検出事項のエクスポート機能も備えています。

### コマンド

- [`import`](./#import)       検出事項をDefectDojoにインポートします。
- [`reimport`](./#reimport)     検出事項をDefectDojoに再インポートします。
- [`export`](./#export)	検出事項をDefectDojoからエクスポートします。
- [`interactive`](./#interactive)   検出事項のインポートおよび再インポートのプロセスをステップごとに設定するインタラクティブモードを開始します

### グローバルオプション

`--help, -h`     
* ヘルプを表示します

`--version, -v`
* バージョンを表示します

#### CLIの書式設定

`--no-color`
* カラー出力を無効にします。（デフォルト: false）`[$DD_CLI_NO_COLOR]`
`--no-emojis, --no-emoji`

* 出力内の絵文字を無効にします。（デフォルト: false）`[$DD_CLI_NO_EMOJIS]`

* `--verbose`
詳細な出力を有効にします。（デフォルト: false）`[$DD_CLI_VERBOSE]`

### インポート

importコマンドを使用して、新しい検出事項をDefectDojoにインポートします。

#### 使用方法

```
defectdojo-cli [global options] import <required flags> [optional flags]
	or: defectdojo-cli [global options] import  --config ./config-file-path
	or: defectdojo-cli import [-h | --help]
	or: defectdojo-cli import example [subcommand options]
	or: defectdojo-cli import example [-h | --help]

>> The API token must be set in the environment variable `DD_CLI_API_TOKEN`.
```

`import`は、2つの方法で検出事項をインポートできます。

**IDによる方法:**
* 製品を作成します（または既存の製品を使用します）
* 製品内にエンゲージメントを作成します
* engagementパラメータにエンゲージメントのidを指定します

このシナリオでは、エンゲージメント内に新しいテストが作成されます。

**名前による方法:**

* 製品を作成します（または既存の製品を使用します）
* 製品内にエンゲージメントを作成します
* product-nameを指定します
* engagement-nameを指定します
* 必要に応じてproduct-type-nameを指定します

このシナリオでは、DefectDojoは指定された詳細情報に基づいてエンゲージメントを検索します。

名前を使用する場合、`auto-create-context=true`を使用することで、インポーターにエンゲージメント、製品、製品タイプを自動的に作成させることができます。
`deduplication-on-engagement`を使用すると、インポートされた検出事項の重複排除を、新しく作成されたエンゲージメントに限定できます。


**importの基本構文:**
```
defectdojo-cli import [options]
```

#### **importの例:**
```
defectdojo-cli import \
--defectdojo-url "https://YOUR_INSTANCE.cloud.defectdojo.com/" \
--scan-type "burp scan" \
--report-path "./examples/burp_findings.xml" \
--product-name "dev" \
--engagement-name "dev" \
--product-type-name "Research and Development" \
--test-name "burp-test-dev" \
--verified \
--active \
--minimum-severity "info" \
--tag "dev" --tag "tools" --tag "burp" --tag "test-dev" \
--test-version "0.0.1" \
--auto-create-context
```

#### コマンド
`example, x`
* importオペレーションに必要なフラグとオプションのフラグの例を表示します

#### オプション

`--active, -a` 
* インポート時に検出事項をアクティブまたは非アクティブに強制するかどうかを指定します。Trueを指定すると検出事項は強制的にアクティブになり、Falseを指定するとすべての検出事項が強制的に非アクティブになります。値が設定されていない場合、アクティブステータスは受信したレポートファイルに依存します。（デフォルト: 未設定）`[$DD_CLI_ACTIVE]`

`--api-scan-configuration value, --asc value`
* インポートまたは再インポート時に使用するAPI Scan Configurationオブジェクトのidです。（デフォルト: 0）`[$DD_CLI_API_SCAN_CONFIGURATION]`

`--apply-tags-endpoints, --te`
* trueに設定すると、（--tagオプションからの）タグがエンドポイントに適用されます（デフォルト: false） 
`[$DD_CLI_APPLY_TAGS_ENDPOINTS]`

`--apply-tags-findings, --tf`
* trueに設定すると、（--tagオプションからの）タグが検出事項に適用されます（デフォルト: false）`[$DD_CLI_APPLY_TAGS_FINDINGS]`

`--auto-create-context, --acc`
* trueに設定すると、インポーターはエンゲージメント、製品、製品タイプを自動的に作成します（デフォルト: false）`[$DD_CLI_AUTO_CREATE_CONTEXT]`

`--close-old-findings, --cof`
* Trueの場合、レポートに存在しなくなった古い検出事項は、インポート時に緩和済みとしてクローズされます。Serviceが設定されている場合、このServiceに関する検出事項のみがクローズされます。[$DD_CLI_CLOSE_OLD_FINDINGS]

`--close-old-findings-product-scope, --cofps`
* --close-old-findingsを製品内の同じタイプの検出事項**すべて**に適用するかどうかを選択します。デフォルトではfalseに設定されており、エンゲージメント内の同じタイプの古い検出事項のみが対象となります（Close Old Findingsによってクローズされます）。[$DD_CLI_CLOSE_OLD_FINDINGS_PRODUCT_SCOPE]

`--deduplication-on-engagement, --doe`
* trueに設定すると、インポーターはインポートされた検出事項の重複排除を、新しく作成されたエンゲージメントに限定します。（デフォルト: false）`[$DD_CLI_DEDUPLICATION_ON_ENGAGEMENT]`

`--engagement-id value, --ei value`
* 検出事項のインポート先となるエンゲージメントのidです。（デフォルト: 0）`[$DD_CLI_ENGAGEMENT_ID]`

`--engagement-name value, -e value`
* 検出事項のインポート先となるエンゲージメントの名前です。`[$DD_CLI_ENGAGEMENT_NAME]`

`--minimum-severity value, --ms value`
* インポートすべき最低レベルの深刻度を指定します。有効な値は、Critical、High、Medium、Low、Infoです。（デフォルト: "Info"）`[$DD_CLI_MINIMUM_SEVERITY]`

`--product-name value, -p value`
* 検出事項のインポート先となる製品の名前です。`[$DD_CLI_PRODUCT_NAME]`

`--product-type-name value, --pt value`
* 検出事項のインポート先となる製品タイプの名前です。`[$DD_CLI_PRODUCT_TYPE_NAME]`

`--report-path value, -r value`
* インポートするレポートへのパスです（必須）。`[$DD_CLI_REPORT_PATH]`

`--scan-type value, -s value`
* ツールのスキャンタイプです（必須）。`[$DD_CLI_SCAN_TYPE]`

`--tag value, -t value [ --tag value, -t value ]`
* テストオブジェクトに適用するタグです `[$DD_CLI_TAGS]`

`--test-name value, --tn value`
* 検出事項のインポート先となるテストの名前です - デフォルトではスキャンタイプの名前が使用されます。`[$DD_CLI_TEST_NAME]`

`--test-version value, -V value`
* テストのバージョンです。`[$DD_CLI_TEST_VERSION]`

`--verified, -v`
* インポート時に検出事項を検証済みに設定するかどうかを指定します。Trueを指定すると検出事項は強制的に検証済みになります。値が設定されていない場合、検証済みステータスは受信したレポートファイルに依存します。`[$DD_CLI_VERIFIED]`

**設定:**

`--config value, -c value`          
* TOML設定ファイルへのパスで、オプションの値を設定するために使用されます。設定ファイルとCLIの両方でオプションが設定されている場合、CLIで設定された値が優先されます。`[$DD_CLI_CONFIG_FILE]`
`--defectdojo-url value, -u value`
* 検出事項のインポート先となるDefectDojoインスタンスのURLです（必須）。`[$DD_CLI_DEFECTDOJO_URL]`
* --insecure-tls, --no-tls          指定されたDefectDojoインスタンスに接続する際のTLS検証エラーを無視します。ほとんどのユーザーはこのフラグを有効にすべきではありません。（デフォルト: false）`[$DD_CLI_INSECURE_TLS]`

### 再インポート

`reimport`コマンドを使用すると、新しいレポートからの検出事項で既存のテストを拡張できます。方法は次の2通りです。

IDによる方法:
- 製品を作成します（または既存の製品を使用します）
- 製品内にエンゲージメントを作成します
- スキャンレポートをインポートし、テストのidを確認します
- これをtest-idパラメータに指定します

名前による方法:
- 製品を作成します（または既存の製品を使用します）
- 製品内にエンゲージメントを作成します
- レポートをインポートすると、テストが作成されます
- product-nameを指定します
- engagement-nameを指定します
- 任意: test-nameを指定します

このシナリオでは、DefectDojoは指定された詳細情報に基づいてテストを検索します。test-nameが指定されていない場合、エンゲージメント内の最新のテストがscan-typeに基づいて選択されます。

名前を使用する場合、`auto-create-context=true`を使用することで、インポーターにエンゲージメント、製品、製品タイプを自動的に作成させることができます。
`deduplication-on-engagement`を使用すると、インポートされた検出事項の重複排除を、新しく作成されたエンゲージメントに限定できます。

#### 使用方法

```
defectdojo-cli [global options] reimport <required flags> [optional flags]
   or: defectdojo-cli [global options] reimport  --config ./config-file-path
   or: defectdojo-cli reimport [-h | --help]
   or: defectdojo-cli reimport example [subcommand options]
   or: defectdojo-cli reimport example [-h | --help]

>> The API token must be set in the environment variable `DD_CLI_API_TOKEN`.
```

#### **reimportの例:**

```
defectdojo-cli reimport \
--defectdojo-url "https://YOUR_INSTANCE.cloud.defectdojo.com/" \
--scan-type "Nancy Scan" \
--report-path "./examples/nancy_findings.json" \
--test-id 11 \
--verified \
--active \
--minimum-severity "info" \
--tag "dev" --tag "tools" --tag "nancy" --tag "test-dev" \
--test-version "1.0" \
--auto-create-context
```

#### コマンド

```
example, x  Shows an example of required and optional flags for reimport operation
```

#### オプション

`--active, -a`                                    
* インポート時に検出事項をアクティブまたは非アクティブに強制するかどうかを指定します。Trueを指定すると検出事項は強制的にアクティブになり、Falseを指定するとすべての検出事項が強制的に非アクティブになります。値が設定されていない場合、アクティブステータスは受信したレポートファイルに依存します。`[$DD_CLI_ACTIVE]`

`--api-scan-configuration value, --asc value`

* インポートまたは再インポート時に使用するAPI Scan Configurationオブジェクトのidです。（デフォルト: 0）`[$DD_CLI_API_SCAN_CONFIGURATION]`

`--apply-tags-endpoints, --te`                     
* trueに設定すると、（--tagオプションからの）タグがエンドポイントに適用されます（デフォルト: false）`[$DD_CLI_APPLY_TAGS_ENDPOINTS]`

`--apply-tags-findings, --tf`                      
* trueに設定すると、（--tagオプションからの）タグが検出事項に適用されます（デフォルト: false）`[$DD_CLI_APPLY_TAGS_FINDINGS]`

`--auto-create-context, --acc`                 
* trueに設定すると、インポーターはエンゲージメント、製品、製品タイプを自動的に作成します（デフォルト: false）`[$DD_CLI_AUTO_CREATE_CONTEXT]`

`--close-old-findings, --cof`
* Trueの場合、レポートに存在しなくなった古い検出事項は、インポート時に緩和済みとしてクローズされます。Serviceが設定されている場合、このServiceに関する検出事項のみがクローズされます。[$DD_CLI_CLOSE_OLD_FINDINGS]

`--close-old-findings-product-scope, --cofps`
* --close-old-findingsを製品内の同じタイプの検出事項**すべて**に適用するかどうかを選択します。デフォルトではfalseに設定されており、エンゲージメント内の同じタイプの古い検出事項のみが対象となります（Close Old Findingsによってクローズされます）。[$DD_CLI_CLOSE_OLD_FINDINGS_PRODUCT_SCOPE]

`--deduplication-on-engagement, --doe`          
* trueに設定すると、インポーターはインポートされた検出事項の重複排除を、新しく作成されたエンゲージメントに限定します。（デフォルト: false）`[$DD_CLI_DEDUPLICATION_ON_ENGAGEMENT]`

`--engagement-name value, -e value`               
* 検出事項のインポート先となるエンゲージメントの名前です。`[$DD_CLI_ENGAGEMENT_NAME]`

`--minimum-severity value, --ms value`          
* インポートすべき最低レベルの深刻度を指定します。有効な値は、Critical、High、Medium、Low、Infoです。（デフォルト: "Info"）`[$DD_CLI_MINIMUM_SEVERITY]`

`--product-name value, -p value`                   
* 検出事項のインポート先となる製品の名前です。`[$DD_CLI_PRODUCT_NAME]`

`--product-type-name value, --pt value`         
* 検出事項のインポート先となる製品タイプの名前です。`[$DD_CLI_PRODUCT_TYPE_NAME]`

`--report-path value, -r value`                    
* インポートするレポートへのパスです（必須）。`[$DD_CLI_REPORT_PATH]`

`--scan-type value, -s value`                      
* ツールのスキャンタイプです（必須）。`[$DD_CLI_SCAN_TYPE]`

`--tag value, -t value [ --tag value, -t value ]`  
* テストオブジェクトに適用するタグです `[$DD_CLI_TAGS]`

`--test-id value, --ti value`                      
* 検出事項の再インポート先となるテストのidです。（デフォルト: 0）`[$DD_CLI_TEST_ID]`

`--test-name value, --tn value`                    
* 検出事項のインポート先となるテストの名前です - デフォルトではスキャンタイプの名前が使用されます。`[$DD_CLI_TEST_NAME]`

`--test-version value, -V value`                   
* テストのバージョンです。`[$DD_CLI_TEST_VERSION]`

`--verified, -v`                                   
* インポート時に検出事項を検証済みに設定するかどうかを指定します。Trueを指定すると検出事項は強制的に検証済みになります。値が設定されていない場合、検証済みステータスは受信したレポートファイルに依存します。`[$DD_CLI_VERIFIED]`

**設定:**

`--config value, -c value`
* TOML設定ファイルへのパスで、オプションの値を設定するために使用されます。設定ファイルとCLIの両方でオプションが設定されている場合、CLIで設定された値が優先されます。`[$DD_CLI_CONFIG_FILE]`

`--defectdojo-url value, -u value`  
* 検出事項のインポート先となるDefectDojoインスタンスのURLです（必須）。`[$DD_CLI_DEFECTDOJO_URL]`

`--insecure-tls, --no-tls`
* 指定されたDefectDojoインスタンスに接続する際のTLS検証エラーを無視します。ほとんどのユーザーはこのフラグを有効にすべきではありません。（デフォルト: false）`[$DD_CLI_INSECURE_TLS]`

### エクスポート

#### 使用方法

```
defectdojo-cli export <required options> [optional options]
	or: defectdojo-cli [global options] export --defectdojo-url <https://YOUR_INSTANCE.cloud.defectdojo.com/> --json ./output_file_path.json [optional filters]
	or: defectdojo-cli [global options] export --defectdojo-url <https://YOUR_INSTANCE.cloud.defectdojo.com/> --csv ./output_file_path.csv [optional filters]
	or: defectdojo-cli [global options] export --defectdojo-url <https://YOUR_INSTANCE.cloud.defectdojo.com/> --json ./output_file_path.json --csv ./output_file_path.csv [optional filters]
	or: defectdojo-cli [global options] export --config ./config-file-path
	or: defectdojo-cli [global options] export --config ./config-file-path --json ./output_file_path.json
	or: defectdojo-cli [global options] export --config ./config-file-path --csv ./output_file_path.csv
	or: defectdojo-cli export [-h | --help]
	or: defectdojo-cli export example [subcommand options]
	or: defectdojo-cli export example [-h | --help]

>> The API token must be set in the environment variable `DD_CLI_API_TOKEN`.
```

DefectDojo-CLIから検出事項をエクスポートするには、エクスポートしたい検出事項の詳細を記載した設定ファイルを用意する必要があります。これは、APIを介したGET Findingsメソッドと似ています。

ヘルプが必要な場合は`defectdojo-cli export --help`を使用してください。

#### **エクスポートの例**

この例では、URL、エクスポート形式、およびいくつかのフィルタパラメータを指定して、検出事項のリストを作成しています。

```
defectdojo-cli export \
--defectdojo-url "https://your-dojo-instance.cloud.defectdojo.com/"
--json "./path/to/findings.json" \
--active "true" \
--created "Past 90 days"
```

#### コマンド

`example, x`
* exportオペレーションに必要なフラグとオプションのフラグの例を表示します

`help, h`
* コマンドの一覧、または特定のコマンドのヘルプを表示します

#### オプション

**検出事項のフィルタ:**

`--active true|false, -a true|false`
* アクティブステータスによる検出事項のフィルタです。`[$DD_CLI_FINDINGS_FILTERS_ACTIVE]`

`--created value`
* 作成日による検出事項のフィルタです。サポートされる値: None, Today, Past 7 days, Past 30 days, Past 90 days, Current month, Current year, Past year `[$DD_CLI_FINDINGS_FILTERS_CREATED]`

`--cvssv3-score value`
* CVSS v3スコアによる検出事項のフィルタです。（デフォルト: 無視されます）`[$DD_CLI_FINDINGS_FILTERS_CVSSV3_SCORE]`

`--cwe value` 
* CWE IDによる検出事項のフィルタです。（デフォルト: 無視されます）`[$DD_CLI_FINDINGS_FILTERS_CWE]`

`--date value`
* 日付による検出事項のフィルタです。サポートされる値: None, Today, Past 7 days, Past 30 days, Past 90 days, Current month, Current year, Past year `[$DD_CLI_FINDINGS_FILTERS_DATE]`

`--discovered-after value`
* 指定した日付以降に発見された検出事項のフィルタです。フォーマット: YYYY-MM-DD `[$DD_CLI_FINDINGS_FILTERS_DISCOVERED_AFTER]`

`--discovered-before value`
* 指定した日付より前に発見された検出事項のフィルタです。フォーマット: YYYY-MM-DD `[$DD_CLI_FINDINGS_FILTERS_DISCOVERED_BEFORE]`

`--discovered-on value`
* 発見日による検出事項のフィルタです。フォーマット: YYYY-MM-DD `[$DD_CLI_FINDINGS_FILTERS_DISCOVERED_ON]`

`--duplicate true|false`
* 重複ステータスによる検出事項のフィルタです。`[$DD_CLI_FINDINGS_FILTERS_DUPLICATE]`

`--engagement-ids value [ --engagement-ids value ]`
* エンゲージメントIDによる検出事項のフィルタです。このフラグは複数回指定するか、カンマ区切りのリストとして使用できます。`[$DD_CLI_FINDINGS_FILTERS_ENGAGEMENT]`

`--epss-percentile value`
* EPSSパーセンタイルによる検出事項のフィルタです。（デフォルト: 無視されます）`[$DD_CLI_FINDINGS_FILTERS_EPSS_PERCENTILE]`

`--epss-score value`
* EPSSスコアによる検出事項のフィルタです。（デフォルト: 無視されます）`[$DD_CLI_FINDINGS_FILTERS_EPSS_SCORE]`

`--false-positive true|false`
* 誤検知ステータスによる検出事項のフィルタです。`[$DD_CLI_FINDINGS_FILTERS_FALSE_POSITIVE]`

`--is-mitigated true|false`
* 緩和ステータスによる検出事項のフィルタです。`[$DD_CLI_FINDINGS_FILTERS_IS_MITIGATED]`

`--mitigated value`
* 緩和済みとしてマークされた日付範囲による検出事項のフィルタです。サポートされる値: None, Today, Past 7 days, Past 30 days, Past 90 days, Current month, Current year, Past year `[$DD_CLI_FINDINGS_FILTERS_MITIGATED]`

`--mitigated-after value`
* 指定した日付以降に緩和された検出事項のフィルタです。フォーマット: YYYY-MM-DD `[$DD_CLI_FINDINGS_FILTERS_MITIGATED_AFTER]`

`--mitigated-before value`
* 指定した日付より前に緩和された検出事項のフィルタです。フォーマット: YYYY-MM-DD `[$DD_CLI_FINDINGS_FILTERS_MITIGATED_BEFORE]`

`--mitigated-by-ids value [ --mitigated-by-ids value ]`
* mitigated_byユーザーIDによる検出事項のフィルタです。このフラグは複数回指定するか、カンマ区切りのリストとして使用できます。--mitigated-by-namesと組み合わせることもできます。`[$DD_CLI_FINDINGS_FILTERS_MITIGATED_BY_IDS]`

`--mitigated-by-names value [ --mitigated-by-names value ]`
* mitigated_byユーザー名による検出事項のフィルタです。このフラグは複数回指定するか、カンマ区切りのリストとして使用できます。--mitigated-by-idsと組み合わせることもできます。`[$DD_CLI_FINDINGS_FILTERS_MITIGATED_BY_NAMES]`

`--mitigated-on value`
* 緩和日による検出事項のフィルタです。フォーマット: YYYY-MM-DD `[$DD_CLI_FINDINGS_FILTERS_MITIGATED_ON]`

`--not-tags value [ --not-tags value ]`
* 存在してはならないタグによる検出事項のフィルタです。このフラグは複数回指定するか、カンマ区切りのリストとして使用できます。`[$DD_CLI_FINDINGS_FILTERS_NOT_TAGS]`

`--out-of-scope true|false`
* 対象外または対象内ステータスによる検出事項のフィルタです。`[$DD_CLI_FINDINGS_FILTERS_OUT_OF_SCOPE]`

`--out-of-sla true|false`
* SLA内またはSLA外のステータスによる検出事項のフィルタです。`[$DD_CLI_FINDINGS_FILTERS_OUT_OF_SLA]`

`--product-name value`
* 製品名による検出事項のフィルタです。`[$DD_CLI_FINDINGS_FILTERS_PRODUCT_NAME]`

`--product-name-contains value`
* 製品名に指定した文字列を含むかどうかによる検出事項のフィルタです。`[$DD_CLI_FINDINGS_FILTERS_PRODUCT_NAME_CONTAINS]`

`--product-type-ids value [ --product-type-ids value ]`
* 製品タイプIDによる検出事項のフィルタです。このフラグは複数回指定するか、カンマ区切りのリストとして使用できます。--product-type-namesと組み合わせることもできます `[$DD_CLI_FINDINGS_FILTERS_PRODUCT_TYPE_IDS]`

`--product-type-names value [ --product-type-names value ]`
* 製品タイプ名による検出事項のフィルタです。このフラグは複数回指定するか、カンマ区切りのリストとして使用できます。--product-type-idsと組み合わせることもできます `[$DD_CLI_FINDINGS_FILTERS_PRODUCT_TYPE_NAMES]`

`--risk-accepted true|false`
* リスク受容済みステータスによる検出事項のフィルタです。`[$DD_CLI_FINDINGS_FILTERS_RISK_ACCEPTED]`

`--severity value [ --severity value ]`
* 深刻度による検出事項のフィルタです。有効な値は、Critical、High、Medium、Low、Infoです。このフラグは複数回指定するか、カンマ区切りのリストとして使用できます。`[$DD_CLI_FINDINGS_FILTERS_SEVERITY]`

`--tags value [ --tags value ]`
* 存在すべきタグによる検出事項のフィルタです。このフラグは複数回指定するか、カンマ区切りのリストとして使用できます。`[$DD_CLI_FINDINGS_FILTERS_TAGS]`

`--test-id value`
* テストIDによる検出事項のフィルタです。（デフォルト: 無視されます）`[$DD_CLI_FINDINGS_FILTERS_TEST_ID]`

`--title-contains value`
* タイトルに指定した文字列を含む検出事項のフィルタです。`[$DD_CLI_FINDINGS_FILTERS_TITLE_CONTAINS]`

`--under-review true|false`
* レビュー中ステータスによる検出事項のフィルタです。`[$DD_CLI_FINDINGS_FILTERS_UNDER_REVIEW]`

`--verified true|false`
* 検証済みステータスによる検出事項のフィルタです。（デフォルト: 無視されます）`[$DD_CLI_FINDINGS_FILTERS_VERIFIED]`

`--vulnerability-id value [ --vulnerability-id value ]`
* 脆弱性IDによる検出事項のフィルタです。このフラグは複数回指定するか、カンマ区切りのリストとして使用できます。`[$DD_CLI_FINDINGS_FILTERS_VULNERABILITY_ID]`

**検出事項の出力**

`--csv value`
* 検出事項のCSVファイルを書き込むファイルのパスです。`[$DD_CLI_FINDINGS_OUTPUT_CSV_PATH_FILE]`

`--json value`  検出事項のJSONファイルを書き込むファイルのパスです。`[$DD_CLI_FINDINGS_OUTPUT_JSON_PATH_FILE]`

**設定**

`--config value, -c value`
TOML設定ファイルへのパスで、オプションの値を設定するために使用されます。設定ファイルとCLIの両方でオプションが設定されている場合、CLIで設定された値が優先されます。`[$DD_CLI_CONFIG_FILE]`

`--defectdojo-url value, -u value`
検出事項のインポート先となるDefectDojoインスタンスのURLです（必須）。`[$DD_CLI_DEFECTDOJO_URL]`

`--insecure-tls, --no-tls`
指定されたDefectDojoインスタンスに接続する際のTLS検証エラーを無視します。ほとんどのユーザーはこのフラグを有効にすべきではありません。（デフォルト: false）`[$DD_CLI_INSECURE_TLS]`

#### エクスポートの例:

```
defectdojo-cli export \
--defectdojo-url "https://your-dojo-instance.cloud.defectdojo.com/"
```

### インタラクティブモード

インタラクティブモードでは、インポートおよび再インポートのプロセスをステップごとに設定できます。

#### 使用方法

```
defectdojo-cli interactive
	or: defectdojo-cli interactive  [--skip-intro] [--no-full-screen] [--log-path]
	or: defectdojo-cli interactive [-h | --help]
```

#### オプション

`--skip-intro `    
* イントロ画面をスキップします（デフォルト: false）

`--no-full-screen`
* フルスクリーンモードを無効にします（デフォルト: false）

`--log-path value`
* ログファイルへのパスです

`--help, -h`
* ヘルプを表示します

## Universal Importer

`universal-importer`は、スキャン結果をDefectDojoにシームレスに統合し、検出事項と関連オブジェクトのインポートおよび再インポートの両方のプロセスを効率化します。使いやすさを重視して設計されたこのツールは、さまざまなエンドポイントに対応しており、初回インポートとその後の再インポートの両方に対応します。これは、DefectDojo APIとの堅牢かつ柔軟なやり取りを必要とするユーザーに最適です。

DefectDojo-CLIと似ていますが、Universal Importerにはエクスポート機能がなく、環境変数のエンコード方法も異なります。

### コマンド

- [`import`](./#import-1)       検出事項をDefectDojoにインポートします。
- [`reimport`](./#reimport-1)     検出事項をDefectDojoに再インポートします。
- [`interactive`](./#interactive-1)   検出事項のインポートおよび再インポートのプロセスをステップごとに設定するインタラクティブモードを開始します

### グローバルオプション

`--help, -h`     
* ヘルプを表示します

`--version, -v`
* バージョンを表示します

#### CLIの書式設定

`--no-color`
* カラー出力を無効にします。（デフォルト: false）`[$DD_IMPORTER_NO_COLOR]`

`--no-emojis, --no-emoji`
* 出力内の絵文字を無効にします。（デフォルト: false）`[$DD_IMPORTER_NO_EMOJIS]`

`--verbose`
* 詳細な出力を有効にします。（デフォルト: false）`[$DD_IMPORTER_VERBOSE]`

### インポート

importコマンドを使用して、新しい検出事項をDefectDojoにインポートします。

#### 使用方法

```
universal-importer [global options] import <required flags> [optional flags]
	or: universal-importer [global options] import  --config ./config-file-path
	or: universal-importer import [-h | --help]
	or: universal-importer import example [subcommand options]
	or: universal-importer import example [-h | --help]

>> The API token must be set in the environment variable `DD_IMPORTER_DOJO_API_TOKEN`.
```

`import`は、2つの方法で検出事項をインポートできます。

**IDによる方法:**
* 製品を作成します（または既存の製品を使用します）
* 製品内にエンゲージメントを作成します
* engagementパラメータにエンゲージメントのidを指定します

このシナリオでは、エンゲージメント内に新しいテストが作成されます。

**名前による方法:**
* 製品を作成します（または既存の製品を使用します）
* 製品内にエンゲージメントを作成します
* product-nameを指定します
* engagement-nameを指定します
* 必要に応じてproduct-type-nameを指定します

このシナリオでは、DefectDojoは指定された詳細情報に基づいてエンゲージメントを検索します。

名前を使用する場合、`auto-create-context=true`を使用することで、インポーターにエンゲージメント、製品、製品タイプを自動的に作成させることができます。
`deduplication-on-engagement`を使用すると、インポートされた検出事項の重複排除を、新しく作成されたエンゲージメントに限定できます。


**importの基本構文:**

```
universal-importer import [options]
```

#### **importの例:**

```
universal-importer import \
--defectdojo-url "https://YOUR_INSTANCE.cloud.defectdojo.com/" \
--scan-type "burp scan" \
--report-path "./examples/burp_findings.xml" \
--product-name "dev" \
--engagement-name "dev" \
--product-type-name "Research and Development" \
--test-name "burp-test-dev" \
--verified \
--active \
--minimum-severity "info" \
--tag "dev" --tag "tools" --tag "burp" --tag "test-dev" \
--test-version "0.0.1" \
--auto-create-context
```

#### コマンド

`example, x`
* importオペレーションに必要なフラグとオプションのフラグの例を表示します

#### オプション

`--active, -a` 
* インポート時に検出事項をアクティブまたは非アクティブに強制するかどうかを指定します。Trueを指定すると検出事項は強制的にアクティブになり、Falseを指定するとすべての検出事項が強制的に非アクティブになります。値が設定されていない場合、アクティブステータスは受信したレポートファイルに依存します。`[$DD_IMPORTER_ACTIVE]`

`--api-scan-configuration value, --asc value`
* インポートまたは再インポート時に使用するAPI Scan Configurationオブジェクトのidです。（デフォルト: 0）`[$DD_IMPORTER_API_SCAN_CONFIGURATION]`

`--apply-tags-endpoints, --te`
* trueに設定すると、（--tagオプションからの）タグがエンドポイントに適用されます（デフォルト: false） 
`[$DD_IMPORTER_APPLY_TAGS_ENDPOINTS]`

`--apply-tags-findings, --tf`
* trueに設定すると、（--tagオプションからの）タグが検出事項に適用されます（デフォルト: false）`[$DD_IMPORTER_APPLY_TAGS_FINDINGS]`

`--auto-create-context, --acc`
* trueに設定すると、インポーターはエンゲージメント、製品、製品タイプを自動的に作成します（デフォルト: false）`[$DD_IMPORTER_AUTO_CREATE_CONTEXT]`

`--close-old-findings, --cof`
* Trueの場合、レポートに存在しなくなった古い検出事項は、インポート時に緩和済みとしてクローズされます。Serviceが設定されている場合、このServiceに関する検出事項のみがクローズされます。[$DD_IMPORTER_CLOSE_OLD_FINDINGS]

`--close-old-findings-product-scope, --cofps`
* --close-old-findingsを製品内の同じタイプの検出事項**すべて**に適用するかどうかを選択します。デフォルトではfalseに設定されており、エンゲージメント内の同じタイプの古い検出事項のみが対象となります（Close Old Findingsによってクローズされます）。[$DD_IMPORTER_CLOSE_OLD_FINDINGS_PRODUCT_SCOPE]

`--deduplication-on-engagement, --doe`
* trueに設定すると、インポーターはインポートされた検出事項の重複排除を、新しく作成されたエンゲージメントに限定します。（デフォルト: false）`[$DD_IMPORTER_DEDUPLICATION_ON_ENGAGEMENT]`

`--engagement-id value, --ei value`
* 検出事項のインポート先となるエンゲージメントのidです。（デフォルト: 0）`[$DD_IMPORTER_ENGAGEMENT_ID]`

`--engagement-name value, -e value`
* 検出事項のインポート先となるエンゲージメントの名前です。`[$DD_IMPORTER_ENGAGEMENT_NAME]`

`--minimum-severity value, --ms value`
* インポートすべき最低レベルの深刻度を指定します。有効な値は、Critical、High、Medium、Low、Infoです。（デフォルト: "Info"）`[$DD_IMPORTER_MINIMUM_SEVERITY]`

`--product-name value, -p value`
* 検出事項のインポート先となる製品の名前です。`[$DD_IMPORTER_PRODUCT_NAME]`

`--product-type-name value, --pt value`
* 検出事項のインポート先となる製品タイプの名前です。`[$DD_IMPORTER_PRODUCT_TYPE_NAME]`

`--report-path value, -r value`
* インポートするレポートへのパスです（必須）。`[$DD_IMPORTER_REPORT_PATH]`

`--scan-type value, -s value`
* ツールのスキャンタイプです（必須）。`[$DD_IMPORTER_SCAN_TYPE]`

`--tag value, -t value [ --tag value, -t value ]`
* テストオブジェクトに適用するタグです `[$DD_IMPORTER_TAGS]`

`--test-name value, --tn value`
* 検出事項のインポート先となるテストの名前です - デフォルトではスキャンタイプの名前が使用されます。`[$DD_IMPORTER_TEST_NAME]`

`--test-version value, -V value`
* テストのバージョンです。`[$DD_IMPORTER_TEST_VERSION]`

`--verified, -v`
* インポート時に検出事項を検証済みに設定するかどうかを指定します。Trueを指定すると検出事項は強制的に検証済みになります。値が設定されていない場合、検証済みステータスは受信したレポートファイルに依存します。`[$DD_IMPORTER_VERIFIED]`

**設定:**

`--config value, -c value`          
* TOML設定ファイルへのパスで、オプションの値を設定するために使用されます。設定ファイルとCLIの両方でオプションが設定されている場合、CLIで設定された値が優先されます。`[$DD_IMPORTER_CONFIG_FILE]`
`--defectdojo-url value, -u value`
* 検出事項のインポート先となるDefectDojoインスタンスのURLです（必須）。`[$DD_IMPORTER_DEFECTDOJO_URL]`
* --insecure-tls, --no-tls          指定されたDefectDojoインスタンスに接続する際のTLS検証エラーを無視します。ほとんどのユーザーはこのフラグを有効にすべきではありません。（デフォルト: false）`[$DD_IMPORTER_INSECURE_TLS]`

### 再インポート

`reimport`コマンドを使用すると、新しいレポートからの検出事項で既存のテストを拡張できます。方法は次の2通りです。

By ID:
- 製品を作成します（または既存の製品を使用します）
- 製品内にエンゲージメントを作成します
- スキャンレポートをインポートし、テストのidを確認します
- これをtest-idパラメータに指定します

By Names:
- 製品を作成します（または既存の製品を使用します）
- 製品内にエンゲージメントを作成します
- レポートをインポートすると、テストが作成されます
- product-nameを指定します
- engagement-nameを指定します
- 任意: test-nameを指定します

このシナリオでは、DefectDojoは指定された詳細情報に基づいてテストを検索します。test-nameが指定されていない場合、エンゲージメント内の最新のテストがscan-typeに基づいて選択されます。

名前を使用する場合、`auto-create-context=true`を使用することで、インポーターにエンゲージメント、製品、製品タイプを自動的に作成させることができます。
`deduplication-on-engagement`を使用すると、インポートされた検出事項の重複排除を、新しく作成されたエンゲージメントに限定できます。

#### 使用方法

```
universal-importer [global options] reimport <required flags> [optional flags]
   or: universal-importer [global options] reimport  --config ./config-file-path
   or: universal-importer reimport [-h | --help]
   or: universal-importer reimport example [subcommand options]
   or: universal-importer reimport example [-h | --help]

>> The API token must be set in the environment variable `DD_IMPORTER_DOJO_API_TOKEN`.
```

#### **reimportの例:**

```
universal-importer reimport \
--defectdojo-url "https://YOUR_INSTANCE.cloud.defectdojo.com/" \
--scan-type "Nancy Scan" \
--report-path "./examples/nancy_findings.json" \
--test-id 11 \
--verified \
--active \
--minimum-severity "info" \
--tag "dev" --tag "tools" --tag "nancy" --tag "test-dev" \
--test-version "1.0" \
--auto-create-context
```

#### コマンド

```
example, x  Shows an example of required and optional flags for reimport operation
```

#### オプション

`--active, -a`                                    
* インポート時に検出事項をアクティブまたは非アクティブに強制するかどうかを指定します。Trueを指定すると検出事項は強制的にアクティブになり、Falseを指定するとすべての検出事項が強制的に非アクティブになります。値が設定されていない場合、アクティブステータスは受信したレポートファイルに依存します。`[$DD_IMPORTER_ACTIVE]`

`--api-scan-configuration value, --asc value`
* インポートまたは再インポート時に使用するAPI Scan Configurationオブジェクトのidです。（デフォルト: 0）`[$DD_IMPORTER_API_SCAN_CONFIGURATION]`

`--apply-tags-endpoints, --te`                     
* trueに設定すると、（--tagオプションからの）タグがエンドポイントに適用されます（デフォルト: false）`[$DD_IMPORTER_APPLY_TAGS_ENDPOINTS]`

`--apply-tags-findings, --tf`                      
* trueに設定すると、（--tagオプションからの）タグが検出事項に適用されます（デフォルト: false）`[$DD_IMPORTER_APPLY_TAGS_FINDINGS]`

`--auto-create-context, --acc`                 
* trueに設定すると、インポーターはエンゲージメント、製品、製品タイプを自動的に作成します（デフォルト: false）`[$DD_IMPORTER_AUTO_CREATE_CONTEXT]`

`--close-old-findings, --cof`
* Trueの場合、レポートに存在しなくなった古い検出事項は、インポート時に緩和済みとしてクローズされます。Serviceが設定されている場合、このServiceに関する検出事項のみがクローズされます。[$DD_IMPORTER_CLOSE_OLD_FINDINGS]

`--close-old-findings-product-scope, --cofps`
* --close-old-findingsを製品内の同じタイプの検出事項**すべて**に適用するかどうかを選択します。デフォルトではfalseに設定されており、エンゲージメント内の同じタイプの古い検出事項のみが対象となります（Close Old Findingsによってクローズされます）。[$DD_IMPORTER_CLOSE_OLD_FINDINGS_PRODUCT_SCOPE]

`--deduplication-on-engagement, --doe`          
* trueに設定すると、インポーターはインポートされた検出事項の重複排除を、新しく作成されたエンゲージメントに限定します。（デフォルト: false）`[$DD_IMPORTER_DEDUPLICATION_ON_ENGAGEMENT]`

`--engagement-name value, -e value`               
* 検出事項のインポート先となるエンゲージメントの名前です。`[$DD_IMPORTER_ENGAGEMENT_NAME]`

`--minimum-severity value, --ms value`          
* インポートすべき最低レベルの深刻度を指定します。有効な値は、Critical、High、Medium、Low、Infoです。（デフォルト: "Info"）`[$DD_IMPORTER_MINIMUM_SEVERITY]`

`--product-name value, -p value`                   
* 検出事項のインポート先となる製品の名前です。`[$DD_IMPORTER_PRODUCT_NAME]`

`--product-type-name value, --pt value`         
* 検出事項のインポート先となる製品タイプの名前です。`[$DD_IMPORTER_PRODUCT_TYPE_NAME]`

`--report-path value, -r value`                    
* インポートするレポートへのパスです（必須）。`[$DD_IMPORTER_REPORT_PATH]`

`--scan-type value, -s value`                      
* ツールのスキャンタイプです（必須）。`[$DD_IMPORTER_SCAN_TYPE]`

`--tag value, -t value [ --tag value, -t value ]`  
* テストオブジェクトに適用するタグです `[$DD_IMPORTER_TAGS]`

`--test-id value, --ti value`                      
* 検出事項の再インポート先となるテストのidです。（デフォルト: 0）`[$DD_IMPORTER_TEST_ID]`

`--test-name value, --tn value`                    
* 検出事項のインポート先となるテストの名前です - デフォルトではスキャンタイプの名前が使用されます。`[$DD_IMPORTER_TEST_NAME]`

`--test-version value, -V value`                   
* テストのバージョンです。`[$DD_IMPORTER_TEST_VERSION]`

`--verified, -v`                                   
* インポート時に検出事項を検証済みに設定するかどうかを指定します。Trueを指定すると検出事項は強制的に検証済みになります。値が設定されていない場合、検証済みステータスは受信したレポートファイルに依存します。（デフォルト: 未設定）`[$DD_IMPORTER_VERIFIED]`

**設定:**

`--config value, -c value`
* TOML設定ファイルへのパスで、オプションの値を設定するために使用されます。設定ファイルとCLIの両方でオプションが設定されている場合、CLIで設定された値が優先されます。`[$DD_IMPORTER_CONFIG_FILE]`

`--defectdojo-url value, -u value`  
* 検出事項のインポート先となるDefectDojoインスタンスのURLです（必須）。`[$DD_IMPORTER_DEFECTDOJO_URL]`

`--insecure-tls, --no-tls`
* 指定されたDefectDojoインスタンスに接続する際のTLS検証エラーを無視します。ほとんどのユーザーはこのフラグを有効にすべきではありません。（デフォルト: false）`[$DD_IMPORTER_INSECURE_TLS]`

### インタラクティブモード
インタラクティブモードでは、インポートおよび再インポートのプロセスをステップごとに設定できます。

#### 使用方法

```
universal-importer interactive
	or: universal-importer interactive  [--skip-intro] [--no-full-screen] [--log-path]
	or: universal-importer interactive [-h | --help]
```

#### オプション

`--skip-intro `    
* イントロ画面をスキップします（デフォルト: false）

`--no-full-screen`
* フルスクリーンモードを無効にします（デフォルト: false）
`--log-path value`
* ログファイルへのパスです
`--help, -h`
* ヘルプを表示します


## トラブルシューティング

これらのツールで問題が発生した場合は、以下を確認してください。
- お使いのオペレーティングシステムおよびCPUアーキテクチャに適したバイナリを使用していることを確認してください。
- APIキーが環境変数に正しく設定されていることを確認してください。
- DefectDojoのURLが正しく、アクセス可能であることを確認してください。
- インポート時には、レポートファイルが存在し、指定したスキャンタイプでサポートされている形式になっていることを確認してください。DefectDojoでサポートされているスキャナーについては、[サポートされているツールの一覧](/supported_tools)をご覧ください。 
