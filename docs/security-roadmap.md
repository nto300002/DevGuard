# SafeCheck セキュリティ課題と実装ロードマップ

## 目的

SafeCheckを、AIエージェントによるアプリ開発で脆弱性を早期に発見し、人間の確認が必要な変更だけを安全に止める基盤として継続改善する。

本書では、現在の課題、他アプリへ引き継ぐべきセキュリティ観点、実装とmain統合の順序を定義する。

## 現状認識

現在は、Git差分・作業ツリーを対象に、AST解析、Security Flow、General Vulnerability、Secret形式検出、SARIF出力、baseline、Git hookを提供している。

一方、静的検査が中心であり、認証・認可、テナント境界、実際のネットワーク到達性、runtime設定の安全性までは完全に保証できない。検出結果は脆弱性の確定判定ではなく、確認が必要な候補として扱う。

## SafeCheck自身の残課題

### 最優先

- #33: generalモードの誤検知削減を完了する
  - 判定根拠・抑制理由をJSONと通常出力へ表示
  - `keikakun_back` Issue #105の代表例を再スキャン
  - 危険な未検証入力の検出を維持
- #34 / #36: フロントエンドとWebAuthn/authenticationの誤検知を削減する
- 個別ブランチの検証結果を確認し、mainへ統合する

### 各子Issueの未完了要件

- #20: import graph、Server/Client境界、Route Handler、設定切替
- #27: 高エントロピー検出、Git履歴検査、各種Secretのallowlist整理
- #26: npm / Python / PHP / Flutterの監査実行、lockfile解析、dependency baseline、CI連携
- #28: baseline更新差分、修正済みFindingの削除候補、allowlistとの優先順位
- #29: `.devguard.yml`設定、PRコメント投稿、承認情報の改ざん防止
- #30: `--suggest-fix` / `--apply-fix`、承認確認、diff、修正後再スキャン
- #31: API / E2E / DAST実行、タイムアウト・未導入報告、デプロイ条件連携
- #32: npm公開版とmainの一致確認、公開後の実環境コマンド検証

## 実装順序と統合方針

### 1. #33の残作業を完了

generalモードの代表的な誤検知を整理し、理由を出力できる状態にする。`keikakun_back`を再スキャンし、件数だけでなく、本番コードに残る未評価Highの内容を確認する。

### 2. #34・#36の誤検知対応

フロントエンドのbrowser/server実行環境、storage、sanitizer、production/test区分を整理する。続いてWebAuthn、CSPRNG、credential参照、認証処理の文脈を解析し、実装不備を見逃さない回帰テストを追加する。

### 3. 各子Issueの未完了要件を実装

各Issueで失敗テストを先に追加し、実装、全テスト、typecheck、build、対象アプリ検証を行う。重要な変更はHuman Gate対象とし、自動修正は承認なしで適用しない。

### 4. mainへ統合

各ブランチをレビュー可能な状態にしてからmainへ順番にマージする。マージ後は以下を確認する。

- main上の全テスト、typecheck、build
- `keikakun_back` / `keikakun_front`の再スキャン
- JSON / SARIF / 通常出力にSecret実値や不要な内部名称がないこと
- Git hookの生成内容
- npmパッケージの内容とmainの一致
- npm公開後の`npx --yes --package=agent-safecheck@<version> safecheck security-check`

## 他アプリへ引き継ぐセキュリティ課題

### 入力と実行経路

- ユーザー入力をSQL、HTML、コマンド、ファイルパス、HTTP接続先へ直接渡さない
- URL許可リスト、HTTPS、private network遮断を適用する
- `path.resolve`後に許可ディレクトリ境界を検証する
- UUIDなどの形式検証だけで安全とみなさず、認可とparameterized queryも確認する

### 認証・認可

- authentication成功だけでなく、resource ownerとtenant境界を毎回確認する
- IDOR、権限昇格、Server/Client境界の誤用をテストする
- WebAuthnのcredential、challenge、CSPRNG、replay防止、rollbackを検証する

### Secretと依存関係

- Secretをログ、URL、レスポンス、browser storage、リポジトリ履歴へ出さない
- 漏えい時はrevoke、rotate、remove、履歴確認まで行う
- lockfileを含めて依存関係を監査し、修正版・CVE/OSV・baselineを管理する
- npm等の公開パッケージは2FA、バージョン固定、公開前テスト、provenanceを利用する

### 運用とデプロイ

- staging以外のURLをDAST対象にしない
- API / E2E / DASTをstagingで実行し、失敗時はデプロイを止める
- Highリスク変更にはHuman Gateを要求する
- allowlistやbaselineで問題を隠し続けない
- CI、ログ、SARIF、PRコメントにSecret実値を含めない

## 完了の定義

「検出できる」だけでは完了としない。対象アプリで回帰テストが通り、誤検知と見逃しの根拠を確認でき、CI・hook・npm公開版・mainの挙動が一致した時点で完了とする。
