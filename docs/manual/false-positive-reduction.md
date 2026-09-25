# Secret検出の誤検出を減らす運用マニュアル

## 目的

Secret検出を無効化したり、検出ルールを弱めたりせず、GitHub Actionsの正当なSecret参照だけを構造的に許容する。固定された鍵や外部入力由来の値は、引き続き高リスクとして停止する。

対象は、主に次のようなworkflow上の参照である。

```yaml
jobs:
  test:
    steps:
      - name: Run tests
        env:
          TEST_DATABASE_URL: ${{ secrets.TEST_DATABASE_URL }}
        run: pytest
```

## 基本方針

### 1. 限定allowlistを使用する

allowlistはworkflow全体やリポジトリ全体を対象にせず、ファイル・job・step・環境変数・Secret名を完全一致で指定する。次の項目を必須とする。

| 項目 | 内容 |
| --- | --- |
| `path` | 対象workflowの相対パス |
| `job_id` | 対象jobのID |
| `step_name` | 対象stepの名前 |
| `env_key` | workflowの環境変数名 |
| `secret_name` | GitHub Actions Secret名 |
| `reason` | 許容する業務上の理由 |
| `owner` | 管理責任者またはチーム |
| `expires_on` | 許容期限（`YYYY-MM-DD`） |

設定例:

```yaml
securityCheck:
  workflowSecretAllowlist:
    - path: .github/workflows/cd-backend.yml
      job_id: deploy-backend
      step_name: Run Pytest
      env_key: TEST_DATABASE_URL
      secret_name: TEST_DATABASE_URL
      reason: テストDBのmigrationとpytestに使用
      owner: backend-team
      expires_on: 2026-12-31
```

期限を過ぎた項目は自動的に許容せず、高リスク検出へ戻す。期限の延長は、利用目的と接続先を再確認してから行う。

### 2. GitHub Expressionsだけを許容する

許容対象は、YAMLの値が次の形式に一致する場合だけとする。

```text
${{ secrets.TEST_DATABASE_URL }}
```

次の値は許容しない。

- 固定リテラルのSecret、JWT、Fernet鍵、秘密鍵
- `postgres://` などの接続文字列
- `${{ github.event.* }}` や `${{ inputs.* }}` など外部入力由来の値
- `PROD_SECRET_KEY` などallowlistに明示されていないSecret
- 任意の `secrets.*` をまとめて許容する指定

### 3. Secret名を明示的に制限する

現時点でテスト用途として検討できるSecretは、運用確認済みのものに限る。

- `TEST_DATABASE_URL`
- `E2E_SECRET_KEY`
- `CALENDAR_ENCRYPTION_KEY`

`PROD_SECRET_KEY`、Stripeの本番Secret、AWS Secretなどは自動許容しない。テストworkflowで参照されていても、用途・権限・ローテーション方針を確認する。

## YAML解析の要件

単純な文字列検索ではなく、YAMLとしてworkflowを解析する。判定対象は次の構造に限定する。

```text
jobs.<job_id>.steps[*].name = <step_name>
jobs.<job_id>.steps[*].env.<env_key> = ${{ secrets.<secret_name> }}
```

この構造解析により、次を区別する。

- `env`キーと値の正しい組み合わせ
- job IDとstep名の正しい組み合わせ
- `run`コマンド中のSecret参照
- コメントやREADME内の説明文
- 同一行に複数存在するSecret参照

コメントやドキュメント中の文字列は、workflowの実行設定として扱わない。ただし、固定鍵形式や実値形式はファイル用途にかかわらず検出対象とする。

## 検出結果の表示

正当なテスト用途と判断できる場合でも、検出を完全に消去せず、次のラベルを付けて結果に残す。

- `CIテスト用途`
- `過剰検出の疑い`

ラベル付きの検出には、Secret名、workflowパス、環境変数名、許容期限を表示できるようにする。高リスクの未許容Secretと区別できることが重要である。

## 必須テスト

SafeCheck側に、少なくとも次のテストを追加する。

1. 正当な `TEST_DATABASE_URL` のGitHub Expressionが、path・job ID・step名・envキー・Secret名の完全一致で許容され、ラベル付きで出力される
2. 同一行にある `TEST_DATABASE_URL` と `PROD_SECRET_KEY` が個別に検出される
3. 固定JWTが検出される
4. 固定Fernet鍵・秘密鍵形式が検出される
5. `${{ github.event.* }}` がSecret参照として許容されない
6. コメント内のSecret名だけではworkflowSecret検出を発生させない
7. 期限切れallowlistは許容せず、高リスクへ戻る
8. allowlistにないSecret名は許容しない
9. JSON・SARIF・通常表示でラベルとSecret名を一貫して出力する

## リポジトリ側の確認手順

1. 固定の`SECRET_KEY`、JWT、Fernet鍵、Stripe形式値をworkflowから除去する
2. 必要な値をGitHub Actions Secretへ移行する
3. workflowのSecret参照が実在するSecret名と一致することを確認する
4. 必要な参照だけを期限付きallowlistへ登録する
5. `security-check --json` と `security-check --mode general` を実行する
6. 高リスクの未許容検出が残っていないことを確認する
7. allowlistの期限、所有者、Issue番号をレビューする

## 禁止事項

次の方法で検出を回避してはいけない。

- `--write-baseline` で全検出を基準化する
- `.github/workflows/` 全体を除外する
- `securityCheck.enabled: false` にする
- hookを`--no-verify`で回避する
- `secrets.*` をワイルドカードで許容する
- 固定ダミー鍵を残したまま検出ルールだけを変更する

## 完了条件

- 正当なCI Secret参照だけが、期限付き・理由付きでラベル表示される
- 固定鍵、実値形式、外部入力由来値は引き続き停止される
- workflow全体の除外やSecret検出無効化を行っていない
- allowlistの期限切れが自動的に高リスクへ戻る
- keikakun_appとkeikakun_backで同じ判定基準を再現できる
