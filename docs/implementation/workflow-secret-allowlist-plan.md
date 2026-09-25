# GitHub Actions Secret誤検出削減 実装計画

## 受け入れ要件

- `jobs.*.steps[*].env` の値が、allowlistに登録された `${{ secrets.NAME }}` の完全一致である場合だけ、正当なCI参照として扱う。
- 次のworkflow項目・Secret組み合わせを許容できる。
  - `DATABASE_URL` ← `TEST_DATABASE_URL`
  - `TEST_DATABASE_URL` ← `TEST_DATABASE_URL`
  - `SECRET_KEY` ← `E2E_SECRET_KEY`
  - `CALENDAR_ENCRYPTION_KEY` ← `CALENDAR_ENCRYPTION_KEY`
- `DATABASE_URL` ← `TEST_DATABASE_URL` は、Alembicまたはpytestのstep用途で許容する。
- 固定JWT、Fernet鍵、秘密鍵、接続文字列は常に検出する。
- `PROD_DATABASE_URL`、`PROD_SECRET_KEY`、Stripe secretなど本番Secretは許容しない。
- allowlistにない`secrets.*`、`github.event.*`、`inputs.*`は許容しない。
- allowlistには`path`、`env_key`、`secret_name`、`reason`、`owner`、`expires_on`を必須とする。
- 期限切れ、metadata不足、workflow外のallowlistは設定エラーまたは未許容扱いにする。
- 許容結果は`CIテスト用途`、`過剰検出の疑い`のラベル付きでJSON・SARIF・通常表示に出力する。
- YAMLコメントやREADME内の文字列はworkflow Secret参照として扱わない。

## タスクリスト（TDD順）

- [ ] 1. allowlistの型・設定パーサー・期限検証を追加
- [ ] 2. YAML workflowからstep/env/Secret expressionを構造的に抽出
- [ ] 3. 許容可能な環境変数・Secretの組み合わせを判定
- [ ] 4. 固定値・本番Secret・外部入力を拒否するテストを追加
- [ ] 5. 検出結果へSecret名・環境変数名・ラベル・期限を追加
- [ ] 6. `security-check`、`check`、`push-check`へ判定を統合
- [ ] 7. keikakun_app / keikakun_back相当のworkflow fixtureで統合テスト
- [ ] 8. 全テスト・型検査・ビルド・実スキャンを実施
- [ ] 9. READMEと誤検出削減マニュアルを更新
- [ ] 10. npmの次版へ反映する準備を行う

各タスクは、先に失敗するテストを追加し、実装後に該当テストと全体テストを実行する。
