# 警報が出たときの対応手順

原則: **①止める → ②証拠を残す → ③原因を消す → ④鍵を替える → ⑤報告する**。
慌ててファイルを消すと原因が分からなくなるので、③の前に必ず②を行う。

---

## scripts — 決済・カートのスクリプトが変化した 🚨

### まず5分で判断
1. 直近に自分でプラグイン・テーマ・WordPressを更新したか？
   - **した** → 通知の「変更」に出ているURLが、更新したプラグインのものか確認 → 一致すれば
     GitHub Actions で `mode=accept` を実行（またはローカルで `python -m site_guard accept`）。終了。
   - **していない／知らないドメインが「追加」されている** → 下の「侵害対応」へ。**迷ったら侵害扱い**。

### 侵害対応（Webスキミングの疑い）
**① 止める（カード入力を止める。最優先）**
- WooCommerce → 設定 → 決済 → Stripe を **無効化**（または一時的にメンテナンスモード）。
  管理画面に入れない場合はサーバーで:
  `wp plugin deactivate woocommerce-gateway-stripe`

**② 証拠を残す（消す前に）**
```bash
TS=$(date +%F-%H%M)
sudo tar czf ~/evidence-$TS.tgz /var/www/<サイト>          # サイト一式
wp db export ~/evidence-$TS.sql                             # DB
sudo cp /var/log/nginx/access.log* ~/                        # アクセスログ
```
ダウンロードしてVPSの外に保存する。

**③ 原因を探して消す**
```bash
wp core verify-checksums                 # WordPress本体の改ざん
wp plugin verify-checksums --all         # 公式プラグインの改ざん
wp user list --role=administrator        # 知らない管理者がいないか
find /var/www/<サイト> -name "*.php" -mtime -7 -newer wp-config.php   # 最近増えたPHP
find /var/www/<サイト>/wp-content/uploads -name "*.php"              # uploads内のPHPはほぼ不正
```
- 改ざんされたファイルは公式版で上書き（`wp core download --force --skip-content`、
  プラグインは削除→再インストール）。
- 知らない管理者は削除。脆弱なプラグインは更新か削除。

**④ 鍵とパスワードをすべて替える**
- Stripe ダッシュボード → 開発者 → APIキー → **シークレットキーをロール（再発行）**、Webhook署名シークレットも
- WordPress管理者全員のパスワード、`wp config shuffle-salts`（全員ログアウトされる）
- DBパスワード、SSH鍵、VPS事業者・ドメイン管理会社のパスワード

**⑤ 報告する**
- **Stripe サポート**に連絡（不正利用の監視・カード会社への連携）
- カード情報・個人情報が漏れた「おそれ」がある時点で、**個人情報保護委員会への漏えい等報告**が必要
  （不正アクセスによる場合は件数に関係なく対象。速報は概ね3〜5日以内、確報は原則60日以内。
  最新の要件は個人情報保護委員会のWebサイトで必ず確認してください）
- 被害が疑われる顧客への通知、必要に応じ警察（サイバー犯罪相談窓口）・IPAに相談
- 自力で原因が特定できない場合は、フォレンジック会社に依頼（証拠②がここで効く）

**⑥ 再開**
- 原因を消し、②〜④が終わってから Stripe を再有効化 → `accept` で新しい基準を承認。

---

## dns — DNSレコードが変わった 🚨
1. 自分で変更していなければ、**ドメイン管理会社（レジストラ）にすぐログイン**し、ネームサーバー・Aレコードを正しい値に戻す。
2. レジストラのパスワード変更、二要素認証を有効化、「ドメインロック（移管ロック）」を有効化。
3. ログインできない場合はレジストラのサポートに乗っ取りとして連絡。
4. その間に偽サイトで入力された可能性があるので、上の「⑤報告する」を検討。

## tls — SSL証明書の期限・エラー
```bash
sudo certbot certificates          # 期限の確認
sudo certbot renew --dry-run       # 自動更新が動くか
sudo systemctl list-timers | grep certbot
```
失敗する場合は、DNSのAレコードがVPSを向いているか、80番ポートが開いているかを確認。

## mail — SPF / DMARC
緊急ではないが、偽メールで顧客が騙される前に直す。
1. 実際にメールを送っているサービスを洗い出す（Google Workspace、WooCommerceの送信元、Mailchimp 等）。
2. SPF: それらを `include:` した TXT を **1つだけ**置く。末尾は `-all`。
3. DMARC: `_dmarc.<ドメイン>` に `v=DMARC1; p=none; rua=mailto:<アドレス>` → 2〜4週間レポートを見て正規の送信が全部通っていれば `p=quarantine` → `p=reject`。

## wordpress / headers — 露出・設定不足
緊急ではないので、週次まとめで1件ずつ潰す。各通知の「対処」に具体的な設定を記載。
- ユーザー名の露出・xmlrpc・readme・バージョン表示 → functions.php または nginx 設定
- セキュリティヘッダー → nginx の `add_header`（CSPは決済が壊れないよう `Content-Security-Policy-Report-Only` から始める）

## 監視自体が失敗した ⚠️
GitHub Actions のリンクを開いてログを確認。サイトがダウンしている・ブロックされている場合は、サイト側の問題として扱う。

---

## 平時にやっておくと、いざという時に楽になること
- VPSの外へ**毎日バックアップ**（ファイル＋DB）。復旧の速さはこれで決まる。
- Stripe・レジストラ・VPS・WordPress管理者に**二要素認証**。
- この手順書をスマホから開けるようにしておく（GitHubアプリでこのリポジトリを開ける）。
