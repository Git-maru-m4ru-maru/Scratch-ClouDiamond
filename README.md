# cloudiamond-scratch

**Encrypted Scratch ⇄ Python communication that stays secure even though every Scratch project's code is public.**
Key exchange X25519, encryption ChaCha20-Poly1305. The Scratch client is generated as an `.sb3`; the package also
ships tools to build, audit and verify that file, an optional asyncio transport, a command router and password helpers.

Scratch ⇄ Python サーバー間の通信を、**コードが全員に見える**前提で守るためのパッケージです。
> `cloudiamond-scratch` は PyPI 上の別プロジェクト `cloudiamond` とは無関係です(import 名は衝突しないよう `cloudiamond_scratch` にしています)。

**バージョン 1.0.0**(プロトコルは 0.1 と互換。変更点は [CHANGELOG.md](CHANGELOG.md))。
Scratch 側の暗号ブロックは 0.1 のコンパイル済みブロックそのままです。**新しく足した Scratch ブロック(HELLO 再送・`🔒 request`・かな対応の文字表)は、実際の `scratch-vm` / エディタでは未確認です**(→ [検証したこと](#検証したこと) / [公開前の確認](#公開前の確認))。

## 発想

Scratch のコードは誰でも読めるので、「アルゴリズムや鍵を隠す」設計は成立しません。そこで **秘密をコードに一切置かない** ようにしています。

- サーバーの**公開鍵**だけをプロジェクトに埋め込む(公開情報)。
- クライアントは接続のたびに**使い捨ての秘密鍵**を作る。その鍵は誰にも送られない。
- プロジェクトのコード・公開鍵・通信の全記録を知っていても、鍵は計算できない(X25519 の離散対数問題)。

暗号は標準のもの(X25519 / ChaCha20-Poly1305 RFC 8439 / HChaCha20)だけで、独自の暗号は作っていません。Scratch にはビット演算も 64bit 整数も無いので、`+ - * floor mod` とリストだけで書き直してあります。

## 1.0.0 の新機能

| 分類 | 内容 |
| --- | --- |
| 安全性 | レート制限(HELLO 全体・メッセージ/セッション)、セッション上限と期限切れ(本物のユーザーを守る追い出し順)、認証に成功したフレームだけがカウンタを進める、セッション ID 衝突で乗っ取れない、サーバー再起動後の HDR 衝突回避、`keygen` は 0600・上書きしない、**`audit`(保存した .sb3 に鍵や通信内容が残っていないか検査)**、**`verify`(改造されていないクライアントか検査)** |
| 信頼性 | **HELLO の自動再送**(6 秒ごと・最大 3 回。サーバーはキャッシュ済みの同じ返信を返す) |
| 機能 | `🔒 request`(送信+返信待ちを 1 ブロックに)、**ひらがな・カタカナ・句読点が送受信可能**、コマンドルーター、`Session`(`user` / `data`)、`on_connect` / `on_close`、パスワードのハッシュ化とログイン試行制限 |
| 使いやすさ | 接続層を同梱(標準ライブラリのみの asyncio WebSocket。**実サーバー未検証・experimental**)、ローカル開発用クラウドサーバー、CLI の整理(`keygen` `pubkey` `build` `inspect` `audit` `verify` `selftest` `serve` `devcloud`) |
| 汎用性 | `--no-demo`(デモ無しのライブラリ用 .sb3)、`.sb3` 内コメントにバージョン・公開鍵・フィンガープリント、鍵は環境変数 `CLOUDIAMOND_SERVER_KEY` でも渡せる、Python 同士の通信用 `ReferenceClient` |

## インストールと最短手順

```
pip install cloudiamond-scratch
cloudiamond-scratch selftest                       # 自己診断(数秒)
cloudiamond-scratch keygen server.key              # サーバーの長期鍵。秘密鍵は公開しない
cloudiamond-scratch build --key server.key -o client.sb3
cloudiamond-scratch inspect client.sb3             # 公開鍵とフィンガープリントを確認
```

`client.sb3` を Scratch / TurboWarp で開くと、`🔒 connect` / `🔒 send text` / `🔒 wait for message` / `🔒 request` などのブロックが入っています(緑の旗でデモが動きます)。埋め込まれるのは**公開鍵だけ**です(`--pub <64桁の16進>` でも生成できます)。名前は `--name`、デモ無しは `--no-demo`。

**Scratch なしで仕組みを試す:** `python examples/in_process_demo.py`(ソースツリーで実行)。

### ローカルで通しで動かす(接続層は experimental)

```
cloudiamond-scratch devcloud                                                      # 端末1: 開発用クラウド変数サーバー (ws://127.0.0.1:9080)
cloudiamond-scratch serve --key server.key --url ws://127.0.0.1:9080 --project-id 1   # 端末2: echo デモのサーバー
```

Scratch / TurboWarp のプロジェクトをこのクラウド変数サーバーにつなぐ必要があります。TurboWarp には別のクラウド変数サーバーを指定する仕組み(`cloud_host`)があるはずですが、**私は動作を確認していません**。ブラウザが `ws://` 接続をブロックする場合もあります。うまくいかないときは、[接続のしかた](#接続のしかた)の「自分で配線する」方法を使ってください。

## Scratch 側の使い方

| ブロック | 働き |
| --- | --- |
| `🔒 connect` | 乱数を集め(約 3 秒。**マウスを動かすほど安全側**)、鍵交換してサーバーを検証する。HELLO は 6 秒ごとに最大 3 回再送。`🔒 connected` が 1 なら成功 |
| `🔒 send text [text]` | 暗号化して送る(未接続なら何もしない) |
| `🔒 wait for message (max [sec] sec)` | 返信を待つ。来たら `🔒 got message` = 1、本文は `🔒 received text` |
| `🔒 request [text] (max [sec] sec)` | 上の 2 つを続けて実行 |
| `🔒 wipe secrets` / `🔒 disconnect` | 鍵・メッセージをすべて消す(**保存・共有の前に必ず**) |

```
when green flag clicked
🔒 connect
if <🔒 connected = 1> then
    🔒 request [score 120] (max 10 sec)
    say (🔒 received text)
🔒 disconnect
```

**送れる文字:** ASCII の**小文字**・数字・記号と、**ひらがな・カタカナ・`ー、。「」・！？`**。大文字は小文字に変換されます(Scratch の `=` が大文字小文字を区別しないため)。表にない文字(漢字・絵文字・全角英数など)は `?` になります。1 メッセージは最大 **286 byte**(1 文字 = 1 byte)。サーバー側で同じ表を使うには `cloudiamond_scratch.text` の `encode` / `decode`(Router は自動)。

## サーバー側の使い方

最小(0.1 と同じ書き方がそのまま使えます):

```python
from cloudiamond_scratch import CloudBridge, SecureServer, load_or_create_static_key

server = SecureServer(load_or_create_static_key("server.key"),
                      on_message=lambda sid, data: b"echo:" + data)   # None を返せば無返信
bridge = CloudBridge(server, write=my_cloud_write, min_interval=0.25)  # write(name, value): クラウド変数を書く関数
bridge.on_variable(name, value)        # クラウド変数が更新されるたびに(名前と値を)渡す
bridge.push(sid, b"server-initiated message")
```

コマンドとログイン(詳しい例は `examples/router_server.py`):

```python
from cloudiamond_scratch import Router, SecureServer
from cloudiamond_scratch.auth import hash_password, verify_password, LoginThrottle

router = Router()

@router.command("login", min_args=2, max_args=2)
def login(ctx):
    name, password = ctx.args
    ...                                   # verify_password(password, stored_hash) / LoginThrottle
    ctx.session.user = name
    return "ok " + name

@router.command("score", login=True, min_args=1, max_args=1)   # login=True: 未ログインなら "error login"
def score(ctx):
    return f"saved {int(ctx.args[0])} for {ctx.user}"

server = SecureServer(key, handler=router, on_connect=lambda s: ..., on_close=lambda s, why: ...)
```

- 未知のコマンドには `error unknown`、ハンドラが例外を出したときは `error` を返します(内部の詳細は返しません)。
- `SecureServer` の主な調整項目: `max_sessions`(1000)、`session_ttl`(3600 秒)、`handshake_ttl`(120 秒)、`message_rate`(5/秒)と `message_burst`(10)、`hello_rate`(5/秒)と `hello_burst`(20)、`frame_rate`(200/秒)。`server.stats` で捨てたフレームの理由(`drop.replay` `drop.auth` …)を数えられます。
- Scratch のクラウド変数の書き込みは 1 秒あたり約 10 回までと言われており(私は未確認)、1 メッセージは最小 2 回の書き込みです。既定のレート制限(5 メッセージ/秒)はその範囲に収まる値にしてあります。
- Python は秘密をメモリから確実に消せません。サーバーのプロセスと OS の保護に頼ってください。

### 接続のしかた

1. **同梱の接続層**(experimental): `cloudiamond-scratch serve ...` か `CloudRunner(server, url, project_id).run()`。TurboWarp 系のクラウド変数 WebSocket(改行区切り JSON、`handshake` → `set`)を話します。**同梱の開発用サーバーでしかテストしていません。** 公式の Scratch サーバーはログインが必要なので、この接続層では動きません。
2. **自分で配線する**: 好きなライブラリ(例えば `scratchattach` など)でクラウド変数の更新を受け取り、`bridge.on_variable(name, value)` に渡し、`write` でクラウド変数に書き込みます。守ること: 変数名は `☁ ` 付きでも無しでも可、**slot を全部書いてから HDR を書く**(`CloudBridge` がそうします)、接続直後にサーバーが再送してくる現在値は `on_variable(..., initial=True)` で渡す。
3. 非同期で自前の制御をしたいとき: I/O を含まない `BridgeCore`(`feed(name, value) -> 書き込むべきフレーム`)を使えます。

## CLI

| コマンド | 内容 |
| --- | --- |
| `keygen [PATH]` | サーバーの秘密鍵ファイルを作る(0600。既存ファイルは `--force` なしでは上書きしない) |
| `pubkey [--key FILE \| --env]` | 公開鍵(16 進)を表示 |
| `build (--key FILE \| --pub HEX) [-o OUT] [--name N] [--no-demo]` | クライアント `.sb3` を作る(同じ入力から同じ内容) |
| `inspect FILE` | 埋め込まれた公開鍵・フィンガープリント・構造チェック |
| `audit FILE` | 保存済み `.sb3` に鍵・通信内容が残っていないか(**公開前に**。問題があれば終了コード 1) |
| `verify FILE [--pub HEX \| --key FILE]` | 改造されていない v1.0.0 のクライアントか。`--pub` を渡すと鍵の一致も確認 |
| `selftest [-v]` | 標準ベクトル・プロトコル・`.sb3` を一通り自己診断 |
| `serve --url URL --project-id ID [--key FILE \| --env] [--handler pkg.mod:obj]` | 接続層につないでサーバーを動かす(省略時は echo デモ) |
| `devcloud [--port N]` | ローカル開発用のクラウド変数サーバー |

## プロトコル

詳細な仕様とテストベクトルは [docs/PROTOCOL.md](docs/PROTOCOL.md) にあります(第三者実装・レビュー用)。

```
        Scratch (client)                              Python (server)
e ← 使い捨て乱数(32 byte)                      s = 長期秘密鍵(サーバーだけが持つ)
E = e·G                                          S = s·G  ← .sb3 に埋め込む(公開情報)

sid | 01 | E ───────────────────────────────▶    r ← 使い捨て乱数, R = r·G
                                                 dh_es = X25519(s, E)   dh_ee = X25519(r, E)
                                                 r を破棄
◀──────────────  sid | 02 | R | AEAD("READY")    (AAD = sid‖02‖E‖R)
dh_es = X25519(e, S)   dh_ee = X25519(e, R)
AEAD を検証できたら = 相手は s を持つサーバー

鍵: master = HChaCha20(dh_ee, HChaCha20(dh_es,"master")[:16]);  k_c2s / k_s2c = HChaCha20(master, ラベル)
以降: sid | 03(c2s)/04(s2c) | ctr(6 byte) | ChaCha20-Poly1305( 長さ‖データ‖0 を 32 byte 単位にパディング )
```

(ラベル中の `SCRSEC1` はプロトコルのバージョン識別子で、旧称の名残です。変更すると互換性が切れるのでそのままにしています。)

| 性質 | どう実現しているか |
| --- | --- |
| 盗聴されても読めない | X25519 + ChaCha20-Poly1305。通信に平文も鍵も乗らない |
| サーバーのなりすまし防止 | `dh_es` は `s` を持つ者しか計算できない。偽サーバーの返信は AEAD 検証で落ちる |
| 改ざん検出 | Poly1305 タグ。1 bit でも変わればサーバーは黙って捨てる |
| 再送(リプレイ)防止 | 方向別の単調増加カウンタ(認証に成功したフレームだけが進める) |
| 前方秘匿性 | 一時鍵 `r` を使用後に破棄。後で `s` が漏れても過去の通信は読めない |
| 長さの秘匿 | 平文を 32 byte 単位にパディング |
| 認証前に送らない | 接続に失敗したら、そのために作った鍵・乱数をすべて消す。未接続のときは送信ブロックが何もしない |

## 防げないもの(正直に)

- **クライアントの本人確認。** コードが公開なので、誰でも正規クライアントと同じものを作れます。ユーザー認証が必要なら、パスワード等を**暗号化されたメッセージの中で**送り、サーバー側で検証してください(`Router` + `auth`。送れる文字の範囲が狭いので、パスワードは長くしてください)。
- **妨害(DoS)。** クラウド変数は誰でも書けます。壊れた通信は捨てられる(安全側)だけで、届かなくすることは防げません。レート制限は CPU とメモリを守るためのものです。
- **メタデータ。** 通信の有無・回数・タイミング、32 byte 刻みの長さ、セッション ID は見えます。
- **クライアント端末の乗っ取り**(本人の端末内のメモリは守れません)。
- **弱い乱数。** Scratch の `pick random` は暗号用ではありません(下記)。
- **同時利用。** クラウド変数は全員で共有です。同時に複数人が書くとフレームが混ざり、暗号が「捨てる」ので安全は保たれますが、メッセージが届かないことがあります(再送は HELLO だけです)。

## 乱数

接続時に約 3 秒かけて、`pick random`・`timer` の細かい桁・マウス座標・`days since 2000` の小数下位桁を HChaCha20 で混ぜ込んで使い捨て秘密鍵を作ります。**マウスを動かしてもらう**ほど安全側です(動かさなくても動作はしますが、その場合の強さはブラウザの `Math.random` に依存します)。サーバーが送る乱数を混ぜても、通信が見える相手には何の秘密も足せないので行っていません。

## 保存・共有のときの注意

Scratch は変数・リストの**現在値をプロジェクトに保存**します。接続した後のプロジェクトをそのまま保存・共有すると、**通信用の鍵が入ったまま**になります。保存・公開の前に必ず `🔒 wipe secrets`(または `🔒 disconnect`)ブロックを実行してください。**サーバーの秘密鍵(`server.key`)は絶対に Scratch に入れない・コミットしない**でください。

```
cloudiamond-scratch audit my_project.sb3      # 鍵・通信内容が残っていないか(CRITICAL があれば公開しない)
cloudiamond-scratch verify downloaded.sb3 --pub <配布元が示した公開鍵>   # 受け取った側: 改造されていないか
```

配布する側は、`.sb3` に **sha256・公開鍵・フィンガープリント・バージョン**を添えてください(`build` が表示します)。`build` は同じ公開鍵・バージョン・`--name`・`--no-demo` から同じ**内容**(`project.json` とアセット)を作ります。zip の圧縮結果は zlib の実装によって変わりうるので、突き合わせには `verify` を使ってください(`verify` は内容で比べます)。

プロジェクトのパレットには、内部で使う変数・リストが多数並びます(関数ごとのローカル変数を含む)。邪魔でも消さないでください。

## クラウド変数の約束

- プロジェクトのクラウド変数は 10 個ちょうど: `☁ C2S_HDR` `☁ C2S_0..3`(クライアント→サーバー)、`☁ S2C_HDR` `☁ S2C_0..3`(サーバー→クライアント)。
- 1 slot = 84 byte(数字だけの文字列。1 byte = 3 桁 + 先頭に `1`、253 桁)。1 フレーム最大 336 byte、**メッセージ本文は最大 286 byte**。
- **slot を全部書いた後で HDR を書く。HDR の値が変わったことが「slot が揃った」合図。** HDR は書くたびに必ず変わる。サーバー側の seq は**サーバー全体で単調増加**にし、起動時の値はランダムにして、クラウドに残っている値と同じ HDR を書かない(`CloudBridge` / `BridgeCore` がそうしています)。
- 書き込み頻度の制限や、公式の Scratch サーバーでの動作は、**実機では確認していません**。

## 検証したこと

テストは `tests/` にあります(`pip install "cloudiamond-scratch[test]"` のうえ、ソースツリーで `pytest`。標準の `unittest` でも動きます)。**228 件**:

- **暗号部品:** RFC 7748 / RFC 8439 / draft-irtf-cfrg-xchacha の公式ベクトル。Python 実装に加え、**Scratch クライアントのブロック自身**にも同じベクトルと `cryptography` との照合をかけています(`test_client_primitives.py`)。
- **固定ベクトル:** 固定の鍵から作った HELLO / REPLY / データフレームを、Python 実装と Scratch ブロックの**両方**が同一に再現(`test_vectors.py`、値は `docs/PROTOCOL.md`)。
- **実クライアントとサーバーの相互運用:** コンパイル済みの Scratch ブロックを、ブロックインタプリタ(`tests/scratch_vm.py`)で実行し、サーバーとつないで、接続 → サーバー認証 → 暗号化メッセージの往復(日本語・最大長・サーバー起点の push・遅延・複数クライアント)を確認。
- **障害:** HELLO のロスト、返信のロスト、サーバー不在(30 秒以内に失敗して鍵を消す)。
- **攻撃シナリオ:** 偽サーバー、返信のビット改ざん(返信の全 73 byte を 1 つずつ反転)、古い返信の差し替え、クライアントフレームの再送、サーバーフレームの再送、反射、ゴミ入力、盗聴者に平文が見えないこと、セッション ID 衝突、HELLO フラッド、位数の小さい点。
- **保存プロジェクト:** 接続後に保存した状態を `audit` が検出し、`wipe secrets` 後は通ること。
- **テストの実効性:** セキュリティ上重要な実装を 1 か所ずつ壊す変異テストを 21 パターン行い、すべてテストが落ちることを確認(`python tools/mutation_check.py` で再現できます。最初は 1 件すり抜けたので、対応するテストを足しました)。
- **接続層:** 実際のローカル WebSocket 上で、開発用サーバー・ランナー・再接続・スナップショット非再処理・他プロジェクトとの分離。
- **ビルドの再現性:** 同梱の Scratch テンプレートが、0.1 の `.sb3`(`tools/upstream/`)から `tools/make_template.py` で完全に再生成できること。0.1 の暗号ブロックのうち変わったのは `🔒 connect` のブロックだけであること(`test_release_consistency.py`)。

> **重要な限界:** 上の「ブロックの実行」は、このリポジトリが持つ**独立した Python 製のインタプリタ**で行っています(`+ − × floor mod`、文字列の大文字小文字を区別しない比較、1 始まりのリスト、などの Scratch の仕様を再現し、未対応のブロックは実行せずエラーにします)。本物の `scratch-vm` ではありません。0.1 で行っていた実 `scratch-vm` を使う検証は、1.0.0 の `.sb3` に対しては**まだ行っていません**。

## 未検証・限界

- **実際の `scratch-vm` / Scratch・TurboWarp のエディタ上での、1.0.0 で追加・変更したブロック**(HELLO 再送、`🔒 request`、かな対応の文字表、ワークスペースのコメント)の動作と読み込み。構造の検査(`lint`)は通っています。
- 実際の Scratch 公式 / TurboWarp のクラウド変数サーバー越しの動作(同梱の接続層は開発用サーバーでしか試していません)。
- 実ブラウザでの速度(0.1 の実測: X25519 1 回 約 0.5 秒、接続 → 2 往復 約 6〜10 秒。実ブラウザ・スマートフォン・古い PC は未計測)。
- Python 3.11 / 3.13 と Windows・macOS での実行(開発は Python 3.12 / Linux。CI の設定は同梱していますが、まだ動かしていません)。
- **第三者による暗号レビューは受けていません。** 部品はすべて標準のものですが、唯一の「組み立て」は 2 段の鍵導出(`HChaCha20` を PRF として連鎖。NaCl の `crypto_box` が HSalsa20 でやっているのと同じ発想で、`dh_es` / `dh_ee` の一方が秘密なら `master` は予測できません)です。単純な XOR 結合は `R := S` で鍵が崩壊するため採りませんでした。標準の HKDF-SHA256 が理想ですが、Scratch への SHA-256 の移植コストが大きいため見送っています。重要な情報を扱う前に、レビューを受けてください。

## 公開前の確認

1. `pip install -e ".[test]"` → `pytest`(すべて通ること)。
2. **本物の Scratch VM / エディタでの確認**(1.0.0 で未実施):
   - `releases/ClouDiamond_v1.0.0_DEMO.sb3` を TurboWarp / Scratch で開く(読み込みエラーが出ないこと。`🔒 request` ブロックと、スプライトのコメントが見えること)。
   - 0.1 で使っていた `scratch-vm` による通しテストを、この `.sb3` に対して実行する(接続 → 往復 → 鍵が消えること)。
   - 実際のクラウド変数サーバーにつないで、`🔒 request [こんにちは]` が往復すること。HELLO 再送は、サーバーの起動を遅らせて 6〜12 秒後に接続できるかで確認できます。
   - 接続後に `🔒 wipe secrets` を実行して保存し、`cloudiamond-scratch audit` が通ること。
3. `python -m build` → `twine check --strict dist/*` → まず **TestPyPI** で `pip install` と `cloudiamond-scratch selftest` を試す。
4. `pyproject.toml` の `authors`(作者名・連絡先。メールアドレスは PyPI で公開されます)を決めて追記する。`[project.urls]` は元のリポジトリの URL を入れてあります。LICENSE は MIT(著作権表示は「cloudiamond-scratch contributors」)。
5. アップロード:
   - **API トークンで手動:** `python -m twine upload dist/*`(ユーザー名 `__token__`、パスワード = トークン。環境変数 `TWINE_PASSWORD` に入れ、コマンド履歴・チャット・Git・Scratch に**絶対に書かない**。万一漏れたらすぐ PyPI で失効させる。可能ならプロジェクト限定のトークン)。
   - **GitHub Actions(Trusted Publishing。トークン不要):** `.github/workflows/publish.yml`。Release を公開すると PyPI へ、Actions 画面からの手動実行で TestPyPI へ。登録(Pending publisher)には Project `cloudiamond-scratch`、Workflow `publish.yml`、Environment `pypi` / `testpypi` を入れ、GitHub 側にも同名の Environment を作る(`pypi` には Required reviewers を推奨)。Release のタグは `v1.0.0`(`pyproject.toml` と違えば公開前に止まります)。
6. Release に `releases/ClouDiamond_v1.0.0_DEMO.sb3` と `SHA256SUMS` を添える。**デモ用の鍵は秘密鍵が公開されています**(`examples/demo_server.key`)。実際のデータには使わず、本番用は自分の `server.key` で `build` し直してください(`build` / `serve` はデモ鍵を使うと警告します)。

## 開発

```
pip install -e ".[test]"
pytest                          # Node.js 不要
python tools/make_template.py   # テンプレートの再生成(tools/upstream/v0.1_DEMO.sb3 から)
```

`src/cloudiamond_scratch/data/client_template.json` が Scratch クライアント本体(コンパイル済み)です。0.1 の README にある `scratch/program.py` / `scratch/spy.py`(SPy)から再生成する流れに戻す手順は [docs/UPGRADING.md](docs/UPGRADING.md) にあります。

## トラブルシュート

| 症状 | 確認すること |
| --- | --- |
| `🔒 connect` が `FAILED: server not verified` | サーバーが動いているか。`.sb3` の公開鍵とサーバーの鍵が対か(`inspect` と `pubkey` のフィンガープリントを比べる)。デモ鍵のサーバーに自分の `.sb3` をつないでいないか |
| 接続はできるが返信が来ない | ハンドラが `None` を返していないか。`server.stats`(`drop.*`)を見る。レート制限・同時利用による衝突 |
| 返信の文字が `?` になる | 表にない文字(漢字・大文字・全角英数)。`cloudiamond_scratch.text` を使う |
| 長いメッセージが切れる | 最大 286 byte。分割して送る |
| サーバー再起動後に通信できない | セッションは再起動で消えます。Scratch 側で `🔒 connect` をやり直す |
| `audit` が CRITICAL を出す | 接続したまま保存しています。`🔒 wipe secrets` を実行してから保存し直す |

## ライセンス

MIT(`LICENSE`)。
