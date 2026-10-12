# cloudiamond-scratch

**Encrypted Scratch ⇄ Python communication that stays secure even though every Scratch project's code is public.**
Key exchange X25519, encryption ChaCha20-Poly1305 — the Scratch side is generated as an `.sb3` and has been run on the real Scratch VM (`scratch-vm`) against the real Python server.

Scratch ⇄ Python サーバー間の通信を、**コードが全員に見える**前提で守るためのパッケージです。

> `cloudiamond-scratch` は PyPI 上の別プロジェクト `cloudiamond` とは無関係です(import 名は衝突しないよう `cloudiamond_scratch` にしています)。

## 発想

Scratch のコードは誰でも読めるので、「アルゴリズムや鍵を隠す」設計は成立しません。そこで **秘密をコードに一切置かない** ようにしています。

- サーバーの**公開鍵**だけをプロジェクトに埋め込む(公開情報)。
- クライアントは接続のたびに**使い捨ての秘密鍵**を作る。その鍵は誰にも送られない。
- プロジェクトのコード・公開鍵・通信の全記録を知っていても、鍵は計算できない(X25519 の離散対数問題)。

暗号は標準のもの(X25519 / ChaCha20-Poly1305 RFC 8439 / HChaCha20)だけで、独自の暗号は作っていません。Scratch にはビット演算も 64bit 整数も無いので、`+ - * floor mod` とリストだけで書き直してあります。

## インストールと最短手順

```bash
pip install cloudiamond-scratch
cloudiamond-scratch selftest                       # 自己診断(数秒)
cloudiamond-scratch keygen server.key              # サーバーの長期鍵。秘密鍵は公開しない
cloudiamond-scratch build --key server.key -o client.sb3
```

`client.sb3` を Scratch / TurboWarp で開くと、`🔒 connect` / `🔒 send text` / `🔒 wait for message` などのブロックが入っています(緑の旗でデモが動きます)。埋め込まれるのは**公開鍵だけ**です(`--pub <64桁の16進>` でも生成できます)。

サーバー側(通信手段の部分は使う人が用意します):

```python
from cloudiamond_scratch import CloudBridge, SecureServer, load_or_create_static_key

server = SecureServer(load_or_create_static_key("server.key"),
                      on_message=lambda sid, data: b"echo:" + data)   # None を返せば無返信
bridge = CloudBridge(server, write=my_cloud_write)   # write(name, value): クラウド変数を書く関数

# クラウド変数が更新されるたびに(名前と値を)渡す。slot を全部書いた後で HDR が書かれる順序を保つこと
bridge.on_variable(name, value)
bridge.push(sid, b"server-initiated message")        # サーバー起点の送信(任意)
```

`CloudBridge` は WebSocket も `scratchattach` も知りません。**接続層(Scratch / TurboWarp の クラウド変数サーバーへの接続)は含まれておらず、実際のサーバーに対しては未検証です。** その代わり、クラウド変数と同じ挙動(slot → HDR の順に書く)で、本物の Scratch VM とつないだ通しテストが付いています。

## プロトコル

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
|---|---|
| 盗聴されても読めない | X25519 + ChaCha20-Poly1305。通信に平文も鍵も乗らない |
| サーバーのなりすまし防止 | `dh_es` は `s` を持つ者しか計算できない。偽サーバーの返信は AEAD 検証で落ちる |
| 改ざん検出 | Poly1305 タグ。1 bit でも変わればサーバーは黙って捨てる |
| 再送(リプレイ)防止 | 方向別の単調増加カウンタ |
| 前方秘匿性 | サーバー側の一時鍵 `r` を使用後に破棄。後で `s` が漏れても過去の通信は読めない |
| 長さの秘匿 | 平文を 32 byte 単位にパディング |
| 認証前に送らない | 接続に失敗したら、そのために作った鍵・乱数をすべて消す。未接続のときは送信ブロックが何もしない |

## 防げないもの(正直に)

- **クライアントの本人確認。** コードが公開なので、誰でも正規クライアントと同じものを作れます。ユーザー認証が必要なら、パスワード等を**暗号化されたメッセージの中で**送り、サーバー側で検証してください。
- **妨害(DoS)。** クラウド変数は誰でも書けます。壊れた通信は捨てられる(安全側)だけで、届かなくすることは防げません。
- **メタデータ。** 通信の有無・回数・タイミング、32 byte 刻みの長さ、セッション ID は見えます。
- **クライアント端末の乗っ取り**(本人の端末内のメモリは守れません)。
- **弱い乱数。** Scratch の `pick random` は暗号用ではありません(下記)。

## 乱数

接続時に約 3 秒かけて、`pick random`・`timer` の細かい桁・マウス座標・`days since 2000` の小数下位桁を HChaCha20 で混ぜ込んで使い捨て秘密鍵を作ります。**マウスを動かしてもらう**ほど安全側です(動かさなくても動作はしますが、その場合の強さはブラウザの `Math.random` に依存します)。

## 保存・共有のときの注意

Scratch は変数・リストの**現在値をプロジェクトに保存**します。接続した後のプロジェクトをそのまま保存・共有すると、**通信用の鍵が入ったまま**になります。保存・公開の前に必ず `🔒 wipe secrets`(または `🔒 disconnect`)ブロックを実行してください。生成直後の `.sb3` には秘密は入っていません(テストで確認)。**サーバーの秘密鍵(`server.key`)は絶対に Scratch に入れない・コミットしない**でください。

GitHub などで `.sb3` を配布するときも同じです。**生成直後のもの、または wipe してから保存したものだけ**を置いてください。接続したあとに保存した `.sb3` は置かないでください。同じ公開鍵・同じバージョン・同じ `--name`(省略時は `Cloudiamond`)なら、`cloudiamond-scratch build --pub <公開鍵>` で同じバイト列を再生成できます。配布物には `sha256`・公開鍵・バージョンを添えておくと、受け取った人が検証できます。

プロジェクトのパレットには、内部で使う変数・リストが多数並びます(関数ごとのローカル変数を含む)。邪魔でも消さないでください。

## クラウド変数の約束

- プロジェクトのクラウド変数は 10 個ちょうど: `☁ C2S_HDR` `☁ C2S_0..3`(クライアント→サーバー)、`☁ S2C_HDR` `☁ S2C_0..3`(サーバー→クライアント)。
- 1 slot = 84 byte(数字だけの文字列。1 byte = 3 桁 + 先頭に `1`、253 桁)。1 フレーム最大 336 byte、**メッセージ本文は最大 286 byte**。
- **slot を全部書いた後で HDR を書く。HDR の値が変わったことが「slot が揃った」合図。** HDR は書くたびに必ず変わる(seq を増やす)。サーバー側の seq は**サーバー全体で単調増加**にすること(`CloudBridge` がそうしています)。
- クラウド変数は全員で共有です。**同時に複数人が使うと衝突**します。衝突は暗号が「捨てる」だけなので安全は保たれますが、再送が必要です(HELLO の自動再送はまだありません)。
- 数字だけ・256 桁まで・1 プロジェクト 10 個、という制約に合わせた設計です。書き込み頻度の制限や、公式の Scratch サーバーでの動作は、**実機では確認していません**。

## 検証したこと

テストは `tests/` にあります(`pip install "cloudiamond-scratch[test]"` + ソースツリーで `pytest`)。

- **暗号部品:** RFC 7748 / RFC 8439 の公式ベクトル、`cryptography` との照合、巨大整数の参照実装との境界値照合(Poly1305 の最終還元など)。テストの感度は、定数を 1 つ壊した版で落ちることで確認しています。
- **Scratch の制約:** 全プリミティブが「+ − × floor mod とリストだけ」で動き、途中の値が 2^53 未満に収まること(ビット演算を禁止した検査クラス経由で実行)。
- **本物の Scratch VM 上での実行:** `.sb3` を `scratch-vm` で実行し、X25519 / HChaCha20 / ChaCha20-Poly1305 / Poly1305 の出力が標準実装と一致。さらに VM 上のクライアントと実物のサーバーを、クラウド変数と同じ挙動でつなぎ、接続 → サーバー認証 → 暗号化メッセージの往復を確認。鍵の違うサーバーは拒否され、鍵素材が残らないことも確認。
- **攻撃シナリオ:** 盗聴 / ビット反転改ざん / 再送 / 反射 / 返信の差し替え(`R := S` など)/ 偽サーバー / 位数の小さい点 / ゴミ入力 / 返信フラッド / レート制限。
- **決定的ビルド:** 同じ公開鍵からは、バイト単位で同じ `.sb3` ができます。配布された `.sb3` は、公開鍵・このパッケージの同じバージョン・同じスプライト名(`--name`)から再生成して `sha256` を突き合わせれば検証できます。

### 実測した速さ(参考値)

開発用サンドボックスの `scratch-vm`(Node.js、画面描画なし)での値です。

| 処理 | 所要時間 |
|---|---|
| X25519 1 回 | 約 0.5 秒 |
| 接続 → 暗号化メッセージ 2 往復(乱数収集の約 3 秒を含む) | 約 6〜10 秒 |

**実際のブラウザの Scratch・スマートフォン・古い PC での時間は計測していません。** 同じインタプリタで動くはずですが、より遅い可能性があります。接続時に X25519 を 3 回行います。

## 未検証・限界

- 実際の Scratch 公式サーバー / TurboWarp のクラウド変数サーバー越しの動作(接続層は含まれていません)
- 実ブラウザでの速度、Scratch のエディタ上での操作感
- **第三者による暗号レビューは受けていません。** 部品はすべて標準のものですが、唯一の「組み立て」は 2 段の鍵導出(`HChaCha20` を PRF として連鎖。NaCl の `crypto_box` が HSalsa20 でやっているのと同じ発想で、`dh_es` / `dh_ee` の一方が秘密なら `master` は予測できません)です。単純な XOR 結合は `R := S` で鍵が崩壊するため採りませんでした。標準の HKDF-SHA256 が理想ですが、Scratch への SHA-256 の移植コストが大きいため見送っています。重要な情報を扱う前に、レビューを受けてください。

## 公開前チェックリスト(PyPI へ出す人向け)

ライセンスは MIT です(`LICENSE`。著作権表示は「cloudiamond-scratch contributors」にしてあるので、個人名・組織名にしたい場合は書き換えてください)。`pyproject.toml` には、公開する人が決めて書く項目がまだ残っています。**意図的に入れていません。**

1. **作者名・連絡先**(`authors`。メールアドレスは PyPI で公開されます)
2. **プロジェクト URL**(`[project.urls]`。GitHub の URL など)
3. `python -m build` → `twine check --strict dist/*` → まず **TestPyPI** で `pip install` を試す
4. アップロードは `.github/workflows/publish.yml`(PyPI の Trusted Publishing。API トークン不要)か、API トークンを使った手動の `twine upload`。トークンは他人に渡さない

### GitHub Actions で公開する場合

`.github/workflows/publish.yml` は、Release を公開すると PyPI へ、Actions 画面からの手動実行で TestPyPI へアップロードします。PyPI / TestPyPI の Trusted Publisher 登録(Pending publisher)には次の値を入れます。

| 項目 | PyPI | TestPyPI |
|---|---|---|
| PyPI Project Name | `cloudiamond-scratch` | `cloudiamond-scratch` |
| Owner / Repository name | GitHub のアカウント名 / リポジトリ名 | 同左 |
| Workflow name | `publish.yml` | `publish.yml` |
| Environment name | `pypi` | `testpypi` |

GitHub 側でも、リポジトリの Settings → Environments に `pypi` と `testpypi` を作ってください(`pypi` には Required reviewers を付けておくと、承認なしに公開されません)。Release のタグは `v` + バージョン(例: `v0.1.0`)にします。`pyproject.toml` のバージョンと違うと、ワークフローは公開前に止まります。

## 開発

```bash
pip install -e ".[test]"
pytest -m "not slow"          # Node.js 不要(Python 実行版の検証)
```

本物の Scratch VM 上のテストには Node.js と `scratch-vm` が必要です。`scratch-vm` を入れたディレクトリの `node_modules` を環境変数で渡すと実行されます(無ければ skip されます)。

```bash
npm install scratch-vm@5.0.300
CLOUDIAMOND_SCRATCH_VM=$PWD/node_modules pytest        # slow も含めて全部
```

`scratch/program.py` が Scratch に載るクライアント本体です。「SPy」という制限付き Python で書かれていて、同じファイルが (1) 普通の Python として動き(標準実装との照合に使う)、(2) `scratch/spy.py` で Scratch のブロックにコンパイルされます。
