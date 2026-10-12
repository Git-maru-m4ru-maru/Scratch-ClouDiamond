"""
cli.py -- コマンドライン: cloudiamond-scratch (または python -m cloudiamond_scratch)

  keygen  server.key            サーバーの長期鍵を作る(0600)。秘密鍵は公開しない。公開鍵が表示される
  pubkey  server.key            既存の秘密鍵から公開鍵を表示する
  build   --key server.key -o client.sb3
          --pub <64桁の16進>                      Scratch クライアント(.sb3)を生成する。埋め込まれるのは公開鍵だけ
  selftest                      標準実装との照合(RFC ベクトル)と、クライアント/サーバーの往復を自己診断する
"""
from __future__ import annotations

import argparse
import os
import sys
import zipfile
from typing import List, Optional

from . import __version__
from .server import load_or_create_static_key, public_bytes, to_digits


def _read_pub(args) -> bytes:
    if args.pub:
        h = args.pub.strip().lower().removeprefix("0x")
        try:
            raw = bytes.fromhex(h)
        except ValueError:
            raise SystemExit("error: --pub は 64 桁の 16 進数です")
        if len(raw) != 32:
            raise SystemExit("error: --pub は 32 byte(64 桁の 16 進数)である必要があります")
        if not any(raw):
            raise SystemExit("error: 全ゼロの公開鍵は使えません")
        return raw
    if args.key:
        if not os.path.exists(args.key):
            raise SystemExit("error: 鍵ファイルがありません: %s(先に keygen してください)" % args.key)
        return public_bytes(load_or_create_static_key(args.key))
    raise SystemExit("error: --key か --pub のどちらかを指定してください")


def cmd_keygen(args) -> int:
    existed = os.path.exists(args.path)
    key = load_or_create_static_key(args.path)
    pub = public_bytes(key)
    print(("既存の" if existed else "新しい") + "サーバー秘密鍵: %s   ← 絶対に公開・コミットしない" % args.path)
    _print_pub(pub)
    return 0


def _print_pub(pub: bytes) -> None:
    print("公開鍵(hex)     :", pub.hex())
    print("公開鍵(数字列)   :", to_digits(pub))
    print("→ 公開鍵は Scratch に埋め込んで構いません(公開情報)。`build` が自動で埋め込みます。")


def cmd_pubkey(args) -> int:
    if not os.path.exists(args.path):
        raise SystemExit("error: 鍵ファイルがありません: %s" % args.path)
    _print_pub(public_bytes(load_or_create_static_key(args.path)))
    return 0


def cmd_build(args) -> int:
    from .scratch.build import build_client_sb3
    pub = _read_pub(args)
    data = build_client_sb3(pub, sprite_name=args.name)
    with open(args.output, "wb") as f:
        f.write(data)
    with zipfile.ZipFile(args.output) as z:
        assert z.testzip() is None
    print("生成しました: %s (%.1f KiB)" % (args.output, len(data) / 1024))
    print("サーバー公開鍵 :", pub.hex())
    print("次の手順       : Scratch / TurboWarp で開き、クラウド変数の接続先をサーバーに向ける(README 参照)")
    print("保存の前に     : 実行した後のプロジェクトを保存・公開する前に『🔒 wipe secrets』ブロックを必ず実行する")
    return 0


def cmd_selftest(args) -> int:
    from .selftest import run
    return run(verbose=True)


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="cloudiamond-scratch",
                                description="Scratch <-> Python の暗号通信(X25519 + ChaCha20-Poly1305)")
    p.add_argument("--version", action="version", version="cloudiamond-scratch " + __version__)
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("keygen", help="サーバーの長期鍵を作る")
    s.add_argument("path", help="秘密鍵の保存先(例: server.key)")
    s.set_defaults(fn=cmd_keygen)

    s = sub.add_parser("pubkey", help="秘密鍵ファイルから公開鍵を表示する")
    s.add_argument("path")
    s.set_defaults(fn=cmd_pubkey)

    s = sub.add_parser("build", help="Scratch クライアント(.sb3)を生成する")
    g = s.add_mutually_exclusive_group(required=True)
    g.add_argument("--key", help="サーバーの秘密鍵ファイル(公開鍵だけを取り出して埋め込む)")
    g.add_argument("--pub", help="サーバーの公開鍵(64 桁の 16 進数)")
    s.add_argument("-o", "--output", default="cloudiamond-client.sb3")
    s.add_argument("--name", default="Cloudiamond", help="スプライト名")
    s.set_defaults(fn=cmd_build)

    s = sub.add_parser("selftest", help="自己診断")
    s.set_defaults(fn=cmd_selftest)

    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
