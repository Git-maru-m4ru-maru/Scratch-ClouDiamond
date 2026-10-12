"""
demo_loopback.py -- ネットワーク無しで 1 往復を再現し、「盗聴者に見えるもの」を表示する。
実行: python demo_loopback.py
"""
import os

from cloudiamond_scratch.reference import client as cr
import cloudiamond_scratch.server as ss

wire = []                                            # 盗聴者が見ているクラウド変数の全履歴


def tap(direction, frame, seq):
    slots, hdr = ss.to_slots(frame, seq)
    wire.append((direction, hdr, slots))
    return ss.from_slots(hdr, slots)[1]              # 受け手が受け取る内容(= 盗聴者と同じもの)


server = ss.SecureServer(on_message=lambda sid, d: b"your balance is 1234 coins" if d == b"balance?" else b"?")
print("サーバー公開鍵(Scratch に埋め込む・公開OK):", ss.to_digits(server.public_key)[:40], "...")

client = cr.ScratchClient(list(server.public_key), cr.mix_entropy(list(os.urandom(32)), list(os.urandom(32))))
reply = server.handle_frame(tap("C→S", bytes(client.hello()), 1))[0]
assert client.on_reply(list(tap("S→C", reply, 1)))
print("ハンドシェイク完了(サーバー認証 + 前方秘匿性)\n")

for i, text in enumerate([b"balance?", b"password=hunter2"], start=2):
    resp = server.handle_frame(tap("C→S", bytes(client.seal(list(text))), i))[0]
    print("クライアントが送った平文 :", text)
    print("クライアントが受け取った :", bytes(client.open(list(tap("S→C", resp, i)))), "\n")

print("=" * 70)
print("盗聴者に見えるクラウド変数の履歴(全部です):")
for d, hdr, slots in wire:
    print(f"  {d} HDR={hdr}  slots={len(slots)}  先頭slot={slots[0][:48]}...")
plain = b"".join(ss.from_digits(s) for _, _, sl in wire for s in sl)
print("\n平文 'hunter2' が通信に含まれるか:", b"hunter2" in plain, "/ 'balance' が含まれるか:", b"balance" in plain)
