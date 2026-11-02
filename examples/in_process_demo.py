"""Run the whole protocol inside one Python process - no Scratch, no network.

    python examples/in_process_demo.py

A ``ReferenceClient`` plays the Scratch client. Use this to see what the server API looks like.
"""
from cloudiamond_scratch import SecureServer, generate_static_key
from cloudiamond_scratch.refclient import ReferenceClient


def main() -> None:
    server = SecureServer(generate_static_key(), on_message=lambda sid, data: b"echo: " + data)
    print("server fingerprint:", server.fingerprint)

    client = ReferenceClient(server.public_key)          # the Scratch project only knows the PUBLIC key
    reply = server.handle_frame(client.hello())          # client -> server: HELLO, server -> client: REPLY
    assert client.accept_reply(reply), "the server could not prove it owns the private key"
    print("handshake ok, server verified")

    frame = server.handle_frame(client.seal(b"hello from the client"))
    print("server answered:", client.open(frame))

    captured = client.seal(b"pay 100")                   # what an eavesdropper could record...
    server.handle_frame(captured)
    print("replaying the recorded frame is silently dropped:", server.handle_frame(captured) is None)
    print("server counters:", dict(server.stats))


if __name__ == "__main__":
    main()
