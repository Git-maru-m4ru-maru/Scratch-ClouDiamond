"""Glue that connects the Scratch VM (client) to a CloudBridge/SecureServer with virtual time."""
from __future__ import annotations

import heapq
import itertools
import json
from pathlib import Path

from scratch_vm import VM

PREFIX = "\u2601 "


def with_pubkey(project: dict, pub: bytes) -> dict:
    p = json.loads(json.dumps(project))
    for t in p["targets"]:
        for lst in t["lists"].values():
            if lst[0] == "SRV":
                lst[1] = list(pub)
    return p


class CloudSim:
    """Cloud variables between one VM client and a bridge, with optional latency and loss.

    ``client_to_server(name, value)`` filters (return False to drop) are applied per write.
    """

    def __init__(self, vm: VM, bridge_factory, *, latency: float = 0.0):
        self.vm = vm
        self.latency = latency
        self.queue: list = []
        self._tie = itertools.count()
        self.log: list[tuple[str, str, str]] = []          # (direction, name, value)
        self.drop_c2s = lambda name, value: False
        self.drop_s2c = lambda name, value: False
        self.bridge = bridge_factory(self._server_write)
        vm.on_cloud_set = self._client_write
        vm.on_wait = self._pump

    def _schedule(self, fn):
        heapq.heappush(self.queue, (self.vm.now + self.latency, next(self._tie), fn))

    def _client_write(self, name: str, value: str):
        self.log.append(("c2s", name, value))
        if self.drop_c2s(name, value):
            return
        if self.latency <= 0:
            self.bridge.on_variable(name, value)
        else:
            self._schedule(lambda: self.bridge.on_variable(name, value))

    def _server_write(self, name: str, value: str):
        self.log.append(("s2c", name, value))
        if self.drop_s2c(name, value):
            return
        if self.latency <= 0:
            self.vm.set_cloud(name, value)
        else:
            self._schedule(lambda: self.vm.set_cloud(name, value))

    def _pump(self, dt: float):
        while self.queue and self.queue[0][0] <= self.vm.now + 1e-9:
            heapq.heappop(self.queue)[2]()


def load_template(path="/home/claude/work/demo/project.json") -> dict:
    return json.load(open(path))


# ------------------------------------------------------------------ helpers for the interop tests
import _setup  # noqa: E402,F401
from cloudiamond_scratch import CloudBridge, SecureServer, generate_static_key, public_key, sb3  # noqa: E402
from cloudiamond_scratch import protocol as P  # noqa: E402

_TEMPLATE_CACHE: dict = {}


def make_client(*, secret: bytes | None = None, server_secret: bytes | None = None, handler=None, seed: int = 1,
                latency: float = 0.0, demo: bool = False, server_kw: dict | None = None):
    """A fresh VM running the real client + a SecureServer wired through a CloudSim.

    ``secret`` is the key whose public half is embedded in the client; ``server_secret`` (default: same)
    is what the server actually holds (differs for impostor tests).
    """
    secret = secret or generate_static_key()
    project = sb3.build_project(public_key(secret), demo=demo)
    vm = VM(project, seed=seed, mouse=(37, -12))
    kw = dict(server_kw or {})
    kw.setdefault("clock", lambda: 1000.0 + vm.now)     # the server lives in the VM's virtual time
    server = SecureServer(server_secret or secret, on_message=handler or (lambda sid, d: b"re:" + d), **kw)
    sim = CloudSim(vm, lambda w: CloudBridge(server, w), latency=latency)
    return vm, server, sim, secret


def frames_in_log(log, direction: str) -> list[bytes]:
    """Reassemble the frames that crossed the (simulated) cloud in one direction."""
    hdr, slots = ("C2S_HDR", P.VAR_C2S) if direction == "c2s" else ("S2C_HDR", P.VAR_S2C)
    vals: dict[str, str] = {}
    out = []
    for d, name, value in log:
        if d != direction:
            continue
        short = name.replace("\u2601", "").strip()
        vals[short] = value
        if short == hdr:
            parsed = P.parse_hdr(value)
            if parsed:
                f = P.slots_to_frame([vals.get(s, "") for s in slots[:parsed[1]]])
                if f:
                    out.append(f)
    return out


def deliver_frame_to_client(vm, frame: bytes, hdr_seq: int) -> None:
    """Write a frame into the client's S2C cloud variables (as an attacker or the server would)."""
    slots = P.frame_to_slots(frame)
    for i, s in enumerate(slots):
        vm.set_cloud(P.CLOUD_PREFIX + P.VAR_S2C[i], s)
    vm.set_cloud(P.CLOUD_PREFIX + P.VAR_S2C_HDR, str(P.make_hdr(hdr_seq, len(slots))))


def zero_lists(vm, names) -> bool:
    return all(float(x) == 0 for n in names for x in vm.list(n))
