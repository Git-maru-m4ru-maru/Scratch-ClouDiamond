"""cloudiamond-scratch: encrypted Scratch <-> Python communication over cloud variables.

Quick start::

    from cloudiamond_scratch import CloudBridge, SecureServer, load_or_create_static_key

    server = SecureServer(load_or_create_static_key("server.key"),
                          on_message=lambda sid, data: b"echo:" + data)
    bridge = CloudBridge(server, write=my_cloud_write)
    bridge.on_variable(name, value)        # for every cloud variable update
"""
from ._version import PROTOCOL, __version__
from .bridge import BridgeCore, CloudBridge
from .crypto import CryptoError, fingerprint
from .keys import (generate_static_key, is_demo_key, key_from_env, load_or_create_static_key, load_static_key,
                   parse_public, parse_secret, public_key, save_static_key)
from .protocol import MAX_MESSAGE
from .router import Context, Router
from .server import MessageTooLarge, SecureServer, Session, UnknownSession

__all__ = [
    "__version__", "PROTOCOL", "MAX_MESSAGE",
    "SecureServer", "Session", "Router", "Context", "CloudBridge", "BridgeCore", "MessageTooLarge", "UnknownSession", "CryptoError",
    "generate_static_key", "load_static_key", "load_or_create_static_key", "save_static_key",
    "key_from_env", "is_demo_key", "parse_secret", "parse_public", "public_key", "fingerprint",
]
