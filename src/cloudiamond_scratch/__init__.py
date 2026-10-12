"""cloudiamond-scratch: Scratch <-> Python の暗号通信(X25519 + ChaCha20-Poly1305)。"""
__version__ = "0.1.0"

from .bridge import CloudBridge  # noqa: E402
from .server import SecureServer, load_or_create_static_key, public_bytes  # noqa: E402

__all__ = ["CloudBridge", "SecureServer", "load_or_create_static_key", "public_bytes", "__version__"]
