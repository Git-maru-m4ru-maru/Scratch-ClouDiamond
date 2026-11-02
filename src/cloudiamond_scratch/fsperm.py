"""Make a secret file private to the current user, and check whether it is.

* POSIX: file mode ``0600`` (set when the file is created, so there is no window in which it is wider).
* Windows: ``os.chmod`` only toggles the read-only attribute, so mode bits mean nothing there. Access is decided
  by the file's ACL, which by default is **inherited from the folder**. This module removes the inherited entries and
  grants access to the current user only, using the ``icacls`` tool that ships with Windows, and reads the result back.

Both functions are best effort and never raise for "could not": :func:`restrict_to_owner` returns ``False`` and
:func:`is_private` returns ``None`` (unknown) when the platform tools are missing or their output is not understood.
Callers decide what to do (the key helpers warn, or raise when ``strict=True``).

Honest limits: this changes who is *listed* in the file's ACL. It cannot protect against an administrator, a process
running as the same user, or a backup / cloud-sync tool that reads the folder. The Windows part is written against the
documented ``icacls`` behaviour; it is exercised by tests on Windows CI, not on every possible configuration.
"""
from __future__ import annotations

import os
import re
import stat
import subprocess
from typing import Optional

__all__ = ["restrict_to_owner", "is_private", "describe_restriction", "icacls_fix_command"]

_SID = re.compile(r"S-1-(?:\d+-)+\d+")
_ACE = re.compile(r"^\s*(?P<who>\S.*?):(?P<flags>(?:\([^()\r\n]*\))+)\s*$")


def _is_windows() -> bool:
    return os.name == "nt"


def _run(cmd: list[str], timeout: float = 20.0) -> Optional[subprocess.CompletedProcess]:
    kwargs = {}
    if _is_windows():
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)   # no console window flashing up
    try:
        return subprocess.run(cmd, capture_output=True, timeout=timeout, check=False, **kwargs)
    except (OSError, subprocess.SubprocessError):
        return None


def _decode(data: bytes) -> str:
    for enc in (("oem", "mbcs") if _is_windows() else ()) + ("utf-8",):
        try:
            return data.decode(enc, "replace")
        except LookupError:
            continue
    return data.decode("utf-8", "replace")


def _current_sid() -> Optional[str]:
    r = _run(["whoami", "/user", "/fo", "csv", "/nh"])
    if r is None or r.returncode != 0:
        return None
    m = _SID.search(_decode(r.stdout))
    return m.group(0) if m else None


def _current_account() -> Optional[str]:
    r = _run(["whoami"])
    if r is None or r.returncode != 0:
        return None
    text = _decode(r.stdout).strip()
    return text.splitlines()[0].strip() if text else None


def parse_icacls(output: str, path: str) -> list[tuple[str, list[str]]]:
    """``icacls <file>`` output -> ``[(principal, [flag, ...]), ...]``. Flags such as ``I`` (inherited), ``F`` (full)."""
    body = output.replace(path, "")
    aces = []
    for line in body.splitlines():
        m = _ACE.match(line)
        if m:
            aces.append((m.group("who").strip(), re.findall(r"\(([^()]*)\)", m.group("flags"))))
    return aces


def icacls_fix_command(path: str | os.PathLike) -> str:
    """The command a user can run by hand to restrict a key file on Windows."""
    return f'icacls "{os.path.abspath(path)}" /inheritance:r /grant:r "%USERNAME%:F"'


def is_private(path: str | os.PathLike) -> Optional[bool]:
    """``True`` = only the current user can access the file; ``False`` = others may (group/other bits on POSIX; inherited or
    additional ACL entries on Windows); ``None`` = could not be determined."""
    path = os.path.abspath(path)
    if not _is_windows():
        try:
            return not (stat.S_IMODE(os.stat(path).st_mode) & 0o077)
        except OSError:
            return None
    r = _run(["icacls", path])
    if r is None or r.returncode != 0:
        return None
    aces = parse_icacls(_decode(r.stdout), path)
    if not aces:
        return None
    if any("I" in flags for _, flags in aces):     # inheritance still on: access follows the folder's rules
        return False
    me = _current_account()
    if me is None:
        return None
    mine = me.lower()
    return all(who.lower().endswith(mine) for who, _ in aces)


def restrict_to_owner(path: str | os.PathLike) -> bool:
    """Make ``path`` private to the current user. Returns ``True`` only if that was achieved and could be confirmed
    (or, when the result cannot be read back, if the platform tool reported success)."""
    path = os.path.abspath(path)
    if not _is_windows():
        try:
            os.chmod(path, 0o600)
        except OSError:
            return False
        return is_private(path) is True
    sid = _current_sid()
    if sid is None:
        return False
    r = _run(["icacls", path, "/inheritance:r", "/grant:r", f"*{sid}:F"])
    if r is None or r.returncode != 0:
        return False
    return is_private(path) is not False


def describe_restriction(path: str | os.PathLike, ok: bool) -> str:
    if ok:
        return "mode 600" if not _is_windows() else "access restricted to the current Windows user"
    if _is_windows():
        return ("could NOT restrict access to the current user; the key file may be readable by others depending on its folder. "
                f"Run:  {icacls_fix_command(path)}")
    return f"could NOT set mode 600; run: chmod 600 {path}"
