"""Mutation check: break security-critical code one place at a time and confirm the test-suite fails.

Usage: python tools/mutation_check.py [NAME-SUBSTRING ...]   (all patterns take a few minutes; works on a temporary copy,
never touches the source tree)
"""
import os
import shutil
import subprocess
import sys
import tempfile
SRC = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
muts = [
 ("server: replay check removed", "src/cloudiamond_scratch/server.py",
  "        if ctr <= s.recv_last:\n            return self._drop(\"replay\")\n", "", ["test_server"]),
 ("server: counter advanced BEFORE authentication", "src/cloudiamond_scratch/server.py",
  "        plain = aead_open(s.k_c2s, P.data_nonce(ctr), frame[:P.HEADER_LEN], frame[P.HEADER_LEN:])\n        if plain is None:",
  "        s.recv_last = ctr\n        plain = aead_open(s.k_c2s, P.data_nonce(ctr), frame[:P.HEADER_LEN], frame[P.HEADER_LEN:])\n        if plain is None:", ["test_server"]),
 ("server: a newcomer may replace a live session (sid collision)", "src/cloudiamond_scratch/server.py",
  "            return self._drop(\"sid_collision\")     # never let a newcomer replace a live session",
  "            self._sessions.pop(sid, None)", ["test_server"]),
 ("server: AEAD tag failure ignored (no auth)", "src/cloudiamond_scratch/server.py",
  "        if plain is None:\n            return self._drop(\"auth\")",
  "        if plain is None:\n            plain = frame[P.HEADER_LEN:-P.TAG_LEN]", ["test_server"]),
 ("server: eviction removes confirmed sessions first", "src/cloudiamond_scratch/server.py",
  "        pool = pending or list(self._sessions.values())",
  "        pool = [s for s in self._sessions.values() if s.confirmed] or list(self._sessions.values())", ["test_server"]),
 ("server: HELLO rate limit disabled", "src/cloudiamond_scratch/server.py",
  "        if not self._hello_bucket.allow(now):\n            return self._drop(\"hello_rate\")\n", "", ["test_server"]),
 ("server: reply does not bind the client's ephemeral key (AAD)", "src/cloudiamond_scratch/server.py",
  "aad = sid + bytes([P.T_REPLY]) + e + big_r", "aad = sid + bytes([P.T_REPLY]) + big_r", ["test_server"]),
 ("server: unsupported reply type crashes handle_frame again", "src/cloudiamond_scratch/server.py",
  "        except TypeError:\n            self.stats[\"handler_error\"] += 1", "        except ZeroDivisionError:\n            self.stats[\"handler_error\"] += 1", ["test_server"]),
 ("bridge: HDR written before the slots", "src/cloudiamond_scratch/bridge.py",
  "        writes.append((self.prefix + P.VAR_S2C_HDR, str(hdr)))\n        return writes",
  "        writes.insert(0, (self.prefix + P.VAR_S2C_HDR, str(hdr)))\n        return writes", ["test_bridge"]),
 ("bridge: HDR may repeat the value already in the cloud", "src/cloudiamond_scratch/bridge.py",
  "        if str(hdr) == self._vals.get(P.VAR_S2C_HDR):", "        if False:", ["test_bridge"]),
 ("bridge: snapshot values are processed", "src/cloudiamond_scratch/bridge.py",
  "if initial or short != P.VAR_C2S_HDR:", "if short != P.VAR_C2S_HDR:", ["test_bridge"]),
 ("protocol: slot byte value >255 accepted", "src/cloudiamond_scratch/protocol.py",
  "        if v > 255:\n            return None\n", "", ["test_protocol"]),
 ("protocol: nonce uses only the counter low bytes", "src/cloudiamond_scratch/protocol.py",
  "    return b\"\\0\" * 6 + ctr.to_bytes(6, \"big\")", "    return b\"\\0\" * 6 + (ctr % 65536).to_bytes(6, \"big\")", ["test_protocol", "test_server"]),
 ("crypto: low-order point check removed", "src/cloudiamond_scratch/crypto.py",
  "    if not any(out):  # belt and braces\n        raise CryptoError(\"all-zero shared secret\")\n", "", ["test_crypto"]),
 ("crypto: C2S/S2C keys not separated", "src/cloudiamond_scratch/crypto.py",
  "return master, hchacha20(master, LABEL_C2S), hchacha20(master, LABEL_S2C)", "return master, hchacha20(master, LABEL_C2S), hchacha20(master, LABEL_C2S)", ["test_crypto"]),
 ("auth: password compare not constant-time-safe -> always true", "src/cloudiamond_scratch/auth.py",
  "        return hmac.compare_digest(dk, base64.b64decode(want))", "        return True", ["test_router_auth_text"]),
 ("audit: session key lists no longer flagged", "src/cloudiamond_scratch/sb3.py",
  '_KEY_LISTS = {"EK", "DHES", "DHEE", "MASTER", "KC2S", "KS2C", "AK",', '_KEY_LISTS = {"EK", "DHES", "DHEE", "MASTER",', ["test_sb3"]),
 ("audit: 64-hex secret scan removed", "src/cloudiamond_scratch/sb3.py",
  "    for m in set(_HEX64.findall(text)):", "    for m in set():", ["test_sb3"]),
 ("verify: block comparison always passes", "src/cloudiamond_scratch/sb3.py",
  "    if got == want:\n        rep.client_unmodified = True", "    if True:\n        rep.client_unmodified = True", ["test_sb3"]),
 ("router: error details leaked to the client", "src/cloudiamond_scratch/router.py",
  '            return self._reply(self.error)\n        return self._reply(out)', '            return self._reply("error " + repr(Exception))\n        return self._reply(out)', ["test_router_auth_text"]),
 ("keys: key file created world-readable", "src/cloudiamond_scratch/keys.py",
  "fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)", "fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)", ["test_keys", "test_fsperm"]),

 ("fsperm: Windows ACL keeps inherited entries (no /inheritance:r)", "src/cloudiamond_scratch/fsperm.py",
  '["icacls", path, "/inheritance:r", "/grant:r", f"*{sid}:F"]', '["icacls", path, "/grant:r", f"*{sid}:F"]', ["test_fsperm"]),
 ("fsperm: inherited ACL entries are not treated as shared", "src/cloudiamond_scratch/fsperm.py",
  '    if any("I" in flags for _, flags in aces):     # inheritance still on: access follows the folder\'s rules\n        return False\n', "", ["test_fsperm"]),
 ("fsperm: any listed account counts as the current user", "src/cloudiamond_scratch/fsperm.py",
  "    return all(who.lower().endswith(mine) for who, _ in aces)", "    return True", ["test_fsperm"]),
 ("keys: secret written before the file is locked down", "src/cloudiamond_scratch/keys.py",
  '        ok = fsperm.restrict_to_owner(p)        # Windows: restrict BEFORE the secret is written; POSIX: no-op\n        with open(p, "wb") as f:\n            f.write(body)\n',
  '        with open(p, "wb") as f:\n            f.write(body)\n        ok = fsperm.restrict_to_owner(p)\n', ["test_fsperm"]),
 ("keys: strict mode keeps a key file that could not be protected", "src/cloudiamond_scratch/keys.py",
  "    if not ok and strict:", "    if False:", ["test_fsperm", "test_cli"]),
 ("keys: shared key file no longer warned about", "src/cloudiamond_scratch/keys.py",
  "    warnings.warn(msg, KeyPermissionWarning, stacklevel=3)", "    pass", ["test_keys", "test_fsperm"]),
 ("cli: console safety removed (crashes on cp932 / cp1252 consoles)", "src/cloudiamond_scratch/cli.py",
  "    _safe_console()\n    logging.basicConfig(", "    logging.basicConfig(", ["test_cli"]),
 ("MANIFEST.in lists file extensions again (a .js harness would be dropped)", "MANIFEST.in",
  "graft tests\n", "recursive-include tests *.py\n", ["test_release_consistency"]),
]
res = []
filters = sys.argv[1:]
for name, rel, old, new, mods in muts:
    if filters and not any(f in name for f in filters):
        continue
    dst = os.path.join(tempfile.gettempdir(), "cloudiamond_mutation")
    shutil.rmtree(dst, ignore_errors=True)
    shutil.copytree(SRC, dst, ignore=shutil.ignore_patterns("__pycache__", "*.pyc", ".git"))
    path = os.path.join(dst, rel)
    with open(path, encoding="utf-8") as fh:
        s = fh.read()
    if old not in s:
        res.append((name, "MUTATION-NOT-APPLIED")); continue
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(s.replace(old, new, 1))
    p = subprocess.run([sys.executable, "-m", "unittest"] + mods, cwd=os.path.join(dst, "tests"),
                       capture_output=True, text=True, timeout=600)
    killed = p.returncode != 0
    res.append((name, "caught" if killed else "SURVIVED"))
    print(f"{'caught  ' if killed else 'SURVIVED'} {name}", flush=True)
bad = [r for r in res if r[1] != "caught"]
print(f"\n{len(res)-len(bad)}/{len(res)} mutations caught"); 
for b in bad: print("  PROBLEM:", b)
sys.exit(1 if bad else 0)
