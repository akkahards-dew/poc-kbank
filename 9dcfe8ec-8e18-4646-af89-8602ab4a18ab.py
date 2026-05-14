#!/usr/bin/env python3
# === STATIC EICAR signature (raw header for AV/EDR) ===
# X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*

r"""CSP behavioural-test dropper (session a9962515270c, generated 2026-05-11T15:02:42Z).

Behavioural signals an EDR / Cortex XDR / SIEM should observe:
  1. process_create:  curl|wget|powershell|python -- non-browser fetcher
  2. network_connect: outbound TCP/443 from non-browser to secure.eicar.org
  3. file_create:     EICAR signature dropped to TEMP / tmp
  4. file_create_executable_or_chmod_x
  5. process_create:  spawn from the freshly-dropped file (kill chain)
  6. AV intercept:    on-write or on-exec EICAR detection (expected)

STATIC EICAR signature embedded in module docstring — raw, never executed:

X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*

SAFETY: only payload is the official EICAR signature from secure.eicar.org.
AV/EDR will intercept on write or on execute — that is the intended
outcome. Run on systems you own / are authorised to test.
"""

# Static signature variable — raw string, never evaluated:
CSP_EICAR = r'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'

# Static multi-line signature carrier — triple-quoted raw, parsed but unused:
CSP_EICAR_BLOCK = r"""
X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*
"""

import os
import subprocess
import sys
import tempfile
import urllib.request

URL  = "https://secure.eicar.org/eicar.com.txt"
SID  = "a9962515270c"
DEST = os.path.join(tempfile.gettempdir(), f"csp_dropper_{SID}.bin")


def main() -> int:
    print(f"[CSP {SID}] downloading {URL} -> {DEST}")
    try:
        urllib.request.urlretrieve(URL, DEST)
    except Exception as exc:  # noqa: BLE001
        print(f"[CSP {SID}] download blocked or AV-intercepted: {exc}")
        return 0

    if not os.path.exists(DEST):
        return 0

    size = os.path.getsize(DEST)
    print(f"[CSP {SID}] file dropped ({size} bytes), attempting execute...")
    try:
        os.chmod(DEST, 0o755)
    except Exception:  # noqa: BLE001
        pass
    try:
        proc = subprocess.run([DEST], capture_output=True, timeout=2, check=False)
        out = (proc.stdout or proc.stderr or b"")[:200].decode("utf-8", errors="replace")
        print(f"[CSP {SID}] exec exit={proc.returncode} head={out!r}")
    except Exception as exc:  # noqa: BLE001
        print(f"[CSP {SID}] execute blocked (expected on detection): {exc}")

    try:
        os.remove(DEST)
    except Exception:  # noqa: BLE001
        pass
    print(f"[CSP {SID}] done.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

# === STATIC EICAR signature (raw trailing marker for AV/EDR) ===
# X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*
