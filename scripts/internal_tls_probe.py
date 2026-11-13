#!/usr/bin/env python3
"""Client-side TLS probe for the internal-TLS image test (AUTPE-8197, R7).

Usage: internal_tls_probe.py HOST PORT GOOD_CA WRONG_CA SERVER_NAME [PATH [MAX_STATUS]]

PATH (default /) is requested over TLS; MAX_STATUS (default 500) is the highest
status that still counts as "served": a server up but answering 5xx because
its database is absent is still proving TLS, so callers may raise it.

Every case must hold; the first failure exits 1. Standard library only.

R7: the TLS 1.1 case uses a Python client with maximum_version=TLSv1_1 and
@SECLEVEL=0 ciphers. `openssl s_client -tls1_1` is not evidence: OpenSSL 3.x
builds can have 1.0 and 1.1 compiled out, so the client refuses before the
server is asked. Here the client is configured to offer 1.1, so a refusal is
the server's.
"""
import http.client
import socket
import ssl
import sys
import warnings

# TLSv1 and TLSv1_1 are deprecated constants; offering them is the point of case 2.
warnings.simplefilter("ignore", DeprecationWarning)

host, port, good_ca, wrong_ca, name = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4], sys.argv[5]
path = sys.argv[6] if len(sys.argv) > 6 else "/"
max_status = int(sys.argv[7]) if len(sys.argv) > 7 else 500
failures = []


def check(label, ok, detail=""):
    print(("ok   " if ok else "FAIL ") + label + (f"  [{detail}]" if detail else ""))
    if not ok:
        failures.append(label)


def context(ca, minimum=None, maximum=None, ciphers=None):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(ca)
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    if ciphers:
        ctx.set_ciphers(ciphers)
    if minimum is not None:
        ctx.minimum_version = minimum
    if maximum is not None:
        ctx.maximum_version = maximum
    return ctx


def handshake(ctx, server_name):
    with socket.create_connection((host, port), timeout=10) as raw:
        with ctx.wrap_socket(raw, server_hostname=server_name) as tls:
            return tls.version()


# 1. TLS 1.2 or later works, and the server answers HTTP on it.
try:
    ctx = context(good_ca, minimum=ssl.TLSVersion.TLSv1_2)
    with socket.create_connection((host, port), timeout=10) as raw:
        with ctx.wrap_socket(raw, server_hostname=name) as tls:
            version = tls.version()
            tls.sendall(b"GET " + path.encode() + b" HTTP/1.1\r\nHost: " + name.encode() + b"\r\nConnection: close\r\n\r\n")
            status = tls.recv(64).split(b" ")[1].decode()
    check("TLS 1.2+ with the right CA and name is served", int(status) <= max_status, f"{version}, HTTP {status}")
except Exception as e:  # noqa: BLE001
    check("TLS 1.2+ with the right CA and name is served", False, repr(e))

# 2. A client offering only TLS 1.1 is refused by the server (R7).
try:
    ctx = context(good_ca, minimum=ssl.TLSVersion.TLSv1, maximum=ssl.TLSVersion.TLSv1_1, ciphers="DEFAULT:@SECLEVEL=0")
except (ValueError, ssl.SSLError) as e:
    # This Python cannot even offer 1.1: the test would prove nothing, so fail loudly.
    check("TLS 1.1 client can be built (else this probe proves nothing)", False, repr(e))
else:
    try:
        version = handshake(ctx, name)
        check("TLS 1.1 only is refused", False, f"negotiated {version}")
    except ssl.SSLError as e:
        check("TLS 1.1 only is refused", "PROTOCOL_VERSION" in str(e).upper() or "ALERT" in str(e).upper() or "VERSION" in str(e).upper(), str(e)[:90])
    except OSError as e:
        check("TLS 1.1 only is refused", True, f"connection dropped: {e.__class__.__name__}")

# 3. A certificate not signed by the configured CA is rejected.
try:
    handshake(context(wrong_ca, minimum=ssl.TLSVersion.TLSv1_2), name)
    check("wrong CA fails verification", False, "handshake succeeded")
except ssl.SSLCertVerificationError as e:
    check("wrong CA fails verification", True, e.verify_message)
except Exception as e:  # noqa: BLE001
    check("wrong CA fails verification", False, repr(e))

# 4. A name that is not in the certificate is rejected.
try:
    handshake(context(good_ca, minimum=ssl.TLSVersion.TLSv1_2), "some-other-service")
    check("wrong hostname fails verification", False, "handshake succeeded")
except ssl.SSLCertVerificationError as e:
    check("wrong hostname fails verification", True, e.verify_message)
except Exception as e:  # noqa: BLE001
    check("wrong hostname fails verification", False, repr(e))

# 5. Plain HTTP to the TLS port is refused: no 2xx or 3xx.
try:
    conn = http.client.HTTPConnection(host, port, timeout=10)
    conn.request("GET", path)
    status = conn.getresponse().status
    check("plaintext HTTP is refused", not (200 <= status < 400), f"HTTP {status}")
except (OSError, http.client.HTTPException) as e:
    check("plaintext HTTP is refused", True, e.__class__.__name__)

sys.exit(1 if failures else 0)
