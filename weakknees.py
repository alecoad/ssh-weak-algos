#!/usr/bin/env python3
"""Reproduce Nessus "SSH Weak Algorithms Supported" finding.

Speaks just enough of the SSH2 protocol to read the server's KEXINIT packet
(the offered algorithm name-lists), then closes. No crypto, no auth.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import socket
import struct
import sys
from dataclasses import dataclass, field
from typing import Optional

CLIENT_ID = b"SSH-2.0-ssh-weak-algos_1.0\r\n"
SSH_MSG_KEXINIT = 20

WEAK_CIPHERS = frozenset({
    # RC4
    "arcfour", "arcfour128", "arcfour256",
    # AES-CTR
    "aes128-ctr", "aes192-ctr", "aes256-ctr",
    # ChaCha20
    "chacha20-poly1305@openssh.com",
    # CBC
    "aes128-cbc", "aes192-cbc", "aes256-cbc",
    "3des-cbc", "blowfish-cbc", "cast128-cbc",
    "rijndael-cbc@lysator.liu.se",
})


@dataclass
class Result:
    target: str
    verdict: str            # vulnerable | clean | error
    c2s_weak: list[str] = field(default_factory=list)
    s2c_weak: list[str] = field(default_factory=list)
    banner: Optional[str] = None
    error: Optional[str] = None


def parse_target(line: str) -> Optional[tuple[str, int]]:
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    # [ipv6]:port
    if line.startswith("["):
        end = line.find("]")
        if end == -1:
            return None
        host = line[1:end]
        rest = line[end + 1:]
        if rest.startswith(":"):
            try:
                return host, int(rest[1:])
            except ValueError:
                return None
        return host, 22
    # host:port or bare host
    if line.count(":") == 1:
        host, _, port_str = line.partition(":")
        if not host:
            return None
        try:
            return host, int(port_str)
        except ValueError:
            return None
    return line, 22


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("peer closed during read")
        buf.extend(chunk)
    return bytes(buf)


def _read_banner(sock: socket.socket, timeout: float) -> str:
    """Read SSH server identification string (last line before first NUL/binary)."""
    sock.settimeout(timeout)
    buf = bytearray()
    deadline_bytes = 64 * 1024
    while len(buf) < deadline_bytes:
        chunk = sock.recv(1024)
        if not chunk:
            raise ConnectionError("peer closed before banner")
        buf.extend(chunk)
        # SSH ID line must end with \r\n; there may be preceding banner lines.
        if b"\r\n" in buf:
            # Find a line starting with SSH-
            for line in buf.split(b"\r\n"):
                if line.startswith(b"SSH-"):
                    return line.decode("ascii", errors="replace")
            # No SSH- line yet; keep reading until we get one or hit cap.
            if buf.count(b"\r\n") >= 50:
                break
    raise ValueError("not an SSH banner")


def _read_name_list(payload: memoryview, offset: int) -> tuple[list[str], int]:
    if offset + 4 > len(payload):
        raise ValueError("truncated name-list length")
    (length,) = struct.unpack(">I", payload[offset:offset + 4])
    offset += 4
    if offset + length > len(payload):
        raise ValueError("truncated name-list body")
    raw = bytes(payload[offset:offset + length]).decode("ascii", errors="replace")
    offset += length
    names = raw.split(",") if raw else []
    return names, offset


def _parse_kexinit(payload: bytes) -> tuple[list[str], list[str]]:
    """Return (encryption_c2s, encryption_s2c) from a KEXINIT payload."""
    if len(payload) < 1 + 16:
        raise ValueError("KEXINIT too short")
    if payload[0] != SSH_MSG_KEXINIT:
        raise ValueError(f"expected KEXINIT (20), got msg type {payload[0]}")
    mv = memoryview(payload)
    offset = 1 + 16  # msg type + cookie
    # 10 name-lists; we keep the 3rd and 4th.
    enc_c2s: list[str] = []
    enc_s2c: list[str] = []
    for i in range(10):
        names, offset = _read_name_list(mv, offset)
        if i == 2:
            enc_c2s = names
        elif i == 3:
            enc_s2c = names
    return enc_c2s, enc_s2c


def probe(target: str, timeout: float) -> Result:
    parsed = parse_target(target)
    if parsed is None:
        return Result(target, "error", error="could not parse target")
    host, port = parsed

    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except socket.gaierror:
        return Result(target, "error", error="DNS resolution failed")
    except (socket.timeout, TimeoutError):
        return Result(target, "error", error="timeout")
    except ConnectionRefusedError:
        return Result(target, "error", error="connection refused")
    except OSError as e:
        return Result(target, "error", error=_short_err(e))

    try:
        sock.settimeout(timeout)
        try:
            banner = _read_banner(sock, timeout)
        except ValueError as e:
            return Result(target, "error", error=str(e))
        except (socket.timeout, TimeoutError):
            return Result(target, "error", error="banner timeout")
        except ConnectionError as e:
            return Result(target, "error", error=_short_err(e))

        try:
            sock.sendall(CLIENT_ID)
        except OSError as e:
            return Result(target, "error", error=_short_err(e))

        try:
            header = _recv_exact(sock, 5)
        except (socket.timeout, TimeoutError):
            return Result(target, "error", banner=banner, error="KEXINIT timeout")
        except ConnectionError as e:
            return Result(target, "error", banner=banner, error=_short_err(e))

        (packet_length,) = struct.unpack(">I", header[:4])
        padding_length = header[4]
        if packet_length < 1 + padding_length or packet_length > 256 * 1024:
            return Result(target, "error", banner=banner, error="bad packet length")
        payload_len = packet_length - padding_length - 1
        try:
            payload = _recv_exact(sock, payload_len)
            _recv_exact(sock, padding_length)  # consume padding (ignored)
        except (socket.timeout, TimeoutError):
            return Result(target, "error", banner=banner, error="KEXINIT timeout")
        except ConnectionError as e:
            return Result(target, "error", banner=banner, error=_short_err(e))

        try:
            enc_c2s, enc_s2c = _parse_kexinit(payload)
        except ValueError as e:
            return Result(target, "error", banner=banner, error=f"malformed KEXINIT: {e}")
    finally:
        try:
            sock.close()
        except OSError:
            pass

    c2s_weak = [a for a in enc_c2s if a in WEAK_CIPHERS]
    s2c_weak = [a for a in enc_s2c if a in WEAK_CIPHERS]
    verdict = "vulnerable" if (c2s_weak or s2c_weak) else "clean"
    return Result(target, verdict, c2s_weak=c2s_weak, s2c_weak=s2c_weak, banner=banner)


def _short_err(e: BaseException) -> str:
    msg = str(e).lower()
    if "connection refused" in msg:
        return "connection refused"
    if "timed out" in msg or "timeout" in msg:
        return "timeout"
    if "no route to host" in msg:
        return "no route to host"
    if "network is unreachable" in msg:
        return "network unreachable"
    if "reset" in msg:
        return "connection reset"
    return str(e)[:60] or type(e).__name__


# ---------------- output ----------------

ANSI = {
    "reset": "\033[0m", "bold": "\033[1m", "dim": "\033[2m",
    "red": "\033[31m", "green": "\033[32m", "yellow": "\033[33m", "cyan": "\033[36m",
}
USE_COLOR = True


def c(s: str, *codes: str) -> str:
    if not USE_COLOR or not codes:
        return s
    return "".join(ANSI[k] for k in codes) + s + ANSI["reset"]


def _bullet(name: str) -> str:
    return f"      {c('-', 'dim')} {name}"


def format_target(r: Result, target_w: int) -> list[str]:
    target = r.target.ljust(target_w)
    head = f"  {target}    "
    if r.verdict == "error":
        return [head + c("error: " + (r.error or "unknown"), "yellow")]
    if r.verdict == "clean":
        return [head + c("clean", "green")]
    lines = [head + c("VULNERABLE", "red", "bold")]
    if r.c2s_weak and r.c2s_weak == r.s2c_weak:
        lines.append("    " + c("weak ciphers offered:", "dim"))
        lines.extend(_bullet(n) for n in r.c2s_weak)
    else:
        if r.c2s_weak:
            lines.append("    " + c("client → server:", "dim"))
            lines.extend(_bullet(n) for n in r.c2s_weak)
        if r.s2c_weak:
            lines.append("    " + c("server → client:", "dim"))
            lines.extend(_bullet(n) for n in r.s2c_weak)
    return lines


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        description="Scan SSH servers for weak encryption algorithms by reading "
                    "the offered KEXINIT cipher lists. Stdlib only; no auth or "
                    "key exchange performed.")
    ap.add_argument("target", nargs="?", help="Single target, e.g. 10.0.0.5:22 or 10.0.0.5")
    ap.add_argument("-f", "--file", help="File with one target per line")
    ap.add_argument("-w", "--workers", type=int, default=20, help="Concurrent workers (default: 20)")
    ap.add_argument("--timeout", type=float, default=10.0, help="Per-target timeout seconds (default: 10)")
    ap.add_argument("--no-color", action="store_true", help="Disable ANSI color")
    args = ap.parse_args(argv)

    global USE_COLOR
    USE_COLOR = sys.stdout.isatty() and not args.no_color

    if bool(args.target) == bool(args.file):
        print("error: provide exactly one of <target> or -f <file>", file=sys.stderr)
        return 2

    if args.file:
        try:
            with open(args.file) as f:
                targets = []
                for ln in f:
                    ln = ln.split("#", 1)[0].strip()
                    if ln:
                        targets.append(ln)
        except OSError as e:
            print(f"error: cannot read {args.file}: {e}", file=sys.stderr)
            return 2
        if not targets:
            print("error: no targets in input file", file=sys.stderr)
            return 2
    else:
        targets = [args.target]

    print(c("SSH weak-cipher scan", "cyan", "bold"))
    print()

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as ex:
        results = list(ex.map(lambda t: probe(t, args.timeout), targets))

    target_w = max((len(r.target) for r in results), default=10)
    for i, r in enumerate(results):
        if i:
            print()
        for line in format_target(r, target_w):
            print(line)

    vuln = sum(1 for r in results if r.verdict == "vulnerable")
    clean = sum(1 for r in results if r.verdict == "clean")
    err = sum(1 for r in results if r.verdict == "error")
    print()
    print("  " + c("─" * 38, "dim"))
    print("  "
          + c(f"{vuln} vulnerable", "red", "bold")
          + "   "
          + c(f"{clean} clean", "green")
          + "   "
          + c(f"{err} error", "dim"))

    return 1 if vuln else 0


if __name__ == "__main__":
    sys.exit(main())
