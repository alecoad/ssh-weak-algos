# weakknees

Standalone Python 3 script that flags SSH servers offering weak encryption algorithms.

It TCP-connects, reads the server identification banner, sends its own `SSH-2.0-...` ID, then reads the server's first binary packet (`SSH_MSG_KEXINIT`) and parses the offered `encryption_algorithms_client_to_server` and `encryption_algorithms_server_to_client` name-lists. No authentication and no key exchange occur — once KEXINIT is parsed the socket is closed.

No dependencies — stdlib only.

## Weak set

- **RC4:** `arcfour`, `arcfour128`, `arcfour256`
- **AES-CTR:** `aes128-ctr`, `aes192-ctr`, `aes256-ctr`
- **ChaCha20:** `chacha20-poly1305@openssh.com`
- **CBC:** `aes128-cbc`, `aes192-cbc`, `aes256-cbc`, `3des-cbc`, `blowfish-cbc`, `cast128-cbc`, `rijndael-cbc@lysator.liu.se`

Flagging AES-CTR and ChaCha20 is aggressive — these are in OpenSSH defaults — but matches the broad set scanners commonly report.

## Usage

```
python3 weakknees.py <target>
python3 weakknees.py -f targets.txt [-w 20] [--timeout 10] [--no-color]
```

Accepted target forms:

- `host:port` — e.g. `10.0.0.5:22`
- bare `host` (defaults to port 22)
- `[ipv6]:port` — e.g. `[::1]:22`

In a targets file, blank lines and `#` comments (full-line or inline) are stripped.

## Verdicts

- **VULNERABLE** — any weak cipher offered in either direction
- **clean** — no weak ciphers offered
- **error** — connect failed, banner timeout, not an SSH service, malformed KEXINIT

Exit code: `1` if any target is VULNERABLE, `2` on usage error, else `0`.

## Example

```
$ python3 weakknees.py -f targets.txt
SSH weak-cipher scan

  10.0.0.5:22    VULNERABLE
    weak ciphers offered:
      - arcfour
      - arcfour128
      - arcfour256
      - aes128-cbc
      - 3des-cbc

  10.0.0.6:22    clean

  10.0.0.7:22    error: connection refused

  ──────────────────────────────────────
  1 vulnerable   1 clean   1 error
```

When the client→server and server→client cipher lists differ, they're shown as separate sub-blocks instead of the collapsed `weak ciphers offered:` form.

Color is emitted when stdout is a TTY; pass `--no-color` or pipe to a file to suppress.

## Credits

Built with [Claude Code](https://claude.com/claude-code) (Opus 4.7).
