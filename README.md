<!--
 * @Author: FunctionSir
 * @License: AGPLv3
 * @Date: 2025-09-18 22:25:36
 * @LastEditTime: 2025-11-24 23:14:07
 * @LastEditors: FunctionSir
 * @Description: -
 * @FilePath: /roxytunnel/README.md
-->

# Roxy Tunnel

Roxy Tunnel, a VPN system based on Resilient Obfuscated eXchange roxY (Roxy) Protocol.

So, what is Roxy? Oh, it's "Resilient Obfuscated eXchange roxY".

But what is Roxy, the last word? Oh, it's "Resilient Obfuscated eXchange roxY"...

Roxy Tunnel will be the bachelor's graduation project of me, I will welcome suggestions and feedback, PRs may not be merged during the development phase. Thank you.

## About the protocol

Roxy Protocol, or Resilient Obfuscated eXchange roxY Protocol, is a VPN protocol based on WSS. TLS is FORCED to ensure you are safe.

### What makes you safe?

**Still in developing!**

1. TLS of WSS (with cert-pinning, OCSP validation, uTLS client fingerprint meek features avaliable).
2. Noise IK based auth and key exchange.
3. AES-256-GCM-SIV with HKDF based key rotation.
4. Pluggable external auth.

## Features / Todo

- ☑ Naming, repo, license.
- ☐ WSS based transport.
- ☐ SQLite based "Instance DB".
- ☑ TLS cert pinning.
- ☑ uTLS "meeked" client.
- ☐ Customizable traffic processors.
- ☐ Customizable income auth failed actions.
- ☐ Noise IK based auth.
- ☐ Pluggable auth.
- ☐ L2 VPN.
- ☐ Inner encryption (AES-256-GCM-SIV, with HKDF based key rotation).
- ☐ "Allow IPs".
- ☐ Useful command-line tools.
- ☐ Web UI.
- ☐ Best-effort shred when needed.
- ☐ The final thesis.
- ......
