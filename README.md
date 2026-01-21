<!--
 * @Author: FunctionSir
 * @License: AGPLv3
 * @Date: 2025-09-18 22:25:36
 * @LastEditTime: 2026-01-21 17:17:09
 * @LastEditors: FunctionSir
 * @Description: -
 * @FilePath: /roxytunnel/README.md
-->

# Roxy Tunnel (Now MOVED to tina)

This repo is not active and kept as a memo. Active development continues at tina. **New repo: <https://github.com/FunctionSir/tina>**

Roxy Tunnel, a VPN system based on Resilient Obfuscated eXchange roxY (Roxy) Protocol.

So, what is Roxy? Oh, it's "Resilient Obfuscated eXchange roxY".

But what is Roxy, the last word? Oh, it's "Resilient Obfuscated eXchange roxY"...

Roxy Tunnel will be the bachelor's graduation project of me, I will welcome suggestions and feedback, PRs may not be merged during the development phase. Thank you.

## Now MOVED to tina (SPROUT)

The story is, the name of Roxy comes from an anime girl, but it's a kind of "love at first sight"... Tina Sprout, who is another anime girl, accompanied me for a really long period of time. And I have four plush dolphins (they might be even older than me...)!

So, I'll do these following mappings:

1. ROXY the protocol -> SPROUT Protocol: Secure Protocol for Resilient Obfuscated Universal Tunnel.
2. roxy the implemention -> tina: Tunnel In a Nutshell Adapters.
3. Griseo RH -> DOLPHINS: Defense using Order Ledger and Protection Helper using Incremental Nums System/Scheme.

This repo will remain as a memo.

**New repo: <https://github.com/FunctionSir/tina>**

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
