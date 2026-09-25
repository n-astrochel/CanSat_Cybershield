# CanSat CyberShield 🛰️

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Status](https://img.shields.io/badge/Status-MVP-yellow.svg)

A lightweight, drop-in security module that protects satellite command channels from spoofing and replay attacks — built for student CanSat teams using ESP-NOW, who currently have no accessible way to protect themselves.

## The Problem

Student small-satellite (CanSat) teams often transmit commands over ESP-NOW with no authentication at all. A documented vulnerability (CVE-2024-42483) shows the protocol's built-in replay protection can be bypassed by flooding the channel — even when encryption is on. Separately, sender spoofing remains an [officially open issue](https://github.com/espressif/esp-idf/issues/15179) in Espressif's own repository.

An independent audit of 65 public CanSat/ESP-NOW repositories found **zero** implementations of command authentication or anti-replay protection, and 19 had explicitly disabled ESP-NOW's built-in encryption.

## The Solution

```
Ground Station                                Satellite
      │                                            │
      │  1. Sign command with HMAC-SHA256          │
      │     + increment counter                    │
      │                                            │
      │──── {command, counter, signature} ───────▶│
      │                                            │
      │                       2. Recompute HMAC & compare
      │                       3. Check counter > last accepted
      │                                            │
      │                    ✅ Valid & new → Execute command
      │                    ❌ Invalid/replayed → Reject packet
```


Two independent, application-layer protections, regardless of ESP-NOW library version:
1. **HMAC-SHA256 authentication** — every command is cryptographically signed; tampering invalidates the signature.
2. **Anti-replay protection** — a strictly increasing counter, persisted in non-volatile storage, rejects any previously-used packet.
Also:
3. **Protection against memory reset** — a separate flag prevents an attacker (or a random failure) from resetting the counter and “reviving” old commands.
4. **Bonus**—**content encryption (Fernet/AES-128)** so that the command itself cannot be read if intercepted.
   
## Quick Start

```bash
git clone https://github.com/yourusername/СanSat_Сybershield.git
cd СanSat_Сybershield
python3 cansat_module.py
```

NOTE: this file needs the third-party `cryptography` package.
Install with: pip install cryptography
(already preinstalled in Google Colab — no action needed there)

## Demo Output

```
=== 1. Legitimate command ===
(on the wire, an eavesdropper only sees: gAAAAABqstUD8ICH2kd2BDLkq0DRZ2gc7nKkysTg...)
ACCEPTED: command 'TAKE_PHOTO' executed (counter 1)

=== 2. Attack: packet intercepted and resent AGAIN ===
REJECTED: replay attack — counter 1 was already used (last accepted: 1)

=== 3. Attack: attacker swaps in a DIFFERENT captured encrypted command ===
REJECTED: invalid signature (forgery or corrupted packet)

=== 4. Another legitimate command after the attacks ===
ACCEPTED: command 'TAKE_PHOTO' executed (counter 3)

=== 5. Attack: counter storage wiped, attacker replays an OLD low-numbered packet ===
REJECTED: counter storage looks reset on an already-provisioned device (possible rollback attack or storage corruption) — manual re-pairing required, not silently trusted

```

## Honest Limitations

- No key rotation — a physically extracted key is compromised permanently (inherent to any pre-shared-key design)
- Python prototype — porting to embedded C/C++ (ESP-IDF) is a required next step for real hardware
- Does not stop RF jamming/DoS, and does not patch unrelated ESP-NOW library bugs (e.g. CVE-2025-52471) — those require updating ESP-IDF itself
- Currently designed for a single sender ↔ single receiver pair

## Scalability

The authentication/anti-replay logic operates at the protocol layer, not the satellite layer — the same mechanism applies in principle to any ESP-NOW-based device (CubeSat subsystems, drones, smart locks, industrial sensors), though testing to date has focused specifically on CanSat command channels.

## Process Note

Built individually as part of a cybersecurity startup accelerator project, with an AI assistant (Claude) used as a tool for research, code drafting, and translation. Problem framing, strategic decisions, testing, and outreach were done independently.

## License

MIT
