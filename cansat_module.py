"""
CanSat CyberShield — Command Channel (Uplink) Security Module
============================================================

WHAT THIS MODULE SOLVES:
Even if the radio channel (ESP-NOW) does NOT encrypt data, an
attacker should NOT be able to:
  1) forge a command pretending to be the ground station (SPOOFING)
  2) capture a legitimate command and resend it later (REPLAY)

HOW THIS IS SOLVED (2 mechanisms, both symmetric, key pre-shared
between the ground station and the satellite ahead of time):

  A) HMAC (Hash-based Message Authentication Code)
     — an "electronic seal". Both sides know a secret key.
       The sender computes a signature over (command + counter)
       and attaches it to the packet. The receiver recomputes the
       signature independently and compares. If even a single bit
       of the command is changed, the signatures won't match.

  B) Frame Counter + anti-replay
     — a "letter number". Every new packet must carry a counter
       STRICTLY GREATER than the last one accepted. The satellite
       remembers the last accepted number (stored in a file here —
       simulating non-volatile memory/EEPROM that survives a
       reboot). A packet with an old or repeated number is
       rejected, even if its signature is valid — because it's
       simply a copy of a previously valid packet.

This is NOT encryption (the command content is visible to anyone
listening on the channel) — that's a separate, optional feature
(scenario 1) for later if time allows. Right now we're only
closing integrity and replay protection — scenario 2, command
hijacking.
"""

import hmac
import hashlib
import json
import os

# ---------------------------------------------------------------
# 1. SHARED SECRET KEY
# ---------------------------------------------------------------
# In a real deployment, this key is "burned into" the firmware of
# both sides BEFORE deployment (pre-shared key). It is never
# transmitted over the air — which is exactly why symmetric
# cryptography is sufficient here, without needing asymmetric
# crypto.
#
# IMPORTANT (known MVP limitation, stated honestly):
# if the satellite's firmware is physically extracted and reverse
# engineered, the key is permanently compromised — there is no
# on-orbit key rotation in this design.
SHARED_SECRET_KEY = b"cubesat-cybershield-demo-key-2026"  # replace with a randomly generated key before real use

# File simulating the satellite's non-volatile memory (EEPROM),
# where the last accepted packet counter is stored. It must
# survive a reboot — otherwise legitimate commands would be
# wrongly rejected as "old" after a restart.
COUNTER_STORAGE_FILE = "satellite_last_counter.json"


# ---------------------------------------------------------------
# 2. GROUND STATION (command sender)
# ---------------------------------------------------------------
class GroundStation:
    def __init__(self, secret_key: bytes):
        self.secret_key = secret_key
        # Counter of commands sent so far. Starts at 0 and only
        # ever increases — it is NOT reset for repeated commands
        # of the same type (you can send "TAKE_PHOTO" 50 times,
        # just each time with a new, higher counter value).
        self.outgoing_counter = 0

    def _compute_hmac(self, command: str, counter: int) -> str:
        """Computes the signature for a given (command, counter) pair."""
        # Build the message in a fixed format: command + counter.
        # The order and format must be identical on both sides,
        # otherwise the signatures will never match.
        message = f"{command}:{counter}".encode("utf-8")

        # HMAC-SHA256: a cryptographically strong "seal".
        # Without knowing secret_key, forging it is computationally
        # infeasible.
        signature = hmac.new(self.secret_key, message, hashlib.sha256)
        return signature.hexdigest()

    def build_command_packet(self, command: str) -> dict:
        """
        Builds a packet ready to be sent to the satellite.
        This is the function a team would call for every command
        before transmitting it over radio.
        """
        self.outgoing_counter += 1  # new packet -> new counter, always greater than the previous one
        signature = self._compute_hmac(command, self.outgoing_counter)

        packet = {
            "command": command,
            "counter": self.outgoing_counter,
            "signature": signature,
        }
        return packet


# ---------------------------------------------------------------
# 3. SATELLITE (command receiver)
# ---------------------------------------------------------------
class Satellite:
    def __init__(self, secret_key: bytes):
        self.secret_key = secret_key
        self.last_accepted_counter = self._load_last_counter()

    def _load_last_counter(self) -> int:
        """Reads the last accepted counter from 'non-volatile memory'."""
        if os.path.exists(COUNTER_STORAGE_FILE):
            with open(COUNTER_STORAGE_FILE, "r") as f:
                return json.load(f).get("last_counter", 0)
        return 0

    def _save_last_counter(self, counter: int):
        """Persists the counter so it survives a satellite 'reboot'."""
        with open(COUNTER_STORAGE_FILE, "w") as f:
            json.dump({"last_counter": counter}, f)
        self.last_accepted_counter = counter

    def _compute_hmac(self, command: str, counter: int) -> str:
        """Same logic as on the ground station — otherwise signatures won't match."""
        message = f"{command}:{counter}".encode("utf-8")
        signature = hmac.new(self.secret_key, message, hashlib.sha256)
        return signature.hexdigest()

    def receive_packet(self, packet: dict) -> tuple[bool, str]:
        """
        Main function for validating an incoming packet.
        Returns (was_the_packet_accepted, reason).
        """
        command = packet.get("command")
        counter = packet.get("counter")
        received_signature = packet.get("signature")

        # STEP 1: authenticity check (HMAC)
        expected_signature = self._compute_hmac(command, counter)

        # hmac.compare_digest instead of "==" — protection against
        # timing attacks (a plain string comparison can leak, via
        # comparison time, information about which character the
        # signature diverges at).
        if not hmac.compare_digest(expected_signature, received_signature):
            return False, "REJECTED: invalid signature (forgery or corrupted packet)"

        # STEP 2: replay check (anti-replay)
        if counter <= self.last_accepted_counter:
            return False, f"REJECTED: replay attack — counter {counter} was already used (last accepted: {self.last_accepted_counter})"

        # STEP 3: packet is authentic and new — accept and execute
        self._save_last_counter(counter)
        return True, f"ACCEPTED: command '{command}' executed (counter {counter})"


# ---------------------------------------------------------------
# 4. DEMO: showing that the mechanism actually protects the system
# ---------------------------------------------------------------
if __name__ == "__main__":
    # Clear the satellite's "memory" at startup so the demo is reproducible
    if os.path.exists(COUNTER_STORAGE_FILE):
        os.remove(COUNTER_STORAGE_FILE)

    station = GroundStation(SHARED_SECRET_KEY)
    satellite = Satellite(SHARED_SECRET_KEY)

    print("=== 1. Legitimate command ===")
    packet1 = station.build_command_packet("TAKE_PHOTO")
    ok, reason = satellite.receive_packet(packet1)
    print(reason)

    print("\n=== 2. Attack: packet intercepted and resent AGAIN ===")
    # The attacker simply copies the already-sent packet1 and resends it
    ok, reason = satellite.receive_packet(packet1)
    print(reason)

    print("\n=== 3. Attack: command tampered with, but attacker doesn't know the key ===")
    forged_packet = dict(packet1)
    forged_packet["command"] = "RESET_SYSTEM"  # attacker changes the command
    forged_packet["counter"] = 999              # and tries any counter value
    # but the signature is still from the original command — HMAC won't match
    ok, reason = satellite.receive_packet(forged_packet)
    print(reason)

    print("\n=== 4. Another legitimate command after the attacks ===")
    packet2 = station.build_command_packet("TAKE_PHOTO")  # same command, new counter
    ok, reason = satellite.receive_packet(packet2)
    print(reason)
