"""
CanSat CyberShield — Command Channel (Uplink) Security Module
============================================================
WHAT THIS MODULE SOLVES:
Even if the radio channel (ESP-NOW) does NOT encrypt data, an
attacker should NOT be able to:
 1) forge a command pretending to be the ground station (SPOOFING)
 2) capture a legitimate command and resend it later (REPLAY)

HOW THIS IS SOLVED (3 mechanisms, all symmetric, key pre-shared
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
 C) Provisioning marker + rollback protection
    — a SEPARATE "has this device ever been paired before?" flag,
    stored apart from the regular counter (simulating a harder-
    to-reach, write-once memory region on real hardware). If the
    counter storage ever gets wiped or corrupted, a naive system
    would treat old captured packets as "new" again. This marker
    catches that: if the device claims to be freshly provisioned
    but a low counter is presented, that's treated as suspicious
    and rejected, requiring manual re-pairing instead of being
    silently trusted. Honest limit: if BOTH files are wiped at
    once, this protection is bypassed too — it raises the bar for
    an attacker, it doesn't make rollback impossible.

This is NOT encryption of the command content by itself — HMAC and
the counter protect authenticity and freshness, not secrecy. As a
bonus feature, command content is ALSO encrypted below using Fernet
(AES-128 + its own integrity check) from the `cryptography` library,
so the two mechanisms work together: Fernet hides what the command
says, HMAC+counter prove who sent it and that it isn't a replay.
"""
# NOTE: this file needs the third-party `cryptography` package.
# Install with: pip install cryptography
# (already preinstalled in Google Colab — no action needed there)
import hmac
import hashlib
import json
import os
from cryptography.fernet import Fernet, InvalidToken

# -------------------------------------------------------------
# 1. SHARED SECRET KEY
# -------------------------------------------------------------
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

# SEPARATE key, used only for encrypting command content (confidentiality).
# Fernet requires its own specific key format (32 url-safe base64-encoded
# bytes) — this is why it's a different constant from SHARED_SECRET_KEY
# above, not the same key reused for two purposes.
# Generate a real one with: Fernet.generate_key()
# Same honest limitation as the HMAC key: pre-shared, no rotation.
SHARED_ENCRYPTION_KEY = b"YwQMg2p_Tuj5Nne3PeRRdYbbeI7PBpShiavmv-zyMmI="  # demo key — replace with your own Fernet.generate_key() output before real use
_fernet = Fernet(SHARED_ENCRYPTION_KEY)

# File simulating the satellite's non-volatile memory (EEPROM),
# where the last accepted packet counter is stored. It must
# survive a reboot — otherwise legitimate commands would be
# wrongly rejected as "old" after a restart.
COUNTER_STORAGE_FILE = "satellite_last_counter.json"

# A SEPARATE file simulating a DIFFERENT, more protected memory region
# (on real hardware — a write-once chip/fuse, physically harder to erase
# than the regularly-updated counter EEPROM). It stores only one fact:
# "this device has accepted a command at least once before."
PROVISIONING_MARKER_FILE = "satellite_provisioned.json"

# [PATCH 2] A file simulating the ground station's own non-volatile storage
# for its outgoing counter — mirrors COUNTER_STORAGE_FILE above, but on the
# sender side. Without this, restarting the ground station's process would
# reset outgoing_counter to 0 in memory, and the satellite (which persists
# and remembers its last_accepted_counter) would then wrongly reject the
# next *legitimate* command as a replay.
GROUND_STATION_COUNTER_FILE = "ground_station_counter.json"

# -------------------------------------------------------------
# 2. GROUND STATION (command sender)
# -------------------------------------------------------------
class GroundStation:
    def __init__(self, secret_key: bytes):
        self.secret_key = secret_key
        # Counter of commands sent so far. Starts at 0 and only
        # ever increases — it is NOT reset for repeated commands
        # of the same type (you can send "TAKE_PHOTO" 50 times,
        # just each time with a new, higher counter value).
        # [PATCH 2] Loaded from disk instead of hardcoded to 0, so a
        # restarted ground station doesn't send a counter the satellite
        # has already seen and accepted.
        self.outgoing_counter = self._load_counter()

    def _load_counter(self) -> int:
        """[PATCH 2] Reads the last sent counter from persistent storage —
        same idea as Satellite._load_last_counter(), applied symmetrically
        on the sender side."""
        if os.path.exists(GROUND_STATION_COUNTER_FILE):
            with open(GROUND_STATION_COUNTER_FILE, "r") as f:
                return json.load(f).get("last_sent_counter", 0)
        return 0

    def _save_counter(self):
        """[PATCH 2] Persists the counter so it survives a ground-station restart."""
        with open(GROUND_STATION_COUNTER_FILE, "w") as f:
            json.dump({"last_sent_counter": self.outgoing_counter}, f)

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
        self._save_counter()  # [PATCH 2] persist immediately, before the packet even goes out
        # HMAC is computed over the ORIGINAL plaintext command + counter.
        # This proves authenticity/freshness regardless of encryption.
        signature = self._compute_hmac(command, self.outgoing_counter)
        # The command content is separately encrypted for confidentiality
        # (bonus feature) — an eavesdropper sees only ciphertext, not the
        # actual command text, on top of the authenticity/replay checks.
        encrypted_command = _fernet.encrypt(command.encode("utf-8")).decode("utf-8")
        packet = {
            "encrypted_command": encrypted_command,
            "counter": self.outgoing_counter,
            "signature": signature,
        }
        return packet


# -------------------------------------------------------------
# 3. SATELLITE (command receiver)
# -------------------------------------------------------------
class Satellite:
    def __init__(self, secret_key: bytes):
        self.secret_key = secret_key
        self.last_accepted_counter = self._load_last_counter()
        self.is_provisioned = self._load_provisioning_marker()

    def _load_last_counter(self) -> int:
        """Reads the last accepted counter from 'non-volatile memory'."""
        if os.path.exists(COUNTER_STORAGE_FILE):
            with open(COUNTER_STORAGE_FILE, "r") as f:
                return json.load(f).get("last_counter", 0)
        return 0

    def _load_provisioning_marker(self) -> bool:
        """Checks the SEPARATE marker: has this device ever accepted a command before?"""
        return os.path.exists(PROVISIONING_MARKER_FILE)

    def _mark_provisioned(self):
        """Written once, on the first-ever accepted command. Simulates a
        write-once memory region that's harder for an attacker to reach
        than the regularly-updated counter storage."""
        with open(PROVISIONING_MARKER_FILE, "w") as f:
            json.dump({"provisioned": True}, f)
        self.is_provisioned = True

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

    def receive_packet(self, packet: dict):
        """
        Main function for validating an incoming packet.
        Returns (was_the_packet_accepted, reason).
        """
        encrypted_command = packet.get("encrypted_command")
        counter = packet.get("counter")
        received_signature = packet.get("signature")

        # STEP -1 [PATCH 3 — added after adversarial testing found a crash]:
        # a packet with a missing field or a wrong field type (e.g. counter
        # sent as a string instead of an int) must never crash the receiver
        # process — it must be rejected like any other invalid packet.
        # This is NOT a fix for RF jamming/DoS (still explicitly out of
        # scope, see master doc section 7) — it only stops one malformed
        # dict from taking the whole receiver process down.
        if not isinstance(encrypted_command, str) or not isinstance(received_signature, str):
            return False, "REJECTED: malformed packet (missing/invalid field type)"
        if not isinstance(counter, int) or isinstance(counter, bool):
            return False, "REJECTED: malformed packet (counter must be an integer)"

        # STEP 0: decrypt the command content first. If this fails, the
        # packet is corrupted or wasn't encrypted with our shared key —
        # reject immediately, nothing else to check.
        try:
            command = _fernet.decrypt(encrypted_command.encode("utf-8")).decode("utf-8")
        except (InvalidToken, AttributeError):
            return False, "REJECTED: could not decrypt payload (corrupted or wrong key)"

        # STEP 1: authenticity check (HMAC), computed over the DECRYPTED
        # plaintext command — this is what proves the command wasn't
        # tampered with, regardless of encryption.
        expected_signature = self._compute_hmac(command, counter)
        if not hmac.compare_digest(expected_signature, received_signature):
            return False, "REJECTED: invalid signature (forgery or corrupted packet)"

        # STEP 2: rollback / counter-reset check
        # If this device has ALREADY been provisioned before (per the separate
        # marker), but the counter storage shows a suspiciously low value,
        # that's a red flag: either the counter file was wiped/corrupted, or
        # someone is attempting a rollback attack. A genuinely continuing
        # device would never legitimately need to send a low counter again.
        #
        # [PATCH 1 — original code checked `counter <= SUSPICIOUS_LOW_THRESHOLD`
        # here, i.e. it only distrusted an INCOMING packet with a small number.
        # That missed the real attack: after last_accepted_counter resets to 0,
        # ANY previously captured packet — even one with a high counter like
        # 4, 50, 400 — passed straight through this check and then also passed
        # STEP 3 (counter > 0). The correct signal is not "is the incoming
        # counter small", it's "does the STORAGE itself show 0 on a device
        # that was already provisioned" — that state alone is only possible
        # after a wipe/corruption/rollback attempt, regardless of what number
        # the attacker's packet carries. So the check below no longer looks
        # at `counter` at all.]
        if self.is_provisioned and self.last_accepted_counter == 0:
            return False, (
                "REJECTED: counter storage reset on an already-provisioned "
                "device (possible rollback attack or storage corruption) — "
                "manual re-pairing required, not silently trusted"
            )

        # STEP 3: replay check (anti-replay)
        if counter <= self.last_accepted_counter:
            return False, f"REJECTED: replay attack — counter {counter} was already used (last accepted: {self.last_accepted_counter})"

        # STEP 4: packet is authentic and new — accept and execute
        self._save_last_counter(counter)
        if not self.is_provisioned:
            self._mark_provisioned()
        return True, f"ACCEPTED: command '{command}' executed (counter {counter})"


# -------------------------------------------------------------
# 4. DEMO: showing that the mechanism actually protects the system
# -------------------------------------------------------------
if __name__ == "__main__":
    # Clear the satellite's "memory" at startup so the demo is reproducible
    # [PATCH 2] also clears the new ground-station counter file
    for f in (COUNTER_STORAGE_FILE, PROVISIONING_MARKER_FILE, GROUND_STATION_COUNTER_FILE):
        if os.path.exists(f):
            os.remove(f)

    station = GroundStation(SHARED_SECRET_KEY)
    satellite = Satellite(SHARED_SECRET_KEY)

    print("=== 1. Legitimate command ===")
    packet1 = station.build_command_packet("TAKE_PHOTO")
    print(f"(on the wire, an eavesdropper only sees: {packet1['encrypted_command'][:40]}...)")
    ok, reason = satellite.receive_packet(packet1)
    print(reason)

    print("\n=== 2. Attack: packet intercepted and resent AGAIN ===")
    ok, reason = satellite.receive_packet(packet1)
    print(reason)

    print("\n=== 3. Attack: attacker swaps in a DIFFERENT captured encrypted command ===")
    # The attacker can't forge new ciphertext without the encryption key,
    # so instead tries substituting a different, previously-seen encrypted
    # blob into an old packet, keeping the old counter/signature.
    other_packet = station.build_command_packet("RESET_SYSTEM")
    forged_packet = dict(packet1)
    forged_packet["encrypted_command"] = other_packet["encrypted_command"]
    # Decryption succeeds (it's valid ciphertext) — but the signature was
    # computed over "TAKE_PHOTO", not "RESET_SYSTEM" — HMAC won't match.
    ok, reason = satellite.receive_packet(forged_packet)
    print(reason)

    print("\n=== 4. Another legitimate command after the attacks ===")
    packet2 = station.build_command_packet("TAKE_PHOTO")
    ok, reason = satellite.receive_packet(packet2)
    print(reason)

    print("\n=== 5. Attack: counter storage wiped, attacker replays an OLD low-numbered packet ===")
    os.remove(COUNTER_STORAGE_FILE)
    satellite_after_wipe = Satellite(SHARED_SECRET_KEY)
    ok, reason = satellite_after_wipe.receive_packet(packet1)
    print(reason)

    print("\n=== 6. [NEW — regression test for the fixed rollback bug] ===")
    print("Attack: counter storage wiped, attacker replays an OLD packet whose")
    print("counter is ABOVE the old threshold of 3. This is the exact packet the")
    print("ORIGINAL, unpatched code wrongly ACCEPTED — it only distrusted incoming")
    print("counters <= 3, so anything with counter >= 4 slipped straight through.")
    # Build a few more legitimate commands so we have a captured packet
    # with counter > 3, which is exactly what slipped through the ORIGINAL
    # SUSPICIOUS_LOW_THRESHOLD = 3 check.
    for _ in range(2):
        pN = station.build_command_packet("TAKE_PHOTO")
        satellite.receive_packet(pN)
    captured_high_counter_packet = pN  # counter is now >= 4
    if os.path.exists(COUNTER_STORAGE_FILE):
        os.remove(COUNTER_STORAGE_FILE)
    satellite_after_wipe_2 = Satellite(SHARED_SECRET_KEY)
    ok, reason = satellite_after_wipe_2.receive_packet(captured_high_counter_packet)
    print(reason)
    assert ok is False, "REGRESSION: the old high-counter rollback bug is back!"

    print("\n*** Scenarios 1-6 end with the satellite correctly requiring manual")
    print("    re-pairing (Patch 1 by design) — so Patch 2 is demoed below on a")
    print("    fresh, separately-paired device pair, like starting a new session. ***")

    for f in (COUNTER_STORAGE_FILE, PROVISIONING_MARKER_FILE, GROUND_STATION_COUNTER_FILE):
        if os.path.exists(f):
            os.remove(f)

    print("\n=== 7. [NEW] Ground station sends its first command ===")
    station_a = GroundStation(SHARED_SECRET_KEY)
    satellite_a = Satellite(SHARED_SECRET_KEY)
    packet_a = station_a.build_command_packet("TAKE_PHOTO")
    ok, reason = satellite_a.receive_packet(packet_a)
    print(reason)
    assert ok is True

    print("\n=== 8. [NEW — Patch 2 demo] Ground station process restarts ===")
    station_restarted = GroundStation(SHARED_SECRET_KEY)
    print(f"(ground station reloaded outgoing_counter = {station_restarted.outgoing_counter}, "
          f"satellite last_accepted_counter = {satellite_a.last_accepted_counter})")
    packet_b = station_restarted.build_command_packet("TAKE_PHOTO")
    ok, reason = satellite_a.receive_packet(packet_b)
    print(reason)
    assert ok is True

    print("\n=== ALL DEMO SCENARIOS PASSED ===")
