#!/usr/bin/env python3
"""Independent FakeTLS/obfuscated2 client: verify req_pq_multi -> matching res_pq.

Development dependency: python cryptography. No login/account/session is needed.
This is a protocol smoke test, not a DPI-resistance or media-transfer test.
"""

import argparse
import hashlib
import hmac
import json
import os
import secrets
import socket
import struct
import time

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def extension(kind, payload):
    return struct.pack("!HH", kind, len(payload)) + payload


def client_hello(domain, secret, pq):
    hostname = domain.encode("ascii")
    sni = struct.pack("!H", len(hostname) + 3) + b"\0" + struct.pack("!H", len(hostname)) + hostname
    key_share = struct.pack("!HH", 0x11EC if pq else 0x001D, 1216 if pq else 32)
    key_share += secrets.token_bytes(1216 if pq else 32)
    extensions = extension(0, sni)
    groups = b"\x11\xec\0\x1d" if pq else b"\0\x1d"
    extensions += extension(0x000A, struct.pack("!H", len(groups)) + groups)
    extensions += extension(0x002B, b"\x02\x03\x04")
    extensions += extension(0x0033, struct.pack("!H", len(key_share)) + key_share)
    body = b"\x03\x03" + bytes(32) + b"\x20" + secrets.token_bytes(32)
    body += b"\0\x06\x13\x01\x13\x02\x13\x03\x01\0"
    # A browser-shaped classical hello should not be an unusually tiny record.
    padding = max(0, 517 - (5 + 4 + len(body) + 2 + len(extensions) + 4))
    extensions += extension(0x0015, bytes(padding))
    body += struct.pack("!H", len(extensions)) + extensions
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    wire = bytearray(b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake)
    digest = bytearray(hmac.digest(secret, wire, "sha256"))
    timestamp = int(time.time()).to_bytes(4, "little")
    for i in range(4):
        digest[28 + i] ^= timestamp[i]
    wire[11:43] = digest
    return bytes(wire), bytes(digest)


def read_exact(stream, size):
    result = bytearray()
    while len(result) < size:
        part = stream.recv(size - len(result))
        if not part:
            raise RuntimeError("proxy closed before a complete response")
        result += part
    return bytes(result)


def read_record(stream):
    header = read_exact(stream, 5)
    size = int.from_bytes(header[3:5], "big")
    if size == 0 or size > 18432 or header[1:3] not in (b"\x03\x01", b"\x03\x03"):
        raise RuntimeError("invalid FakeTLS record header")
    return header, read_exact(stream, size)


def probe(host, port, domain, secret, dc=2, pq=False, timeout=10, on_reply=None):
    if len(secret) != 16 or not -1000 <= dc <= 1000 or dc == 0:
        raise ValueError("expected a 16-byte secret and a nonzero signed datacenter")
    started = time.monotonic()
    hello, digest = client_hello(domain, secret, pq)
    with socket.create_connection((host, port), timeout=timeout) as stream:
        stream.settimeout(timeout)
        stream.sendall(hello)
        response = bytearray()
        for expected_kind in (0x16, 0x14, 0x17):
            header, data = read_record(stream)
            if header[0] != expected_kind:
                raise RuntimeError("unexpected FakeTLS handshake record order")
            response += header + data
        received_digest = bytes(response[11:43])
        response[11:43] = bytes(32)
        expected_digest = hmac.digest(secret, digest + response, "sha256")
        if not hmac.compare_digest(received_digest, expected_digest):
            raise RuntimeError("FakeTLS server HMAC did not authenticate")

        banned = (b"HEAD", b"POST", b"GET ", bytes.fromhex("eeeeeeee"), bytes.fromhex("dddddddd"))
        while True:
            nonce = bytearray(secrets.token_bytes(64))
            if nonce[0] != 0xEF and bytes(nonce[:4]) not in banned and nonce[4:8] != bytes(4):
                break
        nonce[56:60] = bytes.fromhex("dddddddd")
        nonce[60:62] = struct.pack("<h", dc)
        reversed_key_iv = bytes(nonce[8:56])[::-1]
        encryptor = Cipher(
            algorithms.AES(hashlib.sha256(nonce[8:40] + secret).digest()),
            modes.CTR(bytes(nonce[40:56])),
        ).encryptor()
        decryptor = Cipher(
            algorithms.AES(hashlib.sha256(reversed_key_iv[:32] + secret).digest()),
            modes.CTR(reversed_key_iv[32:]),
        ).decryptor()
        encrypted_nonce = encryptor.update(bytes(nonce))
        obfuscation = bytes(nonce[:56]) + encrypted_nonce[56:]
        request_nonce = secrets.token_bytes(16)
        message_id = int(time.time() * (1 << 32)) & ~3
        message = struct.pack("<QQII", 0, message_id, 20, 0xBE7E8EF1) + request_nonce
        framed = struct.pack("<I", len(message)) + message
        application = obfuscation + encryptor.update(framed)
        stream.sendall(b"\x14\x03\x03\0\x01\x01")
        stream.sendall(b"\x17\x03\x03" + struct.pack("!H", len(application)) + application)
        plaintext = bytearray()
        received = 0
        while time.monotonic() - started < timeout:
            header, data = read_record(stream)
            if header[0] == 0x14:
                continue
            if header[0] != 0x17:
                raise RuntimeError("proxy sent a non-application record")
            received += len(data)
            if received > 4 * 1024 * 1024:
                raise RuntimeError("probe response exceeds limit")
            plaintext += decryptor.update(data)
            while len(plaintext) >= 4:
                size = int.from_bytes(plaintext[:4], "little")
                if size & 0x80000000:
                    del plaintext[:4]  # quick ack, if emitted
                    continue
                if size == 0 or size > 2 * 1024 * 1024:
                    raise RuntimeError("invalid MTProto intermediate frame length")
                if len(plaintext) < size + 4:
                    break
                payload = bytes(plaintext[4 : 4 + (size & ~3)])
                del plaintext[: size + 4]
                if len(payload) >= 40 and payload[:8] == bytes(8):
                    constructor = int.from_bytes(payload[20:24], "little")
                    if constructor == 0x05162463 and payload[24:40] == request_nonce:
                        if on_reply is not None:
                            on_reply(stream)
                        return {"dc": dc, "pq": pq, "response_bytes": len(payload),
                                "elapsed_ms": round((time.monotonic() - started) * 1000)}
        raise RuntimeError("no matching res_pq before probe deadline")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("host")
    parser.add_argument("port", type=int)
    parser.add_argument("domain")
    parser.add_argument("--dc", type=int, default=2)
    parser.add_argument("--pq", action="store_true")
    args = parser.parse_args()
    key = bytes.fromhex(os.environ["MTDD_PROXY_SECRET"])
    print(json.dumps(probe(args.host, args.port, args.domain, key, args.dc, args.pq)))
