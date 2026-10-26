#!/usr/bin/env python3
# Independent regeneration of the ME RPC_HANDSHAKE known-answer vectors in
# tests/unit/protocol_cases_middle_end.cpp.
#
# Uses the test's already independently derived keys (validated against the KDF
# golden vector) and zlib.crc32 + cryptography AES-256-CBC. The field layout
# uses reversed IPv4 octets, little-endian port and little-endian CRC.
#
# Changed by the CRC32C negotiation work: the request now advertises
# RPC_HANDSHAKE flag USE_CRC32C (0x800), so its ciphertext changed. The answer is
# generated twice (flags 0 -> IEEE CRC-32 stream, flags 0x800 -> CRC-32C stream)
# so a golden test pins each negotiation outcome.
import zlib

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

WRITE_KEY = bytes.fromhex("3c570bb28a07c6d2e625251af0fdb92a394409e252cc1ca1f434e3e20eb7958c")
WRITE_IV = bytes.fromhex("0a3897c0664be4972963954ba2284efe")
READ_KEY = bytes.fromhex("1a0873e6e697bb4dee5d998b9aeb5852950c9238687cbfde5dd34a03f9590e2d")
READ_IV = bytes.fromhex("dc756fa62f214e6b097c1a60223621d3")


def le32(value):
    return (value & 0xFFFFFFFF).to_bytes(4, "little")


def plain_frame(seq, payload):
    assert len(payload) % 4 == 0
    frame = le32(len(payload) + 12) + le32(seq) + payload
    frame += le32(zlib.crc32(frame) & 0xFFFFFFFF)
    while len(frame) % 16:
        frame += le32(4)
    return frame


def encrypt(key, iv, data):
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return enc.update(data) + enc.finalize()


def handshake(sender, peer, flags):
    payload = le32(0x7682EEF5) + le32(flags) + sender + peer
    return encrypt(WRITE_KEY, WRITE_IV, plain_frame(0xFFFFFFFF, payload))


def handshake_answer(server_pid, echo_sender, flags):
    payload = le32(0x7682EEF5) + le32(flags) + server_pid + echo_sender
    return encrypt(READ_KEY, READ_IV, plain_frame(0xFFFFFFFF, payload))


sender = bytes([9, 113, 0, 203, 0x31, 0xD4, 0x3A, 0x1F, 0x00, 0x10, 0x5E, 0x5F])
peer = bytes([50, 175, 154, 149, 0xB8, 0x22, 0, 0, 0, 0, 0, 0])
server = bytes([50, 175, 154, 149, 0xB8, 0x22, 0x34, 0x12, 0x00, 0x00, 0x00, 0x60])

print("request flags=0x800 :", handshake(sender, peer, 0x800).hex())
print("answer  flags=0     :", handshake_answer(server, sender, 0).hex())
print("answer  flags=0x800 :", handshake_answer(server, sender, 0x800).hex())
