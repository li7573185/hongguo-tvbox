"""影视仓红果插件：网络和播放处理都在电视本机运行。"""

import base64
import bisect
import gzip
import hashlib
import io
import json
import os
import re
import secrets
import struct
import threading
import time
import uuid
import unicodedata
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlencode, urlparse

import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
"""播放请求签名的纯 Python 实现；打包时内嵌，电视无需额外运行环境。"""
import base64
import hashlib
import re
import secrets
import struct
from urllib.parse import urlencode

"""公开协议置换表，非用户密钥；来源固定提交 7d5e4b8124c5。"""

SG_SBOX = bytes.fromhex(
    "fa7d086b9c59b34b045f39d0384a91990067a6209ff54d827326eedf18668333800319fbd9feaeaaa9b052c60bf379254e78b436ac5d1a279e88dbbd3c63ec49"
    "15c1301fdcb856d46ccdca0943c835a3ef1ef496d2fc0e727b9484d1ea455a62023fd31281342bdd7ee628f2a54613013b21f66137292a0ded8cafbf9d5cbb24"
    "760f75e45389e1988db19a65704f544c58ab6e6f8b23c407110cbacfa0a48ed8053d14b2da74c3d7e7bed67fde48163e8590a155b7774222c986502e17f96431"
    "2c9bf16d1c4468e3e9a89397cb3257ebe5716aadc0ccc7c5fd601da22d47a7e251695e7ace0a41b6958ff7b987e03a06108ab5f85bd5f0bc92ff7c2fc2e81b40"
    "ec1bdabdba98910cb22b83413467fb0ad876b546055961237590872ae350154cacb179ebaee595470468f0863d518b0fca8ee4b94ef21282bc0ed5f7ef2825cf"
    "5b5de96a5502e133be93e7f5ad9d3e3924a8e2fa1757d07a0d0830d6b8a38dfd079ac41e6e226497d21db0bf45663f6cdddb2780a711dca6c552f8c0b6c85c00"
    "73607ba01913aac935484bd3a4cd9f99f3104440547e29f4061fa2aba12f3cf6af856236217f5edf201ab3b4e6ff72848f6526945a77ea4378c74acc2c146bc6"
    "e87453fcd41cce317003188c96383289f13a5fd7f9a969b7633758c23bc371cb9e92018a0b4d889bbb4f6d6fe0fea549de561609ed9cc12dee817dd97cd12e42"
    "5b4dc1a65dea44fd454e1ba13fd189e17d2faadbabad59cbb1ce9a28c9e0f670394ad7ff30f5ddbc573b118db2ee00b6e61a5a7cf9dec4cd2e80bbb94ca59f84"
    "08c66f426cf027e78b3a9c51fb6721754131a7ca20432ab7bfd97af2b5f88c2c23834f8f60a004133714e301c563665c7481df58bd68903dd2b334f419933229"
    "d649ae0d4bd8079eac1e2d0b40b872ba761071a8e4561d48fee5c24791da87269d1f886bc098be25099733a385165e7fdc6e54e9f7a9c8e8c377d0822bec0262"
    "8a920e3eb00f05f3f19678388636183c24cf0ab453cc6165a4c794d5157e6def792235126a8e5206557b46645095e20cedd31703a29b99eb1cfcafd47369fa5f"
    "f72c1ebfc8e1f39f76807148aa94ad64fb89c660c332b34dd2e044dd5fa8b1c7682334c96d127fb7eb15bea9d17893a00c92a4d747e38ac270ab26419a79a7d8"
    "14858fc06f56d08c11b92e3ce29dcf0ede035d463ecd38430f335ad91a656c223bfc30a688ea37a2b48d8e519cd640eef9f884f4ae97e9ca0a456757042f835c"
    "d5c5c482b6a391981f4aac96816ecb1b0908af1895497d54edfa16313adab866f5a5f1fe10010674cc63df7c2825f6ceb24f8be5bc8769bb8621070036e70b50"
    "599b1ce862581961f2bd275eba1de699423d0d2ab5dc5b29f02d4c537b6a734e3f75ff4ba1351755723920d3b0fdef02ec777ee42bdb90c1059e7ad4526b2413"
)
SG_ORDERS = bytes.fromhex(
    "0f0704000908030a060b050d0e010c020f05080c0009020103070e060b0a0d04060500070c000a04080f010b0d09020e060b02050403080101070a000d0c090e"
    "0d070e0f0b0208030c0509010004060a0d0902060f0b0a040807000c0503010e0c090f07060f030e020d0405010b0a000c050a090e0802040407030f01060b00"
    "0b0f0408020a0700090d06010e03050c0b060a0508020c03070f0e090d0001040906080f050800040a0b030d01020c0e090d0c0604070a03030f00080105020e"
    "01000d0f090a0b0e0402080703060c0501080a0c0f0905060b000304020e070d04080f000c0f0e0d0a01060207090503040205080d0b0a0606000e0f070c0903"
    "0a08040f000b01060d0c0709030e05020a070b050f00020e0108030d0c0609040d070f08050f06040b0a0e0c090002030d0c020704010b0e0e08060f09050003"
)
SG_MD5C = (
    0xa7aefe20, 0x7149f1d6, 0x47e4ca07, 0xe9b58f67, 0x93b924de, 0xc614d0f5, 0x38afe0ef, 0xb2bbad73,
    0xe24444c3, 0x9d3aec9b, 0xdf7b37e4, 0xd8b16d40, 0xf8ac31b8, 0x76b9a90b, 0x31d833ee, 0x953fce64,
    0x353595a4, 0x4609c13b, 0x36925008, 0x8c6d0925, 0x5df5c177, 0x1cfbf52b, 0x8a4fa7f0, 0x114ca35e,
    0x8193f984, 0x7a7a8733, 0x316ab4d5, 0x3c20cfc9, 0xa6d84453, 0x3a18500c, 0x798ec47a, 0x97a76b28,
    0x66c4ff96, 0x51716443, 0x0dd2fc3b, 0xb5696da7, 0xbbeb3ac5, 0x5c53d204, 0xd32608ce, 0x7279b9ec,
    0xf4188ecf, 0xf7d793db, 0x332cc491, 0xab76ae15, 0x9bebe727, 0x18a01384, 0x5be9f8a7, 0x5f90a754,
    0x39b663c0, 0x36673c83, 0x7c92f514, 0x9d7d94d7, 0xe2e8d9aa, 0x5f7e9ea9, 0x7abd4551, 0x569e05da,
    0x40a25632, 0x3df5a9a5, 0xbab37d80, 0x454286dc, 0x3f5d4e78, 0x03d7b75d, 0xb1fe4af7, 0xa5ab26a3,
)



def sg_rot(value, count, width=32):
    mask = (1 << width) - 1
    value &= mask
    count %= width
    return ((value << count) | (value >> ((width - count) % width))) & mask


def sg_le(value):
    return struct.pack("<I", value & 0xffffffff)


def sg_sm3(data):
    # 部分电视的 OpenSSL 未包含 SM3，使用标准算法确保 Python 3.8 可运行。
    length = len(data) * 8
    padded = data + b"\x80"
    padded += b"\0" * ((56 - len(padded)) % 64) + struct.pack(">Q", length)
    state = [0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600, 0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e]
    for offset in range(0, len(padded), 64):
        words = list(struct.unpack_from(">16I", padded, offset))
        for index in range(16, 68):
            value = words[index - 16] ^ words[index - 9] ^ sg_rot(words[index - 3], 15)
            words.append(value ^ sg_rot(value, 15) ^ sg_rot(value, 23) ^ sg_rot(words[index - 13], 7) ^ words[index - 6])
        a, b, c, d, e, f, g, h = state
        for index in range(64):
            constant = 0x79cc4519 if index < 16 else 0x7a879d8a
            first = a ^ b ^ c if index < 16 else (a & b) | (a & c) | (b & c)
            second = e ^ f ^ g if index < 16 else (e & f) | (~e & g)
            rotate = sg_rot(sg_rot(a, 12) + e + sg_rot(constant, index), 7)
            next_a = (first + d + (rotate ^ sg_rot(a, 12)) + (words[index] ^ words[index + 4])) & 0xffffffff
            next_e = (second + h + rotate + words[index]) & 0xffffffff
            a, b, c, d = next_a, a, sg_rot(b, 9), c
            e, f, g, h = next_e ^ sg_rot(next_e, 9) ^ sg_rot(next_e, 17), e, sg_rot(f, 19), g
        state = [left ^ right for left, right in zip(state, (a, b, c, d, e, f, g, h))]
    return struct.pack(">8I", *state)


def sg_branch(query, body, stamp):
    digest = sg_sm3(query.encode())
    body_digest = hashlib.md5(body).digest() if body else bytes(16)
    value = 0x20230928
    for part in (digest, body_digest, sg_le(stamp)):
        for index, byte in enumerate(part):
            value = ((value >> 4) ^ value ^ (value << 6) ^ byte) if index % 2 == 0 else ~((value >> 7) ^ value ^ (byte | (value << 12)))
            value &= 0xffffffff
    return value, digest, body_digest


def sg_f13(iv, stamp, digest, body_digest):
    group = ((iv & 15) - 2) // 3
    count = ((0x8980f29b, 0xeb549c7f, 0xb08726db, 0xd40cb5e6, 0xe8f559e4)[group] + stamp) & 0xffffffff
    shift = (count + 5) & 7
    message = digest + body_digest + sg_le(stamp) + bytes(((byte * 257) >> shift) & 255 for byte in bytes.fromhex("8496779dd4150bf8")) + bytes([160, 1, 0, 0])
    start = [sg_rot(value, -(count & 31)) for value in (0x79e0f2fb, 0xc8b52570, 0xebc2f8cd, 0x7c104d93)]
    end = [sg_rot(value, -((count + 6) & 31)) for value in (0x19be4866, 0xe85986b4, 0xe19b326e, 0x71d1d7d4)]
    shifts = ((7, 12, 17, 22), (5, 9, 14, 20), (4, 11, 16, 23), (6, 10, 15, 21))
    a, b, c, d = start
    for index in range(64):
        part = index // 16
        value = ((b & c) | (~b & d), (b & d) | (c & ~d), b ^ c ^ d, c ^ (b | ~d))[part]
        word = struct.unpack_from("<I", message, SG_ORDERS[group * 64 + index] * 4)[0]
        next_b = (b + sg_rot(a + value + word + sg_rot(SG_MD5C[index], -((count + 1) & 31)), shifts[part][index % 4])) & 0xffffffff
        a, b, c, d = d, next_b, b, c
    result = b"".join(sg_le((left + value) ^ right) for left, value, right in zip(start, (a, b, c, d), end))
    check = 0x20220420
    for index, byte in enumerate(result[:12]):
        check = ((check >> 3) ^ check ^ byte ^ (check << 7)) if index % 2 == 0 else ((check >> 5) ^ check ^ ~(byte | (check << 11)))
        check &= 0xffffffff
    return result + sg_le((check | 4) ^ 0x1000000)


class SignProto:
    """只编码签名用到的 protobuf 字段，避免在电视引入大型依赖。"""
    def __init__(self):
        self.data = bytearray()

    def varint(self, value):
        while value > 127:
            self.data.append((value & 127) | 128)
            value >>= 7
        self.data.append(value)

    def integer(self, field, value):
        self.varint(field << 3)
        self.varint(-value * 2 - 1 if value < 0 else value * 2)

    def blob(self, field, value):
        if isinstance(value, str):
            value = value.encode()
        self.varint((field << 3) | 2)
        self.varint(len(value))
        self.data.extend(value)

    def floating(self, field, value):
        self.varint((field << 3) | 5)
        self.data.extend(struct.pack("<f", value))


def sg_proto(query, stamp, nonce, device_id, digest, body_digest, f13, version):
    device, report, environment, count, output = [SignProto() for unused in range(5)]
    for field, value in ((1, 1), (2, 2), (7, -888888), (8, -888888), (9, 3), (10, -888888), (14, 4), (23, 41), (24, 36), (29, -1), (38, 31)):
        device.integer(field, value)
    for field, value in ((3, "8662"), (4, device_id), (5, "Ai6svO3PyrwDOUSmO6ZcResxu"), (6, "!noperm!"), (11, "!notset!"), (12, "Asia/Shanghai,8"), (13, "zh_CN"), (22, "16")):
        device.blob(field, value)
    for field, value in enumerate((255.24993896484375, 35.58599090576172, 3.467449188232422, 3.467449188232422, 255.1754913330078, 42.17544174194336), 16):
        device.floating(field, value)
    for field in range(25, 29):
        device.integer(field, 1728388016635 + (2 if field == 28 else 0))
    for field, value in enumerate(("25053RT47C", "Redmi", "25053RT47C", "25053RT47C", "Redmi", "Redmi", "Redmi"), 30):
        device.blob(field, value)
    # 签名需保持参考协议的字段序列；统一按字段编号重新排列。
    device.data = bytearray(sg_order_proto(device.data))
    for field, value in ((1, stamp), (2, -2), (4, 200)):
        report.integer(field, value)
    for field, value in ((1, 110), (2, 146331399), (3, 146331396), (5, 7)):
        environment.integer(field, value)
    environment.blob(6, "v04.06.04.03-bugfix")
    environment.integer(7, 11001)
    environment.blob(12, device.data)
    environment.blob(13, report.data)
    environment.blob(14, version)
    for field, value in ((1, 111), (2, 10), (3, 694367), (5, 586952199)):
        count.integer(field, value)
    # 下列是公开协议常量，不是账号令牌或用户密钥。
    output.blob(1, bytes.fromhex("f7e85ffad7d7dc3bd62ac87057cf6118"))
    output.integer(2, 3)
    output.integer(3, nonce)
    for field, value in ((4, "8662"), (5, device_id), (6, "1588093228"), (7, version), (8, "v04.06.04-ml-android")):
        output.blob(field, value)
    output.integer(9, 67503104)
    output.blob(10, bytes.fromhex("4001000000000000"))
    output.integer(12, stamp)
    for field, value in ((13, f13), (14, digest[:6]), (15, count.data), (16, "AXYQOS6n2m60x1fVZHIrH3iol")):
        output.blob(field, value)
    output.integer(17, stamp)
    output.blob(19, sg_sm3(query.encode() + body_digest + b"none"))
    output.blob(20, "none")
    output.integer(21, 312)
    output.blob(23, environment.data)
    output.blob(24, '{"cmr":16777216,"cmr2":16777216,"un_h":1879194040,"vpn":0,"kd":0,"fkd":3672518972,"pd":-1872573247,"dyn":"","do":0,"tk":true}')
    return bytes(output.data)


def sg_order_proto(data):
    # 仅处理内部生成且长度已知的数据，不解析来自网络的 protobuf。
    position, fields = 0, []
    def read_varint():
        nonlocal position
        value, shift = 0, 0
        while True:
            byte = data[position]
            position += 1
            value |= (byte & 127) << shift
            if byte < 128:
                return value
            shift += 7
    while position < len(data):
        start = position
        tag = read_varint()
        if tag & 7 == 0:
            read_varint()
        elif tag & 7 == 2:
            size = read_varint()
            position += size
        else:
            position += 4
        fields.append((tag >> 3, bytes(data[start:position])))
    return b"".join(value for field, value in sorted(fields))


def sg_helios(stamp, nonce):
    mask = (1 << 64) - 1
    words = struct.unpack("<4Q", hashlib.md5(sg_le(nonce) + b"8662").hexdigest().encode())
    key, pending = words[0], list(words[1:])
    rounds = [key]
    for index in range(33):
        value = ((sg_rot(pending.pop(0), -8, 64) + key) & mask) ^ index
        pending.append(value)
        key = value ^ sg_rot(key, 3, 64)
        rounds.append(key)
    plain = (str(stamp) + "-1588093228-8662").encode()
    padding = 16 - len(plain) % 16
    plain += bytes([padding]) * padding
    output = bytearray(sg_le(nonce))
    for offset in range(0, len(plain), 16):
        a, b = struct.unpack_from("<QQ", plain, offset)
        for key in rounds:
            b = key ^ ((a + sg_rot(b, -8, 64)) & mask)
            a = b ^ sg_rot(a, 3, 64)
        output.extend(struct.pack("<QQ", a, b))
    return base64.b64encode(output).decode()


def sg_xor(data, key):
    output = bytearray(len(data))
    for index, byte in enumerate(data):
        offset = (index * 4) & 28
        a, b = key[offset:offset + 2]
        value = (~(sg_rot(byte, 4, 8) + a) ^ b) & 255
        value = (sg_rot(value, 3, 8) + b) & 255
        output[-1 - index] = ~(value ^ a) & 255
    flag, old = output[-1] ^ output[-2], output[0]
    output[0] = (output[0] + ~flag) & 255
    output[1] = (output[1] + (output[0] ^ output[-1] ^ 254)) & 255
    output[2] = (output[2] + ((flag - old) ^ sg_rot(output[1], 3, 8) ^ 2)) & 255
    for index in range(len(output) - 4):
        output[index + 3] = (output[index + 3] + ~(sg_rot(output[index + 2], 3, 8) ^ output[index + 1] ^ (index + 3))) & 255
    output[-1] ^= output[-2]
    output[0] = ((output[0] ^ output[1]) + sum(output[1:])) & 255
    return bytes(output)


def sg_aes(data, stamp):
    """公开签名封装的置换运算，不用于保存或加密用户数据。"""
    if len(data) < 248:
        raise ValueError("签名封装长度不足")
    branch = stamp & 3
    box = SG_SBOX[branch * 256:(branch + 1) * 256]
    columns = ((1, 0, 2, 3), (2, 0, 3, 1), (0, 1, 3, 2), (1, 0, 2, 3))[branch]
    order = ((0, 9, 14, 11, 4, 13, 2, 7, 8, 1, 6, 15, 12, 5, 10, 3), (0, 9, 14, 15, 4, 13, 2, 7, 8, 1, 6, 3, 12, 5, 10, 11), (0, 9, 14, 7, 4, 13, 2, 11, 8, 1, 6, 3, 12, 5, 10, 15), (0, 9, 14, 11, 4, 13, 2, 7, 8, 1, 6, 15, 12, 5, 10, 3))[branch]
    initial = (0xca025ddc, 0x823dc546, 0xc9420583, 0xc298225f)[branch]
    protocol_key = bytes.fromhex("f1593376766ea98d34f31b057a9d5be4")
    schedule = bytearray(48)
    for index, byte in enumerate(protocol_key):
        schedule[index] = byte ^ ((initial >> ((index % 4) * 8)) & 255)
    rotation = 8
    for index in range(4, 12):
        previous = schedule[index * 4 - 4:index * 4]
        if index % 4 == 0:
            previous = bytes((((initial >> (rotation & 24)) & 255) ^ box[previous[1]], box[previous[2]], box[previous[3]], box[previous[0]]))
        rotation += 2
        for column in range(4):
            schedule[index * 4 + column] = previous[column] ^ schedule[index * 4 + column - 16]

    def block(source):
        result = bytearray(source)
        def add(offset):
            for index in range(16):
                result[index] ^= schedule[offset + (index // 4) * 4 + columns[index % 4]]
        add(0)
        for round_number in (1, 2):
            previous = bytes(result)
            for index in range(16):
                position = order[index]
                result[index] = box[previous[columns[position // 4] * 4 + position % 4]]
            if round_number == 1:
                previous = bytes(result)
                for index in range(16):
                    result[index] = previous[(index // 4) * 4 + columns[index % 4]]
                for column in range(4):
                    a, b, c, d = [result[column + index * 4] for index in range(4)]
                    total = a ^ b ^ c ^ d
                    for index, value in enumerate((a ^ b, b ^ c, c ^ d, d ^ a)):
                        doubled = ((value << 1) ^ (0x1b if value & 128 else 0)) & 255
                        result[column + index * 4] ^= total ^ doubled
            add(round_number * 16)
        return bytes(value ^ schedule[16 + index] for index, value in enumerate(result))

    plain = bytearray(32)
    for index in range(31):
        d = data[index * 8:index * 8 + 8]
        plain[index] = ((d[0] >> 4) & 2) | (d[1] & 64) | ((d[2] >> 2) & 1) | ((d[3] << 3) & 128) | ((d[4] >> 1) & 4) | ((d[5] << 3) & 16) | ((d[6] << 5) & 32) | ((d[7] >> 4) & 8)
    plain[31] = 1
    previous = bytes.fromhex("1fe109a4125283f418de9e051a969e12")
    encrypted = bytearray()
    for offset in (0, 16):
        previous = block(bytes(a ^ b for a, b in zip(plain[offset:offset + 16], previous)))
        encrypted.extend(previous)
    output = bytearray(bytes([encrypted[31]]) + data)
    for index in range(31):
        value, offset = encrypted[index], 1 + index * 8
        for part, mask, bits in ((0, 32, value << 4), (1, 64, value), (2, 4, value << 2), (3, 16, value >> 3), (4, 8, value << 1), (5, 2, value >> 3), (6, 1, value >> 5), (7, 128, value << 4)):
            output[offset + part] = (output[offset + part] & ~mask) | (bits & mask)
    return bytes(output)


def sg_medusa(query, stamp, nonce, hash_random, envelope_random, device_id, iv, digest, body_digest, version):
    f13 = sg_f13(iv, stamp, digest, body_digest)
    payload = sg_proto(query, stamp, nonce, device_id, digest, body_digest, f13, version)
    # 公开协议派生常量；实际匿名身份与随机数在电视上临时生成。
    protocol_key = bytes.fromhex("8ebdfa3806ecc5cee79423e6029ed82540bc2218bb7eaef71cb691f7aa8aa2f5")
    key = sg_sm3(protocol_key + sg_le(hash_random) + protocol_key)
    high = (hash_random >> 16) & 255
    seed = sg_le(~(((high << 11) | (hash_random >> 24)) ^ (high >> 5) ^ high))
    payload = (bytes.fromhex("4001000000000000") + sg_xor(payload, key))[::-1]
    payload = bytes(byte ^ seed[(~index) & 3] for index, byte in enumerate(payload))
    check = 0x18000001 | ((digest[0] & 63) << 14) | ((f13[0] & 63) << 8)
    body = b"\x35" + sg_le(envelope_random) + sg_le(check) + payload + sg_le(hash_random)[2:]
    encrypted = sg_aes(body, stamp)
    header = bytes.fromhex("03000000f7e85ffad7d7dc3bd62ac87057cf6118")
    header = b"".join(sg_le(value ^ stamp) for value in struct.unpack("<5I", header))
    return header + sg_le(hash_random)[:2] + b"\0\x01" + encrypted


def sign_playback(params, body, stamp, device_id, gorgon_function):
    """签名必须覆盖最终发送的查询和正文；每次重试重新生成。"""
    if not isinstance(params, dict) or params.get("version_name") != "7.1.3.32" or not isinstance(body, bytes) or len(body) > 65536 or type(stamp) is not int or not 1000 <= stamp < 0xffffffff * 1000 or not re.fullmatch(r"[1-9][0-9]{0,24}", str(device_id)):
        raise ValueError("播放签名参数无效")
    values = dict(params)
    timestamp = stamp // 1000
    values["ts"] = str(timestamp)
    # 仅改变毫秒票据选择参考协议已验证的分支，循环有明确上限。
    for offset in range(256):
        values["_rticket"] = str(stamp + offset)
        query = urlencode(sorted(values.items()))
        iv, digest, body_digest = sg_branch(query, body, timestamp)
        if (iv & 15) % 3 == 2:
            break
    else:
        raise ValueError("无法生成支持的播放签名")
    nonce, hash_random, envelope_random, helios_random = [secrets.randbits(32) for unused in range(4)]
    signature = sg_medusa(query, timestamp, nonce, hash_random, envelope_random, str(device_id), iv, digest, body_digest, values["version_name"])
    headers = {
        "X-Khronos": str(timestamp), "X-SS-Req-Ticket": values["_rticket"],
        "X-Helios": sg_helios(timestamp, helios_random), "X-Medusa": base64.b64encode(signature).decode(),
        "X-Gorgon": gorgon_function(query, body, timestamp, nonce & 65535),
        "X-Argus": base64.b64encode(sg_le(timestamp)).decode(),
        "X-Ladon": base64.b64encode(struct.pack(">I", timestamp)).decode(),
        "Sdk-Version": "2", "X-Xs-From-Web": "0", "X-Tt-Dt": "",
        "X-Tt-Store-Region": "cn", "X-Tt-Store-Region-Src": "did",
    }
    if body:
        headers["X-SS-STUB"] = body_digest.hex().upper()
    return query, headers


WEB = "https://hongguoduanju.com"
API = "https://api5-normal-sinfonlineb.fqnovel.com"
PLAYBACK_ALTERNATE = "https://api5-normal-hl.fqnovel.com"
PLAYBACK_PATH = "/novel/player/multi_video_model/v1/"
WEB_UA = "Mozilla/5.0 (Android TV; HongguoTV)"
APP_UA = "com.phoenix.read/73532 (Linux; U; Android 16; zh_CN; 25053RT47C; Build/BP2A.250605.031.A3; Cronet/TTNetVersion:04657795 2026-01-23 QuicVersion:c67e9834 2025-09-08)"
PLAY_UA = "com.phoenix.read/71532 (Linux; U; Android 9; SM-N9860; Build/PQ3A.190705.10241111;tt-ok/3.12.13.20)"
MAX_JSON = 5 * 1024 * 1024
RANKS = {
    "hot-drama": "热播榜", "hot-comic-drama": "漫剧榜", "recommend": "推荐榜", "must-watch": "必看榜",
    "new-rank": "新剧榜", "hot-search": "热搜榜", "chase-update": "追更榜", "followed": "收藏榜",
    "prestige": "臻果榜", "hot-real-drama": "真人短剧", "hot-ai-drama": "AI 短剧",
}
# 标识取自上游分类选择器，首屏仍核验实际选中项，避免默认榜冒充。
APP_RANKS = {
    "recommend": "ranklist_hot_sc", "must-watch": "ranklist_must_watch",
    "new-rank": "ranklist_new_rank_sc", "hot-search": "ranklist_hot_search_sc",
    "chase-update": "ranklist_chase_update", "followed": "ranklist_followed", "prestige": "ranklist_prestige",
}


def show_notice(message):
    """搜索在工作线程执行，提示交给主线程，失败不影响结果返回。"""
    try:
        from java import cast, dynamic_proxy, jclass
        platform = cast("com.chaquo.python.android.AndroidPlatform", jclass("com.chaquo.python.Python").getPlatform())
        context = platform.getApplication()

        class Notice(dynamic_proxy(jclass("java.lang.Runnable"))):
            def run(self):
                jclass("android.widget.Toast").makeText(context, message, 1).show()

        jclass("android.os.Handler")(jclass("android.os.Looper").getMainLooper()).post(Notice())
    except Exception:
        pass


class EmptyResponse(RuntimeError):
    pass


class MediaReadError(RuntimeError):
    """视频地址未返回可用分段；准备播放时可尝试同格式备用地址。"""


def require_id(value):
    value = str(value)
    if not re.fullmatch(r"[1-9][0-9]{0,24}", value):
        raise ValueError("剧集编号无效")
    return value


def encode_json(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")


def device_key(seed):
    if len(seed) != 32:
        raise ValueError("设备随机参数长度无效")
    # 这是协议公开盐值，不是用户凭证；每次注册的密钥由随机种子派生。
    salt = bytes.fromhex("4dd4c2e6b83162090e52b3c7a6733ba41cb2462b829ab58a196b39db57177524f49baf7f08e8d68d26a72e37c1a95a2f1f05a51892aef2949732b62a38aadd58")
    return hashlib.sha512(hashlib.sha512(seed).digest() + salt).digest()


def encode_device(payload, seed):
    compressed = gzip.compress(payload, compresslevel=9, mtime=0)
    compressed = b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x00" + compressed[10:]
    key = device_key(seed)
    cipher = AES.new(key[:16], AES.MODE_CBC, key[16:32])
    return b"tc\x05\x10\x00\x00" + seed + cipher.encrypt(pad(hashlib.sha512(compressed).digest() + compressed, 16))


def decode_device(data):
    if len(data) < 118 or data[:6] != b"tc\x05\x10\x00\x00" or (len(data) - 38) % 16:
        raise ValueError("设备注册响应结构无效")
    key = device_key(data[6:38])
    plain = unpad(AES.new(key[:16], AES.MODE_CBC, key[16:32]).decrypt(data[38:]), 16)
    if len(plain) < 64 or not secrets.compare_digest(plain[:64], hashlib.sha512(plain[64:]).digest()):
        raise ValueError("设备注册响应校验失败")
    with gzip.GzipFile(fileobj=io.BytesIO(plain[64:])) as stream:
        result = stream.read(MAX_JSON + 1)
    if len(result) > MAX_JSON:
        raise ValueError("设备注册响应过大")
    return result


def gorgon(query, body, stamp, nonce):
    data = bytearray(hashlib.md5(query.encode()).digest()[:4] + hashlib.md5(body).digest()[:4] + b"\x00" * 4 + struct.pack("<I", 67503104) + struct.pack(">I", stamp))
    key = [0x4a, 0x40, 0x16, nonce >> 8, 0x47, 0x6c, 1, nonce & 255]
    state = list(range(256))
    index = 0
    for offset in range(256):
        index = (index + state[offset] + key[offset % 8]) & 255
        state[offset] = state[index]
    index = 0
    for offset in range(20):
        index += state[offset + 1]
        value = state[index & 255]
        state[offset + 1] = value
        data[offset] ^= state[(value * 2) & 255]
    for offset in range(20):
        value = ((data[offset] << 4) | (data[offset] >> 4)) & 255
        value ^= data[offset + 1] if offset < 19 else data[0]
        data[offset] = (~(int(format(value, "08b")[::-1], 2) ^ 20)) & 255
    return (bytes([0x84, 4, nonce & 255, nonce >> 8, 0x40, 1]) + data).hex()


def app_query(version="73532"):
    return dict(ac="wifi", aid="8662", app_name="novelread", channel="update_64", device_brand="Redmi", device_platform="android", device_type="25053RT47C", dpi="520", language="zh", manifest_version_code=version, os="android", os_api="36", os_version="16", resolution="1280*2772", ssmix="a", update_version_code=version, version_code=version, version_name="7.3.5.32" if version == "73532" else "7.1.3.32")


class Client:
    def __init__(self):
        self.session = requests.Session()
        self.session.trust_env = False
        self.device = None
        self.device_lock = threading.Lock()
        self.last_identity_refresh = float("-inf")

    def read(self, url, method="GET", data=None, headers=None, isolated=False):
        # 固定上游域名，避免网页提供的地址让插件访问用户内网。
        parsed = urlparse(url)
        allowed = parsed.hostname in {"hongguoduanju.com", "api5-normal-sinfonlineb.fqnovel.com", "log.snssdk.com"}
        alternate = parsed.hostname == "api5-normal-hl.fqnovel.com" and parsed.path == PLAYBACK_PATH and method == "POST" and isolated
        if parsed.scheme != "https" or parsed.username or parsed.password or parsed.port not in (None, 443) or not (allowed or alternate):
            raise ValueError("接口地址不在允许范围内")
        head = {"User-Agent": WEB_UA}
        if not isolated:
            head["Referer"] = WEB + "/"
        head.update(headers or {})
        session = requests.Session() if isolated else self.session
        try:
            if isolated:
                # 播放和匿名注册均不依赖登录 Cookie，隔离请求避免沿用旧身份。
                session.trust_env = False
                head["Connection"] = "close"
            with session.request(method, url, data=data, headers=head, timeout=(8, 20), allow_redirects=False, stream=True) as response:
                if response.status_code != 200:
                    raise RuntimeError("红果接口返回 HTTP %d" % response.status_code)
                chunks, size = [], 0
                for chunk in response.iter_content(65536):
                    size += len(chunk)
                    if size > MAX_JSON:
                        raise ValueError("接口响应超过大小限制")
                    chunks.append(chunk)
        finally:
            if isolated:
                session.close()
        result = b"".join(chunks)
        if not result.strip():
            raise EmptyResponse("红果接口返回空内容，请稍后重试")
        return result

    def register(self):
        with self.device_lock:
            if self.device:
                return self.device
            stamp = int(time.time() * 1000)
            cdid, client_id, open_id = str(uuid.uuid4()), str(uuid.uuid4()), secrets.token_hex(8)
            header = dict(aid=8662, access="wifi", app_version="7.3.5.32", app_version_minor="", channel="update_64", device_brand="Redmi", device_manufacturer="Redmi", device_model="25053RT47C", device_category="phone", device_platform="android", os="Android", os_api=36, os_version="16", density_dpi=520, display_density="xxxhdpi", resolution="2772x1280", language="zh", timezone=8, tz_name="Asia/Shanghai", tz_offset=28800, region="CN", package="com.phoenix.read", version_code=73532, manifest_version_code=73532, update_version_code=73532, apk_first_install_time=stamp, cdid=cdid, clientudid=client_id, openudid=open_id, cpu_abi="arm64-v8a", display_name="红果短剧", sdk_version="3.7.2", sdk_target_version=29, sdk_flavor="china", guest_mode=0, is_system_app=0, not_request_sender=0, oaid_may_support=True, ipv6_list=[], sim_serial_number=[], custom=dict(is_android_fold=0, filter_warn=0, web_ua="", is_android_pad=0, client_ipv4=""))
            body = encode_device(encode_json(dict(magic_tag="ss_app_log", header=header, _gen_time=stamp)), secrets.token_bytes(32))
            query = app_query()
            query.update(cdid=cdid, openudid=open_id, tt_data="a", ts=str(stamp // 1000), _rticket=str(stamp), package="com.phoenix.read")
            encoded = urlencode(sorted(query.items()))
            headers = {"User-Agent": APP_UA, "Content-Type": "application/octet-stream;tt-data=a", "Accept": "application/json; charset=utf-8,application/x-protobuf", "Content-Encoding": "gzip", "X-Tt-Request-Tag": "t=0;n=1", "Log-Encode-Type": "gzip", "Lc": "102", "Sdk-Version": "2", "Passport-Sdk-Version": "60755", "Passport-Sdk-Settings": "device_transfer_s_0,device_transfer_ab_1", "X-SS-DP": "8662", "X-Vc-Bdturing-Sdk-Version": "4.0.3.cn", "X-Tt-Store-Region": "cn", "X-Tt-Store-Region-Src": "did", "X-Khronos": str(stamp // 1000), "X-Argus": base64.b64encode(struct.pack("<I", stamp // 1000)).decode(), "X-SS-Req-Ticket": str(stamp), "X-SS-STUB": hashlib.md5(body).hexdigest(), "X-Gorgon": gorgon(encoded, body, stamp // 1000, secrets.randbelow(65536))}
            # 注册若携带上次的 install_id Cookie，服务端可能仍返回旧身份，
            # 导致空响应后的恢复失效。使用隔离连接，也不污染榜单会话。
            raw = self.read("https://log.snssdk.com/service/2/device_register/?" + encoded, "POST", body, headers, isolated=True)
            result = json.loads(decode_device(raw) if raw.startswith(b"tc\x05") else raw)
            self.device = {"cdid": cdid, "device_id": require_id(result.get("device_id_str") or result.get("device_id")), "iid": require_id(result.get("install_id_str") or result.get("install_id"))}
            return self.device

    def options(self, video_id):
        video_id = require_id(video_id)
        query = app_query("71332")
        query.update(self.register())
        query.update(_rticket=str(int(time.time() * 1000)), dragon_device_type="phone", host_abi="arm64-v8a", is_android_pad_screen="0", need_personal_recommend="1", player_so_load="1", pv_player="71332", compliance_status="0")
        body = {"biz_param": {"detail_page_version": 0, "device_level": 3, "disable_digg_stat": False, "need_all_video_definition": True, "need_mp4_align": False, "use_os_player": False, "use_server_dns": False, "video_platform": 1024}, "mixed_video_id_map": {"1004": [video_id]}}
        encoded_body = encode_json(body)
        for attempt in range(6):
            stamp = int(time.time() * 1000)
            query["_rticket"] = str(stamp)
            # 每个身份最多三次：签名主接口、签名备用、原请求兼容。
            # 只在 HTTP 200 空响应时继续；拒绝、超时和结构错误直接报告。
            policy = attempt % 3
            endpoint = PLAYBACK_ALTERNATE if policy == 1 else API
            headers = {"User-Agent": PLAY_UA, "Content-Type": "application/json; charset=UTF-8", "Accept": "application/json; charset=utf-8,application/x-protobuf"}
            encoded_query = urlencode(sorted(query.items()))
            if policy < 2:
                encoded_query, signature = sign_playback(query, encoded_body, stamp, query.get("device_id"), gorgon)
                headers.update(signature)
                headers["User-Agent"] = APP_UA.replace("/73532 ", "/71332 ", 1)
            try:
                raw = self.read(endpoint + PLAYBACK_PATH + "?" + encoded_query, "POST", encoded_body, headers, isolated=True)
                break
            except EmptyResponse:
                if attempt == 5:
                    raise
                if attempt == 2:
                    # 实测有匿名身份持续返回空内容；只恢复一次，并限制恢复频率。
                    # HTTP 拒绝、权限错误和格式错误不会进入这一分支。
                    with self.device_lock:
                        delay = min(30, max(0, self.last_identity_refresh + 30 - time.monotonic()))
                    if delay:
                        # 快速换剧不应在保护期内直接失败；等待剩余时间后
                        # 再恢复一次。等待时释放锁，让榜单等请求正常使用会话。
                        show_notice("正在恢复播放连接，请等待约 %d 秒" % min(30, int(delay) + 1))
                        time.sleep(delay)
                    with self.device_lock:
                        now = time.monotonic()
                        if now - self.last_identity_refresh >= 30:
                            self.last_identity_refresh = now
                            self.device = None
                        # 若其他调用已恢复过身份，直接复用，避免重复注册。
                    query.update(self.register())
                else:
                    time.sleep(0.4 * (attempt % 3 + 1))
        envelope = json.loads(raw)
        if str(envelope.get("code", "0")) != "0":
            raise RuntimeError("红果播放接口拒绝了请求")
        container = envelope.get("data", {})
        model = container.get(video_id, container).get("video_model")
        if isinstance(model, str):
            model = json.loads(model)
        if not isinstance(model, dict):
            raise ValueError("播放响应缺少视频信息")
        rows = model.get("video_list", [])
        if isinstance(rows, dict):
            rows = list(rows.values())
        result = []
        for row in rows:
            meta = row.get("video_meta") or {}
            codec = str(row.get("codec_type") or meta.get("codec_type") or "").lower()
            if codec == "bytevc2":
                continue
            urls = media_addresses(row)
            if not urls:
                continue
            encryption = row.get("encrypt_info") or {}
            key = decode_content_key(encryption["spade_a"]) if encryption.get("spade_a") else None
            definition = str(row.get("quality_desc") or row.get("definition") or meta.get("definition") or "")
            match = re.search(r"\d{3,4}", definition)
            height = int(match.group()) if match else int(row.get("vheight") or meta.get("vheight") or 0)
            result.append(dict(url=urls[0], backup_urls=urls[1:], key=key, codec=codec, height=height))
        if not result:
            raise ValueError("没有取得本插件支持的视频格式")
        # 优先常见编码的 720P，控制旧电视的带宽和解码负担。
        return sorted(result, key=lambda item: (item["codec"] in ("bytevc1", "hevc"), abs(item["height"] - 720)))

    def rank(self, rank_id, cursor=None):
        if rank_id not in APP_RANKS.values():
            raise ValueError("榜单标识无效")
        cursor = cursor or {"offset": 0, "session": ""}
        query = app_query()
        query.update(self.register())
        query.update(tab_type="26" if cursor["offset"] == 0 else "18", client_req_type="2", client_template="2", background_selected_items="", category_id="0", limit="20", cell_sub_id="0", gender="2", cell_id="7470092475068071998", selected_items="all", sub_selected_items=rank_id, panel_selected_items="", offset=str(cursor["offset"]), session_id=cursor["session"], filter_ids="", unlimited_selector_change_type="0")
        payload = json.loads(self.read(API + "/reading/bookapi/bookmall/cell/change/v?" + urlencode(sorted(query.items())), headers={"User-Agent": APP_UA}))
        if not isinstance(payload, dict) or str(payload.get("code")) != "0":
            raise RuntimeError("榜单接口未确认成功，请稍后重试")
        data = payload.get("data")
        view = data.get("cell_view") if isinstance(data, dict) else None
        if not isinstance(view, dict) or not isinstance(view.get("cell_data"), list):
            raise ValueError("榜单数据暂不可用，请稍后重试")
        # 首屏必须确认服务器确实选中了所请求榜单，防止接口退回默认榜。
        if cursor["offset"] == 0:
            selector = view.get("cell_selector") or {}
            outer = (selector.get("outer_row") or {}).get("items", [])
            selected = [row for row in outer if row.get("selector_item_id") == "all" and row.get("is_selected")]
            children = ((selected[0].get("sub_cell_selector") or {}).get("outer_row") or {}).get("items", []) if selected else []
            if not any(row.get("selector_item_id") == rank_id and row.get("is_selected") for row in children):
                raise ValueError("上游未返回所选榜单，未使用其他榜单替代")
        rows = []
        for cell in view["cell_data"]:
            if not isinstance(cell, dict):
                continue
            videos = cell.get("video_data", [])
            if isinstance(videos, dict):
                videos = [videos]
            if not isinstance(videos, list):
                continue
            for row in videos:
                if isinstance(row, dict) and not row.get("disable_play") and isinstance(row.get("episode_cnt"), int) and row["episode_cnt"] > 0:
                    rows.append(dict(row, episode_right_text="共 %d 集" % row["episode_cnt"]))
        items = cards(rows)
        offset = view.get("next_offset", data.get("next_offset", cursor["offset"]))
        session = view.get("session_id", data.get("session_id", cursor["session"]))
        more = view.get("has_more", data.get("has_more", False))
        if type(offset) is not int or not 0 <= offset <= 100000 or not isinstance(session, str) or len(session) > 12000:
            raise ValueError("榜单分页参数无效")
        # 游标来自服务器，不能以作品数量计算；停滞或空页停止翻页。
        return items, {"offset": offset, "session": session}, bool(more and items and offset > cursor["offset"])


def decode_content_key(value):
    if not isinstance(value, str) or len(value) > 1024:
        raise ValueError("视频密钥参数无效")
    raw = base64.b64decode(value + "=" * (-len(value) % 4), validate=True)
    if len(raw) < 3:
        raise ValueError("视频密钥数据过短")
    tag_size = (raw[0] ^ raw[1] ^ raw[2]) - 48
    size = len(raw) - tag_size - 1
    if tag_size < 1 or size < 33 or size >= len(raw):
        raise ValueError("视频密钥结构无效")
    seed = raw[-tag_size - 2] ^ raw[-tag_size - 1]
    tag = bytes(value ^ seed for value in raw[-tag_size:])
    if tag in (b"app_v2", b"web_v2"):
        raise ValueError("暂不支持该视频密钥格式")
    previous, decoded = [250, 85], bytearray()
    for index in range(size):
        current = raw[index + 1]
        decoded.append(((previous[index % 2] ^ current) - 21 - bin(index).count("1")) & 255)
        previous[index % 2] = current
    if size - int(chr(decoded[0]), 36) - 1 != 32:
        raise ValueError("视频密钥长度无效")
    key = bytes.fromhex(decoded[1:33].decode("ascii"))
    if len(key) != 16:
        raise ValueError("视频密钥长度无效")
    return key


def router_data(raw):
    text = raw.decode("utf-8")
    match = re.search(r"(?:window\.)?_ROUTER_DATA\s*=\s*", text)
    if not match:
        raise ValueError("网页数据结构已变化")
    result, unused = json.JSONDecoder().raw_decode(text[match.end():])
    return result


def find_value(value, name):
    # 迭代查找，避免外部 JSON 的深层嵌套耗尽递归栈。
    pending = [value]
    for unused in range(20000):
        if not pending:
            return None
        current = pending.pop()
        if isinstance(current, dict):
            if name in current:
                return current[name]
            pending.extend(current.values())
        elif isinstance(current, list):
            pending.extend(current)
    raise ValueError("网页数据结构过于复杂")


def card(row):
    row = row.get("video_data", row)
    identifier = require_id(row.get("series_id_str") or row.get("series_id") or row.get("seriesId") or row.get("book_id") or row.get("id"))
    title = str(row.get("series_title") or row.get("series_name") or row.get("title") or "未命名短剧")[:200]
    cover = str(row.get("series_cover") or row.get("cover") or row.get("cover_url") or "")
    if not cover.startswith("https://"):
        cover = ""
    return {"vod_id": identifier, "vod_name": title, "vod_pic": cover, "vod_remarks": str(row.get("episode_right_text") or row.get("heatText") or ""), "vod_content": str(row.get("series_intro") or row.get("video_desc") or row.get("description") or "")[:5000]}


def cards(rows):
    result, seen = [], set()
    for row in rows[:1000]:
        if not isinstance(row, dict):
            continue
        try:
            value = card(row)
        except (ValueError, TypeError):
            continue
        if value["vod_id"] not in seen:
            result.append(value)
            seen.add(value["vod_id"])
    return result


def matching_search_rows(rows, query):
    # 官网在无匹配时可能返回推荐流；只展示名称、简介或分类能匹配的作品。
    tokens = unicodedata.normalize("NFKC", query).casefold().split()
    result = []
    for row in rows:
        data = row.get("video_data") if isinstance(row, dict) else None
        if not isinstance(data, dict):
            continue
        categories = data.get("category_list") or []
        names = [category.get("name", "") for category in categories if isinstance(category, dict)] if isinstance(categories, list) else []
        fields = [data.get("series_title", ""), data.get("series_name", ""), data.get("series_intro", "")] + names
        text = unicodedata.normalize("NFKC", " ".join(value for value in fields if isinstance(value, str))).casefold()
        if all(token in text for token in tokens):
            result.append(row)
    return result


def boxes(data, start=0, end=None):
    end = len(data) if end is None else end
    if not 0 <= start <= end <= len(data):
        raise ValueError("MP4 区间越界")
    result = []
    while start < end:
        if end - start < 8:
            raise ValueError("MP4 结构被截断")
        size, kind = struct.unpack_from(">I4s", data, start)
        header = 8
        if size == 1:
            if end - start < 16:
                raise ValueError("MP4 扩展长度被截断")
            size = struct.unpack_from(">Q", data, start + 8)[0]
            header = 16
        elif size == 0:
            size = end - start
        if size < header or start + size > end:
            raise ValueError("MP4 结构长度无效")
        result.append((start, start + header, start + size, kind))
        if len(result) > 20000:
            raise ValueError("MP4 结构数量过多")
        start += size
    return result


def child(data, parent, kind):
    return next((box for box in boxes(data, parent[1], parent[2]) if box[3] == kind), None)


def table(data, box, prefix, width):
    if box is None or box[1] + prefix > box[2]:
        raise ValueError("MP4 缺少必要的样本表")
    count = struct.unpack_from(">I", data, box[1] + prefix - 4)[0]
    if count > 200000 or box[1] + prefix + count * width != box[2]:
        raise ValueError("MP4 样本表长度或数量无效")
    return count, box[1] + prefix


def media_index(moov, total, media_ranges):
    """建立样本索引并修正元数据，保留全部文件偏移以支持拖动。"""
    data, samples = bytearray(moov), []
    root = boxes(data)
    if len(root) != 1 or root[0][3] != b"moov":
        raise ValueError("视频缺少完整的 moov")
    for track in boxes(data, root[0][1], root[0][2]):
        if track[3] != b"trak":
            continue
        parent = track
        for name in (b"mdia", b"minf", b"stbl"):
            parent = child(data, parent, name)
            if parent is None:
                raise ValueError("视频轨道结构不完整")
        senc = child(data, parent, b"senc")
        if senc is None:
            continue
        stsz = child(data, parent, b"stsz")
        if stsz is None or stsz[1] + 12 > stsz[2]:
            raise ValueError("视频缺少样本长度")
        fixed_size, count = struct.unpack_from(">II", data, stsz[1] + 4)
        if not 0 < count <= 200000:
            raise ValueError("视频样本数量无效")
        if fixed_size:
            if stsz[1] + 12 != stsz[2]:
                raise ValueError("定长样本表结构无效")
            sizes = [fixed_size] * count
        else:
            unused, cursor = table(data, stsz, 12, 4)
            sizes = list(struct.unpack_from(">%dI" % count, data, cursor))
        chunk_box = child(data, parent, b"stco") or child(data, parent, b"co64")
        width = 8 if chunk_box and chunk_box[3] == b"co64" else 4
        chunk_count, cursor = table(data, chunk_box, 8, width)
        offsets = struct.unpack_from(">%d%s" % (chunk_count, "Q" if width == 8 else "I"), data, cursor)
        stsc = child(data, parent, b"stsc")
        entry_count, cursor = table(data, stsc, 8, 12)
        entries = [struct.unpack_from(">III", data, cursor + index * 12) for index in range(entry_count)]
        if not entries or entries[0][0] != 1 or any(entry[1] == 0 or entry[2] != 1 for entry in entries) or any(entries[index][0] >= entries[index + 1][0] for index in range(len(entries) - 1)):
            raise ValueError("视频分块表不受支持")
        if senc[1] + 8 > senc[2]:
            raise ValueError("视频加密信息被截断")
        flags, encrypted_count = struct.unpack_from(">II", data, senc[1])
        iv_size = (senc[2] - senc[1] - 8) // count
        if flags != 0 or encrypted_count != count or iv_size not in (8, 16) or senc[1] + 8 + count * iv_size != senc[2]:
            raise ValueError("暂不支持该视频的加密分块格式")
        position, entry_index = 0, 0
        for chunk, offset in enumerate(offsets, 1):
            while entry_index + 1 < len(entries) and entries[entry_index + 1][0] <= chunk:
                entry_index += 1
            for unused in range(entries[entry_index][1]):
                if position >= count:
                    raise ValueError("视频分块与样本数量不一致")
                size = sizes[position]
                if size <= 0 or offset + size > total or not any(left <= offset and offset + size <= right for left, right in media_ranges):
                    raise ValueError("视频样本超出媒体区间")
                iv_start = senc[1] + 8 + position * iv_size
                samples.append((offset, offset + size, bytes(data[iv_start:iv_start + iv_size])))
                offset += size
                position += 1
        if position != count:
            raise ValueError("视频样本索引不完整")
        stsd = child(data, parent, b"stsd")
        if stsd is None or stsd[1] + 8 > stsd[2]:
            raise ValueError("视频缺少编码信息")
        descriptions = boxes(data, stsd[1] + 8, stsd[2])
        if len(descriptions) != 1:
            raise ValueError("暂不支持多种编码的轨道")
        entry = descriptions[0]
        if entry[3] not in (b"encv", b"enca"):
            raise ValueError("加密样本与编码描述不一致")
        header_size = 78 if entry[3] == b"encv" else 28
        parts = boxes(data, entry[1] + header_size, entry[2])
        protection = next((part for part in parts if part[3] == b"sinf"), None)
        original = child(data, protection, b"frma") if protection else None
        if original is None or original[2] - original[1] != 4:
            raise ValueError("视频缺少原始编码标识")
        codec = bytes(data[original[1]:original[2]])
        if codec not in (b"avc1", b"hvc1", b"hev1", b"mp4a"):
            raise ValueError("暂不支持该视频编码")
        data[entry[0] + 4:entry[0] + 8] = codec
        # 用等长空盒替换保护描述，避免破坏 stco/co64 的绝对偏移。
        for box in (protection, senc, child(data, parent, b"saiz"), child(data, parent, b"saio")):
            if box:
                data[box[0] + 4:box[0] + 8] = b"free"
                data[box[1]:box[2]] = b"\x00" * (box[2] - box[1])
    samples.sort(key=lambda item: item[0])
    if not samples or any(samples[index][1] > samples[index + 1][0] for index in range(len(samples) - 1)):
        raise ValueError("视频样本缺失或相互重叠")
    return bytes(data), samples


def decrypt_part(data, offset, samples, starts, key):
    output = bytearray(data)
    end = offset + len(data)
    index = max(0, bisect.bisect_right(starts, offset) - 1)
    while index < len(samples) and samples[index][0] < end:
        start, stop, iv = samples[index]
        left, right = max(offset, start), min(end, stop)
        if left < right:
            skipped = left - start
            counter = int.from_bytes(iv.ljust(16, b"\x00"), "big") + skipped // 16
            cipher = AES.new(key, AES.MODE_CTR, nonce=b"", initial_value=counter)
            cipher.decrypt(b"\x00" * (skipped % 16))
            output[left - offset:right - offset] = cipher.decrypt(data[left - offset:right - offset])
        index += 1
    return bytes(output)


def media_addresses(row):
    """仅收集同一个视频格式下的地址，最多保留主地址和两个备用。"""
    backups = row.get("backup_url_list")
    candidates = [row.get("main_url"), row.get("backup_url")]
    if isinstance(backups, list):
        candidates.extend(backups[:16])
    result = []
    for value in candidates:
        if not isinstance(value, str) or not value or len(value) > 16384:
            continue
        try:
            url = value if value.startswith("https://") else base64.b64decode(
                value + "=" * (-len(value) % 4), validate=True).decode("utf-8")
            if any(ord(char) <= 32 or ord(char) == 127 for char in url):
                continue
            valid_media_url(url)
        except (ValueError, UnicodeError):
            continue
        if url not in result:
            result.append(url)
        if len(result) == 3:
            break
    return result


def prepare_media(option):
    """开始播放前逐个初始化地址，不在播放途中混用文件或清晰度。"""
    candidates = [option]
    for url in option.get("backup_urls", [])[:2]:
        candidates.append(dict(option, url=url))
    for index, candidate in enumerate(candidates):
        try:
            # 每个候选重新读取索引；不沿用失败地址的长度、样本或解密偏移。
            return RemoteMedia(candidate)
        except (MediaReadError, requests.RequestException):
            if index == len(candidates) - 1:
                raise


def valid_media_url(url):
    parsed = urlparse(url)
    host = parsed.hostname or ""
    allowed = ("qznovelvod.com", "fqnovelvod.com", "douyinvod.com")
    if parsed.scheme != "https" or parsed.username or parsed.password or parsed.port not in (None, 443) or not any(host == domain or host.endswith("." + domain) for domain in allowed):
        raise ValueError("视频地址不在允许的 CDN 范围内")
    return url


class RemoteMedia:
    def __init__(self, option):
        self.url = valid_media_url(option["url"])
        self.key = option["key"]
        self.total = None
        self.moov_offset, self.moov, self.samples, self.starts = 0, b"", [], []
        self.read_range(0, 15)
        if not self.key:
            return
        cursor, moov, media_ranges = 0, None, []
        for unused in range(64):
            if cursor == self.total:
                break
            head = self.read_range(cursor, min(cursor + 15, self.total - 1))
            if len(head) < 8:
                raise ValueError("视频文件头不完整")
            size, kind = struct.unpack_from(">I4s", head)
            header = 8
            if size == 1:
                if len(head) < 16:
                    raise ValueError("视频文件扩展头不完整")
                size, header = struct.unpack_from(">Q", head, 8)[0], 16
            elif size == 0:
                size = self.total - cursor
            if size < header or cursor + size > self.total:
                raise ValueError("视频文件结构越界")
            if kind == b"moov":
                if moov is not None or size > 8 * 1024 * 1024:
                    raise ValueError("视频元数据过大或重复")
                self.moov_offset = cursor
                moov = self.read_range(cursor, cursor + size - 1)
            elif kind == b"mdat":
                media_ranges.append((cursor + header, cursor + size))
            elif kind == b"moof":
                raise ValueError("暂不支持分片 MP4")
            cursor += size
        if cursor != self.total or moov is None:
            raise ValueError("未取得完整的视频索引")
        self.moov, self.samples = media_index(moov, self.total, media_ranges)
        self.starts = [sample[0] for sample in self.samples]

    def read_range(self, start, end):
        if not 0 <= start <= end or end - start + 1 > 8 * 1024 * 1024:
            raise ValueError("视频读取区间无效")
        headers = {"Range": "bytes=%d-%d" % (start, end), "User-Agent": PLAY_UA, "Referer": "https://novel.snssdk.com/", "Origin": "https://novel.snssdk.com", "Accept-Encoding": "identity"}
        with requests.Session() as session:
            session.trust_env = False
            with session.get(self.url, headers=headers, timeout=(8, 20), allow_redirects=False, stream=True) as response:
                match = re.fullmatch(r"bytes (\d+)-(\d+)/(\d+)", response.headers.get("Content-Range", ""))
                if response.status_code != 206 or not match:
                    raise MediaReadError("视频服务器不支持分段读取，或播放地址已过期")
                left, right, total = map(int, match.groups())
                if left != start or right != end or not end < total <= 512 * 1024 * 1024 or self.total not in (None, total):
                    raise ValueError("视频服务器返回的区间不一致")
                content = response.raw.read(end - start + 2)
                if len(content) != end - start + 1:
                    raise ValueError("视频分段内容长度不一致")
                self.total = total
                return content

    def content(self, start, end):
        data = self.read_range(start, end)
        if self.key:
            data = bytearray(decrypt_part(data, start, self.samples, self.starts, self.key))
            left = max(start, self.moov_offset)
            right = min(end + 1, self.moov_offset + len(self.moov))
            if left < right:
                data[left - start:right - start] = self.moov[left - self.moov_offset:right - self.moov_offset]
        return bytes(data)


def parse_range(value, total):
    if not value:
        return 0, total - 1, 200
    match = re.fullmatch(r"bytes=(\d*)-(\d*)", value)
    if not match or not any(match.groups()):
        raise ValueError("请求区间无效")
    left, right = match.groups()
    if not left:
        if int(right) <= 0:
            raise ValueError("请求区间无效")
        start, end = max(0, total - int(right)), total - 1
    else:
        start = int(left)
        end = min(int(right), total - 1) if right else total - 1
    if not 0 <= start <= end < total:
        raise ValueError("请求区间超出文件")
    return start, end, 206


class MediaServer:
    def __init__(self):
        self.items, self.lock = {}, threading.Lock()
        self.slots = threading.BoundedSemaphore(4)
        owner = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_GET(self):
                self.serve(False)

            def do_HEAD(self):
                self.serve(True)

            def log_message(self, *args):
                pass

            def serve(self, head_only):
                # 每次媒体响应结束后关闭连接，提供明确的传输结束边界。
                # 这是片尾兼容措施；仍保留完整内容和 Range，不能替代宿主的切集事件。
                self.close_connection = True
                with owner.lock:
                    item = owner.items.get(self.path)
                if not item or item[1] < time.monotonic():
                    self.send_error(404)
                    return
                media = item[0]
                try:
                    start, end, status = parse_range(self.headers.get("Range"), media.total)
                except ValueError:
                    self.send_response(416)
                    self.send_header("Content-Range", "bytes */%d" % media.total)
                    self.send_header("Content-Length", "0")
                    self.send_header("Connection", "close")
                    self.end_headers()
                    return
                if not owner.slots.acquire(timeout=2):
                    self.send_error(503)
                    return
                try:
                    self.send_response(status)
                    self.send_header("Content-Type", "video/mp4")
                    self.send_header("Accept-Ranges", "bytes")
                    self.send_header("Content-Length", str(end - start + 1))
                    self.send_header("Cache-Control", "no-store")
                    self.send_header("Connection", "close")
                    if status == 206:
                        self.send_header("Content-Range", "bytes %d-%d/%d" % (start, end, media.total))
                    self.end_headers()
                    if not head_only:
                        while start <= end:
                            stop = min(start + 1024 * 1024 - 1, end)
                            self.wfile.write(media.content(start, stop))
                            start = stop + 1
                except (OSError, ValueError, RuntimeError, requests.RequestException):
                    # 已发出的媒体响应不能再插入错误页；中断后由播放器重试。
                    self.close_connection = True
                finally:
                    owner.slots.release()

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def add(self, media):
        path = "/" + secrets.token_urlsafe(24) + ".mp4"
        with self.lock:
            self.items = {key: item for key, item in self.items.items() if item[1] > time.monotonic()}
            while len(self.items) >= 8:
                self.items.pop(next(iter(self.items)))
            self.items[path] = (media, time.monotonic() + 1800)
        return "http://127.0.0.1:%d%s" % (self.server.server_port, path)

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        with self.lock:
            self.items.clear()


try:
    from base.spider import Spider as BaseSpider
except ModuleNotFoundError as error:
    # 本地验证不包含 Android 基类；电视上由影视仓提供该模块。
    if error.name not in ("base", "base.spider"):
        raise
    class BaseSpider:
        pass


class Spider(BaseSpider):
    def init(self, extend=""):
        if getattr(self, "media_server", None):
            self.destroy()
        self.client = Client()
        self.media_server = None
        self.play_lock = threading.Lock()
        self.details = {}
        self.rank_pages = {}
        self.rank_lock = threading.Lock()

    def getName(self):
        return "红果短剧"

    def getDependence(self):
        return []

    def homeContent(self, filter=False):
        return {"class": [{"type_id": key, "type_name": value} for key, value in RANKS.items()], "list": self.homeVideoContent()["list"]}

    def homeVideoContent(self):
        # 宿主选择“站点推荐”后读取此列表；插件不能覆盖宿主的豆瓣模式。
        return {"list": self.categoryContent("recommend", 1)["list"]}

    def categoryContent(self, tid, pg, filter=False, extend=None):
        if tid not in RANKS or not str(pg).isdigit() or not 1 <= int(pg) <= 1000:
            raise ValueError("分类或页码无效")
        page = int(pg)
        if tid in APP_RANKS:
            return self.app_rank(tid, page)
        route = WEB + "/rank/" + tid + ("?page=%d" % page if page > 1 else "")
        value = find_value(router_data(self.client.read(route, headers={"User-Agent": "Googlebot"})), "content")
        if not isinstance(value, dict) or not isinstance(value.get("rankList"), list):
            raise ValueError("榜单返回结构无效")
        pagination = value.get("pagination") or {}
        if int(pagination.get("pageNum", 1)) != page:
            raise ValueError("榜单未返回所请求的页面")
        items = cards(value["rankList"])
        return {"list": items, "page": page, "pagecount": max(page, int(pagination.get("totalPages", page))), "limit": 20, "total": int(pagination.get("totalCount", len(items)))}

    def app_rank(self, tid, page):
        with self.rank_lock:
            now = time.monotonic()
            state = self.rank_pages.get(tid)
            if page == 1:
                state = {"time": now, "next": {1: None}, "pages": {}, "seen": set()}
            elif not state or now - state["time"] > 600 or page not in state["next"]:
                raise ValueError("请重新进入此榜单，从第一页开始浏览")
            if page in state["pages"]:
                return state["pages"][page]
            if page > 100:
                raise ValueError("已达到单次榜单浏览上限，请重新进入榜单")
            items, cursor, more = self.client.rank(APP_RANKS[tid], state["next"][page])
            items = [item for item in items if item["vod_id"] not in state["seen"]]
            more = more and bool(items)
            result = {"list": items, "page": page, "pagecount": page + int(more), "limit": 20}
            if not items:
                result["msg"] = "该榜单暂时没有可播放作品，请稍后重试"
                show_notice(result["msg"])
            # 网络失败时不提交新状态，重试仍请求同一页；各榜单游标独立。
            state["pages"][page] = result
            state["seen"].update(item["vod_id"] for item in items)
            if more:
                state["next"][page + 1] = cursor
            self.rank_pages[tid] = state
            return result

    def searchContent(self, key, quick=False, pg=1):
        key = key.strip() if isinstance(key, str) else ""
        if not 1 <= len(key) <= 80 or any(ord(char) < 32 for char in key) or not str(pg).isdigit() or not 1 <= int(pg) <= 1000:
            raise ValueError("搜索词或页码无效")
        page = int(pg)
        query = {"query": key}
        if page > 1:
            query["page"] = page
        try:
            value = json.loads(self.client.read(WEB + "/api/search/result?" + urlencode(query)))
        except (RuntimeError, ValueError, requests.RequestException):
            show_notice("搜索服务暂时不可用，请稍后重试")
            raise
        if not isinstance(value, dict) or not isinstance(value.get("searchList"), list) or value.get("pageNum") != page:
            raise ValueError("搜索返回结构或页码无效")
        matching = matching_search_rows(value["searchList"], key)
        items = cards(matching)
        result = {"list": items, "page": page, "pagecount": max(page, int(value.get("totalPages", page))), "limit": 10, "total": int(value.get("totalCount", len(items)))}
        if len(matching) != len(value["searchList"]):
            # 上游总数包含无关推荐，不能拿它当成过滤后的匹配总数。
            result.pop("total")
        if not items:
            if not value["searchList"]:
                result["pagecount"] = page
                result["total"] = 0
            result["msg"] = "本页未找到匹配作品，请换个剧名或关键词" if result["pagecount"] > page else "未找到匹配作品，请换个剧名或关键词"
            show_notice(result["msg"])
        return result

    def detailContent(self, ids):
        if not isinstance(ids, list) or len(ids) != 1:
            raise ValueError("请选择一部短剧")
        identifier = require_id(ids[0])
        value = find_value(router_data(self.client.read(WEB + "/detail?series_id=" + identifier)), "seriesDetail")
        if not isinstance(value, dict):
            raise ValueError("网页缺少剧集详情")
        item = card(value)
        if item["vod_id"] != identifier:
            raise ValueError("返回的剧集与请求不一致")
        videos = value.get("vid_list")
        if not isinstance(videos, list) or not videos or len(videos) > 2000:
            raise ValueError("剧集列表为空或超出限制")
        videos = [require_id(video) for video in videos]
        # accessible_episode_cnt 是网页预览数量。实测第 4 集和末集仍可由
        # 匿名播放接口返回有效视频，因此选集以完整 vid_list 为准。
        # 每集能否播放由点播时的真实接口响应决定，不把预览数量当成总集数。
        item["vod_play_from"] = "红果短剧"
        item["vod_play_url"] = "#".join("第%d集$%s:%s" % (index + 1, identifier, video) for index, video in enumerate(videos))
        item["vod_remarks"] = "共 %d 集" % len(videos)
        self.details[identifier] = set(videos)
        while len(self.details) > 32:
            self.details.pop(next(iter(self.details)))
        return {"list": [item]}

    def playerContent(self, flag, id, vipFlags=None):
        parts = str(id).split(":")
        if len(parts) != 2:
            raise ValueError("播放参数无效")
        series_id, video_id = map(require_id, parts)
        with self.play_lock:
            stage = "剧集校验"
            try:
                if series_id not in self.details:
                    self.detailContent([series_id])
                if video_id not in self.details[series_id]:
                    raise ValueError("该集不在当前剧集列表中")
                stage = "播放接口"
                option = self.client.options(video_id)[0]
                stage = "视频读取"
                media = prepare_media(option)
                stage = "本机播放服务"
                if self.media_server is None:
                    self.media_server = MediaServer()
                return {"parse": 0, "playUrl": "", "url": self.media_server.add(media), "header": {}, "format": "video/mp4"}
            except Exception as error:
                # 宿主把异常统一显示为“获取播放信息错误”；只显示固定的
                # 阶段描述，第三方异常可能包含带签名地址，不能直接弹出。
                if isinstance(error, EmptyResponse):
                    message = "P01：%s返回空内容，请稍后重试" % stage
                elif isinstance(error, requests.Timeout):
                    message = "P02：%s超时，请检查电视网络" % stage
                elif isinstance(error, requests.RequestException):
                    message = "P03：%s连接失败，请检查电视网络" % stage
                else:
                    message = {
                        "播放接口": "P04：未取得有效播放信息，请稍后重试",
                        "视频读取": "P05：视频地址读取或格式处理失败",
                        "本机播放服务": "P06：电视本机播放服务启动或响应失败",
                        "剧集校验": "P07：剧集信息校验失败，请重新进入详情",
                    }[stage]
                show_notice(message)
                raise

    def localProxy(self, param):
        return [404, "text/plain; charset=utf-8", "无此接口"]

    def isVideoFormat(self, url):
        return str(url).startswith("http://127.0.0.1:") and str(url).endswith(".mp4")

    def manualVideoCheck(self):
        return False

    def liveContent(self, url):
        return ""

    def action(self, action):
        return ""

    def destroy(self):
        if self.media_server:
            self.media_server.close()
            self.media_server = None
        if getattr(self, "client", None):
            self.client.session.close()
