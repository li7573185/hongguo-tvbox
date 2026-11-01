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
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlencode, urlparse

import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

WEB = "https://hongguoduanju.com"
API = "https://api5-normal-sinfonlineb.fqnovel.com"
WEB_UA = "Mozilla/5.0 (Android TV; HongguoTV)"
APP_UA = "com.phoenix.read/73532 (Linux; U; Android 16; zh_CN; 25053RT47C; Build/BP2A.250605.031.A3; Cronet/TTNetVersion:04657795 2026-01-23 QuicVersion:c67e9834 2025-09-08)"
PLAY_UA = "com.phoenix.read/71532 (Linux; U; Android 9; SM-N9860; Build/PQ3A.190705.10241111;tt-ok/3.12.13.20)"
MAX_JSON = 5 * 1024 * 1024
RANKS = {"hot-drama": "热门短剧", "hot-real-drama": "真人短剧", "hot-comic-drama": "漫剧", "hot-ai-drama": "AI 短剧"}


class EmptyResponse(RuntimeError):
    pass


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

    def read(self, url, method="GET", data=None, headers=None):
        # 固定上游域名，避免网页提供的地址让插件访问用户内网。
        parsed = urlparse(url)
        if parsed.scheme != "https" or parsed.hostname not in {"hongguoduanju.com", "api5-normal-sinfonlineb.fqnovel.com", "log.snssdk.com"}:
            raise ValueError("接口地址不在允许范围内")
        head = {"User-Agent": WEB_UA, "Referer": WEB + "/"}
        head.update(headers or {})
        with self.session.request(method, url, data=data, headers=head, timeout=(8, 20), allow_redirects=False, stream=True) as response:
            if response.status_code != 200:
                raise RuntimeError("红果接口返回 HTTP %d" % response.status_code)
            chunks, size = [], 0
            for chunk in response.iter_content(65536):
                size += len(chunk)
                if size > MAX_JSON:
                    raise ValueError("接口响应超过大小限制")
                chunks.append(chunk)
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
            raw = self.read("https://log.snssdk.com/service/2/device_register/?" + encoded, "POST", body, headers)
            result = json.loads(decode_device(raw) if raw.startswith(b"tc\x05") else raw)
            self.device = {"cdid": cdid, "device_id": require_id(result.get("device_id_str") or result.get("device_id")), "iid": require_id(result.get("install_id_str") or result.get("install_id"))}
            return self.device

    def options(self, video_id):
        video_id = require_id(video_id)
        query = app_query("71332")
        query.update(self.register())
        query.update(_rticket=str(int(time.time() * 1000)), dragon_device_type="phone", host_abi="arm64-v8a", is_android_pad_screen="0", need_personal_recommend="1", player_so_load="1", pv_player="71332", compliance_status="0")
        body = {"biz_param": {"detail_page_version": 0, "device_level": 3, "disable_digg_stat": False, "need_all_video_definition": True, "need_mp4_align": False, "use_os_player": False, "use_server_dns": False, "video_platform": 1024}, "mixed_video_id_map": {"1004": [video_id]}}
        for attempt in range(6):
            query["_rticket"] = str(int(time.time() * 1000))
            try:
                raw = self.read(API + "/novel/player/multi_video_model/v1/?" + urlencode(sorted(query.items())), "POST", encode_json(body), {"User-Agent": PLAY_UA, "Content-Type": "application/json; charset=UTF-8", "Accept": "application/json"})
                break
            except EmptyResponse:
                if attempt == 5:
                    raise
                if attempt == 2:
                    # 实测有匿名身份持续返回空内容；只恢复一次，并限制恢复频率。
                    # HTTP 拒绝、权限错误和格式错误不会进入这一分支。
                    with self.device_lock:
                        now = time.monotonic()
                        if now - self.last_identity_refresh < 30:
                            raise
                        self.last_identity_refresh = now
                        self.device = None
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
            url = row.get("main_url") or row.get("backup_url") or next(iter(row.get("backup_url_list", [])), "")
            if not url.startswith("http"):
                url = base64.b64decode(url + "=" * (-len(url) % 4)).decode("utf-8")
            if urlparse(url).scheme != "https":
                continue
            encryption = row.get("encrypt_info") or {}
            key = decode_content_key(encryption["spade_a"]) if encryption.get("spade_a") else None
            definition = str(row.get("quality_desc") or row.get("definition") or meta.get("definition") or "")
            match = re.search(r"\d{3,4}", definition)
            height = int(match.group()) if match else int(row.get("vheight") or meta.get("vheight") or 0)
            result.append(dict(url=url, key=key, codec=codec, height=height))
        if not result:
            raise ValueError("没有取得本插件支持的视频格式")
        # 优先常见编码的 720P，控制旧电视的带宽和解码负担。
        return sorted(result, key=lambda item: (item["codec"] in ("bytevc1", "hevc"), abs(item["height"] - 720)))


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
                    raise RuntimeError("视频服务器不支持分段读取，或播放地址已过期")
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

    def getName(self):
        return "红果短剧"

    def getDependence(self):
        return []

    def homeContent(self, filter=False):
        return {"class": [{"type_id": key, "type_name": value} for key, value in RANKS.items()], "list": self.categoryContent("hot-drama", 1)["list"]}

    def homeVideoContent(self):
        return {"list": self.categoryContent("hot-drama", 1)["list"]}

    def categoryContent(self, tid, pg, filter=False, extend=None):
        if tid not in RANKS or not str(pg).isdigit() or not 1 <= int(pg) <= 1000:
            raise ValueError("分类或页码无效")
        page = int(pg)
        route = WEB + "/rank/" + tid + ("?page=%d" % page if page > 1 else "")
        value = find_value(router_data(self.client.read(route, headers={"User-Agent": "Googlebot"})), "content")
        if not isinstance(value, dict) or not isinstance(value.get("rankList"), list):
            raise ValueError("榜单返回结构无效")
        pagination = value.get("pagination") or {}
        if int(pagination.get("pageNum", 1)) != page:
            raise ValueError("榜单未返回所请求的页面")
        items = cards(value["rankList"])
        return {"list": items, "page": page, "pagecount": max(page, int(pagination.get("totalPages", page))), "limit": 20, "total": int(pagination.get("totalCount", len(items)))}

    def searchContent(self, key, quick=False, pg=1):
        key = str(key).strip()
        if not 1 <= len(key) <= 80 or not str(pg).isdigit() or not 1 <= int(pg) <= 1000:
            raise ValueError("搜索词或页码无效")
        page = int(pg)
        query = {"query": key}
        if page > 1:
            query["page"] = page
        value = json.loads(self.client.read(WEB + "/api/search/result?" + urlencode(query)))
        if not isinstance(value.get("searchList"), list) or value.get("pageNum") != page:
            raise ValueError("搜索返回结构或页码无效")
        items = cards([row for row in value["searchList"] if isinstance(row, dict) and isinstance(row.get("video_data"), dict)])
        return {"list": items, "page": page, "pagecount": max(page, int(value.get("totalPages", page))), "limit": 10, "total": int(value.get("totalCount", len(items)))}

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
            if series_id not in self.details:
                self.detailContent([series_id])
            if video_id not in self.details[series_id]:
                raise ValueError("该集不在当前剧集列表中")
            option = self.client.options(video_id)[0]
            media = RemoteMedia(option)
            if self.media_server is None:
                self.media_server = MediaServer()
            return {"parse": 0, "playUrl": "", "url": self.media_server.add(media), "header": {}, "format": "video/mp4"}

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
