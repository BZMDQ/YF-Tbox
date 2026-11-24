"""Authenticated LAN system-information and complete-package OTA client."""
import argparse
import errno
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import socket
import select
import struct
import time
import zlib

def parse_device_info(body):
    """Read device JSON, including the known 1.2.1-1.2.4 extra quote defect."""
    text = body.decode('utf-8') if isinstance(body, bytes) else str(body)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        if '"device_name":' in text and '"","uptime_ms":' in text:
            return json.loads(text.replace('"","uptime_ms":', '","uptime_ms":', 1))
        raise


HEADER = struct.Struct('<4sIIII')
OTA_CHUNK_SIZE = 16384
OTA_MAX_CHUNK_SIZE = 32768
OTA_TRANSFER_WINDOW = 2
OTA_TRANSFER_CAPS_OP = 35
OTA_LAYOUT_OP = 36
OTA_LEGACY_CHUNK_SIZE = 1024
OTA_RESPONSE_READ_SIZE = 4096
OTA_RAM_SIZE = 0x3C000
W78_MAX_HEX_SIZE = 512 * 1024
W78_CHUNK_SIZE = 32768
W78_PIPELINE_WINDOW = 2
W78_PIPELINE_NEGOTIATE = 31
W78_PIPELINE_DATA_LEGACY = 32
W78_PIPELINE_DATA = 33
W78_MAX_PAYLOAD = 16 * 1024
W78_RAW_MAX_PAYLOAD = 32 * 1024
W78_ACK_TIMEOUT = 4.0
W78_BATCH_ACK_TIMEOUT = 6.0
W78_ACK_POLL = 0.25
W78_LOGICAL_CHUNK_SIZES = (4096, 8192, 16384, 32768)
W78_STATE_READY = 3
W78_STATE_DONE = 13
W78_STATE_FAILED = 14


class DeviceError(RuntimeError):
    def __init__(self, status):
        self.status = status
        detail = {
            11: '（设备将当前连接判定为次级只读连接；请关闭同一设备上的其他 Local TCP 客户端后重试）',
            12: '：设备不接受当前分包长度；请在设置中降低无线烧录分包后重试',
            14: '（开发板拒绝了 OTA 请求或确认超时）',
            6: '（W78 HEX 分片偏移或长度不正确）',
            8: '（W78 Intel HEX 格式、校验和或 APROM 地址错误）',
            9: '（升级包校验失败）',
            13: '（Local TCP Key 认证失败）',
            16: '（系统 OTA 分区布局不匹配）',
        }.get(status, '')
        super().__init__(f'设备返回错误 {status}{detail}')


def frame(op, offset=0, payload=b''):
    prefix = struct.pack('<4sIII', b'LNET', op, offset, len(payload))
    crc = zlib.crc32(payload, zlib.crc32(prefix)) & 0xffffffff
    return b''.join((prefix, struct.pack('<I', crc), payload))


def exact(sock, count):
    data = bytearray()
    while len(data) < count:
        part = sock.recv(count - len(data))
        if not part:
            raise ConnectionError('设备已关闭连接')
        data.extend(part)
    return bytes(data)


class SocketReader:
    """Buffered reader for sockets that use short timeouts while listening."""
    def __init__(self, sock, read_ahead=0):
        self.sock = sock
        self.buffer = bytearray()
        self.read_ahead = read_ahead

    def peek(self, count):
        while len(self.buffer) < count:
            part = self.sock.recv(max(count - len(self.buffer), self.read_ahead))
            if not part:
                raise ConnectionError('设备已关闭连接')
            self.buffer.extend(part)
        return bytes(self.buffer[:count])

    def exact(self, count):
        data = self.peek(count)
        del self.buffer[:count]
        return data


def response_header(header):
    """读取并检查 LNET 响应头，供同步连接和异步发现共用。"""
    magic, op, status, size, crc = HEADER.unpack(header)
    if magic != b'LNET' or size > 1024:
        raise ValueError('无效响应头')
    return op, status, size, crc


def checked_response(header, body, fields):
    op, status, _size, crc = fields
    if zlib.crc32(body, zlib.crc32(header[:16])) & 0xffffffff != crc:
        raise ValueError('响应 CRC 校验失败')
    if status:
        raise DeviceError(status)
    return op, body


def receive(sock, reader=None):
    read_exact = reader.exact if reader is not None else lambda count: exact(sock, count)
    # 整帧读齐才消费头部，避免正文分段到达时一次超时破坏流对齐。
    buffered = isinstance(reader, SocketReader)
    header = reader.peek(HEADER.size) if buffered else read_exact(HEADER.size)
    fields = response_header(header)
    size = fields[2]
    body = (read_exact(HEADER.size + size)[HEADER.size:] if buffered else read_exact(size))
    return checked_response(header, body, fields)


def request(sock, op, offset=0, payload=b'', on_info=None, send_lock=None,
            reader=None, cancel=None):
    packet = frame(op, offset, payload)
    if send_lock is None:
        _check_cancel(cancel)
        sock.sendall(packet)
    else:
        with send_lock:
            _check_cancel(cancel)
            sock.sendall(packet)
    while True:
        response, body = receive(sock, reader=reader)
        if response == op | 0x80000000:
            return body
        if response == 0x80000001:
            if on_info:
                on_info(body)
            else:
                print(body.decode('utf-8'))  # Settings-page manual information upload.
        else:
            raise ValueError('响应命令不匹配')


def upload_ota_stream(sock, package, chunk_size=OTA_CHUNK_SIZE, on_progress=None,
                      on_info=None, send_lock=None, cancel=None, on_mode=None, window=1,
                      reader=None):
    """按设备能力使用窗口 1 或 2，按 Flash 写入回执推进进度。"""
    if not 0 < chunk_size <= OTA_MAX_CHUNK_SIZE or window not in (1, OTA_TRANSFER_WINDOW):
        raise ValueError('系统 OTA 分片或窗口大小无效')
    if cancel is not None and cancel.is_set():
        raise InterruptedError()
    if chunk_size > OTA_CHUNK_SIZE or window > 1:
        # 查询能力不修改槽位。旧固件返回不支持或未知命令的权限错误。
        try:
            caps = request(sock, OTA_TRANSFER_CAPS_OP, on_info=on_info, send_lock=send_lock,
                           reader=reader, cancel=cancel)
        except DeviceError as exc:
            if exc.status not in (11, 13):
                raise
            capacity, supported_window = OTA_CHUNK_SIZE, 1
        else:
            if len(caps) != 8:
                raise ValueError('设备返回的系统 OTA 能力长度无效')
            capacity, supported_window = struct.unpack('<II', caps)
            if capacity not in (OTA_CHUNK_SIZE, OTA_MAX_CHUNK_SIZE) or supported_window not in (1, OTA_TRANSFER_WINDOW):
                raise ValueError('设备返回的系统 OTA 能力无效')
        chunk_size = min(chunk_size, capacity)
        window = min(window, supported_window)
    if on_mode:
        on_mode(chunk_size, window)

    next_offset = written = 0
    pending = []
    # 用视图直接取包数据，组帧前无需再复制每个分片。
    package_view = memoryview(package)
    total = len(package_view)
    while written < total:
        if cancel is not None and cancel.is_set():
            raise InterruptedError()
        outgoing = []
        while len(pending) < window and next_offset < total:
            end = min(total, next_offset + chunk_size)
            outgoing.append(frame(3, next_offset, package_view[next_offset:end]))
            pending.append(end)
            next_offset = end
        if outgoing:
            packets = b''.join(outgoing)
            if send_lock is None:
                _check_cancel(cancel)
                sock.sendall(packets)
            else:
                with send_lock:
                    _check_cancel(cancel)
                    sock.sendall(packets)

        response, ack = receive(sock, reader=reader)
        if response == 0x80000001:
            if on_info:
                on_info(ack)
            else:
                print(ack.decode('utf-8'))
            continue
        # 只接受队首块的已写入偏移。回执异常立即停止，不自动重放不确定的写入。
        if response != 0x80000003 or len(ack) != 4 or struct.unpack('<I', ack)[0] != pending[0]:
            raise ValueError('OTA确认命令、偏移或长度不匹配')
        written = pending.pop(0)
        if on_progress:
            on_progress(written)


def request_wait(sock, op, offset=0, payload=b'', on_info=None, send_lock=None,
                 reader=None, cancel=None, timeout=120, ignore_ops=(),
                 on_ignored=None, before_send=None):
    """发送一次请求，在可取消的短超时轮询中等待完整响应。"""
    packet = frame(op, offset, payload)
    def send():
        _check_cancel(cancel)
        if before_send is not None:
            before_send()
        sock.sendall(packet)

    if send_lock is None:
        send()
    else:
        with send_lock:
            send()

    expected = op | 0x80000000
    ignored = {value | 0x80000000 for value in ignore_ops}
    deadline = time.monotonic() + max(0.001, float(timeout))
    old_timeout = sock.gettimeout()
    try:
        while True:
            if cancel is not None and cancel.is_set():
                raise InterruptedError()
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('等待开发板响应超时。')
            sock.settimeout(min(0.5, remaining))
            try:
                response, body = receive(sock, reader=reader)
            except socket.timeout:
                continue
            if response == expected:
                return body
            if response in ignored:
                if on_ignored:
                    on_ignored(response)
                continue
            if response == 0x80000001:
                if on_info:
                    on_info(body)
                else:
                    print(body.decode('utf-8'))
                continue
            raise ValueError('响应命令不匹配')
    finally:
        try:
            sock.settimeout(old_timeout)
        except OSError:
            # 停止操作可能已经关闭套接字，保留原来的接收或取消结果。
            if cancel is None or not cancel.is_set():
                raise


def upload_w78_window(sock, package, logical_chunk_size, session_id, stop_event,
                      on_progress=None, on_info=None, send_lock=None,
                      target=0, window=W78_PIPELINE_WINDOW, max_retries=3, on_retry=None):
    """原始 HEX 最多 32 KiB 一帧、窗口 2；按旧固件能力逐级回退。"""
    total = len(package)
    frame_request = min(logical_chunk_size, W78_RAW_MAX_PAYLOAD)
    if session_id <= 0 or session_id > 0x00FFFFFF:
        raise ValueError('流水会话号超出 24 位范围。')

    # 多帧时优先协商双帧累计确认。旧板拒绝新标志后，保持原有 32/16 KiB 和旧帧回退。
    legacy_request = min(logical_chunk_size, W78_MAX_PAYLOAD)
    negotiation = [(2, frame_request)] if window == 2 and total > frame_request else []
    negotiation.append((1, frame_request))
    if frame_request > legacy_request:
        negotiation.append((1, legacy_request))
    negotiation.append((0, legacy_request))
    for index, (feature, frame_request) in enumerate(negotiation):
        hello = (struct.pack('<IIII', session_id, window, frame_request, feature)
                 if feature else struct.pack('<III', session_id, window, frame_request))
        try:
            caps = request(sock, W78_PIPELINE_NEGOTIATE, target, hello,
                           on_info=on_info, send_lock=send_lock)
            break
        except DeviceError as exc:
            if exc.status in (11, 13):
                return None
            if exc.status != 4 or index == len(negotiation) - 1:
                raise

    if len(caps) != 24:
        raise ValueError('开发板返回的流水传输协商数据无效。')
    remote_session, max_data, remote_window, next_seq, next_offset, credits = struct.unpack('<6I', caps)
    raw_mode = feature != 0
    protocol_limit = W78_RAW_MAX_PAYLOAD if raw_mode else W78_MAX_PAYLOAD - 8
    if (remote_session != session_id or max_data < 1024 or max_data > protocol_limit
            or remote_window < 1 or remote_window > W78_PIPELINE_WINDOW
            or next_seq != 0 or next_offset != 0 or not credits):
        raise ValueError('开发板返回的帧上限或接收额度无效。')
    frame_size = min(frame_request, max_data)
    window = min(window, remote_window, credits)
    if frame_size <= 0 or not window:
        raise ValueError('开发板没有可用的接收额度。')

    protocol_op = W78_PIPELINE_DATA if raw_mode else W78_PIPELINE_DATA_LEGACY
    reader = SocketReader(sock)
    pending = {}
    sent_end = {}
    next_send_offset = 0
    next_send_seq = 0
    acked_offset = 0
    confirmed_seq = 0
    retries_total = 0
    send_credit = window
    ack_deadline = 0.0
    ack_timeout = W78_BATCH_ACK_TIMEOUT if feature == 2 else W78_ACK_TIMEOUT
    old_timeout = sock.gettimeout()

    def send_packet(packet):
        if send_lock is None:
            sock.sendall(packet)
        else:
            with send_lock:
                sock.sendall(packet)

    def resend(item, reason, error):
        nonlocal retries_total, ack_deadline
        if stop_event is not None and stop_event.is_set():
            raise InterruptedError()
        if item['retries'] >= max_retries:
            raise TimeoutError(error)
        sock.settimeout(old_timeout)
        send_packet(item['packet'])
        item['retries'] += 1
        ack_deadline = time.monotonic() + ack_timeout
        retries_total += 1
        if on_retry:
            on_retry(reason)

    try:
        while acked_offset < total:
            if stop_event is not None and stop_event.is_set():
                raise InterruptedError()
            sock.settimeout(old_timeout)
            window_empty = not pending
            outgoing = []
            while (next_send_offset < total and len(pending) < window
                   and send_credit > 0):
                if next_send_seq > 0xFF:
                    raise ValueError('HEX 分包数超过当前流水序号范围。')
                end = min(total, next_send_offset + frame_size)
                block = package[next_send_offset:end]
                if raw_mode:
                    # 24 位会话号和 8 位序号放在外层 offset，不挤占原始 HEX 数据。
                    wire_offset = (session_id << 8) | next_send_seq
                    payload = block
                else:
                    wire_offset = next_send_seq
                    payload = struct.pack('<II', session_id, next_send_offset) + block
                packet = frame(protocol_op, wire_offset, payload)
                outgoing.append(packet)
                pending[next_send_seq] = {'packet': packet, 'retries': 0}
                sent_end[next_send_seq] = end
                next_send_offset = end
                next_send_seq += 1
                send_credit -= 1
            if outgoing:
                # 一次提交可用窗口，TCP 字节流仍包含独立的两帧和各自 CRC。
                send_packet(b''.join(outgoing))
                if window_empty:
                    ack_deadline = time.monotonic() + ack_timeout

            if not pending:
                raise ConnectionError('开发板未返回流水发送额度。')
            oldest = min(pending)
            remaining = ack_deadline - time.monotonic()
            wait = max(0.05, min(W78_ACK_POLL, remaining))
            sock.settimeout(wait)
            try:
                response, body = receive(sock, reader=reader)
            except socket.timeout:
                # 短轮询用于响应取消；只有完整 ACK 等待期限届满才重传。
                item = pending[oldest]
                if time.monotonic() < ack_deadline:
                    continue
                if reader.buffer:
                    raise TimeoutError('开发板的 HEX 确认帧未收齐，已停止上传。')
                resend(item, 'timeout', 'HEX 分包多次重传仍未收到开发板确认。')
                continue
            except DeviceError as exc:
                if exc.status != 1:
                    raise
                resend(pending[oldest], 'crc', 'HEX 分包校验多次失败，停止重传。')
                continue

            if response == 0x80000001:
                if on_info:
                    on_info(body)
                continue
            if response != (protocol_op | 0x80000000) or len(body) != 24:
                raise ValueError('开发板返回了不匹配的流水 ACK。')

            ack_session, ack_seq, expected_seq, expected_offset, credit, classification = struct.unpack('<6I', body)
            if ack_session != session_id or expected_seq > next_send_seq or expected_offset > total:
                raise ValueError('开发板 ACK 序号或会话号无效。')
            known_offset = sent_end.get(expected_seq - 1, 0) if expected_seq else 0
            if expected_offset != known_offset:
                raise ValueError('开发板累计 ACK 字节偏移不匹配。')
            if classification not in ((0, 1, 2, 3) if feature == 2 else (0, 1, 2)) or credit > remote_window:
                raise ValueError('开发板 ACK 分类或接收额度无效。')
            if classification in (0, 1) and (ack_seq >= next_send_seq or expected_seq <= ack_seq):
                raise ValueError('开发板 ACK 序号未覆盖已接受分包。')
            if expected_seq < confirmed_seq:
                continue  # 迟到回执不能回退已确认进度或覆盖最新发送额度。

            # 负确认同样携带已接受的前缀，先销账，再按明确的缺失序号重传。
            if expected_seq > confirmed_seq:
                confirmed_seq = expected_seq
                for seq in list(pending):
                    if seq < confirmed_seq:
                        del pending[seq]
                ack_deadline = time.monotonic() + ack_timeout
                acked_offset = expected_offset
                if on_progress:
                    on_progress(acked_offset, total)
            if classification in (2, 3):
                missing = pending.get(expected_seq)
                # 同一缺口的后续乱序通知不抢跑；真正的 CRC 拒绝可立即重传。
                if missing is not None and (classification == 3 or not missing['retries']):
                    if classification == 3:
                        resend(missing, 'crc', 'HEX 分包校验多次失败，停止重传。')
                    else:
                        resend(missing, 'sequence', '流水序号多次重传仍未被开发板接受。')
            send_credit = min(window, credit)
    finally:
        sock.settimeout(old_timeout)
    return logical_chunk_size, frame_size, window, retries_total, raw_mode


def check_ota_layout(sock, package_layout, on_info=None, send_lock=None):
    """写入前查询设备布局，旧固件不认识该只读命令时视为布局 1。"""
    try:
        body = request(sock, OTA_LAYOUT_OP, on_info=on_info, send_lock=send_lock)
    except DeviceError as exc:
        if exc.status not in (11, 13):
            raise
        target_layout = 1
    else:
        if len(body) != 4:
            raise ValueError('设备返回的 OTA 布局无效')
        target_layout, = struct.unpack('<I', body)
    if target_layout != package_layout:
        raise ValueError(f'升级包布局 {package_layout} 与开发板布局 {target_layout} 不匹配。首次切换请使用配套工厂 HEX。')


def validate_package(package):
    if len(package) < 128:
        raise ValueError('升级包太短')
    magic, fmt, hsize, total, load, app, assets, ac, rc, pc, version, _ = struct.unpack_from('<8s9I20s60s', package)
    if (magic, fmt) not in ((b'F750OTA1', 1), (b'F750OTA2', 2)) or hsize != 128 or total != len(package):
        raise ValueError('请选择完整的 STM32F750_版本.ota.bin')
    max_assets, max_slot = (0x4C0000, 0x500000) if fmt == 2 else (0x380000, 0x400000)
    if (load != 0x20010000 or not 8 <= app <= OTA_RAM_SIZE or assets > max_assets
            or total != 128 + app + assets or total > max_slot or (fmt == 2 and any(package[64:80]))):
        raise ValueError('升级包分区尺寸错误')
    for data, expected in ((package[:124], struct.unpack_from('<I', package, 124)[0]),
                           (package[128:128+app], ac), (package[128+app:], rc), (package[128:], pc)):
        if zlib.crc32(data) & 0xffffffff != expected:
            raise ValueError('升级包 CRC 校验失败')
    return version.split(b'\0', 1)[0].decode('ascii')


def validate_w78_filename(path):
    """Return an ASCII-safe device filename for the selected local W78 HEX."""
    name = Path(path).name
    if not name.lower().endswith('.hex'):
        raise ValueError('W78 无线烧录只接受 .hex 文件。')

    safe_name = ''.join(
        char if char.isascii() and (char.isalnum() or char in '_.-') else '_'
        for char in name
    )
    if safe_name != name or len(safe_name) >= 48:
        safe_name = safe_name[:-4][:43] + '.hex'
    encoded = safe_name.encode('ascii')
    if not 5 <= len(encoded) < 48:
        raise ValueError('无线传输名需为 5–47 个 ASCII 字节，并以 .hex 结尾。')
    return encoded


def validate_w78_hex(path, *, include_extent=False):
    """Read and validate a W78E516 Intel HEX image before wireless upload."""
    path = Path(path)
    validate_w78_filename(path)
    package = path.read_bytes()
    # Some HEX tools append DOS Ctrl+Z (0x1A) as an end-of-file marker.
    if package.endswith(b'\x1a'):
        package = package[:-1]
    if not 1 <= len(package) <= W78_MAX_HEX_SIZE:
        raise ValueError('W78 HEX 文件大小必须在 1 到 512 KiB 之间。')
    try:
        text = package.decode('ascii')
    except UnicodeError as exc:
        raise ValueError('W78 HEX 文件内容必须使用 ASCII 字符。') from exc
    if path.suffix.lower() != '.hex':
        raise ValueError('W78 烧录只接受 .hex 文件。')

    base = 0
    aprom_extent = 0
    eof = False
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.rstrip('\r')
        if not line:
            continue
        if eof or not line.startswith(':') or len(line) < 11 or len(line) > 523:
            raise ValueError(f'Intel HEX 第 {line_number} 行格式错误。')
        if any(c not in '0123456789abcdefABCDEF' for c in line[1:]):
            raise ValueError(f'Intel HEX 第 {line_number} 行含非十六进制字符。')
        try:
            record = bytes.fromhex(line[1:])
        except ValueError as exc:
            raise ValueError(f'Intel HEX 第 {line_number} 行含非十六进制字符。') from exc
        count = record[0]
        if len(record) != count + 5 or sum(record) & 0xFF:
            raise ValueError(f'Intel HEX 第 {line_number} 行长度或校验和错误。')
        address = (record[1] << 8) | record[2]
        kind = record[3]
        payload = record[4:-1]
        if kind == 0:
            absolute = base + address
            if absolute > 65536 or count > 65536 - absolute:
                raise ValueError(f'Intel HEX 第 {line_number} 行超出 W78 64 KiB APROM。')
            # 固件从地址 0 连续写到最高有数据地址；空记录不扩大范围。
            if count:
                aprom_extent = max(aprom_extent, absolute + count)
        elif kind == 1:
            if count or address:
                raise ValueError(f'Intel HEX 第 {line_number} 行 EOF 记录无效。')
            eof = True
        elif kind == 2:
            if count != 2 or address:
                raise ValueError(f'Intel HEX 第 {line_number} 行段地址记录无效。')
            base = int.from_bytes(payload, 'big') << 4
        elif kind == 4:
            if count != 2 or address:
                raise ValueError(f'Intel HEX 第 {line_number} 行扩展线性地址记录无效。')
            base = int.from_bytes(payload, 'big') << 16
        elif kind in (3, 5):
            if count != 4:
                raise ValueError(f'Intel HEX 第 {line_number} 行起始地址记录无效。')
        else:
            raise ValueError(f'Intel HEX 第 {line_number} 行使用了不支持的记录类型。')
    if not eof or not aprom_extent:
        raise ValueError('W78 HEX 必须包含数据记录和 EOF 记录。')
    return (package, aprom_extent) if include_extent else package


class W78StageTiming:
    """记录轮询可确定的时间范围；设备事件必然落在请求与收到响应之间。"""

    def __init__(self, start):
        self.start = start
        # 各范围依次是写入、校验、写入和校验合计；合计用于两段都短于轮询的情况。
        self.windows = [[start, None, None, None] for _ in range(3)]

    def observe(self, state, sent, received):
        if state not in (3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13):
            return
        stage = 0 if state < 10 else 1 if state == 10 else 2 if state == 11 else 3
        for window, (begin, end) in zip(self.windows, ((1, 1), (2, 2), (1, 2))):
            if window[3] is not None:
                continue
            if stage < begin:
                window[0] = sent
            elif stage <= end:
                if window[1] is None:
                    window[1] = received
                window[2] = sent
            else:
                window[3] = received

    @staticmethod
    def describe(window):
        before, first_end, last_start, after = window
        if after is None:
            return '未观测到结束'
        maximum = math.ceil(max(0, after - before) * 1000)
        if first_end is None:
            return f'未采到（≤ {maximum:,} ms）'
        minimum = math.floor(max(0, last_start - first_end) * 1000)
        return f'{minimum:,}–{maximum:,} ms' if minimum else f'≤ {maximum:,} ms'

    def detail(self):
        return '；'.join(f'{label} {self.describe(window)}' for label, window in
                        zip(('写入', '校验', '写入＋校验'), self.windows))


def bind_lan_route(sock, host, cancel=None):
    """局域网设备使用与扫描相同的物理网卡，避免被 TUN 默认路由接管。"""
    if os.name != 'nt':
        return None
    try:
        address = ipaddress.IPv4Address(host)
    except (ValueError, TypeError):
        return None
    if (not address.is_private or address.is_loopback or address.is_link_local or
            address in ipaddress.IPv4Network('198.18.0.0/15')):
        return None
    # 延迟导入可以避免设备扫描模块与网络客户端循环导入。
    from device_directory import lan_interfaces, route_interface
    interfaces = lan_interfaces(cancel)
    if cancel is not None and cancel.is_set():
        raise InterruptedError()
    route = route_interface(str(address), interfaces)
    if route:
        index, source = route
        sock.setsockopt(socket.IPPROTO_IP, getattr(socket, 'IP_UNICAST_IF', 31),
                        struct.pack('!I', index))
        sock.bind((source, 0))
    return route


def configure_tcp_socket(sock):
    """统一小报文延迟和空闲连接检测；不改变OTA帧与窗口协议。"""
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    try:
        if os.name == 'nt' and hasattr(socket, 'SIO_KEEPALIVE_VALS'):
            # 空闲30秒后开始探测，每5秒一次；不发送任何业务命令。
            sock.ioctl(socket.SIO_KEEPALIVE_VALS, (1, 30000, 5000))
        elif hasattr(socket, 'TCP_KEEPIDLE'):
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 30)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 5)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
    except OSError:
        # 部分旧系统仅支持SO_KEEPALIVE，仍保留系统默认探测参数。
        pass


def _check_cancel(cancel):
    if cancel is not None and cancel.is_set():
        raise InterruptedError('连接已停止')


def _connect_tcp(sock, endpoint, timeout, cancel):
    """非阻塞建立TCP，使停止操作不必等完系统连接超时。"""
    _check_cancel(cancel)
    deadline = time.monotonic() + timeout
    sock.setblocking(False)
    result = sock.connect_ex(endpoint)
    pending = {errno.EINPROGRESS, errno.EWOULDBLOCK, errno.EALREADY,
               10035, 10036, 10037}
    if result not in (0, errno.EISCONN, 10056) and result not in pending:
        raise OSError(result, os.strerror(result))
    while result in pending:
        _check_cancel(cancel)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('TCP连接超时')
        _, writable, exceptional = select.select([], [sock], [sock], min(0.1, remaining))
        if writable or exceptional:
            result = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
            if result:
                raise OSError(result, os.strerror(result))
    _check_cancel(cancel)
    sock.settimeout(timeout)


class _HandshakeReader:
    """仅供认证使用的总时限读取器；半帧取消/超时后必须关闭整条连接。"""
    def __init__(self, sock, timeout, cancel):
        self.sock = sock
        self.deadline = time.monotonic() + timeout
        self.cancel = cancel

    def exact(self, count):
        data = bytearray()
        while len(data) < count:
            _check_cancel(self.cancel)
            remaining = self.deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('Local TCP Key认证超时')
            readable, _, _ = select.select([self.sock], [], [], min(0.1, remaining))
            if not readable:
                continue
            part = self.sock.recv(count - len(data))
            if not part:
                raise ConnectionError('设备已关闭连接')
            data.extend(part)
        _check_cancel(self.cancel)
        return bytes(data)


def connect(args, key, on_info=None, cancel=None, on_socket=None):
    """只重试无副作用的TCP/认证握手；返回后业务命令由调用者负责。"""
    _check_cancel(cancel)
    # Local TCP及物理网卡选择均为IPv4；优先直接使用地址，避免额外DNS查询。
    try:
        host = str(ipaddress.IPv4Address(args.host))
    except (ValueError, TypeError):
        host = socket.gethostbyname(args.host)
    _check_cancel(cancel)
    transient = {errno.ECONNREFUSED, errno.ECONNRESET, errno.ECONNABORTED,
                 errno.ETIMEDOUT, errno.ENETUNREACH, errno.EHOSTUNREACH,
                 errno.ENETDOWN, errno.EADDRNOTAVAIL,
                 10051, 10050, 10049, 10053, 10054, 10060, 10061, 10065}
    for attempt in range(2):
        _check_cancel(cancel)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        stage = '创建连接'
        try:
            if on_socket is not None:
                on_socket(sock)
            _check_cancel(cancel)
            configure_tcp_socket(sock)
            stage = '绑定网卡'
            bind_lan_route(sock, host, cancel)
            stage = 'TCP连接'
            _connect_tcp(sock, (host, args.port), 3.0, cancel)
            stage = 'Key认证'
            sock.settimeout(5.0)
            request(sock, 0, payload=key, on_info=on_info,
                    reader=_HandshakeReader(sock, 5.0, cancel))
            _check_cancel(cancel)
            sock.settimeout(120)  # 保留W25擦除和完整包校验需要的业务超时。
            return sock
        except Exception as exc:
            sock.close()
            _check_cancel(cancel)
            if isinstance(exc, OSError) and (stage == '绑定网卡' or
                    getattr(exc, 'errno', None) in {errno.EADDRNOTAVAIL, errno.ENETUNREACH, 10049, 10051}):
                from device_directory import invalidate_lan_interfaces
                invalidate_lan_interfaces()
            # DeviceError及CRC/响应格式错误不属于可重试传输错误。
            retryable = isinstance(exc, (TimeoutError, ConnectionError)) or (
                isinstance(exc, OSError) and getattr(exc, 'errno', None) in transient)
            if isinstance(exc, InterruptedError) or not retryable or attempt:
                raise
            if cancel is not None:
                if cancel.wait(0.15):
                    raise InterruptedError('连接已停止') from exc
            else:
                time.sleep(0.15)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host', required=True, help='开发板设置中显示的 IP 地址')
    parser.add_argument('--port', type=int, default=5000)
    parser.add_argument('--key-file', type=Path, default=Path(__file__).with_name('local_tcp_access.key'))
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('info')
    sub.add_parser('listen', help='保持连接，接收屏幕设置中的系统信息上传')
    ota = sub.add_parser('ota')
    ota.add_argument('package', type=Path)
    args = parser.parse_args()
    if args.key_file.is_file():
        key = args.key_file.read_text(encoding='ascii').strip().encode('ascii')
        if len(key) != 32 or any(c not in b'0123456789abcdef' for c in key):
            parser.error('密钥文件必须是本固件配套的 32 位十六进制密钥')
    else:
        key = b''
    package = args.package.read_bytes() if args.command == 'ota' else None
    version = validate_package(package) if package is not None else None
    with connect(args, key) as sock:
        if args.command == 'info':
            print(json.dumps(json.loads(request(sock, 1)), ensure_ascii=False, indent=2))
            return
        elif args.command == 'listen':
            print('已认证；点击开发板设置中的发送系统信息。Ctrl+C 结束。')
            sock.settimeout(None)
            while True:
                op, body = receive(sock)
                if op == 0x80000001:
                    print(json.dumps(json.loads(body), ensure_ascii=False, indent=2))
        else:
            if not key:
                print('未提供 Key；开始 OTA 后，请在开发板屏幕确认升级请求。')
            digest = hashlib.md5(package).hexdigest().encode('ascii')
            layout = struct.unpack_from('<I', package, 8)[0]
            check_ota_layout(sock, layout)
            request(sock, 2, offset=2 if layout == 2 else 0, payload=struct.pack('<I', len(package)) + digest)
            # 上传和提交共用读取缓冲，保留一次读取中的后续响应或设备信息。
            reader = SocketReader(sock, read_ahead=OTA_RESPONSE_READ_SIZE)
            upload_ota_stream(
                sock, package, chunk_size=OTA_MAX_CHUNK_SIZE, window=OTA_TRANSFER_WINDOW,
                reader=reader,
                on_progress=lambda written: print(
                    f'\r写入 W25：{written}/{len(package)}', end='', flush=True))
            request(sock, 4, reader=reader)
            print(f'\n{version} 校验通过并提交安装，设备正在重启。')
    if args.command == 'ota':
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            time.sleep(3)
            try:
                with connect(args, key) as sock:
                    info = json.loads(request(sock, 1))
                print(json.dumps(info, ensure_ascii=False, indent=2))
                if info.get('version') == version:
                    print('新版本已启动。')
                else:
                    print('设备已恢复连接，请核对上面的固件版本。')
                return
            except (OSError, ValueError, RuntimeError):
                continue
        print('暂未重新连接，请在屏幕确认版本与网络地址。')


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        pass
    except (OSError, ValueError, RuntimeError) as exc:
        raise SystemExit(str(exc))


def validate_app_package(data):
    if len(data) < 128 or len(data) > 0x20000:
        raise ValueError('App 包大小错误')
    values = struct.unpack_from('<8s8I20s64sI', data)
    magic, fmt, header, app_id, abi, address, image, ram, checksum, version, _, header_crc = values
    if (magic != b'F750APP1' or fmt != 1 or header != 128 or app_id >= 15 or
            abi not in (1, 2) or address != 0xC0580000 or image + 128 != len(data) or
            not image <= ram <= 0x80000):
        raise ValueError('App 包格式或 ABI 错误，需要 1.0.0 模块底座')
    if zlib.crc32(data[:124]) & 0xffffffff != header_crc or zlib.crc32(data[128:]) & 0xffffffff != checksum:
        raise ValueError('App 包 CRC 校验失败')
    return app_id, version.split(b'\0', 1)[0].decode('ascii')


def validate_app_bundle(data):
    """Validate all entries before any device write; return independent FAPP images."""
    if len(data)<32 or len(data)>0x400000:
        raise ValueError('App bundle size invalid')
    magic,fmt,header,total,count,payload_crc,header_crc=struct.unpack_from('<8s6I',data)
    if magic!=b'F750APB1' or fmt!=1 or header!=32 or total!=len(data) or not 1<=count<=15:
        raise ValueError('App bundle header invalid')
    if zlib.crc32(data[:28])&0xffffffff!=header_crc or zlib.crc32(data[32:])&0xffffffff!=payload_crc:
        raise ValueError('App bundle CRC mismatch')
    items=[];seen=set();ranges=[];end=32+count*16
    for i in range(count):
        app_id,offset,size,crc=struct.unpack_from('<4I',data,32+i*16)
        if app_id in seen or offset<end or size<128 or offset+size>len(data):
            raise ValueError('App bundle entry invalid')
        if any(offset<b and a<offset+size for a,b in ranges):
            raise ValueError('App bundle entries overlap')
        package=data[offset:offset+size]
        if zlib.crc32(package)&0xffffffff!=crc:raise ValueError('App entry CRC mismatch')
        actual,version=validate_app_package(package)
        if actual!=app_id:raise ValueError('App entry ID mismatch')
        seen.add(app_id);ranges.append((offset,offset+size));items.append((app_id,version,package))
    return items
