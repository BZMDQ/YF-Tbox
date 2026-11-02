"""Authenticated LAN system-information and complete-package OTA client."""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import socket
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
OTA_LEGACY_CHUNK_SIZE = 1024
OTA_RAM_SIZE = 0x3C000
W78_MAX_HEX_SIZE = 512 * 1024
W78_CHUNK_SIZE = 32768
W78_PIPELINE_WINDOW = 2
W78_PIPELINE_NEGOTIATE = 31
W78_PIPELINE_DATA_LEGACY = 32
W78_PIPELINE_DATA = 33
W78_MAX_PAYLOAD = 16 * 1024
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
            13: '（Key 认证失败）',
            14: '（开发板拒绝了 OTA 请求或确认超时）',
            3: '（设备忙或已有升级任务）',
            4: '（W78 HEX 文件名或上传信息无效）',
            6: '（W78 HEX 分片偏移或长度不正确）',
            8: '（W78 Intel HEX 格式、校验和或 APROM 地址错误）',
            9: '（升级包校验失败）',
        }.get(status, '')
        super().__init__(f'设备返回错误 {status}{detail}')


def frame(op, offset=0, payload=b''):
    prefix = struct.pack('<4sIII', b'LNET', op, offset, len(payload))
    crc = zlib.crc32(payload, zlib.crc32(prefix)) & 0xffffffff
    return prefix + struct.pack('<I', crc) + payload


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
    def __init__(self, sock):
        self.sock = sock
        self.buffer = bytearray()

    def exact(self, count):
        while len(self.buffer) < count:
            part = self.sock.recv(count - len(self.buffer))
            if not part:
                raise ConnectionError('设备已关闭连接')
            self.buffer.extend(part)
        data = bytes(self.buffer[:count])
        del self.buffer[:count]
        return data


def receive(sock, reader=None):
    read_exact = reader.exact if reader is not None else lambda count: exact(sock, count)
    header = read_exact(20)
    magic, op, status, size, crc = HEADER.unpack(header)
    if magic != b'LNET' or size > 1024:
        raise ValueError('无效响应头')
    body = read_exact(size)
    if zlib.crc32(body, zlib.crc32(header[:16])) & 0xffffffff != crc:
        raise ValueError('响应 CRC 校验失败')
    if status:
        raise DeviceError(status)
    return op, body


def request(sock, op, offset=0, payload=b'', on_info=None, send_lock=None,
            reader=None):
    if send_lock is None:
        sock.sendall(frame(op, offset, payload))
    else:
        with send_lock:
            sock.sendall(frame(op, offset, payload))
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


def request_wait(sock, op, offset=0, payload=b'', on_info=None, send_lock=None,
                 reader=None, cancel=None, timeout=120, ignore_ops=(),
                 on_ignored=None):
    """发送一次请求，在可取消的短超时轮询中等待完整响应。"""
    packet = frame(op, offset, payload)
    if send_lock is None:
        sock.sendall(packet)
    else:
        with send_lock:
            sock.sendall(packet)

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
        sock.settimeout(old_timeout)


def upload_w78_window(sock, package, logical_chunk_size, session_id, stop_event,
                      on_progress=None, on_info=None, send_lock=None,
                      target=0, window=W78_PIPELINE_WINDOW, max_retries=3):
    """每个 32 KiB 逻辑块拆成不超过 16 KiB 的有序协议帧流水发送。"""
    total = len(package)
    frame_request = min(logical_chunk_size, W78_MAX_PAYLOAD)
    if session_id <= 0 or session_id > 0x00FFFFFF:
        raise ValueError('流水会话号超出 24 位范围。')

    # 新固件用外层 offset 携带会话号/序号，保留 16 KiB 的单帧数据上限。
    raw_mode = True
    hello = struct.pack('<IIII', session_id, window, frame_request, 1)
    try:
        caps = request(sock, W78_PIPELINE_NEGOTIATE, target, hello,
                       on_info=on_info, send_lock=send_lock)
    except DeviceError as exc:
        if exc.status == 4:
            # 旧固件仅接受 12 字节协商头，退回带会话和绝对偏移的旧帧格式。
            raw_mode = False
            legacy_request = min(logical_chunk_size, W78_MAX_PAYLOAD)
            hello = struct.pack('<III', session_id, window, legacy_request)
            try:
                caps = request(sock, W78_PIPELINE_NEGOTIATE, target, hello,
                               on_info=on_info, send_lock=send_lock)
            except DeviceError as legacy_exc:
                if legacy_exc.status in (11, 13):
                    return None
                raise
        elif exc.status in (11, 13):
            # 更旧固件不支持流水传输，由调用方改用顺序分包。
            return None
        else:
            raise
    if len(caps) != 24:
        raise ValueError('开发板返回的流水传输协商数据无效。')
    remote_session, max_data, remote_window, next_seq, next_offset, credits = struct.unpack('<6I', caps)
    protocol_limit = W78_MAX_PAYLOAD if raw_mode else W78_MAX_PAYLOAD - 8
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
    retries_total = 0
    send_credit = window
    old_timeout = sock.gettimeout()

    def send_packet(packet):
        if send_lock is None:
            sock.sendall(packet)
        else:
            with send_lock:
                sock.sendall(packet)

    try:
        while acked_offset < total:
            if stop_event is not None and stop_event.is_set():
                raise InterruptedError()
            sock.settimeout(old_timeout)
            while (next_send_offset < total and len(pending) < window
                   and send_credit > 0):
                if next_send_seq > 0xFF:
                    raise ValueError('HEX 分包数超过当前流水序号范围。')
                end = min(total, next_send_offset + frame_size)
                block = package[next_send_offset:end]
                if raw_mode:
                    # 24 位会话号和 8 位序号放在外层 offset，不挤占 16 KiB 帧数据。
                    wire_offset = (session_id << 8) | next_send_seq
                    payload = block
                else:
                    wire_offset = next_send_seq
                    payload = struct.pack('<II', session_id, next_send_offset) + block
                packet = frame(protocol_op, wire_offset, payload)
                send_packet(packet)
                pending[next_send_seq] = {
                    'offset': next_send_offset, 'end': end, 'packet': packet,
                    'sent_at': time.monotonic(), 'retries': 0,
                }
                sent_end[next_send_seq] = end
                next_send_offset = end
                next_send_seq += 1
                send_credit -= 1

            if not pending:
                raise ConnectionError('开发板未返回流水发送额度。')
            oldest = min(pending, key=lambda seq: pending[seq]['sent_at'])
            wait = max(0.05, min(1.0, 1.0 - (time.monotonic() - pending[oldest]['sent_at'])))
            sock.settimeout(wait)
            try:
                response, body = receive(sock, reader=reader)
            except socket.timeout:
                item = pending[oldest]
                if item['retries'] >= max_retries:
                    raise TimeoutError('HEX 分包多次重传仍未收到开发板确认。')
                sock.settimeout(old_timeout)
                send_packet(item['packet'])
                item['retries'] += 1
                item['sent_at'] = time.monotonic()
                retries_total += 1
                continue
            except DeviceError as exc:
                if exc.status != 1:
                    raise
                item = pending[oldest]
                if item['retries'] >= max_retries:
                    raise TimeoutError('HEX 分包校验多次失败，停止重传。')
                sock.settimeout(old_timeout)
                send_packet(item['packet'])
                item['retries'] += 1
                item['sent_at'] = time.monotonic()
                retries_total += 1
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
            if classification not in (0, 1, 2) or credit > window:
                raise ValueError('开发板 ACK 分类或接收额度无效。')

            if classification in (0, 1):
                if ack_seq >= next_send_seq or expected_seq <= ack_seq:
                    raise ValueError('开发板 ACK 序号未覆盖已接受分包。')
                for seq in list(pending):
                    if seq < expected_seq:
                        del pending[seq]
                if expected_offset > acked_offset:
                    acked_offset = expected_offset
                    if on_progress:
                        on_progress(acked_offset, total)
            elif classification == 2:
                # 设备告知它仍在等的序号；重传该分包，不把乱序数据写入 HEX 缓冲。
                missing = pending.get(expected_seq)
                if missing is not None:
                    if missing['retries'] >= max_retries:
                        raise TimeoutError('流水序号多次重传仍未被开发板接受。')
                    sock.settimeout(old_timeout)
                    send_packet(missing['packet'])
                    missing['retries'] += 1
                    missing['sent_at'] = time.monotonic()
                    retries_total += 1
            send_credit = min(window, credit)
    finally:
        sock.settimeout(old_timeout)
    return logical_chunk_size, frame_size, window, retries_total, raw_mode


def validate_package(package):
    if len(package) < 128:
        raise ValueError('升级包太短')
    magic, fmt, hsize, total, load, app, assets, ac, rc, pc, version, _ = struct.unpack_from('<8s9I20s60s', package)
    if magic != b'F750OTA1' or fmt != 1 or hsize != 128 or total != len(package):
        raise ValueError('请选择完整的 STM32F750_版本.ota.bin')
    if load != 0x20010000 or not 8 <= app <= OTA_RAM_SIZE or assets > 0x380000 or total != 128 + app + assets:
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


def validate_w78_hex(path):
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
    data_bytes = 0
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
            data_bytes += count
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
    if not eof or not data_bytes:
        raise ValueError('W78 HEX 必须包含数据记录和 EOF 记录。')
    return package


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


def connect(args, key, on_info=None, cancel=None):
    try:
        address = ipaddress.IPv4Address(args.host)
    except (ValueError, TypeError):
        address = None
    if address is None:
        sock = socket.create_connection((args.host, args.port), timeout=10)
    else:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            bind_lan_route(sock, args.host, cancel)
            sock.settimeout(10)
            sock.connect((args.host, args.port))
        except Exception:
            sock.close()
            raise
    # Authentication should be immediate. Keep its timeout bounded so a
    # rebooting device cannot stall reconnect checks for the OTA timeout.
    sock.settimeout(10)
    try:
        request(sock, 0, payload=key, on_info=on_info)
    except Exception:
        sock.close()
        raise
    sock.settimeout(120)  # W25 erase and final full-package validation.
    return sock


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
            request(sock, 2, payload=struct.pack('<I', len(package)) + digest)
            for offset in range(0, len(package), OTA_CHUNK_SIZE):
                block = package[offset:offset + OTA_CHUNK_SIZE]
                ack = request(sock, 3, offset, block)
                if len(ack) != 4 or struct.unpack('<I', ack)[0] != offset + len(block):
                    raise ValueError('下载进度响应错误')
                print(f'\r写入 W25：{offset+len(block)}/{len(package)}', end='', flush=True)
            request(sock, 4)
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
