"""D133经F750 USB的A/B更新；按能力协商窗口，写入命令均只发送一次。"""
from contextlib import closing
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import select
import struct
import time
import zlib

from d133_ota_client import PRODUCT, HARDWARE, validate_cpio
from local_tcp_client import HEADER, connect, exact, frame

INFO, DATA, COMMIT, HEALTH, BEGIN, CANCEL = 0xD100, 0xD102, 0xD103, 0xD105, 0xD106, 0xD107
LOGICAL_DATA = 0xD109
LEGACY_CHUNK_SIZE = 4096
LARGE_CHUNK_SIZE = 32768
LNET_MAX_PAYLOAD = 16384
LARGE_CHUNK_WINDOW = 2
REQUEST_TIMEOUT = 120
PROGRESS_INTERVAL = 0.2
MAX_PACKAGE = 5248 * 1024 + 8192
ERRORS = {1: '帧CRC错误', 3: 'D133或USB链路忙', 4: '参数、型号或硬件不匹配',
          6: '累计偏移错误', 9: '完整摘要错误',
          11: '固件不支持USB A/B更新；请先安装F750 1.4.49和D133 1.0.169或更新固件',
          14: 'D133屏幕拒绝或确认超时', 24: 'RSA签名验证失败', 25: 'Flash写入失败',
          27: '启动槽提交失败', 31: 'CPIO校验失败', 32: '官方Flash写入失败',
          100: 'F750尚未连接可用的D133 USB设备',
          101: 'F750到D133的USB超时或断开；旧版D133须先通过原TCP或SD安装1.0.169或更新固件',
          102: 'F750收到无效的D133 USB响应'}


class ProxyError(RuntimeError):
    def __init__(self, status):
        self.status = status
        super().__init__(f'D133 USB更新错误 {status}：{ERRORS.get(status, "设备返回未知错误")}')


@dataclass(frozen=True)
class Package:
    data: bytes
    signature: bytes
    version: str


def load_package(path, signature_path=None):
    """选择CPIO时必须同时存在同名签名；不接受任意另一包的签名路径。"""
    path = Path(path).resolve()
    if path.suffix.lower() != '.cpio':
        raise ValueError('请选择D133的ota.cpio文件')
    expected = Path(str(path) + '.sig')
    signature_path = Path(signature_path).resolve() if signature_path else expected
    if signature_path != expected:
        raise ValueError('签名必须与CPIO位于同一目录且命名为“CPIO文件名.sig”')
    if not 636 <= path.stat().st_size <= MAX_PACKAGE:
        raise ValueError('D133 CPIO长度超出USB更新范围')
    data = path.read_bytes()
    version = validate_cpio(data)
    signature = signature_path.read_bytes()
    if not 1 <= len(signature) <= 512:
        raise ValueError('同名RSA签名长度必须为1到512字节')
    return Package(data, signature, version)


def _send_request(sock, op, offset, payload):
    limit = LARGE_CHUNK_SIZE if op == LOGICAL_DATA else LEGACY_CHUNK_SIZE
    if len(payload) > limit:
        raise ValueError(f'D133 USB请求不得超过{limit}字节')
    if op == LOGICAL_DATA:
        # 逻辑块内连续发送物理帧，每个完整逻辑块只对应一次累计应答。
        if not payload:
            raise ValueError('D133 USB数据块不能为空')
        for part in range(0, len(payload), LNET_MAX_PAYLOAD):
            sock.sendall(frame(op, offset + part, payload[part:part + LNET_MAX_PAYLOAD]))
    else:
        sock.sendall(frame(op, offset, payload))


def _read_pending(sock, count, deadline, cancel):
    """在同一截止时间内读齐数据，半帧取消时由事务关闭连接。"""
    data = bytearray()
    while len(data) < count:
        _check_cancel(cancel)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('等待D133 USB数据累计确认超时')
        if not select.select([sock], [], [], min(.1, remaining))[0]:
            continue
        part = sock.recv(count - len(data))
        if not part:
            raise ConnectionError('设备已关闭连接')
        data.extend(part)
    return bytes(data)


def _receive_response(sock, op, cancel=None):
    """仅接收当前命令的有界应答，丢弃F750自动信息帧。"""
    if cancel is None:
        read = lambda count: exact(sock, count)
    else:
        deadline = time.monotonic() + (sock.gettimeout() or REQUEST_TIMEOUT)
        read = lambda count: _read_pending(sock, count, deadline, cancel)
    while True:
        header = read(HEADER.size)
        magic, response, status, size, crc = HEADER.unpack(header)
        if magic != b'LNET' or size > 1000:
            raise ValueError('D133代理响应头无效或长度超过1000字节')
        body = read(size)
        if zlib.crc32(body, zlib.crc32(header[:16])) & 0xffffffff != crc:
            raise ValueError('D133代理响应CRC错误')
        if response == 0x80000001 and status == 0:
            continue  # F750主动上报自身信息，不向D133信息解析器转交。
        if response != op | 0x80000000:
            raise ValueError('D133代理响应命令不匹配')
        if status:
            raise ProxyError(status)
        return body


def request(sock, op, offset=0, payload=b''):
    _send_request(sock, op, offset, payload)
    return _receive_response(sock, op)


def device_info(sock, op=INFO):
    info = json.loads(request(sock, op).decode('utf-8'))
    if not isinstance(info, dict) or (info.get('product'), info.get('hardware'),
            info.get('protocol'), info.get('usb_ota')) != (PRODUCT, HARDWARE, 1, 1):
        raise ValueError('目标不是兼容的D133 USB A/B服务；请先安装D133 1.0.169及F750 1.4.49或更新固件')
    if info.get('stream_ota', 0) < 2 or info.get('slot') not in ('A', 'B') or info.get('next_slot') not in ('A', 'B'):
        raise ValueError('D133槽位或流式写入能力字段无效')
    if not isinstance(info.get('confirmed'), bool) or not isinstance(info.get('version'), str):
        raise ValueError('D133版本或健康确认字段无效')
    return info


def _check_cancel(cancel, committed=False):
    if cancel is not None and cancel.is_set():
        raise InterruptedError('提交请求已发出；仅停止电脑等待，D133更新不能撤销，健康状态尚未确认' if committed
                               else '已停止未提交更新；非活动槽不会被激活')


def _ack(body, expected, operation):
    if body != struct.pack('<I', expected):
        raise ValueError(f'{operation}累计偏移ACK不匹配；未重发写入命令')


def _chunk_size(info):
    # 只有 F750 与 D133 都明确报告整数 32768，才在本次更新使用大块。
    limits = (info.get('relay_max_chunk'), info.get('usb_max_chunk'))
    if all(type(limit) is int and limit == LARGE_CHUNK_SIZE for limit in limits):
        return LARGE_CHUNK_SIZE
    return LEGACY_CHUNK_SIZE


def transfer(sock, package, info, progress, cancel=None, on_commit=None):
    """逐块核对累计确认，全部确认后才允许提交。"""
    if not info['confirmed'] or info['slot'] != info['next_slot']:
        raise ValueError('D133当前槽尚未健康确认，禁止开始下一次更新')
    _check_cancel(cancel)
    target = 'B' if info['slot'] == 'A' else 'A'
    chunk_size = _chunk_size(info)
    relay_window = info.get('relay_max_window')
    window = (LARGE_CHUNK_WINDOW if chunk_size == LARGE_CHUNK_SIZE and
              type(relay_window) is int and relay_window == LARGE_CHUNK_WINDOW else 1)
    data_op = LOGICAL_DATA if chunk_size == LARGE_CHUNK_SIZE else DATA
    total = len(package.data)
    metadata = struct.pack('<I32s32s32s32s', total, hashlib.sha256(package.data).digest(),
                           PRODUCT.encode(), HARDWARE.encode(), package.version.encode())
    committed = False
    sent = written = 0
    mode = f'数据块 {chunk_size // 1024} KiB，窗口 {window}'
    try:
        # 只有设备明确报告 JSON false 才免屏幕确认，旧固件缺少字段。
        if info.get('usb_screen_confirm') is False:
            confirmation = f'电脑端已确认，D133将校验签名并更新非活动槽{target}'
        else:
            confirmation = f'等待D133屏幕确认写入槽{target}'
        progress(0, f'D133 {info["version"]} / 槽{info["slot"]}；{mode}；{confirmation}')
        # BEGIN偏移2明确启用F750的双块缓存，窗口1继续使用原协议偏移0。
        request(sock, BEGIN, offset=window if window > 1 else 0, payload=metadata + package.signature)
        last_progress = started = time.monotonic()
        while written < total:
            _check_cancel(cancel)
            # 只用已核对的偏移释放窗口；收到一个ACK便补发下一块。
            while sent < min(total, written + window * chunk_size):
                _check_cancel(cancel)
                offset = sent
                sent = min(total, offset + chunk_size)
                _send_request(sock, data_op, offset, package.data[offset:sent])
            expected = min(written + chunk_size, total)
            _ack(_receive_response(sock, data_op, cancel=cancel if window > 1 else None), expected, 'DATA')
            written = expected
            # 速度按全链路累计ACK计时，节制界面刷新并始终显示最后一块。
            now = time.monotonic()
            if written == total or now - last_progress >= PROGRESS_INTERVAL:
                elapsed = max(now - started, .001)
                progress(written * 100 // total,
                         f'{mode}；写入非活动槽{target} {written:,}/{total:,} 字节；'
                         f'{written / 1024 / elapsed:.1f} KiB/s')
                last_progress = now
        _check_cancel(cancel)
        # 发送前即锁定提交状态；即使ACK丢失，也不得CANCEL或重放COMMIT。
        committed = True
        if on_commit:
            on_commit()
        progress(100, '正在完整校验并提交；此后仅等待D133重启与健康确认，请勿断电')
        try:
            _ack(request(sock, COMMIT), total, 'COMMIT')
        except ProxyError as exc:
            if exc.status not in (27, 100, 101, 102):
                raise
            progress(100, f'提交结果待核对（{exc}）；不重发，只读等待重启')
        except (OSError, ValueError) as exc:
            progress(100, f'提交ACK未确认（{exc}）；不重发，只读等待重启')
        return target
    except InterruptedError:
        if not committed:
            if sent > written:
                # 仍有未读的DATA ACK，断开由F750清理，避免把旧ACK当作取消应答。
                sock.close()
            else:
                try:
                    request(sock, CANCEL)
                except Exception as exc:
                    progress(0, f'取消应答未确认：{exc}；没有发送提交，请检查D133状态')
        raise


def monitor(connection, package, initial, target, progress, cancel=None, timeout=420):
    """仅健康查询可重连；版本、预先推导的目标槽和confirmed必须同时匹配。"""
    started = time.monotonic()
    while time.monotonic() - started < timeout:
        _check_cancel(cancel, committed=True)
        try:
            with connection() as sock:
                state = device_info(sock, HEALTH)
            if (state['version'] == package.version and state['slot'] == target and
                    state['next_slot'] == target and state['confirmed']):
                progress(100, f'D133 {package.version} / 槽{target}；重启和健康确认已核对')
                return package.version
            if (time.monotonic() - started > 30 and state['version'] == initial['version'] and
                    state['slot'] == initial['slot'] and state['next_slot'] == initial['slot'] and state['confirmed']):
                raise RuntimeError(f'D133仍在原槽{initial["slot"]} / {initial["version"]}，可能已回退或未切换；未确认更新成功')
        except (OSError, ValueError, ProxyError):
            pass  # 只重试只读查询，包含重启时USB暂未就绪的F750错误。
        if cancel is not None:
            cancel.wait(2)
        else:
            time.sleep(2)
    raise RuntimeError('提交请求已发出，420秒内未核对新版本、目标槽和健康确认；请检查D133屏幕及回退日志')


def upload(args, key, path, progress, cancel=None, on_commit=None, signature_path=None):
    if len(key) != 32:
        raise ValueError('D133经F750 USB更新必须导入配套32字节Local TCP Key')
    package = load_package(path, signature_path)

    def connection():
        # 沿用F750原认证与IPv4路由策略；认证信息帧始终属于F750。
        sock = connect(args, key, cancel=cancel, on_info=lambda _body: None)
        sock.settimeout(REQUEST_TIMEOUT)
        return closing(sock)

    with connection() as sock:
        initial = device_info(sock)
        target = transfer(sock, package, initial, progress, cancel, on_commit)
    progress(100, f'提交请求已发出；等待D133以{package.version}从槽{target}重启并健康确认')
    return monitor(connection, package, initial, target, progress, cancel)
