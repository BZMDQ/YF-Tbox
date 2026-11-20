"""F750单份内部BOOT打包与窗口1客户端；写入/提交失败不自动重放。"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
from pathlib import Path
import re
import struct
import sys
import time
import zlib

from local_tcp_client import DeviceError, request, parse_device_info

BASE = 0x08000000
IMAGE_SIZE = 65536
VERSION_OFFSET = 0xFA00
NEW_LAYOUT_STAMP = b'F750LAY2'
NEW_LAYOUT_FLAG = 8
BOARD_ID = 0x07500008
HEADER = struct.Struct('<8s7I20s68sI')
PACKAGE_SIZE = 128 + IMAGE_SIZE
CAP = struct.Struct('<4s4I20sI')
STATUS = struct.Struct('<5I')
OP_CAP, OP_BEGIN, OP_DATA, OP_COMMIT, OP_STATUS, OP_CANCEL = range(0x40, 0x46)
IDLE, RECEIVING, READY, QUEUED, WRITING, DONE, FAILED, CANCELED, UNCHANGED = range(9)
VERSION_PATTERN = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,18}\Z')
UPGRADE_REQUIRED = '该设备尚不支持内部 BOOT 更新，请先通过系统 OTA 升级到 1.4.43 或更新版本。'
RECOVERY_WARNING = '内部 BOOT 可能已部分写入；不要断电或重启，保持供电并用同一完整镜像手动重试，必要时用 ST-LINK 恢复。'


@dataclass(frozen=True)
class BootPackage:
    data: bytes
    image: bytes
    version: str
    image_crc32: int

    @property
    def md5(self):
        return hashlib.md5(self.data).hexdigest()


@dataclass(frozen=True)
class BootCapability:
    version: str
    image_crc32: int
    max_chunk: int
    flags: int


@dataclass(frozen=True)
class BootStatus:
    state: int
    error: int
    received: int
    total: int
    written: int


class BootUpdateError(RuntimeError):
    pass


class BootUpdateFailed(BootUpdateError):
    def __init__(self, status):
        self.status = status
        super().__init__(f'BOOT 更新失败：error={status.error}，已写 {status.written}/65536。{RECOVERY_WARNING}')


def _version(raw):
    if b'\0' not in raw:
        raise ValueError('BOOT 版本字段缺少 NUL 结束符')
    value = raw.split(b'\0', 1)[0].decode('ascii')
    if not VERSION_PATTERN.fullmatch(value):
        raise ValueError('BOOT 版本字段无效')
    return value


def validate_image(image):
    if len(image) != IMAGE_SIZE:
        raise ValueError('内部 BOOT 镜像必须恰好为 64KiB')
    sp, entry = struct.unpack_from('<II', image)
    if sp & 7 or not 0x20000000 < sp <= 0x20010000:
        raise ValueError('BOOT 初始栈地址不正确')
    code = entry & ~1
    if not entry & 1 or not BASE <= code <= BASE + IMAGE_SIZE - 2:
        raise ValueError('BOOT Thumb 入口超出内部 64KiB 范围')
    if image[code - BASE:code - BASE + 2] == b'\xff\xff':
        raise ValueError('BOOT 入口指向空白区域')
    return _version(image[VERSION_OFFSET:VERSION_OFFSET + 20])


def image_from_hex(path):
    """只接受内部64KiB数据，严格拒绝QSPI/选项字节/SRAM与冲突记录。"""
    image = bytearray(b'\xff' * IMAGE_SIZE)
    seen = bytearray(IMAGE_SIZE)
    base = 0
    eof = False
    populated = False
    for number, raw in enumerate(Path(path).read_text(encoding='ascii').splitlines(), 1):
        line = raw.strip()
        if not line:
            continue
        if eof or not line.startswith(':') or not re.fullmatch(r':[0-9A-Fa-f]+', line):
            raise ValueError(f'HEX 第 {number} 行格式无效或出现在 EOF 之后')
        try:
            record = bytes.fromhex(line[1:])
        except ValueError as exc:
            raise ValueError(f'HEX 第 {number} 行十六进制无效') from exc
        if len(record) < 5 or len(record) != record[0] + 5 or sum(record) & 255:
            raise ValueError(f'HEX 第 {number} 行长度或校验和错误')
        size, address, kind = record[0], int.from_bytes(record[1:3], 'big'), record[3]
        payload = record[4:-1]
        if kind == 0:
            first = base + address
            if address + size > 0x10000 or first < BASE or first + size > BASE + IMAGE_SIZE:
                raise ValueError(f'HEX 第 {number} 行越界；只允许 0x08000000..0x0800FFFF')
            for index, value in enumerate(payload):
                at = first - BASE + index
                if seen[at] and image[at] != value:
                    raise ValueError(f'HEX 地址0x{first + index:08X}存在冲突数据')
                image[at], seen[at] = value, 1
            populated |= bool(size)
        elif kind == 1:
            if size or address:
                raise ValueError('HEX EOF 记录格式错误')
            eof = True
        elif kind in (2, 4):
            if size != 2 or address:
                raise ValueError('HEX 扩展地址记录格式错误')
            base = int.from_bytes(payload, 'big') << (4 if kind == 2 else 16)
        elif kind in (3, 5):
            if size != 4 or address:
                raise ValueError('HEX 启动地址记录格式错误')
            start = (int.from_bytes(payload[:2], 'big') << 4) + int.from_bytes(payload[2:], 'big') if kind == 3 else int.from_bytes(payload, 'big')
            if not BASE <= (start & ~1) < BASE + IMAGE_SIZE:
                raise ValueError('HEX 启动地址超出内部BOOT范围')
        else:
            raise ValueError(f'HEX 不支持记录类型0x{kind:02X}')
    if not eof or not populated:
        raise ValueError('HEX 必须包含数据和 EOF 记录')
    validate_image(image)
    return bytes(image)


def build_package(image):
    image = bytes(image)
    version = validate_image(image)
    crc = zlib.crc32(image) & 0xffffffff
    header = HEADER.pack(b'F750BOT1', 1, 128, PACKAGE_SIZE, BASE, IMAGE_SIZE,
                         crc, BOARD_ID, version.encode().ljust(20, b'\0'), bytes(68), 0)
    header = header[:124] + struct.pack('<I', zlib.crc32(header[:124]) & 0xffffffff)
    return validate_package(header + image)


def validate_package(data):
    data = bytes(data)
    if len(data) != PACKAGE_SIZE:
        raise ValueError('BOOT 包长度必须为 65664 字节')
    magic, form, head, total, address, size, crc, board, raw_version, reserved, header_crc = HEADER.unpack_from(data)
    if (magic, form, head, total, address, size, board) != (b'F750BOT1', 1, 128, PACKAGE_SIZE, BASE, IMAGE_SIZE, BOARD_ID):
        raise ValueError('不是受支持的 F750BOT1 单份内部BOOT包')
    if any(reserved) or zlib.crc32(data[:124]) & 0xffffffff != header_crc:
        raise ValueError('BOOT 包头CRC或保留字段错误')
    image = data[128:]
    if zlib.crc32(image) & 0xffffffff != crc:
        raise ValueError('BOOT 完整64KiB镜像CRC错误')
    version = validate_image(image)
    if _version(raw_version) != version:
        raise ValueError('BOOT 包版本与0x0800FA00内部版本不匹配')
    return BootPackage(data, image, version, crc)


def load_package(path):
    path = Path(path)
    if path.suffix.lower() == '.hex':
        return build_package(image_from_hex(path))
    data = path.read_bytes()
    if len(data) == IMAGE_SIZE:
        return build_package(data)
    return validate_package(data)


def get_capability(sock, on_info=None):
    try:
        body = request(sock, OP_CAP, on_info=on_info)
    except DeviceError as exc:
        if exc.status in (4, 11, 12):
            raise BootUpdateError(UPGRADE_REQUIRED) from exc
        raise
    if len(body) != CAP.size:
        raise ValueError('BOOT 能力响应长度错误')
    magic, proto, total, chunk, flags, version, crc = CAP.unpack(body)
    if magic != b'BOT1' or proto != 1 or total != PACKAGE_SIZE or not 1 <= chunk <= 16384 or flags & 7 != 7:
        raise ValueError('BOOT 能力响应不符合单份/Key/无回滚协议')
    try:
        current_version = _version(version)
    except (ValueError, UnicodeError):
        # 擦写失败后内部版本区可能为空白；仍允许保留RAM镜像的人工恢复。
        # 目标包始终严格校验，成功核验也仍要求版本精确匹配。
        current_version = '未知/无效'
    return BootCapability(current_version, crc, chunk, flags)


def get_status(sock, on_info=None):
    body = request(sock, OP_STATUS, on_info=on_info)
    if len(body) != STATUS.size:
        raise ValueError('BOOT 状态响应长度错误')
    value = BootStatus(*STATUS.unpack(body))
    if value.state not in range(9) or value.total not in (0, PACKAGE_SIZE) or value.received > value.total or value.written > IMAGE_SIZE:
        raise ValueError('BOOT 状态字段越界')
    return value


def target_identity(info):
    if not isinstance(info, dict) or 'F750' not in str(info.get('board', '')).upper() or not info.get('uid'):
        raise BootUpdateError('内部 BOOT 更新只支持有明确UID的 STM32F750，D133及未知设备禁止使用。')
    return str(info['uid'])


def _check_cancel(cancel):
    if cancel is not None and cancel.is_set():
        raise InterruptedError('BOOT 操作已停止')


def cancel_staging(sock, on_info=None):
    """只由用户取消暂存/确认时调用；写入开始后调用者不得发送此命令。"""
    try:
        request(sock, OP_CANCEL, on_info=on_info)
    except DeviceError as exc:
        if exc.status == 3:
            return False  # 部分写入后的恢复镜像由固件保留，电脑端不得清掉。
        raise
    return True


def stage_package(sock, package, capability, cancel=None, on_progress=None, on_info=None):
    """严格窗口1；任何DATA/ACK错误立即结束，不重放写入或提交。"""
    package = validate_package(package.data if isinstance(package, BootPackage) else package)
    _check_cancel(cancel)
    # 以实际镜像标识核对 BOOT 布局，避免用版本字符串推断分区。
    new_boot = package.image[VERSION_OFFSET + 20:VERSION_OFFSET + 28] == NEW_LAYOUT_STAMP
    if new_boot != bool(capability.flags & NEW_LAYOUT_FLAG):
        raise ValueError('BOOT 镜像与开发板的 QSPI 布局不一致。首次切换请使用配套工厂 HEX。')
    body = request(sock, OP_BEGIN, payload=struct.pack('<I', PACKAGE_SIZE) + package.md5.encode('ascii'), on_info=on_info)
    if len(body) != 4:
        raise ValueError('BOOT BEGIN确认格式错误')
    received = struct.unpack('<I', body)[0]
    if received not in (0, PACKAGE_SIZE):
        raise ValueError('BOOT BEGIN返回了不允许的接收偏移')
    # FAILED的同MD5完整镜像可由板端重新验证回READY；这需要用户新发起一次动作。
    for offset in range(received, PACKAGE_SIZE, capability.max_chunk):
        _check_cancel(cancel)
        block = package.data[offset:offset + capability.max_chunk]
        ack = request(sock, OP_DATA, offset, block, on_info=on_info)
        received = offset + len(block)
        if len(ack) != 4 or struct.unpack('<I', ack)[0] != received:
            raise ValueError('BOOT DATA累计接收确认不匹配，未重发分片')
        if on_progress:
            on_progress(received, PACKAGE_SIZE)
    _check_cancel(cancel)
    status = get_status(sock, on_info)
    if status.state == FAILED:
        raise BootUpdateFailed(status)
    if status.state != READY or status.received != PACKAGE_SIZE or status.total != PACKAGE_SIZE:
        raise BootUpdateError('板端未确认完整BOOT镜像READY，禁止提交')
    if on_progress:
        on_progress(PACKAGE_SIZE, PACKAGE_SIZE)
    return status


def commit_once(sock, on_info=None):
    """单次排队提交。异常可能表示应答丢失，调用者只能只读查状态，不能重发。"""
    body = request(sock, OP_COMMIT, on_info=on_info)
    if len(body) != 4 or struct.unpack('<I', body)[0] not in (QUEUED, WRITING, DONE, UNCHANGED):
        raise ValueError('BOOT 提交确认格式/状态错误，未重发COMMIT')


def monitor_update(connection_factory, package, expected_uid, cancel=None,
                   on_status=None, on_info=None, timeout=90, poll_interval=0.25):
    """提交后只读监测；DONE也必须等Reset后IDLE并重连CAP版本+CRC核对。"""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        _check_cancel(cancel)
        try:
            with connection_factory() as sock:
                sock.settimeout(2)
                while time.monotonic() < deadline:
                    _check_cancel(cancel)
                    status = get_status(sock, on_info)
                    if on_status:
                        on_status(status)
                    if status.state == FAILED:
                        raise BootUpdateFailed(status)
                    if status.state in (UNCHANGED, IDLE):
                        cap = get_capability(sock, on_info)
                        info = parse_device_info(request(sock, 1, on_info=on_info))
                        if target_identity(info) != expected_uid:
                            raise BootUpdateError('重连设备UID不匹配，BOOT更新未确认')
                        if cap.version != package.version or cap.image_crc32 != package.image_crc32:
                            raise BootUpdateError('BOOT重连版本/完整镜像CRC不匹配，禁止判为成功。' + RECOVERY_WARNING)
                        return 'unchanged' if status.state == UNCHANGED else 'verified_after_reset'
                    if status.state == DONE:
                        # DONE仅表示板端读回通过；释放旧会话，让板端完成Reset后再查CAP。
                        break
                    if status.state == READY:
                        raise BootUpdateError('提交尚未确认，板端仍保留READY镜像；没有自动重发COMMIT，请手动检查后重试。')
                    if status.state == CANCELED:
                        raise BootUpdateError('板端BOOT暂存已取消，未确认更新')
                    if cancel is not None:
                        if cancel.wait(poll_interval): _check_cancel(cancel)
                    else:
                        time.sleep(poll_interval)
        except (ConnectionError, OSError):
            _check_cancel(cancel)
            # 仅查询状态/CAP允许断线后重新连接，绝不把BEGIN/DATA/COMMIT带入循环。
            pass
        if cancel is not None:
            if cancel.wait(poll_interval): _check_cancel(cancel)
        else:
            time.sleep(poll_interval)
    raise BootUpdateError('BOOT写入/重启核验超时，未判为成功。' + RECOVERY_WARNING)


def main():
    # Windows非中文区域/管道输出也使用UTF-8，避免打包完成后打印中文抛异常。
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8', errors='backslashreplace')
    parser = argparse.ArgumentParser(description='将单份内部BOOT HEX打包为F750BOT1；不连接设备。')
    parser.add_argument('--hex', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    package = build_package(image_from_hex(args.hex))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(package.data)
    print(f'BOOT {package.version} | 0x{BASE:08X}..0x{BASE+IMAGE_SIZE-1:08X} | CRC32={package.image_crc32:08X} | {len(package.data)}字节 | {args.output}')


if __name__ == '__main__':
    main()
