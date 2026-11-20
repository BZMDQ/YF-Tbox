"""Simple Windows GUI for the authenticated Local TCP / OTA client."""
from contextlib import contextmanager
import base64
from concurrent.futures import ThreadPoolExecutor, as_completed
import http.client
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import queue
import re
import shutil
import socket
import struct
import sys
import subprocess
import tempfile
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import font as tkfont
from types import SimpleNamespace
from urllib.parse import urlsplit
import uuid
import zlib

import customtkinter as ctk
from PIL import Image, ImageOps

from local_tcp_client import (
    DeviceError, OTA_MAX_CHUNK_SIZE, OTA_LEGACY_CHUNK_SIZE, OTA_TRANSFER_WINDOW, W78_CHUNK_SIZE,
    W78_LOGICAL_CHUNK_SIZES, SocketReader,
    W78_STATE_DONE, W78_STATE_FAILED, bind_lan_route, connect, frame, receive, request,
    upload_w78_window, validate_package, validate_w78_filename, validate_w78_hex, parse_device_info,
    request_wait, upload_ota_stream, W78StageTiming,
)
import boot_update_ui
import d133_proxy_ui
from operation_history import HistoryError, OperationHistory


APP_TITLE = '研发工具箱'
APP_VERSION = '0.8.70'
APP_ICON_FILE = 'research_toolbox.ico'
APP_LOGO_FILE = 'wslogo.png'
DEFAULT_PORT = 5000
W78_STATUS_INTERVAL = 0.10  # 顺序查询，快速任务更容易采到；不改变烧录传输窗口。
WIRELESS_HEX_MODE = 'hex'
WIRELESS_D133_MODE = 'd133'
TRANSFER_CHUNK_SIZES = (1024, 2048, 4096, 8192, 16384, OTA_MAX_CHUNK_SIZE)
SITE_RESOURCE_SLUG = re.compile(r'^[a-z0-9]+(?:-[a-z0-9]+)*$')
SITE_MAX_UPLOAD_BYTES = 1024 * 1024 * 1024
OTA_FILENAME = 'STM32F750_1.0.0.ota.bin'
F750_W25Q128_LOADER = 'W25Q128JVEIQ_STM32F7508-DK.stldr'
SWD_FREQUENCIES_KHZ = (
    10000, 8000, 4000, 3300, 1800, 1000, 950, 480,
    240, 200, 125, 100, 50, 25, 15, 5,
)
SWD_FREQUENCY_LABELS = {
    frequency: (
        f'{frequency:,} kHz ({frequency / 1000:g} MHz)'
        if frequency >= 1000 else f'{frequency:,} kHz'
    )
    for frequency in SWD_FREQUENCIES_KHZ
}
SWD_FREQUENCY_CHOICES = [
    SWD_FREQUENCY_LABELS[frequency] for frequency in SWD_FREQUENCIES_KHZ
]
UI_FRAME_INTERVAL_MS = 8  # Best-effort 120 Hz UI updates on high-refresh displays.
UI_EVENT_BATCH_LIMIT = 128
UI_EVENT_BUDGET_S = 0.008
SCROLL_EASING = 0.30
PIC24_U12_PART = '24FJ256DA210'
PIC24_U12_STAGE_HEX_ADDRESS = 0x8000
PIC24_U12_STATUS_HEX_ADDRESS = 0x54F00
PIC24_U12_STATUS_WORDS = 6
PIC24_U12_HEADER_SIZE = 36
PIC24_U12_MAX_STAGED_BYTES = ((0x54800 - PIC24_U12_STAGE_HEX_ADDRESS) // 4) * 3
PIC24_U12_IMAGE_WIDTH = 800
PIC24_U12_IMAGE_HEIGHT = 480
PIC24_U12_IMAGE_BYTES = PIC24_U12_IMAGE_WIDTH * PIC24_U12_IMAGE_HEIGHT * 2
# 使用 Radix Slate 与 Blue 色阶建立统一的浅色主题，保留品牌青色和状态色。
COLORS = {
    'background': '#F1F5F7',
    'sidebar': '#102B35',
    'sidebar_active': '#224652',
    'sidebar_text': '#B7CBD2',
    'sidebar_card': '#FFFFFF',
    'card': '#FFFFFF',
    'soft': '#EAF0F3',
    'input': '#FFFFFF',
    'border': '#DCE6EB',
    'text': '#102933',
    'muted': '#4D6570',
    'blue': '#006D5D',
    'blue_hover': '#005A4C',
    'teal': '#006D5D',
    'teal_hover': '#005A4C',
    'cyan': '#006D5D',
    'orange': '#AD5700',
    'orange_hover': '#8F4E00',
    'tip': '#EAF0F3',
    'success_bg': '#E0F4ED',
    'success_text': '#006A50',
    'warning_bg': '#FFF4D5',
    'warning_text': '#AD5700',
    'error_bg': '#FCEBEB',
    'error_text': '#A82B36',
    'info_bg': '#E6EDFE',
    'info_text': '#3A5BC7',
}



def _ihex_record(record_type, address, payload=b''):
    body = bytes((len(payload), (address >> 8) & 0xFF, address & 0xFF, record_type)) + payload
    return ':' + (body + bytes(((-sum(body)) & 0xFF,))).hex().upper() + '\n'


def read_intel_hex_memory(path):
    """Read Intel HEX records into an absolute-address byte map."""
    memory = {}
    base = 0
    eof_seen = False
    with Path(path).open('r', encoding='ascii', errors='strict') as handle:
        for line_number, raw_line in enumerate(handle, 1):
            line = raw_line.strip()
            if not line:
                continue
            if eof_seen or not line.startswith(':'):
                raise ValueError(f'HEX 第 {line_number} 行格式无效。')
            try:
                record = bytes.fromhex(line[1:])
            except ValueError as exc:
                raise ValueError(f'HEX 第 {line_number} 行包含无效字符。') from exc
            if len(record) < 5 or len(record) != record[0] + 5 or (sum(record) & 0xFF):
                raise ValueError(f'HEX 第 {line_number} 行长度或校验和无效。')
            count = record[0]
            address = (record[1] << 8) | record[2]
            record_type = record[3]
            payload = record[4:-1]
            if record_type == 0x00:
                for index, value in enumerate(payload):
                    absolute = base + address + index
                    previous = memory.get(absolute)
                    if previous is not None and previous != value:
                        raise ValueError(f'HEX 地址 0x{absolute:X} 存在冲突数据。')
                    memory[absolute] = value
            elif record_type == 0x01:
                if count or address:
                    raise ValueError(f'HEX 第 {line_number} 行 EOF 记录格式无效。')
                eof_seen = True
            elif record_type == 0x02 and count == 2:
                base = int.from_bytes(payload, 'big') << 4
            elif record_type == 0x04 and count == 2:
                base = int.from_bytes(payload, 'big') << 16
            elif record_type in (0x03, 0x05) and count == 4:
                continue
            else:
                raise ValueError(f'HEX 第 {line_number} 行记录类型无效。')
    if not eof_seen or not memory:
        raise ValueError('HEX 文件缺少数据或 EOF 结束记录。')
    return memory


def write_intel_hex_memory(memory, path):
    """Write an absolute-address byte map as checksummed Intel HEX records."""
    addresses = sorted(memory)
    with Path(path).open('w', encoding='ascii', newline='\n') as handle:
        active_upper = None
        index = 0
        while index < len(addresses):
            start = addresses[index]
            upper = start >> 16
            if upper != active_upper:
                handle.write(_ihex_record(0x04, 0, upper.to_bytes(2, 'big')))
                active_upper = upper
            payload = bytearray((memory[start],))
            index += 1
            while (index < len(addresses) and len(payload) < 16 and
                   addresses[index] == start + len(payload) and
                   (addresses[index] >> 16) == upper):
                payload.append(memory[addresses[index]])
                index += 1
            handle.write(_ihex_record(0x00, start & 0xFFFF, payload))
        handle.write(_ihex_record(0x01, 0, b''))


def rgb565_be_image(path):
    """Center-crop an image to 5:3 and convert it to the U12 RGB565 byte layout."""
    with Image.open(path) as source:
        image = ImageOps.exif_transpose(source).convert('RGB')
    target_ratio = 5 / 3
    source_ratio = image.width / image.height
    if source_ratio > target_ratio:
        crop_width = round(image.height * target_ratio)
        left = (image.width - crop_width) // 2
        image = image.crop((left, 0, left + crop_width, image.height))
    else:
        crop_height = round(image.width / target_ratio)
        top = (image.height - crop_height) // 2
        image = image.crop((0, top, image.width, top + crop_height))
    image = image.resize((PIC24_U12_IMAGE_WIDTH, PIC24_U12_IMAGE_HEIGHT), Image.Resampling.LANCZOS)
    source_rgb = image.tobytes()
    result = bytearray(PIC24_U12_IMAGE_BYTES)
    output_index = 0
    for index in range(0, len(source_rgb), 3):
        red, green, blue = source_rgb[index:index + 3]
        pixel = ((red & 0xF8) << 8) | ((green & 0xFC) << 3) | (blue >> 3)
        result[output_index] = (pixel >> 8) & 0xFF
        result[output_index + 1] = pixel & 0xFF
        output_index += 2
    return bytes(result), image


def create_pic24_u12_stage_hex(bridge_hex, image_chunk, image_offset,
                               image_length, chunk_index, chunk_count,
                               image_crc, destination, verify_u12=True):
    """Merge bridge firmware and one RGB565 chunk into a PIC24 Intel HEX image."""
    memory = read_intel_hex_memory(bridge_hex)
    header = bytearray(PIC24_U12_HEADER_SIZE)
    header[0:5] = b'U12B\x01'
    header[5:7] = int(chunk_index).to_bytes(2, 'little')
    header[7:9] = int(chunk_count).to_bytes(2, 'little')
    header[9:13] = int(image_length).to_bytes(4, 'little')
    header[13:17] = int(image_offset).to_bytes(4, 'little')
    header[17:21] = len(image_chunk).to_bytes(4, 'little')
    header[21:25] = (zlib.crc32(image_chunk) & 0xFFFFFFFF).to_bytes(4, 'little')
    header[25:29] = (image_crc & 0xFFFFFFFF).to_bytes(4, 'little')
    header[33] = 1 if verify_u12 else 0
    header[29:33] = (zlib.crc32(header[:29] + header[33:34]) & 0xFFFFFFFF).to_bytes(4, 'little')
    header[34:36] = b'\xFF\xFF'
    staged = bytes(header) + bytes(image_chunk)
    if len(staged) > PIC24_U12_MAX_STAGED_BYTES:
        raise ValueError('U12 图片分块超过 PIC24 可暂存范围。')
    padded = staged + (b'\xFF' * ((-len(staged)) % 3))
    encoded = bytearray()
    for index in range(0, len(padded), 3):
        encoded.extend(padded[index:index + 3])
        encoded.append(0x00)  # PIC24 HEX uses three program bytes plus one phantom byte.
    for index, value in enumerate(encoded):
        address = PIC24_U12_STAGE_HEX_ADDRESS + index
        previous = memory.get(address)
        if previous is not None and previous != value:
            raise ValueError(f'桥接程序与暂存数据地址冲突：0x{address:05X}。')
        memory[address] = value
    # The bridge erases this pending marker on startup and replaces it with
    # progress rows. It distinguishes no execution from an unfinished write.
    pending = b'U12P' + int(chunk_index).to_bytes(2, 'little') + bytes(12)
    for index in range(0, len(pending), 3):
        base = 0x54800 + (index // 3) * 4
        for offset, value in enumerate(pending[index:index + 3]):
            memory[base + offset] = value
        memory[base + 3] = 0
    write_intel_hex_memory(memory, destination)
    return len(staged)


def parse_pic24_u12_status(hex_path):
    """Read the bridge result marker from its reserved PIC24 program-memory row."""
    memory = read_intel_hex_memory(hex_path)
    marker = bytearray()
    for word in range(PIC24_U12_STATUS_WORDS):
        base = PIC24_U12_STATUS_HEX_ADDRESS + word * 4
        marker.extend(memory.get(base + offset, 0xFF) for offset in range(3))
    if marker[:3] != b'U12' or marker[3] not in (ord('O'), ord('E')):
        return None
    return {
        'success': marker[3] == ord('O'),
        'index': int.from_bytes(marker[4:6], 'little'),
        'error': int.from_bytes(marker[6:8], 'little'),
        'chunk_crc': int.from_bytes(marker[8:12], 'little'),
        'image_crc': int.from_bytes(marker[12:16], 'little'),
    }


def parse_pic24_u12_trace(hex_path):
    memory = read_intel_hex_memory(hex_path)
    phases = {
        1: '桥接已启动，正在检查分块头',
        2: '分块头通过，正在计算 PIC24 暂存 CRC',
        3: '暂存 CRC 通过，正在识别 U12',
        4: 'U12 已识别，正在擦除 Flash',
        5: '擦除完成，正在写入 U12',
        6: 'U12 写入完成，正在处理分块回读选项',
        7: '分块处理完成，正在处理整图校验/完成标记',
    }
    latest = '没有桥接启动记录；需检查 PIC24 运行、配置字或状态页写入'
    for slot in range(7):
        record = bytearray()
        for word in range(6):
            base = 0x54800 + slot * 0x100 + word * 4
            record.extend(memory.get(base + offset, 0xFF) for offset in range(3))
        if record[:4] == b'U12P':
            return '桥接启动未完成：PIC24 未运行桥接或状态页擦除失败'
        if record[:4] == b'U12R':
            phase = int.from_bytes(record[6:8], 'little')
            latest = phases.get(phase, f'未知桥接阶段 {phase}')
    return latest


def parse_swd_frequency(value):
    match = re.match(r'^\s*([\d,]+)\s*kHz\b', str(value), re.IGNORECASE)
    if match is None:
        raise ValueError('请选择有效的 SWD 下载频率。')
    frequency = int(match.group(1).replace(',', ''))
    if frequency not in SWD_FREQUENCIES_KHZ:
        raise ValueError('SWD 频率必须从下拉列表中选择。')
    return frequency


def app_directory():
    executable = sys.executable if getattr(sys, 'frozen', False) else __file__
    return Path(executable).resolve().parent


def discover_website_root():
    start = app_directory()
    for candidate in (start, *start.parents):
        if (candidate / 'catalog.json').is_file() and (candidate / 'downloads').is_dir():
            return candidate
    return None


def app_resource_path(name):
    bundle_dir = Path(getattr(sys, '_MEIPASS', Path(__file__).resolve().parent))
    return bundle_dir / name


def ascii_existing_path(path):
    """Return an existing ASCII path, using Windows 8.3 names when needed."""
    candidate = str(path)
    if os.name == 'nt' and not candidate.isascii():
        try:
            import ctypes
            short_path = ctypes.create_unicode_buffer(32768)
            get_short_path = ctypes.windll.kernel32.GetShortPathNameW
            get_short_path.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint]
            get_short_path.restype = ctypes.c_uint
            length = get_short_path(candidate, short_path, len(short_path))
            if length and length < len(short_path):
                candidate = short_path.value
        except (AttributeError, OSError, TypeError, ValueError):
            pass
    if candidate.isascii() and Path(candidate).exists():
        return Path(candidate)
    return None


def ascii_temp_directory():
    """Find a writable temporary directory whose path is ASCII-only."""
    candidates = [Path(tempfile.gettempdir())]
    system_root = os.environ.get('SystemRoot') or os.environ.get('WINDIR')
    if system_root:
        candidates.append(Path(system_root) / 'Temp')
    for candidate in candidates:
        ascii_candidate = ascii_existing_path(candidate)
        if ascii_candidate is None or not ascii_candidate.is_dir():
            continue
        try:
            probe = tempfile.mkdtemp(prefix='STM32T_', dir=str(ascii_candidate))
            Path(probe).rmdir()
            return ascii_candidate
        except OSError:
            continue
    return None


def cubeprogrammer_runtime(cli_path):
    """Return an ASCII CLI path, working directory, and optional temp copy."""
    cli_path = Path(cli_path)
    cli_directory = cli_path.parent
    ascii_cli = ascii_existing_path(cli_path)
    ascii_directory = ascii_existing_path(cli_directory)
    if (ascii_cli is not None and ascii_directory is not None
            and ascii_directory.is_dir()):
        return ascii_cli, ascii_directory, None

    temp_directory = ascii_temp_directory()
    if temp_directory is None:
        raise RuntimeError('无法为 CubeProgrammer 创建纯英文运行目录。')
    staged_root = Path(tempfile.mkdtemp(prefix='STM32C_', dir=str(temp_directory)))
    try:
        database_source = cli_directory.parent / 'Data_Base'
        if not database_source.is_dir():
            raise RuntimeError('找不到 STM32CubeProgrammer 器件数据库 Data_Base。')
        staged_programmer = staged_root / 'STM32CubeProgrammer'
        staged_bin = staged_programmer / 'bin'
        staged_bin.parent.mkdir(parents=True)
        shutil.copytree(cli_directory, staged_bin)
        shutil.copytree(database_source, staged_programmer / 'Data_Base')
        staged_cli = staged_bin / cli_path.name
        if not staged_cli.is_file():
            raise RuntimeError('临时 CubeProgrammer CLI 副本不完整。')
        return staged_cli, staged_bin, staged_root
    except Exception:
        shutil.rmtree(staged_root, ignore_errors=True)
        raise


def discover_pk3cmd(configured_path=''):
    """Find the MPLAB 8 PICkit 3 command-line programmer."""
    candidates = []
    if configured_path:
        candidates.append(Path(configured_path))
    app_root = app_directory()
    candidates.extend((
        app_root / 'PK3CMD.exe',
        app_root / 'MPLAB IDE' / 'Programmer Utilities' / 'PICkit3' / 'PK3CMD.exe',
    ))
    install_roots = []
    for variable in ('ProgramFiles(x86)', 'ProgramFiles'):
        value = os.environ.get(variable)
        if value:
            install_roots.append(Path(value))
    install_roots.extend((Path('C:/Program Files (x86)'), Path('C:/Program Files')))
    for root in install_roots:
        candidates.append(root / 'Microchip' / 'MPLAB IDE' /
                          'Programmer Utilities' / 'PICkit3' / 'PK3CMD.exe')
    for candidate in candidates:
        try:
            if candidate.is_file():
                return candidate.resolve()
        except OSError:
            continue
    return None


def copy_external_loader_to_ascii_temp(source):
    """Stage a CubeProgrammer loader at an ASCII-only path.

    CubeProgrammer can reject a valid .stldr when its path contains non-ASCII
    characters (for example, the Chinese portable-package directory name).
    Use a short temp path so the vendor CLI receives a path it can load.
    """
    return copy_file_to_ascii_temp(source, prefix='STM32L_', suffix='.stldr')


def create_ascii_temp_file(prefix, suffix):
    temp_directory = ascii_temp_directory()
    if temp_directory is None:
        raise RuntimeError('无法创建纯英文临时文件路径。')
    fd, filename = tempfile.mkstemp(
        prefix=prefix, suffix=suffix, dir=str(temp_directory))
    os.close(fd)
    return Path(filename)


def copy_file_to_ascii_temp(source, prefix, suffix):
    staged_path = create_ascii_temp_file(prefix, suffix)
    try:
        shutil.copyfile(source, staged_path)
        return staged_path
    except Exception:
        staged_path.unlink(missing_ok=True)
        raise


def atomic_write_json(path, values):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    import uuid
    temporary = str(path.with_name(path.name + '.' + uuid.uuid4().hex + '.save'))
    fd = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, 'O_BINARY', 0), 0o600)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as handle:
            json.dump(values, handle, ensure_ascii=False, indent=2)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, str(path))
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def settings_candidates():
    local = Path(os.environ.get('LOCALAPPDATA') or Path.home()) / 'LocalTCP_Tools' / 'settings.json'
    roaming = Path(os.environ.get('APPDATA') or Path.home()) / 'LocalTCP_Tools' / 'settings.json'
    home = Path.home() / '.LocalTCP_Tools' / 'settings.json'
    shared = app_directory().parent / 'LocalTCP_Tools_Data' / 'settings.json'
    portable = app_directory() / 'Data' / 'settings.json'
    return list(dict.fromkeys([local, roaming, home, shared, portable]))


def settings_file():
    candidates = settings_candidates()
    existing = []
    for path in candidates:
        try:
            if path.is_file():
                existing.append((path.stat().st_mtime_ns, path))
        except OSError:
            pass
    return max(existing, key=lambda item: item[0])[1] if existing else candidates[0]


def u12_recovery_state_path():
    root = Path(os.environ.get('LOCALAPPDATA') or Path.home())
    return root / 'ResearchToolbox' / 'U12Recovery' / 'pending.json'


def load_u12_recovery_state():
    state_path = u12_recovery_state_path()
    try:
        state = json.loads(state_path.read_text(encoding='utf-8'))
        backup_path = Path(state['backup_path'])
        if backup_path.is_file() and state.get('part') == PIC24_U12_PART:
            return state
    except (OSError, ValueError, KeyError, TypeError):
        pass
    return None


def inspect_intel_hex(path):
    """Validate Intel HEX and return address range and memory-region flags."""
    base = 0
    first = None
    last = None
    has_qspi = False
    has_internal_flash = False
    has_sram = False
    eof_seen = False
    with Path(path).open('r', encoding='ascii', errors='strict') as handle:
        for line_number, raw_line in enumerate(handle, 1):
            line = raw_line.strip()
            if not line:
                continue
            if eof_seen:
                raise ValueError(f'第 {line_number} 行出现在 EOF 记录之后。')
            if not line.startswith(':'):
                raise ValueError(f'第 {line_number} 行不是 Intel HEX 记录。')
            try:
                record = bytes.fromhex(line[1:])
            except ValueError as exc:
                raise ValueError(f'第 {line_number} 行包含无效十六进制数据。') from exc
            if len(record) < 5 or len(record) != record[0] + 5:
                raise ValueError(f'第 {line_number} 行记录长度不正确。')
            if sum(record) & 0xFF:
                raise ValueError(f'第 {line_number} 行校验和错误。')

            count = record[0]
            address = (record[1] << 8) | record[2]
            record_type = record[3]
            payload = record[4:-1]
            if record_type == 0x00:
                if count:
                    start = base + address
                    end = start + count - 1
                    first = start if first is None else min(first, start)
                    last = end if last is None else max(last, end)
                    if start <= 0x90FFFFFF and end >= 0x90000000:
                        has_qspi = True
                    if start <= 0x080FFFFF and end >= 0x08000000:
                        has_internal_flash = True
                    if start <= 0x2007FFFF and end >= 0x20000000:
                        has_sram = True
            elif record_type == 0x01:
                if count != 0 or address != 0:
                    raise ValueError(f'第 {line_number} 行 EOF 记录格式不正确。')
                eof_seen = True
            elif record_type == 0x02:
                if count != 2:
                    raise ValueError(f'第 {line_number} 行扩展段地址格式不正确。')
                base = int.from_bytes(payload, 'big') << 4
            elif record_type == 0x04:
                if count != 2:
                    raise ValueError(f'第 {line_number} 行扩展线性地址格式不正确。')
                base = int.from_bytes(payload, 'big') << 16
            elif record_type in (0x03, 0x05):
                if count != 4:
                    raise ValueError(f'第 {line_number} 行启动地址记录格式不正确。')
            else:
                raise ValueError(f'第 {line_number} 行使用了不支持的记录类型 0x{record_type:02X}。')

    if not eof_seen:
        raise ValueError('HEX 文件缺少 EOF 结束记录。')
    if first is None or last is None:
        raise ValueError('HEX 文件中没有可写入的数据记录。')
    return first, last, has_qspi, has_internal_flash, has_sram


def _intel_hex_record(record_type, address, payload=b''):
    body = bytes((len(payload), (address >> 8) & 0xFF, address & 0xFF, record_type)) + payload
    checksum = (-sum(body)) & 0xFF
    return ':' + (body + bytes((checksum,))).hex().upper() + '\n'


def write_intel_hex_without_qspi(source, destination):
    """Write a valid HEX copy with 0x90000000–0x90FFFFFF data removed."""
    base = 0
    output_upper = None
    written_bytes = 0
    qspi_start = 0x90000000
    qspi_end = 0x90FFFFFF
    with Path(source).open('r', encoding='ascii', errors='strict') as src, \
            Path(destination).open('w', encoding='ascii', newline='\n') as dst:
        for raw_line in src:
            line = raw_line.strip()
            if not line:
                continue
            record = bytes.fromhex(line[1:])
            count = record[0]
            address = (record[1] << 8) | record[2]
            record_type = record[3]
            payload = record[4:-1]
            if record_type == 0x00 and count:
                absolute = base + address
                end = absolute + count
                segments = []
                if absolute < qspi_start:
                    segment_end = min(end, qspi_start)
                    if segment_end > absolute:
                        segments.append((absolute, payload[:segment_end - absolute]))
                if end > qspi_end + 1:
                    segment_start = max(absolute, qspi_end + 1)
                    if end > segment_start:
                        segments.append((segment_start, payload[segment_start - absolute:]))
                for segment_start, segment_data in segments:
                    offset = 0
                    while offset < len(segment_data):
                        current_address = segment_start + offset
                        upper = (current_address >> 16) & 0xFFFF
                        if upper != output_upper:
                            dst.write(_intel_hex_record(0x04, 0, upper.to_bytes(2, 'big')))
                            output_upper = upper
                        room = 0x10000 - (current_address & 0xFFFF)
                        size = min(255, len(segment_data) - offset, room)
                        dst.write(_intel_hex_record(
                            0x00, current_address & 0xFFFF,
                            segment_data[offset:offset + size]))
                        offset += size
                        written_bytes += size
            elif record_type == 0x02:
                base = int.from_bytes(payload, 'big') << 4
            elif record_type == 0x04:
                base = int.from_bytes(payload, 'big') << 16
            else:
                dst.write(line + '\n')
    if not written_bytes:
        raise ValueError('这个 HEX 文件只有扩展 Flash 数据；请勾选“下载扩展 Flash（QSPI）”后再烧录。')
    return written_bytes


def decode_programmer_output(raw_line):
    """Decode CLI output across Windows code pages and suppress garbled progress glyphs."""
    if isinstance(raw_line, str):
        text = raw_line
    else:
        text = raw_line.decode('utf-8', errors='replace')
        if '\ufffd' in text and '%' not in text and os.name == 'nt':
            legacy = raw_line.decode('mbcs', errors='replace')
            if legacy.count('\ufffd') < text.count('\ufffd'):
                text = legacy
    text = re.sub(r'\x1B\[[0-?]*[ -/]*[@-~]', '', text)
    text = text.replace('\x1b', '').replace('\r', '\n')
    text = re.sub(r'[\ufffd\u2500-\u259f]+', ' ', text)
    text = ''.join(char for char in text if char.isprintable() or char == '\n')
    return re.sub(r'[ \t]+', ' ', text).strip()


def normalize_device_info(data):
    """Use one resolution field and omit retired telemetry, including legacy packets."""
    if not isinstance(data, dict):
        return data
    values = {key: value for key, value in data.items()
              if not str(key).lower().startswith(('mqtt', 'sdram'))}
    if 'screen_resolution' not in values and 'lcd_width' in values and 'lcd_height' in values:
        values['screen_resolution'] = str(values['lcd_width']) + 'x' + str(values['lcd_height'])
    diagnostic = values.get('net_diag')
    if isinstance(diagnostic, list) and diagnostic:
        keys = ['uart_errors', 'rx_overflows', 'retries', 'failed_state', 'error', 'local_tcp_errors']
        named = {'uart_baud': diagnostic[0]}
        named.update({key: value for key, value in zip(keys, diagnostic[1:]) if value})
        named['status'] = '存在诊断记录' if len(named) > 1 else '正常'
        values['net_diag'] = named
    elif isinstance(diagnostic, dict):
        named = dict(diagnostic)
        named['status'] = '正常' if named.get('status') == 'ok' else '存在诊断记录'
        values['net_diag'] = named
    values.pop('qspi_mapped', None)
    values.pop('lcd_width', None)
    values.pop('lcd_height', None)
    return values


class LocalTcpApp:
    def __init__(self, root):
        self.root = root
        self.device_received_var = tk.StringVar(master=root, value='尚未收到设备数据')
        self.device_info_cache = None
        logo = Image.open(app_resource_path(APP_LOGO_FILE)).convert('RGBA')
        self.logo_image = ctk.CTkImage(light_image=logo, dark_image=logo, size=(68, 40))
        self.font_family = self._choose_font(root)
        self.base_dir = app_directory()
        self.default_key_path = self.base_dir / 'local_tcp_access.key'
        self.key_path = None
        self.key_disabled = False
        self.default_ota = self.base_dir / OTA_FILENAME
        self.events = queue.Queue()
        self.socket_lock = threading.Lock()
        self.active_socket = None
        self.connecting_socket = None
        self.active_ota_sockets = {}
        self.ota_socket_cancel_allowed = {}
        self.ota_batch_running = False
        self.ota_device_rows = {}
        self.w78_program_started = False
        self.ota_send_lock = threading.Lock()
        self.w78_send_lock = threading.Lock()
        self.process_lock = threading.Lock()
        self.active_process = None
        self.programmer_runtime_source = None
        self.programmer_runtime_cli = None
        self.programmer_runtime_workdir = None
        self.programmer_runtime_temp = None
        self.stop_event = None
        self.is_running = False
        self.task_thread = None
        self.close_pending = False
        self.package_path = None
        self.package_version = None
        self.boot_image_path = self.boot_package = None
        self.boot_update_running = self.boot_commit_started = False
        d133_proxy_ui.initialize(self, sys.modules[__name__])
        self.boot_progress = None
        self.boot_file_var = tk.StringVar(master=root, value='未选择BOOT HEX或boot.bin')
        self.boot_detail_var = tk.StringVar(master=root, value='仅内部0x08000000..0x0800FFFF，完整64KiB；先升级系统1.4.43。')
        self.boot_status_var = tk.StringVar(master=root, value='只暂存到RAM，完整镜像READY后再确认单份原址提交。')
        self.progress = None
        self.w78_progress = None
        self.hex_progress = None
        self.mplab_progress = None
        self.u12_progress = None
        self.device_metric_vars = {}
        self.device_metric_detail_vars = {}
        self.active_page_key = None
        self._scroll_after_ids = {}
        self._scroll_targets = {}
        settings = self._load_settings()
        self.ui_language = settings.get('language', 'zh-CN')
        try:
            self.ota_chunk_size = int(settings.get('ota_chunk_size', OTA_MAX_CHUNK_SIZE))
        except (TypeError, ValueError):
            self.ota_chunk_size = OTA_MAX_CHUNK_SIZE
        if self.ota_chunk_size not in TRANSFER_CHUNK_SIZES:
            self.ota_chunk_size = OTA_MAX_CHUNK_SIZE
        try:
            self.w78_chunk_size = int(settings.get('w78_chunk_size', W78_CHUNK_SIZE))
        except (TypeError, ValueError):
            self.w78_chunk_size = W78_CHUNK_SIZE
        if self.w78_chunk_size not in W78_LOGICAL_CHUNK_SIZES:
            self.w78_chunk_size = W78_CHUNK_SIZE
        self.key_disabled = bool(settings.get('key_disabled', False))
        candidates = []
        saved_key_path = settings.get('key_path')
        if not self.key_disabled and isinstance(saved_key_path, str) and saved_key_path.strip():
            candidates.append(Path(saved_key_path))
        if not self.key_disabled and self.default_key_path not in candidates:
            candidates.append(self.default_key_path)
        for candidate in candidates:
            try:
                self._read_key_file(candidate)
                self.key_path = candidate.resolve()
                break
            except (OSError, ValueError):
                continue
        self.host_var = tk.StringVar(value=settings.get('host', ''))
        self.port_var = tk.StringVar(value=str(settings.get('port', DEFAULT_PORT)))
        self.w78_host_var = tk.StringVar(
            value=str(settings.get('w78_host', settings.get('host', '')) or ''))
        self.ota_hosts_text = str(settings.get('ota_hosts', '') or '')

        self.hex_name_var = tk.StringVar(value='未选择 HEX 文件')
        self.hex_path_detail_var = tk.StringVar(value='选择由 STM32CubeIDE、Keil 等生成的 Intel HEX 文件。')
        self.hex_memory_summary_var = tk.StringVar(value='选择 HEX 后自动检查数据地址和外部 Flash。')
        self.hex_extension_download_var = tk.BooleanVar(value=False)
        try:
            saved_swd_frequency = int(settings.get('swd_frequency_khz', 4000))
        except (TypeError, ValueError):
            saved_swd_frequency = 4000
        if saved_swd_frequency not in SWD_FREQUENCIES_KHZ:
            saved_swd_frequency = 4000
        self.swd_frequency_var = tk.StringVar(
            value=SWD_FREQUENCY_LABELS[saved_swd_frequency])
        self.hex_progress_indeterminate = False
        self.stlink_status_var = tk.StringVar(value='尚未检测')
        self.stlink_check_running = False
        self.stlink_poll_after_id = None
        self.stm32_programmer_cli_path = str(
            settings.get('stm32_programmer_cli_path', '') or '')
        self.hex_file = None
        self.hex_has_external_data = False
        self.hex_has_internal_flash = False
        self.hex_has_sram = False
        self.hex_address_range = None
        self.mplab_file = None
        self.mplab_address_range = None
        self.mplab_device_var = tk.StringVar(value=str(settings.get('mplab_device', '')))
        self.mplab_cli_path = discover_pk3cmd(settings.get('pk3cmd_path', ''))
        self.mplab_cli_path_var = tk.StringVar(
            value=str(self.mplab_cli_path) if self.mplab_cli_path else '未找到 PK3CMD.exe')
        self.mplab_tool_status_var = tk.StringVar(
            value='已找到 MPLAB 烧录命令' if self.mplab_cli_path else '未找到烧录命令')
        self.mplab_hex_name_var = tk.StringVar(value='未选择 Intel HEX 文件')
        self.mplab_hex_path_var = tk.StringVar(value='选择 PIC24 工程生成的 .hex 文件。')
        self.mplab_hex_summary_var = tk.StringVar(value='选择文件后会检查 HEX 格式和地址范围。')
        self.mplab_progress_indeterminate = False
        self.u12_image_path = None
        self.u12_image_data = None
        self.u12_preview = None
        self.u12_recovery_state = load_u12_recovery_state()
        self.u12_progress_indeterminate = False
        self.u12_image_name_var = tk.StringVar(value='未选择图片')
        self.u12_image_path_var = tk.StringVar(value='支持 PNG、JPG、BMP 等常见图片格式。')
        self.u12_image_detail_var = tk.StringVar(value='选择图片后自动转换为 800 × 480 RGB565。')
        self.u12_recovery_status_var = tk.StringVar(value='当前没有待恢复的 PIC24 备份。')
        self.u12_progress_text_var = tk.StringVar(value='等待选择图片')
        self.manual_key_var = tk.StringVar(value='')
        self.key_var = tk.StringVar(value=self.key_path.name if self.key_path else '未导入 key 文件')
        self.package_var = tk.StringVar(value='未选择升级包')
        self.package_hint_var = tk.StringVar(value='')
        self.w78_hex_path = None
        self.w78_hex_name_var = tk.StringVar(value='未选择 HEX 文件')
        self.w78_hex_summary_var = tk.StringVar(value='—')
        self.w78_progress_text_var = tk.StringVar(value='等待选择 HEX 文件')
        self.status_var = tk.StringVar(value='就绪')
        self.connection_summary_var = tk.StringVar(value='未设置设备 IP')
        self.connection_state_var = tk.StringVar(value='未连接')
        self.key_summary_var = tk.StringVar(value='尚未导入')
        self.key_entries = []
        self.key_visibility_buttons = []
        self.key_visible = False
        self.host_var.trace_add('write', self._update_summaries)
        self.port_var.trace_add('write', self._update_summaries)
        self.manual_key_var.trace_add('write', self._update_summaries)
        self.key_var.trace_add('write', self._update_summaries)

        self._build_workspace()
        if self.default_ota.is_file():
            try:
                self._set_package(self.default_ota)
            except Exception as exc:
                self.package_var.set(OTA_FILENAME)
                self.package_hint_var.set(f'默认升级包无效：{exc}')
        self._append_log('请确认电脑与开发板在同一可互访的局域网。')
        self._append_log('在开发板“设置 → NETWORK >”开启 Local TCP / OTA，并填写屏幕显示的 IP 地址。')
        if self.key_path is None:
            self._append_log('未导入 Key：仍可读取设备信息；进行 OTA 时需在开发板确认。')
        self.root.after(UI_FRAME_INTERVAL_MS, self._poll_events)
        self.root.protocol('WM_DELETE_WINDOW', self._on_close)
        # 提前查询物理网卡，点击连接时直接使用短期缓存；此处不访问开发板。
        threading.Thread(target=self._prewarm_network, name='LAN-prewarm', daemon=True).start()

    @staticmethod
    def _prewarm_network():
        try:
            from device_directory import lan_interfaces
            lan_interfaces()
        except Exception:
            # 预热失败不阻止界面打开，真正建连时仍按正常流程重新查询。
            pass

    def _load_settings(self):
        try:
            values = json.loads(settings_file().read_text(encoding='utf-8'))
            return values if isinstance(values, dict) else {}
        except (OSError, ValueError, TypeError):
            return {}

    def _save_settings(self):
        try:
            path = settings_file()
            path.parent.mkdir(parents=True, exist_ok=True)
            try:
                port = int(self.port_var.get())
                if not 1 <= port <= 65535:
                    port = DEFAULT_PORT
            except ValueError:
                port = DEFAULT_PORT
            try:
                swd_frequency = parse_swd_frequency(self.swd_frequency_var.get())
            except ValueError:
                swd_frequency = 4000
            values = {
                'host': self.host_var.get().strip(),
                'port': port,
                'w78_host': self.w78_host_var.get().strip()
                if hasattr(self, 'w78_host_var') else '',
                'language': self.ui_language,
                'ota_chunk_size': self.ota_chunk_size,
                'w78_chunk_size': self.w78_chunk_size,
                'ota_hosts': (
                    self.ota_hosts_input.get('1.0', 'end-1c').strip()
                    if hasattr(self, 'ota_hosts_input') else self.ota_hosts_text
                ),
                'key_path': str(self.key_path) if self.key_path else '',
                'key_disabled': self.key_disabled,
                'swd_frequency_khz': swd_frequency,
                'mplab_device': self.mplab_device_var.get().strip(),
                'pk3cmd_path': str(self.mplab_cli_path) if self.mplab_cli_path else '',
                'stm32_programmer_cli_path': self.stm32_programmer_cli_path,
            }
            if hasattr(self, 'device_names'):
                values['device_names'] = self.device_names
                values['device_name_dirty'] = self.device_name_dirty
                values['device_uids'] = self.device_uids
                values['device_scan_ranges'] = self.device_scan_ranges
            self._enqueue_settings_write(path, values)
        except (OSError, ValueError) as exc:
            self._post('log', '配置保存失败：' + str(exc))

    def _enqueue_settings_write(self, path, values):
        # Snapshot Tk values on the UI thread; only file I/O runs in the worker.
        snapshot = json.loads(json.dumps(values, ensure_ascii=False))
        if not hasattr(self, '_settings_write_lock'):
            self._settings_write_lock = threading.Lock()
            self._settings_write_pending = None
            self._settings_write_running = False
        with self._settings_write_lock:
            self._settings_write_pending = (path, snapshot)
            if self._settings_write_running:
                return
            self._settings_write_running = True
        def worker():
            while True:
                with self._settings_write_lock:
                    task = self._settings_write_pending
                    self._settings_write_pending = None
                    if task is None:
                        self._settings_write_running = False
                        return
                target, data = task
                try:
                    errors = []
                    for candidate in dict.fromkeys([target] + settings_candidates()):
                        try:
                            atomic_write_json(candidate, data)
                            if 'device_names' in data:
                                atomic_write_json(candidate.with_name('device_names.json'), {
                                    'format': 1, 'device_names': data['device_names'],
                                    'device_name_dirty': data.get('device_name_dirty', {}),
                                    'device_uids': data.get('device_uids', {}),
                                })
                            if candidate != target:
                                self._post('log', '原配置目录不可写，已保存到备用位置：' + str(candidate))
                            break
                        except OSError as exc:
                            errors.append(str(exc))
                    else:
                        raise OSError('; '.join(errors))
                    self._post('settings_saved', None)
                except (OSError, ValueError) as exc:
                    self._post('settings_saved', str(exc))
        threading.Thread(target=worker, name='settings-writer', daemon=False).start()

    def _open_settings(self):
        existing = getattr(self, 'settings_window', None)
        if existing is not None:
            try:
                if existing.winfo_exists():
                    existing.lift()
                    return
            except tk.TclError:
                pass

        dialog = ctk.CTkToplevel(self.root)
        self.settings_window = dialog
        dialog.title('设置')
        dialog.geometry('540x510')
        dialog.resizable(False, False)
        dialog.transient(self.root)
        dialog.grab_set()

        card = self._card(dialog)
        card.pack(fill='both', expand=True, padx=15, pady=15)
        ctk.CTkLabel(card, text='工具设置', font=self._font(19, 'bold'),
                     text_color=COLORS['text']).pack(anchor='w', padx=18, pady=(17, 4))
        ctk.CTkLabel(
            card, text='选择界面语言，并设置网络发送分块大小。',
            font=self._font(10), text_color=COLORS['muted'], anchor='w',
        ).pack(fill='x', padx=18, pady=(0, 14))

        def add_setting_row(label, variable, values):
            row = ctk.CTkFrame(card, fg_color='transparent')
            row.pack(fill='x', padx=18, pady=7)
            row.grid_columnconfigure(0, weight=1)
            ctk.CTkLabel(row, text=label, font=self._font(11, 'bold'),
                         text_color=COLORS['text'], anchor='w').grid(
                row=0, column=0, sticky='ew', padx=(0, 10))
            menu = ctk.CTkOptionMenu(
                row, variable=variable, values=values, width=148, height=32,
                corner_radius=8, font=self._font(10, 'bold'),
                fg_color=COLORS['soft'], button_color=COLORS['blue'],
                button_hover_color=COLORS['blue_hover'], text_color=COLORS['text'],
                dropdown_fg_color=COLORS['card'], dropdown_text_color=COLORS['text'],
                dropdown_hover_color=COLORS['soft'],
            )
            menu.grid(row=0, column=1, sticky='e')
            return menu

        language_labels = {'zh-CN': '简体中文', 'zh-TW': '繁體中文'}
        self.settings_language_var = tk.StringVar(
            master=dialog, value=language_labels.get(self.ui_language, '简体中文'))
        self.settings_ota_chunk_var = tk.StringVar(
            master=dialog, value=f'{self.ota_chunk_size // 1024} KiB')
        self.settings_w78_chunk_var = tk.StringVar(
            master=dialog, value=f'{self.w78_chunk_size // 1024} KiB')
        add_setting_row('界面语言', self.settings_language_var,
                        ['简体中文', '繁體中文'])
        add_setting_row('F750 系统 OTA 分片', self.settings_ota_chunk_var,
                        [f'{size // 1024} KiB' for size in TRANSFER_CHUNK_SIZES])
        add_setting_row('无线烧录逻辑块大小', self.settings_w78_chunk_var,
                        ['4 KiB', '8 KiB', '16 KiB', '32 KiB'])
        ctk.CTkLabel(
            card, text='系统 OTA 的 32 KiB 和窗口 2 需 F750 1.4.78；旧固件自动回退。',
            font=self._font(9), text_color=COLORS['muted'], anchor='w',
        ).pack(fill='x', padx=18, pady=(9, 5))

        ctk.CTkLabel(card, text='IP 扫描范围（留空自动扫描；最多 4096 个地址）',
                     anchor='w').pack(fill='x', padx=18, pady=(8, 3))
        self.settings_scan_var = tk.StringVar(master=dialog, value=self.device_scan_ranges)
        scan_entry = ctk.CTkEntry(card, textvariable=self.settings_scan_var,
                                 placeholder_text='192.168.21.1-192.168.21.254 或 192.168.21.0/24')
        scan_entry.pack(fill='x', padx=18, pady=(0, 6))
        ctk.CTkLabel(card, text='多个范围用分号分隔。刷新设备会读取开发板当前名称。',
                     text_color=COLORS['muted']).pack(fill='x', padx=18)

        actions = ctk.CTkFrame(card, fg_color='transparent')
        actions.pack(fill='x', padx=18, pady=(13, 16))

        def close_dialog():
            try:
                dialog.grab_release()
            except tk.TclError:
                pass
            dialog.destroy()

        def save_settings():
            language_label = self.settings_language_var.get()
            new_language = 'zh-CN' if language_label.startswith(('简', '簡')) else 'zh-TW'
            try:
                ota_kib = int(self.settings_ota_chunk_var.get().split()[0])
                w78_kib = int(self.settings_w78_chunk_var.get().split()[0])
            except (TypeError, ValueError, IndexError):
                messagebox.showerror('设置无效', '请选择有效的发送速度。', parent=dialog)
                return
            if ota_kib * 1024 not in TRANSFER_CHUNK_SIZES or w78_kib * 1024 not in W78_LOGICAL_CHUNK_SIZES:
                messagebox.showerror('设置无效', '请选择有效的发送速度。', parent=dialog)
                return
            try:
                from device_directory import configured_targets
                configured_targets(self.settings_scan_var.get())
            except ValueError as exc:
                messagebox.showerror('扫描范围无效', str(exc), parent=dialog)
                return
            self.device_scan_ranges = self.settings_scan_var.get().strip()
            self.ui_language = new_language
            self.ota_chunk_size = ota_kib * 1024
            self.w78_chunk_size = w78_kib * 1024
            self._save_settings()
            self._apply_ui_language(new_language)
            close_dialog()

        ctk.CTkButton(
            actions, text='取消', command=close_dialog, width=92, height=34,
            corner_radius=8, fg_color='transparent', border_width=1,
            border_color=COLORS['border'], hover_color=COLORS['soft'],
            text_color=COLORS['muted'], font=self._font(10, 'bold'),
        ).pack(side='right', padx=(8, 0))
        ctk.CTkButton(
            actions, text='保存并应用', command=save_settings, width=112, height=34,
            corner_radius=8, fg_color=COLORS['teal'],
            hover_color=COLORS['teal_hover'], text_color='#FFFFFF',
            font=self._font(10, 'bold'),
        ).pack(side='right')
        dialog.protocol('WM_DELETE_WINDOW', close_dialog)

    def _build_workspace(self):
        self.root.title(f'{APP_TITLE} | {APP_VERSION}')
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        width = min(1360, max(980, screen_width - 30))
        height = min(840, max(650, screen_height - 65))
        self.root.geometry(f'{width}x{height}')
        self.root.minsize(min(width, 980), min(height, 690))
        self.root.configure(fg_color=COLORS['background'])
        shell = ctk.CTkFrame(self.root, fg_color='transparent')
        shell.pack(fill='both', expand=True)
        shell.grid_columnconfigure(0, weight=0)
        shell.grid_columnconfigure(1, weight=1)
        shell.grid_rowconfigure(0, weight=1)

        self.rail_width = 258 if width >= 1230 else 220
        sidebar = ctk.CTkFrame(shell, width=208 if width >= 1230 else 170,
                               fg_color=COLORS['sidebar'], corner_radius=0)
        sidebar.grid(row=0, column=0, sticky='nsw')
        sidebar.grid_propagate(False)
        sidebar.grid_columnconfigure(0, weight=1)
        sidebar.grid_rowconfigure(9, weight=1)

        brand = ctk.CTkFrame(sidebar, fg_color='transparent')
        brand.grid(row=0, column=0, sticky='ew', padx=16, pady=(21, 19))
        # 采用稿中的红色标志，WINSTAR 字样单独排版，深色导航上仍清楚。
        from PIL import ImageDraw
        symbol = Image.new('RGBA', (62, 52))
        draw = ImageDraw.Draw(symbol)
        for points in (((0,2),(8,2),(12,9),(4,9)), ((10,2),(18,2),(22,9),(14,9)),
                       ((20,2),(27,2),(31,9),(24,9)), ((5,12),(13,12),(17,20),(9,20)),
                       ((15,12),(23,12),(27,20),(19,20))):
            draw.polygon([(x * 2, y * 2) for x, y in points], fill='#F44954')
        self.nav_brand = ctk.CTkImage(light_image=symbol, dark_image=symbol, size=(31, 26))
        ctk.CTkLabel(brand, image=self.nav_brand, text='').grid(row=0, column=0, rowspan=2, padx=(0, 9))
        ctk.CTkLabel(brand, text='WINSTAR', font=('Consolas', 11),
                     text_color=COLORS['sidebar_text'], height=16).grid(row=0, column=1, sticky='w')
        ctk.CTkLabel(brand, text='研发工具箱', font=self._font(16, 'bold'),
                     text_color='#FFFFFF', height=22).grid(row=1, column=1, sticky='w')
        self.nav_buttons = {}
        self.nav_icons = {}
        items = [('home', '设备总览', 'grid'), ('listen', '设备信息', 'device'),
                 ('w78', '无线烧录', 'flash'), ('ota', '固件升级', 'update'),
                 ('devices', '地址管理', 'network'), ('fixture', '测试用具', 'test'),
                 ('boot', '内部 BOOT', 'chip')]
        for index, (page, label, icon) in enumerate(items, 1):
            self.nav_icons[page] = self._nav_icon(icon, COLORS['sidebar_text'])
            button = ctk.CTkButton(sidebar, text=label, image=self.nav_icons[page], anchor='w',
                height=42, corner_radius=8, font=self._font(13), fg_color='transparent',
                text_color=COLORS['sidebar_text'], hover_color=COLORS['sidebar_active'],
                command=lambda selected=page: self._show_page(selected))
            button.grid(row=index, column=0, sticky='ew', padx=12, pady=2)
            self.nav_buttons[page] = button
        self.settings_button = ctk.CTkButton(sidebar, text='设置', anchor='w', height=40,
            image=self._nav_icon('settings', COLORS['sidebar_text']),
            fg_color='transparent', hover_color=COLORS['sidebar_active'],
            text_color=COLORS['sidebar_text'], command=self._open_settings)
        self.settings_button.grid(row=10, column=0, sticky='ew', padx=12)
        ctk.CTkLabel(sidebar, text=f'WINDOWS  /  {APP_VERSION}', font=('Consolas', 11),
            text_color=COLORS['sidebar_text']).grid(row=11, column=0, sticky='w', padx=16, pady=(0, 12))

        content = ctk.CTkFrame(shell, fg_color='transparent')
        content.grid(row=0, column=1, sticky='nsew', padx=(22, 20), pady=(15, 13))
        content.grid_columnconfigure(0, weight=1)
        content.grid_rowconfigure(1, weight=1)

        header = ctk.CTkFrame(content, fg_color='transparent')
        header.grid(row=0, column=0, columnspan=2, sticky='ew', pady=(0, 15))
        header.grid_columnconfigure(0, weight=1)
        title_block = ctk.CTkFrame(header, fg_color='transparent')
        title_block.grid(row=0, column=0, sticky='w')
        self.page_title_var = tk.StringVar(value='设备总览')
        ctk.CTkLabel(title_block, textvariable=self.page_title_var,
                     font=self._font(25, 'bold'), text_color=COLORS['text']).pack(anchor='w')
        header_actions = ctk.CTkFrame(header, fg_color='transparent')
        header_actions.grid(row=0, column=1, sticky='e')
        ctk.CTkLabel(header_actions, textvariable=self.connection_summary_var,
            font=self._font(12, 'bold'), text_color=COLORS['text'],
            wraplength=220).pack(side='left', padx=(0, 8))
        self.connection_state_label = ctk.CTkLabel(header_actions, textvariable=self.connection_state_var,
            font=self._font(11, 'bold'), text_color=COLORS['muted'],
            fg_color=COLORS['success_bg'], padx=10, corner_radius=12)
        self.connection_state_label.pack(side='left')
        # 右栏独立滚动；停止按钮固定在栏顶，切换导航仍可操作。
        rail = ctk.CTkFrame(content, width=self.rail_width, fg_color='transparent')
        rail.grid(row=1, column=1, rowspan=2, sticky='nsew', padx=(16, 0))
        rail.grid_propagate(False)
        rail.grid_columnconfigure(0, weight=1)
        rail.grid_rowconfigure(1, weight=1)
        self.running_card = self._card(rail)
        self.running_card.grid(row=0, column=0, sticky='ew', pady=(0, 9))
        self.status_label = ctk.CTkLabel(self.running_card, text='● 就绪',
            font=self._font(11, 'bold'), text_color=COLORS['muted'], fg_color=COLORS['soft'],
            wraplength=self.rail_width - 30, corner_radius=9, padx=9, pady=4)
        self.status_label.pack(fill='x', padx=12, pady=(10, 5))
        self.stop_button = ctk.CTkButton(self.running_card, text='停止当前操作',
            command=self._confirm_stop, height=40, corner_radius=8,
            font=self._font(12, 'bold'), fg_color=COLORS['error_bg'],
            hover_color=COLORS['error_bg'], text_color=COLORS['error_text'], state=tk.DISABLED)
        self.stop_button.pack(fill='x', padx=12, pady=(0, 10))
        self.running_card.grid_remove()
        self.rail_host = ctk.CTkScrollableFrame(rail, fg_color='transparent', corner_radius=0,
            width=self.rail_width - 20, scrollbar_button_color=COLORS['soft'])
        self.rail_host.grid(row=1, column=0, sticky='nsew')
        self.rail_host.grid_columnconfigure(0, weight=1)
        self.page_rails = {}

        self.pages_frame = ctk.CTkFrame(content, fg_color='transparent')
        self.pages_frame.grid(row=1, column=0, sticky='nsew')
        self.pages_frame.grid_columnconfigure(0, weight=1)
        self.pages_frame.grid_rowconfigure(0, weight=1)
        self.pages = {}
        self.action_widgets = []
        self.action_widgets.append(self.settings_button)
        # Build the landing page first. Construct other pages only when opened.
        self.page_builders = {
            'listen': self._build_listen_page,
            'ota': self._build_ota_page,
            'w78': self._build_w78_page,
            'devices': self._build_devices_page,
            'fixture': self._build_test_fixture_page,
            'boot': self._build_boot_page,
        }
        self._build_home_page()
        self._install_smooth_scrolling()

        activity = self._card(content)
        activity.grid(row=2, column=0, sticky='ew', pady=(8, 0))
        self.log_open = False
        activity.grid_columnconfigure(0, weight=1)
        activity.grid_rowconfigure(1, weight=1)
        log_header = ctk.CTkFrame(activity, fg_color='transparent')
        log_header.grid(row=0, column=0, sticky='ew', padx=14, pady=(7, 4))
        log_header.grid_columnconfigure(0, weight=1)
        self.log_toggle = ctk.CTkButton(log_header, text='详细记录  ▸',
            command=self._toggle_log, anchor='w', fg_color='transparent',
            hover_color=COLORS['soft'], text_color=COLORS['text'], width=110, height=28,
            font=self._font(12, 'bold'))
        self.log_toggle.grid(row=0, column=0, sticky='w')
        self.clear_log_button = ctk.CTkButton(
            log_header, text='清空', width=52, height=26, font=self._font(10),
            corner_radius=7, fg_color='transparent', hover_color=COLORS['soft'],
            text_color=COLORS['muted'], command=self._clear_log,
        )
        self.clear_log_button.grid(row=0, column=2, sticky='e')
        self.log = ctk.CTkTextbox(
            activity, height=112, wrap='word', corner_radius=9,
            border_width=1, border_color=COLORS['border'],
            fg_color=COLORS['input'], text_color=COLORS['text'],
            font=self._font(12), activate_scrollbars=True,
        )
        self.log.grid(row=1, column=0, sticky='ew', padx=12, pady=(0, 9))
        self.log.grid_remove()
        self.clear_log_button.grid_remove()
        self._show_page('home')

    def _confirm_stop(self):
        if getattr(self, 'd133_proxy_running', False):
            text = ('已提交。停止后，D133 仍会完成升级。' if self.d133_proxy_committed
                    else '停止更新？已写入的数据不会切换启动槽。')
        elif getattr(self, 'w78_program_started', False):
            text = '停止烧录？目标可能需要重新烧录。'
        else:
            self._stop_operation()
            return
        if messagebox.askyesno('停止当前操作', text, parent=self.root, default='no'):
            self._stop_operation()

    def _toggle_log(self):
        self.log_open = not self.log_open
        self.log_toggle.configure(text='详细记录  ▾' if self.log_open else '详细记录  ▸')
        for widget in (self.log, self.clear_log_button):
            if self.log_open:
                widget.grid()
            else:
                widget.grid_remove()

    def _rail_card(self, page, title, row=0):
        # 按页管理操作栏，控件的父容器固定，避免切换时重建业务控件。
        parent = self.page_rails.get(page)
        if parent is None:
            parent = ctk.CTkFrame(self.rail_host, fg_color='transparent')
            parent.grid(row=0, column=0, sticky='ew')
            parent.grid_remove()
            parent.grid_columnconfigure(0, weight=1)
            self.page_rails[page] = parent
        card = self._card(parent)
        card.grid(row=row, column=0, sticky='ew', pady=(0, 12))
        if title:
            ctk.CTkLabel(card, text=title, font=self._font(15, 'bold')).pack(
                anchor='w', padx=13, pady=(12, 7))
        return card

    def _rail_button(self, card, text, command, primary=False):
        make = self._primary_button if primary else self._secondary_button
        button = make(card, text, command, width=100)
        button.pack(fill='x', padx=12, pady=(4, 9))
        return button

    def _nav_icon(self, kind, color):
        from PIL import ImageDraw
        img = Image.new('RGBA', (72, 72))
        d = ImageDraw.Draw(img)
        def path(*pts):
            d.line([(x*3, y*3) for x, y in pts], fill=color, width=5, joint='curve')
        def rect(x, y, a, b):
            path((x,y),(a,y),(a,b),(x,b),(x,y))
        if kind == 'grid':
            for x in (3,14):
                for y in (4,14):
                    rect(x,y,x+7,y+7)
        elif kind == 'device':
            rect(4,5,20,16); path((12,16),(12,20)); path((8,20),(16,20))
        elif kind == 'flash':
            path((13,2),(4,14),(11,14),(10,22),(20,10),(13,10),(13,2))
        elif kind == 'update':
            path((12,3),(12,15)); path((7,8),(12,3),(17,8)); path((4,15),(4,20),(20,20),(20,15))
        elif kind == 'network':
            for left, top, right, bottom in [(1,5,23,22),(5,10,19,22),(9,15,15,21)]:
                d.arc((left*3,top*3,right*3,bottom*3), 212, 328, fill=color, width=5)
            d.ellipse((33,57,39,63), fill=color)
        elif kind == 'test':
            path((9,3),(15,3)); path((10,3),(10,9),(4,21),(20,21),(14,9),(14,3)); path((7,15),(17,15))
        elif kind == 'chip':
            rect(6,6,18,18); rect(10,10,14,14)
            for x in (9,15):
                path((x,2),(x,6)); path((x,18),(x,22)); path((2,x),(6,x)); path((18,x),(22,x))
        else:
            path((4,7),(20,7)); path((4,17),(20,17)); path((9,4),(9,10)); path((15,14),(15,20))
        return ctk.CTkImage(light_image=img, dark_image=img, size=(19,19))

    def _register_action(self, widget):
        self.action_widgets.append(widget)
        return widget

    def _page(self, key):
        page = ctk.CTkScrollableFrame(
            self.pages_frame, fg_color='transparent', corner_radius=0,
            scrollbar_button_color=COLORS['soft'],
            scrollbar_button_hover_color=COLORS['teal'],
        )
        page.grid(row=0, column=0, sticky='nsew')
        page.grid_columnconfigure(0, weight=1)
        self.pages[key] = page
        return page

    def _page_card(self, page, row, column=0, columnspan=1, pady=(0, 12)):
        card = self._card(page)
        card.grid(row=row, column=column, columnspan=columnspan,
                  sticky='nsew', padx=0, pady=pady)
        return card

    def _field_label(self, parent, text, row, column, padx=(0, 0)):
        ctk.CTkLabel(parent, text=text, font=self._font(10, 'bold'),
                     text_color=COLORS['muted']).grid(row=row, column=column,
                                                       sticky='w', padx=padx, pady=(0, 6))

    def _new_entry(self, parent, variable, placeholder='', width=None, show=None):
        options = {}
        if width is not None:
            options['width'] = width
        if show is not None:
            options['show'] = show
        entry = ctk.CTkEntry(
            parent, textvariable=variable, placeholder_text=placeholder,
            height=40, corner_radius=9,
            border_color=COLORS['border'], fg_color=COLORS['input'],
            text_color=COLORS['text'], placeholder_text_color=COLORS['muted'],
            font=self._font(14),
            **options,
        )
        return self._register_action(entry)

    def _primary_button(self, parent, text, command, width=170, accent='blue'):
        return self._register_action(ctk.CTkButton(
            parent, text=text, command=command, width=width, height=42,
            corner_radius=8, font=self._font(18, 'bold'),
            fg_color=COLORS[accent], hover_color=COLORS[f'{accent}_hover'],
            text_color='#FFFFFF',
        ))

    def _secondary_button(self, parent, text, command, width=150):
        return self._register_action(ctk.CTkButton(
            parent, text=text, command=command, width=width, height=38,
            corner_radius=8, font=self._font(12, 'bold'),
            fg_color=COLORS['soft'], hover_color=COLORS['border'],
            text_color=COLORS['text'], border_width=1,
            border_color=COLORS['border'],
        ))

    def _build_home_page(self):
        page = self._page('home')
        devices = self._page_card(page, 0)
        ctk.CTkLabel(devices, text='设备', font=self._font(18, 'bold')).pack(
            anchor='w', padx=16, pady=(13, 6))
        self.overview_rows = ctk.CTkFrame(devices, fg_color='transparent')
        self.overview_rows.pack(fill='x', padx=13, pady=(0, 11))
        recent = self._page_card(page, 1)
        ctk.CTkLabel(recent, text='最近操作 · 24 小时', font=self._font(16, 'bold')).pack(
            anchor='w', padx=16, pady=(13, 5))
        self.history_view = ctk.CTkTextbox(recent, height=145, wrap='word', corner_radius=8,
            fg_color=COLORS['card'], text_color=COLORS['text'], font=self._font(12))
        self.history_view.pack(fill='x', padx=12, pady=(0, 10))
        self.operation_history = None
        self.history_rows = None
        self.history_warned = False
        try:
            self.operation_history = OperationHistory(settings_file().with_name('operation_history.sqlite3'))
        except (HistoryError, OSError):
            pass
        self._refresh_history()
        self.root.after(60_000, self._age_history)
        self.home_connect_card = self._rail_card('home', '设备连接')
        fields = ctk.CTkFrame(self.home_connect_card, fg_color='transparent')
        self.home_target_fields = fields
        fields.pack(fill='x', padx=12, pady=5)
        fields.grid_columnconfigure(0, weight=1)
        self._field_label(fields, '设备 IP', 0, 0)
        self.host_entry = self._new_entry(fields, self.host_var, 'IPv4 地址', width=108)
        self.host_entry.grid(row=1, column=0, sticky='ew')
        self._field_label(fields, '端口', 0, 1, padx=(7, 0))
        self.port_entry = self._new_entry(fields, self.port_var, width=57)
        self.port_entry.grid(row=1, column=1, padx=(7, 0), sticky='ew')
        self.info_button = self._rail_button(self.home_connect_card, '连接并读取', self._read_once)
        key_card = self._rail_card('home', '工具密钥', row=2)
        key_row = ctk.CTkFrame(key_card, fg_color='transparent')
        key_row.pack(fill='x', padx=12, pady=4)
        key_row.grid_columnconfigure(0, weight=1)
        self.key_entry_home = self._new_entry(key_row, self.manual_key_var, '密钥', width=90, show='•')
        self.key_entries.append(self.key_entry_home)
        self.key_entry_home.grid(row=0, column=0, sticky='ew')
        self.key_visibility_button = self._secondary_button(key_row, '显示', self._toggle_key_visibility, width=46)
        self.key_visibility_buttons.append(self.key_visibility_button)
        self.key_visibility_button.grid(row=0, column=1, padx=(5, 0))
        self.key_name_label = ctk.CTkLabel(key_card, textvariable=self.key_var,
            font=self._font(10), text_color=COLORS['muted'], wraplength=170, anchor='w')
        self.key_name_label.pack(fill='x', padx=12, pady=4)
        self.import_key_button = self._rail_button(key_card, '导入密钥', self._choose_key)
        self.clear_key_button = self._rail_button(key_card, '不使用密钥', self._clear_key)
        quick = self._rail_card('home', '快捷操作', row=1)
        for label, target in [('无线烧录', 'w78'), ('固件升级', 'ota'), ('测试用具', 'fixture')]:
            self._rail_button(quick, label, lambda key=target: self._show_page(key))

    def _build_listen_page(self):
        page = self._page('listen')
        page.grid_columnconfigure(0, weight=1)
        intro = self._page_card(page, 0, pady=(0, 10))
        intro.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(intro, textvariable=self.device_received_var, font=self._font(12),
                     text_color=COLORS['muted']).grid(row=0, column=0, sticky='w', padx=16, pady=10)
        rail = self._rail_card('listen', '设备操作')
        self._rail_button(rail, '读取设备信息', self._read_once, primary=True)
        self.listen_button = self._rail_button(rail, '保持信息连接', self._listen)

        data_card = self._page_card(page, 1, pady=(0, 8))
        data_card.grid_columnconfigure(0, weight=1)
        header = ctk.CTkFrame(data_card, fg_color='transparent')
        header.grid(row=0, column=0, sticky='ew', padx=15, pady=(10, 2))
        header.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(header, text='收到的状态', font=self._font(16, 'bold'),
                     text_color=COLORS['text']).grid(row=0, column=0, sticky='w')

        grid = ctk.CTkFrame(data_card, fg_color='transparent')
        grid.grid(row=1, column=0, sticky='ew', padx=8, pady=(2, 8))
        grid.grid_columnconfigure((0, 1, 2), weight=1, uniform='device-metric')
        metric_specs = (
            ('version', '固件版本'),
            ('board', '开发板型号'),
            ('framework', 'UI 框架'),
            ('uid', '设备 UID'),
            ('device_name', '设备名称'),
            ('uptime_ms', '运行时长'),
            ('hclk_hz', 'HCLK 主频'),
            ('screen_resolution', '屏幕分辨率'),
            ('touch_ready', '触摸状态'),
            ('flash_jedec', 'Flash JEDEC'),
            ('backlight_compare', '背光比较值'),
            ('ui_frames', 'UI 帧数'),
        )
        self.device_metric_vars = {}
        self.device_metric_detail_vars = {}
        for index, (key, title) in enumerate(metric_specs):
            row, column = divmod(index, 3)
            tile = ctk.CTkFrame(grid, fg_color=COLORS['soft'], corner_radius=11,
                                border_width=1, border_color=COLORS['border'])
            tile.grid(row=row, column=column, sticky='nsew', padx=4, pady=4)
            tile.grid_columnconfigure(0, weight=1)
            ctk.CTkLabel(tile, text=title, font=self._font(12, 'bold'),
                         text_color=COLORS['muted']).grid(
                row=0, column=0, sticky='w', padx=11, pady=(9, 2))
            value_var = tk.StringVar(value='—')
            detail_var = tk.StringVar(value='')
            self.device_metric_vars[key] = value_var
            self.device_metric_detail_vars[key] = detail_var
            ctk.CTkLabel(tile, textvariable=value_var, font=self._font(18, 'bold'),
                         text_color=COLORS['text'], anchor='w', justify='left',
                         wraplength=240).grid(row=1, column=0, sticky='ew', padx=11, pady=(0, 1))
            ctk.CTkLabel(tile, textvariable=detail_var, font=self._font(12),
                         text_color=COLORS['muted'], anchor='w', justify='left',
                         wraplength=240).grid(row=2, column=0, sticky='ew', padx=11, pady=(0, 8))

        if self.device_info_cache is not None:
            self._update_device_metric_values(self.device_info_cache)


    def _build_ota_page(self):
        page = self._page('ota')
        page.grid_columnconfigure(0, weight=1)
        card = self._page_card(page, 0, pady=(0, 8))
        self._build_named_selector(card, 'ota')
        file_box = ctk.CTkFrame(card, fg_color=COLORS['soft'], corner_radius=12)
        file_box.pack(fill='x', padx=18, pady=(0, 15))
        file_box.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(file_box, textvariable=self.package_var, wraplength=390, justify="left", font=self._font(12, 'bold'),
                     text_color=COLORS['text'], anchor='w').grid(row=0, column=0, sticky='ew', padx=14, pady=(13, 3))
        self.package_hint_label = ctk.CTkLabel(file_box, textvariable=self.package_hint_var,
                                              font=self._font(10), text_color=COLORS['cyan'], anchor='w')
        self.package_hint_label.grid(row=1, column=0, sticky='ew', padx=14, pady=(0, 13))
        self.ota_file_box = file_box
        self.ota_rail = self._rail_card('ota', '升级操作')
        self.browse_button = self._rail_button(self.ota_rail, '选择系统 OTA…', self._choose_package)

        ctk.CTkLabel(
            card, text='目标设备',
            font=self._font(12, 'bold'), text_color=COLORS['text'],
        ).pack(anchor='w', padx=18, pady=(8, 6))
        self.ota_hosts_input = self._register_action(ctk.CTkTextbox(
            card, height=78, wrap='none', corner_radius=9,
            border_width=1, border_color=COLORS['border'],
            fg_color=COLORS['input'], text_color=COLORS['text'],
            font=self._font(12), activate_scrollbars=True,
        ))
        # 系统 OTA 与设置共用目标列表；App 功能随完整固件统一更新。
        if self.ota_hosts_text:
            self.ota_hosts_input.insert('1.0', self.ota_hosts_text)
        manual_row = ctk.CTkFrame(card, fg_color='transparent')
        manual_row.pack(fill='x', padx=18, pady=(0, 6))
        manual_row.grid_columnconfigure(0, weight=1)
        self.ota_manual_ip_var = tk.StringVar(master=self.root)
        manual_entry = self._register_action(ctk.CTkEntry(
            manual_row, textvariable=self.ota_manual_ip_var,
            placeholder_text='IPv4 地址', height=34))
        manual_entry._toolbox_user_data = True
        manual_entry.grid(row=0, column=0, sticky='ew', padx=(0, 8))
        manual_entry.bind('<Return>', lambda _event: self._add_ota_manual_host())
        self._secondary_button(manual_row, '添加设备', self._add_ota_manual_host,
                               width=100).grid(row=0, column=1)
        self.ota_selection_frame = ctk.CTkScrollableFrame(
            card, height=100, fg_color=COLORS['input'], corner_radius=9,
            border_width=1, border_color=COLORS['border'])
        self.ota_selection_frame.pack(fill='x', padx=18, pady=(0, 5))
        self.ota_selection_frame.grid_columnconfigure(0, weight=1)
        self.ota_remove_buttons = []
        self.ota_selection_signature = None
        self._refresh_ota_names()
        # 安装风险由启动确认和升级状态呈现。
        self.progress = ctk.CTkProgressBar(
            card, height=9, corner_radius=6, progress_color=COLORS['teal'],
            fg_color=COLORS['soft'],
        )
        self.progress.pack(fill='x', padx=18, pady=(0, 14))
        self.progress.set(0)
        self.ota_targets_frame = ctk.CTkScrollableFrame(
            card, height=150, fg_color=COLORS['soft'], corner_radius=10,
            scrollbar_button_color=COLORS['border'],
            scrollbar_button_hover_color=COLORS['teal'],
        )
        self.ota_targets_frame.pack(fill='x', padx=18, pady=(0, 14))
        self.ota_targets_frame.grid_columnconfigure(1, weight=1)
        self.ota_button = self._rail_button(self.ota_rail, '开始升级', self._upload_ota, primary=True)
        self.boot_entry_button = self._rail_button(self.ota_rail, '内部 BOOT', lambda: self._show_page('boot'))
        self._refresh_boot_controls()

    def _build_boot_page(self):
        return boot_update_ui.build_page(self, sys.modules[__name__])

    def _choose_boot_image(self):
        return boot_update_ui.choose_image(self)

    def _start_boot_update(self):
        return boot_update_ui.start_update(self)

    def _boot_connection_inputs(self):
        return boot_update_ui.connection_inputs(self)

    def _refresh_boot_controls(self):
        return boot_update_ui.refresh_controls(self)

    def _build_w78_page(self):
        page = self._page('w78')
        modes = self._page_card(page, 0, pady=(0, 8))
        # 使用固定模式值，简繁转换只改变显示文字，保留当前选项。
        self.wireless_mode_var = tk.StringVar(master=self.root, value=WIRELESS_HEX_MODE)
        self.wireless_hex_choice = self._register_action(ctk.CTkRadioButton(
            modes, text='HEX 烧录', variable=self.wireless_mode_var,
            value=WIRELESS_HEX_MODE, command=self._show_wireless_mode, font=self._font(12, 'bold')))
        self.wireless_hex_choice.pack(side='left', padx=(18, 20), pady=12)
        self.wireless_d133_choice = self._register_action(ctk.CTkRadioButton(
            modes, text='D133 USB A/B', variable=self.wireless_mode_var,
            value=WIRELESS_D133_MODE, command=self._show_wireless_mode, font=self._font(12, 'bold')))
        self.wireless_d133_choice.pack(side='left', padx=(0, 18), pady=12)
        self.wireless_hex_card = self._build_wireless_hex_card(page)
        self.wireless_d133_card = d133_proxy_ui.build_card(self, sys.modules[__name__], page, row=1)
        self._show_wireless_mode()
        if self.is_running:
            self._set_controls_enabled(False)

    def _show_wireless_mode(self):
        # 保留各模式已选的文件和设置，切换时仅更换可见表单。
        if hasattr(self, 'wireless_hex_actions') and hasattr(self, 'wireless_d133_actions'):
            show_d133 = self.wireless_mode_var.get() == WIRELESS_D133_MODE
            self.wireless_link_address.configure(textvariable=self.host_var if show_d133 else self.w78_host_var)
            for active, card in ((not show_d133, self.wireless_hex_actions), (show_d133, self.wireless_d133_actions)):
                if active:
                    card.grid()
                else:
                    card.grid_remove()
        if self.wireless_mode_var.get() == WIRELESS_D133_MODE:
            self.wireless_hex_card.grid_remove()
            self.wireless_d133_card.grid()
        else:
            self.wireless_d133_card.grid_remove()
            self.wireless_hex_card.grid()

    def _build_wireless_hex_card(self, page):
        card = self._page_card(page, 1, pady=(0, 8))

        target_row = ctk.CTkFrame(card, fg_color='transparent')
        target_row.pack(fill='x', padx=18, pady=(12, 8))
        ctk.CTkLabel(target_row, text='烧录对象', font=self._font(11, 'bold'),
                     text_color=COLORS['text']).pack(side='left', padx=(0, 10))
        self.w78_target_var = tk.StringVar(master=self.root, value='W78E516DDG')
        self.w78_target_selector = self._register_action(ctk.CTkComboBox(
            target_row, variable=self.w78_target_var,
            values=['W78E516DDG', 'PIC24FJ256DA210', '其它目标（接口预留）'],
            state='readonly', width=230, height=34,
            command=self._select_w78_target))
        self.w78_target_selector.pack(side='left')
        self.w78_target_notice = ctk.CTkLabel(
            card, text='请该型号暂不支持',
            fg_color=COLORS['warning_bg'], text_color=COLORS['warning_text'],
            corner_radius=8, anchor='w', justify='left')
        self._build_named_selector(card, 'w78')
        connection_row = ctk.CTkFrame(card, fg_color='transparent')
        connection_row.pack(fill='x', padx=18, pady=(0, 9))
        ctk.CTkLabel(connection_row, text='设备 IP', font=self._font(10, 'bold'),
                     text_color=COLORS['muted']).pack(side='left', padx=(0, 9))
        self.w78_host_entry = self._new_entry(
            connection_row, self.w78_host_var, 'IPv4 地址', width=230)
        self.w78_host_entry.pack(side='left')

        file_box = ctk.CTkFrame(card, fg_color=COLORS['soft'], corner_radius=12)
        file_box.pack(fill='x', padx=18, pady=(0, 10))
        file_box.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(file_box, textvariable=self.w78_hex_name_var,
                     font=self._font(12, 'bold'), text_color=COLORS['text'],
                     anchor='w').grid(row=0, column=0, sticky='ew', padx=14, pady=(13, 3))
        ctk.CTkLabel(file_box, textvariable=self.w78_hex_summary_var,
                     font=self._font(10), text_color=COLORS['cyan'], anchor='w',
                     wraplength=600, justify='left').grid(
                         row=1, column=0, sticky='ew', padx=14, pady=(0, 13))
        self.wireless_hex_actions = self._rail_card('w78', '任务操作')
        self.w78_hex_browse_button = self._rail_button(self.wireless_hex_actions, '选择文件', self._choose_w78_hex)
        self.w78_program_button = self._rail_button(self.wireless_hex_actions, '开始烧录', self._upload_w78_wireless, primary=True)
        link = self._rail_card('w78', '连接', row=1)
        self.wireless_link_address = ctk.CTkLabel(link, textvariable=self.w78_host_var, font=('Consolas', 13))
        self.wireless_link_address.pack(anchor='w', padx=12, pady=4)
        ctk.CTkLabel(link, textvariable=self.port_var, font=('Consolas', 12),
                     text_color=COLORS['muted']).pack(anchor='w', padx=12, pady=(0, 10))

        heading = ctk.CTkFrame(card, fg_color='transparent')
        heading.pack(fill='x', padx=18, pady=(6, 6))
        ctk.CTkLabel(heading, text='任务进度', font=self._font(16, 'bold')).pack(side='left')
        self.w78_percent_var = tk.StringVar(master=self.root, value='0%')
        ctk.CTkLabel(heading, textvariable=self.w78_percent_var, font=('Consolas', 23),
                     text_color=COLORS['teal']).pack(side='right')
        self.w78_progress = ctk.CTkProgressBar(
            card, height=9, corner_radius=6, progress_color=COLORS['teal'],
            fg_color=COLORS['soft'],
        )
        self.w78_progress.pack(fill='x', padx=18, pady=(0, 8))
        self.w78_progress.set(0)
        stages = ctk.CTkFrame(card, fg_color='transparent')
        stages.pack(fill='x', padx=18, pady=(0, 7))
        self.w78_stage_labels = []
        for i, caption in enumerate(('01  接收', '02  写入', '03  校验')):
            stages.grid_columnconfigure(i, weight=1, uniform='phase')
            label = ctk.CTkLabel(stages, text=caption, font=self._font(11, 'bold'),
                                 text_color=COLORS['muted'])
            label.grid(row=0, column=i, sticky='w')
            self.w78_stage_labels.append(label)
        ctk.CTkLabel(card, textvariable=self.w78_progress_text_var,
                     font=self._font(10), text_color=COLORS['muted'],
                     anchor='w', justify='left', wraplength=410).pack(fill='x', padx=18, pady=(0, 14))
        self.w78_target_notice.pack(fill='x', padx=18, pady=(0, 10))
        self.w78_target_notice.pack_forget()
        self._select_w78_target(self.w78_target_var.get())
        return card

    def _select_w78_target(self, value):
        connected = value.startswith(('W78E516DDG', 'PIC24FJ256DA210'))
        notice = getattr(self, 'w78_target_notice', None)
        if notice is not None:
            if connected:
                notice.pack_forget()
            else:
                notice.pack(fill='x', padx=18, pady=(0, 10), before=self.w78_progress)
        for name in ('w78_hex_browse_button', 'w78_program_button'):
            widget = getattr(self, name, None)
            if widget is not None:
                widget.configure(state=tk.NORMAL if connected and not self.is_running else tk.DISABLED)

    def _build_hex_page(self):
        page = self._page('hex')
        page.grid_columnconfigure(0, weight=1)
        card = self._page_card(page, 0, pady=(0, 8))
        ctk.CTkLabel(card, text='ST-LINK 烧录 HEX', font=self._font(18, 'bold'),
                     text_color=COLORS['text']).pack(anchor='w', padx=18, pady=(18, 5))
        ctk.CTkLabel(
            card,
            text='选择 Intel HEX 文件后，通过 ST-LINK / SWD 烧录并校验。进入本页时自动检测探针。',
            font=self._font(11), text_color=COLORS['muted'], wraplength=760,
            justify='left',
        ).pack(anchor='w', padx=18, pady=(0, 15))

        stlink_row = ctk.CTkFrame(card, fg_color=COLORS['soft'], corner_radius=10)
        stlink_row.pack(fill='x', padx=18, pady=(0, 14))
        ctk.CTkLabel(stlink_row, text='ST-LINK', font=self._font(11, 'bold'),
                     text_color=COLORS['muted']).pack(side='left', padx=(13, 8), pady=10)
        self.stlink_status_label = ctk.CTkLabel(
            stlink_row, textvariable=self.stlink_status_var,
            font=self._font(11, 'bold'), text_color=COLORS['muted'],
            anchor='w',
        )
        self.stlink_status_label.pack(side='left', fill='x', expand=True, pady=10)
        self.stlink_cli_button = self._register_action(self._secondary_button(
            stlink_row, '选择 CLI…', self._choose_stm32_programmer_cli, width=120))
        self.stlink_cli_button.pack(side='right', padx=10, pady=5)
        file_box = ctk.CTkFrame(card, fg_color=COLORS['soft'], corner_radius=12)
        file_box.pack(fill='x', padx=18, pady=(0, 14))
        file_box.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(file_box, textvariable=self.hex_name_var,
                     font=self._font(12, 'bold'), text_color=COLORS['text'],
                     anchor='w').grid(row=0, column=0, sticky='ew', padx=14, pady=(12, 2))
        ctk.CTkLabel(file_box, textvariable=self.hex_path_detail_var,
                     font=self._font(9), text_color=COLORS['muted'], anchor='w',
                     justify='left', wraplength=660).grid(
            row=1, column=0, sticky='ew', padx=14, pady=(0, 12))
        self.hex_memory_summary_label = ctk.CTkLabel(
            file_box, textvariable=self.hex_memory_summary_var,
            font=self._font(9, 'bold'), text_color=COLORS['cyan'], anchor='w',
            justify='left', wraplength=660)
        self.hex_memory_summary_label.grid(
            row=2, column=0, sticky='ew', padx=14, pady=(0, 12))
        self.hex_browse_button = self._secondary_button(
            file_box, '选择 HEX 文件…', self._choose_hex_file, width=155)
        self.hex_browse_button.grid(row=0, column=1, rowspan=3, padx=13, pady=12)

        programmer_card = self._page_card(page, 1, pady=(0, 12))
        programmer_card.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(programmer_card, text='下载范围', font=self._font(13, 'bold'),
                     text_color=COLORS['text']).grid(row=0, column=0, sticky='w', padx=17, pady=(14, 6))
        self.hex_extension_checkbox = self._register_action(ctk.CTkCheckBox(
            programmer_card,
            text='下载扩展 Flash（QSPI）',
            variable=self.hex_extension_download_var,
            onvalue=True,
            offvalue=False,
            command=self._update_hex_extension_hint,
            font=self._font(12, 'bold'),
            text_color=COLORS['text'],
            fg_color=COLORS['teal'],
            hover_color=COLORS['teal_hover'],
            border_color=COLORS['border'],
            checkmark_color='#FFFFFF',
            corner_radius=5,
            border_width=2,
            checkbox_width=20,
            checkbox_height=20,
        ))
        self.hex_extension_checkbox.grid(row=1, column=0, sticky='w', padx=17, pady=(2, 5))
        ctk.CTkLabel(
            programmer_card,
            text='默认只烧录内部 Flash；勾选后，同时下载 HEX 中的外部 QSPI 数据。',
            font=self._font(10), text_color=COLORS['muted'],
            wraplength=760, justify='left',
        ).grid(row=2, column=0, sticky='w', padx=45, pady=(0, 14))

        frequency_row = ctk.CTkFrame(programmer_card, fg_color='transparent')
        frequency_row.grid(row=3, column=0, sticky='ew', padx=17, pady=(0, 14))
        frequency_row.grid_columnconfigure(2, weight=1)
        ctk.CTkLabel(frequency_row, text='SWD 下载频率',
                     font=self._font(11, 'bold'), text_color=COLORS['text']).grid(
            row=0, column=0, sticky='w', padx=(0, 11))
        self.swd_frequency_menu = self._register_action(ctk.CTkOptionMenu(
            frequency_row,
            variable=self.swd_frequency_var,
            values=SWD_FREQUENCY_CHOICES,
            width=205,
            height=34,
            corner_radius=8,
            font=self._font(10, 'bold'),
            fg_color=COLORS['soft'],
            button_color=COLORS['blue'],
            button_hover_color=COLORS['blue_hover'],
            text_color=COLORS['text'],
            dropdown_fg_color=COLORS['card'],
            dropdown_text_color=COLORS['text'],
            dropdown_hover_color=COLORS['soft'],
        ))
        self.swd_frequency_menu.grid(row=0, column=1, sticky='w')
        ctk.CTkLabel(
            frequency_row,
            text='最高可选 10 MHz；实际生效频率取决于 ST-LINK 型号。',
            font=self._font(9), text_color=COLORS['muted'],
            wraplength=440, justify='left',
        ).grid(row=0, column=2, sticky='w', padx=(13, 0))

        action_row = ctk.CTkFrame(programmer_card, fg_color='transparent')
        action_row.grid(row=6, column=0, sticky='ew', padx=18, pady=(0, 17))
        self.hex_progress = ctk.CTkProgressBar(
            action_row, height=9, corner_radius=6, progress_color=COLORS['teal'],
            fg_color=COLORS['soft'],
        )
        self.hex_progress.pack(fill='x', pady=(0, 12))
        self.hex_progress.set(0)
        self.hex_program_button = self._primary_button(
            action_row, '连接并烧录', self._start_hex_programming,
            width=170, accent='teal')
        self.hex_program_button.pack(anchor='e')

    def _build_mplab_page(self):
        page = self._page('mplab')
        page.grid_columnconfigure(0, weight=1)

        tool_card = self._page_card(page, 0, pady=(0, 8))
        tool_card.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(tool_card, text='PIC24 HEX 烧录',
                     font=self._font(18, 'bold'), text_color=COLORS['text']).grid(
            row=0, column=0, sticky='w', padx=17, pady=(14, 3))
        ctk.CTkLabel(
            tool_card,
            text='使用 PICkit 3 与 PK3CMD，为 PIC24 烧录并校验 Intel HEX。U12 外部 Flash 图片写入请使用单独的 U12 图片烧录页。',
            font=self._font(10), text_color=COLORS['muted'], wraplength=760,
            justify='left',
        ).grid(row=1, column=0, sticky='w', padx=17, pady=(0, 10))
        cli_row = ctk.CTkFrame(tool_card, fg_color=COLORS['soft'], corner_radius=10)
        cli_row.grid(row=2, column=0, sticky='ew', padx=17, pady=(0, 14))
        cli_row.grid_columnconfigure(0, weight=1)
        self.mplab_tool_status_label = ctk.CTkLabel(
            cli_row, textvariable=self.mplab_tool_status_var,
            font=self._font(11, 'bold'),
            text_color=COLORS['cyan'] if self.mplab_cli_path else '#B45309',
            anchor='w')
        self.mplab_tool_status_label.grid(
            row=0, column=0, sticky='ew', padx=12, pady=(9, 2))
        ctk.CTkLabel(cli_row, textvariable=self.mplab_cli_path_var,
                     font=self._font(9), text_color=COLORS['muted'], anchor='w',
                     justify='left', wraplength=620).grid(
            row=1, column=0, sticky='ew', padx=12, pady=(0, 9))
        self.mplab_cli_button = self._secondary_button(
            cli_row, '定位 PK3CMD…', self._choose_pk3cmd, width=142)
        self.mplab_cli_button.grid(row=0, column=1, rowspan=2, padx=12, pady=10)

        file_card = self._page_card(page, 1, pady=(0, 12))
        file_card.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(file_card, text='烧录文件', font=self._font(13, 'bold'),
                     text_color=COLORS['text']).grid(
            row=0, column=0, sticky='w', padx=17, pady=(13, 7))
        ctk.CTkLabel(file_card, textvariable=self.mplab_hex_name_var,
                     font=self._font(12, 'bold'), text_color=COLORS['text'],
                     anchor='w').grid(row=1, column=0, sticky='ew', padx=17, pady=(0, 2))
        ctk.CTkLabel(file_card, textvariable=self.mplab_hex_path_var,
                     font=self._font(9), text_color=COLORS['muted'], anchor='w',
                     justify='left', wraplength=660).grid(
            row=2, column=0, sticky='ew', padx=17, pady=(0, 2))
        self.mplab_hex_summary_label = ctk.CTkLabel(
            file_card, textvariable=self.mplab_hex_summary_var,
            font=self._font(9, 'bold'), text_color=COLORS['cyan'], anchor='w',
            justify='left', wraplength=660)
        self.mplab_hex_summary_label.grid(
            row=3, column=0, sticky='ew', padx=17, pady=(0, 13))
        self.mplab_hex_browse_button = self._secondary_button(
            file_card, '选择 HEX 文件…', self._choose_mplab_hex_file, width=155)
        self.mplab_hex_browse_button.grid(row=1, column=1, rowspan=3, padx=13, pady=12)

        target_card = self._page_card(page, 2, pady=(0, 12))
        target_card.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(target_card, text='目标器件', font=self._font(13, 'bold'),
                     text_color=COLORS['text']).grid(
            row=0, column=0, sticky='w', padx=17, pady=(13, 6))
        self._field_label(target_card, 'PIC24 完整型号', 1, 0, padx=(17, 0))
        self.mplab_device_entry = self._new_entry(
            target_card, self.mplab_device_var, '例如 PIC24FJ256GA106')
        self.mplab_device_entry.grid(row=2, column=0, sticky='ew', padx=17, pady=(0, 5))
        ctk.CTkLabel(
            target_card,
            text='请填写芯片完整型号。工具会按 PK3CMD 格式自动去掉开头的 “PIC”，例如 PIC24FJ… → 24FJ…。',
            font=self._font(9), text_color=COLORS['muted'], wraplength=760,
            justify='left',
        ).grid(row=3, column=0, sticky='w', padx=17, pady=(0, 13))

        action_card = self._page_card(page, 3, pady=(0, 12))
        action_card.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(action_card, text='编程方式', font=self._font(13, 'bold'),
                     text_color=COLORS['text']).grid(
            row=0, column=0, sticky='w', padx=17, pady=(13, 5))
        ctk.CTkLabel(
            action_card, text='写入 HEX 中包含的程序与配置数据，随后执行校验。',
            font=self._font(10), text_color=COLORS['muted'],
        ).grid(row=1, column=0, sticky='w', padx=17, pady=(0, 3))
        ctk.CTkLabel(
            action_card,
            text='试验区：烧录会改写 PIC24 存储内容。请先确认器件型号、HEX 文件和 ICSP 接线。',
            font=self._font(10, 'bold'), text_color=COLORS['warning_text'], wraplength=760,
            justify='left',
        ).grid(row=2, column=0, sticky='w', padx=17, pady=(0, 12))
        action_row = ctk.CTkFrame(action_card, fg_color='transparent')
        action_row.grid(row=3, column=0, sticky='ew', padx=17, pady=(0, 16))
        self.mplab_progress = ctk.CTkProgressBar(
            action_row, height=9, corner_radius=6, progress_color=COLORS['teal'],
            fg_color=COLORS['soft'],
        )
        self.mplab_progress.pack(fill='x', pady=(0, 12))
        self.mplab_progress.set(0)
        self.mplab_program_button = self._primary_button(
            action_row, '连接 PICkit 3 并烧录', self._start_mplab_programming,
            width=210, accent='teal')
        self.mplab_program_button.pack(anchor='e')

    def _build_u12_page(self):
        page = self._page('u12')
        page.grid_columnconfigure(0, weight=1)

        intro = self._page_card(page, 0, pady=(0, 8))
        intro.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(intro, text='板载 U12 图片烧录',
                     font=self._font(18, 'bold'), text_color=COLORS['text']).grid(
            row=0, column=0, sticky='w', padx=17, pady=(14, 3))
        ctk.CTkLabel(
            intro,
            text='选择一张图片，工具会自动裁切并转换为开发板所需格式，再通过 PICkit 3 → PIC24 → SPI 写入 U12。',
            font=self._font(10), text_color=COLORS['muted'], wraplength=760,
            justify='left',
        ).grid(row=1, column=0, sticky='w', padx=17, pady=(0, 13))
        cli_row = ctk.CTkFrame(intro, fg_color='transparent')
        cli_row.grid(row=2, column=0, sticky='ew', padx=17, pady=(0, 12))
        cli_row.grid_columnconfigure(0, weight=1)
        self.u12_cli_status_label = ctk.CTkLabel(
            cli_row, textvariable=self.mplab_tool_status_var,
            font=self._font(10, 'bold'),
            text_color=COLORS['cyan'] if self.mplab_cli_path else '#B45309',
            anchor='w',
        )
        self.u12_cli_status_label.grid(row=0, column=0, sticky='w')
        self.u12_cli_button = self._secondary_button(
            cli_row, '定位 PK3CMD…', self._choose_pk3cmd, width=142)
        self.u12_cli_button.grid(row=0, column=1, sticky='e')
        self._register_action(self.u12_cli_button)

        image_card = self._page_card(page, 1, pady=(0, 12))
        image_card.grid_columnconfigure(1, weight=1)
        self.u12_preview_label = ctk.CTkLabel(
            image_card, text='图片预览', width=320, height=192,
            fg_color=COLORS['input'], text_color=COLORS['muted'],
            corner_radius=10,
        )
        self.u12_preview_label.grid(row=0, column=0, rowspan=4, sticky='nw',
                                    padx=16, pady=16)
        ctk.CTkLabel(image_card, text='图片文件', font=self._font(10, 'bold'),
                     text_color=COLORS['muted']).grid(
            row=0, column=1, sticky='w', padx=(12, 16), pady=(16, 4))
        ctk.CTkLabel(image_card, textvariable=self.u12_image_name_var,
                     font=self._font(18, 'bold'), text_color=COLORS['text'],
                     anchor='w').grid(row=1, column=1, sticky='ew', padx=(12, 16))
        ctk.CTkLabel(image_card, textvariable=self.u12_image_path_var,
                     font=self._font(9), text_color=COLORS['muted'],
                     anchor='w', justify='left', wraplength=470).grid(
            row=2, column=1, sticky='ew', padx=(12, 16), pady=(4, 8))
        ctk.CTkLabel(image_card, textvariable=self.u12_image_detail_var,
                     font=self._font(10, 'bold'), text_color=COLORS['cyan'],
                     anchor='w', justify='left', wraplength=470).grid(
            row=3, column=1, sticky='ew', padx=(12, 16), pady=(0, 11))
        self.u12_choose_button = self._secondary_button(
            image_card, '选择图片…', self._choose_u12_image, width=135)
        self.u12_choose_button.grid(row=4, column=1, sticky='e', padx=16, pady=(0, 15))
        self._register_action(self.u12_choose_button)

        action_card = self._page_card(page, 2, pady=(0, 12))
        action_card.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(action_card, text='写入 U12', font=self._font(13, 'bold'),
                     text_color=COLORS['text']).grid(
            row=0, column=0, sticky='w', padx=17, pady=(13, 5))
        ctk.CTkLabel(
            action_card,
            text='过程会临时改写 PIC24。工具先备份当前程序，逐块写入并校验 U12，随后自动恢复 PIC24。烧录期间请保持开发板供电和 PICkit 3 连接。',
            font=self._font(10, 'bold'), text_color=COLORS['warning_text'], wraplength=760,
            justify='left',
        ).grid(row=1, column=0, sticky='w', padx=17, pady=(0, 10))
        self.u12_progress = ctk.CTkProgressBar(
            action_card, height=9, corner_radius=6,
            progress_color=COLORS['teal'], fg_color=COLORS['soft'],
        )
        self.u12_progress.grid(row=2, column=0, sticky='ew', padx=17, pady=(0, 5))
        self.u12_progress.set(0)
        ctk.CTkLabel(action_card, textvariable=self.u12_progress_text_var,
                     font=self._font(9), text_color=COLORS['muted'],
                     anchor='w').grid(row=3, column=0, sticky='ew', padx=17, pady=(0, 9))
        action_row = ctk.CTkFrame(action_card, fg_color='transparent')
        action_row.grid(row=4, column=0, sticky='ew', padx=17, pady=(0, 15))
        self.u12_restore_button = self._secondary_button(
            action_row, '恢复 PIC24 备份', self._start_u12_restore, width=155)
        self.u12_restore_button.pack(side='left')
        self.u12_program_button = self._primary_button(
            action_row, '写入 U12 并恢复 PIC24', self._start_u12_programming,
            width=220, accent='teal')
        self.u12_program_button.pack(side='right')
        self._register_action(self.u12_restore_button)
        self._register_action(self.u12_program_button)

        recovery = self._page_card(page, 3, pady=(0, 12))
        recovery.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(recovery, text='恢复保护', font=self._font(11, 'bold'),
                     text_color=COLORS['cyan']).grid(
            row=0, column=0, sticky='w', padx=16, pady=(12, 3))
        ctk.CTkLabel(recovery, textvariable=self.u12_recovery_status_var,
                     font=self._font(10), text_color=COLORS['muted'],
                     anchor='w', justify='left', wraplength=760).grid(
            row=1, column=0, sticky='ew', padx=16, pady=(0, 12))
        self._refresh_u12_recovery_view()

    def _refresh_u12_recovery_view(self):
        if not hasattr(self, 'u12_restore_button'):
            return
        state = self.u12_recovery_state
        backup_path = None
        if state:
            try:
                backup_path = Path(state.get('backup_path', ''))
            except (TypeError, ValueError):
                backup_path = None
        has_backup = bool(backup_path and backup_path.is_file())
        if state and has_backup:
            self.u12_recovery_status_var.set(
                f'发现待恢复备份：{backup_path.name}。如上次写入中断，先点击“恢复 PIC24 备份”。')
        elif state:
            self.u12_recovery_status_var.set(
                '发现未完成的写入记录，但备份 HEX 不存在；请检查 %LOCALAPPDATA%\\ResearchToolbox\\U12Recovery。')
        else:
            self.u12_recovery_status_var.set('当前没有待恢复的 PIC24 备份。')
        running = self.is_running
        self.u12_restore_button.configure(
            state=tk.NORMAL if (has_backup and not running) else tk.DISABLED)
        can_program = bool(self.u12_image_data) and not running and not state
        self.u12_program_button.configure(
            state=tk.NORMAL if can_program else tk.DISABLED)

    def _show_page(self, page):
        titles = {
            'home': '设备总览',
            'listen': '设备信息',
            'ota': '固件升级',
            'w78': '无线烧录',
            'hex': 'ST-LINK 烧录',
            'devices': '地址管理',
            'fixture': '测试用具',
            'boot': '内部 BOOT',
        }
        if page not in self.pages:
            builder = getattr(self, 'page_builders', {}).get(page)
            if builder is None:
                return
            builder()
        previous_page = self.active_page_key
        if previous_page and previous_page != page:
            self._cancel_scroll_animation(self.active_page_key)
        self.active_page_key = page
        for key, frame in self.pages.items():
            if key == page:
                frame.grid()
            else:
                frame.grid_remove()
        for key, panel in getattr(self, 'page_rails', {}).items():
            if key == page:
                panel.grid()
            else:
                panel.grid_remove()
        self.page_title_var.set(titles[page])
        if getattr(self, 'is_running', False):
            self._set_controls_enabled(False)
        for key, button in self.nav_buttons.items():
            active = key == page
            button.configure(
                fg_color=COLORS['sidebar_active'] if active else 'transparent',
                hover_color=COLORS['sidebar_active'],
                text_color='#FFFFFF' if active else COLORS['sidebar_text'],
                border_width=0,
                border_color=COLORS['blue'] if active else COLORS['sidebar'],
            )
        if page == 'u12':
            self._refresh_u12_recovery_view()

    def _stop_stlink_auto_poll(self):
        if self.stlink_poll_after_id is not None:
            try:
                self.root.after_cancel(self.stlink_poll_after_id)
            except tk.TclError:
                pass
            self.stlink_poll_after_id = None

    def _schedule_stlink_auto_poll(self, delay_ms=5000):
        if (self.active_page_key != 'hex' or self.stlink_poll_after_id is not None
                or not self.root.winfo_exists()):
            return
        self.stlink_poll_after_id = self.root.after(
            delay_ms, self._check_stlink_connection)

    def _get_cubeprogrammer_runtime(self, cli_path):
        source = str(Path(cli_path).resolve())
        if (self.programmer_runtime_source == source
                and self.programmer_runtime_cli is not None
                and self.programmer_runtime_cli.is_file()
                and self.programmer_runtime_workdir.is_dir()):
            return self.programmer_runtime_cli, self.programmer_runtime_workdir
        self._cleanup_cubeprogrammer_runtime()
        runtime_cli, runtime_workdir, runtime_temp = cubeprogrammer_runtime(cli_path)
        self.programmer_runtime_source = source
        self.programmer_runtime_cli = runtime_cli
        self.programmer_runtime_workdir = runtime_workdir
        self.programmer_runtime_temp = runtime_temp
        return runtime_cli, runtime_workdir

    def _cleanup_cubeprogrammer_runtime(self):
        if self.programmer_runtime_temp is not None:
            shutil.rmtree(self.programmer_runtime_temp, ignore_errors=True)
        self.programmer_runtime_source = None
        self.programmer_runtime_cli = None
        self.programmer_runtime_workdir = None
        self.programmer_runtime_temp = None

    def _check_stlink_connection(self):
        self._stop_stlink_auto_poll()
        if self.active_page_key != 'hex':
            return
        if self.is_running or self.stlink_check_running:
            self._schedule_stlink_auto_poll()
            return
        cli_path = Path(self._detect_stm32_programmer_cli(
            self.stm32_programmer_cli_path))
        if not cli_path.is_file():
            self.stlink_status_var.set('未找到兼容的 CubeProgrammer CLI')
            self.stlink_status_label.configure(text_color='#B91C1C')
            self._schedule_stlink_auto_poll()
            return

        self.stlink_check_running = True
        self.stlink_status_var.set('正在检测…')
        self.stlink_status_label.configure(text_color='#2563EB')
        self.hex_program_button.configure(state=tk.DISABLED)

        def worker():
            try:
                # Listing probes does not require the device database. Running
                # the bundled CLI directly avoids copying its full runtime and
                # database into a temporary directory just to check USB state.
                programmer_cli = ascii_existing_path(cli_path) or cli_path
                programmer_workdir = ascii_existing_path(cli_path.parent) or cli_path.parent
                result = subprocess.run(
                    [str(programmer_cli), '-l'],
                    cwd=str(programmer_workdir),
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    timeout=20,
                    creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0),
                    check=False,
                )
                output = decode_programmer_output(result.stdout or b'')
                serial_match = re.search(
                    r'ST[- ]?LINK\s*SN\s*:\s*([A-Fa-f0-9]+)',
                    output, re.IGNORECASE)
                probe_match = re.search(
                    r'ST[- ]?Link\s+Probe\s+\d+\s*:', output, re.IGNORECASE)
                dfu_missing = 'no stm32 device in dfu mode connected' in output.lower()
                if serial_match:
                    detail = '未检测到 DFU 设备；ST-LINK / SWD 已连接。' if dfu_missing else ''
                    state = (f'ST-LINK 已连接 | SN {serial_match.group(1)}',
                             '#15803D', detail)
                elif probe_match:
                    detail = '探针已枚举，但 CLI 未返回序列号。'
                    if dfu_missing:
                        detail += ' DFU 接口未连接与 ST-LINK 状态无关。'
                    state = ('ST-LINK 已连接 | 序列号不可用', '#15803D', detail)
                elif result.returncode == 0:
                    details = '\n'.join(output.splitlines()[-10:])
                    if dfu_missing:
                        details = ('未检测到 DFU 设备；DFU 与 ST-LINK 是不同接口。\n' + details)
                    details = (details + '\n' if details else '') + (
                        '当前列表没有 ST-LINK 探针。请检查 USB 数据线、驱动和设备管理器。')
                    state = ('未检测到 ST-LINK', '#B45309', details)
                else:
                    details = '\n'.join(output.splitlines()[-6:])
                    state = (
                        f'检测失败（退出代码 {result.returncode}）',
                        '#B91C1C',
                        details or 'CubeProgrammer 未返回探针列表。',
                    )
            except subprocess.TimeoutExpired:
                state = ('检测超时', '#B91C1C', 'ST-LINK 探针枚举超过 20 秒。')
            except Exception as exc:
                state = ('检测失败', '#B91C1C', str(exc))
            self.stlink_check_running = False
            self._post('stlink_result', state)

        threading.Thread(target=worker, name='ST-LINK-detect', daemon=True).start()

    def _install_smooth_scrolling(self):
        # CTkScrollableFrame binds one immediate wheel handler per page. Replace
        # those handlers with one eased animation so fast wheel input does not
        # jump the canvas by several rows at once.
        for sequence in ('<MouseWheel>', '<Button-4>', '<Button-5>'):
            self.root.unbind_all(sequence)
            self.root.bind_all(sequence, self._on_mousewheel)

    def _on_mousewheel(self, event):
        page_key = self.active_page_key
        page = self.pages.get(page_key)
        if page is None:
            return None
        try:
            if not page._check_if_valid_scroll(event.widget):
                return None
        except (AttributeError, tk.TclError):
            return None

        if getattr(event, 'num', None) == 4:
            wheel_delta = 120
        elif getattr(event, 'num', None) == 5:
            wheel_delta = -120
        else:
            wheel_delta = getattr(event, 'delta', 0) or 0
        if not wheel_delta:
            return 'break'

        # Match CTk's former Windows travel distance, while retaining fractional
        # movement from precision touchpads.
        distance = max(-360.0, min(360.0, -float(wheel_delta) / 6.0))
        self._queue_smooth_scroll(page_key, distance)
        return 'break'

    def _queue_smooth_scroll(self, page_key, distance):
        page = self.pages.get(page_key)
        if page is None:
            return
        canvas = page._parent_canvas
        bounds = canvas.bbox('all')
        if not bounds:
            return
        content_top, content_bottom = bounds[1], bounds[3]
        content_height = max(1, content_bottom - content_top)
        max_scroll = max(0, content_height - canvas.winfo_height())
        if max_scroll <= 0:
            return

        current = canvas.yview()[0] * content_height - content_top
        current = max(0.0, min(max_scroll, current))
        target = self._scroll_targets.get(page_key, current) + distance
        self._scroll_targets[page_key] = max(0.0, min(max_scroll, target))
        if page_key not in self._scroll_after_ids:
            self._scroll_after_ids[page_key] = self.root.after(
                UI_FRAME_INTERVAL_MS,
                lambda selected=page_key: self._animate_scroll(selected),
            )

    def _animate_scroll(self, page_key):
        self._scroll_after_ids.pop(page_key, None)
        page = self.pages.get(page_key)
        if page is None or not self.root.winfo_exists():
            self._scroll_targets.pop(page_key, None)
            return
        canvas = page._parent_canvas
        bounds = canvas.bbox('all')
        if not bounds:
            self._scroll_targets.pop(page_key, None)
            return

        content_top, content_bottom = bounds[1], bounds[3]
        content_height = max(1, content_bottom - content_top)
        max_scroll = max(0, content_height - canvas.winfo_height())
        target = self._scroll_targets.get(page_key)
        if target is None:
            return
        target = max(0.0, min(max_scroll, target))
        current = canvas.yview()[0] * content_height - content_top
        current = max(0.0, min(max_scroll, current))
        distance = target - current
        if abs(distance) < 0.8:
            current = target
            self._scroll_targets.pop(page_key, None)
        else:
            current += distance * SCROLL_EASING

        canvas.yview_moveto((content_top + current) / content_height)
        if page_key in self._scroll_targets:
            self._scroll_after_ids[page_key] = self.root.after(
                UI_FRAME_INTERVAL_MS,
                lambda selected=page_key: self._animate_scroll(selected),
            )

    def _cancel_scroll_animation(self, page_key):
        after_id = self._scroll_after_ids.pop(page_key, None)
        if after_id is not None:
            try:
                self.root.after_cancel(after_id)
            except tk.TclError:
                pass
        self._scroll_targets.pop(page_key, None)

    def _update_summaries(self, *_):
        host = self.host_var.get().strip()
        port = self.port_var.get().strip()
        self.connection_summary_var.set(f'{host}:{port}' if host else '未设置设备 IP')
        manual_key = self.manual_key_var.get().strip()
        key_name = self.key_var.get().strip()
        if manual_key:
            key_summary = '已填写手动 Key'
        elif self.key_path and key_name != '未导入 key 文件':
            key_summary = f'已导入 | {key_name}'
        else:
            key_summary = '未设置 Key（信息可读取，OTA 需板端确认）'
        self.key_summary_var.set(key_summary)

    @staticmethod
    def _card(parent):
        return ctk.CTkFrame(parent, fg_color=COLORS['card'], corner_radius=12,
                            border_width=1, border_color=COLORS['border'])

    @staticmethod
    def _choose_font(root):
        try:
            installed = {name.casefold(): name for name in tkfont.families(root)}
        except tk.TclError:
            return 'Segoe UI'
        for family in ('Microsoft YaHei UI', 'Microsoft YaHei',
                       'Microsoft JhengHei UI', 'Microsoft JhengHei',
                       'Noto Sans CJK TC', 'Noto Sans CJK SC', 'SimHei',
                       'MingLiU', 'PMingLiU', 'Segoe UI'):
            if family.casefold() in installed:
                return installed[family.casefold()]
        return 'Segoe UI'

    @staticmethod
    def _stm32_cli_machine(path):
        try:
            with Path(path).open('rb') as stream:
                header = stream.read(64)
                if len(header) < 64 or header[:2] != b'MZ':
                    return None
                pe_offset = struct.unpack_from('<I', header, 0x3C)[0]
                stream.seek(pe_offset)
                if stream.read(4) != b'PE\0\0':
                    return None
                machine = stream.read(2)
                return struct.unpack('<H', machine)[0] if len(machine) == 2 else None
        except (OSError, ValueError, struct.error):
            return None

    @staticmethod
    def _windows_is_64bit():
        architecture = (os.environ.get('PROCESSOR_ARCHITEW6432') or
                        os.environ.get('PROCESSOR_ARCHITECTURE', '')).upper()
        return architecture in ('AMD64', 'ARM64', 'IA64')

    @classmethod
    def _detect_stm32_programmer_cli(cls, configured_path=''):
        executable = 'STM32_Programmer_CLI.exe'
        app_dir = app_directory()
        is_64bit = cls._windows_is_64bit()
        candidates = [Path(configured_path)] if configured_path else []
        # Portable distribution: keep STM32CubeProgrammer beside the toolbox EXE.
        if is_64bit:
            candidates.extend((
                app_dir / 'STM32CubeProgrammer' / 'bin' / executable,
                app_dir / 'STM32CubeProgrammer' / 'win64' / 'bin' / executable,
                app_dir / 'STM32CubeProgrammer' / 'win32' / 'bin' / executable,
                app_dir / 'CubeProgrammer' / 'bin' / executable,
            ))
            env_names = ('PROGRAMFILES', 'PROGRAMFILES(X86)')
        else:
            candidates.extend((
                app_dir / 'STM32CubeProgrammer' / 'win32' / 'bin' / executable,
                app_dir / 'STM32CubeProgrammer' / 'Win7_x86' / 'bin' / executable,
                app_dir / 'CubeProgrammer' / 'win32' / 'bin' / executable,
                app_dir / 'STM32CubeProgrammer' / 'bin' / executable,
            ))
            env_names = ('PROGRAMFILES(X86)', 'PROGRAMFILES')
        for env_name in env_names:
            root = os.environ.get(env_name)
            if root:
                candidates.append(
                    Path(root) / 'STMicroelectronics' / 'STM32Cube' /
                    'STM32CubeProgrammer' / 'bin' / executable)
        candidates.extend((
            Path('C:/ST/STM32CubeProgrammer/bin') / executable,
            Path('C:/STMicroelectronics/STM32CubeProgrammer/bin') / executable,
        ))
        located = shutil.which(executable)
        if located:
            candidates.append(Path(located))
        for candidate in candidates:
            if not candidate.is_file():
                continue
            machine = cls._stm32_cli_machine(candidate)
            if machine == 0x014C or (is_64bit and machine in (0x8664, 0xAA64)):
                return str(candidate.resolve())
        return ''

    def _choose_stm32_programmer_cli(self):
        selected = filedialog.askopenfilename(
            parent=self.root,
            title='选择 STM32CubeProgrammer 命令行工具',
            initialdir=str(Path(self.stm32_programmer_cli_path).parent)
            if self.stm32_programmer_cli_path else str(self.base_dir),
            filetypes=[('STM32CubeProgrammer CLI', 'STM32_Programmer_CLI.exe'),
                       ('可执行文件', '*.exe')],
        )
        if not selected:
            return
        candidate = Path(selected).resolve()
        if candidate.name.casefold() != 'stm32_programmer_cli.exe':
            messagebox.showerror('工具不匹配', '请选择 STM32_Programmer_CLI.exe。',
                                 parent=self.root)
            return
        machine = self._stm32_cli_machine(candidate)
        if machine != 0x014C and not (
                self._windows_is_64bit() and machine in (0x8664, 0xAA64)):
            messagebox.showerror(
                '架构不匹配',
                '所选 CubeProgrammer CLI 与当前 Windows 位数不兼容。',
                parent=self.root,
            )
            return
        self.stm32_programmer_cli_path = str(candidate)
        self._save_settings()
        self._check_stlink_connection()

    @staticmethod
    def _detect_stm32_external_loader(cli_path=''):
        candidates = []
        if cli_path:
            cli = Path(cli_path)
            candidates.append(cli.parent / 'ExternalLoader' / F750_W25Q128_LOADER)
        for env_name in ('PROGRAMFILES', 'PROGRAMFILES(X86)'):
            root = os.environ.get(env_name)
            if root:
                base = Path(root) / 'STMicroelectronics' / 'STM32Cube' / 'STM32CubeProgrammer'
                candidates.extend((
                    base / 'bin' / 'ExternalLoader' / F750_W25Q128_LOADER,
                    base / 'api' / 'lib' / 'ExternalLoader' / F750_W25Q128_LOADER,
                ))
        candidates.extend((
            Path('C:/ST/STM32CubeProgrammer/bin/ExternalLoader') / F750_W25Q128_LOADER,
            Path('C:/STMicroelectronics/STM32CubeProgrammer/bin/ExternalLoader') / F750_W25Q128_LOADER,
        ))
        for candidate in candidates:
            if candidate.is_file():
                return str(candidate.resolve())
        return ''

    def _font(self, size, weight='normal'):
        # 全界面统一为四档字号，保证标签和状态文字不低于 12px。
        actual_size = 12 if size <= 11 else 13 if size <= 14 else 16 if size <= 20 else 24
        return ctk.CTkFont(family=self.font_family, size=actual_size, weight=weight)

    def _append_log(self, message):
        timestamp = time.strftime('%H:%M:%S')
        self.log.insert('end', f'[{timestamp}] {message}\n')
        self.log.see('end')

    def _refresh_history(self):
        store = getattr(self, 'operation_history', None)
        if store is None:
            text = '无法读取操作记录'
        else:
            try:
                records = store.recent()
            except (HistoryError, OSError):
                return
            # 分页区域只显示时间和摘要；无变化时保留滚动位置。
            if records == self.history_rows:
                return
            self.history_rows = records
            text = '\n\n'.join(
                '  '.join(part for part in (
                    time.strftime('%m-%d %H:%M', time.localtime(stamp)), action, target, state) if part)
                for stamp, action, target, state in records) or '暂无操作'
        self.history_view.configure(state='normal')
        self.history_view.delete('1.0', 'end')
        self.history_view.insert('1.0', text)
        self.history_view.configure(state='disabled')

    def _age_history(self):
        self._refresh_history()
        self.root.after(60_000, self._age_history)

    def _history_start(self, action, target=''):
        store = getattr(self, 'operation_history', None)
        if store is None:
            return None
        try:
            record = store.start(action, target)
            self._refresh_history()
            return record
        except (HistoryError, OSError):
            self._history_warning()
            return None

    def _history_finish(self, record, state):
        if record is None:
            return
        try:
            self.operation_history.finish(record, state)
            self._refresh_history()
        except (HistoryError, OSError):
            self._history_warning()

    def _history_warning(self):
        if not self.history_warned:
            self.history_warned = True
            self._append_log('无法保存最近操作。')

    def _clear_log(self):
        self.log.delete('1.0', 'end')

    def _set_status(self, value):
        self.status_var.set(value)
        if getattr(self, 'running_card', None) is not None:
            if self.is_running or getattr(self, 'device_scan_running', False) or value not in ('就绪', ''):
                self.running_card.grid()
            else:
                self.running_card.grid_remove()
        lowered = value.lower()
        if any(word in lowered for word in ('失败', '超时', '错误', '断开')):
            fg, text = COLORS['error_bg'], COLORS['error_text']
        elif any(word in lowered for word in ('连接成功', '升级完成', '已读取', '已连接并')):
            fg, text = COLORS['success_bg'], COLORS['success_text']
        elif any(word in lowered for word in ('正在', '刷新中', '等待')):
            fg, text = COLORS['info_bg'], COLORS['info_text']
        else:
            fg, text = COLORS['soft'], COLORS['muted']
        self.status_label.configure(text=f'● {value}', fg_color=fg, text_color=text)
        if not (self.is_running or getattr(self, 'device_scan_running', False)) and hasattr(self, 'stop_button'):
            self.stop_button.pack_forget()
        elif hasattr(self, 'stop_button') and not self.stop_button.winfo_manager():
            self.stop_button.pack(fill='x', padx=12, pady=(0, 10))

    def _post(self, kind, value=None):
        self.events.put((kind, value))

    def _update_ota_batch_progress(self):
        if not self.ota_device_rows:
            return
        fraction = sum(row['fraction'] for row in self.ota_device_rows.values())
        self.progress.set(fraction / len(self.ota_device_rows))

    def _poll_events(self):
        # 高速任务事件保留 FIFO 顺序，单轮用完预算就先让出界面线程。
        deadline = time.perf_counter() + UI_EVENT_BUDGET_S
        try:
            for index in range(UI_EVENT_BATCH_LIMIT):
                if index and time.perf_counter() >= deadline:
                    break
                kind, value = self.events.get_nowait()
                if kind == 'log':
                    self._append_log(value)
                elif kind == 'settings_saved':
                    if value:
                        self._append_log('配置保存失败：' + value)
                        if hasattr(self, 'device_add_status_var'):
                            self.device_add_status_var.set('列表已更新，但保存失败：' + value)
                    elif hasattr(self, 'device_add_status_var'):
                        self.device_add_status_var.set('设备列表已保存，可在总览按名称选择。')
                elif kind == 'fixture_state':
                    self._fixture_accept(value)
                elif kind == 'device_info':
                    self._render_device_info(value)
                elif kind == 'connection_state':
                    self._set_connection_state(value)
                elif kind == 'u12_recovery':
                    self.u12_recovery_state = value
                    self._refresh_u12_recovery_view()
                elif kind == 'u12_progress_text':
                    self.u12_progress_text_var.set(value)
                elif kind == 'stlink_result':
                    status, color, details = value
                    self.stlink_check_running = False
                    self.stlink_status_var.set(status)
                    self.stlink_status_label.configure(text_color=color)
                    state = tk.DISABLED if self.is_running else tk.NORMAL
                    self.hex_program_button.configure(state=state)
                    if details:
                        self._append_log('ST-LINK 检测详情：\n' + details)
                    if not self.close_pending:
                        self._schedule_stlink_auto_poll()
                elif kind == 'status':
                    self._set_status(value)
                elif kind == 'progress':
                    sent, total = value
                    percent = sent * 100 // max(1, total)
                    fraction = sent / max(1, total)
                    for bar, indeterminate_name in (
                            (getattr(self, 'progress', None), None),
                            (getattr(self, 'hex_progress', None),
                             'hex_progress_indeterminate'),
                            (getattr(self, 'mplab_progress', None),
                             'mplab_progress_indeterminate'),
                            (getattr(self, 'u12_progress', None),
                             'u12_progress_indeterminate')):
                        if bar is None:
                            continue
                        if indeterminate_name and getattr(
                                self, indeterminate_name, False):
                            bar.stop()
                            bar.configure(mode='determinate')
                            setattr(self, indeterminate_name, False)
                        bar.set(fraction)
                    self._set_status(f'正在写入 | {percent}%')
                    if self.active_page_key == 'u12':
                        self.u12_progress_text_var.set(f'总进度 {percent}%')
                elif kind == 'ota_target_status':
                    host, status = value
                    row = self.ota_device_rows.get(host)
                    if row is not None:
                        row['status_var'].set(status)
                        if '失败' in status or '错误' in status:
                            row['status_label'].configure(text_color='#B91C1C')
                        elif '完成' in status:
                            row['status_label'].configure(text_color='#15803D')
                        elif '待确认' in status or '核对' in status:
                            row['status_label'].configure(text_color=COLORS['warning_text'])
                        else:
                            row['status_label'].configure(text_color='#2563EB')
                        if status == '升级完成':
                            row['fraction'] = 1.0
                            row['progress'].set(1.0)
                            row['progress_text_var'].set('100%')
                        self._update_ota_batch_progress()
                elif kind == 'ota_target_progress':
                    host, sent, total = value
                    row = self.ota_device_rows.get(host)
                    if row is not None:
                        fraction = sent / max(1, total)
                        row['fraction'] = fraction
                        row['progress'].set(fraction)
                        row['progress_text_var'].set(f'{fraction * 100:.0f}%')
                        self._update_ota_batch_progress()
                elif kind == 'ota_batch_status':
                    self._set_status(value)
                elif kind == 'w78_progress':
                    sent, total, label = value
                    fraction = min(1.0, sent / total) if total else 0.0
                    self.w78_progress.set(fraction)
                    self.w78_progress_text_var.set(label)
                    self.w78_percent_var.set(f'{fraction:.0%}' if total else '—')
                    phase = 2 if ('校验' in label or '完成' in label) else 1 if '写入' in label else 0
                    for i, stage in enumerate(self.w78_stage_labels):
                        color = COLORS['teal'] if i <= phase else COLORS['muted']
                        if stage.cget('text_color') != color:
                            stage.configure(text_color=color)
                elif kind in ('boot_status', 'boot_progress', 'boot_confirm', 'boot_finished'):
                    boot_update_ui.handle_event(self, kind, value)
                elif kind in ('d133_proxy_progress', 'd133_proxy_commit', 'd133_proxy_finished'):
                    d133_proxy_ui.handle_event(self, kind, value)
                elif kind == 'history_finish':
                    self._history_finish(*value)
                elif kind == 'finished':
                    if value is self.stop_event:
                        self.w78_program_started = False
                        self._finish_task()
        except queue.Empty:
            pass
        except Exception as exc:
            # A broken widget or unexpected event must never stop the UI
            # event pump; otherwise Stop would leave the window stuck.
            try:
                self._append_log(f'界面事件处理异常：{exc}')
            except Exception:
                pass
        if self.close_pending and not self.is_running and not self.stlink_check_running:
            return
        if self.root.winfo_exists():
            self.root.after(UI_FRAME_INTERVAL_MS, self._poll_events)

    def _finish_task(self):
        with self.socket_lock:
            self.active_ota_sockets.clear()
            self.ota_socket_cancel_allowed.clear()
        self.ota_batch_running = False
        self.is_running = False
        self.stop_event = None
        self.task_thread = None
        if self.hex_progress_indeterminate and getattr(
                self, 'hex_progress', None) is not None:
            self.hex_progress.stop()
            self.hex_progress.configure(mode='determinate')
            self.hex_progress.set(0)
            self.hex_progress_indeterminate = False
        if self.mplab_progress_indeterminate and getattr(
                self, 'mplab_progress', None) is not None:
            self.mplab_progress.stop()
            self.mplab_progress.configure(mode='determinate')
            self.mplab_progress.set(0)
            self.mplab_progress_indeterminate = False
        if self.u12_progress_indeterminate and getattr(
                self, 'u12_progress', None) is not None:
            self.u12_progress.stop()
            self.u12_progress.configure(mode='determinate')
            self.u12_progress.set(0)
            self.u12_progress_indeterminate = False
        self._set_controls_enabled(True)
        self.stop_button.configure(state=tk.DISABLED, fg_color=COLORS['error_bg'],
                                   hover_color=COLORS['error_bg'], text_color=COLORS['error_text'])
        self._refresh_u12_recovery_view()
        if hasattr(self, 'running_card'):
            self.stop_button.pack_forget()
    def _set_controls_enabled(self, enabled):
        state = tk.NORMAL if enabled else tk.DISABLED
        for widget in self.action_widgets:
            widget.configure(state=state)
        if hasattr(self, 'w78_target_var'):
            self._select_w78_target(self.w78_target_var.get())
        self._refresh_boot_controls()

    def _set_connection_state(self, value):
        self.connection_state_var.set(value)
        if value == '已连接':
            color = '#15803D'
        elif value in ('连接中', '正在重连'):
            color = '#2563EB'
        else:
            color = COLORS['muted']
        self.connection_state_label.configure(text_color=color)

    def _toggle_key_visibility(self):
        self.key_visible = not self.key_visible
        show = '' if self.key_visible else '•'
        label = '隐藏' if self.key_visible else '显示'
        for entry in self.key_entries:
            entry.configure(show=show)
        for button in self.key_visibility_buttons:
            button.configure(text=label)

    @staticmethod
    def _parse_key_text(value):
        try:
            raw_key = str(value).strip().lower().encode('ascii')
        except UnicodeError as exc:
            raise ValueError('Key 格式不正确；请输入 32 个十六进制字符。') from exc
        if len(raw_key) != 32 or any(char not in b'0123456789abcdef' for char in raw_key):
            raise ValueError('Key 格式不正确；请输入 32 个十六进制字符。')
        return raw_key

    @staticmethod
    def _read_key_file(path):
        try:
            value = Path(path).read_text(encoding='utf-8-sig').strip().lower()
        except (OSError, UnicodeError) as exc:
            raise ValueError('无法读取 Key 文件；请选择固件配套的文本密钥文件。') from exc
        return LocalTcpApp._parse_key_text(value)

    def _choose_key(self):
        initial_dir = self.key_path.parent if self.key_path else self.base_dir
        path = filedialog.askopenfilename(
            parent=self.root,
            title='选择与开发板固件配套的 Key 文件',
            initialdir=str(initial_dir),
            filetypes=[('Key 文件', '*.key'), ('文本文件', '*.txt'), ('所有文件', '*.*')],
        )
        if not path:
            return
        try:
            self._read_key_file(path)
        except ValueError as exc:
            messagebox.showerror('Key 文件无效', str(exc), parent=self.root)
            return
        self.key_path = Path(path).resolve()
        self.key_disabled = False
        self.manual_key_var.set('')
        self.key_var.set(self.key_path.name)
        self.key_name_label.configure(text_color=COLORS['cyan'])
        self._save_settings()
        self._append_log(f'已选择 Key 文件：{self.key_path.name}。密钥内容不会复制到程序目录。')

    def _clear_key(self):
        self.key_path = None
        self.key_disabled = True
        self.manual_key_var.set('')
        self.key_var.set('未导入 key 文件')
        self.key_name_label.configure(text_color=COLORS['warning_text'])
        self._save_settings()
        self._update_summaries()
        self._append_log('已选择不使用 Key；设备信息仍可读取，OTA 需在开发板确认。')

    def _connection_inputs(self, host_override=None):
        host = (self.host_var.get() if host_override is None else str(host_override)).strip()
        if not host:
            if host_override is None:
                raise ValueError('请先IPv4 地址 地址。')
            raise ValueError('请在无线烧录页IPv4 地址 地址。')
        try:
            port = int(self.port_var.get())
        except ValueError as exc:
            raise ValueError('端口必须是 1 到 65535 之间的数字。') from exc
        if not 1 <= port <= 65535:
            raise ValueError('端口必须是 1 到 65535 之间的数字。')
        manual_key = self.manual_key_var.get().strip()
        if manual_key:
            raw_key = self._parse_key_text(manual_key)
        elif self.key_path and self.key_path.is_file():
            raw_key = self._read_key_file(self.key_path)
        else:
            raw_key = b''
        return SimpleNamespace(host=host, port=port), raw_key

    def _render_ota_selection_rows(self):
        if not hasattr(self, 'ota_selection_frame'):
            return
        from device_directory import ota_tokens
        hosts = ota_tokens(self.ota_hosts_input.get('1.0', 'end-1c'))
        rows = tuple((host, self._device_display_label(host)) for host in hosts)
        if rows == self.ota_selection_signature:
            return
        self.ota_selection_signature = rows
        old_buttons = set(self.ota_remove_buttons)
        self.action_widgets[:] = [w for w in self.action_widgets if w not in old_buttons]
        self.ota_remove_buttons = []
        for child in self.ota_selection_frame.winfo_children():
            child.destroy()
        if not rows:
            ctk.CTkLabel(self.ota_selection_frame, text='尚未选择升级设备，请从上方选择或手动添加 IP。',
                         text_color=COLORS['muted']).grid(row=0, column=0, sticky='w', padx=8, pady=8)
        for index, (host, label) in enumerate(rows):
            row = ctk.CTkFrame(self.ota_selection_frame, fg_color=COLORS['soft'])
            row.grid(row=index, column=0, sticky='ew', pady=3)
            row.grid_columnconfigure(0, weight=1)
            name = ctk.CTkLabel(row, text=label, anchor='w', text_color=COLORS['text'])
            name._toolbox_user_data = True
            name.grid(row=0, column=0, sticky='ew', padx=10, pady=4)
            button = self._secondary_button(row, '删除',
                lambda target=host: self._remove_ota_target(target), width=72)
            button.configure(height=30, state=tk.DISABLED if self.is_running else tk.NORMAL)
            button.grid(row=0, column=1, padx=(8, 6), pady=4)
            self.ota_remove_buttons.append(button)

    def _write_ota_selection(self, hosts):
        self.ota_hosts_input.delete('1.0', 'end')
        self.ota_hosts_input.insert('1.0', '\n'.join(self._device_display_label(host) for host in hosts))
        self._refresh_ota_names()
        if hasattr(self, 'ota_targets_frame'):
            self._reset_ota_target_rows([])
            self.progress.set(0)
        self._save_settings()

    def _add_ota_target(self, host):
        if self.is_running:
            return False
        from device_directory import normalize_ipv4, ota_tokens
        try:
            host = normalize_ipv4(host)
        except ValueError as exc:
            self._append_log('添加升级设备失败：' + str(exc))
            self._set_status('设备 IP 无效')
            return False
        hosts = ota_tokens(self.ota_hosts_input.get('1.0', 'end-1c'))
        if host in hosts:
            self._set_status('设备已在升级列表')
            return True
        self._write_ota_selection(hosts + [host])
        self._append_log('已加入升级列表：' + self._device_display_label(host))
        return True

    def _add_ota_manual_host(self):
        if self._add_ota_target(self.ota_manual_ip_var.get()):
            self.ota_manual_ip_var.set('')
        return 'break'

    def _remove_ota_target(self, host):
        if self.is_running:
            return
        from device_directory import ota_tokens
        hosts = ota_tokens(self.ota_hosts_input.get('1.0', 'end-1c'))
        self._write_ota_selection([value for value in hosts if value != host])
        self._append_log('已从升级列表删除：' + self._device_display_label(host))

    def _ota_target_hosts(self):
        raw = self.ota_hosts_input.get('1.0', 'end-1c').strip()
        from device_directory import ota_tokens
        tokens = ota_tokens(raw)
        if not tokens:
            raise ValueError('升级列表为空，请先选择或添加需要升级的设备。')
        hosts = []
        seen = set()
        for token in tokens:
            try:
                host = str(ipaddress.ip_address(token))
            except ValueError as exc:
                raise ValueError(f'设备 IP 地址无效：{token}') from exc
            if host in seen:
                raise ValueError(f'设备 IP 重复：{host}')
            seen.add(host)
            hosts.append(host)
        return hosts

    def _reset_ota_target_rows(self, hosts):
        for child in self.ota_targets_frame.winfo_children():
            child.destroy()
        self.ota_device_rows = {}
        for index, host in enumerate(hosts):
            row_frame = ctk.CTkFrame(self.ota_targets_frame, fg_color='transparent')
            row_frame.grid(row=index, column=0, sticky='ew', padx=4, pady=3)
            row_frame.grid_columnconfigure(1, weight=1)
            ctk.CTkLabel(
                row_frame, text=self._device_display_label(host), width=150, anchor='w',
                font=self._font(10, 'bold'), text_color=COLORS['text'],
            ).grid(row=0, column=0, sticky='w', padx=(3, 10))
            status_var = tk.StringVar(master=self.root, value='等待开始')
            status_label = ctk.CTkLabel(
                row_frame, textvariable=status_var, anchor='w',
                font=self._font(9), text_color=COLORS['muted'],
            )
            status_label.grid(row=0, column=1, sticky='ew')
            progress = ctk.CTkProgressBar(
                row_frame, width=150, height=7, corner_radius=5,
                progress_color=COLORS['teal'], fg_color=COLORS['input'],
            )
            progress.grid(row=0, column=2, sticky='e', padx=(8, 5))
            progress.set(0)
            progress_text_var = tk.StringVar(master=self.root, value='0%')
            ctk.CTkLabel(
                row_frame, textvariable=progress_text_var, width=42,
                anchor='e', font=self._font(9), text_color=COLORS['muted'],
            ).grid(row=0, column=3, sticky='e', padx=(0, 3))
            self.ota_device_rows[host] = {
                'status_var': status_var,
                'status_label': status_label,
                'progress': progress,
                'progress_text_var': progress_text_var,
                'fraction': 0.0,
            }

    def _start_task(self, title, action, require_connection=True, host_override=None):
        if self.is_running:
            return
        if require_connection or host_override is not None:
            try:
                args, key = self._connection_inputs(host_override=host_override)
            except ValueError as exc:
                messagebox.showerror('无法开始', str(exc), parent=self.root)
                return
        else:
            args, key = None, None
        self._save_settings()
        if args is not None:
            self.connection_summary_var.set(f'{args.host}:{args.port}')
        self.is_running = True
        self.stop_event = threading.Event()
        stop_event = self.stop_event
        record = None
        try:
            self._set_controls_enabled(False)
            self._refresh_u12_recovery_view()
            self.stop_button.configure(state=tk.NORMAL, fg_color=COLORS['error_text'],
                                       hover_color='#991B1B', text_color='#FFFFFF')
            self._set_status(title)
            for bar in (getattr(self, 'progress', None), getattr(self, 'w78_progress', None),
                        getattr(self, 'hex_progress', None),
                        getattr(self, 'mplab_progress', None),
                        getattr(self, 'u12_progress', None)):
                if bar is not None:
                    bar.set(0)
            if title == 'ST-LINK 烧录 HEX 文件' and self.hex_progress is not None:
                self.hex_progress.configure(mode='indeterminate')
                self.hex_progress.start()
                self.hex_progress_indeterminate = True
            elif title == 'MPLAB PICkit 3 烧录 HEX 文件' and self.mplab_progress is not None:
                self.mplab_progress.configure(mode='indeterminate')
                self.mplab_progress.start()
                self.mplab_progress_indeterminate = True
            self._append_log(f'开始：{title}')
            record = self._history_start(title, args.host if args is not None else '')
    
            def worker():
                # 正常返回只说明工具箱任务结束，不能证明每个目标升级成功。
                result = '已结束'
                try:
                    action(args, key, stop_event)
                    if stop_event.is_set():
                        result = '已停止等待'
                except InterruptedError:
                    result = '已停止等待'
                    self._post('log', '操作已停止。')
                    self._post('status', '已停止')
                except Exception as exc:
                    if stop_event.is_set():
                        result = '已停止等待'
                        self._post('log', '操作已停止。')
                        self._post('status', '已停止')
                    else:
                        result = '失败'
                        self._post('log', f'操作失败：{self._friendly_error(exc, args)}')
                        if isinstance(exc, socket.timeout):
                            self._post('status', '连接超时')
                        else:
                            self._post('status', '操作失败')
                finally:
                    if record is not None:
                        self._post('history_finish', (record, result))
                    self._post('finished', stop_event)
    
            self.task_thread = threading.Thread(target=worker, name='LocalTCP-worker', daemon=True)
            self.task_thread.start()
        except Exception as exc:
            self._history_finish(record, '未启动')
            self._finish_task()
            self._set_status("任务未启动")
            self._append_log(f"任务启动失败：{exc}")

    @contextmanager
    def _connection(self, args, key, stop_event, update_status=True):
        if stop_event.is_set():
            raise InterruptedError()
        if update_status:
            self._post('status', f'正在连接 {args.host}:{args.port}…')
        self._post('connection_state', '连接中' if update_status else '正在重连')
        observed = [None]
        sock = None
        failed = False

        def register_socket(candidate):
            # 重试会创建新套接字；始终登记当前对象，让停止按钮立即唤醒建连/认证。
            with self.socket_lock:
                if stop_event.is_set():
                    raise InterruptedError()
                observed[0] = candidate
                self.connecting_socket = candidate

        try:
            sock = connect(args, key, cancel=stop_event, on_socket=register_socket,
                           on_info=lambda body: self._on_device_info(body)
                           if not stop_event.is_set() else None)
            with self.socket_lock:
                if stop_event.is_set():
                    raise InterruptedError()
                self.connecting_socket = None
                self.active_socket = sock
            if update_status:
                self._post('status', '已连接并通过认证' if key else '已连接，可读取设备信息')
            self._post('connection_state', '已连接')
            yield sock
        except Exception:
            failed = True
            raise
        finally:
            with self.socket_lock:
                if self.active_socket is sock:
                    self.active_socket = None
                if self.connecting_socket is observed[0]:
                    self.connecting_socket = None
            self._post('connection_state', '未连接' if failed else '连接已释放')
            if sock is not None:
                self._close_socket(sock)

    @staticmethod
    def _friendly_error(exc, args):
        if args is None:
            return str(exc)
        if isinstance(exc, socket.timeout):
            return (f'连接 {args.host}:{args.port} 等待响应超时。请确认开发板显示 LISTENING、IP/端口正确；'
                    '若启用了 Mihomo/VPN 的 TUN 模式，请将设备网段设为直连或暂时关闭 TUN。')
        if isinstance(exc, ConnectionRefusedError):
            return (f'{args.host}:{args.port} 拒绝连接。请在开发板开启 Local TCP / OTA，'
                    '确认状态为 LISTENING，并检查当前 IP。')
        if isinstance(exc, ConnectionError):
            return (f'{exc}。请确认连接目标是开发板、电脑与开发板网络可互访，'
                    '且工具密钥与设备固件配套。')
        if isinstance(exc, OSError):
            return f'网络错误：{exc}。请检查设备 IP、局域网路由和 VPN/TUN 设置。'
        return str(exc)

    @staticmethod
    def _close_socket(sock):
        """Close a socket so a recv() blocked in another thread really wakes."""
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            sock.close()
        except OSError:
            pass

    def _cancel_socket_async(self, sock, cancel_frame=None, send_lock=None,
                             name='LocalTCP-cancel'):
        """Send an optional cancel frame, then always close the socket.

        On Windows, shutdown() does not reliably wake a recv() blocked in
        another thread; closing the socket does.  The cancel frame is sent on
        a helper thread so a jammed send or a held send lock cannot freeze the
        Tk main loop.  The socket is closed even when the frame cannot be sent.
        """
        def worker():
            try:
                if cancel_frame is not None:
                    try:
                        sock.settimeout(0.5)
                    except OSError:
                        pass
                    acquired = True
                    if send_lock is not None:
                        acquired = send_lock.acquire(timeout=0.2)
                    if acquired:
                        try:
                            sock.sendall(cancel_frame)
                        except OSError:
                            pass
                        finally:
                            if send_lock is not None:
                                send_lock.release()
            finally:
                self._close_socket(sock)
        threading.Thread(target=worker, name=name, daemon=True).start()

    def _terminate_process_async(self, process):
        """Give terminate() a short chance, then force-kill a stuck child."""
        def worker():
            deadline = time.monotonic() + 2.0
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    return
                time.sleep(0.1)
            try:
                process.kill()
            except OSError:
                pass
        threading.Thread(target=worker, name='process-stop', daemon=True).start()

    def _stop_operation(self):
        pending = getattr(self, 'device_name_sync_pending', {})
        if pending:
            count = len(pending)
            pending.clear()
            self._append_log(f'已取消 {count} 个等待发送的设备名称。')
        if getattr(self, 'device_scan_running', False):
            self._cancel_device_scan()
            self.stop_button.configure(state=tk.DISABLED)
            self._set_status('正在停止设备扫描…')
            self._append_log('已停止设备扫描；正在关闭活动网络连接。')
            return
        if not self.is_running or self.stop_event is None:
            self._set_status('已停止')
            return
        if self.task_thread is None or not self.task_thread.is_alive():
            self._finish_task()
            self._set_status('已停止')
            self._append_log('已清理未运行的任务状态，操作已停止。')
            return
        if self.d133_proxy_running:
            d133_proxy_ui.stop_operation(self)
            return
        if self.boot_update_running:
            boot_update_ui.stop_operation(self)
            return
        if self.ota_batch_running:
            with self.socket_lock:
                active_ota = list(self.active_ota_sockets.items())
                committing = [
                    host for host, _sock in active_ota
                    if not self.ota_socket_cancel_allowed.get(host, True)
                ]
            if committing:
                self._append_log('已停止电脑端等待；正在提交的设备会继续完成写入：' + '、'.join(committing))
            self.stop_event.set()
            self.stop_button.configure(state=tk.DISABLED, fg_color=COLORS['error_bg'],
                                       hover_color='#FECACA', text_color=COLORS['error_text'])
            self._set_status('正在停止多设备更新…')
            for host, ota_socket in active_ota:
                self._cancel_socket_async(
                    ota_socket, None if host in committing else frame(5), self.ota_send_lock,
                    f'OTA-cancel-{host}',
                )
            if active_ota:
                self._append_log('正在向所有升级中的设备发送取消指令并断开连接…')
            return
        with self.socket_lock:
            sock = self.active_socket or self.connecting_socket
        self.stop_event.set()
        self.stop_button.configure(state=tk.DISABLED, fg_color=COLORS['error_bg'],
                                   hover_color=COLORS['error_bg'], text_color=COLORS['error_text'])
        self._set_status('正在停止…')
        if sock is not None:
            if self.w78_program_started:
                self._append_log('正在停止当前烧录；如已擦写，开发板将保持目标复位。')
                self._cancel_socket_async(
                    sock, frame(13), self.w78_send_lock, 'W78-cancel')
            else:
                # The worker may be blocked in a socket read with no timeout
                # (for example "主动上传").  Closing the socket is what wakes
                # it on Windows; shutdown() alone leaves the UI stuck.
                self._cancel_socket_async(sock, None, None, 'LocalTCP-cancel')
        with self.process_lock:
            process = self.active_process
        if process is not None and process.poll() is None:
            try:
                process.terminate()
            except OSError:
                pass
            self._terminate_process_async(process)

    def _on_device_info(self, body):
        self._post('device_info', body)
        self._post('log', '收到设备信息：\n' + self._format_json(body))

    @staticmethod
    def _metric_integer(value):
        if isinstance(value, bool):
            return int(value)
        if isinstance(value, int):
            return value
        if isinstance(value, float) and value.is_integer():
            return int(value)
        if isinstance(value, str):
            text = value.strip()
            return int(text, 16) if text.lower().startswith('0x') else int(text)
        raise ValueError('不是整数')

    @classmethod
    def _format_device_metric(cls, key, value):
        if value is None:
            return '—', '设备未提供此字段'
        if key == 'screen_resolution':
            match = re.fullmatch(r'\s*(\d+)\s*[xX×]\s*(\d+)\s*', str(value))
            return (f'{match[1]} × {match[2]}', '像素') if match else (str(value), '')
        if key in ('version', 'board', 'framework', 'uid'):
            return str(value), ''
        try:
            number = cls._metric_integer(value)
        except (TypeError, ValueError, OverflowError):
            return str(value), ''
        if key == 'uptime_ms':
            seconds = max(0, number // 1000)
            days, seconds = divmod(seconds, 86400)
            hours, seconds = divmod(seconds, 3600)
            minutes, seconds = divmod(seconds, 60)
            parts = []
            if days:
                parts.append(f'{days}天')
            if hours:
                parts.append(f'{hours}小时')
            if minutes:
                parts.append(f'{minutes}分')
            parts.append(f'{seconds}秒')
            return ' '.join(parts), f'{number:,} ms'
        if key == 'hclk_hz':
            mhz = number / 1_000_000
            value_text = f'{mhz:g} MHz'
            return value_text, f'{number:,} Hz'
        if key in ('touch_ready', 'qspi_mapped'):
            state = '就绪' if number else '未就绪'
            if key == 'qspi_mapped':
                state = '已映射' if number else '未映射'
            return state, f'设备值：{number}'
        if key == 'flash_jedec':
            return f'0x{number:08X}', f'{number:,}（十进制）'
        if key in ('backlight_compare', 'ui_frames'):
            return f'{number:,}', ''
        return f'{number:,}', ''

    def _update_device_metric_values(self, data):
        for key, value_var in self.device_metric_vars.items():
            value, detail = self._format_device_metric(key, data.get(key))
            value_var.set(value)
            self.device_metric_detail_vars[key].set(detail)

    def _render_device_info(self, body):
        try:
            data = parse_device_info(body)
            if not isinstance(data, dict):
                raise ValueError('设备数据不是 JSON 对象')
        except (AttributeError, UnicodeError, ValueError, TypeError):
            self.device_received_var.set('收到的数据不是有效 JSON')
            return
        data = normalize_device_info(data)
        self.device_info_cache = data
        self.device_received_var.set(f"最近接收：{time.strftime('%H:%M:%S')}")
        self._update_device_metric_values(data)

    @staticmethod
    def _format_json(body):
        try:
            return json.dumps(normalize_device_info(parse_device_info(body)), ensure_ascii=False, indent=2)
        except (UnicodeError, ValueError):
            return body.decode('utf-8', errors='replace')

    def _read_once(self):
        def action(args, key, stop_event):
            with self._connection(args, key, stop_event) as sock:
                if stop_event.is_set():
                    raise InterruptedError()
                body = request(sock, 1, on_info=self._on_device_info)
                self._post('device_info', body)
                self._post('log', '设备信息：\n' + self._format_json(body))
                self._post('status', '已读取设备信息')
        self._start_task('读取设备信息', action)

    def _listen(self):
        def action(args, key, stop_event):
            failures = 0
            while not stop_event.is_set():
                connected_at = None
                try:
                    with self._connection(args, key, stop_event) as sock:
                        connected_at = time.monotonic()
                        # 只读监听建立后主动读取一次，接收帧始终由同一个线程处理。
                        body = request(sock, 1, on_info=self._on_device_info)
                        self._on_device_info(body)
                        sock.settimeout(None)
                        self._post('status', '信息连接已保持；点击“停止”断开')
                        while not stop_event.is_set():
                            # 禁止超时后重启同一连接的收帧，避免把半帧当成新帧头。
                            op, body = receive(sock)
                            if op != 0x80000001:
                                raise ValueError(f'收到未知响应命令：{op}')
                            self._on_device_info(body)
                except (ConnectionError, OSError) as exc:
                    if stop_event.is_set():
                        raise InterruptedError() from exc
                    # 仅只读监听允许恢复连接；烧录、OTA 等写操作不在此重放。
                    if connected_at is not None and time.monotonic() - connected_at >= 10:
                        failures = 0
                    delay = min(5.0, 0.5 * (2 ** min(failures, 4)))
                    failures += 1
                    self._post('connection_state', '正在重连')
                    self._post('status', f'信息连接中断，{delay:g} 秒后重连；可停止')
                    self._post('log', f'只读信息连接中断：{exc}；正在重连。')
                    if stop_event.wait(delay):
                        raise InterruptedError() from exc
            raise InterruptedError()
        self._start_task('保持设备信息连接', action)

    def _set_package(self, path):
        path = Path(path).resolve()
        # 统一固件已取消独立 App 安装，明确拒绝旧包，避免误发旧协议。
        if path.suffix.lower() in ('.fapp', '.fappb'):
            raise ValueError('已取消独立 App 更新，请选择包含全部 App 的系统 OTA 包。')
        package = path.read_bytes()
        version = validate_package(package)
        self.package_path = path
        self.package_version = version
        self.package_var.set(path.name)
        self.package_hint_var.set(f'版本 {version} | {len(package):,} 字节 | 包校验通过')

    def _choose_package(self):
        path = filedialog.askopenfilename(
            parent=self.root,
            title='选择完整的 STM32F750 OTA 升级包',
            initialdir=str(self.base_dir),
            filetypes=[('系统 OTA 升级包', '*.ota.bin'), ('所有文件', '*.*')],
        )
        if not path:
            return
        try:
            self._set_package(path)
            self._append_log(f'已选择升级包：{self.package_path.name}（版本 {self.package_version}）')
        except Exception as exc:
            messagebox.showerror('升级包无效', str(exc), parent=self.root)

    def _choose_w78_hex(self):
        initial_dir = self.w78_hex_path.parent if self.w78_hex_path else self.base_dir
        path = filedialog.askopenfilename(
            parent=self.root,
            title='选择当前烧录对象的 Intel HEX 文件',
            initialdir=str(initial_dir),
            filetypes=[('Intel HEX 文件', '*.hex'), ('所有文件', '*.*')],
        )
        if not path:
            return
        try:
            selected = Path(path).resolve()
            from pic24_hex import validate_pic24_hex
            package = validate_pic24_hex(selected) if self.w78_target_var.get().startswith('PIC24') else validate_w78_hex(selected)
            # 校验兼容传输名，但 Windows 界面只显示原始文件名。
            validate_w78_filename(selected)
            eof_marker_note = ' | 已忽略末尾 Ctrl+Z' if selected.stat().st_size != len(package) else ''
            self.w78_hex_path = selected
            self.w78_hex_name_var.set(selected.name)
            self.w78_hex_summary_var.set(
                f'{len(package):,} 字节 | Intel HEX 校验通过 | {self.w78_target_var.get()}\n'
                f'{selected.name}{eof_marker_note}')
            self.w78_progress.set(0)
            self.w78_progress_text_var.set('HEX 已就绪，等待无线烧录')
            self._append_log(
                f'已选择 HEX：{selected.name}（{len(package):,} 字节，记录校验通过{eof_marker_note}）')
        except Exception as exc:
            messagebox.showerror('W78 HEX 无效', str(exc), parent=self.root)

    def _choose_hex_file(self):
        initial_dir = self.hex_file.parent if self.hex_file else self.base_dir
        path = filedialog.askopenfilename(
            parent=self.root,
            title='选择 STM32 Intel HEX 文件',
            initialdir=str(initial_dir),
            filetypes=[('Intel HEX 文件', '*.hex'), ('所有文件', '*.*')],
        )
        if not path:
            return
        candidate = Path(path).resolve()
        try:
            if candidate.suffix.lower() != '.hex':
                raise ValueError('请选择 .hex 格式的 Intel HEX 文件。')
            if not candidate.is_file() or candidate.stat().st_size == 0:
                raise ValueError('HEX 文件不存在或为空。')
            (first_address, last_address, has_qspi,
             has_internal_flash, has_sram) = inspect_intel_hex(candidate)
        except (OSError, UnicodeError, ValueError) as exc:
            messagebox.showerror('HEX 文件无效', str(exc), parent=self.root)
            return
        self.hex_file = candidate
        self.hex_address_range = (first_address, last_address)
        self.hex_has_external_data = has_qspi
        self.hex_has_internal_flash = has_internal_flash
        self.hex_has_sram = has_sram
        self.hex_extension_download_var.set(False)
        self.hex_name_var.set(candidate.name)
        self.hex_path_detail_var.set(str(candidate))
        range_text = f'地址范围 0x{first_address:08X}–0x{last_address:08X}'
        self.hex_memory_summary_var.set(range_text)
        self._update_hex_extension_hint()
        self._append_log(
            f'已选择 HEX 文件：{candidate.name}（{candidate.stat().st_size:,} 字节，{range_text}）')

    def _choose_pk3cmd(self):
        initial_dir = self.mplab_cli_path.parent if self.mplab_cli_path else Path('C:/Program Files (x86)/Microchip')
        path = filedialog.askopenfilename(
            parent=self.root,
            title='选择 MPLAB PICkit 3 命令行工具',
            initialdir=str(initial_dir),
            filetypes=[('PICkit 3 命令行工具', 'PK3CMD.exe'), ('可执行文件', '*.exe')],
        )
        if not path:
            return
        candidate = Path(path).resolve()
        if candidate.name.casefold() != 'pk3cmd.exe':
            messagebox.showerror('工具不匹配', '请选择 MPLAB IDE 中的 PK3CMD.exe。', parent=self.root)
            return
        if not (candidate.parent / 'MPPICkit3.dll').is_file():
            messagebox.showerror(
                '缺少 PICkit 3 组件',
                '所选目录没有 MPPICkit3.dll。请从 MPLAB IDE 的 Programmer Utilities\\PICkit3 目录中选择 PK3CMD.exe。',
                parent=self.root,
            )
            return
        self.mplab_cli_path = candidate
        self.mplab_cli_path_var.set(str(candidate))
        self.mplab_tool_status_var.set('已找到 MPLAB 烧录命令')
        self.mplab_tool_status_label.configure(text_color=COLORS['cyan'])
        if hasattr(self, 'u12_cli_status_label'):
            self.u12_cli_status_label.configure(text_color=COLORS['cyan'])
        self._save_settings()
        self._append_log(f'已选择 PICkit 3 命令工具：{candidate}')

    def _choose_mplab_hex_file(self):
        initial_dir = self.mplab_file.parent if self.mplab_file else self.base_dir
        path = filedialog.askopenfilename(
            parent=self.root,
            title='选择 PIC24 Intel HEX 文件',
            initialdir=str(initial_dir),
            filetypes=[('Intel HEX 文件', '*.hex'), ('所有文件', '*.*')],
        )
        if not path:
            return
        candidate = Path(path).resolve()
        try:
            if candidate.suffix.lower() != '.hex':
                raise ValueError('请选择 .hex 格式的 Intel HEX 文件。')
            if not candidate.is_file() or candidate.stat().st_size == 0:
                raise ValueError('HEX 文件不存在或为空。')
            first_address, last_address, *_ = inspect_intel_hex(candidate)
        except (OSError, UnicodeError, ValueError) as exc:
            messagebox.showerror('HEX 文件无效', str(exc), parent=self.root)
            return
        self.mplab_file = candidate
        self.mplab_address_range = (first_address, last_address)
        self.mplab_hex_name_var.set(candidate.name)
        self.mplab_hex_path_var.set(str(candidate))
        self.mplab_hex_summary_var.set(
            f'Intel HEX 已通过格式检查 | 地址范围 0x{first_address:08X}–0x{last_address:08X}')
        self.mplab_hex_summary_label.configure(text_color=COLORS['cyan'])
        self._append_log(
            f'已选择 PIC24 HEX：{candidate.name}（{candidate.stat().st_size:,} 字节，'
            f'地址范围 0x{first_address:08X}–0x{last_address:08X}）')

    def _choose_u12_image(self):
        initial_dir = self.u12_image_path.parent if self.u12_image_path else self.base_dir
        path = filedialog.askopenfilename(
            parent=self.root,
            title='选择用于 U12 的图片',
            initialdir=str(initial_dir),
            filetypes=[
                ('图片文件', '*.png *.jpg *.jpeg *.bmp *.gif *.tif *.tiff *.webp'),
                ('所有文件', '*.*'),
            ],
        )
        if not path:
            return
        candidate = Path(path).resolve()
        try:
            converted, preview = rgb565_be_image(candidate)
            if len(converted) != PIC24_U12_IMAGE_BYTES:
                raise ValueError('图片转换后的长度不正确。')
        except Exception as exc:
            messagebox.showerror('图片无法转换', str(exc), parent=self.root)
            return
        self.u12_image_path = candidate
        self.u12_image_data = converted
        self.u12_image_name_var.set(candidate.name)
        self.u12_image_path_var.set(str(candidate))
        self.u12_image_detail_var.set(
            '已自动转换 | 800 × 480 | RGB565 大端 | 768,000 字节 | 以中心裁切适配 5:3')
        self.u12_preview = ctk.CTkImage(
            light_image=preview, dark_image=preview, size=(320, 192))
        self.u12_preview_label.configure(image=self.u12_preview, text='')
        self.u12_progress_text_var.set('图片已转换，确认 PICkit 3 后即可写入 U12。')
        self._append_log(
            f'已选择 U12 图片：{candidate.name}，自动转换为 800×480 RGB565（{len(converted):,} 字节）。')
        self._refresh_u12_recovery_view()

    def _u12_cli_path(self):
        cli_path = self.mplab_cli_path
        if not cli_path or not cli_path.is_file():
            cli_path = discover_pk3cmd()
        if not cli_path or not cli_path.is_file():
            messagebox.showerror(
                '找不到 PK3CMD',
                '请先安装 MPLAB IDE v8.90，或点击“定位 PK3CMD…”选择 PICkit 3 的 PK3CMD.exe。',
                parent=self.root,
            )
            return None
        if not (cli_path.parent / 'MPPICkit3.dll').is_file():
            messagebox.showerror(
                'MPLAB 组件不完整',
                'PK3CMD.exe 所在目录缺少 MPPICkit3.dll。请选择 Programmer Utilities\\PICkit3 中的完整工具。',
                parent=self.root,
            )
            return None
        self.mplab_cli_path = cli_path.resolve()
        self.mplab_cli_path_var.set(str(self.mplab_cli_path))
        self.mplab_tool_status_var.set('已找到 MPLAB 烧录命令')
        if hasattr(self, 'mplab_tool_status_label'):
            self.mplab_tool_status_label.configure(text_color=COLORS['cyan'])
        if hasattr(self, 'u12_cli_status_label'):
            self.u12_cli_status_label.configure(text_color=COLORS['cyan'])
        return self.mplab_cli_path

    @staticmethod
    def _wait_for_process(process, timeout=3.0):
        """Wait for a child without ever blocking a worker indefinitely."""
        try:
            return process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            try:
                process.kill()
            except OSError:
                pass
            try:
                return process.wait(timeout=1.0)
            except subprocess.TimeoutExpired:
                return None

    def _run_pk3_command(self, cli_path, arguments, stop_event, label,
                         progress_range=None, ignore_stop=False):
        if stop_event.is_set() and not ignore_stop:
            raise InterruptedError()
        command = [str(cli_path), *[str(argument) for argument in arguments]]
        self._post('status', label)
        self._post('log', 'PK3CMD：' + ' '.join(command[1:]))
        output_queue = queue.Queue()
        output_lines = []
        process = None
        reader_thread = None
        try:
            try:
                process = subprocess.Popen(
                    command,
                    cwd=str(cli_path.parent),
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    bufsize=-1,
                    creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0),
                )
            except OSError as exc:
                raise RuntimeError(f'无法启动 PK3CMD：{exc}') from exc
            with self.process_lock:
                self.active_process = process

            def read_output():
                try:
                    while True:
                        chunk = process.stdout.read1(4096)
                        if not chunk:
                            break
                        output_queue.put(chunk)
                finally:
                    output_queue.put(None)

            reader_thread = threading.Thread(
                target=read_output, name='PK3CMD-U12-output', daemon=True)
            reader_thread.start()
            output_finished = False
            output_buffer = bytearray()

            def handle_output(raw_line):
                for line in decode_programmer_output(raw_line).splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    output_lines.append(line)
                    self._post('log', line)
                    if progress_range is not None:
                        percentages = re.findall(r'\b(\d{1,3})\s*%', line)
                        if percentages:
                            percent = min(100, int(percentages[-1]))
                            start, span = progress_range
                            self._post('progress', (start + span * percent // 100, 100))

            stop_started = None
            while not output_finished:
                if stop_event.is_set() and not ignore_stop:
                    now = time.monotonic()
                    if stop_started is None:
                        stop_started = now
                        if process.poll() is None:
                            try:
                                process.terminate()
                            except OSError:
                                pass
                    elif now >= stop_started + 1.5 and process.poll() is None:
                        try:
                            process.kill()
                        except OSError:
                            pass
                    # A grandchild can inherit the stdout pipe and keep it open
                    # after PK3CMD dies.  Do not wait on that pipe forever.
                    if now >= stop_started + 3.0:
                        if output_buffer:
                            handle_output(bytes(output_buffer))
                            output_buffer.clear()
                        output_finished = True
                        break
                try:
                    raw_line = output_queue.get(timeout=0.1)
                except queue.Empty:
                    continue
                if raw_line is None:
                    if output_buffer:
                        handle_output(bytes(output_buffer))
                        output_buffer.clear()
                    output_finished = True
                else:
                    output_buffer.extend(raw_line)
                    while True:
                        separators = [position for position in (
                            output_buffer.find(b'\n'), output_buffer.find(b'\r'))
                            if position >= 0]
                        if not separators:
                            break
                        end = min(separators)
                        raw_line = bytes(output_buffer[:end])
                        del output_buffer[:end + 1]
                        if raw_line:
                            handle_output(raw_line)
            return_code = self._wait_for_process(process, 3.0)
        finally:
            if process is not None:
                if process.poll() is None:
                    try:
                        process.terminate()
                    except OSError:
                        pass
                    self._wait_for_process(process, 1.0)
                if process.stdout is not None and (
                        reader_thread is None or not reader_thread.is_alive()):
                    try:
                        process.stdout.close()
                    except OSError:
                        pass
            with self.process_lock:
                if self.active_process is process:
                    self.active_process = None
        if stop_event.is_set() and not ignore_stop:
            raise InterruptedError()
        return return_code, '\n'.join(output_lines)

    @staticmethod
    def _write_u12_recovery_state(backup_path):
        state_path = u12_recovery_state_path()
        state_path.parent.mkdir(parents=True, exist_ok=True)
        state = {
            'part': PIC24_U12_PART,
            'backup_path': str(Path(backup_path).resolve()),
            'created_at': time.strftime('%Y-%m-%d %H:%M:%S'),
        }
        state_path.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding='utf-8')
        return state

    @staticmethod
    def _clear_u12_recovery_state(state):
        try:
            u12_recovery_state_path().unlink(missing_ok=True)
        except OSError:
            pass
        backup_path = Path(state.get('backup_path', '')) if state else None
        if backup_path:
            try:
                backup_path.unlink(missing_ok=True)
            except OSError:
                pass

    def _restore_u12_backup(self, cli_path, backup_path, stop_event, ignore_stop=False,
                            progress_range=None):
        temporary_hex = copy_file_to_ascii_temp(
            backup_path, prefix='U12_RSTR_', suffix='.hex')
        try:
            return_code, output = self._run_pk3_command(
                cli_path,
                [f'-P{PIC24_U12_PART}', f'-F{temporary_hex}', '-M', '-Y'],
                stop_event,
                '正在恢复 PIC24 原程序…',
                progress_range=progress_range,
                ignore_stop=ignore_stop,
            )
        finally:
            temporary_hex.unlink(missing_ok=True)
        if return_code != 0:
            raise RuntimeError(
                f'PIC24 备份恢复失败（PK3CMD 退出代码 {return_code}）。请检查操作日志后再次点击“恢复 PIC24 备份”。')
        return output

    def _start_u12_restore(self):
        state = self.u12_recovery_state
        backup_path = Path(state.get('backup_path', '')) if state else None
        if not backup_path or not backup_path.is_file():
            messagebox.showerror('找不到备份', '没有可用的 PIC24 备份 HEX。', parent=self.root)
            return
        cli_path = self._u12_cli_path()
        if cli_path is None:
            return
        if not messagebox.askyesno(
            '确认恢复 PIC24',
            f'将使用备份文件恢复 PIC24：\n{backup_path}\n\n保持开发板供电并连接 PICkit 3。继续吗？',
            parent=self.root,
        ):
            return

        def action(args, key, stop_event):
            self._post('log', f'使用备份恢复 PIC24：{backup_path.name}')
            self._restore_u12_backup(
                cli_path, backup_path, stop_event, progress_range=(5, 95))
            self._clear_u12_recovery_state(state)
            self._post('u12_recovery', None)
            self._post('progress', (100, 100))
            self._post('status', 'PIC24 原程序恢复并校验完成')
            self._post('log', 'PIC24 原程序已从备份恢复并通过 PK3CMD 校验。')

        self._start_task('恢复 PIC24 备份', action, require_connection=False)

    def _start_u12_programming(self):
        image_data = self.u12_image_data
        image_path = self.u12_image_path
        if not image_data or not image_path:
            messagebox.showerror('未选择图片', '请先选择一张图片，工具会自动转换格式。', parent=self.root)
            return
        if self.u12_recovery_state:
            messagebox.showerror(
                '需要先恢复 PIC24',
                '检测到上次操作留下的 PIC24 备份。请先点击“恢复 PIC24 备份”，确认 PIC24 已恢复后再写 U12。',
                parent=self.root,
            )
            return
        cli_path = self._u12_cli_path()
        if cli_path is None:
            return
        chunk_capacity = ((PIC24_U12_MAX_STAGED_BYTES - PIC24_U12_HEADER_SIZE) // 256) * 256
        chunk_count = (len(image_data) + chunk_capacity - 1) // chunk_capacity
        fast_u12 = bool(
            getattr(self, 'u12_fast_write_var', None)
            and self.u12_fast_write_var.get()
        )
        if not messagebox.askyesno(
            '确认写入板载 U12',
            f'图片：{image_path.name}\n目标：PIC24FJ256DA210 + U12/W25Q32\n'
            f'数据：800 × 480 RGB565，{len(image_data):,} 字节，分 {chunk_count} 批写入\n\n'
            '工具会先备份 PIC24，临时写入桥接程序，擦除并校验 U12，最后恢复 PIC24。'
            '期间请勿断电、拔出 PICkit 3 或关闭工具。是否开始？',
            parent=self.root,
        ):
            return

        def action(args, key, stop_event):
            bridge_hex = app_resource_path('u12_pic24_bridge.hex')
            if not bridge_hex.is_file():
                raise RuntimeError('工具包缺少 U12/PIC24 桥接固件，请重新安装完整便携版。')
            if stop_event.is_set():
                raise InterruptedError()

            temporary_files = []
            backup_path = None
            pending_state = None
            try:
                backup_temp = create_ascii_temp_file('U12_BKUP_', '.hex')
                temporary_files.append(backup_temp)
                self._post('status', '正在读取并备份 PIC24…')
                self._post('progress', (2, 100))
                code, _ = self._run_pk3_command(
                    cli_path, [f'-P{PIC24_U12_PART}', f'-GF{backup_temp}'],
                    stop_event, '正在备份 PIC24 当前程序…', progress_range=(2, 8))
                if code != 0 or not backup_temp.is_file() or backup_temp.stat().st_size == 0:
                    raise RuntimeError(f'无法备份 PIC24（PK3CMD 退出代码 {code}），没有改写目标程序。')
                backup_memory = read_intel_hex_memory(backup_temp)
                if not any(0x400 <= address < 0x55800 for address in backup_memory):
                    raise RuntimeError('PIC24 备份中没有可恢复的用户程序数据；为保护原程序，已停止写入。')

                recovery_dir = u12_recovery_state_path().parent
                recovery_dir.mkdir(parents=True, exist_ok=True)
                timestamp = time.strftime('%Y%m%d_%H%M%S')
                backup_path = recovery_dir / f'PIC24FJ256DA210_{timestamp}.hex'
                shutil.copyfile(backup_temp, backup_path)
                pending_state = self._write_u12_recovery_state(backup_path)
                self._post('u12_recovery', pending_state)
                self._post('log', f'PIC24 备份已保存：{backup_path}')

                whole_crc = zlib.crc32(image_data) & 0xFFFFFFFF
                if fast_u12:
                    self._post('log', 'U12 快速烧录已开启：保留 PIC24 暂存 CRC，跳过外部 W25Q32 分块与整图回读 CRC。')
                stage_total = 78
                stage_span = stage_total / chunk_count
                for chunk_index, image_offset in enumerate(range(0, len(image_data), chunk_capacity)):
                    if stop_event.is_set():
                        raise InterruptedError()
                    chunk = image_data[image_offset:image_offset + chunk_capacity]
                    stage_temp = create_ascii_temp_file('U12_STAGE_', '.hex')
                    temporary_files.append(stage_temp)
                    create_pic24_u12_stage_hex(
                        bridge_hex, chunk, image_offset, len(image_data),
                        chunk_index, chunk_count, whole_crc, stage_temp,
                        verify_u12=not fast_u12)
                    progress_start = 10 + int(stage_span * chunk_index)
                    progress_width = max(1, int(stage_span))
                    self._post('status', f'正在写入 PIC24 桥接程序和第 {chunk_index + 1}/{chunk_count} 批数据…')
                    self._post('log',
                               f'U12 分块 {chunk_index + 1}/{chunk_count}：'
                               f'偏移 0x{image_offset:06X}，{len(chunk):,} 字节。')
                    code, _ = self._run_pk3_command(
                        cli_path,
                        [f'-P{PIC24_U12_PART}', f'-F{stage_temp}', '-H', '-M'],
                        stop_event,
                        f'正在通过 PICkit 3 写入第 {chunk_index + 1}/{chunk_count} 批…',
                        progress_range=(progress_start, progress_width // 2),
                    )
                    if code != 0:
                        raise RuntimeError(f'PIC24 桥接程序/数据写入失败（PK3CMD 退出代码 {code}）。')

                    # PK3CMD processes combined flags alphabetically, so release
                    # reset in a separate command after programming has finished.
                    code, _ = self._run_pk3_command(
                        cli_path, [f'-P{PIC24_U12_PART}', '-L'],
                        stop_event, '正在释放 PIC24 复位并运行 U12 桥接程序…')
                    if code != 0:
                        raise RuntimeError(f'无法运行 PIC24 桥接程序（PK3CMD 退出代码 {code}）。')

                    erase_blocks = (len(image_data) + 0xFFFF) // 0x10000
                    # PK3CMD reads assert MCLR. The bridge can still be
                    # erasing each 64 KB block for its full 5 s timeout, so
                    # never query status until every erase has a safe window.
                    wait_seconds = 24 + erase_blocks * 6 if chunk_index == 0 else (
                        10 + (len(chunk) + 0xFFFF) // 0x10000
                    )
                    if fast_u12 and chunk_index > 0:
                        wait_seconds = max(
                            8, wait_seconds - (len(chunk) + 0xFFFF) // 0x10000)
                    if chunk_index + 1 == chunk_count and not fast_u12:
                        wait_seconds += (len(image_data) + 0x3FFFF) // 0x40000 * 2
                    phase = '快速写入' if fast_u12 else '写入并校验'
                    self._post('status', f'PIC24 正在{phase} U12（第 {chunk_index + 1}/{chunk_count} 批）…')
                    self._post(
                        'log',
                        f'等待 PIC24 完成 U12 第 {chunk_index + 1} 批桥接写入'
                        f'{"与回读校验" if not fast_u12 else "（快速模式跳过 U12 回读 CRC）"}，'
                        f'预计等待 {wait_seconds} 秒。',
                    )
                    for elapsed in range(wait_seconds):
                        if stop_event.wait(1.0):
                            raise InterruptedError()
                        waiting_progress = progress_start + progress_width // 2 + (
                            (progress_width // 2) * (elapsed + 1) // wait_seconds)
                        self._post('progress', (waiting_progress, 100))

                    status_temp = create_ascii_temp_file('U12_STAT_', '.hex')
                    temporary_files.append(status_temp)
                    code, _ = self._run_pk3_command(
                        cli_path,
                        [
                            f'-P{PIC24_U12_PART}', f'-GF{status_temp}',
                        ],
                        stop_event, f'正在读取第 {chunk_index + 1} 批校验结果…')
                    if code != 0 or not status_temp.is_file() or status_temp.stat().st_size == 0:
                        raise RuntimeError(f'读取 U12 第 {chunk_index + 1} 批校验结果失败（PK3CMD 退出代码 {code}）。')
                    marker = parse_pic24_u12_status(status_temp)
                    if marker is None or not marker['success'] or marker['index'] != chunk_index:
                        trace = parse_pic24_u12_trace(status_temp)
                        self._post('log', f'U12 桥接阶段：{trace}')
                        diagnostic_path = recovery_dir / (
                            f'PIC24_U12_STATUS_{time.strftime("%Y%m%d_%H%M%S")}_'
                            f'{chunk_index + 1}.hex'
                        )
                        try:
                            shutil.copyfile(status_temp, diagnostic_path)
                            self._post('log', f'U12 状态读取原始文件已保留：{diagnostic_path}')
                        except OSError as diagnostic_error:
                            self._post('log', f'无法保存 U12 状态读取原始文件：{diagnostic_error}')
                    if marker is not None and not marker['success']:
                        errors = {
                            1: '暂存分块头无效', 2: 'PIC24 暂存 CRC 不匹配',
                            3: '未识别到 U12/W25Q32', 4: 'U12 擦除失败或超时',
                            5: 'U12 页写入失败或超时', 6: 'U12 分块回读不匹配',
                            7: 'U12 整图 CRC 不匹配',
                            8: 'PIC24 在桥接执行中再次复位，当前分块未完成',
                            9: 'PIC24 内部异常中断导致桥接复位，当前分块未完成',
                        }
                        detail = errors.get(marker['error'], '未知桥接错误')
                        if marker['error'] in (8, 9):
                            rcon = marker['chunk_crc'] & 0xFFFF
                            intcon1 = marker['image_crc'] & 0xFFFF
                            causes = []
                            for mask, name in ((0x8000, '陷阱冲突'), (0x4000, '非法操作码'),
                                               (0x0080, '外部/MCLR 复位'), (0x0040, '软件复位'),
                                               (0x0010, '看门狗'), (0x0002, '欠压'), (0x0001, '上电标志')):
                                if rcon & mask:
                                    causes.append(name)
                            traps = []
                            for mask, name in ((0x0002, '振荡器异常'), (0x0004, '栈异常'),
                                               (0x0008, '地址异常'), (0x0010, '数学异常')):
                                if intcon1 & mask:
                                    traps.append(name)
                            detail += (f'；RCON=0x{rcon:04X}（{"、".join(causes) or "未记录复位标志"}）'
                                       f'，INTCON1=0x{intcon1:04X}（{"、".join(traps) or "未记录陷阱标志"}）')
                        raise RuntimeError(
                            f'U12 桥接失败：{detail}（错误码 {marker["error"]}）。PIC24 备份仍保留。')
                    if marker is None or marker['index'] != chunk_index:
                        raise RuntimeError(
                            f'未读取到 U12 第 {chunk_index + 1} 批的完成标记（{trace}）。PIC24 备份仍保留，请先恢复 PIC24。')
                    chunk_crc = zlib.crc32(chunk) & 0xFFFFFFFF
                    if marker['chunk_crc'] != chunk_crc:
                        raise RuntimeError('U12 分块状态标记与图片数据不匹配；PIC24 备份仍保留。')
                    if chunk_index + 1 == chunk_count and marker['image_crc'] != whole_crc:
                        raise RuntimeError('U12 整图状态标记与图片数据不匹配；PIC24 备份仍保留。')
                    self._post('progress', (progress_start + progress_width, 100))
                    if fast_u12:
                        self._post('log', f'U12 第 {chunk_index + 1}/{chunk_count} 批写入完成；快速模式已跳过 U12 回读 CRC。')
                    else:
                        self._post('log', f'U12 第 {chunk_index + 1}/{chunk_count} 批写入和回读校验通过。')
                    stage_temp.unlink(missing_ok=True)
                    temporary_files.remove(stage_temp)
                    status_temp.unlink(missing_ok=True)
                    temporary_files.remove(status_temp)

                self._post('status', 'U12 写入完成，正在按选项处理 PIC24…')
                self._restore_u12_backup(
                    cli_path, backup_path, stop_event, progress_range=(88, 12))
                self._clear_u12_recovery_state(pending_state)
                pending_state = None
                backup_path = None
                self._post('u12_recovery', None)
                self._post('progress', (100, 100))
                if fast_u12:
                    self._post('log', 'U12 图片已写入；快速模式跳过 U12 回读 CRC，PIC24 原程序已恢复并校验。')
                    self._post('u12_progress_text', 'U12 图片已写入（快速模式跳过 U12 回读 CRC）；PIC24 原程序已恢复。')
                else:
                    self._post('log', 'U12 图片写入和整图 CRC 校验通过；PIC24 原程序已恢复并校验。')
                    self._post('u12_progress_text', 'U12 已写入并校验，PIC24 原程序已恢复。')
                self._post('status', 'U12 写入完成，PIC24 已恢复')
            except Exception as exc:
                if backup_path and backup_path.is_file() and pending_state:
                    self._post('log', f'U12 写入中断或失败，正在尝试自动恢复 PIC24：{exc}')
                    try:
                        self._restore_u12_backup(
                            cli_path, backup_path, stop_event, ignore_stop=True)
                    except Exception as restore_exc:
                        self._post('log', f'自动恢复失败：{restore_exc}')
                        self._post('status', 'PIC24 需要恢复：请点击“恢复 PIC24 备份”')
                        self._post('u12_progress_text', '写入未完成；PIC24 备份保留，请点击“恢复 PIC24 备份”。')
                    else:
                        self._clear_u12_recovery_state(pending_state)
                        pending_state = None
                        backup_path = None
                        self._post('u12_recovery', None)
                        self._post('log', 'PIC24 原程序已自动恢复并通过校验。')
                        self._post('status', 'PIC24 原程序已恢复')
                        self._post('u12_progress_text', '写入未完成；PIC24 原程序已自动恢复。')
                raise
            finally:
                for temporary_file in temporary_files:
                    try:
                        temporary_file.unlink(missing_ok=True)
                    except OSError:
                        pass

        self._start_task('PICkit3 写入 U12 图片', action, require_connection=False)

    @staticmethod
    def _normalize_pic24_part(value):
        part = re.sub(r'\s+', '', str(value).upper())
        if part.startswith('PIC'):
            part = part[3:]
        if not re.fullmatch(r'24[A-Z0-9]{3,}', part):
            raise ValueError('请输入完整 PIC24 型号，例如 PIC24FJ256GA106。')
        return part

    def _update_hex_extension_hint(self):
        if not self.hex_file:
            return
        first_address, last_address = self.hex_address_range
        range_text = f'地址范围 0x{first_address:08X}–0x{last_address:08X}'
        if self.hex_has_sram and not self.hex_has_internal_flash:
            self.hex_memory_summary_var.set(
                f'{range_text} | RAM/OTA 中间镜像，请选择 FactoryOTA HEX')
            self.hex_memory_summary_label.configure(text_color=COLORS['warning_text'])
            return
        if not self.hex_has_external_data:
            self.hex_memory_summary_var.set(f'{range_text} | 未发现 QSPI 扩展数据')
            self.hex_memory_summary_label.configure(text_color=COLORS['muted'])
        elif self.hex_extension_download_var.get():
            self.hex_memory_summary_var.set(f'{range_text} | 扩展下载已开启（F750 / W25Q128）')
            self.hex_memory_summary_label.configure(text_color=COLORS['cyan'])
        else:
            self.hex_memory_summary_var.set(f'{range_text} | 本次将跳过 QSPI，只烧录内部 Flash')
            self.hex_memory_summary_label.configure(text_color=COLORS['warning_text'])

    def _start_hex_programming(self):
        if not self.hex_file or not self.hex_file.is_file():
            messagebox.showerror('未选择 HEX 文件', '请先选择有效的 Intel HEX 文件。', parent=self.root)
            return
        if self.hex_has_sram and not self.hex_has_internal_flash:
            messagebox.showerror(
                '不能直接烧录 RAM 镜像',
                '所选 HEX 含有 0x20000000 SRAM 数据，但没有 0x08000000 内部 Flash 数据。\n\n'
                '这是 OTA/Boot 流程使用的 RAM 执行镜像。RAM 在复位后会清空，因此直接烧录会在 '
                '0x20010000 校验失败。请改用当前固件对应、包含 Boot 和内部 Flash 数据的 '
                'FactoryOTA_x.x.hex，再按需勾选 QSPI 扩展下载。\n\n'
                'OTA 升级请在工具箱的 OTA 页面选择 .ota.bin 文件。',
                parent=self.root,
            )
            return
        cli_path = Path(self._detect_stm32_programmer_cli())
        if not cli_path.is_file():
            messagebox.showerror(
                '找不到烧录器',
                '未找到 STM32CubeProgrammer CLI。请确认工具箱目录中的 STM32CubeProgrammer 文件夹完整。',
                parent=self.root,
            )
            return
        hex_path = self.hex_file
        extension_enabled = bool(self.hex_extension_download_var.get())
        loader_path = None
        if extension_enabled and self.hex_has_external_data:
            loader_text = self._detect_stm32_external_loader(str(cli_path))
            if not loader_text or not Path(loader_text).is_file():
                messagebox.showerror(
                    '需要外部 Flash 驱动',
                    'HEX 包含 QSPI 数据，但未找到工具箱自带的 F750/W25Q128 驱动。请确认 STM32CubeProgrammer 文件夹完整。',
                    parent=self.root,
                )
                return
            loader_path = Path(loader_text).resolve()
        skip_qspi = self.hex_has_external_data and not extension_enabled
        try:
            frequency = parse_swd_frequency(self.swd_frequency_var.get())
        except ValueError as exc:
            messagebox.showerror('SWD 频率无效', str(exc), parent=self.root)
            return
        address_text = ''
        if self.hex_address_range:
            address_text = (f'\n地址范围：0x{self.hex_address_range[0]:08X}–'
                            f'0x{self.hex_address_range[1]:08X}')
        range_mode = ('\n下载范围：内部 Flash + 外部 QSPI'
                      if loader_path else '\n下载范围：内部 Flash')
        if skip_qspi:
            range_mode += '\nHEX 中的 QSPI 数据将跳过'
        if not messagebox.askyesno(
            '确认 ST-LINK 烧录',
            f'将通过 ST-LINK / SWD 烧录并校验：\n{hex_path.name}'
            f'{address_text}{range_mode}\nSWD 频率：{frequency:,} kHz\n\n'
            '请确认已连接正确的 STM32 目标板并保持供电。是否继续？',
            parent=self.root,
        ):
            return

        cli_path = cli_path.resolve()

        def action(args, key, stop_event, retry_under_reset=False):
            if stop_event.is_set():
                raise InterruptedError()
            programming_hex = hex_path
            temporary_hex = None
            cli_log_path = None
            return_code = None
            if skip_qspi:
                temporary_hex = create_ascii_temp_file(
                    prefix='STM32Toolbox_', suffix='_internal.hex')
                try:
                    retained = write_intel_hex_without_qspi(hex_path, temporary_hex)
                except Exception:
                    temporary_hex.unlink(missing_ok=True)
                    raise
                programming_hex = temporary_hex
                self._post('log', f'扩展下载未勾选，跳过 QSPI 数据；本次写入 {retained:,} 字节。')
            elif extension_enabled and not self.hex_has_external_data:
                self._post('log', '已勾选扩展下载，但这个 HEX 没有 QSPI 地址数据。')
            if not skip_qspi:
                ascii_hex = ascii_existing_path(hex_path)
                if ascii_hex is None:
                    temporary_hex = copy_file_to_ascii_temp(
                        hex_path, prefix='STM32Toolbox_', suffix='.hex')
                    programming_hex = temporary_hex
                    self._post('log', '已将 HEX 文件复制到纯英文临时路径，避免路径编码问题。')
                else:
                    programming_hex = ascii_hex
            cli_log_path = create_ascii_temp_file(
                prefix='STM32Toolbox_CLI_', suffix='.log')
            connection_frequency = min(frequency, 1000) if retry_under_reset else frequency
            command = [
                str(cli_path), '-c', 'port=SWD', f'freq={connection_frequency}',
            ]
            if retry_under_reset:
                command.extend(['mode=UR', 'reset=HWrst'])
            command.extend(['-vb', '3', '-log', str(cli_log_path)])
            self._post('status', '正在连接 ST-LINK…')
            if retry_under_reset:
                self._post(
                    'log',
                    f'首次连接未识别到目标，自动切换为 Under Reset / HWrst，'
                    f'SWD {connection_frequency} kHz 后重试。')
            else:
                self._post(
                    'log',
                    f'正在启动 STM32CubeProgrammer：{hex_path.name}（SWD {frequency} kHz）')
            if loader_path:
                self._post('log', f'扩展下载已开启，使用随包驱动：{loader_path.name}')
            process = None
            temporary_loader = None
            reader_thread = None
            connection_failure_seen = False
            target_identified = False
            try:
                programmer_cli, programmer_workdir = self._get_cubeprogrammer_runtime(
                    cli_path)
                command[0] = str(programmer_cli)
                self._post('log', f'CubeProgrammer CLI 路径：{programmer_cli}')
                self._post('log', f'CubeProgrammer 数据库工作目录：{programmer_workdir}')
                if loader_path:
                    temporary_loader = copy_external_loader_to_ascii_temp(loader_path)
                    command.extend(['-el', str(temporary_loader)])
                    self._post('log', '已将外部 Flash 驱动复制到纯英文临时路径，避免路径编码导致加载失败。')
                command.extend(['-w', str(programming_hex), '-v', '-rst'])
                try:
                    process = subprocess.Popen(
                        command,
                        # CubeProgrammer resolves its device database relative
                        # to the current directory using a non-Unicode path.
                        cwd=str(programmer_workdir),
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        bufsize=-1,
                        creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0),
                    )
                except OSError as exc:
                    raise RuntimeError(f'无法启动 STM32CubeProgrammer CLI：{exc}') from exc
                with self.process_lock:
                    self.active_process = process
                if process.stdout is None:
                    raise RuntimeError('无法读取 STM32CubeProgrammer 输出。')
                def handle_output(raw_line):
                    nonlocal connection_failure_seen, target_identified
                    for line in decode_programmer_output(raw_line).splitlines():
                        line = line.strip()
                        if not line:
                            continue
                        self._post('log', line)
                        lowered = line.casefold()
                        if ('dev_connect_err' in lowered or
                                'dev_target_reset_err' in lowered or
                                'unable to read device id from rom table' in lowered):
                            connection_failure_seen = True
                        if (('device id' in lowered and 'unable' not in lowered) or
                                'target detected' in lowered):
                            target_identified = True
                        if 'verify' in lowered or 'verif' in lowered:
                            self._post('status', '正在校验 HEX…')
                        elif any(word in lowered for word in ('download', 'erase', 'program')):
                            self._post('status', '正在写入 HEX…')
                        percentages = re.findall(r'\b(\d{1,3})\s*%', line)
                        if percentages:
                            percent = min(100, int(percentages[-1]))
                            self._post('progress', (percent, 100))

                output_queue = queue.Queue()

                def read_output():
                    try:
                        while True:
                            chunk = process.stdout.read1(4096)
                            if not chunk:
                                break
                            output_queue.put(chunk)
                    finally:
                        output_queue.put(None)

                reader_thread = threading.Thread(
                    target=read_output, name='CubeProgrammer-output',
                    daemon=True)
                reader_thread.start()
                output_buffer = bytearray()
                output_finished = False
                stop_started = None
                while not output_finished:
                    if stop_event.is_set():
                        now = time.monotonic()
                        if stop_started is None:
                            stop_started = now
                            if process.poll() is None:
                                try:
                                    process.terminate()
                                except OSError:
                                    pass
                        elif now >= stop_started + 1.5 and process.poll() is None:
                            try:
                                process.kill()
                            except OSError:
                                pass
                        if now >= stop_started + 3.0:
                            break
                    try:
                        chunk = output_queue.get(timeout=0.1)
                    except queue.Empty:
                        continue
                    if chunk is None:
                        output_finished = True
                    else:
                        output_buffer.extend(chunk)
                        while True:
                            separators = [position for position in (
                                output_buffer.find(b'\n'), output_buffer.find(b'\r'))
                                if position >= 0]
                            if not separators:
                                break
                            end = min(separators)
                            raw_line = bytes(output_buffer[:end])
                            del output_buffer[:end + 1]
                            if raw_line:
                                handle_output(raw_line)
                if output_buffer:
                    handle_output(bytes(output_buffer))
                return_code = self._wait_for_process(process, 3.0)
            finally:
                if process is not None:
                    if process.poll() is None:
                        try:
                            process.terminate()
                        except OSError:
                            pass
                        self._wait_for_process(process, 1.0)
                    if process.stdout is not None and (
                            reader_thread is None or not reader_thread.is_alive()):
                        try:
                            process.stdout.close()
                        except OSError:
                            pass
                with self.process_lock:
                    if self.active_process is process:
                        self.active_process = None
                if temporary_hex is not None:
                    temporary_hex.unlink(missing_ok=True)
                if temporary_loader is not None:
                    temporary_loader.unlink(missing_ok=True)
                if cli_log_path is not None and (
                        process is None or return_code == 0 or stop_event.is_set()):
                    cli_log_path.unlink(missing_ok=True)
            if stop_event.is_set():
                raise InterruptedError()
            if return_code != 0 and cli_log_path is not None and cli_log_path.is_file():
                try:
                    cli_log_text = cli_log_path.read_bytes().decode(
                        'utf-8', errors='replace').casefold()
                    for line in cli_log_text.splitlines():
                        if any(marker in line for marker in (
                                'dev_connect_err',
                                'dev_target_reset_err',
                                'unable to read device id from rom table')):
                            connection_failure_seen = True
                        if (('device id' in line and 'unable' not in line) or
                                'target detected' in line):
                            target_identified = True
                except OSError:
                    pass
            if (return_code != 0 and connection_failure_seen and
                    not target_identified and not retry_under_reset):
                self._post(
                    'log',
                    '连接阶段未读到目标器件 ID，未进入写入；准备使用 NRST 硬件复位方式重试一次。')
                if cli_log_path is not None:
                    cli_log_path.unlink(missing_ok=True)
                return action(args, key, stop_event, retry_under_reset=True)
            if return_code != 0:
                if cli_log_path is not None and cli_log_path.is_file():
                    try:
                        log_size = cli_log_path.stat().st_size
                        with cli_log_path.open('rb') as handle:
                            handle.seek(max(0, log_size - 16384))
                            trace_lines = handle.read().splitlines()[-30:]
                        trace_lines = [
                            decode_programmer_output(line) for line in trace_lines
                        ]
                        trace_lines = [line for line in trace_lines if line]
                        if trace_lines:
                            self._post('log', 'CubeProgrammer 诊断信息（末尾）：')
                            for line in trace_lines:
                                self._post('log', f'  {line}')
                    except OSError:
                        pass
                    self._post('log', f'完整 CubeProgrammer 日志：{cli_log_path}')
                detail = ''
                if retry_under_reset:
                    detail = ' Under Reset 重试仍失败；请核对目标板供电、SWDIO、SWCLK、共地及 NRST。'
                if loader_path:
                    detail += (
                        f' HEX 包含外部 QSPI 数据，已使用 {loader_path.name}；'
                        '若 0x90000000 地址仍校验失败，请核对外部驱动与目标板 Flash 型号、引脚配置是否匹配。')
                raise RuntimeError(
                    f'STM32CubeProgrammer 烧录失败（退出代码 {return_code}）。'
                    f'请检查操作记录、目标板供电、SWDIO/SWCLK 和 ST-LINK 驱动。{detail}')
            self._post('progress', (100, 100))
            self._post('log', 'HEX 烧录与校验完成，目标板已复位。')
            self._post('status', 'HEX 烧录并校验完成')

        self._start_task('ST-LINK 烧录 HEX 文件', action, require_connection=False)

    def _start_mplab_programming(self):
        try:
            part = self._normalize_pic24_part(self.mplab_device_var.get())
        except ValueError as exc:
            messagebox.showerror('器件型号无效', str(exc), parent=self.root)
            return
        if not self.mplab_file or not self.mplab_file.is_file():
            messagebox.showerror('未选择 HEX 文件', '请先选择有效的 PIC24 Intel HEX 文件。', parent=self.root)
            return
        cli_path = self.mplab_cli_path
        if not cli_path or not cli_path.is_file():
            cli_path = discover_pk3cmd()
            if cli_path:
                self.mplab_cli_path = cli_path
                self.mplab_cli_path_var.set(str(cli_path))
                self.mplab_tool_status_var.set('已找到 MPLAB 烧录命令')
                self.mplab_tool_status_label.configure(text_color=COLORS['cyan'])
        if not cli_path or not cli_path.is_file():
            messagebox.showerror(
                '找不到 PK3CMD',
                '没有找到 MPLAB IDE 的 PK3CMD.exe。请安装 MPLAB IDE v8.90，或点击“定位 PK3CMD…”选择该文件。',
                parent=self.root,
            )
            return
        if not (cli_path.parent / 'MPPICkit3.dll').is_file():
            messagebox.showerror(
                'MPLAB 组件不完整',
                'PK3CMD.exe 所在目录缺少 MPPICkit3.dll。请从 MPLAB IDE 的 Programmer Utilities\\PICkit3 目录选择完整工具。',
                parent=self.root,
            )
            return

        hex_path = self.mplab_file
        range_text = ''
        if self.mplab_address_range:
            range_text = (f'\nHEX 地址范围：0x{self.mplab_address_range[0]:08X}–'
                          f'0x{self.mplab_address_range[1]:08X}')
        if not messagebox.askyesno(
            '确认 PICkit 3 烧录',
            f'目标器件：PIC{part}\nHEX 文件：{hex_path.name}{range_text}\n\n'
            'PK3CMD 将按 HEX 内容写入 PIC24 并执行校验。请确认芯片型号、HEX 与 ICSP 接线正确。是否继续？',
            parent=self.root,
        ):
            return

        cli_path = cli_path.resolve()

        def action(args, key, stop_event):
            if stop_event.is_set():
                raise InterruptedError()
            programming_hex = ascii_existing_path(hex_path)
            temporary_hex = None
            process = None
            reader_thread = None
            return_code = None
            if programming_hex is None:
                temporary_hex = copy_file_to_ascii_temp(
                    hex_path, prefix='MPLAB_', suffix='.hex')
                programming_hex = temporary_hex
                self._post('log', 'HEX 路径含非英文字符，已复制到临时英文路径供 PK3CMD 读取。')
            command = [
                str(cli_path), f'-P{part}', f'-F{programming_hex}', '-M', '-Y',
            ]
            self._post('status', '正在连接 PICkit 3…')
            self._post('log', f'正在启动 PK3CMD：{hex_path.name}（器件 PIC{part}，写入并校验）')
            self._post('log', '如果 PK3CMD 正在更新 PICkit 3 固件，请保持烧录器连接并等待完成。')
            output_queue = queue.Queue()
            try:
                try:
                    process = subprocess.Popen(
                        command,
                        cwd=str(cli_path.parent),
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        bufsize=-1,
                        creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0),
                    )
                except OSError as exc:
                    raise RuntimeError(f'无法启动 PK3CMD：{exc}') from exc
                with self.process_lock:
                    self.active_process = process

                def read_output():
                    try:
                        while True:
                            chunk = process.stdout.read1(4096)
                            if not chunk:
                                break
                            output_queue.put(chunk)
                    finally:
                        output_queue.put(None)

                reader_thread = threading.Thread(
                    target=read_output, name='PK3CMD-output', daemon=True)
                reader_thread.start()

                def handle_output(raw_line):
                    for line in decode_programmer_output(raw_line).splitlines():
                        line = line.strip()
                        if not line:
                            continue
                        self._post('log', line)
                        lowered = line.casefold()
                        if any(word in lowered for word in ('verify', 'verifying', '校验')):
                            self._post('status', '正在校验 PIC24…')
                        elif any(word in lowered for word in ('program', 'write', 'erase', '写入')):
                            self._post('status', '正在写入 PIC24…')
                        percentages = re.findall(r'\b(\d{1,3})\s*%', line)
                        if percentages:
                            self._post('progress', (min(100, int(percentages[-1])), 100))

                output_finished = False
                output_buffer = bytearray()
                stop_started = None
                while not output_finished:
                    if stop_event.is_set():
                        now = time.monotonic()
                        if stop_started is None:
                            stop_started = now
                            if process.poll() is None:
                                try:
                                    process.terminate()
                                except OSError:
                                    pass
                        elif now >= stop_started + 1.5 and process.poll() is None:
                            try:
                                process.kill()
                            except OSError:
                                pass
                        if now >= stop_started + 3.0:
                            if output_buffer:
                                handle_output(bytes(output_buffer))
                                output_buffer.clear()
                            output_finished = True
                            break
                    try:
                        raw_line = output_queue.get(timeout=0.1)
                    except queue.Empty:
                        continue
                    if raw_line is None:
                        if output_buffer:
                            handle_output(bytes(output_buffer))
                            output_buffer.clear()
                        output_finished = True
                    else:
                        output_buffer.extend(raw_line)
                        while True:
                            separators = [position for position in (
                                output_buffer.find(b'\n'), output_buffer.find(b'\r'))
                                if position >= 0]
                            if not separators:
                                break
                            end = min(separators)
                            raw_line = bytes(output_buffer[:end])
                            del output_buffer[:end + 1]
                            if raw_line:
                                handle_output(raw_line)
                return_code = self._wait_for_process(process, 3.0)
            finally:
                if process is not None:
                    if process.poll() is None:
                        try:
                            process.terminate()
                        except OSError:
                            pass
                        self._wait_for_process(process, 1.0)
                    if process.stdout is not None and (
                            reader_thread is None or not reader_thread.is_alive()):
                        process.stdout.close()
                with self.process_lock:
                    if self.active_process is process:
                        self.active_process = None
                if temporary_hex is not None:
                    temporary_hex.unlink(missing_ok=True)

            if stop_event.is_set():
                raise InterruptedError()
            if return_code != 0:
                code_hints = {
                    1: 'PK3CMD 命令参数无效。',
                    2: 'PICkit 3 通讯失败；请确认没有其他 MPLAB 程序占用烧录器，并检查 USB 连接。',
                    3: '烧录或校验失败；请检查目标供电、ICSP 接线和 HEX 文件。',
                    5: 'PK3CMD 未识别目标器件；请核对完整 PIC24 型号及探针固件支持。',
                }
                hint = code_hints.get(return_code, '请查看上方 PK3CMD 输出。')
                raise RuntimeError(f'PICkit 3 烧录失败（退出代码 {return_code}）。{hint}')
            self._post('progress', (100, 100))
            self._post('log', 'PIC24 HEX 烧录与校验完成。')
            self._post('status', 'PIC24 烧录并校验完成')

        self._start_task('MPLAB PICkit 3 烧录 HEX 文件', action, require_connection=False)

    def _report_w78_failure(self, sock, error):
        detail = {
            8: 'HEX 格式、记录校验和或 APROM 地址错误',
            9: 'F750 DTA/RST 控制 GPIO 初始化或电平自检失败',
            10: 'W78 ISP 应答校验失败，加载程序协议可能不匹配',
            11: 'W78 APROM 累计校验失败',
            12: 'HEX 无线上传超时',
            13: 'W78 DTA 数据发送失败或超时',
            14: 'W78 DTA 入口未应答：检查 P3.1 单线、LDROM 及复位选通；DTA 不使用 UART 波特率',
            15: 'W78 DTA 校验应答接收超时；数据发送完成不代表目标校验成功',
            16: 'UART3 半双工方向切换失败',
            17: 'W78 DTA 应答长度不足，请检查加载程序和单线时序',
            18: '目标加载程序不是受支持的 DTA v4.00',
            19: 'W78 操作已停止；如已擦写，目标保持复位',
            20: 'W78 RST 或 LDROM 选通电平检查失败；请查看引脚诊断',
        }.get(error, f'设备错误代码 {error}')
        try:
            raw = request(sock, 10, on_info=self._on_device_info,
                          send_lock=self.w78_send_lock)
            if len(raw) != 40:
                raise ValueError('诊断数据长度错误')
            values = struct.unpack('<10I', raw)
            keys = ('phase', 'hal_status', 'hal_error', 'received_bytes',
                    'USART3_ISR', 'USART3_BRR', 'clock_source', 'clock_hz',
                    'ISP_command', 'ISP_state')
            diagnostic = dict(zip(keys, values))
            if (error == 9 and diagnostic.get('clock_source') == 0x44544131
                    and diagnostic.get('phase') == 1
                    and diagnostic.get('ISP_command') == 0xD106):
                packed = diagnostic.get('hal_error', 0)
                if (packed >> 28) == 0xA:
                    mode = (packed >> 8) & 3
                    open_drain = (packed >> 10) & 1
                    output_latch = (packed >> 11) & 1
                    rst_idr = (packed >> 1) & 1
                    self._post('log', f'PB4 状态：MODER={mode:02b}，'
                        f'OTYPER={open_drain}，ODR={output_latch}，RST_IDR={rst_idr} '
                        '（期望 MODER=01、OTYPER=0、ODR=0、RST_IDR=0）')
                    if mode == 1 and open_drain == 0 and output_latch == 0 and rst_idr == 1:
                        detail = ('PB4 已配置推挽输出并写低，但引脚仍读高；'
                                  '检查 IO2 线路、UART1L_TX 共网和 RST 外部驱动。')
                    else:
                        detail = ('PB4 的 GPIO 配置或输出锁存值异常；'
                                  '请根据上方 MODER/OTYPER/ODR 读数检查 F750 配置。')
                else:
                    detail = ('RST(PB4) 读回仍高；此 F750 固件没有扩展 GPIO 寄存器快照，'
                              '请先更新 OTA 0.20.36。')
            if diagnostic.get('clock_source') == 0x44544131 and diagnostic.get('phase') == 2:
                stage={0xD001:'DTA 入口等待目标下降沿',0xD011:'DTA 入口等待目标回高',
                    0xD002:'第一次校准等待目标下降沿',0xD021:'第一次校准等待目标回高',
                    0xD003:'第二次校准等待目标下降沿',0xD031:'第二次校准等待目标回高'}.get(diagnostic.get('ISP_command'),'入口握手')
                pins=diagnostic.get('hal_error',0)
                self._post('log',f'超时位置：{stage}；引脚快照 DTA={pins&1} RST={(pins>>1)&1} P2.6={(pins>>2)&1} P2.7={(pins>>3)&1}')

            try:
                preview_raw = request(sock, 11, on_info=self._on_device_info,
                                      send_lock=self.w78_send_lock)
                if len(preview_raw) != 4:
                    raise ValueError('接收字节诊断数据长度错误')
                preview = struct.unpack('<I', preview_raw)[0]
                diagnostic['RX_first4'] = ' '.join(
                    f'{(preview >> (8 * index)) & 0xff:02X}' for index in range(4))
            except DeviceError as preview_error:
                if preview_error.status != 11:
                    raise
            self._post('log', 'W78 串口诊断：\n' + json.dumps(
                diagnostic, ensure_ascii=False, indent=2))
        except (OSError, ValueError, RuntimeError) as diagnostic_error:
            self._post('log', f'未取得扩展诊断：{diagnostic_error}')
            if error == 9:
                detail = '设备错误 9；旧固件会将接收超时也报告为初始化失败，请升级到 OTA 0.20.5 后区分'
        raise RuntimeError(f'W78 烧录失败：{detail}')

    def _report_pic24_failure(self, sock, error):
        """记录失败地址与实际读回值，便于核对接线和目标型号。"""
        reasons = {100:'HEX 数据无效',101:'芯片 ID 不匹配或 ISP 接线未连通',
                   102:'擦写或上传超时',103:'目标读回校验失败',104:'操作已停止',
                   105:'开发板计时器不可用',106:'HEX 缺少关键配置字或配置位无效'}
        body = request(sock, 10, send_lock=self.w78_send_lock)
        if len(body) == 40:
            values = struct.unpack('<10I', body)
            self._post('log', 'PIC24 诊断：地址 0x%06X，预期/命令 0x%06X，实际/ID 0x%06X' % (values[3], values[8], values[2]))
        raise RuntimeError('PIC24 烧录失败：' + reasons.get(error, '错误码 %s' % error))

    def _upload_w78_wireless(self):
        if not self.w78_target_var.get().startswith(('W78E516DDG', 'PIC24FJ256DA210')):
            messagebox.showinfo('烧录对象尚未接入', '请选择已接入的烧录对象。', parent=self.root)
            return
        if not self.w78_hex_path or not self.w78_hex_path.is_file():
            messagebox.showerror('未选择 HEX', '请先选择当前对象的完整 Intel HEX 文件。', parent=self.root)
            return
        host_override = self.w78_host_var.get().strip()
        try:
            args, key = self._connection_inputs(host_override=host_override)
        except ValueError as exc:
            messagebox.showerror('无法开始', str(exc), parent=self.root)
            return
        hex_path = self.w78_hex_path
        pic24 = self.w78_target_var.get().startswith('PIC24')
        target_name = 'PIC24FJ256DA210' if pic24 else 'W78E516DDG'
        self.connection_summary_var.set(f'{args.host}:{args.port}')

        def action(args, key, stop_event):
            from pic24_hex import validate_pic24_hex
            if pic24:
                package, capacity = validate_pic24_hex(hex_path), 262656
            else:
                package, extent = validate_w78_hex(hex_path, include_extent=True)
                capacity = None
            filename = validate_w78_filename(hex_path)
            total = len(package)
            version = '未知'
            with self._connection(args, key, stop_event) as sock:
                # 从本次认证连接读取版本，避免使用界面上其他设备或上次连接的数据。
                if not pic24:
                    sock.settimeout(5)
                    try:
                        info = request(sock, 1, on_info=self._on_device_info, send_lock=self.w78_send_lock)
                        version = str(parse_device_info(info).get('version') or '未知')
                    except (DeviceError, ValueError):
                        pass
                    if version == '1.4.70':
                        capacity = extent
                    elif version == '1.4.69':
                        capacity = 65536
                    if capacity is None:
                        self._post('log', f'F750 {version}：未确认 W78 写入范围，先显示设备返回的字节数。')
                    else:
                        self._post('log', f'F750 {version}：W78 写入范围 {capacity:,} 字节，擦除范围 64 KiB。')
                # PIC24 擦写与读回时会有较长的状态间隔，交由可取消的短轮询处理。
                sock.settimeout(120)
                # 新版固件显式选择目标；旧版固件仅允许继续原 W78 流程。
                try:
                    request(sock, 30, 1 if pic24 else 0, send_lock=self.w78_send_lock)
                except DeviceError as exc:
                    if pic24 or exc.status != 11:
                        raise RuntimeError('目标切换失败，请确认开发板固件为 1.3.7 或以上且当前未忙碌') from exc
                ack = request(sock, 6, total, filename, on_info=self._on_device_info,
                              send_lock=self.w78_send_lock)
                if len(ack) != 4 or struct.unpack('<I', ack)[0] != 0:
                    raise ValueError('设备没有接受当前对象的 HEX 上传请求。')
                display_name = hex_path.name.encode('utf-8')[:191].decode('utf-8', errors='ignore').encode('utf-8')
                try:
                    request(sock, 25, payload=display_name, send_lock=self.w78_send_lock)
                except DeviceError as exc:
                    if exc.status != 11:
                        raise
                    self._post('log', '当前开发板固件未提供中文文件名显示；升级至 1.2.0 后支持。')
                upload_started = time.monotonic()
                session_id = uuid.uuid4().int & 0x00FFFFFF or 1
                retry_causes = {'timeout': 0, 'crc': 0, 'sequence': 0}
                def note_retry(reason):
                    retry_causes[reason] += 1
                pipeline = upload_w78_window(
                    sock, package, self.w78_chunk_size, session_id, stop_event,
                    on_progress=lambda written, _total: self._post(
                        'w78_progress', (written, total, f'HEX 接收确认：{written:,} / {total:,} 字节')),
                    on_info=self._on_device_info, send_lock=self.w78_send_lock,
                    target=1 if pic24 else 0, on_retry=note_retry,
                )
                if pipeline is None:
                    # 老固件不支持流水协议；每个兼容帧仍不超过 16 KiB。
                    legacy_chunk = min(self.w78_chunk_size, 16384)
                    self._post('log', f'开发板未提供流水协议，改用 {legacy_chunk // 1024} KiB 顺序分包。')
                    for offset in range(0, total, legacy_chunk):
                        if stop_event.is_set():
                            raise InterruptedError()
                        block = package[offset:offset + legacy_chunk]
                        ack = request(sock, 7, offset, block, on_info=self._on_device_info,
                                      send_lock=self.w78_send_lock)
                        written = offset + len(block)
                        if len(ack) != 4 or struct.unpack('<I', ack)[0] != written:
                            raise ValueError('设备返回的 HEX 上传进度不正确。')
                        self._post('w78_progress', (written, total, f'HEX 接收确认：{written:,} / {total:,} 字节'))
                    logical_chunk, frame_size, upload_window, retries, raw_mode = (
                        self.w78_chunk_size, legacy_chunk, 1, 0, False)
                else:
                    logical_chunk, frame_size, upload_window, retries, raw_mode = pipeline
                    frame_format = '原始帧' if raw_mode else '旧协议兼容帧'
                    causes = '，'.join(f'{label} {retry_causes[key]}' for key, label in
                                       (('timeout', 'ACK 超时'), ('crc', 'CRC'), ('sequence', '序号')))
                    self._post('log', f'流水上传：{frame_format} {frame_size:,} 字节，窗口 {upload_window}，重传 {retries} 次（{causes}）。')

                upload_seconds = max(time.monotonic() - upload_started, 0.001)
                self._post('log', f'HEX 接收确认完成：{total:,} 字节，{upload_seconds:.2f} 秒，平均 {total / upload_seconds / 1024:.1f} KiB/秒；逻辑块 {logical_chunk:,} 字节，帧 {frame_size:,} 字节，窗口 {upload_window}。')
                self._post('w78_progress', (0, capacity, 'HEX 已收齐；等待开发板确认芯片并开始实际写入'))

                if stop_event.is_set():
                    raise InterruptedError()
                sock.settimeout(120)
                operation_reader = SocketReader(sock)
                self._post('status', '正在启动 ' + target_name + ' ISP…')
                self._post('log', target_name + ' HEX 接收与传输校验完成，正在识别目标芯片；上传 ACK 不代表目标写入完成。')
                self.w78_program_started = True
                ignored_upload_acks = set()
                def note_late_ack(command):
                    if command not in ignored_upload_acks:
                        ignored_upload_acks.add(command)
                        self._post('log', f'已跳过迟到的 HEX 上传确认响应（命令 {command}）。')
                # 从发送烧录命令开始计时，不包含 HEX 上传。
                started_at = time.monotonic()
                w78_timing = None if pic24 else W78StageTiming(started_at)
                try:
                    request_wait(sock, 8, 1 if pic24 else 0, on_info=self._on_device_info,
                                 send_lock=self.w78_send_lock, reader=operation_reader,
                                 cancel=stop_event, timeout=15, ignore_ops=(32, 33),
                                 on_ignored=lambda response: note_late_ack(response & 0x7FFFFFFF))
                except DeviceError:
                    state_body = request_wait(sock, 9, on_info=self._on_device_info,
                                              send_lock=self.w78_send_lock,
                                              reader=operation_reader, cancel=stop_event,
                                              timeout=15, ignore_ops=(8, 32, 33),
                                              on_ignored=lambda response: note_late_ack(response & 0x7FFFFFFF))
                    if len(state_body) == 72:
                        state, error = struct.unpack_from('<2I', state_body)
                        if state == W78_STATE_FAILED:
                            self._report_pic24_failure(sock, error) if pic24 else self._report_w78_failure(sock, error)
                    raise
                except TimeoutError:
                    # 启动 ACK 丢失时先读状态确认，绝不重复发送有副作用的启动命令。
                    self._post('log', '启动确认暂未返回，正在读取开发板状态；不会重复启动或中断擦写。')
                    sampled_at = time.monotonic()
                    state_body = request_wait(
                        sock, 9, on_info=self._on_device_info,
                        send_lock=self.w78_send_lock, reader=operation_reader,
                        cancel=stop_event, timeout=15, ignore_ops=(8, 32, 33),
                        on_ignored=lambda response: note_late_ack(response & 0x7FFFFFFF),
                    )
                    if len(state_body) != 72:
                        raise ValueError('开发板返回的烧录状态格式无效。')
                    observed_state, error = struct.unpack_from('<2I', state_body)
                    if w78_timing is not None:
                        w78_timing.observe(observed_state, sampled_at, time.monotonic())
                    if observed_state == W78_STATE_FAILED:
                        self._report_pic24_failure(sock, error) if pic24 else self._report_w78_failure(sock, error)
                    if observed_state not in tuple(range(4, 13)) + (W78_STATE_DONE,):
                        raise RuntimeError('开发板没有进入擦写状态；请重新启动烧录。')
                state_names = {
                    4: '复位并选择 ISP', 5: '等待目标启动', 6: '连接 ISP',
                    7: '同步数据包', 8: '擦除 APROM', 9: '发送 APROM 地址及校验值',
                    10: '写入 APROM', 11: '校验目标 APROM', 12: '启动目标程序',
                }
                if pic24:
                    state_names = {4:'进入编程模式',5:'等待编程模式',6:'读取芯片 ID',7:'写入并校验配置字',8:'擦除程序区',9:'写入程序',10:'写入程序',11:'读回校验程序区',12:'启动 PIC24'}
                # 进度包含空白区跳过，因此报告的是地址进度速率。
                timing = {'stage': None, 'start': 0.0, 'first': 0, 'last': 0}
                last_reported_state = None
                def mark_pic_stage(stage, progress):
                    now = time.monotonic()
                    if timing['stage'] != stage:
                        if timing['stage'] is not None:
                            elapsed = max(now - timing['start'], 0.001)
                            advanced = max(0, timing['last'] - timing['first'])
                            self._post('log', f"PIC24 {timing['stage']}：观测 {elapsed:.2f} 秒，进度推进 {advanced:,} 字节，平均 {advanced / elapsed / 1024:.1f} KiB/秒。")
                        timing.update(stage=stage, start=now, first=progress, last=progress)
                    elif stage is not None:
                        timing['last'] = progress
                deadline = time.monotonic() + (600 if pic24 else 300)
                wait_seconds = 0.5 if pic24 else 0.0
                while time.monotonic() < deadline:
                    if stop_event.wait(wait_seconds):
                        raise InterruptedError()
                    wait_seconds = 0.5 if pic24 else W78_STATUS_INTERVAL
                    sampled_at = time.monotonic()
                    body = request_wait(
                        sock, 9, on_info=self._on_device_info,
                        send_lock=self.w78_send_lock, reader=operation_reader,
                        cancel=stop_event, timeout=max(1, deadline - time.monotonic()),
                        ignore_ops=(8, 32, 33),
                        on_ignored=lambda response: note_late_ack(response & 0x7FFFFFFF),
                    )
                    if len(body) != 72:
                        raise ValueError('开发板返回的烧录状态格式无效。')
                    observed_at = time.monotonic()
                    state, error, _total, received, programmed, _source = struct.unpack_from('<6I', body)
                    if w78_timing is not None:
                        w78_timing.observe(state, sampled_at, observed_at)
                        # 非预期固件行为时回退为纯字节显示，最终范围以板端为准。
                        if capacity is not None and programmed > capacity:
                            capacity = None
                    if state != last_reported_state:
                        phase = state_names.get(state, '校验通过（状态 13）' if
                                                not pic24 and state == W78_STATE_DONE else f'状态 {state}')
                        self._post('log', f'{target_name} 阶段：{phase}。')
                        last_reported_state = state
                    if pic24:
                        mark_pic_stage('写入程序' if state in (9, 10) else '读回校验' if state == 11 else None, programmed)
                    count_text = (f'{programmed:,} / {capacity:,} 字节' if capacity
                                  else f'已写入 {programmed:,} 字节')
                    if state == W78_STATE_FAILED:
                        self._post('w78_progress', (programmed, capacity,
                            f'{count_text}；目标校验未通过'))
                        self._post('log', f'设备最终状态：{state}，错误码 {error}，'
                            f'设备报告处理进度 {count_text}；尚未确认烧录成功。')
                        self._report_pic24_failure(sock, error) if pic24 else self._report_w78_failure(sock, error)
                    if state == W78_STATE_DONE:
                        if w78_timing is not None:
                            detail = w78_timing.detail()
                            actual = f'{programmed:,} 字节' if programmed else '实际写入量未上报'
                            # 耗时只显示在完成进度区，不写入操作日志或本地记录文件。
                            self._post('w78_progress', (1, 1, f'{hex_path.name} · 完成：{actual}｜{detail}（轮询观测）'))
                            self._post('log', f'{target_name} 写入并校验完成：{hex_path.name}')
                        else:
                            self._post('w78_progress', (capacity, capacity, f'{hex_path.name} · 写入并校验完成'))
                            self._post('log', f'{target_name} 写入并校验完成：{hex_path.name}')
                        self._post('status', target_name + ' 无线烧录完成')
                        return
                    if state in state_names:
                        percent = f'（{min(100, programmed * 100 // capacity)}%）' if capacity else ''
                        self._post('w78_progress', (programmed, capacity, f'{state_names[state]}：{count_text}{percent}'))
                        self._post('status', f'{target_name} | {state_names[state]} {percent}')
                    elif state == 3:
                        self._post('status', f'HEX 已校验 | {received:,} 字节')
                raise TimeoutError('等待目标烧录完成超时；请查看开发板状态。')

        self._start_task('无线烧录', action,
                         require_connection=False, host_override=host_override)

    @contextmanager
    def _ota_batch_session(self, args, key, stop_event, host, total, digest, on_info):
        for attempt in range(5):
            if stop_event.is_set():
                raise InterruptedError()
            self._post('ota_target_status', (host, '正在连接'))
            sock = connect(args, key, on_info=on_info, cancel=stop_event)
            if stop_event.is_set():
                self._close_socket(sock)
                raise InterruptedError()
            with self.socket_lock:
                self.active_ota_sockets[host] = sock
                self.ota_socket_cancel_allowed[host] = True
            try:
                if not key:
                    self._post('ota_target_status', (host, '等待设备端确认'))
                    self._post(
                        'log',
                        f'[{host}] 未使用 Key；请在这台设备屏幕上确认 OTA 请求。',
                    )
                try:
                    request(
                        sock, 2, payload=struct.pack('<I', total) + digest,
                        on_info=on_info, send_lock=self.ota_send_lock,
                    )
                except DeviceError as exc:
                    if exc.status != 11 or attempt == 4:
                        raise
                    self._post(
                        'log',
                        f'[{host}] 收到错误 11（次级只读连接），'
                        f'正在断开并重试主连接 {attempt + 1}/4。',
                    )
                    self._post('ota_target_status', (host, '等待主连接释放后重试'))
                    if stop_event.wait(1.0):
                        raise InterruptedError() from exc
                    continue
                yield sock
                return
            finally:
                with self.socket_lock:
                    if self.active_ota_sockets.get(host) is sock:
                        self.active_ota_sockets.pop(host, None)
                    self.ota_socket_cancel_allowed.pop(host, None)
                self._close_socket(sock)
        raise RuntimeError('设备未能分配可升级的 Local TCP 主连接。')

    def _upload_ota(self):
        if self.is_running:
            return
        if not self.package_path or not self.package_version:
            messagebox.showerror('未选择升级包', '请先选择一个有效的 .ota.bin 文件。', parent=self.root)
            return
        try:
            hosts = self._ota_target_hosts()
            base_args, key = self._connection_inputs(host_override=hosts[0])
        except ValueError as exc:
            messagebox.showerror('无法开始升级', str(exc), parent=self.root)
            return
        targets = [
            (host, SimpleNamespace(host=host, port=base_args.port))
            for host in hosts
        ]
        host_summary = '\n'.join(hosts[:8])
        if len(hosts) > 8:
            host_summary += f'\n…另有 {len(hosts) - 8} 台'
        if not messagebox.askyesno(
            '确认批量升级',
            f'将版本 {self.package_version} 同时上传到 {len(hosts)} 台设备：\n'
            f'{host_summary}\n\n升级期间请保持所有设备供电。继续吗？',
            parent=self.root,
        ):
            return

        package_path = self.package_path
        expected_version = self.package_version
        self._reset_ota_target_rows(hosts)
        self.connection_summary_var.set(f'{len(hosts)} 台设备 | {base_args.port}')
        self.ota_batch_running = True

        def action(_args, _key, stop_event):
            package = package_path.read_bytes()
            version = validate_package(package)
            digest = hashlib.md5(package).hexdigest().encode('ascii')
            total = len(package)
            self._post('ota_batch_status', f'正在并行升级 | {len(hosts)} 台设备')
            self._post(
                'log',
                f'固件版本 {version}，目标 {len(hosts)} 台；每台设备使用独立连接和进度。',
            )

            def on_info(host):
                return lambda body: self._post(
                    'log', f'[{host}] 设备信息：\n{self._format_json(body)}',
                )

            def upgrade_target(host, args):
                status = '正在准备'
                category = 'failed'
                report = ''
                info_callback = on_info(host)
                commit_ack_received = False
                try:
                    chunk_sizes = [self.ota_chunk_size]
                    if self.ota_chunk_size != OTA_LEGACY_CHUNK_SIZE:
                        chunk_sizes.append(OTA_LEGACY_CHUNK_SIZE)
                    for chunk_size in chunk_sizes:
                        try:
                            with self._ota_batch_session(
                                args, key, stop_event, host, total, digest, info_callback,
                            ) as sock:
                                sock.settimeout(120)
                                self._post('ota_target_status', (host, '正在传输'))
                                upload_ota_stream(
                                    sock, package, chunk_size=chunk_size,
                                    window=1 if chunk_size == OTA_LEGACY_CHUNK_SIZE else OTA_TRANSFER_WINDOW,
                                    on_info=info_callback, send_lock=self.ota_send_lock,
                                    cancel=stop_event,
                                    on_progress=lambda written: self._post(
                                        'ota_target_progress', (host, written, total)),
                                    on_mode=lambda size, window: self._post(
                                        'log', f'[{host}] OTA 分片 {size} 字节，窗口 {window}，按偏移逐片确认。'),
                                )
                                if stop_event.is_set():
                                    raise InterruptedError()
                                with self.socket_lock:
                                    self.ota_socket_cancel_allowed[host] = False
                                self._post('ota_target_status', (host, '设备校验并提交中'))
                                self._post(
                                    'log',
                                    f'[{host}] 固件数据已写入，设备正在完整校验并提交安装。',
                                )
                                sock.settimeout(20)
                                try:
                                    request(
                                        sock, 4, on_info=info_callback,
                                        send_lock=self.ota_send_lock,
                                    )
                                except OSError as exc:
                                    if stop_event.is_set():
                                        raise InterruptedError() from exc
                                    self._post(
                                        'log',
                                        f'[{host}] 提交期间连接中断（{exc}）；'
                                        '继续确认设备是否重启。',
                                    )
                                else:
                                    commit_ack_received = True
                            break
                        except DeviceError as exc:
                            if exc.status != 12 or chunk_size == OTA_LEGACY_CHUNK_SIZE:
                                raise
                            self._post(
                                'log',
                                f'[{host}] 设备不接受 {chunk_size // 1024} KiB 分片，'
                                '重新连接并从头使用 1 KiB 兼容分片。',
                            )
                            self._post('ota_target_progress', (host, 0, total))

                    if commit_ack_received:
                        self._post(
                            'log',
                            f'[{host}] 版本 {version} 已通过设备校验并提交，设备正在重启。',
                        )
                    else:
                        self._post(
                            'log',
                            f'[{host}] 未收到最终提交响应，正在确认设备当前版本。',
                        )
                    self._post('ota_target_status', (host, '设备重启中，确认版本'))
                    reconnect_started = time.monotonic()
                    deadline = reconnect_started + 60
                    next_notice = reconnect_started + 10
                    while time.monotonic() < deadline and not stop_event.is_set():
                        if stop_event.wait(2):
                            break
                        try:
                            with connect(args, key, on_info=info_callback, cancel=stop_event) as sock:
                                sock.settimeout(5)
                                info = parse_device_info(request(sock, 1, on_info=info_callback))
                            self._post(
                                'log',
                                f'[{host}] 重启后设备信息：\n'
                                + json.dumps(info, ensure_ascii=False, indent=2),
                            )
                            if info.get('version') == expected_version:
                                status = '升级完成'
                                category = 'success'
                                report = f'[{host}] 新版本 {expected_version} 已启动。'
                            else:
                                status = '已重连 | 版本待核对'
                                category = 'pending'
                                report = f'[{host}] 已重新连接，当前版本为 {info.get("version", "未知")}。'
                            break
                        except (OSError, ValueError, RuntimeError):
                            now = time.monotonic()
                            if now >= next_notice:
                                waited = int(now - reconnect_started)
                                self._post(
                                    'log',
                                    f'[{host}] 设备仍在重启或联网，已等待 {waited} 秒。',
                                )
                                next_notice = now + 10
                    else:
                        if stop_event.is_set():
                            if commit_ack_received:
                                status = '已停止等待 | OTA 已提交'
                                category = 'pending'
                                report = f'[{host}] OTA 已提交，设备版本尚未确认。'
                            else:
                                status = '已停止'
                                category = 'stopped'
                                report = f'[{host}] 已停止等待重连。'
                        elif commit_ack_received:
                            status = '升级结果待确认'
                            category = 'pending'
                            report = f'[{host}] OTA 已提交，但 60 秒内未重新连接。'
                        else:
                            status = '升级结果待确认'
                            category = 'pending'
                            report = f'[{host}] 未收到提交确认，设备未重新连接。'
                    if not report:
                        if status == '升级完成':
                            report = f'[{host}] 升级完成。'
                        elif status == '已重连 | 版本待核对':
                            report = f'[{host}] 设备已重连，版本需要核对。'
                except InterruptedError:
                    status = '已停止'
                    category = 'stopped'
                    report = f'[{host}] 升级已停止。'
                except Exception as exc:
                    if stop_event.is_set():
                        status = '已停止'
                        category = 'stopped'
                        report = f'[{host}] 升级已停止。'
                    else:
                        status = '升级失败'
                        category = 'failed'
                        detail = self._friendly_error(exc, args)
                        report = f'[{host}] 升级失败：{detail}'
                self._post('ota_target_status', (host, status))
                if report:
                    self._post('log', report)
                return host, category, status

            results = []
            with ThreadPoolExecutor(
                max_workers=len(targets), thread_name_prefix='OTA-target',
            ) as executor:
                futures = [
                    executor.submit(upgrade_target, host, args)
                    for host, args in targets
                ]
                for future in as_completed(futures):
                    results.append(future.result())

            successes = sum(category == 'success' for _host, category, _status in results)
            pending = sum(category == 'pending' for _host, category, _status in results)
            failures = sum(category == 'failed' for _host, category, _status in results)
            stopped = sum(category == 'stopped' for _host, category, _status in results)
            if stop_event.is_set():
                summary = f'批量升级已停止 | 完成 {successes} 台，待确认 {pending} 台'
            elif failures or pending:
                summary = (
                    f'批量升级结束 | 成功 {successes}/{len(hosts)}，'
                    f'待确认 {pending} 台，失败 {failures} 台'
                )
            else:
                summary = f'批量升级完成 | {successes}/{len(hosts)} 台'
            if stopped and not stop_event.is_set():
                summary += f'，停止 {stopped} 台'
            self._post('ota_batch_status', summary)

        self._start_task('上传并安装 OTA 固件', action, require_connection=False)

    def _finalize_close(self):
        if self.is_running or self.stlink_check_running:
            if self.root.winfo_exists():
                self.root.after(100, self._finalize_close)
            return
        self._save_settings()
        self._cleanup_cubeprogrammer_runtime()
        self.root.destroy()

    def _on_close(self):
        if self.is_running or self.stlink_check_running:
            self.close_pending = True
            if self.is_running:
                self._stop_operation()
            self.root.after(100, self._finalize_close)
            return
        self._save_settings()
        self._cleanup_cubeprogrammer_runtime()
        self.root.destroy()


def main():
    ctk.set_appearance_mode('light')
    ctk.set_default_color_theme('blue')
    root = ctk.CTk()
    try:
        root.iconbitmap(default=str(app_resource_path(APP_ICON_FILE)))
    except (OSError, tk.TclError):
        pass
    app = LocalTcpApp(root)
    # Capture a useful Python stack if the UI stops servicing events.
    try:
        import faulthandler
        diagnostic = settings_file().with_name('ui_hang.log')
        diagnostic.parent.mkdir(parents=True, exist_ok=True)
        app._hang_log = diagnostic.open('a', encoding='utf-8')
        def heartbeat():
            faulthandler.cancel_dump_traceback_later()
            faulthandler.dump_traceback_later(15, file=app._hang_log)
            root.after(3000, heartbeat)
        heartbeat()
    except (OSError, RuntimeError):
        pass
    root.mainloop()
    try:
        faulthandler.cancel_dump_traceback_later()
    except (NameError, RuntimeError):
        pass


if __name__ == '__main__':
    main()


