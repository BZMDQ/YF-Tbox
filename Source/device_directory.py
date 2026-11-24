"""Persistent device aliases and read-only discovery on local IPv4 networks."""
from __future__ import annotations

import asyncio
import concurrent.futures
import errno
import copy
import ipaddress
import json
import queue
import re
import socket
import os
import struct
import select
import zlib
import subprocess
import threading
import time
import unicodedata

import customtkinter as ctk
import tkinter as tk
from tkinter import messagebox
from local_tcp_client import (
    HEADER, DeviceError, checked_response, frame, parse_device_info, response_header,
)


_SCAN_MAX_ADDRESSES = 4096
_SCAN_FIRST_LIMIT = 1024
_SCAN_RETRY_LIMIT = 512
_SCAN_STARTUP_LIMIT = 2048
_SCAN_UI_BATCH = 128
_SCAN_UDP_WINDOW = 2.0
_SCAN_UDP_RETRY_AT = 0.7
_SCAN_UDP_HEAD_START = 0.20
_SCAN_TUN_NETWORK = ipaddress.IPv4Network('198.18.0.0/15')


def _automatic_ipv4(value):
    # 自动发现只使用本机、当前设备和已保存设备的局域网地址。
    try:
        address = ipaddress.IPv4Address(value)
    except (ValueError, TypeError):
        return None
    if (address.is_private and not address.is_loopback and not address.is_link_local
            and not address.is_unspecified and address not in _SCAN_TUN_NETWORK):
        return address
    return None


def discovery_targets(current='', known=(), routes=(), limit=_SCAN_MAX_ADDRESSES):
    """使用物理网卡的子网掩码与已知设备确定自动扫描范围。"""
    local_networks = {}
    for network, _metric, _index, source, _gateway in routes:
        address = _automatic_ipv4(source)
        if address is not None:
            local_networks.setdefault(address, network)
    if not local_networks:
        # 有物理网卡快照时无需再调用 ipconfig 或阻塞等待主机名解析。
        try:
            local = socket.gethostbyname_ex(socket.gethostname())[2]
        except OSError:
            local = []
        if not local:
            try:
                result = subprocess.run(['ipconfig'], stdout=subprocess.PIPE,
                                        stderr=subprocess.DEVNULL, timeout=3,
                                        creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
                local = re.findall(r'IPv4[^:\r\n]*:\s*(\d+\.\d+\.\d+\.\d+)',
                                   result.stdout.decode(errors='ignore'))
            except (OSError, subprocess.TimeoutExpired):
                pass
        for source in local:
            address = _automatic_ipv4(source)
            if address is not None:
                local_networks[address] = ipaddress.IPv4Network((address, 24), strict=False)

    selected = [address for value in (current, *known)
                if (address := _automatic_ipv4(value)) is not None]
    targets = dict.fromkeys(address for address in selected if address not in local_networks)
    # 大于地址预算的物理网段分成等长子网，以本机或已知设备所在段为起点。
    minimum_prefix = 32 - (limit.bit_length() - 1)
    networks = dict.fromkeys(
        ipaddress.IPv4Network((address, max(network.prefixlen, minimum_prefix)), strict=False)
        for address, network in local_networks.items()
    )
    for address in selected:
        if not any(address in network for network in networks):
            prefix = next((network.prefixlen for network in local_networks.values() if address in network), 24)
            networks[ipaddress.IPv4Network((address, max(prefix, minimum_prefix)), strict=False)] = None
    for network in networks:
        for address in network.hosts():
            if len(targets) >= limit:
                break
            if address not in local_networks:
                targets.setdefault(address, None)
        if len(targets) >= limit:
            break
    return [str(address) for address in list(targets)[:limit]]


def configured_targets(value):
    """Accept one CIDR, IPv4 interval or address per line, at most 4096 hosts."""
    targets = set()
    for part in re.split(r'[,;\n]+', value):
        part = part.strip()
        if not part:
            continue
        if '/' in part:
            network = ipaddress.IPv4Network(part, strict=False)
            if network.num_addresses > _SCAN_MAX_ADDRESSES:
                raise ValueError('单次扫描最多 4096 个地址')
            addresses = network.hosts()
        elif '-' in part:
            first, last = [int(ipaddress.IPv4Address(v.strip())) for v in part.split('-', 1)]
            if last < first or last - first >= _SCAN_MAX_ADDRESSES:
                raise ValueError('扫描范围顺序无效或超过 4096 个地址')
            addresses = (ipaddress.IPv4Address(v) for v in range(first, last + 1))
        else:
            addresses = [ipaddress.IPv4Address(part)]
        targets.update(str(v) for v in addresses)
        if len(targets) > _SCAN_MAX_ADDRESSES:
            raise ValueError('单次扫描最多 4096 个地址')
    return sorted(targets, key=ipaddress.IPv4Address)


def normalize_ipv4(value):
    if isinstance(value, bytes):
        value = value.decode('utf-8', errors='replace')
    text = unicodedata.normalize('NFKC', str(value))
    text = ''.join(char for char in text
                   if unicodedata.category(char) != 'Cf')
    text = text.replace('。', '.').replace('．', '.').replace('｡', '.')
    text = ''.join(text.split())
    return str(ipaddress.IPv4Address(text))


def ota_tokens(raw):
    tokens = []
    for line in raw.splitlines():
        address = re.split(r'\s+[|\u00b7]\s+', line)[-1].strip()
        tokens.extend(v for v in re.split(r'[\s,，;；]+', address) if v)
    return tokens


_LAN_CACHE_TTL = 30.0
_LAN_FAILURE_TTL = 2.0
_lan_condition = threading.Condition()
_lan_cache = []
_lan_cache_until = 0.0
_lan_refreshing = False
_lan_generation = 0


def invalidate_lan_interfaces():
    """连接绑定失败后让下次查询重取物理网卡，不清除正在使用的快照。"""
    global _lan_cache_until, _lan_generation
    with _lan_condition:
        _lan_cache_until = 0.0
        _lan_generation += 1
        _lan_condition.notify_all()


def lan_interfaces(cancel=None):
    """短期缓存物理网卡；并发连接共用一次枚举，等待者可独立取消。"""
    global _lan_cache, _lan_cache_until, _lan_refreshing
    with _lan_condition:
        while True:
            if cancel is not None and cancel.is_set():
                return []
            if time.monotonic() < _lan_cache_until:
                return copy.deepcopy(_lan_cache)
            if not _lan_refreshing:
                _lan_refreshing = True
                generation = _lan_generation
                break
            _lan_condition.wait(0.05)
    try:
        value = _enumerate_lan_interfaces(cancel)
    except Exception:
        # 刷新失败必须释放single-flight，避免所有后续连接永久等待。
        with _lan_condition:
            _lan_refreshing = False
            _lan_condition.notify_all()
        raise
    with _lan_condition:
        if generation == _lan_generation and not (cancel is not None and cancel.is_set()):
            _lan_cache = copy.deepcopy(value)
            _lan_cache_until = time.monotonic() + (_LAN_CACHE_TTL if value else _LAN_FAILURE_TTL)
        _lan_refreshing = False
        _lan_condition.notify_all()
    return copy.deepcopy(value)


def _enumerate_lan_interfaces(cancel=None):
    if os.name != 'nt':
        return []
    # Get-WmiObject明确依赖系统Windows PowerShell 5.1；保留物理网卡筛选，避免TUN/VPN接管跨网段连接。
    script = "[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new(); $ids=@(Get-WmiObject Win32_NetworkAdapter -Filter 'PhysicalAdapter=True AND NetEnabled=True' | ForEach-Object {$_.InterfaceIndex}); @(Get-WmiObject Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' | Where-Object {$ids -contains $_.InterfaceIndex} | Select-Object InterfaceIndex,Description,IPAddress,IPSubnet,DefaultIPGateway,IPConnectionMetric) | ConvertTo-Json -Compress"
    process = None
    try:
        process = subprocess.Popen(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', script],
                                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                    creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        deadline = time.monotonic() + 4
        while process.poll() is None:
            if cancel is not None and cancel.is_set():
                process.kill()
                process.communicate()
                return []
            if time.monotonic() >= deadline:
                process.kill()
                process.communicate()
                return []
            time.sleep(0.05)
        stdout, _ = process.communicate()
        value = json.loads(stdout.decode('utf-8-sig', errors='replace'))
        return value if isinstance(value, list) else [value] if isinstance(value, dict) else []
    except (OSError, ValueError, subprocess.TimeoutExpired):
        if process is not None and process.poll() is None:
            process.kill()
            process.communicate()
        return []


def _lan_routes(interfaces):
    routes = []
    for adapter in interfaces:
        for source, mask in zip(adapter.get('IPAddress') or [], adapter.get('IPSubnet') or []):
            try:
                network = ipaddress.IPv4Network(source + '/' + mask, strict=False)
                index = int(adapter['InterfaceIndex'])
                metric = int(adapter.get('IPConnectionMetric') or 9999)
            except (ValueError, TypeError, KeyError):
                continue
            routes.append((network, metric, index, source, bool(adapter.get('DefaultIPGateway'))))
    return sorted(routes, key=lambda route: route[1:4])


def _choose_route(target, routes):
    fallback = None
    for network, _metric, index, source, gateway in routes:
        if target in network:
            return index, source
        if gateway and fallback is None:
            fallback = index, source
    return fallback


def route_interface(ip, interfaces):
    return _choose_route(ipaddress.IPv4Address(ip), _lan_routes(interfaces))


def _udp_candidate(packet, sender, allowed, uid, nonce):
    if len(packet) < 48 or packet[:6] != b'DNET\x01\x06':
        return None
    size = struct.unpack_from('<H', packet, 6)[0]
    if size + 40 != len(packet) or packet[20:32] != uid or struct.unpack_from('<I', packet, 32)[0] != nonce:
        return None
    if struct.unpack_from('<I', packet, len(packet) - 4)[0] != zlib.crc32(packet[:-4]) & 0xffffffff:
        return None
    ip = socket.inet_ntoa(packet[36:40])
    if ip not in allowed or sender[0] != ip:
        return None
    port = struct.unpack_from('<H', packet, 40)[0]
    length = packet[42]
    end = 43 + length
    if length > 63 or end >= len(packet) - 4 or not port:
        return None
    version_size = packet[end]
    if end + 1 + version_size + 4 != len(packet):
        return None
    return ip, {
        'uid': ''.join(f'{word:08X}' for word in struct.unpack('<III', packet[8:20])),
        'port': port, 'device_name': packet[43:end].decode('utf-8'),
        'version': packet[end + 1:end + 1 + version_size].decode('ascii'),
    }


def udp_discover(targets, routes, cancel, publish):
    """每个地址走一次选定网卡，DNET 候选交给 TCP 核验。"""
    groups = {}
    for ip in targets:
        route = routes[ip]
        if route:
            groups.setdefault(route, []).append(ip)
    allowed, found = set(targets), {}
    sockets = {}
    uid = os.urandom(12)
    nonce = int.from_bytes(os.urandom(4), 'little')
    try:
        for (index, source), addresses in groups.items():
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                sock.setsockopt(socket.IPPROTO_IP, getattr(socket, 'IP_UNICAST_IF', 31), struct.pack('!I', index))
                sock.bind((source, 0))
                sock.setblocking(False)
                header = struct.pack('<4sBBH12s12sI4s', b'DNET', 1, 5, 6, uid, bytes(12), nonce,
                                     socket.inet_aton(source))
                body = header + struct.pack('<H', sock.getsockname()[1])
                packet = body + struct.pack('<I', zlib.crc32(body) & 0xffffffff)
                broadcasts = {str(ipaddress.IPv4Network(ip + '/24', strict=False).broadcast_address)
                              for ip in addresses}
                sockets[sock] = packet, broadcasts, addresses
            except OSError:
                sock.close()
        if not sockets:
            return found

        start = time.monotonic()
        sent_round = -1
        while not cancel.is_set() and found.keys() < allowed:
            elapsed = time.monotonic() - start
            if elapsed >= _SCAN_UDP_WINDOW:
                break
            round_no = int(elapsed >= _SCAN_UDP_RETRY_AT)
            if round_no != sent_round:
                sent_round = round_no
                for sock, (packet, broadcasts, addresses) in sockets.items():
                    # 先发广播，单播补齐跨网段地址；第二轮跳过已应答地址。
                    for destination in (*broadcasts, *addresses):
                        if cancel.is_set():
                            return found
                        if destination in found:
                            continue
                        try:
                            sock.sendto(packet, (destination, 5000))
                        except OSError:
                            pass

            readable, _, _ = select.select(list(sockets), [], [], 0.05)
            for sock in readable:
                # 一次就绪读取一批，避免大量响应反复调用 select。
                for _ in range(64):
                    try:
                        packet, sender = sock.recvfrom(512)
                    except OSError:
                        break
                    try:
                        candidate = _udp_candidate(packet, sender, allowed, uid, nonce)
                    except (ValueError, UnicodeError, struct.error):
                        continue
                    if candidate:
                        ip, info = candidate
                        if ip not in found:
                            found[ip] = info
                            publish(ip, info)
        return found
    finally:
        for sock in sockets:
            sock.close()


class _DiscoveryConnection:
    def __init__(self, loop, sock):
        self.loop = loop
        self.sock = sock
        self.buffer = bytearray()

    async def _fill(self, size):
        while len(self.buffer) < size:
            # 常见的短响应一次读取头部和正文，分段到达时继续保留已读数据。
            block = await self.loop.sock_recv(self.sock, 2048)
            if not block:
                raise ConnectionError('设备已关闭连接')
            self.buffer.extend(block)

    async def request(self, op):
        await self.loop.sock_sendall(self.sock, frame(op))
        while True:
            await self._fill(HEADER.size)
            header = self.buffer[:HEADER.size]
            fields = response_header(header)
            end = HEADER.size + fields[2]
            await self._fill(end)
            body = bytes(self.buffer[HEADER.size:end])
            # 即使设备返回错误码也要消费当前帧，兼容请求才能读取下一条应答。
            del self.buffer[:end]
            response, body = checked_response(header, body, fields)
            if response == op | 0x80000000:
                return body
            if response != 0x80000001:
                raise ValueError('响应命令不匹配')


async def probe(ip, port, route=None, known=False, confirm=False):
    stage = 'TCP 连接'
    protocol = False
    loop = asyncio.get_running_loop()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            if route:
                stage = '绑定局域网网卡'
                index, source = route
                sock.setsockopt(socket.IPPROTO_IP, getattr(socket, 'IP_UNICAST_IF', 31), struct.pack('!I', index))
                sock.bind((source, 0))
            sock.setblocking(False)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            stage = 'TCP 连接'
            await asyncio.wait_for(loop.sock_connect(sock, (ip, port)), 1.5 if confirm else 0.8)
            connection = _DiscoveryConnection(loop, sock)
            timeout = (10 if known else 6) if confirm else (6 if known else 3)
            stage = '快速发现'
            try:
                body = await asyncio.wait_for(connection.request(27), timeout)
                protocol = True
            except DeviceError:
                protocol = True
                stage = '兼容旧固件只读认证'
                await asyncio.wait_for(connection.request(0), timeout)
                stage = '读取设备信息'
                body = await asyncio.wait_for(connection.request(1), 12)

            info = parse_device_info(body)
            if isinstance(info, dict):
                board = str(info.get('board', '')).upper()
                if (board.startswith('STM32') and info.get('uid')) or board.startswith('D133'):
                    return 'found', (ip, info)
            return 'failed', (ip, '识别设备', '响应未包含受支持的板级型号和设备UID', protocol)
    except (asyncio.TimeoutError, TimeoutError):
        return 'failed', (ip, stage, '等待响应超时', protocol)
    except (OSError, ValueError, RuntimeError) as exc:
        shortage = getattr(exc, 'errno', None) in (errno.ENOBUFS, errno.EMFILE, 10055)
        error = '本机连接资源暂时不足' if shortage else (str(exc) or type(exc).__name__)
        return 'failed', (ip, stage, error, protocol)


_SCAN_THREAD_CAP = 8
_SCAN_ADDRESSES_PER_THREAD = 256


def _scan_worker_count(address_count):
    threads_for_size = (address_count + _SCAN_ADDRESSES_PER_THREAD - 1) // _SCAN_ADDRESSES_PER_THREAD
    return max(1, min(threads_for_size, _SCAN_THREAD_CAP, os.cpu_count() or 1))


async def _scan_lane(next_address, probe_one, count, cancel, publish):
    # Windows 的默认 Proactor 循环使用 IOCP，每个线程可同时处理多条连接。
    async def slot():
        while not cancel.is_set():
            ip = next_address()
            if ip is None:
                return
            result = await probe_one(ip)
            if not cancel.is_set():
                publish(result)

    async def wait_for_stop():
        while not cancel.is_set():
            await asyncio.sleep(0.05)

    tasks = [asyncio.create_task(slot()) for _ in range(count)]
    group = asyncio.gather(*tasks)
    stop = asyncio.create_task(wait_for_stop())
    try:
        completed, _ = await asyncio.wait((group, stop), return_when=asyncio.FIRST_COMPLETED)
        if group in completed:
            group.result()
    finally:
        stop.cancel()
        for task in tasks:
            task.cancel()
        await asyncio.gather(stop, group, *tasks, return_exceptions=True)


async def scan_pass(addresses, probe_one, cancel, limit, publish, pool=None):
    """多个扫描线程共享地址队列，按本轮总上限分配异步连接配额。"""
    if not addresses or cancel.is_set():
        return
    remaining = iter(addresses)
    lock = threading.Lock()
    count = min(len(addresses), limit)
    lanes = _scan_worker_count(count)
    loop = asyncio.get_running_loop()

    def next_address():
        # 慢地址占用自己的配额，空闲线程直接取下一个地址。
        with lock:
            return None if cancel.is_set() else next(remaining, None)

    if lanes == 1:
        await _scan_lane(next_address, probe_one, count, cancel, publish)
        return
    per_lane, remainder = divmod(count, lanes)
    jobs = [loop.run_in_executor(pool, asyncio.run, _scan_lane(
        next_address, probe_one, per_lane + int(index < remainder), cancel,
        lambda result: loop.call_soon_threadsafe(publish, result))) for index in range(lanes)]
    await asyncio.gather(*jobs)


def _uid(info):
    uid = str(info.get('uid') or '').strip().upper()
    return '' if uid == 'D133CBS-UNKNOWN' else uid


async def scan_network(targets, routes, port, priority, startup, cancel, emit):
    """UDP 提供端口和 UID，所有在线结果均使用只读 TCP 请求确认。"""
    loop = asyncio.get_running_loop()
    hints = {}
    waiting_for_udp = []
    failures = {}
    found_uids = {}
    first_limit = _SCAN_STARTUP_LIMIT if startup else _SCAN_FIRST_LIMIT

    def record(result, retry=False):
        kind, value = result
        if kind == 'found':
            ip, info = value
            uid = _uid(info)
            expected = hints.get(ip, {}).get('uid')
            duplicate = found_uids.get(uid) if uid else None
            if expected and uid != expected:
                kind, value = 'failed', (ip, 'UID 核验', 'UDP 与 TCP 返回的设备身份不同', True)
            elif duplicate and duplicate != ip:
                kind, value = 'failed', (ip, 'UID 去重', f'同一台设备已通过 {duplicate} 确认在线', True)
            else:
                if uid:
                    found_uids[uid] = ip
                emit('found', value)
        if kind == 'failed':
            if not retry:
                failures[value[0]] = value
            emit('failed' if retry else 'first_failed', value)
        if retry:
            emit('retry_checked', None)

    with concurrent.futures.ThreadPoolExecutor(max_workers=_SCAN_THREAD_CAP + 1,
                                               thread_name_prefix='设备扫描') as pool:
        async def collect_udp():
            udp_result = await loop.run_in_executor(
                pool, udp_discover, targets, routes, cancel,
                lambda ip, info: loop.call_soon_threadsafe(hints.__setitem__, ip, info),
            )
            hints.update(udp_result)
            if not cancel.is_set():
                for result in waiting_for_udp:
                    record(result)
                emit('note', f'UDP 发现 {len(hints)} 个候选地址，在线设备以 TCP 核验为准。')
            waiting_for_udp.clear()

        udp = asyncio.create_task(collect_udp())
        try:
            # 给 UDP 短暂先行时间，其余等待与 TCP 首轮重叠。
            await asyncio.wait((udp,), timeout=_SCAN_UDP_HEAD_START)
            if cancel.is_set():
                return
            ordered = sorted(targets, key=lambda ip: (ip not in hints, ip not in priority))
            first_ports = {ip: info['port'] for ip, info in hints.items()}
            emit('note', f'TCP 首轮并发上限 {first_limit}，本轮 {len(ordered)} 个地址。')

            async def first(ip):
                return await probe(ip, first_ports.get(ip, port), routes[ip],
                                   known=ip in priority or ip in first_ports)

            def first_result(result):
                if result[0] == 'found' and not udp.done() and result[1][0] not in hints:
                    waiting_for_udp.append(result)
                else:
                    record(result)

            await scan_pass(ordered, first, cancel, first_limit, first_result, pool)
            await udp
            if cancel.is_set():
                return

            pending = [
                ip for ip, stage, error, protocol in failures.values()
                if stage != 'UID 去重' and (
                    ip in hints or ip in priority or protocol or '超时' in error
                    or '10060' in error or '连接资源' in error
                )
            ]
            if not pending:
                return
            pending.sort(key=lambda ip: (ip not in hints, ip not in priority))
            emit('retrying', len(pending))
            # 给刚释放连接的设备留出处理时间，再复核需要补扫的地址。
            await asyncio.sleep(0.20)

            async def retry(ip):
                hint = hints.get(ip, {})
                return await probe(ip, hint.get('port', port), routes[ip],
                                   known=ip in priority or ip in hints, confirm=True)

            await scan_pass(pending, retry, cancel, _SCAN_RETRY_LIMIT,
                            lambda result: record(result, retry=True), pool)
        finally:
            # 等 UDP 线程释放自己的套接字后再关闭事件循环。
            await asyncio.gather(udp, return_exceptions=True)


def install(gui):
    cls = gui.LocalTcpApp
    original_load = cls._load_settings
    original_save = cls._save_settings
    original_home = cls._build_home_page
    original_summaries = cls._update_summaries
    original_close = cls._on_close
    original_show_page = cls._show_page
    original_render_info = cls._render_device_info

    def load(app):
        settings = original_load(app)
        backup = {}
        try:
            backup_path = gui.settings_file().with_name('device_names.json')
            backup = json.loads(backup_path.read_text(encoding='utf-8'))
            if not isinstance(backup, dict):
                backup = {}
        except (OSError, ValueError, TypeError):
            backup = {}
        raw = settings.get('device_names')
        backup_names = backup.get('device_names', {})
        if not isinstance(raw, dict) or (not raw and isinstance(backup_names, dict) and backup_names):
            raw = backup_names
        app.device_names = {str(ip): str(name)[:64] for ip, name in raw.items()} if isinstance(raw, dict) else {}
        raw_dirty = settings.get('device_name_dirty')
        backup_dirty = backup.get('device_name_dirty')
        if not isinstance(raw_dirty, dict) or (not raw_dirty and isinstance(backup_dirty, dict) and backup_dirty):
            raw_dirty = backup_dirty
        app.device_name_dirty = {str(ip): str(name)[:64] for ip, name in raw_dirty.items()} if isinstance(raw_dirty, dict) else {ip: name for ip, name in app.device_names.items() if name}
        app.device_scan_ranges = str(settings.get('device_scan_ranges', ''))
        app.device_uids = dict(settings.get('device_uids', {}))
        app.named_device_selectors = {}
        app.discovered_device_names = {}
        app.discovered_devices = set()
        app.device_scan_found = {}
        app.device_name_sync_pending = {}
        app.device_name_sync_results = queue.Queue()
        app.device_name_sync_running = False
        app.device_name_sync_after = None
        app.device_scan_running = False
        app.device_startup_scan_started = False
        app.device_rows_need_refresh = False
        app.device_online_ips = set()
        app.device_scan_queue = queue.Queue()
        app.device_scan_cancel = threading.Event()
        app.device_save_after = None
        app.device_name_drafts = {}
        return settings

    def save(app):
        original_save(app)

    def labels(app):
        addresses = set(app.device_names) | app.discovered_devices
        current = app.host_var.get().strip()
        if current:
            addresses.add(current)
        return [(ip, ((app.device_names.get(ip) or app.discovered_device_names.get(ip, '')) + ' | ' + ip)
                     if (app.device_names.get(ip) or app.discovered_device_names.get(ip)) else ip)
                for ip in sorted(addresses)]

    def refresh_choices(app):
        choices = labels(app)
        values = [label for _, label in choices] or ['尚未添加设备']
        by_ip = dict(choices)
        app.device_label_to_ip = {label: ip for ip, label in choices}
        if hasattr(app, 'device_combo'):
            app.device_combo.configure(values=values)
            current = app.host_var.get().strip()
            app.device_combo.set(by_ip.get(current, current))
        for kind, combo in app.named_device_selectors.items():
            combo.configure(values=values)
            target_vars = {'w78': 'w78_host_var', 'd133_usb': 'd133_proxy_host_var'}
            saved = getattr(app, target_vars.get(kind, ''), None)
            selected = saved.get().strip() if saved is not None else getattr(app, 'ota_selected_ip', app.host_var.get().strip())
            combo.set(by_ip.get(selected, selected))
        if hasattr(app, 'ota_hosts_input'):
            refresh_ota_names(app)
        current = app.host_var.get().strip()
        name = app.device_names.get(current) or app.discovered_device_names.get(current, '')
        summary = (name + ' | ' + current) if current and name else (current or '未设置设备 IP')
        app.connection_summary_var.set(summary)
        if hasattr(app, 'device_current_label_var'):
            app.device_current_label_var.set(('当前选择：' + summary + (' | 已确认在线' if current in app.device_online_ips else ' | 历史记录／未确认')) if current else '输入或选择设备 IP')

        render_overview(app, choices)
        if hasattr(app, '_fixture_refresh_device_choices'):
            app._fixture_refresh_device_choices()

    def named_selector(app, parent, kind):
        row = ctk.CTkFrame(parent, fg_color='transparent')
        row.pack(fill='x', padx=18, pady=(0, 10))
        row.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(row, text='选择设备加入升级列表' if kind == 'ota' else '选择设备').grid(row=0, column=0, padx=(0, 10))
        def choose(value):
            if app.is_running:
                return
            ip = app.device_label_to_ip.get(value)
            if not ip:
                return
            if kind == 'w78':
                app.w78_host_var.set(ip)
            elif kind == 'd133_usb':
                app.d133_proxy_host_var.set(ip)
            else:
                app.ota_selected_ip = ip
                app._add_ota_target(ip)
            app._save_settings()
            app._refresh_device_choices()
        choices = labels(app)
        combo = app._register_action(ctk.CTkComboBox(row, values=[label for _, label in choices] or ['尚未添加设备'],
                                                    command=choose, state='readonly', height=34))
        combo._toolbox_user_data = True
        combo.grid(row=0, column=1, sticky='ew')
        app.named_device_selectors[kind] = combo
        app._refresh_device_choices()

    def display_label(app, ip):
        name = app.device_names.get(ip) or app.discovered_device_names.get(ip, '')
        return (name + ' | ' + ip) if name else ip

    def refresh_ota_names(app):
        if app.is_running:
            return
        raw = app.ota_hosts_input.get('1.0', 'end-1c').strip()
        if not raw:
            app._render_ota_selection_rows()
            return
        try:
            if app.root.focus_get() == app.ota_hosts_input._textbox:
                return
        except tk.TclError:
            return
        lines = []
        for token in ota_tokens(raw):
            try:
                ip = normalize_ipv4(token)
            except ValueError:
                return
            lines.append(display_label(app, ip))
        text = '\n'.join(lines)
        if text != raw:
            app.ota_hosts_input.delete('1.0', 'end')
            app.ota_hosts_input.insert('1.0', text)
        app._render_ota_selection_rows()

    def select(app, value):
        if app.is_running:
            return
        ip = app.device_label_to_ip.get(value, value.split(' | ', 1)[0])
        app.host_var.set(ip)
        app.w78_host_var.set(ip)
        app._save_settings()
        app._refresh_device_choices()
        app._read_once()

    def render_overview(app, choices):
        if not hasattr(app, 'overview_rows'):
            return
        active = app.host_var.get().strip()
        snapshots = getattr(app, 'overview_snapshots', {})
        pane = app.overview_rows

        def make_row(values, ip=None):
            header = ip is None
            line = ctk.CTkFrame(pane, fg_color='transparent', corner_radius=7)
            labels = []
            for j, weight in enumerate((3, 2, 3, 2, 2)):
                line.grid_columnconfigure(j, weight=weight, uniform='设备列', minsize=0)
                label = ctk.CTkLabel(line, width=16, height=31 if header else 42,
                    text=values[j], anchor='w',
                    font=app._font(11 if header else 12, 'bold' if header or j == 0 else 'normal'),
                    text_color=gui.COLORS['muted' if header or j == 4 else 'text'])
                label.grid(row=0, column=j, sticky='ew', padx=5)
                if ip is not None:
                    label.bind('<Button-1>', lambda _event, address=ip: app._select_named_device(address))
                labels.append(label)
            return line, labels

        if not hasattr(app, 'overview_row_items'):
            app.overview_row_items = {}
            pane.grid_columnconfigure(0, weight=1)
            heading, _ = make_row(('名称', '型号', 'IP 地址', '版本', '状态'))
            heading.grid(row=0, column=0, sticky='ew', pady=2)
            app.overview_empty_label = ctk.CTkLabel(pane, text='未发现设备',
                                                   text_color=gui.COLORS['muted'])

        rows = app.overview_row_items
        live = {ip for ip, _ in choices}
        for ip in rows.keys() - live:
            line, _labels, _index, _data, _selected = rows.pop(ip)
            line.destroy()
        if choices:
            app.overview_empty_label.grid_remove()
        else:
            app.overview_empty_label.grid(row=1, column=0, pady=12)

        # 只更新新增或状态变化的行，扫描时保留已有控件与滚动位置。
        for index, (ip, label) in enumerate(choices, 1):
            info = snapshots.get(ip, {})
            online = ip in app.device_online_ips
            name = label.rsplit(' | ', 1)[0] if ' | ' in label else '—'
            values = (name, info.get('board'), ip, info.get('version'), '在线' if online else '未确认')
            data = []
            for value, limit in zip(values, (13, 12, 17, 10, 8)):
                value = str(value or '—')
                data.append(value if len(value) <= limit else value[:limit - 1] + '…')
            selected = ip == active
            existing = rows.get(ip)
            if existing:
                line, labels, old_index, old_data, old_selected = existing
                for widget, old, new in zip(labels, old_data, data):
                    if old != new:
                        widget.configure(text=new)
                if old_data[-1] != data[-1]:
                    labels[-1].configure(text_color=gui.COLORS['success_text' if online else 'muted'])
            else:
                line, labels = make_row(data, ip)
                labels[-1].configure(text_color=gui.COLORS['success_text' if online else 'muted'])
                old_index, old_selected = None, None
            if old_index != index:
                line.grid(row=index, column=0, sticky='ew', pady=2)
            if old_selected != selected:
                line.configure(fg_color=gui.COLORS['success_bg'] if selected else 'transparent')
            rows[ip] = line, labels, index, data, selected


    def home(app):
        original_home(app)
        card = app.home_connect_card
        app.device_combo = ctk.CTkComboBox(card, values=['设备列表'], command=app._select_named_device, height=36)
        app.device_combo._toolbox_user_data = True
        app._register_action(app.device_combo)
        app.device_combo.pack(fill='x', padx=12, pady=(0, 5), before=app.home_target_fields)
        app.device_scan_button = app._rail_button(card, '扫描设备', app._discover_devices, primary=True)
        app.device_scan_button.pack_configure(before=app.info_button)
        app.device_current_label_var = tk.StringVar(master=app.root, value='')
        app._refresh_device_choices()
        app.host_var.trace_add('write', lambda *_: app._refresh_device_choices())

    def build_page(app):
        page = app._page('devices')
        card = app._rail_card('devices', '添加设备')
        form = ctk.CTkFrame(card, fg_color='transparent')
        form.pack(fill='x', padx=12, pady=5)
        form.grid_columnconfigure((0, 1), weight=1)
        app.new_device_ip = tk.StringVar(master=app.root)
        app.new_device_name = tk.StringVar(master=app.root)
        ip_entry = ctk.CTkEntry(form, textvariable=app.new_device_ip, placeholder_text='设备 IP 地址', height=40, corner_radius=8, border_color=gui.COLORS['border'], fg_color=gui.COLORS['input'], text_color=gui.COLORS['text'], font=app._font(14))
        ip_entry.grid(row=0, column=0, columnspan=2, sticky='ew', pady=(0, 6))
        name_entry = ctk.CTkEntry(form, textvariable=app.new_device_name, placeholder_text='设备名称', height=40, corner_radius=8, border_color=gui.COLORS['border'], fg_color=gui.COLORS['input'], text_color=gui.COLORS['text'], font=app._font(14))
        app.device_ip_entry = ip_entry
        app.device_name_entry = name_entry
        name_entry.grid(row=1, column=0, columnspan=2, sticky='ew')
        add_button = app._secondary_button(form, '添加到列表', lambda owner=app: add(owner), width=100)
        add_button.grid(row=2, column=0, columnspan=2, sticky='ew', pady=(8, 3))
        ip_entry.bind('<Return>', lambda _event, owner=app: (add(owner), 'break')[1])
        name_entry.bind('<Return>', lambda _event, owner=app: (add(owner), 'break')[1])
        app.device_add_status_var = tk.StringVar(master=app.root, value='')
        ctk.CTkLabel(card, textvariable=app.device_add_status_var, font=app._font(11),
                     wraplength=170, text_color=gui.COLORS['blue']).pack(fill='x', padx=10, pady=6)
        ctk.CTkLabel(page, text='已保存设备', font=app._font(18, 'bold')).grid(row=0,column=0,sticky='w',padx=4)
        app.device_rows = ctk.CTkFrame(page, fg_color='transparent')
        app.device_rows.grid(row=1, column=0, sticky='ew')
        app._render_device_rows()

    def render(app):
        if app.device_save_after is not None:
            app.root.after_cancel(app.device_save_after)
            app.device_save_after = None
            app._save_settings()
        for widget in app.device_rows.winfo_children():
            widget.destroy()
        # 每行先呈现设备名称和地址，再排列编辑与操作按钮。
        for index, (ip, label) in enumerate(labels(app)):
            row = ctk.CTkFrame(app.device_rows, fg_color=gui.COLORS['card'], corner_radius=10,
                                border_width=1, border_color=gui.COLORS['border'])
            row.pack(fill='x', pady=4)
            row.grid_columnconfigure(1, weight=1)
            ctk.CTkLabel(row, text=(label[:24]+'…' if len(label)>25 else label), width=124, anchor='w', font=app._font(14, 'bold'),
                         text_color=gui.COLORS['text']).grid(row=0, column=0, padx=12, pady=10)
            variable = tk.StringVar(master=app.root, value=app.device_name_drafts.get(ip, app.device_names.get(ip, '')))
            entry = ctk.CTkEntry(row, textvariable=variable, placeholder_text='设备名称', height=40,
                                 corner_radius=8, border_color=gui.COLORS['border'],
                                 fg_color=gui.COLORS['input'], text_color=gui.COLORS['text'],
                                 font=app._font(14))
            entry.grid(row=0, column=1, sticky='ew', padx=8, pady=8)
            def changed(*_, address=ip, var=variable):
                app.device_name_drafts[address] = var.get()
            variable.trace_add('write', changed)
            ctk.CTkButton(row, text='选择', command=lambda address=ip: app._select_named_device(address),
                          width=55, height=38, corner_radius=8, fg_color=gui.COLORS['soft'],
                          hover_color=gui.COLORS['border'], text_color=gui.COLORS['text']).grid(row=0, column=2, padx=3)
            ctk.CTkButton(row, text='发送名称', command=lambda address=ip, var=variable: app._sync_device_name(address, var.get().strip()),
                          width=74, height=38, corner_radius=8, fg_color=gui.COLORS['blue'],
                          hover_color=gui.COLORS['blue_hover'], text_color='#FFFFFF').grid(row=0, column=3, padx=3)
            def remove(address=ip):
                app.device_name_drafts.pop(address, None)
                app.device_names.pop(address, None)
                app.device_name_dirty.pop(address, None)
                app.discovered_devices.discard(address)
                app._save_settings()
                app._refresh_device_choices()
                app._render_device_rows()
            ctk.CTkButton(row, text='删除', command=remove, width=68, height=38, corner_radius=8,
                          fg_color=gui.COLORS['error_bg'], hover_color='#FFD6D7',
                          text_color=gui.COLORS['error_text']).grid(row=0, column=4, padx=(3, 10))

    def add(app):
        raw_ip = app.device_ip_entry.get()
        try:
            ip = normalize_ipv4(raw_ip)
        except (ValueError, UnicodeError, TypeError):
            message = f'无法识别 IPv4 地址（输入值：{raw_ip!r}）。请只输入 192.168.1.50 这样的 IPv4 地址，不要附加端口。'
            if hasattr(app, 'device_add_status_var'):
                app.device_add_status_var.set(message)
            app._set_status('IP 地址格式无效')
            messagebox.showerror('IP 地址无效', message, parent=app.root)
            return
        try:
            entered_name = app._truncate_device_name(app.device_name_entry.get().strip())
            previous_name = app.device_names.get(ip) or app.discovered_device_names.get(ip, '')
            name = previous_name
            app.device_names[ip] = name
            if entered_name:
                app.device_name_drafts[ip] = entered_name
            app._save_settings()
            app._refresh_device_choices()
            app._render_device_rows()
            app.host_var.set(ip)
            app.w78_host_var.set(ip)
            app._refresh_device_choices()
            app.new_device_ip.set('')
            app.new_device_name.set('')
            app.device_add_status_var.set(f'已添加 {ip}，已加入列表，正在后台保存；可在总览中选择。')
            app._set_status('设备已添加')
            app._append_log(f'已将 {ip} 添加到本机设备列表；后台保存配置，可在总览中选择。')
        except Exception as exc:
            if hasattr(app, 'device_add_status_var'):
                app.device_add_status_var.set('添加失败：' + str(exc))
            app._set_status('添加失败')
            messagebox.showerror('添加设备失败', '本机设备列表未能完成保存：' + str(exc), parent=app.root)

    def discover(app, *, startup=False):
        if startup:
            if app.device_startup_scan_started:
                return
            app.device_startup_scan_started = True
        if app.device_scan_running or app.is_running:
            return

        scope = app.device_scan_ranges
        try:
            try:
                port = int(app.port_var.get())
            except ValueError:
                port = 0
            if not 1 <= port <= 65535:
                raise ValueError('请输入 1–65535 的 TCP 端口。')
            configured = configured_targets(scope)
        except ValueError as exc:
            detail = str(exc)
            if startup:
                app._append_log('启动扫描未开始：' + detail)
            else:
                messagebox.showerror('无法扫描设备', detail, parent=app.root)
            return

        scan_name = '启动设备扫描' if startup else '扫描设备'
        app.device_scan_running = True
        app.device_scan_history_id = app._history_start(scan_name)
        app.device_scan_found = {}
        app.device_online_ips.clear()
        cancel = app.device_scan_cancel
        cancel.clear()
        app.device_scan_button.configure(state='disabled', text='正在寻找…')
        app.stop_button.configure(state='normal', fg_color=gui.COLORS['error_text'],
                                  hover_color='#991B1B', text_color='#FFFFFF')
        app._set_status('正在启动扫描…' if startup else '正在扫描设备…')
        app.device_scan_checked = 0
        app.device_scan_checked_ips = set()
        app.device_scan_protocol_ips = set()
        app.device_scan_phase = 1
        app.device_scan_retry_checked = 0
        app.device_scan_retry_total = 0
        app.device_scan_reachable = 0
        app.device_scan_total = 0
        current = app.host_var.get().strip()
        known = tuple(app.device_names)
        priority = set(known) | {current}

        def publish(kind, value):
            app.device_scan_queue.put((kind, value))

        def worker():
            failure = None
            try:
                interfaces = lan_interfaces(cancel)
                if not cancel.is_set():
                    limit = _SCAN_STARTUP_LIMIT if startup else _SCAN_MAX_ADDRESSES
                    route_table = _lan_routes(interfaces)
                    if configured:
                        targets = sorted(configured, key=lambda ip: ip not in priority)[:limit]
                    else:
                        targets = discovery_targets(current, known, route_table, limit)
                    publish('range', len(targets))
                    names = [str(v.get('Description') or v.get('InterfaceIndex')) for v in interfaces]
                    publish('interfaces', names)
                    if targets and not cancel.is_set():
                        routes = {ip: _choose_route(ipaddress.IPv4Address(ip), route_table) for ip in targets}
                        asyncio.run(scan_network(targets, routes, port, priority, startup, cancel, publish))
            except Exception as exc:
                failure = str(exc) or type(exc).__name__
            if cancel.is_set():
                publish('cancelled', None)
            elif failure is not None:
                publish('error', failure)
            else:
                publish('done', None)

        threading.Thread(target=worker, name='设备扫描调度', daemon=True).start()

        next_refresh_at = 0.0
        rows_dirty = False

        def poll():
            nonlocal next_refresh_at, rows_dirty
            handled = False
            next_poll_ms = 100
            deadline = time.perf_counter() + 0.010
            found_messages = []
            terminal = None
            for index in range(_SCAN_UI_BATCH):
                # 大范围扫描的结果逐批消费，给界面线程保留处理操作的时间。
                if index and time.perf_counter() >= deadline:
                    next_poll_ms = 10
                    break
                try:
                    kind, value = app.device_scan_queue.get_nowait()
                except queue.Empty:
                    break
                handled = True
                if kind == 'range':
                    app.device_scan_total = value
                    label = scope.strip() or '物理网卡与已知设备网段'
                    app._append_log(f'{scan_name}：{label}，共 {value} 个地址，TCP 端口 {port}。')
                elif kind == 'interfaces':
                    app._append_log('扫描出站网卡：' + ('；'.join(value) if value else '使用系统路由'))
                elif kind == 'note':
                    app._append_log(value)
                elif kind == 'retrying':
                    app.device_scan_phase = 2
                    app.device_scan_retry_total = value
                    app._append_log(f'补扫 {value} 个待核验地址，并发上限 {_SCAN_RETRY_LIMIT}。')
                elif kind == 'retry_checked':
                    app.device_scan_retry_checked += 1
                elif kind == 'found':
                    ip, info = value
                    app.device_scan_checked_ips.add(ip)
                    app.device_scan_protocol_ips.add(ip)
                    app.device_scan_found[ip] = info
                    app.device_online_ips.add(ip)
                    app.discovered_devices.add(ip)
                    accept_info(app, ip, info, refresh=False)
                    rows_dirty = True
                    name = str(info.get('device_name') or '').strip() or '未命名'
                    found_messages.append(f'发现开发板：{name} | {ip}')
                elif kind in ('first_failed', 'failed'):
                    ip, stage, error, protocol = value
                    app.device_scan_checked_ips.add(ip)
                    if protocol:
                        app.device_scan_protocol_ips.add(ip)
                    if ip in priority:
                        app._append_log(f'[{ip}] {stage}：{error}')
                else:
                    terminal = kind, value
                    break
            else:
                next_poll_ms = 10

            if found_messages:
                app._append_log('\n'.join(found_messages))
            app.device_scan_checked = len(app.device_scan_checked_ips)
            app.device_scan_reachable = len(app.device_scan_protocol_ips)
            if terminal:
                kind, value = terminal
                app.device_scan_running = False
                app.device_scan_button.configure(state='disabled' if app.is_running else 'normal', text='扫描设备')
                results = {'done': '已结束', 'cancelled': '已停止', 'error': '失败'}
                app._history_finish(app.device_scan_history_id, results[kind])
                count = len(app.device_scan_found)
                if kind == 'done':
                    app.discovered_devices = set(app.device_scan_found)
                    history = len(set(app.device_names) - set(app.device_scan_found))
                    message = (f'{scan_name}完成：已检查 {app.device_scan_checked}/{app.device_scan_total} 个地址，'
                               f'确认在线 {count} 台，历史记录未确认 {history} 台。')
                    status = f'发现 {count} 台开发板' if count else '未发现开发板'
                elif kind == 'cancelled':
                    message, status = f'扫描已停止，保留已确认的 {count} 台设备。', '扫描已停止'
                else:
                    message, status = '扫描失败：' + str(value), '扫描失败'
                app._append_log(message)
                if not app.is_running:
                    app.stop_button.configure(state='disabled', fg_color=gui.COLORS['error_bg'],
                                              hover_color='#FECACA', text_color=gui.COLORS['error_text'])
                    app._set_status(status)
                if hasattr(app, 'device_add_status_var'):
                    app.device_add_status_var.set(message)
                if app.device_scan_found:
                    app._save_settings()
                app._refresh_device_choices()
                if hasattr(app, 'device_rows'):
                    if getattr(app, 'active_page_key', 'devices') == 'devices':
                        app._render_device_rows()
                    else:
                        app.device_rows_need_refresh = True
                return

            now = time.monotonic()
            if rows_dirty and now >= next_refresh_at:
                app._refresh_device_choices()
                next_refresh_at = now + 0.25
                rows_dirty = False
            if handled:
                if app.device_scan_phase == 2:
                    progress = f'补扫 {app.device_scan_retry_checked}/{app.device_scan_retry_total}'
                else:
                    progress = f'扫描 {app.device_scan_checked}/{app.device_scan_total}'
                app.device_scan_button.configure(text=progress)
            app.root.after(next_poll_ms, poll)

        app.root.after(100, poll)

    def cancel_discovery(app):
        # 套接字由各扫描线程释放，界面只发送停止信号。
        app.device_scan_cancel.set()

    def show_page(app, page):
        original_show_page(app, page)
        if page == 'devices' and app.device_rows_need_refresh:
            app.device_rows_need_refresh = False
            app._render_device_rows()

    def accept_info(app, ip, info, refresh=True):
        if isinstance(info, dict) and ip:
            if not hasattr(app, 'overview_snapshots'):
                app.overview_snapshots = {}
            app.overview_snapshots[ip] = {key: info.get(key) for key in ('board', 'version')}

        if 'device_name' not in info:
            return
        uid = _uid(info)
        name = truncate_name(info.get('device_name') or '')
        if uid:
            for previous, old_uid in list(app.device_uids.items()):
                if previous != ip and str(old_uid).upper() == uid:
                    app.device_names.pop(previous, None)
                    app.discovered_device_names.pop(previous, None)
                    app.discovered_devices.discard(previous)
                    app.device_uids.pop(previous, None)
                    app.device_name_dirty.pop(previous, None)
            app.device_uids[ip] = uid
        app.device_online_ips.add(ip)
        app.device_names[ip] = name
        app.discovered_device_names[ip] = name
        app.discovered_devices.add(ip)
        if refresh:
            app._save_settings()
            app._refresh_device_choices()

    def render_info(app, body):
        original_render_info(app, body)
        try:
            info = parse_device_info(body)
            accept_info(app, app.host_var.get().strip(), info)
            if hasattr(app, 'device_rows'):
                app._render_device_rows()
        except (ValueError, TypeError, AttributeError):
            pass

    def truncate_name(value):
        value = str(value).strip()
        out = ''
        for char in value:
            if ord(char) < 32 or ord(char) == 127:
                continue
            if len((out + char).encode('utf-8')) > 63:
                break
            out += char
        return out

    def sync_name(app, ip, value):
        name = truncate_name(value)
        app.device_name_dirty[ip] = name
        app.device_name_sync_pending[ip] = name
        app._save_settings()
        action = f'发送设备名称“{name}”' if name else '清除开发板名称'
        app._append_log(f'[{ip}] 已提交{action}，正在等待发送。')
        app._set_status('名称同步等待中' if (app.is_running or app.device_scan_running)
                        else '正在发送设备名称…')
        pump_sync(app)

    def pump_sync(app):
        if app.device_name_sync_running or not app.device_name_sync_pending:
            return
        if app.is_running or app.device_scan_running:
            if app.device_name_sync_after is None:
                app.device_name_sync_after = app.root.after(500, lambda: sync_poll(app))
            return
        ip = next(iter(app.device_name_sync_pending))
        name = app.device_name_sync_pending.pop(ip)
        try:
            args, key = app._connection_inputs(host_override=ip)
            if len(key) != 32:
                app._append_log(f'[{ip}] 开发板名称尚未同步：请先导入配套 Local TCP Key。')
                app._set_status('名称未发送：需要配套 Key')
                return
            payload = name.encode('utf-8')
        except (ValueError, UnicodeError) as exc:
            app._append_log(f'[{ip}] 开发板名称尚未同步：{exc}')
            app._set_status('名称未发送：配置无效')
            return
        app.device_name_sync_running = True
        app._append_log(f'[{ip}] 正在连接开发板，写入名称并回读确认…')
        app._set_status('正在同步设备名称…')
        def action(_args, _key, stop_event):
            stage = '连接与Key认证'
            for attempt in range(3):
                try:
                    if stop_event.is_set():
                        raise InterruptedError()
                    stage = '连接与Key认证'
                    with app._connection(args, key, stop_event) as sock:
                        sock.settimeout(15)
                        stage = '读取板端当前名称'
                        info = parse_device_info(gui.request(sock, 1))
                        if 'device_name' not in info:
                            raise RuntimeError('固件未提供device_name字段，请先升级配套OTA')
                        if str(info.get('device_name') or '') != name:
                            if stop_event.is_set():
                                raise InterruptedError()
                            stage = '发送名称与板端保存'
                            gui.request(sock, 26, payload=payload)
                            stage = '读取板端名称确认'
                            info = parse_device_info(gui.request(sock, 1))
                            if str(info.get('device_name') or '') != name:
                                raise RuntimeError('板端返回名称与发送值不一致')
                        app.device_name_sync_results.put((ip, name, None, info))
                        return
                except Exception as exc:
                    if stop_event.is_set() or isinstance(exc, InterruptedError):
                        app.device_name_sync_results.put((ip, name, '已停止', None))
                        raise InterruptedError()
                    if not isinstance(exc, (OSError, ConnectionError)) or attempt == 2:
                        app.device_name_sync_results.put((ip, name, stage + '失败：' + str(exc), None))
                        return
                    app._post('log', f'[{ip}] {stage}未完成，正在重试（{attempt + 2}/3）。')
                    if stop_event.wait(0.6 * (attempt + 1)):
                        app.device_name_sync_results.put((ip, name, '已停止', None))
                        raise InterruptedError()
        app._start_task('同步设备名称', action, require_connection=False)
        if not app.is_running:
            app.device_name_sync_running = False
            app.device_name_sync_results.put((ip, name, '任务未能启动，请查看操作记录', None))
        if app.device_name_sync_after is None:
            app.device_name_sync_after = app.root.after(100, lambda: sync_poll(app))

    def sync_poll(app):
        app.device_name_sync_after = None
        try:
            while True:
                ip, name, error, info = app.device_name_sync_results.get_nowait()
                app.device_name_sync_running = False
                if error == '已停止':
                    app._append_log(f'[{ip}] 名称发送已停止，未确认保存。')
                    app._set_status('已停止')
                elif error:
                    app._append_log(f'[{ip}] 开发板名称同步失败：{error}。可点击“发送名称”重试。')
                    app._set_status('设备名称同步失败')
                else:
                    app.device_name_synced = getattr(app, 'device_name_synced', {})
                    app.device_name_synced[ip] = name
                    app.device_online_ips.add(ip)
                    if truncate_name(app.device_name_drafts.get(ip, '')) == name:
                        app.device_name_drafts.pop(ip, None)
                    app.device_names[ip] = name
                    app.discovered_device_names[ip] = name
                    app._refresh_device_choices()
                    if hasattr(app, 'device_rows'):
                        app._render_device_rows()
                    if app.device_name_dirty.get(ip) == name:
                        app.device_name_dirty.pop(ip, None)
                    app._save_settings()
                    app._append_log(f'[{ip}] 开发板名称已保存：{name or "（已清除）"}。局域网内设备互联列表将同步更新。')
                    app._set_status('设备名称已同步')
                    if info is not None and app.host_var.get().strip() == ip:
                        info = gui.normalize_device_info(info)
                        app.device_info_cache = info
                        app.device_received_var.set(f"最近接收：{time.strftime('%H:%M:%S')}")
                        app._update_device_metric_values(info)
                        app._append_log(f'[{ip}] 当前设备信息已同步到设备信息页。')
                pump_sync(app)
        except queue.Empty:
            pass
        pump_sync(app)
        if (app.device_name_sync_running or app.device_name_sync_pending) and app.device_name_sync_after is None:
            app.device_name_sync_after = app.root.after(250, lambda: sync_poll(app))

    def summaries(app, *args):
        try:
            if not app.root.winfo_exists():
                return
        except tk.TclError:
            return
        original_summaries(app, *args)
        app._refresh_device_choices()
        if app.device_name_sync_pending:
            pump_sync(app)

    def close(app):
        cancel_discovery(app)
        if app.device_name_sync_after is not None:
            try:
                app.root.after_cancel(app.device_name_sync_after)
            except tk.TclError:
                pass
        if app.device_save_after is not None:
            try:
                app.root.after_cancel(app.device_save_after)
            except tk.TclError:
                pass
        return original_close(app)

    cls._refresh_ota_names = refresh_ota_names
    cls._build_named_selector = named_selector
    cls._device_display_label = display_label
    cls._accept_device_info = accept_info
    cls._render_device_info = render_info
    cls._on_close = close
    cls._show_page = show_page
    cls._update_summaries = summaries
    cls._load_settings = load
    cls._save_settings = save
    cls._build_home_page = home
    cls._build_devices_page = build_page
    cls._refresh_device_choices = refresh_choices
    cls._select_named_device = select
    cls._render_device_rows = render
    cls._add_named_device = add
    cls._truncate_device_name = staticmethod(truncate_name)
    cls._sync_device_name = sync_name
    cls._discover_devices = discover
    cls._cancel_device_scan = cancel_discovery
