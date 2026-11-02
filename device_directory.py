"""Persistent device aliases and read-only discovery on local IPv4 networks."""
from __future__ import annotations

import concurrent.futures
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
from local_tcp_client import parse_device_info, DeviceError


def discovery_targets(current='', known=()):
    local = set()
    try:
        local.update(socket.gethostbyname_ex(socket.gethostname())[2])
    except OSError:
        pass
    try:
        result = subprocess.run(['ipconfig'], stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, timeout=5,
                                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        local.update(re.findall(r'IPv4[^:\r\n]*:\s*(\d+\.\d+\.\d+\.\d+)',
                                result.stdout.decode(errors='ignore')))
    except (OSError, subprocess.TimeoutExpired):
        pass
    targets = set()
    networks = []
    # Include the selected/saved devices' subnets: a reachable board may be
    # on a routed LAN different from the computer's own adapter subnet.
    for value in [current] + list(known) + sorted(local):
        try:
            address = ipaddress.IPv4Address(value)
            if (address.is_private and not address.is_loopback and not address.is_link_local
                    and address not in ipaddress.IPv4Network('198.18.0.0/15')):
                network = ipaddress.IPv4Network(str(address) + '/24', strict=False)
                if network not in networks:
                    networks.append(network)
        except ValueError:
            continue
    for network in networks[:4]:
        targets.update(str(address) for address in network.hosts())
    for value in [current] + list(known):
        try:
            address = ipaddress.IPv4Address(value)
            if address.is_private and not address.is_loopback:
                targets.add(str(address))
        except ValueError:
            continue
    targets.difference_update(local)
    return sorted(targets, key=ipaddress.IPv4Address)


def configured_targets(value):
    """Accept one CIDR, IPv4 interval or address per line, at most 4096 hosts."""
    targets = set()
    for part in re.split(r'[,;\n]+', value):
        part = part.strip()
        if not part:
            continue
        if '/' in part:
            network = ipaddress.IPv4Network(part, strict=False)
            if network.num_addresses > 4096:
                raise ValueError('单次扫描最多 4096 个地址')
            addresses = network.hosts()
        elif '-' in part:
            first, last = [int(ipaddress.IPv4Address(v.strip())) for v in part.split('-', 1)]
            if last < first or last - first >= 4096:
                raise ValueError('扫描范围顺序无效或超过 4096 个地址')
            addresses = (ipaddress.IPv4Address(v) for v in range(first, last + 1))
        else:
            addresses = [ipaddress.IPv4Address(part)]
        targets.update(str(v) for v in addresses)
        if len(targets) > 4096:
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


def lan_interfaces(cancel=None):
    if os.name != 'nt':
        return []
    script = "$ids=@(Get-WmiObject Win32_NetworkAdapter -Filter 'PhysicalAdapter=True AND NetEnabled=True' | ForEach-Object {$_.InterfaceIndex}); @(Get-WmiObject Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' | Where-Object {$ids -contains $_.InterfaceIndex} | Select-Object InterfaceIndex,Description,IPAddress,IPSubnet,DefaultIPGateway,IPConnectionMetric) | ConvertTo-Json -Compress"
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


def route_interface(ip, interfaces):
    target = ipaddress.IPv4Address(ip)
    candidates = []
    for adapter in interfaces:
        addresses = adapter.get('IPAddress') or []
        masks = adapter.get('IPSubnet') or []
        for source, mask in zip(addresses, masks):
            try:
                network = ipaddress.IPv4Network(source + '/' + mask, strict=False)
                match = target in network
                if match or adapter.get('DefaultIPGateway'):
                    candidates.append((not match, int(adapter.get('IPConnectionMetric') or 9999),
                                       int(adapter['InterfaceIndex']), source))
            except (ValueError, TypeError, KeyError):
                continue
    return min(candidates)[2:] if candidates else None


def udp_discover(targets, interfaces, cancel, report):
    """DNET v1 type5 request/type6 reply, nonce + CRC; TCP verifies every reply."""
    sockets = []
    uid = os.urandom(12)
    nonce = int.from_bytes(os.urandom(4), 'little')
    found = {}
    try:
        sources = {}
        for ip in targets:
            route = route_interface(ip, interfaces)
            if route:
                sources[route[1]] = route[0]
        for source, index in sources.items():
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                sock.setsockopt(socket.IPPROTO_IP, getattr(socket, 'IP_UNICAST_IF', 31), struct.pack('!I', index))
                sock.bind((source, 0))
                sock.setblocking(False)
                sockets.append((sock, source))
            except OSError:
                sock.close()
        if not sockets:
            report('UDP发现未找到可用物理网卡，将使用TCP兼容扫描。')
            return found
        broadcasts = {str(ipaddress.IPv4Network(ip + '/24', strict=False).broadcast_address) for ip in targets}
        allowed = set(targets)
        start = time.monotonic()
        sent_round = -1
        while time.monotonic() - start < 4.2 and not cancel.is_set():
            round_no = min(2, int((time.monotonic() - start) / 1.3))
            if round_no != sent_round:
                sent_round = round_no
                for sock, source in sockets:
                    header = struct.pack('<4sBBH12s12sI4s', b'DNET', 1, 5, 6, uid, bytes(12), nonce, socket.inet_aton(source))
                    body = header + struct.pack('<H', sock.getsockname()[1])
                    packet = body + struct.pack('<I', zlib.crc32(body) & 0xffffffff)
                    # Directed UDP also reaches routed LANs where broadcast is blocked.
                    destinations = broadcasts | allowed
                    for destination in destinations:
                        if cancel.is_set():
                            return found
                        try:
                            sock.sendto(packet, (destination, 5000))
                        except OSError:
                            pass
            readable, _, _ = select.select([sock for sock, _ in sockets], [], [], 0.1)
            for sock in readable:
                try:
                    packet, sender = sock.recvfrom(512)
                    if len(packet) < 48 or packet[:6] != b'DNET\x01\x06':
                        continue
                    size = struct.unpack_from('<H', packet, 6)[0]
                    if size + 40 != len(packet) or packet[20:32] != uid or struct.unpack_from('<I', packet, 32)[0] != nonce:
                        continue
                    if struct.unpack_from('<I', packet, len(packet)-4)[0] != zlib.crc32(packet[:-4]) & 0xffffffff:
                        continue
                    ip = socket.inet_ntoa(packet[36:40])
                    if ip not in allowed or sender[0] != ip:
                        continue
                    port = struct.unpack_from('<H', packet, 40)[0]
                    length = packet[42]
                    at = 43 + length
                    if length > 63 or at >= len(packet)-4:
                        continue
                    name = packet[43:at].decode('utf-8')
                    version_size = packet[at]
                    if at + 1 + version_size + 4 != len(packet) or not port:
                        continue
                    version = packet[at+1:at+1+version_size].decode('ascii')
                    board_uid = ''.join(f'{word:08X}' for word in struct.unpack('<III', packet[8:20]))
                    found[ip] = {'uid': board_uid, 'device_name': name, 'version': version, 'port': port}
                except (OSError, ValueError, UnicodeError, struct.error):
                    continue
        report(f'UDP发现 {len(found)} 个候选地址，开始TCP核验；UDP回复不直接计为在线设备。')
        return found
    finally:
        for sock, _ in sockets:
            sock.close()


def probe(ip, port, request, interfaces=(), known=False, confirm=False,
          cancel=None, active_sockets=None, active_lock=None):
    reachable = False
    protocol = False
    stage = 'TCP连接'
    if cancel is not None and cancel.is_set():
        return 'cancelled', (ip, stage, '已停止', False)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lock = active_lock if active_lock is not None else threading.Lock()
    if active_sockets is not None:
        with lock:
            active_sockets.add(sock)
    for attempt in range(1):
        try:
            with sock:
                if cancel is not None and cancel.is_set():
                    return 'cancelled', (ip, stage, '已停止', False)
                route = route_interface(ip, interfaces)
                if route:
                    stage = '绑定局域网网卡'
                    index, source = route
                    sock.setsockopt(socket.IPPROTO_IP, getattr(socket, 'IP_UNICAST_IF', 31), struct.pack('!I', index))
                    sock.bind((source, 0))
                sock.settimeout(1.5 if confirm else 0.8)
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                stage = 'TCP连接'
                sock.connect((ip, port))
                reachable = True
                sock.settimeout((10 if known else 6) if confirm else (6 if known else 3))
                stage = '快速发现'
                try:
                    body = request(sock, 27)
                    protocol = True
                except DeviceError:
                    protocol = True
                    stage = '兼容旧固件只读认证'
                    request(sock, 0, payload=b'')
                    sock.settimeout(12)
                    stage = '读取设备信息'
                    body = request(sock, 1)
                value = parse_device_info(body)
                if isinstance(value, dict) and str(value.get('board', '')).upper().startswith('STM32') and value.get('uid'):
                    return 'found', (ip, value)
                return 'failed', (ip, '识别设备', '响应未包含STM32型号和设备UID', protocol)
        except (OSError, ValueError, RuntimeError) as exc:
            error = str(exc) or type(exc).__name__
            return 'failed', (ip, stage, error, protocol)
        finally:
            if active_sockets is not None:
                with lock:
                    active_sockets.discard(sock)
    return 'failed', (ip, stage, '读取未完成', protocol)


def install(gui):
    cls = gui.LocalTcpApp
    original_load = cls._load_settings
    original_save = cls._save_settings
    original_home = cls._build_home_page
    original_summaries = cls._update_summaries
    original_close = cls._on_close
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
        app.device_online_ips = set()
        app.device_scan_queue = queue.Queue()
        app.device_scan_cancel = threading.Event()
        app.device_scan_sockets = set()
        app.device_scan_socket_lock = threading.Lock()
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
        app.device_label_to_ip = {label: ip for ip, label in choices}
        if hasattr(app, 'device_combo'):
            app.device_combo.configure(values=[label for _, label in choices] or ['尚未添加设备'])
            current = app.host_var.get().strip()
            app.device_combo.set(next((label for ip, label in choices if ip == current), current))
        for kind, combo in app.named_device_selectors.items():
            combo.configure(values=[label for _, label in choices] or ['尚未添加设备'])
            selected = app.w78_host_var.get().strip() if kind == 'w78' else getattr(app, 'ota_selected_ip', app.host_var.get().strip())
            combo.set(next((label for ip, label in choices if ip == selected), selected))
        if hasattr(app, 'ota_hosts_input'):
            refresh_ota_names(app)
        current = app.host_var.get().strip()
        name = app.device_names.get(current) or app.discovered_device_names.get(current, '')
        summary = (name + ' | ' + current) if current and name else (current or '未设置设备 IP')
        app.connection_summary_var.set(summary)
        if hasattr(app, 'device_current_label_var'):
            app.device_current_label_var.set(('当前选择：' + summary + (' | 已确认在线' if current in app.device_online_ips else ' | 历史记录／未确认')) if current else '输入或选择设备 IP')

        if hasattr(app, '_fixture_refresh_device_choices'):
            app._fixture_refresh_device_choices()

    def named_selector(app, parent, kind):
        row = ctk.CTkFrame(parent, fg_color='transparent')
        row.pack(fill='x', padx=18, pady=(0, 10))
        row.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(row, text='选择设备' if kind == 'w78' else '选择设备加入升级列表').grid(row=0, column=0, padx=(0, 10))
        def choose(value):
            if app.is_running:
                return
            ip = app.device_label_to_ip.get(value)
            if not ip:
                return
            if kind == 'w78':
                app.w78_host_var.set(ip)
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

    def home(app):
        original_home(app)
        card = app.pages['home'].grid_slaves(row=0, column=0)[0]
        for widget in card.grid_slaves(row=1, column=0):
            widget.destroy()
        row = ctk.CTkFrame(card, fg_color='transparent')
        row.grid(row=1, column=0, sticky='ew', padx=17, pady=(3, 10))
        row.grid_columnconfigure(0, weight=1)
        app.device_combo = ctk.CTkComboBox(row, values=['尚未添加设备'],
                                         command=app._select_named_device, height=34)
        app.device_combo._toolbox_user_data = True
        app.device_combo.grid(row=0, column=0, sticky='ew')
        app.device_scan_button = app._secondary_button(row, '刷新寻找设备', app._discover_devices, width=126)
        app.device_scan_button.grid(row=0, column=1, padx=(8, 0))
        app.device_current_label_var = tk.StringVar(master=app.root, value='输入或选择设备 IP')
        ctk.CTkLabel(row, textvariable=app.device_current_label_var, anchor='w',
                     text_color=gui.COLORS['cyan']).grid(row=1, column=0, columnspan=2,
                                                         sticky='ew', pady=(5, 0))
        app._refresh_device_choices()
        app.host_var.trace_add('write', lambda *_: app._refresh_device_choices())

    def build_page(app):
        page = app._page('devices')
        card = app._page_card(page, 0)
        card.grid_columnconfigure(0, weight=1)
        form = ctk.CTkFrame(card, fg_color='transparent')
        form.grid(row=0, column=0, sticky='ew', padx=16, pady=14)
        form.grid_columnconfigure((0, 1), weight=1)
        app.new_device_ip = tk.StringVar(master=app.root)
        app.new_device_name = tk.StringVar(master=app.root)
        ip_entry = ctk.CTkEntry(form, textvariable=app.new_device_ip, placeholder_text='设备 IP 地址', height=40, corner_radius=8, border_color=gui.COLORS['border'], fg_color=gui.COLORS['input'], text_color=gui.COLORS['text'], font=app._font(14))
        ip_entry.grid(row=0, column=0, sticky='ew', padx=(0, 8))
        name_entry = ctk.CTkEntry(form, textvariable=app.new_device_name, placeholder_text='设备名称', height=40, corner_radius=8, border_color=gui.COLORS['border'], fg_color=gui.COLORS['input'], text_color=gui.COLORS['text'], font=app._font(14))
        app.device_ip_entry = ip_entry
        app.device_name_entry = name_entry
        name_entry.grid(row=0, column=1, sticky='ew', padx=(0, 8))
        add_button = app._secondary_button(form, '添加到列表', lambda owner=app: add(owner), width=100)
        add_button.grid(row=0, column=2)
        ip_entry.bind('<Return>', lambda _event, owner=app: (add(owner), 'break')[1])
        name_entry.bind('<Return>', lambda _event, owner=app: (add(owner), 'break')[1])
        app.device_add_status_var = tk.StringVar(master=app.root, value='')
        ctk.CTkLabel(card, text='设备名称写入开发板后，可在互联设备中同步显示。', font=app._font(12),
                     text_color=gui.COLORS['muted']).grid(row=2, column=0, sticky='w', padx=16, pady=(0, 5))
        ctk.CTkLabel(card, textvariable=app.device_add_status_var, font=app._font(12),
                     text_color=gui.COLORS['blue']).grid(row=3, column=0, sticky='w', padx=16, pady=(0, 10))
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
            ctk.CTkLabel(row, text=label, width=178, anchor='w', font=app._font(14, 'bold'),
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
                          width=72, height=38, corner_radius=8, fg_color=gui.COLORS['soft'],
                          hover_color=gui.COLORS['border'], text_color=gui.COLORS['text']).grid(row=0, column=2, padx=3)
            ctk.CTkButton(row, text='发送名称', command=lambda address=ip, var=variable: app._sync_device_name(address, var.get().strip()),
                          width=96, height=38, corner_radius=8, fg_color=gui.COLORS['blue'],
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

    def discover(app):
        if app.device_scan_running or app.is_running:
            return
        try:
            port = int(app.port_var.get())
            if not 1 <= port <= 65535:
                raise ValueError()
        except ValueError:
            messagebox.showerror('端口无效', '请输入 1–65535 的 TCP 端口。', parent=app.root)
            return
        try:
            configured = configured_targets(app.device_scan_ranges)
        except ValueError as exc:
            messagebox.showerror('扫描范围无效', str(exc), parent=app.root)
            return
        app.device_scan_running = True
        app.device_scan_found = {}
        app.device_online_ips.clear()
        if hasattr(app, 'device_rows'):
            app._render_device_rows()
        app.device_scan_cancel.clear()
        app.device_scan_button.configure(state='disabled', text='正在寻找…')
        app.stop_button.configure(state='normal', fg_color=gui.COLORS['error_text'],
                                  hover_color='#991B1B', text_color='#FFFFFF')
        app._set_status('正在扫描设备…')
        app.device_scan_checked = 0
        app.device_scan_checked_ips = set()
        app.device_scan_protocol_ips = set()
        app.device_scan_phase = 1
        app.device_scan_retry_checked = 0
        app.device_scan_retry_total = 0
        app.device_scan_reachable = 0
        app.device_scan_total = 0
        app._append_log('正在当前局域网寻找开发板（只读取设备信息）…')
        current = app.host_var.get().strip()
        known = tuple(app.device_names)
        def worker():
            try:
                targets = configured or discovery_targets(current, known)
                # Probe saved/current devices first, and publish results as they finish.
                priority = set(known) | {current}
                targets.sort(key=lambda ip: (ip not in priority, ipaddress.IPv4Address(ip)))
                app.device_scan_queue.put(('range', (len(targets), targets[0] if targets else '', targets[-1] if targets else '')))
                interfaces = lan_interfaces(app.device_scan_cancel)
                app.device_scan_queue.put(('interfaces', [str(v.get('Description') or v.get('InterfaceIndex')) for v in interfaces]))
                candidates = udp_discover(targets, interfaces, app.device_scan_cancel,
                                          lambda message: app.device_scan_queue.put(('note', message)))
                if app.device_scan_cancel.is_set():
                    app.device_scan_queue.put(('cancelled', None))
                    return
                verify = set(targets)
                expected = {ip: value['uid'] for ip, value in candidates.items()}
                ports = {ip: value['port'] for ip, value in candidates.items()}
                pending = []
                confirmed_uids = {}
                def record(kind, value):
                    if kind == 'found':
                        ip, info = value
                        board_uid = str(info.get('uid') or '').upper()
                        if ip in expected and board_uid != expected[ip]:
                            return 'failed', (ip, 'UID核验', 'UDP与TCP返回的设备身份不同', True)
                        if board_uid in confirmed_uids and confirmed_uids[board_uid] != ip:
                            app.device_scan_queue.put(('note', f'同一UID在多个地址响应：保留 {confirmed_uids[board_uid]}，忽略重复地址 {ip}。'))
                            app.device_scan_queue.put(('first_failed', (ip, 'UID去重', '重复设备身份，未重复计为在线', True)))
                            return 'duplicate', value
                        confirmed_uids[board_uid] = ip
                    return kind, value
                ordered = sorted(verify, key=lambda ip: (ip not in candidates, ip not in priority, ipaddress.IPv4Address(ip)))
                app.device_scan_queue.put(('plan', len(ordered)))
                app.device_scan_queue.put(('note', '每次刷新都会核验扫描范围；UDP候选优先检查，避免漏掉未响应UDP的开发板。'))
                with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
                    futures = {executor.submit(probe, ip, ports.get(ip, port), gui.request, interfaces,
                                               ip in priority or ip in candidates,
                                               cancel=app.device_scan_cancel,
                                               active_sockets=app.device_scan_sockets,
                                               active_lock=app.device_scan_socket_lock): ip for ip in ordered}
                    for future in concurrent.futures.as_completed(futures):
                        if app.device_scan_cancel.is_set():
                            app.device_scan_queue.put(('cancelled', None))
                            return
                        result = future.result()
                        if result[0] == 'cancelled' or app.device_scan_cancel.is_set():
                            app.device_scan_queue.put(('cancelled', None))
                            return
                        kind, value = record(*result)
                        if kind == 'found':
                            app.device_scan_queue.put((kind, value))
                        elif kind == 'failed':
                            ip, stage, error, protocol = value
                            if ip in priority or ip in candidates or protocol or 'timed out' in error or '10060' in error:
                                pending.append(ip)
                            app.device_scan_queue.put(('first_failed', value))
                if pending and not app.device_scan_cancel.is_set():
                    app.device_scan_queue.put(('retrying', len(pending)))
                    if app.device_scan_cancel.wait(0.8):
                        app.device_scan_queue.put(('cancelled', None))
                        return
                    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
                        futures = {executor.submit(probe, ip, ports.get(ip, port), gui.request, interfaces,
                                                   ip in priority or ip in candidates, True,
                                                   app.device_scan_cancel, app.device_scan_sockets,
                                                   app.device_scan_socket_lock): ip for ip in pending}
                        for future in concurrent.futures.as_completed(futures):
                            if app.device_scan_cancel.is_set():
                                app.device_scan_queue.put(('cancelled', None))
                                return
                            result = future.result()
                            if result[0] == 'cancelled' or app.device_scan_cancel.is_set():
                                app.device_scan_queue.put(('cancelled', None))
                                return
                            kind, value = record(*result)
                            if kind != 'duplicate':
                                app.device_scan_queue.put((kind, value))
                            app.device_scan_queue.put(('retry_checked', None))
                app.device_scan_queue.put(('done', None))
            except Exception as exc:
                app.device_scan_queue.put(('error', str(exc)))
        threading.Thread(target=worker, daemon=True).start()
        def poll():
            while True:
                try:
                    kind, value = app.device_scan_queue.get_nowait()
                except queue.Empty:
                    break
                if kind == 'range':
                    app.device_scan_total, first, last = value
                    scope = app.device_scan_ranges.strip() or '自动识别本机、当前设备及已保存设备所在网段'
                    app._append_log(f'扫描范围：{scope}；共 {app.device_scan_total} 个地址；TCP端口 {port}。')
                elif kind == 'interfaces':
                    app._append_log('扫描出站网卡：' + ('；'.join(value) if value else '未识别物理网卡，使用系统路由'))
                elif kind == 'plan':
                    app.device_scan_total = value
                elif kind == 'note':
                    app._append_log(value)
                elif kind == 'retrying':
                    app.device_scan_phase = 2
                    app.device_scan_retry_total = value
                    app._append_log(f'首轮发现 {len(app.device_scan_found)} 台，正在自动补扫 {value} 个未识别地址；补扫完成后公布最终结果。')
                elif kind == 'retry_checked':
                    app.device_scan_retry_checked += 1
                elif kind == 'cancelled':
                    app.device_scan_running = False
                    app.device_scan_button.configure(state='normal', text='刷新寻找设备')
                    app.stop_button.configure(state='disabled', fg_color=gui.COLORS['error_bg'],
                                              hover_color='#FECACA', text_color=gui.COLORS['error_text'])
                    app.stop_button.configure(state='disabled', fg_color=gui.COLORS['error_bg'],
                                              hover_color='#FECACA', text_color=gui.COLORS['error_text'])
                    app._set_status('扫描已停止')
                    app._append_log(f'扫描已停止；已确认 {len(app.device_scan_found)} 台开发板。')
                    if hasattr(app, 'device_add_status_var'):
                        app.device_add_status_var.set('扫描已停止；已确认设备保留在列表中。')
                    continue
                elif kind == 'first_failed':
                    ip, stage, error, protocol = value
                    app.device_scan_checked_ips.add(ip)
                    app.device_scan_checked = len(app.device_scan_checked_ips)
                    if protocol:
                        app.device_scan_protocol_ips.add(ip)
                    if ip == current or ip in known:
                        app._append_log(f'[{ip}] 首轮未识别，稍后自动补扫：{stage}：{error}')
                elif kind == 'found':
                    ip, info = value
                    app.device_scan_checked_ips.add(ip)
                    app.device_scan_checked = len(app.device_scan_checked_ips)
                    app.device_scan_protocol_ips.add(ip)
                    app.device_scan_reachable = len(app.device_scan_protocol_ips)
                    app.device_scan_found[ip] = info
                    app.discovered_devices.add(ip)
                    accept_info(app, ip, info)
                    if hasattr(app, 'device_rows'):
                        app._render_device_rows()
                    name = str(info.get('device_name') or '').strip() or '未命名'
                    app._append_log(f'发现开发板：{name} | {ip}；已同步到名称配置和总览。')
                elif kind == 'failed':
                    ip, stage, error, reachable = value
                    app.device_scan_checked_ips.add(ip)
                    app.device_scan_checked = len(app.device_scan_checked_ips)
                    if reachable:
                        app.device_scan_protocol_ips.add(ip)
                    app.device_scan_reachable = len(app.device_scan_protocol_ips)
                    if ip == current or ip in known:
                        app._append_log(f'[{ip}] 扫描未识别：{stage}：{error}')
                else:
                    app.device_scan_running = False
                    app.device_scan_button.configure(state='normal', text='刷新寻找设备')
                    app.discovered_devices = set(app.device_scan_found)
                    app._save_settings()
                    app._refresh_device_choices()
                    if hasattr(app, 'device_rows'):
                        app._render_device_rows()
                    count = len(app.device_scan_found)
                    history = len(set(app.device_names) - set(app.device_scan_found))
                    message = (f'扫描完成（含自动补扫）：检查 {app.device_scan_checked}/{app.device_scan_total} 个地址，协议已识别 {app.device_scan_reachable} 个，确认在线 {count} 台，历史记录未确认 {history} 台。'
                               if kind == 'done' else '搜索失败：' + str(value))
                    if kind == 'done' and not count:
                        message += ' 未发现开发板，请核对扫描范围、开发板IP、端口及网络可达性。'
                    app._append_log(message)
                    app._set_status(f'发现 {count} 台开发板' if count else '未发现开发板')
                    if hasattr(app, 'device_add_status_var'):
                        app.device_add_status_var.set(message)
                if app.device_scan_running:
                    progress = (f'补扫 {app.device_scan_retry_checked}/{app.device_scan_retry_total}' if app.device_scan_phase == 2 else f'扫描 {app.device_scan_checked}/{app.device_scan_total}')
                    app.device_scan_button.configure(text=progress)
            if app.device_scan_running:
                app.root.after(100, poll)
        app.root.after(100, poll)

    def cancel_discovery(app):
        app.device_scan_cancel.set()
        with app.device_scan_socket_lock:
            sockets = list(app.device_scan_sockets)
        for sock in sockets:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                sock.close()
            except OSError:
                pass

    def accept_info(app, ip, info):
        if 'device_name' not in info:
            return
        uid = str(info.get('uid') or '').strip()
        name = truncate_name(info.get('device_name') or '')
        if uid:
            for previous, old_uid in list(app.device_uids.items()):
                if previous != ip and old_uid == uid:
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
