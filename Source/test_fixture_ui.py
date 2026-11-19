"""Test-fixture UI parameters. No physical outputs or simulated measurements."""
from decimal import Decimal, DecimalException
import struct
import tkinter as tk
from tkinter import messagebox
import customtkinter as ctk
from local_tcp_client import request, DeviceError

PARAMETERS = [('VDD', 'V'), ('VLED', 'V'), ('ILED', 'mA'), ('AVDD', 'V'),
              ('VCOM', 'V'), ('VGH', 'V'), ('VGL', 'V')]
MEASUREMENTS = [('VDD', 'V'), ('IDD', 'mA'), ('VLED', 'V'), ('ILED', 'mA'),
                ('AVDD', 'V'), ('IAVDD', 'mA'), ('VCOM', 'V'), ('IVCOM', 'mA'),
                ('VGH', 'V'), ('IVGH', 'mA'), ('VGL', 'V'), ('IVGL', 'mA'),
                ('VOP', 'V'), ('VEE', 'V')]
MAX_VALUE = 999999999


def value_text(value):
    return str(Decimal(value) / Decimal(1000))


def scaled(value, label, empty=False):
    if empty and not str(value).strip():
        return 0
    try:
        number = Decimal(str(value).strip()) * 1000
        if not number.is_finite() or number < 0 or number > MAX_VALUE or number != number.to_integral_value():
            raise ValueError()
        return int(number)
    except (DecimalException, ValueError):
        raise ValueError(label + '请输入非负数，最多三位小数。') from None


def encode_config(rows, generation):
    payload = bytearray(struct.pack('<2I', 1, generation))
    for (name, _unit), row in zip(PARAMETERS, rows):
        value = scaled(row['value'], name + ' 设定值：')
        low = scaled(row['minimum'], name + ' 最小值：', True)
        high = scaled(row['maximum'], name + ' 最大值：', True)
        step = scaled(row['step'], name + ' 步进：')
        enabled = int(bool(row['range_enabled']))
        if not step:
            raise ValueError(name + ' 步进必须大于 0。')
        if enabled and (high <= low or not low <= value <= high):
            raise ValueError(name + ' 量程无效或设定值超出量程。')
        payload.extend(struct.pack('<5I', value, low, high, step, enabled))
    if len(payload) != 148:
        raise ValueError('测试用具参数数量不正确。')
    return bytes(payload)


def decode_state(data):
    if len(data) != 220:
        raise ValueError('设备的测试用具数据格式不匹配，请升级到固件 1.3.6。')
    header = struct.unpack_from('<6I', data)
    if header[0] != 1:
        raise ValueError('不支持的测试用具接口版本。')
    return dict(generation=header[1], source=header[2], hardware_ready=header[3],
                valid_mask=header[4], updated_ms=header[5],
                parameters=[struct.unpack_from('<5I', data, 24 + i * 20) for i in range(7)],
                measurements=struct.unpack_from('<14i', data, 164))


def install(gui):
    cls = gui.LocalTcpApp

    def refresh_devices(app):
        if not hasattr(app, 'fixture_device_combo'):
            return
        choices = app.device_label_to_ip
        app.fixture_device_combo.configure(values=list(choices) or ['请先在总览添加设备'])
        host = app.fixture_host_var.get().strip()
        app.fixture_device_combo.set(next((label for label, ip in choices.items() if ip == host), host))

    def build(app):
        page = app._page('fixture')
        page.grid_columnconfigure(0, weight=1)
        card = app._page_card(page, 0)
        card.grid_columnconfigure(0, weight=1)
        app.fixture_host_var = tk.StringVar(master=app.root, value=app.host_var.get())
        app.fixture_generation = None
        app.fixture_state_host = None
        app.fixture_status_var = tk.StringVar(master=app.root, value='硬件未接入 | 当前仅配置和同步界面参数')
        app.fixture_source_var = tk.StringVar(master=app.root, value='参数尚未读取；量程和步进可自定义')
        ctk.CTkLabel(card, textvariable=app.fixture_status_var, fg_color=gui.COLORS['info_bg'],
                     text_color=gui.COLORS['blue'], corner_radius=8, anchor='w', height=34).grid(
                         row=0, column=0, sticky='ew', padx=16, pady=(12, 8))
        connect = ctk.CTkFrame(card, fg_color='transparent')
        connect.grid(row=1, column=0, sticky='ew', padx=16, pady=(0, 8))
        connect.grid_columnconfigure(0, weight=1)

        def select(value):
            ip = app.device_label_to_ip.get(value)
            if ip:
                app.fixture_host_var.set(ip)
                app.fixture_generation = None
                app.fixture_status_var.set('已选择设备，请读取参数 | 硬件未接入')

        app.fixture_device_combo = app._register_action(ctk.CTkComboBox(
            connect, values=['请先在总览添加设备'], command=select, state='readonly', height=34))
        app.fixture_device_combo._toolbox_user_data = True
        app.fixture_device_combo.grid(row=0, column=0, sticky='ew', padx=(0, 8))
        entry = app._register_action(ctk.CTkEntry(connect, textvariable=app.fixture_host_var, width=160, height=34))
        entry._toolbox_user_data = True
        entry.grid(row=0, column=1, padx=(0, 8))
        app._secondary_button(connect, '读取参数/测量', app._fixture_read, width=136).grid(row=0, column=2)
        tabs = ctk.CTkTabview(card, height=352, fg_color=gui.COLORS['soft'])
        tabs.grid(row=2, column=0, sticky='ew', padx=16, pady=(0, 8))
        settings = tabs.add('参数设定')
        measurements = tabs.add('实际测量')
        for column in range(1, 5):
            settings.grid_columnconfigure(column, weight=1)
        for column, label in enumerate(['通道 / 单位', '设定值', '最小值', '最大值', '步进', '限制量程']):
            ctk.CTkLabel(settings, text=label, text_color=gui.COLORS['muted']).grid(row=0, column=column, padx=5)
        app.fixture_fields = []
        for index, (name, unit) in enumerate(PARAMETERS):
            ctk.CTkLabel(settings, text=f'{name} ({unit})', anchor='w', width=94).grid(row=index + 1, column=0, sticky='w', padx=5, pady=3)
            fields = {key: tk.StringVar(master=app.root, value=default) for key, default in (
                ('value', '0'), ('minimum', '0'), ('maximum', ''), ('step', '1' if name == 'ILED' else '0.1'))}
            fields['range_enabled'] = tk.BooleanVar(master=app.root, value=False)
            for column, key in enumerate(['value', 'minimum', 'maximum', 'step'], 1):
                entry = app._register_action(ctk.CTkEntry(settings, textvariable=fields[key], width=100, height=30))
                entry._toolbox_user_data = True
                entry.grid(row=index + 1, column=column, sticky='ew', padx=4, pady=3)
            app._register_action(ctk.CTkCheckBox(settings, text='', variable=fields['range_enabled'], width=38)).grid(
                row=index + 1, column=5, padx=10)
            app.fixture_fields.append(fields)
        ctk.CTkLabel(settings, text='开启量程后按最小/最大值限制；当前使用非负设定值。', text_color=gui.COLORS['muted']).grid(
            row=8, column=0, columnspan=6, sticky='w', padx=5, pady=(8, 0))
        measurements.grid_columnconfigure((0, 1), weight=1)
        app.fixture_measure_vars = []
        for index, (name, unit) in enumerate(MEASUREMENTS):
            row = ctk.CTkFrame(measurements, fg_color=gui.COLORS['card'], corner_radius=7)
            row.grid(row=index % 7, column=index // 7, sticky='ew', padx=5, pady=3)
            row.grid_columnconfigure(1, weight=1)
            ctk.CTkLabel(row, text=name, width=90, anchor='w').grid(row=0, column=0, padx=10)
            value = tk.StringVar(master=app.root, value=f'— {unit}')
            app.fixture_measure_vars.append(value)
            ctk.CTkLabel(row, textvariable=value, anchor='e', text_color=gui.COLORS['blue']).grid(row=0, column=1, sticky='ew', padx=10)
        ctk.CTkLabel(card, textvariable=app.fixture_source_var, anchor='w', text_color=gui.COLORS['muted']).grid(
            row=3, column=0, sticky='ew', padx=16, pady=(0, 4))
        actions = ctk.CTkFrame(card, fg_color='transparent')
        actions.grid(row=4, column=0, sticky='ew', padx=16, pady=(0, 12))
        ctk.CTkLabel(actions, text='参数暂存于开发板；重启后复位。输出与测量接口尚未接入。',
                     text_color=gui.COLORS['muted']).pack(side='left')
        app._primary_button(actions, '发送界面参数', app._fixture_send, width=150).pack(side='right')
        refresh_devices(app)

    def accept(app, value):
        host, state = value
        if host != app.fixture_host_var.get().strip():
            return
        app.fixture_generation = state['generation']
        app.fixture_state_host = host
        for variables, values in zip(app.fixture_fields, state['parameters']):
            for key, value in zip(['value', 'minimum', 'maximum', 'step'], values[:4]):
                variables[key].set(value_text(value))
            variables['range_enabled'].set(bool(values[4]))
        for index, ((name, unit), value) in enumerate(zip(MEASUREMENTS, state['measurements'])):
            valid = bool(state['hardware_ready'] and state['valid_mask'] & (1 << index))
            app.fixture_measure_vars[index].set(f'{value_text(value)} {unit}' if valid else f'— {unit}')
        app.fixture_status_var.set('参数已同步 | 硬件未接入' if not state['hardware_ready'] else '参数与测量状态已读取')
        source = {0: '初始参数', 1: '开发板', 2: '工具箱'}.get(state['source'], '其它端')
        app.fixture_source_var.set(f'参数版本 {state["generation"]} | 最近修改：{source}')

    def exchange(app, payload=None):
        host = app.fixture_host_var.get().strip()
        def action(args, key, stop_event):
            with app._connection(args, key, stop_event) as sock:
                sock.settimeout(10)
                if stop_event.is_set():
                    raise InterruptedError()
                try:
                    body = request(sock, 28 if payload is None else 29,
                                   payload=b'' if payload is None else payload, on_info=app._on_device_info)
                except DeviceError as exc:
                    if payload is not None and exc.status == 3:
                        raise ValueError('参数已被另一端修改，请重新读取后再发送。') from exc
                    raise ValueError('设备暂不支持测试用具界面参数，请升级完整固件 1.3.6。') from exc
                state = decode_state(body)
                app._post('fixture_state', (args.host, state))
                app._post('log', f'[{args.host}] 测试用具参数已' + ('读取' if payload is None else '发送并读回') + '；硬件未接入。')
                app._post('status', '测试用具参数已同步')
        app._start_task('读取测试用具参数' if payload is None else '发送测试用具界面参数', action, host_override=host)

    def read(app):
        exchange(app)

    def send(app):
        if app.fixture_generation is None or app.fixture_state_host != app.fixture_host_var.get().strip():
            messagebox.showinfo('请先读取', '请先读取所选设备的当前参数，再编辑并发送。', parent=app.root)
            return
        try:
            rows = [{key: var.get() for key, var in fields.items()} for fields in app.fixture_fields]
            payload = encode_config(rows, app.fixture_generation)
        except ValueError as exc:
            messagebox.showerror('参数无效', str(exc), parent=app.root)
            return
        exchange(app, payload)

    cls._build_test_fixture_page = build
    cls._fixture_accept = accept
    cls._fixture_read = read
    cls._fixture_send = send
    cls._fixture_refresh_device_choices = refresh_devices
