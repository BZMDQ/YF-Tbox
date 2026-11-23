"""无线烧录页中的 D133 经 F750 USB 更新表单及任务回调。"""
from pathlib import Path
from tkinter import filedialog, messagebox

import d133_proxy_client as proxy
from device_directory import normalize_ipv4


def initialize(app, gui):
    app.d133_proxy_running = app.d133_proxy_committed = False
    app.d133_proxy_path = app.d133_proxy_signature = None
    app.d133_proxy_file_var = gui.tk.StringVar(master=app.root, value='未选择文件')
    app.d133_proxy_detail_var = gui.tk.StringVar(master=app.root, value='系统 OTA / 屏幕配置包')
    app.d133_proxy_status_var = gui.tk.StringVar(master=app.root, value='等待开始')


def build_card(app, gui, page, row):
    card = app._page_card(page, row)
    gui.ctk.CTkLabel(card, text='D133 USB 更新', font=app._font(18, 'bold'),
                     anchor='w', wraplength=410).pack(fill='x', padx=18, pady=(16, 8))
    app._build_named_selector(card, 'd133_usb')
    target = gui.ctk.CTkFrame(card, fg_color='transparent')
    target.pack(fill='x', padx=18, pady=(0, 12))
    target.grid_columnconfigure(1, weight=1)
    gui.ctk.CTkLabel(target, text='F750 IP').grid(row=0, column=0, sticky='w', padx=(0, 10))
    app._new_entry(target, app.d133_proxy_host_var, width=210).grid(row=0, column=1, sticky='ew')
    gui.ctk.CTkLabel(target, text='TCP端口').grid(row=1, column=0, sticky='w', padx=(0, 10), pady=(8, 0))
    app._new_entry(target, app.port_var, width=90).grid(row=1, column=1, sticky='w', pady=(8, 0))
    gui.ctk.CTkLabel(card, textvariable=app.d133_proxy_file_var, anchor='w', justify='left',
                     wraplength=410, font=app._font(12, 'bold')).pack(fill='x', padx=18, pady=(0, 6))
    gui.ctk.CTkLabel(card, textvariable=app.d133_proxy_detail_var, anchor='w', justify='left',
                     wraplength=410, text_color=gui.COLORS['cyan']).pack(fill='x', padx=18, pady=(0, 12))
    app.wireless_d133_actions = app._rail_card('w78', '更新操作')
    app._rail_button(app.wireless_d133_actions, '选择文件', lambda: choose_package(app))
    app._rail_button(app.wireless_d133_actions, '开始更新', lambda: start_update(app), primary=True)
    app.d133_proxy_progress = gui.ctk.CTkProgressBar(card, height=8, progress_color=gui.COLORS['teal'])
    app.d133_proxy_progress.pack(fill='x', padx=18, pady=(0, 10))
    app.d133_proxy_progress.set(0)
    gui.ctk.CTkLabel(card, textvariable=app.d133_proxy_status_var, anchor='w', justify='left',
                     wraplength=410).pack(fill='x', padx=18, pady=(0, 18))
    return card


def choose_package(app):
    path = filedialog.askopenfilename(parent=app.root, title='选择 D133 更新文件',
                                     filetypes=[('D133 更新文件', ('*.cpio', '*.d133cfg')),
                                                ('D133 系统 OTA', '*.cpio'),
                                                ('屏幕配置包', '*.d133cfg')])
    if not path:
        return
    try:
        package = proxy.load_usb_file(path)
        app.d133_proxy_path = Path(path).resolve()
        app.d133_proxy_file_var.set(app.d133_proxy_path.name)
        if isinstance(package, proxy.HardwarePackage):
            app.d133_proxy_signature = None
            app.d133_proxy_detail_var.set(
                f'{package.code} | {package.resolution} | {package.panel} | {package.touch}')
        else:
            app.d133_proxy_signature = Path(str(app.d133_proxy_path) + '.sig')
            app.d133_proxy_detail_var.set(f'D133 {package.version} | {len(package.data):,} 字节 | CPIO 预检通过')
        app.d133_proxy_status_var.set('已就绪')
    except (OSError, ValueError) as exc:
        app.d133_proxy_path = app.d133_proxy_signature = None
        app.d133_proxy_file_var.set('未选择有效文件')
        messagebox.showerror('D133升级包无效', str(exc), parent=app.root)


def stop_operation(app):
    """由上传任务按当前事务状态处理停止请求。"""
    app.stop_event.set()
    app.stop_button.configure(state='disabled')
    text = ('提交请求已发出；仅停止电脑等待，不能撤销D133更新，健康状态尚未确认。' if app.d133_proxy_committed else
            '正在取消未提交事务。')
    app.d133_proxy_status_var.set(text)
    app._append_log(text)
    app._set_status('D133停止请求已记录')


def handle_event(app, kind, value):
    if kind == 'd133_proxy_progress':
        percent, text = value
        app.d133_proxy_progress.set(percent / 100)
        app.d133_proxy_status_var.set(text)
    elif kind == 'd133_proxy_commit':
        app.stop_button.configure(text='仅停止电脑等待')
    elif kind == 'd133_proxy_finished':
        app.d133_proxy_running = False
        app.stop_button.configure(text='■  停止当前操作')


def start_update(app):
    if app.is_running:
        return
    try:
        args, key = app._connection_inputs(host_override=normalize_ipv4(app.d133_proxy_host_var.get().strip()))
        if len(key) != 32:
            raise ValueError('请在设置中导入当前F750的配套32字节Local TCP Key')
        if app.d133_proxy_path is None:
            raise ValueError('请选择 D133 OTA 或独立配置包。')
        package = proxy.load_usb_file(app.d133_proxy_path, app.d133_proxy_signature)
    except (OSError, ValueError) as exc:
        messagebox.showerror('无法经F750更新D133', str(exc), parent=app.root)
        return
    hardware = isinstance(package, proxy.HardwarePackage)
    target = f'F750 {args.host}:{args.port}\n'
    if hardware:
        text = target + (f'{package.code} · {package.resolution}\n{package.panel} · {package.touch}\n\n'
                         '安装屏幕配置后 D133 将重启。')
    else:
        text = target + (f'D133 目标版本 {package.version}\n{app.d133_proxy_path.name}\n'
                         f'{app.d133_proxy_signature.name}\n\n更新非活动系统槽，请保持供电和 USB 连接。')
    if not messagebox.askyesno('确认 D133 USB 更新', text, parent=app.root):
        return
    app.d133_proxy_running = True
    app.d133_proxy_committed = False
    app.d133_proxy_progress.set(0)
    path, signature = app.d133_proxy_path, app.d133_proxy_signature

    def action(_args, _key, stop):
        def progress(percent, message):
            app._post('d133_proxy_progress', (percent, message))

        def committed():
            app.d133_proxy_committed = True
            app._post('d133_proxy_commit')

        try:
            if hardware:
                message = proxy.install_hardware(args, key, package, progress, stop, committed)
            else:
                version = proxy.upload(args, key, path, progress, stop, committed, signature)
                message = f'D133 {version}更新完成；新版本、预定非活动槽与健康确认均已核对。'
            progress(100, message)
            app._post('log', message)
            app._post('status', message if hardware else 'D133重启与健康核对完成')
        except Exception as exc:
            # 此动作自己保留“已提交/未知”结论，避免通用任务框架把它改写为“已取消”。
            message = str(exc)
            if isinstance(exc, proxy.HardwareConfigRejected):
                app.d133_proxy_committed = False
            if app.d133_proxy_committed and not hardware:
                message += '\n提交请求已发出；不能撤销，未确认新系统健康。'
            progress(100 if app.d133_proxy_committed else 0, message)
            app._post('log', 'D133经F750 USB：' + message)
            app._post('status', 'D133 配置状态待核对' if hardware and app.d133_proxy_committed else
                      'D133已提交，健康待核对' if app.d133_proxy_committed else 'D133更新未完成')
        finally:
            app._post('d133_proxy_finished')
    app._start_task('D133 屏幕配置' if hardware else 'D133经F750 USB A/B更新',
                    action, require_connection=False)
    if not app.is_running:
        app.d133_proxy_running = False
