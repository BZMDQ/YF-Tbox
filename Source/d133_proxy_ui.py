"""无线烧录页中的 D133 经 F750 USB 更新表单及任务回调。"""
from pathlib import Path
from tkinter import filedialog, messagebox

import d133_proxy_client as proxy


def initialize(app, gui):
    app.d133_proxy_running = app.d133_proxy_committed = False
    app.d133_proxy_path = app.d133_proxy_signature = None
    app.d133_proxy_file_var = gui.tk.StringVar(master=app.root, value='未选择D133 ota.cpio及同名.sig')
    app.d133_proxy_detail_var = gui.tk.StringVar(master=app.root, value='电脑TCP → 当前F750 → USB → 同一D133的非活动系统槽')
    app.d133_proxy_status_var = gui.tk.StringVar(master=app.root, value='先安装F750 1.4.49和D133 1.0.169或更新固件，再连接USB。D133 1.0.170起支持免屏幕确认。')


def build_card(app, gui, page, row):
    card = app._page_card(page, row)
    gui.ctk.CTkLabel(card, text='D133 · 经F750 USB更新A/B系统槽', font=app._font(18, 'bold'),
                     anchor='w', wraplength=680).pack(fill='x', padx=18, pady=(16, 8))
    gui.ctk.CTkLabel(card, text='使用当前F750的IP、TCP端口及配套Key认证。CPIO由F750经USB转交D133。D133 1.0.170起在电脑端确认即可，旧固件仍需在D133屏幕确认。',
                     anchor='w', justify='left', wraplength=680,
                     text_color=gui.COLORS['muted']).pack(fill='x', padx=18, pady=(0, 12))
    target = gui.ctk.CTkFrame(card, fg_color='transparent')
    target.pack(fill='x', padx=18, pady=(0, 12))
    target.grid_columnconfigure(1, weight=1)
    gui.ctk.CTkLabel(target, text='当前F750 IP').grid(row=0, column=0, sticky='w', padx=(0, 10))
    app._new_entry(target, app.host_var, width=210).grid(row=0, column=1, sticky='ew')
    gui.ctk.CTkLabel(target, text='TCP端口').grid(row=1, column=0, sticky='w', padx=(0, 10), pady=(8, 0))
    app._new_entry(target, app.port_var, width=90).grid(row=1, column=1, sticky='w', pady=(8, 0))
    gui.ctk.CTkLabel(card, textvariable=app.d133_proxy_file_var, anchor='w', justify='left',
                     wraplength=680, font=app._font(12, 'bold')).pack(fill='x', padx=18, pady=(0, 6))
    gui.ctk.CTkLabel(card, textvariable=app.d133_proxy_detail_var, anchor='w', justify='left',
                     wraplength=680, text_color=gui.COLORS['cyan']).pack(fill='x', padx=18, pady=(0, 12))
    # 两行按钮适应最小窗口，避免中文按钮及签名说明发生遮挡。
    app._secondary_button(card, '选择D133 CPIO及同名.sig…', lambda: choose_package(app), width=270).pack(anchor='w', padx=18, pady=(0, 10))
    app._primary_button(card, '经F750 USB更新D133…', lambda: start_update(app), width=270).pack(anchor='w', padx=18, pady=(0, 14))
    gui.ctk.CTkLabel(card, text='块大小与窗口由设备自动协商。三端支持且 F750 使用被动接收时，每块 128 KiB、窗口 2。旧设备仍可协商 64、32 或 4 KiB，进度区显示实际模式。D133校验签名并更新非活动槽。\n提交后停止按钮只停止电脑等待。请保持F750与D133供电及USB连接。',
                     wraplength=680, anchor='w', justify='left',
                     text_color=gui.COLORS['warning_text']).pack(fill='x', padx=18, pady=(0, 14))
    app.d133_proxy_progress = gui.ctk.CTkProgressBar(card)
    app.d133_proxy_progress.pack(fill='x', padx=18, pady=(0, 10))
    app.d133_proxy_progress.set(0)
    gui.ctk.CTkLabel(card, textvariable=app.d133_proxy_status_var, anchor='w', justify='left',
                     wraplength=680).pack(fill='x', padx=18, pady=(0, 18))
    return card


def choose_package(app):
    path = filedialog.askopenfilename(parent=app.root, title='选择D133 CPIO（同目录应有同名.cpio.sig）',
                                     filetypes=[('D133 ArtInChip CPIO', '*.cpio')])
    if not path:
        return
    try:
        package = proxy.load_package(path)
        app.d133_proxy_path = Path(path).resolve()
        app.d133_proxy_signature = Path(str(app.d133_proxy_path) + '.sig')
        app.d133_proxy_file_var.set(f'{app.d133_proxy_path}\n签名：{app.d133_proxy_signature.name}')
        app.d133_proxy_detail_var.set(f'D133 {package.version} | {len(package.data):,} 字节 | CPIO预检通过；RSA由D133验证')
        app.d133_proxy_status_var.set('已选择CPIO及同名签名；尚未发送到设备。')
    except (OSError, ValueError) as exc:
        app.d133_proxy_path = app.d133_proxy_signature = None
        app.d133_proxy_file_var.set('未选择有效CPIO及同名签名')
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
        args, key = app._connection_inputs()
        if len(key) != 32:
            raise ValueError('请在设置中导入当前F750的配套32字节Local TCP Key')
        if app.d133_proxy_path is None:
            raise ValueError('请先选择D133 ota.cpio及同名.sig')
        package = proxy.load_package(app.d133_proxy_path, app.d133_proxy_signature)
    except (OSError, ValueError) as exc:
        messagebox.showerror('无法经F750更新D133', str(exc), parent=app.root)
        return
    text = (f'F750转发设备：{args.host}:{args.port}\nD133目标版本：{package.version}\n'
            f'包：{app.d133_proxy_path.name}\n签名：{app.d133_proxy_signature.name}\n\n'
            'D133 1.0.170起使用电脑端确认。旧固件请按进度提示在D133屏幕确认。\n'
            'D133校验签名并更新非活动系统槽；请保持USB连接及稳定供电。开始？')
    if not messagebox.askyesno('确认D133经F750 USB A/B更新', text, parent=app.root):
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
            version = proxy.upload(args, key, path, progress, stop, committed, signature)
            message = f'D133 {version}更新完成；新版本、预定非活动槽与健康确认均已核对。'
            progress(100, message)
            app._post('log', message)
            app._post('status', 'D133重启与健康核对完成')
        except Exception as exc:
            # 此动作自己保留“已提交/未知”结论，避免通用任务框架把它改写为“已取消”。
            message = str(exc)
            if app.d133_proxy_committed:
                message += '\n提交请求已发出；不能撤销，未确认新系统健康。'
            progress(100 if app.d133_proxy_committed else 0, message)
            app._post('log', 'D133经F750 USB：' + message)
            app._post('status', 'D133已提交，健康待核对' if app.d133_proxy_committed else 'D133更新未完成')
        finally:
            app._post('d133_proxy_finished')
    app._start_task('D133经F750 USB A/B更新', action, require_connection=False)
    if not app.is_running:
        app.d133_proxy_running = False
