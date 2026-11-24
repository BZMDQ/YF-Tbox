"""无线烧录页中的 D133 经 F750 USB 更新表单及任务回调。"""
from pathlib import Path
from tkinter import filedialog, messagebox

import d133_proxy_client as proxy
import wireless_batch


SYSTEM_STAGES = ('01  接收', '02  写入', '03  校验')
PROFILE_STAGES = ('01  连接', '02  登记', '03  核对')


def initialize(app, gui):
    app.d133_proxy_running = app.d133_proxy_committed = app.d133_proxy_hardware = False
    app.d133_proxy_percent_var = gui.tk.StringVar(master=app.root, value='0%')
    app.d133_proxy_path = app.d133_proxy_signature = None
    app.d133_proxy_file_var = gui.tk.StringVar(master=app.root, value='未选择文件')
    app.d133_proxy_detail_var = gui.tk.StringVar(master=app.root, value='系统 OTA / 屏幕配置包')
    app.d133_proxy_status_var = gui.tk.StringVar(master=app.root, value='等待开始')


def build_card(app, gui, page, row):
    card = app._page_card(page, row, pady=(0, 8))
    target = app._wireless_target_row(card)
    gui.ctk.CTkLabel(target, text='D133', font=app._font(11, 'bold'),
                     text_color=gui.COLORS['text']).pack(side='left')
    app.d133_proxy_host_entry = app._wireless_device_row(card, 'd133_usb', app.d133_proxy_host_var)
    app._wireless_file_card(card, app.d133_proxy_file_var, app.d133_proxy_detail_var)
    app.wireless_d133_actions = app._rail_card('w78', '任务操作')
    app._rail_button(app.wireless_d133_actions, '选择文件', lambda: choose_package(app))
    app.d133_proxy_start = app._rail_button(
        app.wireless_d133_actions, '开始更新', lambda: start_update(app), primary=True)
    app.d133_proxy_progress, app.d133_proxy_stage_labels = app._wireless_task_progress(
        card, app.d133_proxy_percent_var, app.d133_proxy_status_var, SYSTEM_STAGES)
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
        hardware = isinstance(package, proxy.HardwarePackage)
        d133_render_package(app, hardware)
        if hardware:
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
        app.d133_proxy_detail_var.set('系统 OTA / 屏幕配置包')
        app.d133_proxy_status_var.set('等待开始')
        d133_render_package(app, False)
        messagebox.showerror('D133升级包无效', str(exc), parent=app.root)


def d133_render_package(app, hardware):
    app.d133_proxy_start.configure(text='登记配置' if hardware else '开始更新')
    for label, caption in zip(app.d133_proxy_stage_labels, PROFILE_STAGES if hardware else SYSTEM_STAGES):
        label.configure(text=caption)
    app._paint_wireless_stages(app.d133_proxy_stage_labels, -1)
    app.d133_proxy_progress.set(0)
    app.d133_proxy_percent_var.set('0%')


def stop_operation(app):
    """由上传任务按当前事务状态处理停止请求。"""
    app.stop_event.set()
    app.stop_button.configure(state='disabled')
    if getattr(app, 'd133_proxy_hardware', False):
        text = ('登记请求已发出，仅停止电脑等待。' if app.d133_proxy_committed else '正在取消登记。')
    else:
        text = ('提交请求已发出；仅停止电脑等待，不能撤销D133更新，健康状态尚未确认。' if app.d133_proxy_committed else
                '正在取消未提交事务。')
    app.d133_proxy_status_var.set(text)
    app._append_log(text)
    app._set_status('D133停止请求已记录')


def handle_event(app, kind, value):
    if kind == 'd133_proxy_progress':
        percent, text = value
        app.d133_proxy_progress.set(percent / 100)
        app.d133_proxy_percent_var.set(f'{percent:.0f}%')
        if app.d133_proxy_hardware:
            stage = 2 if percent >= 70 else 1 if percent else 0
        else:
            stage = 2 if percent >= 100 else 1 if percent else 0
        app._paint_wireless_stages(app.d133_proxy_stage_labels, stage)
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
        targets, key = wireless_batch.inputs(app, 'd133')
        if len(key) != 32:
            raise ValueError('请在设置中导入当前F750的配套32字节Local TCP Key')
        if app.d133_proxy_path is None:
            raise ValueError('请选择 D133 OTA 或独立配置包。')
        package = proxy.load_usb_file(app.d133_proxy_path, app.d133_proxy_signature)
    except (OSError, ValueError) as exc:
        messagebox.showerror('无法经F750更新D133', str(exc), parent=app.root)
        return
    hardware = isinstance(package, proxy.HardwarePackage)
    target_text = wireless_batch.confirmation_targets(targets) + '\n'
    if hardware:
        text = target_text + (f'{package.code} · {package.resolution}\n{package.panel} · {package.touch}\n\n'
                              '登记后继续使用当前屏幕。可在 F750 的 USB 控制中切换。')
    else:
        text = target_text + (f'D133 目标版本 {package.version}\n{app.d133_proxy_path.name}\n'
                              f'{app.d133_proxy_signature.name}\n\n更新非活动系统槽，请保持供电和 USB 连接。')
    if not messagebox.askyesno('确认 D133 USB 更新', text, parent=app.root):
        return
    app.d133_proxy_hardware = hardware
    d133_render_package(app, hardware)

    def program(target):
        def progress(percent, message):
            # 最后一块数据的确认仍在写入阶段，提交之后才显示校验阶段。
            verifying = percent >= 70 if hardware else target.committed
            stage = 2 if verifying else int(percent > 0)
            target.progress(percent, message, stage)

        try:
            if hardware:
                message = proxy.install_hardware(target.args, target.key, package, progress,
                                                 target.cancel, target.mark_committed)
            else:
                version = proxy.upload_package(target.args, target.key, package, progress,
                                               target.cancel, target.mark_committed)
                message = f'D133 {version} 更新完成，新版本、目标槽及健康确认已核对。'
        except proxy.HardwareConfigRejected:
            target.reject_commit()
            raise
        except Exception as exc:
            if target.committed:
                # 已提交的目标只结束本机核对，保持每台的真实事务结果。
                return 'pending', str(exc)
            raise
        target.log(message)
        return message

    title = 'D133 屏幕配置登记' if hardware else 'D133经F750 USB A/B更新'
    wireless_batch.start(app, 'd133', title, targets, key, program)
