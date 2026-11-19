"""独立F750 BOOT入口；暂存完成后才在主线程展示具体提交确认。"""
from pathlib import Path
import threading
from tkinter import filedialog, messagebox

import boot_update_client as boot
from local_tcp_client import DeviceError, parse_device_info, request


def is_f750(app):
    selector = getattr(app, 'ota_board_var', None)
    return selector is None or selector.get() == 'STM32F750'


def connection_inputs(app):
    if not is_f750(app):
        raise ValueError('D133模式禁止内部BOOT更新；仅STM32F750支持此入口。')
    args, key = app._connection_inputs()
    if len(key) != 32:
        raise ValueError('内部BOOT更新必须导入配套32字节Local TCP Key，不支持空Key或板端免Key确认。')
    return args, key


def refresh_controls(app):
    enabled = is_f750(app) and not getattr(app, 'is_running', False)
    for name in ('boot_browse_button', 'boot_start_button', 'boot_entry_button'):
        widget = getattr(app, name, None)
        if widget is not None:
            widget.configure(state='normal' if enabled else 'disabled')
    button = getattr(app, 'nav_buttons', {}).get('boot')
    if button is not None:
        button.configure(state='normal' if is_f750(app) else 'disabled')
    if not is_f750(app) and hasattr(app, 'boot_status_var'):
        app.boot_status_var.set('D133模式不支持内部BOOT更新；不会发送BOOT协议。')


def build_page(app, gui):
    page = app._page('boot')
    page.grid_columnconfigure(0, weight=1)
    card = app._page_card(page, 0)
    gui.ctk.CTkLabel(card, text='STM32F750 · 单份内部 BOOT', font=app._font(18, 'bold'),
                     text_color=gui.COLORS['text']).pack(anchor='w', padx=18, pady=(16, 8))
    gui.ctk.CTkLabel(card, text='先通过系统 OTA 安装 1.4.43 或更新版本，之后才支持此入口。仅更新当前一台设备，必须使用配套 Key。',
                     wraplength=760, justify='left', text_color=gui.COLORS['muted']).pack(fill='x', padx=18, pady=(0, 12))
    target = gui.ctk.CTkFrame(card, fg_color='transparent')
    target.pack(fill='x', padx=18, pady=(0, 12))
    gui.ctk.CTkLabel(target, text='当前设备 IP').pack(side='left', padx=(0, 10))
    app._new_entry(target, app.host_var, width=230).pack(side='left')
    gui.ctk.CTkLabel(target, text='TCP端口').pack(side='left', padx=(18, 8))
    app._new_entry(target, app.port_var, width=85).pack(side='left')
    gui.ctk.CTkLabel(card, textvariable=app.boot_file_var, anchor='w', wraplength=760,
                     font=app._font(12, 'bold')).pack(fill='x', padx=18, pady=(0, 5))
    gui.ctk.CTkLabel(card, textvariable=app.boot_detail_var, anchor='w', justify='left',
                     wraplength=760, text_color=gui.COLORS['cyan']).pack(fill='x', padx=18, pady=(0, 12))
    row = gui.ctk.CTkFrame(card, fg_color='transparent')
    row.pack(fill='x', padx=18, pady=(0, 14))
    app.boot_browse_button = app._secondary_button(row, '选择 BOOT HEX / boot.bin…', app._choose_boot_image, width=255)
    app.boot_browse_button.pack(side='left')
    app.boot_start_button = app._primary_button(row, '核验并暂存镜像…', app._start_boot_update, width=210, accent='orange')
    app.boot_start_button.pack(side='right')
    gui.ctk.CTkLabel(card, text='⚠ 原址更新 0x08000000..0x0800FFFF，只有一份 BOOT，没有回滚副本。\n开始擦除后断电可能无法启动，需要 ST-LINK 恢复。请保持稳定供电。',
                     wraplength=760, justify='left', text_color=gui.COLORS['error_text'],
                     font=app._font(12, 'bold')).pack(fill='x', padx=18, pady=(0, 14))
    app.boot_progress = gui.ctk.CTkProgressBar(card, progress_color=gui.COLORS['orange'])
    app.boot_progress.pack(fill='x', padx=18, pady=(0, 10)); app.boot_progress.set(0)
    gui.ctk.CTkLabel(card, textvariable=app.boot_status_var, wraplength=760, justify='left',
                     anchor='w').pack(fill='x', padx=18, pady=(0, 18))
    refresh_controls(app)


def choose_image(app):
    if not is_f750(app):
        messagebox.showerror('平台不支持', 'D133模式禁止内部BOOT更新。', parent=app.root)
        return
    path = filedialog.askopenfilename(parent=app.root, title='选择仅内部64KiB的BOOT镜像',
                                     filetypes=[('内部BOOT HEX或BOOT包', '*.hex *.bin')])
    if not path:
        return
    try:
        package = boot.load_package(path)
        app.boot_image_path = Path(path)
        app.boot_package = package
        app.boot_file_var.set(app.boot_image_path.name)
        app.boot_detail_var.set(f'版本 {package.version} | 64KiB | CRC32 {package.image_crc32:08X}\n'
                                '头/镜像CRC、向量、板型、内部版本及地址范围均已在本地检查。')
        app.boot_status_var.set('尚未写设备；点击核验并暂存，完整镜像READY后再确认原址提交。')
    except (OSError, ValueError) as exc:
        app.boot_package = app.boot_image_path = None
        app.boot_file_var.set('未选择有效BOOT镜像')
        app.boot_detail_var.set(str(exc))
        messagebox.showerror('BOOT镜像无效', str(exc), parent=app.root)


def confirmation_text(args, package, capability, info):
    return (f'设备：{info.get("device_name") or "未命名"} | {args.host}:{args.port}\n'
            f'板型：{info.get("board")}\nUID：{info.get("uid")}\n'
            f'系统：{info.get("version", "未知")}\n'
            f'当前 BOOT：{capability.version} | CRC32 {capability.image_crc32:08X}\n'
            f'目标 BOOT：{package.version} | CRC32 {package.image_crc32:08X}\n'
            f'完整更新包 {boot.PACKAGE_SIZE} 字节（镜像65536字节）已暂存，板端校验状态为 READY。\n\n'
            '确认后将原址替换内部 0x08000000..0x0800FFFF。只有单份BOOT，没有A/B或回滚。\n'
            '断电可能无法启动，需使用 ST-LINK 恢复；请确认供电稳定。\n'
            '同一镜像由设备逐字节核对后跳过擦写和重启。现在开始提交？')


def handle_event(app, kind, value):
    if kind == 'boot_status':
        app.boot_status_var.set(value)
        if app.boot_commit_started:
            app.stop_button.configure(text='仅停止电脑等待')
    elif kind == 'boot_progress':
        current, total, text = value
        app.boot_progress.set(current / max(1, total)); app.boot_status_var.set(text)
    elif kind == 'boot_confirm':
        text, ready, answer, stop = value
        try:
            answer['yes'] = not stop.is_set() and messagebox.askyesno(
                '确认单份内部BOOT原址更新', text, parent=app.root)
        finally:
            ready.set()
    elif kind == 'boot_finished':
        app.boot_update_running = app.boot_commit_started = False
        app.stop_button.configure(text='■  停止当前操作')
        refresh_controls(app)


def stop_operation(app):
    """不与DATA响应交错发取消；当前ACK结束后由同一工作线程发送CANCEL。"""
    app.stop_event.set()
    app.stop_button.configure(state='disabled')
    message = ('只停止电脑端等待，板端擦写不能取消；请保持供电，稍后重新核对BOOT状态。'
               if app.boot_commit_started else '正在停止暂存；等待当前响应后取消RAM暂存，不擦写内部BOOT。')
    app._append_log(message);app.boot_status_var.set(message);app._set_status('BOOT停止请求已记录')


def start_update(app):
    if app.is_running:
        return
    try:
        args, key = connection_inputs(app)
        if not app.boot_image_path:
            raise ValueError('请先选择内部BOOT HEX或boot.bin')
        # 开始前重新读文件，防止用户选择后文件被替换。
        package = boot.load_package(app.boot_image_path)
    except (OSError, ValueError) as exc:
        messagebox.showerror('不能更新内部BOOT', str(exc), parent=app.root)
        return
    app.boot_package = package
    app.boot_update_running = True
    app.boot_commit_started = False

    def action(_args, _key, stop):
        retained_recovery = False
        try:
            with app._connection(args, key, stop) as sock:
                sock.settimeout(8)
                capability = boot.get_capability(sock)
                info = parse_device_info(request(sock, 1))
                uid = boot.target_identity(info)
                app._post('log', f'BOOT目标：{info.get("board")} | {args.host} | UID {uid}；当前{capability.version}/{capability.image_crc32:08X}')
                try:
                    boot.stage_package(sock, package, capability, cancel=stop,
                        on_progress=lambda received, total: app._post('boot_progress',
                            (received, total, f'RAM暂存 {received}/{total}；尚未擦写内部BOOT')))
                    ready, answer = threading.Event(), {'yes': False}
                    app._post('boot_confirm', (confirmation_text(args, package, capability, info), ready, answer, stop))
                    while not ready.wait(0.1):
                        boot._check_cancel(stop)
                    if stop.is_set() or not answer['yes']:
                        canceled = boot.cancel_staging(sock)
                        text = ('已取消RAM暂存，未提交BOOT擦写。' if canceled else
                                '设备保留了不能取消的恢复镜像。' + boot.RECOVERY_WARNING)
                        app._post('boot_status', text); app._post('log', text)
                        return
                    app.boot_commit_started = True
                    app._post('boot_status', '开始提交；擦写后不能取消，请保持供电。')
                    app._post('log', '单份BOOT提交只发送一次；此后仅STATUS/CAP只读监测。')
                    try:
                        boot.commit_once(sock)
                    except (OSError, ValueError) as exc:
                        app._post('log', f'COMMIT应答未确认（{exc}），不重发提交；关闭此流后只读核验。')
                except InterruptedError:
                    if not app.boot_commit_started:
                        try: retained_recovery = not boot.cancel_staging(sock)
                        except Exception: pass
                    raise

            last = [None]
            def status(value):
                state = (value.state, value.error, value.written)
                labels = {0: '重启后核验', 3: '提交已排队', 4: '内部Flash擦写中', 5: '读回通过，等待Reset', 8: '同镜像，跳过擦写/重启'}
                text = labels.get(value.state, '读取BOOT状态')
                app._post('boot_progress', (value.written, boot.IMAGE_SIZE, text))
                if state != last[0]:
                    app._post('log', f'BOOT状态：{text} | error={value.error} written={value.written}')
                    last[0] = state
            result = boot.monitor_update(lambda: app._connection(args, key, stop, update_status=False),
                                         package, uid, cancel=stop, on_status=status)
            text = ('同镜像UNCHANGED，未擦写、未重启；版本与完整CRC核对通过。' if result == 'unchanged'
                    else f'BOOT {package.version} 已Reset重连，UID、版本和完整64KiB CRC均核对通过。')
            app._post('boot_progress', (1, 1, text));app._post('log', text);app._post('status', 'BOOT核验完成')
        except InterruptedError:
            text = (boot.RECOVERY_WARNING if retained_recovery else
                    '电脑端等待已停止；板端更新可能仍在进行，请保持供电后重新核对。' if app.boot_commit_started
                    else 'BOOT暂存已停止，没有发送COMMIT。')
            app._post('boot_status', text);app._post('log', text)
            raise
        except Exception as exc:
            text = str(exc)
            if app.boot_commit_started and not isinstance(exc, (DeviceError, boot.BootUpdateFailed)):
                text += '\n' + boot.RECOVERY_WARNING
            app._post('boot_status', text);app._post('log', text)
            raise
        finally:
            app._post('boot_finished')
    app._start_task('内部BOOT核验与单份更新', action, require_connection=False)
    if not app.is_running:
        app.boot_update_running = app.boot_commit_started = False
        refresh_controls(app)
