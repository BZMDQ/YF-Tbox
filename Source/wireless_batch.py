"""无线烧录的设备清单、并发任务与逐台结果。"""
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock, Thread
from tkinter import messagebox
from types import SimpleNamespace

import customtkinter as ctk
from device_directory import normalize_ipv4


MAX_WORKERS = 4
LABELS = {'queued': '排队中', 'running': '进行中', 'success': '完成',
          'failed': '失败', 'stopped': '已停止', 'pending': '待确认'}
COLORS = {'success': '#15803D', 'failed': '#B91C1C', 'pending': '#92400E'}


class Target:
    def __init__(self, args, key, cancel, notify, log):
        self.args, self.key, self.cancel = args, key, cancel
        self.host = args.host
        self.send_lock = Lock()
        self._socket_lock = Lock()
        self._socket = None
        self._notify, self._log = notify, log
        self.committed = False
        self.percent = 0
        self.stage = 0

    def progress(self, percent, detail, stage=0):
        self.percent = max(0, min(100, percent))
        self.stage = stage
        self._notify(self.host, 'running', self.percent, detail, stage)

    def log(self, text):
        self._log(f'[{self.host}] {text}')

    def mark_committed(self):
        self.committed = True

    def reject_commit(self):
        self.committed = False

    def attach_socket(self, sock):
        with self._socket_lock:
            if self.cancel.is_set():
                raise InterruptedError()
            self._socket = sock

    def detach_socket(self):
        with self._socket_lock:
            self._socket = None

    def stop_hex(self, cancel_frame, close_socket):
        # 与启动命令使用同一把锁，防止停止指令先于烧录启动发送。
        def interrupt():
            with self._socket_lock:
                sock = self._socket
            if sock is None:
                return
            acquired = self.send_lock.acquire(timeout=0.25)
            try:
                if acquired and self.committed:
                    sock.settimeout(0.5)
                    sock.sendall(cancel_frame)
            except OSError:
                pass
            finally:
                if acquired:
                    self.send_lock.release()
                close_socket(sock)

        Thread(target=interrupt, name=f'HEX-stop-{self.host}', daemon=True).start()


def run(target_args, key, cancel, program, notify, *, max_workers=MAX_WORKERS,
        log=None, register=None):
    """每台设备各自连接、验收和报告结果，失败不会中断其余设备。"""
    log = log or (lambda _message: None)

    def worker(args):
        target = Target(args, key, cancel, notify, log)
        if register:
            register(target)
        if cancel.is_set():
            notify(args.host, 'stopped', 0, '尚未开始', 0)
            return 'stopped'
        target.progress(0, '正在连接')
        try:
            result = program(target)
            state, message = result if isinstance(result, tuple) else ('success', result)
        except Exception as exc:
            if target.committed:
                state = 'pending'
                message = str(exc).strip() or '已停止电脑端等待'
                message += '；已发出设备操作请求，最终状态待核对。'
            elif cancel.is_set() or isinstance(exc, InterruptedError):
                state, message = 'stopped', '已停止'
            else:
                state, message = 'failed', str(exc).strip() or type(exc).__name__
        finally:
            target.detach_socket()
        if state != 'success':
            target.log(f'{LABELS[state]}：{message}')
        notify(args.host, state, 100 if state == 'success' else target.percent, message, target.stage)
        return state

    with ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix='wireless-target') as executor:
        futures = {executor.submit(worker, args): args.host for args in target_args}
        return {futures[future]: future.result() for future in as_completed(futures)}


def inputs(app, kind):
    # 显式清单生效后，只烧录清单内设备。空清单允许直接输入单台地址。
    panel = getattr(app, 'wireless_targets', {}).get(kind)
    if panel and panel.hosts:
        hosts = list(panel.hosts)
    else:
        field = app.w78_host_var if kind == 'hex' else app.d133_proxy_host_var
        try:
            hosts = [normalize_ipv4(field.get())]
        except ValueError as exc:
            raise ValueError('请选择设备或输入有效的 IPv4 地址。') from exc
    known_uids = getattr(app, 'device_uids', {})
    seen = {}
    for host in hosts:
        uid = known_uids.get(host)
        if uid:
            if uid in seen:
                raise ValueError(f'{seen[uid]} 和 {host} 属于同一台 F750，请移除重复地址。')
            seen[uid] = host
    args, key = app._connection_inputs(host_override=hosts[0])
    return [SimpleNamespace(host=host, port=args.port) for host in hosts], key


def confirmation_targets(targets):
    hosts = '、'.join(target.host for target in targets)
    if len(targets) == 1:
        return f'F750 {targets[0].host}:{targets[0].port}'
    return f'{len(targets)} 台 F750\n{hosts}'


class TargetPanel:
    def __init__(self, app, kind, card, anchor, field, colors):
        self.app, self.kind, self.field, self.colors = app, kind, field, colors
        self.hosts, self.rows, self.results = [], {}, {}
        self.anchor = anchor
        self.frame = ctk.CTkScrollableFrame(card, height=110, fg_color=colors['soft'],
                                            label_text='烧录设备', label_font=app._font(11, 'bold'))
        self.add_button = app._register_action(ctk.CTkButton(
            anchor, text='添加设备', width=86, height=32, command=self.add,
            fg_color=colors['soft'], text_color=colors['text'],
            hover_color=colors['border'],
        ))
        self.add_button.pack(side='left', padx=(8, 0))

    def add(self):
        if self.app.is_running:
            return
        try:
            host = normalize_ipv4(self.field.get())
        except ValueError:
            messagebox.showerror('无法添加设备', '请选择设备或输入有效的 IPv4 地址。', parent=self.app.root)
            return
        if host not in self.hosts:
            self.hosts.append(host)
            self.show(self.hosts)

    def remove(self, host):
        if not self.app.is_running:
            self.hosts.remove(host)
            self.show(self.hosts)

    def show(self, hosts):
        self.results.clear()
        for widget in self.frame.winfo_children():
            widget.destroy()
        self.rows.clear()
        if not hosts:
            self.frame.pack_forget()
            return
        self.frame.pack(after=self.anchor, fill='x', padx=18, pady=(0, 9))
        for host in hosts:
            line = ctk.CTkFrame(self.frame, fg_color='transparent')
            line.pack(fill='x', pady=(0, 3))
            line.grid_columnconfigure(0, weight=1)
            ctk.CTkLabel(line, text=self.app._device_display_label(host),
                         font=self.app._font(11, 'bold'), anchor='w').grid(row=0, column=0, sticky='ew', padx=6)
            status = ctk.CTkLabel(line, text='', font=self.app._font(10), anchor='e')
            status.grid(row=0, column=1, sticky='e', padx=5)
            remove = ctk.CTkButton(line, text='移除', width=54, height=24,
                                   fg_color='transparent', text_color=self.colors['muted'],
                                   hover_color=self.colors['border'],
                                   command=lambda ip=host: self.remove(ip))
            remove.grid(row=0, column=2, padx=6)
            detail = ctk.CTkLabel(line, text='', font=self.app._font(10), anchor='w',
                                  justify='left', wraplength=425, text_color=self.colors['muted'])
            detail.grid(row=1, column=0, columnspan=3, sticky='ew', padx=6)
            detail.grid_remove()
            self.rows[host] = status, detail, remove

    def update(self, host, state, percent, detail, stage):
        if self.kind == 'hex' and state != 'success':
            # HEX 三个阶段各有独立计数，合并后批量总进度保持单调。
            start, weight = ((0, 30), (30, 40), (70, 30))[stage]
            percent = start + percent * weight / 100 if state in ('running', 'pending', 'failed') else 0
        if state != 'success':
            percent = min(percent, 99)
        percent = max(percent, self.results.get(host, 0))
        self.results[host] = percent
        if host in self.rows:
            badge, label, _remove = self.rows[host]
            badge.configure(text=f'{LABELS[state]} {percent:.0f}%',
                            text_color=COLORS.get(state, self.colors['text']))
            label.configure(text=detail)
            if detail:
                label.grid()

    def enable(self, enabled):
        for _badge, _detail, remove in self.rows.values():
            remove.configure(state='normal' if enabled else 'disabled')


def build_picker(app, kind, card, row, field, colors):
    if not hasattr(app, 'wireless_targets'):
        app.wireless_targets = {}
    app.wireless_targets[kind] = TargetPanel(app, kind, card, row, field, colors)


def start(app, kind, title, targets, key, program, *, prepare=None):
    if app.is_running:
        return
    job = SimpleNamespace(kind=kind, active=[], lock=Lock(), targets=targets, states={})
    app.wireless_batch_job = job
    panel = getattr(app, 'wireless_targets', {}).get(kind)
    if panel:
        panel.show(panel.hosts)
    for args in targets:
        handle_event(app, (job, args.host, 'queued', 0, '', 0))

    def register(target):
        with job.lock:
            job.active.append(target)

    def action(_args, _key, cancel):
        task = program
        if prepare is not None:
            try:
                task = prepare()
            except (OSError, ValueError) as exc:
                reason = str(exc)
                def task(_target):
                    raise ValueError(reason)
        results = run(
            targets, key, cancel, task,
            lambda *event: app._post('wireless_target', (job,) + event),
            log=lambda line: app._post('log', line), register=register,
        )
        counts = Counter(results.values())
        summary = ' · '.join(f'{LABELS[state]} {counts[state]}' for state in
                             ('success', 'failed', 'stopped', 'pending') if counts[state])
        if len(targets) > 1:
            app._post('status', summary)
            app._post('log', f'{title}：{summary}')
        return summary

    app.connection_summary_var.set(
        f'{targets[0].host}:{targets[0].port}' if len(targets) == 1 else f'{len(targets)} 台设备')
    app._start_task(title, action, require_connection=False)
    if not app.is_running:
        app.wireless_batch_job = None


def handle_event(app, event):
    job, host, state, percent, detail, stage = event
    if job is not getattr(app, 'wireless_batch_job', None):
        return
    panel = getattr(app, 'wireless_targets', {}).get(job.kind)
    if panel:
        panel.update(host, state, percent, detail, stage)
    job.states[host] = 2 if state == 'success' else stage
    if len(job.targets) > 1 and panel:
        percent = sum(panel.results.values()) / len(job.targets)
        detail = f'{len(job.targets)} 台设备'
        stage = min(job.states.values())
    elif detail:
        app._set_status(LABELS[state] if state != 'running' else '无线烧录进行中')
        if state != 'success':
            percent = min(percent, 99)
    if job.kind == 'hex':
        bar, label, display, stages = (app.w78_progress, app.w78_progress_text_var,
                                       app.w78_percent_var, app.w78_stage_labels)
    else:
        bar, label, display, stages = (app.d133_proxy_progress, app.d133_proxy_status_var,
                                       app.d133_proxy_percent_var, app.d133_proxy_stage_labels)
    bar.set(percent / 100)
    label.set(detail)
    display.set(f'{percent:.0f}%')
    app._paint_wireless_stages(stages, 2 if state == 'success' and len(job.targets) == 1 else stage)


def stop(app, cancel_frame):
    job = getattr(app, 'wireless_batch_job', None)
    if job is None:
        return False
    app.stop_event.set()
    # D133 会话由自己的协议处理停止，需要保留已提交设备的验收状态。
    if job.kind == 'hex':
        with job.lock:
            active = list(job.active)
        for target in active:
            target.stop_hex(cancel_frame, app._close_socket)
    return True
