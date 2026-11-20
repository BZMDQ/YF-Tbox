"""只读连接恢复与旧 App 包入口的定向验证，不接触开发板。"""
from contextlib import contextmanager
from types import SimpleNamespace
import queue
import threading
import unittest
from unittest.mock import patch

import device_directory
import local_tcp_gui as gui


class ImmediateStop:
    """验证重连退避可取消，不实际等待倒计时。"""
    def __init__(self):
        self.stopped = False
        self.delays = []

    def is_set(self):
        return self.stopped

    def wait(self, delay):
        self.delays.append(delay)
        self.stopped = True
        return True


class EventPumpPerformance(unittest.TestCase):
    def test_task_event_budget_preserves_fifo_and_reschedules(self):
        app = gui.LocalTcpApp.__new__(gui.LocalTcpApp)
        seen, scheduled = [], []
        app.events = queue.Queue()
        app.close_pending = False
        app.root = SimpleNamespace(winfo_exists=lambda: True,
                                   after=lambda ms, cb: scheduled.append(cb))
        app._append_log = seen.append
        count = gui.UI_EVENT_BATCH_LIMIT + 3
        for index in range(count):
            app.events.put(('log', index))
        with patch.object(gui.time, 'perf_counter', return_value=0):
            app._poll_events()
            self.assertEqual(len(seen), gui.UI_EVENT_BATCH_LIMIT)
            scheduled.pop(0)()
        self.assertEqual(seen, list(range(count)))

    def test_scan_batches_progress_and_saves_found_devices_once(self):
        class ScanApp(gui.LocalTcpApp):
            pass

        device_directory.install(SimpleNamespace(LocalTcpApp=ScanApp, COLORS=gui.COLORS))
        app = ScanApp.__new__(ScanApp)
        counts = dict(save=0, refresh=0, render=0)
        scheduled, button_updates = [], []

        def tick(key):
            counts[key] += 1

        app.root = SimpleNamespace(after=lambda ms, cb: scheduled.append((ms, cb)))
        app.port_var = SimpleNamespace(get=lambda: '5000')
        app.host_var = SimpleNamespace(get=lambda: '192.168.1.100')
        app.device_scan_button = SimpleNamespace(configure=lambda **kw: button_updates.append(kw))
        app.stop_button = SimpleNamespace(configure=lambda **_: None)
        app.device_scan_ranges = '192.168.1.1-192.168.1.10'
        app.device_scan_running = app.is_running = False
        app.device_scan_queue = queue.Queue()
        app.device_scan_cancel = threading.Event()
        app.device_online_ips = set()
        app.discovered_devices = set()
        app.device_names, app.device_name_dirty = {}, {}
        app.discovered_device_names, app.device_uids = {}, {}
        app.device_rows = object()
        app._save_settings = lambda: tick('save')
        app._refresh_device_choices = lambda: tick('refresh')
        app._render_device_rows = lambda: tick('render')
        app._history_start = lambda *_: 'scan'
        app._history_finish = app._set_status = app._append_log = lambda *_: None

        # 只注入扫描结果，避免启动网络探测或打开真实窗口。
        with patch.object(device_directory.threading, 'Thread',
                          return_value=SimpleNamespace(start=lambda: None)):
            app._discover_devices()
        counts['render'] = 0
        button_updates.clear()
        for _ in range(device_directory._SCAN_UI_BATCH):
            app.device_scan_queue.put(('first_failed', ('192.168.1.1', 'TCP', '', False)))
        for index in (2, 3, 4):
            ip = f'192.168.1.{index}'
            app.device_scan_queue.put(('found', (ip, {'device_name': f'设备{index}', 'uid': str(index)})))
        app.device_scan_queue.put(('done', None))
        scheduled.pop(0)[1]()
        self.assertEqual(len(button_updates), 1)
        self.assertEqual(scheduled[0][0], 10)
        self.assertEqual(counts, dict(save=0, refresh=0, render=0))
        scheduled.pop(0)[1]()
        self.assertEqual(counts, dict(save=1, refresh=1, render=1))
        self.assertEqual(len(app.device_online_ips), 3)
        self.assertFalse(app.device_scan_running)
        self.assertTrue(app.device_scan_queue.empty())


class GuiConnectionPolicy(unittest.TestCase):
    def listener(self, connection):
        app = gui.LocalTcpApp.__new__(gui.LocalTcpApp)
        app._connection = connection
        app.posts = []
        app._post = lambda *event: app.posts.append(event)
        app._on_device_info = lambda body: app.posts.append(('info', body))
        app._start_task = lambda title, action: setattr(app, 'action', action)
        app._listen()
        return app

    def test_old_app_packages_rejected_before_reading_file(self):
        app = gui.LocalTcpApp.__new__(gui.LocalTcpApp)
        for suffix in ('.fapp', '.fappb'):
            with self.subTest(suffix=suffix):
                with self.assertRaisesRegex(ValueError, '系统 OTA'):
                    app._set_package('missing-old-package' + suffix)
        self.assertFalse(hasattr(gui.LocalTcpApp, '_upload_app'))

    def test_monitor_recovers_transport_without_replaying_writes(self):
        stop = threading.Event()
        sockets = []

        @contextmanager
        def connection(*_):
            sock = SimpleNamespace(settimeout=lambda _: None)
            sockets.append(sock)
            yield sock

        app = self.listener(connection)
        commands = []

        def request(sock, op, **_):
            commands.append(op)
            if len(sockets) == 2:
                stop.set()
            return b'{"version":"test"}'

        # 用立即返回的可取消等待替代真实退避，避免测试耗时。
        with patch.object(gui, 'request', side_effect=request), \
                patch.object(gui, 'receive', side_effect=ConnectionResetError('reset')), \
                patch.object(stop, 'wait', return_value=False):
            with self.assertRaises(InterruptedError):
                app.action(None, b'', stop)
        self.assertEqual(len(sockets), 2)
        self.assertEqual(commands, [1, 1])

    def test_auth_rejection_and_bad_frames_do_not_retry(self):
        for error in (gui.DeviceError(13), ValueError('CRC错误')):
            attempts = []

            @contextmanager
            def connection(*_):
                attempts.append(1)
                raise error
                yield

            app = self.listener(connection)
            with self.subTest(error=type(error).__name__):
                with self.assertRaises(type(error)):
                    app.action(None, b'', threading.Event())
                self.assertEqual(len(attempts), 1)

    def test_stop_during_reconnect_does_not_create_another_connection(self):
        attempts = []

        @contextmanager
        def connection(*_):
            attempts.append(1)
            raise ConnectionResetError('reset')
            yield

        stop = ImmediateStop()
        app = self.listener(connection)
        with self.assertRaises(InterruptedError):
            app.action(None, b'', stop)
        self.assertEqual(len(attempts), 1)
        self.assertEqual(stop.delays, [0.5])

    def test_cancelled_connect_clears_registered_socket(self):
        app = gui.LocalTcpApp.__new__(gui.LocalTcpApp)
        app.socket_lock = threading.Lock()
        app.active_socket = app.connecting_socket = None
        app._post = lambda *_: None
        app._on_device_info = lambda *_: None
        app._close_socket = lambda *_: None
        stop = threading.Event()

        def connect(*_, **kwargs):
            kwargs['on_socket'](object())
            stop.set()
            raise InterruptedError()

        with patch.object(gui, 'connect', side_effect=connect):
            with self.assertRaises(InterruptedError):
                with app._connection(SimpleNamespace(host='127.0.0.1', port=5000), b'', stop):
                    self.fail('取消后仍进入业务阶段')
        self.assertIsNone(app.active_socket)
        self.assertIsNone(app.connecting_socket)


if __name__ == '__main__':
    unittest.main()
