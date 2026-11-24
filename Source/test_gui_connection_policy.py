"""只读连接恢复与旧 App 包入口的定向验证，不接触开发板。"""
from contextlib import ExitStack, contextmanager
from types import SimpleNamespace
import queue
import threading
import unittest
from unittest.mock import AsyncMock, Mock, patch

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

    def scan_app(self):
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
        app.device_startup_scan_started = False
        app.device_scan_queue = queue.PriorityQueue()
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
        return app, counts, scheduled, button_updates

    def test_scan_delivers_found_devices_before_failure_backlog_and_saves_once(self):
        app, counts, scheduled, _ = self.scan_app()
        pending = []

        async def scan(_targets, _routes, _port, _priority, _startup, _cancel, publish, **_):
            # 让确认结果排在大量超时之后到达，检查两个连续界面帧均能立即显示。
            for _ in range(device_directory._SCAN_UI_BATCH * 2):
                publish('first_failed', ('192.168.1.1', 'TCP', '', False))
            for index in (2, 3):
                ip = f'192.168.1.{index}'
                publish('found', (ip, {'device_name': f'设备{index}', 'uid': str(index)}))
                scheduled.pop(0)[1]()
                self.assertIn(ip, app.device_online_ips)
                self.assertEqual(counts['refresh'], index - 1)
                self.assertEqual(counts['save'], 0)
                self.assertTrue(app.device_scan_running)

        with patch.object(device_directory, 'lan_interfaces', return_value=[]), \
                patch.object(device_directory, 'scan_network', side_effect=scan), \
                patch.object(device_directory.threading, 'Thread',
                             side_effect=lambda target, **_: SimpleNamespace(start=lambda: pending.append(target))), \
                patch.object(device_directory.time, 'perf_counter', return_value=0):
            app._discover_devices()
            self.assertEqual(scheduled[0][0], device_directory._SCAN_UI_INTERVAL_MS)
            pending.pop(0)()
            while scheduled:
                scheduled.pop(0)[1]()
        self.assertEqual(counts, dict(save=1, refresh=3, render=1))
        self.assertFalse(app.device_scan_running)
        self.assertTrue(app.device_scan_queue.empty())

    def test_startup_scan_runs_once_with_2048_distinct_addresses_in_saved_range(self):
        app, _, scheduled, _ = self.scan_app()
        app.device_scan_ranges = '10.0.0.1-10.0.11.254'
        app.host_var = SimpleNamespace(get=lambda: '10.0.10.99')
        scan = AsyncMock()
        with patch.object(device_directory, 'lan_interfaces', return_value=[]), \
                patch.object(device_directory, 'scan_network', scan), \
                patch.object(device_directory.threading, 'Thread',
                             side_effect=lambda target, **_: SimpleNamespace(start=target)):
            app._discover_devices(startup=True)
            scheduled.pop(0)[1]()
            app._discover_devices(startup=True)
        scan.assert_awaited_once()
        targets, _, _, _, startup = scan.await_args.args[:5]
        self.assertTrue(startup)
        self.assertEqual(len(targets), 2048)
        self.assertEqual(len(set(targets)), 2048)
        self.assertEqual(targets[0], '10.0.10.99')
        self.assertFalse(app.device_scan_running)


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


class OtaConnectionPolicy(unittest.TestCase):
    def test_two_devices_use_distinct_sending_locks(self):
        app = gui.LocalTcpApp.__new__(gui.LocalTcpApp)
        app.socket_lock = threading.Lock()
        app.active_ota_sessions = {}
        app._post = app._close_socket = lambda *_: None
        stop = threading.Event()
        addresses = ('192.0.2.10', '192.0.2.11')

        # 两台设备同时停留在 OTA 会话中，布局与启动必须共用各自连接的发送锁。
        with patch.object(gui, 'connect', side_effect=(object(), object())), \
                patch.object(gui, 'check_ota_layout') as check_layout, \
                patch.object(gui, 'request') as request, ExitStack() as sessions:
            for address in addresses:
                args = SimpleNamespace(host=address, port=5000)
                sessions.enter_context(app._ota_batch_session(
                    args, b'key', stop, address, 32768, b'0' * 32, None, 1))
            self.assertEqual(set(app.active_ota_sessions), set(addresses))

        locks = [call.kwargs['send_lock'] for call in request.call_args_list]
        self.assertIsNot(locks[0], locks[1])
        self.assertEqual(locks, [call.kwargs['send_lock'] for call in check_layout.call_args_list])
        self.assertEqual(app.active_ota_sessions, {})

    def test_stop_sends_cancel_on_upload_socket_only(self):
        app = gui.LocalTcpApp.__new__(gui.LocalTcpApp)
        app.socket_lock = threading.Lock()
        app.is_running = app.ota_batch_running = True
        app.d133_proxy_running = app.boot_update_running = False
        app.stop_event = threading.Event()
        app.task_thread = SimpleNamespace(is_alive=lambda: True)
        app.stop_button = SimpleNamespace(configure=lambda **_: None)
        app._set_status = app._append_log = lambda *_: None
        app._cancel_socket_async = Mock()
        uploading = gui.OtaTargetSession(object())
        committing = gui.OtaTargetSession(object())
        committing.committing = True
        app.active_ota_sessions = {'192.0.2.10': uploading, '192.0.2.11': committing}

        app._stop_operation()

        self.assertTrue(app.stop_event.is_set())
        self.assertEqual([call.args[:3] for call in app._cancel_socket_async.call_args_list], [
            (uploading.sock, gui.frame(5), uploading.send_lock),
            (committing.sock, None, committing.send_lock),
        ])


if __name__ == '__main__':
    unittest.main()
