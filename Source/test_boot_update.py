"""单份BOOT打包/协议/最终确认行为测试；仅临时文件、mock与127.0.0.1。"""
from contextlib import contextmanager
from pathlib import Path
import hashlib
import select
import socket
import struct
import subprocess
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import zlib

import boot_update_client as boot
import boot_update_ui as ui
import local_tcp_client as tcp


def image():
    value = bytearray(b'\xff' * boot.IMAGE_SIZE)
    struct.pack_into('<II', value, 0, 0x20001000, boot.BASE + 0x101)
    value[0x100:0x102] = b'\x00\xbf'
    value[boot.VERSION_OFFSET:boot.VERSION_OFFSET + 7] = b'1.0.16\0'
    return bytes(value)


def record(kind, address, data=b''):
    raw = bytes([len(data), address >> 8, address & 255, kind]) + data
    return ':' + (raw + bytes([-sum(raw) & 255])).hex().upper() + '\n'


def hex_text():
    value = image()
    return (record(4, 0, b'\x08\x00') + record(0, 0, value[:8]) +
            record(0, 0x100, value[0x100:0x102]) +
            record(0, boot.VERSION_OFFSET, b'1.0.16\0') + record(1, 0))


def capability(package, raw_version=None, crc=None):
    return boot.CAP.pack(b'BOT1', 1, boot.PACKAGE_SIZE, 16384, 7,
                         raw_version if raw_version is not None else package.version.encode().ljust(20, b'\0'),
                         package.image_crc32 if crc is None else crc)


class Loopback:
    def __init__(self, handler):
        self.handler = handler
        self.errors = []
        self.listener = socket.socket()
        self.listener.bind(('127.0.0.1', 0)); self.listener.listen(1); self.listener.settimeout(2)

    def __enter__(self):
        def worker():
            try:
                with self.listener.accept()[0] as connection:
                    connection.settimeout(2); self.handler(connection)
            except Exception as exc: self.errors.append(exc)
            finally: self.listener.close()
        self.thread = threading.Thread(target=worker, daemon=True); self.thread.start()
        self.socket = socket.create_connection(self.listener.getsockname(), timeout=2)
        return self.socket

    def __exit__(self, *_):
        self.socket.close(); self.thread.join(3)
        if self.thread.is_alive(): raise AssertionError('回环服务未退出')
        if self.errors: raise self.errors[0]


def read_frame(sock):
    header = tcp.exact(sock, 20)
    magic, op, offset, size, crc = tcp.HEADER.unpack(header)
    if magic != b'LNET' or size > 16384: raise AssertionError('客户端帧头越界')
    body = tcp.exact(sock, size)
    if zlib.crc32(body, zlib.crc32(header[:16])) & 0xffffffff != crc: raise AssertionError('客户端帧CRC错误')
    return op, offset, body


def reply(sock, op, body=b'', error=0):
    sock.sendall(tcp.frame(op | 0x80000000, error, body))


class PackageTests(unittest.TestCase):
    def setUp(self):
        folder = Path(__file__).parent / '.test_boot_artifacts'
        folder.mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=folder)
        self.folder = Path(self.temp.name)

    def tearDown(self): self.temp.cleanup()

    def test_hex_holes_fill_ff_package_and_cli_roundtrip(self):
        source, output = self.folder / 'Boot.hex', self.folder / 'Internal.boot.bin'
        source.write_text(hex_text(), encoding='ascii')
        self.assertEqual(boot.image_from_hex(source), image())
        subprocess.run([sys.executable, str(Path(boot.__file__)), '--hex', str(source), '--output', str(output)], check=True, stdout=subprocess.PIPE)
        package = boot.load_package(output)
        self.assertEqual((len(package.data), package.version, package.image), (65664, '1.0.16', image()))
        self.assertEqual(package.md5, hashlib.md5(output.read_bytes()).hexdigest())

    def test_hex_strict_boundaries_and_conflicts(self):
        cases = [
            record(4, 0, b'\x90\x00') + record(0, 0, b'\x01') + record(1, 0),
            record(4, 0, b'\x08\x01') + record(0, 0, b'\x01') + record(1, 0),
            record(4, 0, b'\x1f\xff') + record(0, 0xF000, b'\x01') + record(1, 0),
            hex_text().replace(record(1, 0), record(0, 0, b'\x01') + record(1, 0)),
            hex_text() + record(0, 0, b'\x01'),
            hex_text().replace(record(1, 0), ''),
            hex_text().replace(':020000040800F2', ':020000040800F3'),
        ]
        source = self.folder / 'bad.hex'
        for value in cases:
            source.write_text(value, encoding='ascii')
            with self.subTest(value=value[:30]), self.assertRaises(ValueError): boot.image_from_hex(source)

    def test_image_vector_marker_and_header_crc_are_strict(self):
        package = boot.build_package(image())
        bad = bytearray(package.data); bad[-1] ^= 1
        with self.assertRaisesRegex(ValueError, 'CRC'): boot.validate_package(bad)
        bad = bytearray(package.data); bad[16] ^= 1
        with self.assertRaises(ValueError): boot.validate_package(bad)
        bad = bytearray(package.data); bad[36:56] = b'1.0.17\0'.ljust(20, b'\0')
        struct.pack_into('<I', bad, 124, zlib.crc32(bad[:124]) & 0xffffffff)
        with self.assertRaisesRegex(ValueError, '版本'): boot.validate_package(bad)
        for at, value in [(0, struct.pack('<I', 0x20000001)), (4, struct.pack('<I', 0x90000001)),
                          (0x100, b'\xff\xff'), (boot.VERSION_OFFSET, b'\xff'*20)]:
            bad_image = bytearray(image()); bad_image[at:at+len(value)] = value
            with self.subTest(at=at), self.assertRaises(ValueError): boot.build_package(bad_image)


class ProtocolTests(unittest.TestCase):
    def test_boot_layout_mismatch_stops_before_begin(self):
        old_package = boot.build_package(image())
        new_image = bytearray(image())
        marker = boot.VERSION_OFFSET + 20
        new_image[marker:marker + 8] = boot.NEW_LAYOUT_STAMP
        new_package = boot.build_package(bytes(new_image))
        for package, flags in ((old_package, 15), (new_package, 7)):
            cap = boot.BootCapability('1.0.18', 0, 16384, flags)
            with patch.object(boot, 'request') as request:
                with self.assertRaisesRegex(ValueError, '布局不一致'):
                    boot.stage_package(object(), package, cap)
                request.assert_not_called()

    def setUp(self):
        self.package = boot.build_package(image())
        self.cap = boot.BootCapability('1.0.15', 123, 16384, 7)

    def test_window1_frames_md5_and_ready_before_commit(self):
        calls = []
        def server(sock):
            op, offset, body = read_frame(sock); calls.append(op)
            self.assertEqual((op, offset), (boot.OP_BEGIN, 0))
            self.assertEqual(body, struct.pack('<I', 65664) + self.package.md5.encode())
            reply(sock, op, struct.pack('<I', 0)); total = bytearray()
            while len(total) < 65664:
                op, offset, body = read_frame(sock); calls.append(op)
                self.assertEqual((op, offset), (boot.OP_DATA, len(total)))
                self.assertFalse(select.select([sock], [], [], .01)[0], '窗口1尚未收到ACK就发下一片')
                total.extend(body); reply(sock, op, struct.pack('<I', len(total)))
            self.assertEqual(bytes(total), self.package.data)
            self.assertEqual(read_frame(sock), (boot.OP_STATUS, 0, b'')); calls.append(boot.OP_STATUS)
            reply(sock, boot.OP_STATUS, boot.STATUS.pack(boot.READY, 0, 65664, 65664, 0))
        with Loopback(server) as sock:
            status = boot.stage_package(sock, self.package, self.cap)
        self.assertEqual(status.state, boot.READY)
        self.assertEqual(calls.count(boot.OP_DATA), 5)
        self.assertNotIn(boot.OP_COMMIT, calls)

    def test_data_ack_error_never_replays_or_commits(self):
        calls = []
        def server(sock):
            op, _, _ = read_frame(sock); reply(sock, op, struct.pack('<I', 0))
            op, _, _ = read_frame(sock); calls.append(op)
            reply(sock, op, struct.pack('<I', 1))
            self.assertEqual(sock.recv(1), b'')
        with self.assertRaisesRegex(ValueError, '确认'):
            with Loopback(server) as sock: boot.stage_package(sock, self.package, self.cap)
        self.assertEqual(calls, [boot.OP_DATA])

    def test_failed_same_package_begin_total_skips_data(self):
        calls = []
        def request(sock, op, **kwargs):
            calls.append(op)
            return struct.pack('<I', 65664) if op == boot.OP_BEGIN else boot.STATUS.pack(boot.READY, 0, 65664, 65664, 1234)
        with patch.object(boot, 'request', side_effect=request): boot.stage_package(object(), self.package, self.cap)
        self.assertEqual(calls, [boot.OP_BEGIN, boot.OP_STATUS])

    def test_partial_flash_unknown_current_version_still_allows_recovery(self):
        with patch.object(boot, 'request', return_value=capability(self.package, b'\xff'*20)):
            self.assertEqual(boot.get_capability(object()).version, '未知/无效')

    def test_old_capability_explains_system_upgrade(self):
        with patch.object(boot, 'request', side_effect=tcp.DeviceError(11)):
            with self.assertRaisesRegex(boot.BootUpdateError, '1.4.43'): boot.get_capability(object())

    def test_incomplete_ready_and_auth_rejection_do_not_commit(self):
        for error in [tcp.DeviceError(13), None]:
            calls = []
            def request(sock, op, **kwargs):
                calls.append(op)
                if error: raise error
                return struct.pack('<I', 65664) if op == boot.OP_BEGIN else boot.STATUS.pack(boot.RECEIVING, 0, 123, 65664, 0)
            with patch.object(boot, 'request', side_effect=request), self.assertRaises((tcp.DeviceError, boot.BootUpdateError)):
                boot.stage_package(object(), self.package, self.cap)
            self.assertNotIn(boot.OP_COMMIT, calls)

    def monitor(self, states, wrong_crc=False):
        connections, calls = [], []
        @contextmanager
        def connection():
            sock = SimpleNamespace(index=len(connections), settimeout=lambda _: None)
            connections.append(sock); yield sock
        def request(sock, op, **kwargs):
            calls.append((sock.index, op))
            if op == boot.OP_STATUS:
                state = states[min(sock.index, len(states)-1)]
                return boot.STATUS.pack(state, 7 if state == boot.FAILED else 0, 65664 if state else 0, 65664 if state else 0, 1234 if state == boot.FAILED else 0)
            if op == boot.OP_CAP: return capability(self.package, crc=0 if wrong_crc else None)
            if op == 1: return b'{"board":"STM32F750Z8","uid":"U1"}'
            raise AssertionError('只读监测发送了写命令')
        with patch.object(boot, 'request', side_effect=request):
            result = boot.monitor_update(connection, self.package, 'U1', poll_interval=0, timeout=.2)
        return result, connections, calls

    def test_done_requires_another_connection_and_idle_cap_match(self):
        result, connections, calls = self.monitor([boot.DONE, boot.IDLE])
        self.assertEqual(result, 'verified_after_reset'); self.assertEqual(len(connections), 2)
        self.assertEqual(calls, [(0, boot.OP_STATUS), (1, boot.OP_STATUS), (1, boot.OP_CAP), (1, 1)])

    def test_unchanged_does_not_reset(self):
        result, connections, calls = self.monitor([boot.UNCHANGED])
        self.assertEqual(result, 'unchanged'); self.assertEqual(len(connections), 1)
        self.assertEqual([op for _, op in calls], [boot.OP_STATUS, boot.OP_CAP, 1])

    def test_failed_partial_write_keeps_power_warning_and_never_resets(self):
        with self.assertRaisesRegex(boot.BootUpdateFailed, '不要断电或重启'): self.monitor([boot.FAILED])

    def test_wrong_post_reset_crc_is_not_success(self):
        with self.assertRaisesRegex(boot.BootUpdateError, 'CRC不匹配'): self.monitor([boot.IDLE], wrong_crc=True)

    def test_commit_timeout_is_one_request_only(self):
        calls = []
        def request(sock, op, **kwargs): calls.append(op); raise TimeoutError('ACK lost')
        with patch.object(boot, 'request', side_effect=request), self.assertRaises(TimeoutError): boot.commit_once(object())
        self.assertEqual(calls, [boot.OP_COMMIT])


class GuiPolicyTests(unittest.TestCase):
    def test_d133_and_missing_key_rejected_before_any_task(self):
        app = SimpleNamespace(ota_board_var=SimpleNamespace(get=lambda: 'D133CBS · ArtInChip'))
        app._connection_inputs = lambda: self.fail('D133进入了连接参数/网络路径')
        with self.assertRaisesRegex(ValueError, 'D133'): ui.connection_inputs(app)
        app.ota_board_var.get = lambda: 'STM32F750'
        app._connection_inputs = lambda: (SimpleNamespace(host='127.0.0.1', port=5000), b'')
        with self.assertRaisesRegex(ValueError, 'Key'): ui.connection_inputs(app)

    def test_actual_confirm_event_continues_same_worker_and_commits_once(self):
        package = boot.build_package(image()); calls = []; posts = []
        app = SimpleNamespace(is_running=False, root=object(), boot_image_path=Path('mock.boot.bin'),
                              ota_board_var=SimpleNamespace(get=lambda: 'STM32F750'))
        app._connection_inputs = lambda: (SimpleNamespace(host='127.0.0.1', port=5000), b'k'*32)
        @contextmanager
        def connection(*_, **__): yield SimpleNamespace(settimeout=lambda _: None)
        app._connection = connection
        def post(kind, value=None):
            posts.append((kind, value))
            if kind == 'boot_confirm':
                text, event, answer, stop = value
                self.assertIn('单份BOOT', text); self.assertIn('CRC32', text); self.assertIn('UID', text)
                ui.handle_event(app, kind, value)
        app._post = post
        def task(title, action, **kwargs): app.is_running=True; app.action=action
        app._start_task = task
        def request(sock, op, **kwargs):
            calls.append(op)
            if op == boot.OP_CAP: return capability(package)
            if op == 1: return b'{"board":"STM32F750Z8","uid":"U1"}'
            if op == boot.OP_BEGIN: return struct.pack('<I', 65664)
            if op == boot.OP_STATUS: return boot.STATUS.pack(boot.READY, 0, 65664, 65664, 0)
            if op == boot.OP_COMMIT: return struct.pack('<I', boot.QUEUED)
            raise AssertionError(op)
        with patch.object(boot, 'load_package', return_value=package), \
                patch.object(boot, 'request', side_effect=request), \
                patch.object(ui, 'request', side_effect=request), \
                patch.object(boot, 'monitor_update', return_value='verified_after_reset'), \
                patch.object(ui.messagebox, 'askyesno', return_value=True) as confirm:
            ui.start_update(app)
            self.assertTrue(app.is_running)
            app.action(None, None, threading.Event())
            confirm.assert_called_once()
        self.assertEqual(calls.count(boot.OP_COMMIT), 1)
        self.assertEqual(calls.count(boot.OP_BEGIN), 1)
        self.assertTrue(any(kind=='boot_finished' for kind,_ in posts))


if __name__ == '__main__':
    unittest.main(verbosity=2)
