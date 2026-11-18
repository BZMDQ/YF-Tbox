"""代理路径的真实socket/帧模型；仅127.0.0.1及临时文件，不连接硬件。"""
from contextlib import closing, contextmanager
import json
from pathlib import Path
import select
import socket
import struct
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import zlib

import d133_proxy_client as proxy
import d133_proxy_ui as ui
import local_tcp_client as tcp


def info(**changes):
    value = dict(product=proxy.PRODUCT, hardware=proxy.HARDWARE, protocol=1,
                 stream_ota=2, usb_ota=1, version='1.0.169', slot='A', next_slot='A', confirmed=True)
    value.update(changes)
    return value


def cpio(payload_size=9000):
    def member(name, body):
        # 官方crc CPIO头：13个8位十六进制字段。
        values = [0, 0o100644, 0, 0, 1, 0, len(body), 0, 0, 0, 0, len(name) + 1, sum(body) & 0xffffffff]
        value = b'070702' + b''.join(f'{x:08x}'.encode() for x in values) + name.encode() + b'\0'
        value += b'\0' * (-len(value) % 4)
        value += body
        return value + b'\0' * (-len(value) % 4)
    total = 0
    for _ in range(4):
        text = b'\0'.join(x.encode() for x in ['[image]', f'size = "{total}";', 'version = "1.0.170";',
                                                '[file]', 'ota_info.bin:file;', 'd13x_os.itb:os;']) + b'\0'
        data = member('ota_info.bin', b'\0' * 4 + text.ljust(508, b'\0'))
        data += member('d13x_os.itb', b'x' * payload_size) + member('TRAILER!!!', b'')
        total = len(data)
    return data


def read_frame(sock, max_payload=4096):
    header = tcp.exact(sock, 20)
    magic, op, offset, size, crc = tcp.HEADER.unpack(header)
    if magic != b'LNET' or size > max_payload:
        raise AssertionError('代理请求越界或错误magic')
    body = tcp.exact(sock, size)
    if zlib.crc32(body, zlib.crc32(header[:16])) & 0xffffffff != crc:
        raise AssertionError('客户端请求CRC不匹配')
    return op, offset, body


def reply(sock, op, body=b'', status=0):
    value = tcp.frame(op | 0x80000000, status, body)
    # 故意分割帧头/CRC/payload，验证生产解析器跨recv正确组帧。
    for start, end in [(0, 3), (3, 18), (18, len(value))]:
        sock.sendall(value[start:end])


class Peer:
    def __init__(self, handler):
        self.handler, self.errors = handler, []

    def __enter__(self):
        server = socket.socket()
        server.bind(('127.0.0.1', 0))
        server.listen(1)
        server.settimeout(2)
        self.sock = socket.create_connection(server.getsockname(), timeout=2)
        def work():
            try:
                with server.accept()[0] as sock:
                    sock.settimeout(2)
                    self.handler(sock)
            except Exception as exc:
                self.errors.append(exc)
            finally:
                server.close()
        self.thread = threading.Thread(target=work, daemon=True)
        self.thread.start()
        return self.sock

    def __exit__(self, *_):
        self.sock.close()
        self.thread.join(3)
        if self.thread.is_alive():
            raise AssertionError('回环模型未退出')
        if self.errors:
            raise self.errors[0]


class ProxyTests(unittest.TestCase):
    def test_screen_prompt_uses_explicit_boolean_capability(self):
        package = proxy.Package(b'package', b'signature', '1.0.170')
        cases = [
            (info(version='1.0.170', usb_screen_confirm=False), '电脑端已确认'),
            (info(), '等待D133屏幕确认'),
            (info(usb_screen_confirm=True), '等待D133屏幕确认'),
            (info(usb_screen_confirm=0), '等待D133屏幕确认'),
        ]
        for state, expected in cases:
            with self.subTest(state=state):
                progress = Mock()
                # 读取 D100 的真实 JSON 形态，截停在 D106，验证开始写入前的提示。
                with patch.object(proxy, 'request', side_effect=[
                        json.dumps(state).encode(), proxy.ProxyError(3)]) as request:
                    sock = object()
                    initial = proxy.device_info(sock)
                    with self.assertRaises(proxy.ProxyError):
                        proxy.transfer(sock, package, initial, progress)
                self.assertIn(expected, progress.call_args.args[1])
                self.assertEqual([call.args[1] for call in request.call_args_list], [proxy.INFO, proxy.BEGIN])

    def test_pc_declines_usb_update_before_any_task(self):
        app = SimpleNamespace(
            is_running=False, root=object(),
            d133_proxy_path=Path('ota.cpio'), d133_proxy_signature=Path('ota.cpio.sig'),
            _connection_inputs=Mock(return_value=(SimpleNamespace(host='127.0.0.1', port=5000), b'k' * 32)),
            _start_task=Mock(),
        )
        package = proxy.Package(b'package', b'signature', '1.0.170')
        with patch.object(proxy, 'load_package', return_value=package), \
                patch.object(ui.messagebox, 'askyesno', return_value=False) as confirm:
            ui.start_update(app)
        confirm.assert_called_once()
        app._start_task.assert_not_called()

    def setUp(self):
        self.package = proxy.Package(cpio(), b'signed', '1.0.170')

    def test_local_cpio_and_matching_signature(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as folder:
            path = Path(folder) / 'ota.cpio'
            path.write_bytes(self.package.data)
            sig = Path(str(path) + '.sig')
            sig.write_bytes(b'signed')
            self.assertEqual(proxy.load_package(path).version, '1.0.170')
            with self.assertRaisesRegex(ValueError, '同一目录'):
                proxy.load_package(path, Path(folder) / 'other.sig')
            sig.write_bytes(b'x' * 513)
            with self.assertRaisesRegex(ValueError, '512'):
                proxy.load_package(path)

    def test_proxy_info_ignores_f750_unsolicited_information(self):
        def handler(sock):
            self.assertEqual(read_frame(sock), (proxy.INFO, 0, b''))
            reply(sock, 1, json.dumps({'board': 'STM32F750', 'version': '1.4.49'}).encode())
            reply(sock, proxy.INFO, json.dumps(info()).encode())
        with Peer(handler) as sock:
            self.assertEqual(proxy.device_info(sock)['product'], proxy.PRODUCT)

    def test_old_or_wrong_target_is_rejected(self):
        for body in ({'board': 'F750'}, info(usb_ota=0), info(slot=0), info(confirmed='true')):
            def handler(sock):
                read_frame(sock)
                reply(sock, proxy.INFO, json.dumps(body).encode())
            with self.subTest(body=body), Peer(handler) as sock, self.assertRaises(ValueError):
                proxy.device_info(sock)

    def test_transfer_window1_fixed_chunks_and_single_commit(self):
        ops = []
        def handler(sock):
            op, offset, body = read_frame(sock)
            ops.append(op)
            self.assertEqual((op, offset), (proxy.BEGIN, 0))
            self.assertEqual(struct.unpack_from('<I', body)[0], len(self.package.data))
            self.assertEqual(len(body), 132 + len(self.package.signature))
            reply(sock, op)
            received = 0
            while received < len(self.package.data):
                op, offset, body = read_frame(sock)
                ops.append(op)
                self.assertEqual((op, offset), (proxy.DATA, received))
                self.assertEqual(body, self.package.data[received:received + 4096])
                self.assertFalse(select.select([sock], [], [], .005)[0], '下一片越过当前ACK')
                received += len(body)
                reply(sock, op, struct.pack('<I', received))
            self.assertEqual(read_frame(sock), (proxy.COMMIT, 0, b''))
            ops.append(proxy.COMMIT)
            reply(sock, proxy.COMMIT, struct.pack('<I', received))
        with Peer(handler) as sock:
            self.assertEqual(proxy.transfer(sock, self.package, info(), lambda *_: None), 'B')
        self.assertEqual(ops.count(proxy.COMMIT), 1)
        self.assertEqual(ops.count(proxy.DATA), 3)

    def test_d100_selects_chunk_size_and_preserves_window1(self):
        both_capable = info(version='1.0.171', relay_max_chunk=32768, usb_max_chunk=32768,
                            usb_screen_confirm=False)
        cases = (
            (info(version='1.0.169', relay_max_chunk=32768, relay_max_window=2), 4096, 9000, '等待D133屏幕确认'),
            (info(version='1.0.171', usb_max_chunk=32768, usb_screen_confirm=False), 4096, 9000, '电脑端已确认'),
            (both_capable, 32768, 34000, '电脑端已确认'),
            (dict(both_capable, relay_max_window=2.0), 32768, 82000, '电脑端已确认'),
        )
        for state, chunk_size, payload_size, confirmation in cases:
            package = proxy.Package(cpio(payload_size), b'signed', '1.0.170')
            frame_size = min(chunk_size, 16384)
            data_op = proxy.DATA if chunk_size == 4096 else proxy.LOGICAL_DATA
            lengths, progress = [], Mock()

            def handler(sock):
                self.assertEqual(read_frame(sock), (proxy.INFO, 0, b''))
                # F750 的主动身份帧即使带能力字段，仍须丢弃。
                reply(sock, 1, json.dumps({'relay_max_chunk': 32768, 'relay_max_window': 2}).encode())
                reply(sock, proxy.INFO, json.dumps(state).encode())
                op, offset, _ = read_frame(sock)
                self.assertEqual((op, offset), (proxy.BEGIN, 0))
                reply(sock, op)
                for expected in range(0, len(package.data), chunk_size):
                    end = min(expected + chunk_size, len(package.data))
                    # 同一逻辑块先读齐所有物理帧，中间不给ACK。
                    for start in range(expected, end, frame_size):
                        op, offset, body = read_frame(sock, max_payload=frame_size)
                        self.assertEqual((op, offset), (data_op, start))
                        self.assertEqual(body, package.data[start:min(start + frame_size, end)])
                        lengths.append(len(body))
                    self.assertFalse(select.select([sock], [], [], .005)[0], '下一块越过当前ACK')
                    reply(sock, data_op, struct.pack('<I', end))
                self.assertEqual(read_frame(sock), (proxy.COMMIT, 0, b''))
                reply(sock, proxy.COMMIT, struct.pack('<I', len(package.data)))

            with self.subTest(state=state, payload_size=payload_size), Peer(handler) as sock:
                self.assertEqual(proxy.transfer(sock, package, proxy.device_info(sock), progress), 'B')
            messages = [call.args[1] for call in progress.call_args_list]
            self.assertIn(f'数据块 {chunk_size // 1024} KiB', messages[0])
            self.assertIn('窗口 1', messages[0])
            self.assertIn(confirmation, messages[0])
            self.assertIn(f'{len(package.data):,}/{len(package.data):,} 字节', messages[-2])
            full, tail = divmod(len(package.data), frame_size)
            self.assertEqual(lengths, [frame_size] * full + ([tail] if tail else []))

    def _read_logical_block(self, sock, package, offset):
        end = min(offset + proxy.LARGE_CHUNK_SIZE, len(package.data))
        for start in range(offset, end, proxy.LNET_MAX_PAYLOAD):
            op, received, body = read_frame(sock, max_payload=proxy.LNET_MAX_PAYLOAD)
            self.assertEqual((op, received), (proxy.LOGICAL_DATA, start))
            self.assertEqual(body, package.data[start:min(start + proxy.LNET_MAX_PAYLOAD, end)])
        return end

    def test_d100_window2_sends_two_blocks_refills_on_one_ack_and_commits_last(self):
        state = info(version='1.0.171', relay_max_chunk=32768, usb_max_chunk=32768, relay_max_window=2)
        package = proxy.Package(cpio(payload_size=100000), b'signed', '1.0.171')
        progress, committed = Mock(), Mock()

        def handler(sock):
            self.assertEqual(read_frame(sock), (proxy.INFO, 0, b''))
            reply(sock, proxy.INFO, json.dumps(state).encode())
            op, offset, _ = read_frame(sock)
            self.assertEqual((op, offset), (proxy.BEGIN, 2))
            reply(sock, op)
            # 先完整收到两块，再按顺序逐块确认。只确认一块时就应补满窗口。
            first = self._read_logical_block(sock, package, 0)
            second = self._read_logical_block(sock, package, first)
            self.assertFalse(select.select([sock], [], [], .02)[0], '第三块越过第一块ACK')
            reply(sock, proxy.LOGICAL_DATA, struct.pack('<I', first))
            third = self._read_logical_block(sock, package, second)
            self.assertFalse(select.select([sock], [], [], .02)[0], '第四块越过第二块ACK')
            reply(sock, proxy.LOGICAL_DATA, struct.pack('<I', second))
            fourth = self._read_logical_block(sock, package, third)
            self.assertEqual(fourth, len(package.data))
            reply(sock, proxy.LOGICAL_DATA, struct.pack('<I', third))
            self.assertFalse(select.select([sock], [], [], .02)[0], '提交越过最后一块ACK')
            committed.assert_not_called()
            reply(sock, proxy.LOGICAL_DATA, struct.pack('<I', fourth))
            self.assertEqual(read_frame(sock), (proxy.COMMIT, 0, b''))
            reply(sock, proxy.COMMIT, struct.pack('<I', fourth))

        with Peer(handler) as sock:
            self.assertEqual(proxy.transfer(sock, package, proxy.device_info(sock), progress,
                                            on_commit=committed), 'B')
        self.assertIn('数据块 32 KiB，窗口 2', progress.call_args_list[0].args[1])
        committed.assert_called_once()

    def test_window2_out_of_order_ack_and_device_error_stop_without_refill_or_commit(self):
        state = info(relay_max_chunk=32768, usb_max_chunk=32768, relay_max_window=2)
        package = proxy.Package(cpio(payload_size=82000), b'signed', '1.0.171')
        for status in (0, 6):
            def handler(sock):
                op, offset, _ = read_frame(sock)
                self.assertEqual((op, offset), (proxy.BEGIN, 2))
                reply(sock, op)
                first = self._read_logical_block(sock, package, 0)
                second = self._read_logical_block(sock, package, first)
                reply(sock, proxy.LOGICAL_DATA, struct.pack('<I', second) if status == 0 else b'', status=status)
                self.assertFalse(sock.recv(1), '错误响应后不应补发、重放或提交')

            error = ValueError if status == 0 else proxy.ProxyError
            with self.subTest(status=status), Peer(handler) as sock, self.assertRaises(error):
                proxy.transfer(sock, package, state, lambda *_: None)

    def test_window2_cancel_closes_socket_with_ack_pending(self):
        state = info(relay_max_chunk=32768, usb_max_chunk=32768, relay_max_window=2)
        package = proxy.Package(cpio(payload_size=82000), b'signed', '1.0.171')
        stop, committed = threading.Event(), Mock()

        def handler(sock):
            op, offset, _ = read_frame(sock)
            self.assertEqual((op, offset), (proxy.BEGIN, 2))
            reply(sock, op)
            first = self._read_logical_block(sock, package, 0)
            self._read_logical_block(sock, package, first)
            stop.set()
            self.assertFalse(sock.recv(1), '仍有未确认数据时应断开连接，不发送CANCEL或COMMIT')

        with Peer(handler) as sock, self.assertRaisesRegex(InterruptedError, '非活动槽不会被激活'):
            proxy.transfer(sock, package, state, lambda *_: None, stop, committed)
        committed.assert_not_called()

    def test_large_chunks_require_both_exact_json_integers(self):
        for field in ('relay_max_chunk', 'usb_max_chunk'):
            for invalid in (None, 32768.0, '32768', True, 4096, 16384, 65536):
                with self.subTest(field=field, invalid=invalid):
                    state = info(relay_max_chunk=32768, usb_max_chunk=32768)
                    state[field] = invalid
                    self.assertEqual(proxy._chunk_size(state), 4096)

    def test_progress_throttles_intermediate_updates_and_always_reports_last_block(self):
        package = proxy.Package(b'x' * (4096 * 3), b'signed', '1.0.170')
        progress = Mock()
        acks = [struct.pack('<I', size) for size in (4096, 8192, 12288)]
        with patch.object(proxy, 'request', side_effect=[b'', acks[-1]]), \
                patch.object(proxy, '_send_request'), \
                patch.object(proxy, '_receive_response', side_effect=acks), \
                patch.object(proxy.time, 'monotonic', side_effect=[0, .05, .21, .26]):
            proxy.transfer(object(), package, info(), progress)
        updates = [call.args for call in progress.call_args_list]
        self.assertEqual([percent for percent, _ in updates], [0, 66, 100, 100])
        self.assertIn('12,288/12,288 字节；46.2 KiB/s', updates[-2][1])

    def test_wrong_ack_stops_without_replay_or_commit(self):
        package = proxy.Package(cpio(payload_size=34000), b'signed', '1.0.170')
        cases = ((info(), 4096, proxy.DATA),
                 (info(relay_max_chunk=32768, usb_max_chunk=32768), 32768, proxy.LOGICAL_DATA))
        for state, chunk_size, data_op in cases:
            def handler(sock):
                op, _, _ = read_frame(sock)
                reply(sock, op)
                frame_size = min(chunk_size, 16384)
                for start in range(0, chunk_size, frame_size):
                    op, offset, body = read_frame(sock, max_payload=frame_size)
                    self.assertEqual((op, offset, len(body)), (data_op, start, frame_size))
                reply(sock, data_op, struct.pack('<I', chunk_size - 1))
                self.assertFalse(sock.recv(1), 'ACK错误后不应重发、缩块或提交')
            with self.subTest(chunk_size=chunk_size), Peer(handler) as sock, self.assertRaisesRegex(ValueError, 'ACK'):
                proxy.transfer(sock, package, state, lambda *_: None)

    def test_cancel_after_begin_ack_never_commits(self):
        stop = threading.Event()
        def handler(sock):
            op, _, _ = read_frame(sock)
            stop.set()
            reply(sock, op)
            self.assertEqual(read_frame(sock), (proxy.CANCEL, 0, b''))
            reply(sock, proxy.CANCEL)
        with Peer(handler) as sock, self.assertRaises(InterruptedError):
            proxy.transfer(sock, self.package, info(), lambda *_: None, stop)

    def test_status_errors_are_propagated(self):
        for code in (14, 24, 25, 27, 31, 32, 100, 101, 102):
            def handler(sock):
                op, _, _ = read_frame(sock)
                reply(sock, op, status=code)
            with self.subTest(code=code), Peer(handler) as sock, self.assertRaises(proxy.ProxyError) as error:
                proxy.request(sock, proxy.BEGIN)
            self.assertEqual(error.exception.status, code)

    def test_bad_crc_opcode_and_oversized_response_are_rejected(self):
        cases = [tcp.frame(proxy.INFO | 0x80000000, 0, b'')[:-1] + b'\xff',
                 tcp.frame(proxy.DATA | 0x80000000), tcp.frame(proxy.INFO | 0x80000000, 0, b'x' * 1001)]
        for raw in cases:
            def handler(sock):
                read_frame(sock)
                sock.sendall(raw)
            with self.subTest(raw=raw[:20]), Peer(handler) as sock, self.assertRaises(ValueError):
                proxy.request(sock, proxy.INFO)

    def test_commit_ack_loss_is_not_canceled_or_replayed(self):
        ops, committed = [], []
        def handler(sock):
            while True:
                op, offset, body = read_frame(sock)
                ops.append(op)
                if op == proxy.COMMIT:
                    return  # USB已提交，但电脑端没有收到ACK。
                reply(sock, op, struct.pack('<I', offset + len(body)) if op == proxy.DATA else b'')
        with Peer(handler) as sock:
            self.assertEqual(proxy.transfer(sock, self.package, info(), lambda *_: None,
                                           on_commit=lambda: committed.append(True)), 'B')
        self.assertEqual(ops.count(proxy.COMMIT), 1)
        self.assertNotIn(proxy.CANCEL, ops)
        self.assertEqual(committed, [True])

    def test_commit_env_error27_continues_readonly_health_without_replay(self):
        """ENV可能部分生效：27不能当作撤销，只重连读取D133健康状态。"""
        ops = []
        def transfer_peer(sock):
            op, _, _ = read_frame(sock)
            ops.append(op)
            self.assertEqual(op, proxy.INFO)
            reply(sock, op, json.dumps(info()).encode())
            while True:
                op, offset, body = read_frame(sock)
                ops.append(op)
                if op == proxy.COMMIT:
                    reply(sock, op, status=27)
                    return
                self.assertIn(op, (proxy.BEGIN, proxy.DATA))
                reply(sock, op, struct.pack('<I', offset + len(body)) if op == proxy.DATA else b'')
        def health_peer(sock):
            op, offset, body = read_frame(sock)
            ops.append(op)
            self.assertEqual((op, offset, body), (proxy.HEALTH, 0, b''))
            reply(sock, op, json.dumps(info(version='1.0.170', slot='B', next_slot='B')).encode())
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as folder:
            path = Path(folder) / 'ota.cpio'
            path.write_bytes(self.package.data)
            Path(str(path) + '.sig').write_bytes(self.package.signature)
            with Peer(transfer_peer) as transfer_sock, Peer(health_peer) as health_sock:
                with patch.object(proxy, 'connect', side_effect=[transfer_sock, health_sock]) as connect:
                    result = proxy.upload(SimpleNamespace(host='127.0.0.1', port=5000), b'k' * 32,
                                          path, lambda *_: None)
                    self.assertEqual(result, '1.0.170')
                    self.assertEqual(connect.call_count, 2)
        self.assertEqual(ops.count(proxy.COMMIT), 1)
        self.assertEqual(ops[-1], proxy.HEALTH)
        self.assertNotIn(proxy.CANCEL, ops)

    def test_health_requires_preselected_inactive_slot_and_confirmation(self):
        states = [proxy.ProxyError(100), proxy.ProxyError(101), info(version='1.0.170'),
                  info(version='1.0.170', slot='B', next_slot='B', confirmed=False),
                  info(version='1.0.170', slot='B', next_slot='B')]
        @contextmanager
        def connection():
            yield object()
        with patch.object(proxy, 'device_info', side_effect=states), patch.object(proxy.time, 'sleep'):
            self.assertEqual(proxy.monitor(connection, self.package, info(), 'B', lambda *_: None), '1.0.170')

    def test_old_slot_after_reboot_window_is_not_success(self):
        @contextmanager
        def connection():
            yield object()
        with patch.object(proxy, 'device_info', return_value=info()), patch.object(proxy.time, 'monotonic', side_effect=[0, 1, 31]):
            with self.assertRaisesRegex(RuntimeError, '原槽'):
                proxy.monitor(connection, self.package, info(), 'B', lambda *_: None)

    def test_stop_after_commit_does_not_send_cancel(self):
        stop = threading.Event()
        stop.set()
        with self.assertRaisesRegex(InterruptedError, '不能撤销'):
            proxy.monitor(lambda: self.fail('停止后不应重连'), self.package, info(), 'B', lambda *_: None, stop)

    def test_upload_requires_existing_f750_key_before_connection(self):
        with patch.object(proxy, 'connect') as connect:
            with self.assertRaisesRegex(ValueError, 'Key'):
                proxy.upload(SimpleNamespace(host='127.0.0.1', port=5000), b'', 'unused', lambda *_: None)
            connect.assert_not_called()

    def test_stop_ui_preserves_committed_semantics(self):
        messages = []
        app = SimpleNamespace(stop_event=threading.Event(), d133_proxy_committed=True,
                              stop_button=SimpleNamespace(configure=lambda **_: None),
                              d133_proxy_status_var=SimpleNamespace(set=messages.append),
                              _append_log=messages.append, _set_status=messages.append)
        ui.stop_operation(app)
        self.assertTrue(app.stop_event.is_set())
        self.assertIn('不能撤销', messages[0])


if __name__ == '__main__':
    unittest.main()
