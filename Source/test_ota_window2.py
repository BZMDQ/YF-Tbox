"""仅用回环服务验证实际OTA在途窗口、旧固件兼容与出错后禁止写入重放。"""
import socket
import select
import struct
import threading
import unittest
import zlib

import local_tcp_client as client


class OtaServer:
    def __init__(self, handler):
        self.handler = handler
        self.errors = []
        self.listener = socket.socket()
        self.listener.bind(('127.0.0.1', 0))
        self.listener.listen(1)
        self.listener.settimeout(3)

    def __enter__(self):
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()
        self.sock = socket.create_connection(self.listener.getsockname(), timeout=3)
        return self.sock

    def run(self):
        try:
            with self.listener.accept()[0] as connection:
                connection.settimeout(3)
                self.handler(connection)
        except Exception as exc:
            self.errors.append(exc)
        finally:
            self.listener.close()

    def __exit__(self, *_):
        self.sock.close()
        self.thread.join(4)
        if self.thread.is_alive():
            raise AssertionError('OTA回环服务未退出')
        if self.errors:
            raise self.errors[0]


def read_frame(connection):
    header = client.exact(connection, 20)
    magic, op, offset, size, crc = client.HEADER.unpack(header)
    if magic != b'LNET' or size > 16384:
        raise AssertionError('发送帧头或长度错误')
    body = client.exact(connection, size)
    if zlib.crc32(body, zlib.crc32(header[:16])) & 0xffffffff != crc:
        raise AssertionError('发送帧CRC错误')
    return op, offset, body


def reply(connection, op, body=b'', status=0):
    connection.sendall(client.frame(op | 0x80000000, status, body))


class OtaWindowTests(unittest.TestCase):
    package = bytes(range(256)) * 197 + b'tail'

    def negotiate(self, connection, maximum=16384, status=0):
        self.assertEqual(read_frame(connection), (34, 0, b''))
        reply(connection, 34, b'OPI1' + struct.pack('<II', maximum, 2)
              if not status else b'', status=status)

    def test_window2_sends_two_full_frames_before_first_ack(self):
        received = []
        modes, progress, info = [], [], []
        def handler(connection):
            self.negotiate(connection)
            # 服务收到两片前不发ACK，证明不是把窗口1日志改成窗口2。
            pending = [read_frame(connection), read_frame(connection)]
            self.assertEqual([len(item[2]) for item in pending], [16384, 16384])
            self.assertFalse(select.select([connection], [], [], 0.03)[0], '未等ACK就发送第三片')
            while pending:
                op, offset, body = pending.pop(0)
                self.assertEqual((op, offset, body), (3, len(b''.join(received)), self.package[offset:offset + len(body)]))
                received.append(body)
                written = offset + len(body)
                if offset == 0:
                    reply(connection, 1, b'{"version":"test"}')
                    # 同一ACK拆成多段也不能改变累计进度或窗口。
                    packet = client.frame(0x80000003, payload=struct.pack('<I', written))
                    connection.sendall(packet[:7])
                    connection.sendall(packet[7:])
                else:
                    reply(connection, 3, struct.pack('<I', written))
                # 每确认一片最多补入一片，最多两片在途。
                loaded = sum(len(item[2]) for item in pending) + written
                if loaded < len(self.package):
                    pending.append(read_frame(connection))
        with OtaServer(handler) as connection:
            client.upload_ota_stream(connection, self.package, chunk_size=1024,
                                     on_mode=lambda *value: modes.append(value),
                                     on_progress=progress.append, on_info=info.append)
        self.assertEqual(b''.join(received), self.package)
        self.assertEqual(modes, [(16384, 2)])
        self.assertEqual(progress, [16384, 32768, 49152, len(self.package)])
        self.assertEqual(len(info), 1)

    def test_legacy_firmware_explicitly_falls_back_to_window1(self):
        modes, received = [], []
        def handler(connection):
            self.negotiate(connection, status=11)
            while sum(map(len, received)) < len(self.package):
                op, offset, body = read_frame(connection)
                self.assertEqual((op, offset), (3, sum(map(len, received))))
                self.assertLessEqual(len(body), 16384)
                self.assertFalse(select.select([connection], [], [], 0.01)[0], '旧固件收到未协商的并发分片')
                received.append(body)
                reply(connection, 3, struct.pack('<I', offset + len(body)))
        with OtaServer(handler) as connection:
            client.upload_ota_stream(connection, self.package,
                                     on_mode=lambda *value: modes.append(value))
        self.assertEqual(modes, [(16384, 1)])
        self.assertEqual(b''.join(received), self.package)

    def test_older_4k_pipeline_capability_remains_supported(self):
        modes, received = [], []
        payload = self.package[:9000]
        def handler(connection):
            self.negotiate(connection, maximum=4096)
            first, second = read_frame(connection), read_frame(connection)
            self.assertEqual([len(first[2]), len(second[2])], [4096, 4096])
            for op, offset, body in (first, second):
                received.append(body)
                reply(connection, op, struct.pack('<I', offset + len(body)))
            op, offset, body = read_frame(connection)
            received.append(body)
            reply(connection, op, struct.pack('<I', offset + len(body)))
        with OtaServer(handler) as connection:
            client.upload_ota_stream(connection, payload, on_mode=lambda *value: modes.append(value))
        self.assertEqual(modes, [(4096, 2)])
        self.assertEqual(b''.join(received), payload)

    def test_auth_error_in_capability_does_not_fall_back_or_send_data(self):
        def handler(connection):
            self.negotiate(connection, status=13)
            self.assertEqual(connection.recv(1), b'')
        with self.assertRaises(client.DeviceError) as raised:
            with OtaServer(handler) as connection:
                client.upload_ota_stream(connection, self.package)
        self.assertEqual(raised.exception.status, 13)

    def test_invalid_window_advertisement_does_not_send_data(self):
        def handler(connection):
            self.assertEqual(read_frame(connection), (34, 0, b''))
            reply(connection, 34, b'OPI1' + struct.pack('<II', 16384, 3))
            self.assertEqual(connection.recv(1), b'')
        with self.assertRaisesRegex(ValueError, '窗口'):
            with OtaServer(handler) as connection:
                client.upload_ota_stream(connection, self.package)

    def test_ack_offset_mismatch_stops_without_replaying_writes(self):
        received = []
        def handler(connection):
            self.negotiate(connection)
            received.extend([read_frame(connection), read_frame(connection)])
            reply(connection, 3, struct.pack('<I', 32768))
            self.assertEqual(connection.recv(1), b'')
        with self.assertRaisesRegex(ValueError, '偏移'):
            with OtaServer(handler) as connection:
                client.upload_ota_stream(connection, self.package)
        self.assertEqual([item[1] for item in received], [0, 16384])

    def test_bad_ack_crc_stops_without_replaying_writes(self):
        def handler(connection):
            self.negotiate(connection)
            read_frame(connection)
            read_frame(connection)
            packet = bytearray(client.frame(0x80000003, payload=struct.pack('<I', 16384)))
            packet[16] ^= 1
            connection.sendall(packet)
            self.assertEqual(connection.recv(1), b'')
        with self.assertRaisesRegex(ValueError, 'CRC'):
            with OtaServer(handler) as connection:
                client.upload_ota_stream(connection, self.package)

    def test_explicit_write_rejection_stops_without_replaying_writes(self):
        def handler(connection):
            self.negotiate(connection)
            read_frame(connection)
            read_frame(connection)
            reply(connection, 3, status=6)
            self.assertEqual(connection.recv(1), b'')
        with self.assertRaises(client.DeviceError) as raised:
            with OtaServer(handler) as connection:
                client.upload_ota_stream(connection, self.package)
        self.assertEqual(raised.exception.status, 6)

    def test_precancel_sends_no_ota_data(self):
        stop = threading.Event()
        stop.set()
        def handler(connection):
            self.negotiate(connection)
            self.assertEqual(connection.recv(1), b'')
        with self.assertRaises(InterruptedError):
            with OtaServer(handler) as connection:
                client.upload_ota_stream(connection, self.package, cancel=stop)


if __name__ == '__main__':
    unittest.main(verbosity=2)
