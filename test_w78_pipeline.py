"""检查 32 KiB 逻辑块、16 KiB 原始帧、窗口 2 和旧协议回退。"""
import socket
import struct
import threading
import zlib

from local_tcp_client import HEADER, W78_MAX_PAYLOAD, frame, request_wait, upload_w78_window

ACTIVE_RX_SIZE = 73728
PIPELINE_WINDOW = 2
FRAME_DATA_SIZE = 16 * 1024
FRAME_WIRE_SIZE = HEADER.size + FRAME_DATA_SIZE


def recv_frame(sock):
    header = bytearray()
    while len(header) < HEADER.size:
        part = sock.recv(HEADER.size - len(header))
        if not part:
            raise ConnectionError('peer closed')
        header.extend(part)
    magic, op, offset, size, crc = HEADER.unpack(header)
    body = bytearray()
    while len(body) < size:
        part = sock.recv(size - len(body))
        if not part:
            raise ConnectionError('peer closed')
        body.extend(part)
    if magic != b'LNET' or zlib.crc32(body, zlib.crc32(header[:16])) & 0xFFFFFFFF != crc:
        raise AssertionError('frame CRC or magic mismatch')
    return op, offset, bytes(body)


def send_reply(sock, op, status, body=b''):
    prefix = struct.pack('<4sIII', b'LNET', op, status, len(body))
    crc = zlib.crc32(body, zlib.crc32(prefix)) & 0xFFFFFFFF
    sock.sendall(prefix + struct.pack('<I', crc) + body)


def make_ack(session, ack_seq, expected_seq, expected_offset, credit, classification):
    return struct.pack('<6I', session, ack_seq, expected_seq, expected_offset,
                       credit, classification)


def test_raw_window_two_32k_logical_blocks_and_retry():
    host, device = socket.socketpair()
    host.settimeout(10)
    session = 0x7351C0
    logical_chunk = 32 * 1024
    package = bytes((i * 37) & 0xFF for i in range(FRAME_DATA_SIZE * 4))
    received, errors = {}, []
    progress = []

    # 两个最大数据帧连同外层头小于每连接 RX 环形缓存，窗口 2 有空间余量。
    assert FRAME_WIRE_SIZE * PIPELINE_WINDOW == 32808
    assert FRAME_WIRE_SIZE * PIPELINE_WINDOW < ACTIVE_RX_SIZE
    assert ACTIVE_RX_SIZE // FRAME_WIRE_SIZE >= PIPELINE_WINDOW

    def peer():
        try:
            op, target, hello = recv_frame(device)
            assert op == 31 and target == 1 and len(hello) == 16
            sid, requested_window, requested_frame, feature = struct.unpack('<4I', hello)
            assert (sid, requested_window, requested_frame, feature) == (
                session, 2, FRAME_DATA_SIZE, 1)
            caps = struct.pack('<6I', session, FRAME_DATA_SIZE, 2, 0, 0, 2)
            send_reply(device, 31 | 0x80000000, 0, caps)

            for sequence in (0, 1):
                op, packed, data = recv_frame(device)
                assert op == 33
                assert packed >> 8 == session and packed & 0xFF == sequence
                assert len(data) == FRAME_DATA_SIZE
                assert data == package[sequence * FRAME_DATA_SIZE:(sequence + 1) * FRAME_DATA_SIZE]
                received[sequence] = data
            # 累计 ACK 表示两个分包已经被开发板接收并写入 HEX 暂存区。
            send_reply(device, 33 | 0x80000000, 0,
                       make_ack(session, 1, 2, logical_chunk, 2, 0))

            for sequence in (2, 3):
                op, packed, data = recv_frame(device)
                assert op == 33
                assert packed >> 8 == session and packed & 0xFF == sequence
                assert len(data) == FRAME_DATA_SIZE
                assert data == package[sequence * FRAME_DATA_SIZE:(sequence + 1) * FRAME_DATA_SIZE]
                received[sequence] = data

            # 暂缓 ACK，确认工具箱会重传最早未确认帧，且设备可用重复 ACK 恢复。
            op, packed, duplicate = recv_frame(device)
            assert op == 33 and packed >> 8 == session and packed & 0xFF == 2
            assert duplicate == received[2]
            send_reply(device, 33 | 0x80000000, 0,
                       make_ack(session, 2, 4, len(package), 2, 1))
        except BaseException as exc:
            errors.append(exc)
        finally:
            device.close()

    worker = threading.Thread(target=peer, daemon=True)
    worker.start()
    result = upload_w78_window(
        host, package, logical_chunk, session, None,
        target=1, on_progress=lambda value, _total: progress.append(value),
    )
    host.close()
    worker.join(3)
    assert not worker.is_alive() and not errors, errors
    assert sorted(received) == [0, 1, 2, 3]
    assert result == (logical_chunk, FRAME_DATA_SIZE, 2, 1, True)
    assert progress == [logical_chunk, len(package)]


def test_old_16k_payload_pipeline_fallback():
    host, device = socket.socketpair()
    host.settimeout(10)
    session = 0x123456
    package = bytes((i * 11) & 0xFF for i in range(1000))
    errors = []

    def peer():
        try:
            op, target, hello = recv_frame(device)
            assert op == 31 and target == 1 and len(hello) == 16
            sid, window, requested, feature = struct.unpack('<4I', hello)
            assert (sid, window, requested, feature) == (session, 2, 16384, 1)
            # 老固件拒绝扩展协商头，工具箱必须回退到现有 op32 格式。
            send_reply(device, 31 | 0x80000000, 4)
            op, target, hello = recv_frame(device)
            assert op == 31 and target == 1 and len(hello) == 12
            sid, window, requested = struct.unpack('<III', hello)
            assert (sid, window, requested) == (session, 2, 16384)
            caps = struct.pack('<6I', session, W78_MAX_PAYLOAD - 8, 2, 0, 0, 2)
            send_reply(device, 31 | 0x80000000, 0, caps)

            op, sequence, payload = recv_frame(device)
            sid, offset = struct.unpack_from('<II', payload)
            assert op == 32 and sequence == 0 and sid == session and offset == 0
            assert payload[8:] == package
            send_reply(device, 32 | 0x80000000, 0,
                       make_ack(session, 0, 1, len(package), 2, 0))
        except BaseException as exc:
            errors.append(exc)
        finally:
            device.close()

    worker = threading.Thread(target=peer, daemon=True)
    worker.start()
    result = upload_w78_window(host, package, 32768, session, None, target=1)
    host.close()
    worker.join(3)
    assert not worker.is_alive() and not errors, errors
    assert result == (32768, W78_MAX_PAYLOAD - 8, 2, 0, False)


def test_legacy_sequential_fallback():
    host, device = socket.socketpair()
    def peer():
        op, _target, hello = recv_frame(device)
        assert op == 31 and len(hello) == 16
        send_reply(device, 31 | 0x80000000, 4)
        op, _target, hello = recv_frame(device)
        assert op == 31 and len(hello) == 12
        send_reply(device, 31 | 0x80000000, 11)
        device.close()
    worker = threading.Thread(target=peer, daemon=True)
    worker.start()
    assert upload_w78_window(host, b'HEX', 32768, 7, None, target=1) is None
    host.close()
    worker.join(2)
    assert not worker.is_alive()


def test_late_pipeline_ack_does_not_break_start_command():
    host, device = socket.socketpair()
    ignored, errors = [], []

    def peer():
        try:
            # 上一阶段的最后 op33 ACK 可能晚于 HEX 接收进度回调到达。
            send_reply(device, 33 | 0x80000000, 0, make_ack(0x51, 1, 2, 32768, 2, 0))
            op, target, body = recv_frame(device)
            assert (op, target, body) == (8, 1, b'')
            send_reply(device, 8 | 0x80000000, 0, struct.pack('<I', 0))
        except BaseException as exc:
            errors.append(exc)
        finally:
            device.close()

    worker = threading.Thread(target=peer, daemon=True)
    worker.start()
    body = request_wait(host, 8, 1, timeout=3, ignore_ops=(32, 33),
                        on_ignored=ignored.append)
    host.close()
    worker.join(2)
    assert not worker.is_alive() and not errors, errors
    assert body == struct.pack('<I', 0)
    assert ignored == [33 | 0x80000000]


if __name__ == '__main__':
    test_raw_window_two_32k_logical_blocks_and_retry()
    test_old_16k_payload_pipeline_fallback()
    test_legacy_sequential_fallback()
    test_late_pipeline_ack_does_not_break_start_command()
    print('W78 32 KiB logical blocks, raw-frame/window-2, retry, compatibility and late-ACK recovery passed')
