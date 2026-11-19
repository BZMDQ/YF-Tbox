"""用研发工具箱 LNET 协议切换 D133 屏幕型号。"""
import argparse
import getpass
from pathlib import Path
import re
import socket

from local_tcp_client import frame, receive


def switch_screen(host, code, key, port=5000):
    if code not in ("CS000", "CS001"):
        raise ValueError("屏幕型号须为 CS000 或 CS001")
    key = key.strip().lower()
    if not re.fullmatch(r"[0-9a-f]{32}", key):
        raise ValueError("请输入 32 位十六进制工具箱 Key")
    with socket.create_connection((host, port), timeout=5) as connection:
        connection.sendall(frame(0, payload=key.encode("ascii")))
        if receive(connection) != (0x80000000, b""):
            raise ValueError("认证响应不匹配")
        connection.sendall(frame(28, payload=code.encode("ascii")))
        operation, body = receive(connection)
        if operation != 0x8000001C or body not in (b"", b"REBOOTING"):
            raise ValueError("切屏响应不匹配")
        return body == b"REBOOTING"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("host")
    parser.add_argument("code", choices=("CS000", "CS001"))
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--key-file", type=Path)
    args = parser.parse_args()
    secret = args.key_file.read_text(encoding="ascii") if args.key_file else getpass.getpass("工具箱 Key: ")
    if switch_screen(args.host, args.code, secret, args.port):
        print("设备已接受切换并开始重启。请重连后确认分辨率。")
    else:
        print("当前屏幕型号已匹配。")
