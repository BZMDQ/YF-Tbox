"""PIC24FJ256DA210 Intel HEX 读取；此模块不执行擦写。"""

from pathlib import Path
import argparse

# PIC24 的 HEX 使用四字节表示一个 24 位指令，第四字节为填充。
PROGRAM_END = 0x55800
CONFIG_START = 0x557F0


def parse_pic24_hex(text):
    """校验记录、地址及重复数据，返回地址到字节的映射。"""
    memory = {}
    base = 0
    eof = False
    lines = text.splitlines()
    for number, line in enumerate(lines, 1):
        line = line.strip()
        if not line:
            continue
        if eof:
            raise ValueError("第 %d 行：结束记录之后仍有数据" % number)
        if not line.startswith(":") or any(c not in "0123456789abcdefABCDEF" for c in line[1:]):
            raise ValueError("第 %d 行：缺少记录起始符" % number)
        try:
            record = bytes.fromhex(line[1:])
        except ValueError as exc:
            raise ValueError("第 %d 行：十六进制数据无效" % number) from exc
        if len(record) < 5 or len(record) != record[0] + 5:
            raise ValueError("第 %d 行：记录长度无效" % number)
        if sum(record) & 0xff:
            raise ValueError("第 %d 行：校验和错误" % number)
        count = record[0]
        offset = (record[1] << 8) | record[2]
        kind = record[3]
        data = record[4:-1]
        if kind == 0:
            # 一条数据记录不能跨越 16 位地址窗口。
            if offset + count > 0x10000:
                raise ValueError("第 %d 行：数据跨越地址窗口" % number)
            for index, value in enumerate(data):
                address = base + offset + index
                if address >= PROGRAM_END:
                    raise ValueError("第 %d 行：地址 0x%X 不在支持的程序空间内" % (number, address))
                if address in memory and memory[address] != value:
                    raise ValueError("第 %d 行：地址 0x%X 数据冲突" % (number, address))
                memory[address] = value
        elif kind == 1:
            if count or offset:
                raise ValueError("第 %d 行：结束记录无效" % number)
            eof = True
        elif kind in (2, 4):
            if count != 2 or offset:
                raise ValueError("第 %d 行：扩展地址记录无效" % number)
            base = int.from_bytes(data, "big") << (4 if kind == 2 else 16)
        else:
            raise ValueError("第 %d 行：不支持记录类型 %d" % (number, kind))
    if not eof or not memory:
        raise ValueError("HEX 缺少数据或结束记录")
    return memory


def validate_pic24_hex(path):
    """检查完整 PIC24 程序和关键配置字，返回可上传的原始记录。"""
    path = Path(path)
    if path.suffix.lower() != '.hex':
        raise ValueError('PIC24 烧录只接受 .hex 文件')
    data = path.read_bytes()
    if data.endswith(b'\x1a'):
        data = data[:-1]
    if not 0 < len(data) <= 2 * 1024 * 1024:
        raise ValueError('PIC24 HEX 文件大小必须在 1 字节到 2 MiB 之间')
    text = data.decode('ascii')
    memory = parse_pic24_hex(text)
    for address in (0x557F8, 0x557F9, 0x557FC, 0x557FD):
        if address not in memory:
            raise ValueError('HEX 缺少 CW1/CW2 配置字；请导出完整的生产 HEX')
    if memory[0x557FD] & 0x80:
        raise ValueError('CW1 保留位 15 必须为 0；请检查 PIC24 工程配置')
    # 规范空白与行尾，使电脑端通过的内容与开发板实际接收内容一致。
    return ('\n'.join(line.strip() for line in text.splitlines() if line.strip()) + '\n').encode('ascii')
