"""D133CBS CPIO 预检与工具箱 TCP 传输；不会直接操作 Flash 地址。"""
import hashlib
import json
import re
import socket
import struct
import time
from pathlib import Path
from local_tcp_client import frame, receive, DeviceError

PRODUCT = 'D133CBS'
HARDWARE = 'D133CBV-QFN88-V1-2'
PORT = 8899
INFO, BEGIN, DATA, COMMIT, SIGNATURE = range(0xD100, 0xD105)
HEALTH = 0xD105
LIMITS = {'ota_info.bin': 512, 'd13x_os.itb': 2*1024*1024, 'rodata.fatfs': 5*1024*1024}

def validate_cpio(data):
    """只接受官方 crc CPIO，校验成员、长度、加和及固定分区白名单。"""
    pos, members = 0, {}
    while pos + 110 <= len(data):
        h = data[pos:pos+110]
        if h[:6] != b'070702': raise ValueError('需要 ArtInChip crc 格式 ota.cpio')
        try: size, namesize, checksum = (int(h[a:a+8],16) for a in (54,94,102))
        except ValueError as exc: raise ValueError('CPIO 头字段无效') from exc
        if not 1 <= namesize <= 64 or pos+110+namesize > len(data): raise ValueError('CPIO 文件名字段无效')
        raw=data[pos+110:pos+110+namesize]
        if raw[-1:]!=b'\0':raise ValueError('CPIO 文件名没有结束符')
        name=raw[:-1].decode('ascii');start=(pos+110+namesize+3)&~3;end=start+size
        if end>len(data):raise ValueError('升级包被截断')
        if name=='TRAILER!!!':
            if size or set(members)!=set(LIMITS) or any(data[end:]):raise ValueError('升级包成员或尾部不完整')
            entries=[]
            for item in members['ota_info.bin'][4:].split(b'\0'):
                if not item or item.startswith(b'\xff'):break
                entries.append(item.decode('ascii').strip())
            if len(entries)!=7 or entries[0]!='[image]' or not entries[1].startswith('size = "') or not entries[1].endswith('";') or entries[3]!='[file]' or entries[4:]!=['ota_info.bin:file;','d13x_os.itb:os;','rodata.fatfs:rodata;']:
                raise ValueError('CPIO 仅允许 ota_info、OS、RODATA，禁止 SPL/DATA 映射')
            match=re.fullmatch(r'version\s*=\s*"(\d+\.\d+\.\d+)";',entries[2])
            size_match=re.fullmatch(r'size\s*=\s*"(\d+)";',entries[1])
            if not match or not size_match or int(size_match.group(1))!=len(data):raise ValueError('CPIO 版本或声明长度不正确')
            return match.group(1)
        if name not in LIMITS or name in members or size==0 or size>LIMITS[name]:raise ValueError('升级包包含重复、超限或不允许的成员：'+name)
        body=data[start:end]
        if sum(body)&0xffffffff!=checksum:raise ValueError('CPIO 成员校验失败：'+name)
        if not members and name!='ota_info.bin':raise ValueError('ota_info.bin 必须为首个成员')
        members[name]=body;pos=(end+3)&~3
    raise ValueError('升级包缺少完整 TRAILER!!!')

def _request(sock,op,offset=0,payload=b''):
    sock.sendall(frame(op,offset,payload))
    try: response,body=receive(sock)
    except DeviceError as exc:
        messages={3:'设备忙',4:'型号、硬件或版本不匹配',5:'SD 卡未就绪或容量不足',6:'传输偏移错误',9:'数据校验失败',14:'开发板拒绝升级或等待超时',20:'CPIO 包预检失败',21:'包版本与传输版本不一致',22:'SHA256 计算失败',23:'SHA256 不匹配',24:'RSA 固件签名验证失败',25:'官方 OTA 写入失败',26:'包成员未完整写入',27:'启动状态提交失败',28:'升级状态文件保存失败'}
        raise RuntimeError(messages.get(exc.status,'D133CBS 返回错误 '+str(exc.status))) from exc
    if response!=op:raise ValueError('D133 升级应答命令不匹配')
    return body

def _device_message(data,progress):
    """显示设备通过 LNET JSON 应答返回的兼容消息。"""
    try:message=json.loads(data.decode('utf-8')).get('device_message','')
    except (UnicodeDecodeError,ValueError,AttributeError):return
    if message:progress(0,'设备消息：'+message)

def _health_info(sock):
    """优先使用无提示音健康查询；旧固件未知命令时回退到原 INFO。"""
    try:body=_request(sock,HEALTH)
    except RuntimeError as exc:
        cause=exc.__cause__
        if not isinstance(cause,DeviceError) or cause.status!=11:raise
        body=_request(sock,INFO)
    return json.loads(body.decode('utf-8'))

def upload(host,port,path,progress,cancel):
    """工具箱后台线程传输；仅在重启后核对版本、槽位及健康状态才报告成功。"""
    data=Path(path).read_bytes();version=validate_cpio(data)
    signature=Path(str(path)+'.sig').read_bytes()
    if not 1<=len(signature)<=512:raise ValueError('需要有效的 RSA 签名文件 ota.cpio.sig')
    with socket.create_connection((host,int(port)),timeout=10) as sock:
        sock.settimeout(180);info=json.loads(_request(sock,INFO).decode('utf-8'))
        _device_message(json.dumps(info,ensure_ascii=False).encode('utf-8'),progress)
        if info.get('product')!=PRODUCT or info.get('hardware')!=HARDWARE or info.get('protocol')!=1:raise ValueError('目标不是兼容的 D133CBS OTA 服务')
        current=tuple(map(int,info['version'].split('.')))
        if tuple(map(int,version.split('.')))<=current:raise ValueError('升级包版本必须高于当前固件 '+info['version'])
        metadata=struct.pack('<I32s32s32s32s',len(data),hashlib.sha256(data).digest(),PRODUCT.encode(),HARDWARE.encode(),version.encode())
        begin_reply=_request(sock,BEGIN,payload=metadata)
        _device_message(begin_reply,progress)
        for offset in range(0,len(data),16384):
            if cancel.is_set():raise InterruptedError('已停止，暂存包不会激活')
            block=data[offset:offset+16384];ack=_request(sock,DATA,offset,block)
            if ack!=struct.pack('<I',offset+len(block)):raise ValueError('设备下载进度不匹配')
            progress((offset+len(block))*100//len(data),'正在接收升级包')
        if cancel.is_set():raise InterruptedError('已停止，尚未提交升级')
        _request(sock,SIGNATURE,payload=signature)
        progress(100,'请在开发板屏幕确认；等待校验、写入和重启，提交后请勿断电')
        ack=_request(sock,COMMIT)
        if ack!=struct.pack('<I',len(data)):raise ValueError('升级提交应答长度错误')
    progress(100,'已提交；等待设备重启及健康检查')
    deadline=time.monotonic()+420
    while time.monotonic()<deadline:
        if cancel.is_set():raise InterruptedError('OTA 已提交；已停止等待，新系统健康状态尚未确认')
        time.sleep(2)
        try:
            with socket.create_connection((host,int(port)),timeout=3) as check:
                check.settimeout(5);state=_health_info(check)
                elapsed=420-(deadline-time.monotonic())
                if state.get('version')==version and state.get('confirmed') and state.get('slot')==state.get('next_slot'):
                    progress(100,'升级完成；新系统版本、槽位和健康状态已确认');return version
                if elapsed>30 and state.get('version')==info.get('version') and state.get('confirmed') and state.get('slot')==state.get('next_slot'):
                    raise RuntimeError('Bootloader 已回滚 OS 与 RODATA 到原版本 '+info['version'])
        except (OSError,ValueError):pass
    raise RuntimeError('OTA 已提交；420 秒内未确认新系统健康，请检查开发板状态及回滚日志')

