from __future__ import annotations

import base64
import ctypes
import os
from pathlib import Path, PurePosixPath
import queue
import shutil
import subprocess
import sys
import tempfile
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import zipfile

APP_NAME = '研发工具箱'
APP_VERSION = '0.8.39'
PAYLOAD_FILE = 'toolbox_payload.zip'
EXE_NAME = 'ResearchToolbox_' + APP_VERSION + '.exe'
PAYLOAD_ROOT = APP_NAME + '_' + APP_VERSION + '_Onedir_Portable_Windows'


def bundle_file(name):
    root = Path(getattr(sys, '_MEIPASS', Path(__file__).resolve().parent))
    return root / name


def suggested_directory():
    try:
        import winreg
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r'Software\CSV0\ResearchToolbox')
        value, _ = winreg.QueryValueEx(key, 'InstallDir')
        winreg.CloseKey(key)
        if value:
            return Path(value)
    except (OSError, ImportError):
        pass
    local = Path(os.environ.get('LOCALAPPDATA') or Path.home())
    return local / 'Programs' / APP_NAME


def encode_ps(text):
    return base64.b64encode(text.encode('utf-16le')).decode('ascii')


def run_powershell(text):
    encoded = encode_ps(text)
    flags = getattr(subprocess, 'CREATE_NO_WINDOW', 0)
    return subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive',
                           '-ExecutionPolicy', 'Bypass', '-EncodedCommand', encoded],
                          stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, timeout=25, creationflags=flags,
                          check=False)


def desktop_directory():
    try:
        path = ctypes.create_unicode_buffer(32768)
        result = ctypes.windll.shell32.SHGetFolderPathW(None, 0x10, None, 0, path)
        if result == 0 and path.value:
            return Path(path.value)
    except (AttributeError, OSError):
        pass
    return Path(os.environ.get('USERPROFILE') or Path.home()) / 'Desktop'


def install_shortcuts(directory, desktop):
    exe = directory / EXE_NAME
    menu = Path(os.environ.get('APPDATA') or Path.home()) / 'Microsoft' / 'Windows' / 'Start Menu' / 'Programs' / APP_NAME
    desk = desktop_directory() / (APP_NAME + '.lnk')
    values = [str(directory), str(exe), str(menu), str(desk)]
    encoded = [base64.b64encode(v.encode('utf-8')).decode('ascii') for v in values]
    command = f"""
$ErrorActionPreference='Stop'
function D($s) {{ [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($s)) }}
$dir=D('{encoded[0]}'); $exe=D('{encoded[1]}'); $menu=D('{encoded[2]}'); $desk=D('{encoded[3]}')
New-Item -ItemType Directory -Path $menu -Force | Out-Null
$ws=New-Object -ComObject WScript.Shell
$l=$ws.CreateShortcut((Join-Path $menu '{APP_NAME}.lnk')); $l.TargetPath=$exe; $l.WorkingDirectory=$dir; $l.IconLocation="$exe,0"; $l.Save()
"""
    if desktop:
        command += "New-Item -ItemType Directory -Path (Split-Path -Parent $desk) -Force | Out-Null\n"
        command += "$l=$ws.CreateShortcut($desk); $l.TargetPath=$exe; $l.WorkingDirectory=$dir; $l.IconLocation=\"$exe,0\"; $l.Save()\n"
        command += "if(-not (Test-Path -LiteralPath $desk -PathType Leaf)){throw '桌面快捷方式创建后未找到'}\n"
    return run_powershell(command)


class Installer:
    def __init__(self, root):
        self.root = root
        self.root.title('安装 ' + APP_NAME)
        self.root.geometry('700x480')
        self.root.resizable(False, False)
        self.root.configure(bg='#FFFFFF')
        try:
            self.root.iconbitmap(str(bundle_file('research_toolbox.ico')))
        except tk.TclError:
            pass
        self.events = queue.Queue()
        self.installing = False
        self.target = tk.StringVar(value=str(suggested_directory()))
        self.desktop = tk.BooleanVar(value=True)
        self.launch = tk.BooleanVar(value=True)
        self._build()

    def _build(self):
        header = tk.Frame(self.root, bg='#EFF6FF', height=112)
        header.pack(fill='x')
        header.pack_propagate(False)
        try:
            from PIL import Image, ImageTk
            logo = Image.open(bundle_file('wslogo.png')).convert('RGBA')
            logo.thumbnail((180, 86), Image.Resampling.LANCZOS)
            self.logo = ImageTk.PhotoImage(logo)
            tk.Label(header, image=self.logo, bg='#EFF6FF').pack(side='left', padx=(22, 18), pady=12)
        except Exception:
            pass
        tk.Label(header, text='安装 ' + APP_NAME, bg='#EFF6FF', fg='#17212F',
                 font=('Segoe UI', 19, 'bold')).pack(anchor='w', pady=(22, 2))
        tk.Label(header, text='选择安装位置，然后点击“安装”', bg='#EFF6FF', fg='#52647A',
                 font=('Segoe UI', 10)).pack(anchor='w')

        body = tk.Frame(self.root, bg='#FFFFFF', padx=28, pady=22)
        body.pack(fill='both', expand=True)
        tk.Label(body, text='安装目录', bg='#FFFFFF', fg='#17212F',
                 font=('Segoe UI', 11, 'bold')).pack(anchor='w')
        row = tk.Frame(body, bg='#FFFFFF')
        row.pack(fill='x', pady=(8, 4))
        self.path_entry = tk.Entry(row, textvariable=self.target, relief='solid', bd=1,
                                   font=('Segoe UI', 10))
        self.path_entry.pack(side='left', fill='x', expand=True, ipady=8)
        self.browse = tk.Button(row, text='浏览…', command=self._browse,
                                bg='#EAF2FF', fg='#1D4ED8', relief='flat',
                                font=('Segoe UI', 10, 'bold'), padx=16, pady=6)
        self.browse.pack(side='left', padx=(10, 0))
        tk.Label(body, text='可安装到任意有写入权限的文件夹。配置和设备名称数据会保留。',
                 bg='#FFFFFF', fg='#64748B', font=('Segoe UI', 9)).pack(anchor='w', pady=(3, 18))

        self.desktop_box = tk.Checkbutton(body, text='在桌面创建快捷方式', variable=self.desktop,
                                          bg='#FFFFFF', activebackground='#FFFFFF', fg='#334155',
                                          font=('Segoe UI', 10))
        self.desktop_box.pack(anchor='w', pady=2)
        self.launch_box = tk.Checkbutton(body, text='安装完成后启动工具箱', variable=self.launch,
                                         bg='#FFFFFF', activebackground='#FFFFFF', fg='#334155',
                                         font=('Segoe UI', 10))
        self.launch_box.pack(anchor='w', pady=2)

        self.status = tk.StringVar(value='准备就绪')
        tk.Label(body, textvariable=self.status, bg='#FFFFFF', fg='#334155',
                 font=('Segoe UI', 10)).pack(anchor='w', pady=(22, 7))
        self.progress = ttk.Progressbar(body, mode='determinate', maximum=100)
        self.progress.pack(fill='x')

        footer = tk.Frame(self.root, bg='#F5F7FA', padx=24, pady=14)
        footer.pack(fill='x', side='bottom')
        self.close_button = tk.Button(footer, text='关闭', command=self.root.destroy,
                                      bg='#FFFFFF', fg='#334155', relief='solid', bd=1,
                                      font=('Segoe UI', 10), padx=22, pady=8)
        self.close_button.pack(side='right')
        self.install_button = tk.Button(footer, text='安装', command=self._install,
                                        bg='#2563EB', fg='#FFFFFF', activebackground='#1D4ED8',
                                        activeforeground='#FFFFFF', relief='flat',
                                        font=('Segoe UI', 10, 'bold'), padx=26, pady=9)
        self.install_button.pack(side='right', padx=(0, 10))

    def _browse(self):
        current = self.target.get().strip()
        initial = current if Path(current).is_dir() else str(Path(current).parent)
        chosen = filedialog.askdirectory(title='选择工具箱安装目录', initialdir=initial,
                                         mustexist=False, parent=self.root)
        if chosen:
            self.target.set(chosen)

    def _install(self):
        if self.installing:
            return
        raw = self.target.get().strip().strip('"')
        if not raw:
            messagebox.showerror('安装目录无效', '请填写安装目录。', parent=self.root)
            return
        destination = Path(raw).expanduser()
        if not destination.is_absolute():
            messagebox.showerror('安装目录无效', '请填写完整的绝对路径。', parent=self.root)
            return
        if destination.exists() and (destination / EXE_NAME).exists():
            if not messagebox.askyesno('更新工具箱', '此目录已安装同版本工具箱，将覆盖程序文件并保留配置。继续吗？', parent=self.root):
                return
        payload = bundle_file(PAYLOAD_FILE)
        if not payload.is_file():
            messagebox.showerror('安装包缺失', '找不到工具箱数据包，请重新下载完整安装程序。', parent=self.root)
            return
        self.installing = True
        for widget in (self.install_button, self.close_button, self.browse, self.desktop_box, self.launch_box, self.path_entry):
            widget.configure(state='disabled')
        self.status.set('正在准备安装…')
        threading.Thread(target=self._worker, args=(destination, payload, bool(self.desktop.get())), daemon=True).start()
        self.root.after(100, self._poll)

    def _worker(self, destination, payload, desktop):
        try:
            destination.mkdir(parents=True, exist_ok=True)
            root = destination.resolve()
            with zipfile.ZipFile(payload, 'r') as archive:
                entries = []
                total = 0
                for info in archive.infolist():
                    path = PurePosixPath(info.filename)
                    if not path.parts or path.parts[0] != PAYLOAD_ROOT or any(part in ('..', '') for part in path.parts):
                        raise ValueError('安装包内含无效文件路径。')
                    if info.is_dir() or len(path.parts) == 1:
                        continue
                    relative = Path(*path.parts[1:])
                    target = (root / relative).resolve()
                    try:
                        target.relative_to(root)
                    except ValueError:
                        raise ValueError('安装包文件超出目标目录。')
                    entries.append((info, target, relative))
                    total += info.file_size
                copied = 0
                for info, target, relative in entries:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with archive.open(info, 'r') as src, target.open('wb') as dst:
                        while True:
                            chunk = src.read(1024 * 1024)
                            if not chunk:
                                break
                            dst.write(chunk)
                            copied += len(chunk)
                            self.events.put(('progress', copied * 100 / max(total, 1), '正在安装：' + relative.name))
            shortcut = install_shortcuts(root, desktop)
            shortcut_note = ''
            if shortcut.returncode:
                shortcut_note = '快捷方式创建失败；可直接运行安装目录中的 ' + EXE_NAME
            try:
                import winreg
                key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, r'Software\CSV0\ResearchToolbox')
                winreg.SetValueEx(key, 'InstallDir', 0, winreg.REG_SZ, str(root))
                winreg.CloseKey(key)
            except OSError:
                pass
            self.events.put(('done', (str(root), shortcut_note)))
        except Exception as exc:
            self.events.put(('error', str(exc)))

    def _poll(self):
        try:
            while True:
                event, value, *extra = self.events.get_nowait()
                if event == 'progress':
                    self.progress['value'] = value
                    self.status.set(extra[0])
                elif event == 'done':
                    directory, shortcut_note = value
                    self.installing = False
                    self.progress['value'] = 100
                    self.status.set('安装完成：' + directory)
                    self.install_button.configure(text='安装完成', state='disabled')
                    self.close_button.configure(state='normal')
                    if shortcut_note:
                        messagebox.showwarning(
                            '安装完成，但快捷方式创建失败',
                            shortcut_note + '\n\n安装目录：' + directory,
                            parent=self.root,
                        )
                    if self.launch.get():
                        exe = Path(directory) / EXE_NAME
                        try:
                            subprocess.Popen([str(exe)], cwd=str(exe.parent))
                        except OSError as exc:
                            messagebox.showerror('无法启动工具箱', str(exc), parent=self.root)
                elif event == 'error':
                    self.installing = False
                    self.status.set('安装失败')
                    for widget in (self.install_button, self.close_button, self.browse, self.desktop_box, self.launch_box, self.path_entry):
                        widget.configure(state='normal')
                    messagebox.showerror('安装失败', value + '\n\n请检查目标文件夹写入权限。', parent=self.root)
        except queue.Empty:
            pass
        if self.installing:
            self.root.after(100, self._poll)


def main():
    if len(sys.argv) == 3 and sys.argv[1] == '--verify-payload':
        import hashlib
        import json
        payload = bundle_file(PAYLOAD_FILE)
        with zipfile.ZipFile(payload, 'r') as archive:
            bad = archive.testzip()
            expected = PAYLOAD_ROOT + '/' + EXE_NAME
            if bad or expected not in archive.namelist():
                raise ValueError('内置安装数据包不完整')
            report = {'ok': True, 'payload': PAYLOAD_FILE,
                      'sha256': hashlib.sha256(payload.read_bytes()).hexdigest(),
                      'entries': len(archive.infolist()), 'exe': expected}
        Path(sys.argv[2]).write_text(json.dumps(report, ensure_ascii=False), encoding='utf-8')
        return
    root = tk.Tk()
    Installer(root)
    root.mainloop()


if __name__ == '__main__':
    main()
