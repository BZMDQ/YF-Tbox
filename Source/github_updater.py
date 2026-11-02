"""研发工具箱 GitHub 私有仓库更新客户端。"""

from __future__ import annotations

import base64
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import urllib.error
import urllib.request
import zipfile
from pathlib import PurePosixPath


GITHUB_REPOSITORY = "BZMDQ/YF-Tbox"
GITHUB_API = "https://api.github.com"
MAX_UPDATE_BYTES = 1024 * 1024 * 1024


class _DataBlob(ctypes.Structure):
    _fields_ = [("cbData", ctypes.c_uint32), ("pbData", ctypes.c_void_p)]


def _blob(data: bytes):
    buffer = ctypes.create_string_buffer(data, len(data))
    return _DataBlob(len(data), ctypes.cast(buffer, ctypes.c_void_p)), buffer


def protect_token(token: str) -> str:
    """用当前 Windows 用户的 DPAPI 加密只读 GitHub Token。"""
    token = str(token or "").strip()
    if not token:
        return ""
    if os.name != "nt":
        raise RuntimeError("GitHub 更新凭据只能在 Windows 上加密保存。")
    source, keepalive = _blob(token.encode("utf-8"))
    target = _DataBlob()
    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    crypt32.CryptProtectData.argtypes = [
        ctypes.POINTER(_DataBlob), ctypes.c_wchar_p, ctypes.c_void_p,
        ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32,
        ctypes.POINTER(_DataBlob),
    ]
    crypt32.CryptProtectData.restype = ctypes.c_int
    if not crypt32.CryptProtectData(ctypes.byref(source), "YF-Tbox read-only token",
                                    None, None, None, 0, ctypes.byref(target)):
        raise ctypes.WinError()
    try:
        return base64.b64encode(ctypes.string_at(target.pbData, target.cbData)).decode("ascii")
    finally:
        kernel32.LocalFree(ctypes.c_void_p(target.pbData))
        del keepalive


def unprotect_token(ciphertext: str) -> str:
    """读取 DPAPI 加密的 Token；不能解密时返回空值，避免卡住启动。"""
    if not ciphertext or os.name != "nt":
        return ""
    try:
        encrypted = base64.b64decode(ciphertext.encode("ascii"), validate=True)
        source, keepalive = _blob(encrypted)
        target = _DataBlob()
        crypt32 = ctypes.windll.crypt32
        kernel32 = ctypes.windll.kernel32
        crypt32.CryptUnprotectData.argtypes = [
            ctypes.POINTER(_DataBlob), ctypes.c_void_p, ctypes.c_void_p,
            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32,
            ctypes.POINTER(_DataBlob),
        ]
        crypt32.CryptUnprotectData.restype = ctypes.c_int
        if not crypt32.CryptUnprotectData(ctypes.byref(source), None, None, None,
                                          None, 0, ctypes.byref(target)):
            return ""
        try:
            return ctypes.string_at(target.pbData, target.cbData).decode("utf-8")
        finally:
            kernel32.LocalFree(ctypes.c_void_p(target.pbData))
            del keepalive
    except (OSError, ValueError, TypeError, UnicodeError):
        return ""


def _request(url: str, token: str, accept: str):
    headers = {
        "Accept": accept,
        "User-Agent": "YF-Tbox-Updater",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = "Bearer " + token
    request = urllib.request.Request(url, headers=headers)
    return urllib.request.urlopen(request, timeout=30)


def _api_error(exc: urllib.error.HTTPError) -> str:
    if exc.code in (401, 403):
        return "GitHub 请求被拒绝或受到频率限制；可配置仅 YF-Tbox Contents 只读 Token 后重试。"
    if exc.code == 404:
        return "YF-Tbox 暂无可访问的最新 Release；若仓库设为私有，请配置只读 Token。"
    return "GitHub 请求失败（HTTP {}）。".format(exc.code)


def parse_version(value: str):
    """将 v0.8.35 等标签解析为可比较的整数版本。"""
    match = re.search(r"(?:^|[^0-9])v?(\d+)\.(\d+)\.(\d+)(?:$|[^0-9])", str(value or ""))
    if not match:
        raise ValueError("GitHub Release 标签格式应为 v主版本.次版本.修订号。")
    return tuple(int(part) for part in match.groups())


def latest_update(current_version: str, token: str):
    """读取最新 Release；只接受完整的 onedir ZIP 与 SHA-256 侧车文件。"""
    url = GITHUB_API + "/repos/{}/releases/latest".format(GITHUB_REPOSITORY)
    try:
        with _request(url, token, "application/vnd.github+json") as response:
            release = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raise RuntimeError(_api_error(exc)) from exc
    except (OSError, ValueError, UnicodeError) as exc:
        raise RuntimeError("连接 GitHub 失败：{}".format(exc)) from exc

    version = str(release.get("tag_name") or "")
    release_version = parse_version(version)
    if release_version <= parse_version(current_version):
        return {"available": False, "version": version, "release": release}

    assets = release.get("assets") or []
    package = next((item for item in assets if str(item.get("name", "")).lower().endswith(
        "_update.zip")), None)
    if package is None:
        raise RuntimeError("最新 Release 缺少 Windows 原位更新 ZIP。")
    checksum_name = str(package.get("name", "")) + ".sha256"
    checksum = next((item for item in assets if item.get("name") == checksum_name), None)
    if checksum is None:
        raise RuntimeError("最新 Release 缺少 ZIP 的 SHA-256 校验文件。")
    size = int(package.get("size") or 0)
    if size <= 0 or size > MAX_UPDATE_BYTES:
        raise RuntimeError("更新包大小无效或超过 1 GiB。")
    return {
        "available": True,
        "version": version,
        "release": release,
        "package": package,
        "checksum": checksum,
    }


def _download_asset(asset, token: str, destination: Path, progress=None):
    asset_id = int(asset["id"])
    url = GITHUB_API + "/repos/{}/releases/assets/{}".format(GITHUB_REPOSITORY, asset_id)
    temporary = destination.with_name(destination.name + ".part")
    total = int(asset.get("size") or 0)
    received = 0
    try:
        with _request(url, token, "application/octet-stream") as response:
            with temporary.open("wb") as output:
                while True:
                    chunk = response.read(1024 * 1024)
                    if not chunk:
                        break
                    received += len(chunk)
                    if received > MAX_UPDATE_BYTES:
                        raise RuntimeError("下载包超过 1 GiB 上限，已中止。")
                    output.write(chunk)
                    if progress:
                        progress(received, total)
        if total and received != total:
            raise RuntimeError("GitHub 下载大小不符：收到 {} / {} 字节。".format(received, total))
        temporary.replace(destination)
        return destination
    except urllib.error.HTTPError as exc:
        raise RuntimeError(_api_error(exc)) from exc
    except Exception:
        try:
            temporary.unlink()
        except OSError:
            pass
        raise


def download_update(update, token: str, cache_dir, progress=None):
    """下载 Release ZIP 和校验文件，验证通过后才返回可安装的 ZIP。"""
    cache = Path(cache_dir)
    cache.mkdir(parents=True, exist_ok=True)
    package = update["package"]
    checksum_asset = update["checksum"]
    name = Path(str(package.get("name", ""))).name
    if not name.lower().endswith(".zip") or name in ("", ".", ".."):
        raise ValueError("Release 更新包文件名无效。")
    archive = cache / name
    checksum_file = cache / (name + ".sha256")
    _download_asset(package, token, archive, progress)
    _download_asset(checksum_asset, token, checksum_file)
    match = re.search(r"\b([0-9a-fA-F]{64})\b", checksum_file.read_text(encoding="ascii", errors="replace"))
    if not match:
        raise RuntimeError("Release SHA-256 文件格式无效。")
    digest = hashlib.sha256()
    with archive.open("rb") as source:
        while True:
            chunk = source.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    if digest.hexdigest().lower() != match.group(1).lower():
        try:
            archive.unlink()
        except OSError:
            pass
        raise RuntimeError("更新包 SHA-256 校验失败，已拒绝安装。")
    # 安装前拒绝绝对路径、父目录跳转与跨盘符条目，阻止 ZIP 路径逃逸。
    try:
        with zipfile.ZipFile(archive, "r") as package_zip:
            entries = package_zip.infolist()
            if not entries or len(entries) > 20000:
                raise RuntimeError("更新包文件清单无效。")
            roots = set()
            for entry in entries:
                path = PurePosixPath(entry.filename.replace("\\", "/"))
                if (path.is_absolute() or not path.parts or
                        any(part in ("", ".", "..") or ":" in part for part in path.parts)):
                    raise RuntimeError("更新包包含不安全的文件路径。")
                roots.add(path.parts[0])
            expected_root = "研发工具箱_{}_Update".format(
                update["version"].lstrip("v"))
            if roots != {expected_root}:
                raise RuntimeError("原位更新包目录名称与 Release 版本不一致。")
    except zipfile.BadZipFile as exc:
        raise RuntimeError("下载的更新包不是有效 ZIP。") from exc
    return archive
