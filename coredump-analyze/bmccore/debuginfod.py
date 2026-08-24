# -*- coding: utf-8 -*-
"""debuginfod 远程符号客户端：按 build-id 从 HTTP 服务器拉取符号文件。

debuginfod 是 elfutils 生态的标准符号分发协议（RFC：ELF Build-ID Server）。
编译服务器无本地符号时，可从远程 debuginfod 服务器按 build-id 拉取。

用法（bmccore.toml）:
    debuginfod_url = "http://debuginfod.example.com:8002"
    # 或环境变量 DEBUGINFOD_URLS（标准方式）
"""
import os
import shutil
import tempfile
import urllib.request


def _get_urls(config=None):
    """获取 debuginfod 服务器 URL 列表（配置 > 环境变量）。"""
    urls = []
    if config and getattr(config, "debuginfod_url", None):
        urls.append(config.debuginfod_url)
    env = os.environ.get("DEBUGINFOD_URLS", "")
    if env:
        urls.extend(u.strip() for u in env.split() if u.strip())
    return urls


def _cache_dir():
    """debuginfod 标准缓存目录。"""
    xdg = os.environ.get("XDG_CACHE_HOME", os.path.expanduser("~/.cache"))
    d = os.path.join(xdg, "debuginfod_client")
    os.makedirs(d, exist_ok=True)
    return d


def fetch_debuginfo(build_id, config=None, timeout=30):
    """按 build-id 从 debuginfod 服务器拉取调试文件。

    返回本地文件路径；拉不到返回 None。
    URL 格式: {server}/buildid/{build_id}/debuginfo
    """
    urls = _get_urls(config)
    if not urls or not build_id:
        return None

    # 缓存检查
    cache_path = os.path.join(_cache_dir(), build_id, "debuginfo")
    if os.path.isfile(cache_path) and os.path.getsize(cache_path) > 0:
        return cache_path

    for base_url in urls:
        url = "%s/buildid/%s/debuginfo" % (base_url.rstrip("/"), build_id)
        try:
            req = urllib.request.Request(url)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if resp.status != 200:
                    continue
                data = resp.read()
                if len(data) < 64:
                    continue
                # 写入缓存
                os.makedirs(os.path.dirname(cache_path), exist_ok=True)
                tmp = cache_path + ".tmp"
                with open(tmp, "wb") as f:
                    f.write(data)
                os.rename(tmp, cache_path)
                return cache_path
        except Exception:
            continue

    return None


def fetch_symbols_for_core(core_modules, config=None):
    """为一组 core 模块批量拉取 debuginfo。

    core_modules: [(module_name, build_id), ...]
    返回 {module_name: local_path}。
    """
    result = {}
    for name, bid in core_modules:
        if not bid:
            continue
        path = fetch_debuginfo(bid, config)
        if path:
            result[name] = path
    return result
