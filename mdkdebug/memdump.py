# -*- coding: utf-8 -*-
"""内存区间转储（批次106）：把目标 RAM/Flash 的一段读成文件（bin / Intel HEX / hexdump）。

为什么单独做成一个工具
----------------------
`read_mem` 一次最多搬一块（UVSOCK 单命令有上限），读 64 KB 就要来回几十次，
而 AI 的上下文放不下几万字节的十六进制串；更要紧的是**中间某块读失败时没有任何交代**——
人会以为「整段读回来了」。本模块把这件事做成一件事：

  - 分块搬运，**每块失败都记账**（gaps + complete=false），失败的块按 0xFF 填，
    不假装读到（Flash 擦除态就是 0xFF，同时 `gap_fill=0x00` 可换成全 0）；
  - 落盘走文件而不是上下文（bin / Intel HEX / 可读 hexdump 三种），
    iHEX 处理 >64 KB 的扩展线性地址与 64 KB 边界不跨记录；
  - `resume=true` 依据已有 bin 的长度从断点续传（大 RAM/外部 Flash 经常读一半断线）；
  - 给 sha256 + 吞吐 + 有效字节数，便于和另一份 dump 比对（如烧录前后）。

本模块只依赖一个 `read(addr, n) -> bytes` 回调（server 侧接 client.read_mem），
不 import uvsock，便于用假目标单测。
"""
from __future__ import annotations

import hashlib
import os
import time

CHUNK_DEFAULT = 4096
MAX_BYTES_DEFAULT = 8 * 1024 * 1024
FORMATS = ("bin", "ihex", "hexdump")


def ihex_records(addr: int, data: bytes, record_len: int = 16, upper=None):
    """生成 Intel HEX 记录行（不含 EOF）。

    返回 (lines, upper)。`upper` 是当前已声明的扩展线性地址高 16 位，
    分批追加时把它传回来可以避免重复声明。记录的地址字段是 16 位，
    所以**一条记录不跨 64 KB 边界**（跨界的后半段由下一条记录接着写）。
    """
    lines = []
    off = 0
    n_total = len(data)
    record_len = max(1, min(int(record_len or 16), 255))
    while off < n_total:
        cur = int(addr + off)
        hi = (cur >> 16) & 0xFFFF
        if upper != hi:
            body = bytes([0x02, 0x00, 0x00, 0x04, (hi >> 8) & 0xFF, hi & 0xFF])
            lines.append(":" + (body + _checksum(body)).hex().upper())
            upper = hi
        room = 0x10000 - (cur & 0xFFFF)
        n = min(record_len, n_total - off, room)
        lo = cur & 0xFFFF
        body = bytes([n, (lo >> 8) & 0xFF, lo & 0xFF, 0x00]) + bytes(data[off:off + n])
        lines.append(":" + (body + _checksum(body)).hex().upper())
        off += n
    return lines, upper


def _checksum(body: bytes) -> bytes:
    return bytes([(-sum(body)) & 0xFF])


def ihex_eof() -> str:
    return ":00000001FF"


def resume_size(path: str) -> int:
    """已有文件的字节数（续传起点）；文件不存在返回 0。"""
    try:
        return int(os.path.getsize(path))
    except OSError:
        return 0


def _hexdump_lines(addr: int, data: bytes, width: int = 16) -> list:
    out = []
    for off in range(0, len(data), width):
        chunk = data[off:off + width]
        hx = " ".join("%02X" % b for b in chunk)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        out.append("%08X  %-*s  |%s|" % (addr + off, width * 3 - 1, hx, asc))
    return out


def dump(read, addr: int, size: int, path: str, fmt: str = "bin",
         chunk: int = CHUNK_DEFAULT, resume: bool = False,
         overwrite: bool = False, fill: int = 0xFF) -> dict:
    """把 [addr, addr+size) 读成文件。

    read(addr, n) 返回 bytes；抛异常或返回不足 n 字节都算「这一块没读到」，
    会按 fill 补满并记进 gaps（`complete=false`）。
    """
    t0 = time.time()
    fmt = str(fmt or "bin").strip().lower()
    if fmt not in FORMATS:
        return {"ok": False, "error": "format 只支持 %s，收到: %r"
                                      % ("/".join(FORMATS), fmt)}
    addr = int(addr)
    size = int(size)
    if size <= 0:
        return {"ok": False, "error": "size 必须是正整数（要转储多少字节）"}
    if size > MAX_BYTES_DEFAULT:
        return {"ok": False,
                "error": "一次转储 %d 字节超过上限 %d（防止手误把整片地址空间拉下来）"
                         % (size, MAX_BYTES_DEFAULT),
                "hint": "分批转储（例如按 1 MB 一段），或确认 size 没写错"}
    chunk = max(16, min(int(chunk or CHUNK_DEFAULT), 65536))
    fill_byte = int(fill) & 0xFF
    path = str(path or "").strip()
    if not path:
        return {"ok": False, "error": "必须给 path（转储写到哪个文件）"}

    start_off = 0
    if resume:
        if fmt != "bin":
            return {"ok": False,
                    "error": "resume 只支持 bin：Intel HEX / hexdump 是文本格式，"
                             "文件长度不等于已读字节数，无法据此续传",
                    "hint": "改用 format=\"bin\" 续传，或重新整体转储"}
        have = resume_size(path)
        if have >= size:
            return {"ok": False,
                    "error": "已有文件 %s 已是 %d 字节，不小于本次要求的 %d 字节——无需续传"
                             % (path, have, size),
                    "hint": "确认 size 是否正确；要重读请 resume=false 并 overwrite=true"}
        start_off = have
    elif os.path.exists(path) and not overwrite:
        return {"ok": False, "error": "文件已存在: %s" % path,
                "hint": "换一个 path，或 overwrite=true 覆盖，或 resume=true 续传（仅 bin）"}

    mode = "ab" if (resume and start_off) else "wb"
    gaps = []
    written = 0
    h = hashlib.sha256()
    upper = None
    cur = addr + start_off
    left = size - start_off
    try:
        fh = open(path, mode)
    except OSError as e:
        return {"ok": False, "error": "打不开输出文件: %s" % e, "path": path}

    try:
        while left > 0:
            n = min(chunk, left)
            reason = ""
            try:
                data = read(cur, n)
            except Exception as e:  # noqa: BLE001
                data, reason = None, str(e)
            if data is None:
                data = b""
            if len(data) < n:
                reason = reason or ("只读回 %d/%d 字节" % (len(data), n))
            if len(data) < n:
                gaps.append({"addr": "0x%08X" % (cur + len(data)),
                             "offset": start_off + (size - left) + len(data),
                             "len": n - len(data), "reason": reason})
                data = bytes(data) + bytes([fill_byte]) * (n - len(data))
            else:
                data = bytes(data[:n])
            if fmt == "bin":
                fh.write(data)
            elif fmt == "ihex":
                lines, upper = ihex_records(cur, data, 16, upper)
                fh.write(("\r\n".join(lines) + "\r\n").encode("ascii"))
            else:
                fh.write(("\n".join(_hexdump_lines(cur, data)) + "\n").encode("ascii"))
            h.update(data)
            written += len(data)
            cur += n
            left -= n
        if fmt == "ihex":
            fh.write((ihex_eof() + "\r\n").encode("ascii"))
    except OSError as e:
        return {"ok": False, "error": "写文件失败: %s" % e, "path": path,
                "written": written}
    finally:
        try:
            fh.close()
        except Exception:  # noqa: BLE001
            pass

    elapsed_ms = int((time.time() - t0) * 1000)
    out = {
        "ok": True, "path": os.path.abspath(path), "format": fmt,
        "addr": "0x%08X" % addr, "size": size,
        "start_offset": start_off, "resumed": bool(start_off),
        "written_bytes": written,
        "complete": not gaps,
        "gap_count": len(gaps),
        "sha256": h.hexdigest(),
        "sha256_scope": ("本次写入的 %d 字节（含按 0x%02X 补齐的空洞）" % (written, fill_byte)),
        "elapsed_ms": elapsed_ms,
        "throughput_kbps": round(written / 1024.0 / max(elapsed_ms, 1) * 1000, 1),
        "file_size": resume_size(path),
    }
    if gaps:
        out["gaps"] = gaps
        out["warning"] = ("有 %d 段没读到，已按 0x%02X 补齐（complete=false）——"
                          "补齐的字节**不是目标真实内容**，比对/取数时先看 gaps"
                          % (len(gaps), fill_byte))
    return out
