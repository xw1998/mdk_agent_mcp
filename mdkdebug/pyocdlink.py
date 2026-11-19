# -*- coding: utf-8 -*-
"""pyOCD 客户端层：进程内 Session 单例 + pyocd_* 工具族。

为什么需要第三条链路
--------------------
- UVSOCK 只服务 Keil MDK：没装 Keil、不想开 uVision、或者在 CI/无界面机器上，
  这条路直接断。
- OpenOCD（ocd_*）能用，但它必须**独占探针**并常驻一个外部进程，还得先是装好
  interface/target cfg 的那份发行版。
- pyOCD 是纯 Python：``pip install pyocd`` 之后 CMSIS-DAP / J-Link / ST-Link
  都能连，烧录靠 CMSIS-Pack 里的 FLM 算法（不必有 Keil），内核寄存器 / 断点 /
  硬看门狗之外的 SWD 能力都在 Python API 上。

所以这一层是**进程内**的：不开 telnet、不解析人肉文本、不复刻 prompt 状态机，
每个动作都是一次 Python 调用，异常原样带出来。同一根探针同一时刻仍然只能被
一个「调试宿主」占着（Keil / OpenOCD / pyOCD 三者互斥），这一点不因为改成
进程内而改变——``pyocd_start`` 连不上时第一句提示就是「别处是否占着探针」。

刻意不做（写清楚，免得后来者以为是漏了）
----------------------------------------
- **不解析 ``pyocd commander`` 的交互输出**：那是人看的，格式随版本变；
  走 Python API 才能拿到「读到几个字节」这种可校验的事实。
- **不在 import 时 import pyocd**：它要加载器件库（几百个目标定义），
  首次导入是秒级的；而且没装 pyocd 的机器不该因此整个 server 起不来。
- **不做 RTT / SWO**：pyOCD 0.4x 没把这两条稳到可以直接当 API 用，
  我们自己的 trace_buff_* / trace_swd_* 已经覆盖目标侧缓冲那条路。
- **不替用户自动 halt**：读内存前只**报告**目标状态，不悄悄停 CPU。
  停不停是调用方的决定（停-读-走会改变被观察对象）。

读数可信度
----------
和 Keil 链路（client.read_mem_verified）用同一套语言：``read_confidence``
(high/medium/low)、``degenerate``(all_zero/all_ff/repeated_word)、
``reread_consistent``、``while_running``。运行态两读不一致时给 medium 而**不**
断言读数真假——因为「变量本来在变」和「读被打断」这两种解释分不开。
"""

from __future__ import annotations

import json
import logging
import os
import re
import socket
import subprocess
import sys
import tempfile
import threading
import time
from collections import deque

__all__ = ["PyOCDError", "PyOCDSession", "PyOCDMemoryClient", "get_session",
           "session_if_open", "available", "register"]

DEF_GDB_PORT = 3333
MEM_CHUNK = 4096            # 单次块读的字节数（CMSIS-DAP 包大小之上再切一刀）
MAX_READ = 8 << 20          # 单次 read 上限 8 MiB，防止一句参数读爆内存
MAX_WRITE = 4 << 20

_CONNECT_MODES = ("halt", "pre-reset", "under-reset", "attach")
_RESET_ALIAS = {
    "default": "default", "hw": "hardware", "hardware": "hardware",
    "sw": "software", "software": "software", "systick": "systick",
    "core": "core", "vectorcatch": "vectorcatch", "vectreset": "vectreset",
    "sysresetreq": "sysresetreq", "system": "system", "nsrst": "nsrst",
    "emulated": "emulated",
}
_BP_KINDS = {"auto": "AUTO", "hw": "HW", "hardware": "HW",
             "sw": "SW", "software": "SW"}
_WP_KINDS = {"w": "WRITE", "write": "WRITE", "r": "READ", "read": "READ",
             "rw": "READ_WRITE", "read_write": "READ_WRITE"}

_LOG_RING = deque(maxlen=300)


class _RingHandler(logging.Handler):
    """把 pyocd.* 的 warning/error 收进环形缓冲：pyocd 把「为什么连不上」写进日志，
    而异常消息往往只有一句 ProbeError。这里只收 warning 以上，避免刷屏。"""

    def emit(self, record):  # noqa: D401
        try:
            if record.levelno < logging.WARNING:
                return
            _LOG_RING.append({
                "ts": time.strftime("%H:%M:%S", time.localtime(record.created)),
                "level": record.levelname,
                "logger": record.name,
                "msg": record.getMessage()[:400],
            })
        except Exception:  # noqa: BLE001
            pass

_CACHE = {"sess": None}


class PyOCDError(RuntimeError):
    """pyOCD 链路的显式错误。code 会原样出现在工具返回的 error_code 里。"""

    def __init__(self, msg: str, code: str = ""):
        super().__init__(msg)
        self.code = code or "pyocd-error"


def _pyocd():
    """惰性导入 pyocd；没装时给出可执行的安装指令而不是 ImportError 栈。"""
    try:
        import pyocd  # noqa: F401
        from pyocd.core.helpers import ConnectHelper  # noqa: F401
        lg = logging.getLogger("pyocd")
        if not any(isinstance(h, _RingHandler) for h in lg.handlers):
            lg.addHandler(_RingHandler())
        return pyocd, ConnectHelper
    except Exception as e:  # noqa: BLE001
        raise PyOCDError(
            "未安装 pyocd：先 pip install pyocd（本机实测 0.46.1 可用）；原始错误：%s" % e,
            "pyocd-not-installed")


def available() -> dict:
    """检查 pyocd 是否可用（不连探针、不开会话）。"""
    out = {"installed": False, "version": "", "error": "", "hint": ""}
    try:
        pyocd, _ = _pyocd()
        out["installed"] = True
        out["version"] = str(getattr(pyocd, "__version__", "?"))
    except PyOCDError as e:
        out["error"] = str(e)
        out["error_code"] = e.code
        out["hint"] = "pip install pyocd"
    return out


# ---------------------------------------------------------------------------
# 会话
# ---------------------------------------------------------------------------
def _state_name(target) -> str:
    """目标状态名：halted / running / sleeping / lockup / reset / unknown。"""
    try:
        st = target.get_state()
    except Exception:  # noqa: BLE001
        return "unknown"
    return str(getattr(st, "name", st)).strip().lower() or "unknown"


def _halt_reason(target) -> str:
    try:
        hr = target.get_halt_reason()
    except Exception:  # noqa: BLE001
        return ""
    return str(getattr(hr, "name", hr)).strip().lower()


def _safe(getter, default=None):
    try:
        return getter()
    except Exception:  # noqa: BLE001
        return default


class PyOCDSession:
    """pyOCD 会话单例的载体。工具层只通过它拿 session/target。"""

    def __init__(self):
        self.sess = None
        self.started_at = 0.0
        self.opts: dict = {}
        self.params: dict = {}
        self.bps: dict = {}          # addr -> kind（本模块登记过的，便于 list/clear）
        self.wps: dict = {}          # (addr,size) -> kind
        self.last_error = ""
        self.gdb = None
        self.gdb_log = ""
        self.lock = threading.RLock()

    # ---- 生命周期 ----
    def running(self) -> bool:
        try:
            return self.sess is not None and bool(self.sess.is_open)
        except Exception:  # noqa: BLE001
            return False

    def open(self, unique_id: str = "", target: str = "", pack: str = "",
             frequency: float = 0, connect_mode: str = "halt", reset_type: str = "",
             options: dict | None = None, auto_unlock: bool = False,
             resume_on_disconnect: bool = False) -> dict:
        _, CH = _pyocd()
        if self.running():
            raise PyOCDError(
                "已有一个 pyOCD 会话在跑（同一根探针不能被两个会话同时占用）；"
                "要换配置先 pyocd_stop，或 pyocd_status 看当前连的是谁",
                "pyocd-already-open")
        opts = {}
        if target:
            opts["target_override"] = str(target).strip()
        if pack:
            p = str(pack).strip()
            if not os.path.exists(p):
                raise PyOCDError("pack 文件不存在：%s" % p, "pyocd-bad-pack")
            opts["pack"] = os.path.abspath(p)
        if frequency:
            f = float(frequency)
            if f <= 0:
                raise PyOCDError("frequency 必须是正数（单位 kHz）", "pyocd-bad-frequency")
            opts["frequency"] = int(f) if f == int(f) else f
        cm = str(connect_mode or "halt").strip().lower()
        if cm not in _CONNECT_MODES:
            raise PyOCDError("connect_mode 只支持 %s，收到 %r"
                             % ("/".join(_CONNECT_MODES), connect_mode),
                             "pyocd-bad-connect-mode")
        opts["connect_mode"] = cm
        if reset_type:
            rt = _RESET_ALIAS.get(str(reset_type).strip().lower())
            if not rt:
                raise PyOCDError("reset_type 不认识：%r" % reset_type, "pyocd-bad-reset-type")
            opts["reset_type"] = rt
        if auto_unlock:
            opts["auto_unlock"] = True
        if resume_on_disconnect:
            opts["resume_on_disconnect"] = True
        if options:
            opts.update({str(k): v for k, v in dict(options).items()})

        t0 = time.time()
        try:
            # auto_open=False：先拿到 session 对象，再自己 open()——这样 open 抛的
            # 异常能被我们原样转成 error_code，而不是混在 ConnectHelper 的选择流程里。
            sess = CH.session_with_chosen_probe(
                unique_id=str(unique_id).strip() or None,
                return_first=True, blocking=False, auto_open=False, options=opts)
        except Exception as e:  # noqa: BLE001
            raise PyOCDError("枚举探针失败：%s" % e, "pyocd-probe-error")
        if sess is None:
            raise PyOCDError(
                "没有找到匹配的探针%s。先 pyocd_list 看当前连了哪些；"
                "探针被 Keil / OpenOCD / 另一个 pyOCD 占着时这里也会拿不到"
                % ("（unique_id=%s）" % unique_id if unique_id else ""),
                "pyocd-no-probe")
        try:
            sess.open()
        except Exception as e:  # noqa: BLE001
            try:
                sess.close()
            except Exception:  # noqa: BLE001
                pass
            raise PyOCDError(
                "打开 pyOCD 会话失败：%s。常见原因：目标没供电 / SWD 线序错 / "
                "target 名不对（pyocd_list(targets=关键字) 查）/ 探针被别的进程占着" % e,
                "pyocd-open-failed")
        with self.lock:
            self.sess = sess
            self.started_at = time.time()
            self.opts = opts
            self.params = {"unique_id": unique_id, "target": target, "pack": pack,
                           "frequency": frequency, "connect_mode": cm,
                           "reset_type": reset_type}
            self.bps = {}
            self.wps = {}
            self.last_error = ""
        return {"ok": True, "open_s": round(time.time() - t0, 3),
                "options": opts, "info": self.info()}

    def close(self, resume: bool = False) -> dict:
        with self.lock:
            sess, self.sess = self.sess, None
            self.bps = {}
            self.wps = {}
        if sess is None:
            return {"ok": True, "was_open": False, "note": "本来就没有打开的会话"}
        out = {"ok": True, "was_open": True}
        try:
            target = sess.target
            if resume and target is not None and _state_name(target) != "running":
                try:
                    target.resume()
                    out["resumed"] = True
                except Exception as e:  # noqa: BLE001
                    out["resume_error"] = str(e)
        except Exception:  # noqa: BLE001
            pass
        try:
            sess.close()
        except Exception as e:  # noqa: BLE001
            out["ok"] = False
            out["error"] = "关闭会话失败：%s" % e
            self.last_error = str(e)
        return out

    def target(self):
        if not self.running():
            raise PyOCDError(
                "pyOCD 会话没开：先 pyocd_start（pyocd_list 看探针；"
                "没装 pyocd 就 pip install pyocd）",
                "pyocd-not-connected")
        t = getattr(self.sess, "target", None)
        if t is None:
            raise PyOCDError("会话已打开但拿不到 target（目标没连上/已断线）",
                             "pyocd-no-target")
        return t

    # ---- 元信息 ----
    def probe_info(self) -> dict:
        s = self.sess
        if s is None:
            return {}
        pr = getattr(s, "probe", None)
        out = {}
        for k, attr in (("unique_id", "unique_id"), ("description", "description"),
                        ("vendor", "vendor_name"), ("product", "product_name"),
                        ("board_name", "board_name"), ("protocol", "protocol")):
            v = _safe(lambda a=attr: getattr(pr, a))
            if v not in (None, ""):
                out[k] = v if isinstance(v, (int, float)) else str(v)
        return out

    def target_info(self, memory_map: bool = False) -> dict:
        t = self.target()
        out = {
            "state": _state_name(t),
            "halt_reason": _halt_reason(t),
            "part_number": str(_safe(lambda: t.part_number, "") or ""),
            "vendor": str(_safe(lambda: t.vendor, "") or ""),
            "name": str(_safe(lambda: t.name, "") or ""),
        }
        try:
            out["cores"] = [str(c) for c in (t.cores or [])]
        except Exception:  # noqa: BLE001
            pass
        if memory_map:
            out["memory_map"] = self.memory_map()
        return out

    def memory_map(self) -> list:
        t = self.target()
        try:
            mm = t.get_memory_map()
        except Exception as e:  # noqa: BLE001
            raise PyOCDError("读内存映射失败：%s" % e, "pyocd-memory-map-failed")
        out = []
        for r in (mm.regions or []):
            attrs = dict(getattr(r, "attributes", {}) or {})
            out.append({
                "start": "0x%08X" % int(r.start),
                "end": "0x%08X" % int(r.end),
                "length": int(r.length),
                "type": str(getattr(r, "type", "") or ""),
                "name": attrs.get("name") or "",
            })
        return out

    def info(self) -> dict:
        out = {"running": self.running()}
        if self.running():
            out["uptime_s"] = round(time.time() - self.started_at, 1)
            out["probe"] = self.probe_info()
            out["options"] = dict(self.opts)
            try:
                out["target"] = self.target_info()
            except Exception as e:  # noqa: BLE001
                out["target_error"] = str(e)
        if self.gdb is not None:
            out["gdb"] = self.gdb_info()
        if self.last_error:
            out["last_error"] = self.last_error
        return out

    # ---- 内存 ----
    def read_bytes(self, addr: int, n: int) -> bytes:
        t = self.target()
        if n < 0:
            raise PyOCDError("n_bytes 不能为负", "pyocd-bad-length")
        if n > MAX_READ:
            raise PyOCDError("单次最多读 %d 字节（要 %d）：分段读或先 query_memory_map"
                             % (MAX_READ, n), "pyocd-too-long")
        out = bytearray()
        while len(out) < n:
            chunk = min(MEM_CHUNK, n - len(out))
            try:
                data = t.read_memory_block8(addr + len(out), chunk)
            except Exception as e:  # noqa: BLE001
                raise PyOCDError(
                    "读内存失败 @0x%08X（+%d，要 %d 字节）：%s"
                    % (addr, len(out), chunk, e), "pyocd-read-failed")
            if data is None or len(data) != chunk:
                raise PyOCDError(
                    "读回的字节数不符 @0x%08X：要 %d，拿到 %s"
                    % (addr + len(out), chunk,
                       "None" if data is None else len(data)),
                    "pyocd-short-read")
            out += bytes(int(b) & 0xFF for b in data)
        return bytes(out)

    def write_bytes(self, addr: int, data: bytes) -> int:
        t = self.target()
        if not data:
            raise PyOCDError("data 不能为空", "pyocd-empty-write")
        if len(data) > MAX_WRITE:
            raise PyOCDError("单次最多写 %d 字节（要 %d）"
                             % (MAX_WRITE, len(data)), "pyocd-too-long")
        total = 0
        while total < len(data):
            chunk = min(MEM_CHUNK, len(data) - total)
            piece = data[total:total + chunk]
            try:
                t.write_memory_block8(addr + total, list(piece))
            except Exception as e:  # noqa: BLE001
                raise PyOCDError(
                    "写内存失败 @0x%08X（已写 %d / %d 字节）：%s"
                    % (addr + total, total, len(data), e), "pyocd-write-failed")
            total += chunk
        return total

    def read_verified(self, addr: int, n: int, verify: str = "auto") -> dict:
        """带可信度标注的读：与 Keil 链路的 read_mem_verified 同一套判定语言。"""
        t = self.target()
        state = _state_name(t)
        running = state != "halted"
        first = self.read_bytes(addr, n)
        deg = _degenerate_kind(first)
        out = {
            "ok": True, "addr": addr, "n_bytes": n,
            "data_hex": first.hex(), "first_read_hex": first.hex(),
            "read_confidence": "high", "reread_count": 0,
            "reread_consistent": None, "while_running": running, "state": state,
        }
        expected_ff = bool(deg == "all_ff" and 0x08000000 <= addr < 0x20000000)
        if deg:
            out["degenerate"] = deg
            if expected_ff:
                out["content_note"] = ("该地址在 Flash 区段，已擦除区域读出全 0xFF 是"
                                       "预期内容，不是脏读")
            else:
                out["degenerate_note"] = {
                    "all_zero": "整帧全 0x00：整片同值通常是读失败而不是真实内容",
                    "all_ff": "整帧全 0xFF：整片同值通常是读失败或该区域未初始化",
                    "repeated_word": ("整帧是同一个 4 字节字的重复：这是「目标全速运行时"
                                      "经 SWD 读 SRAM」的伪值签名之一，不是真实内容"),
                }.get(deg, "整帧同值：不像真实内容")
        mode = str(verify or "auto").strip().lower()
        need = (mode in ("1", "true", "yes", "on", "always", "force")
                or (mode not in ("0", "false", "no", "off", "never")
                    and (bool(deg) or running)))
        if not need:
            if deg and not expected_ff:
                out["read_confidence"] = "low"
                out["warning"] = "首帧整帧退化（%s）且未复读：该结果不可信" % deg
            return out
        prev = first
        for i in (1, 2):
            time.sleep(0.05)
            try:
                nxt = self.read_bytes(addr, n)
            except PyOCDError as e:
                out["reread_error"] = str(e)
                break
            out["reread_count"] = i
            if nxt == prev:
                out["reread_consistent"] = True
                out["data_hex"] = nxt.hex()
                if nxt != first:
                    out.pop("degenerate", None)
                    out.pop("degenerate_note", None)
                    out["warning"] = ("首帧是脏值，已复读 %d 次一致后采用新值；"
                                      "首帧 first_read_hex 不可信" % (i + 1))
                    out["read_confidence"] = "high"
                elif deg:
                    out["read_confidence"] = "high" if expected_ff else "low"
                    if not expected_ff:
                        out["warning"] = ("连续 %d 次都是整帧 %s：可能是该区域确实如此，"
                                          "也可能读通路异常，换地址/换链路交叉确认"
                                          % (i + 1, deg))
                else:
                    out["read_confidence"] = "high"
                return out
            if running:
                # 两读不同：可能是变量在变，也可能是读被打断——分不开，所以不下断言
                out["read_confidence"] = "medium"
                out["reread_consistent"] = False
                out["read_unstable"] = True
                out["first_read_hex"] = prev.hex()
                out["data_hex"] = nxt.hex()
                out["warning"] = ("目标不在 halted 状态，两次读到的内容不同：可能该地址本来"
                                  "就在被 CPU 改写，也可能这次读被打断。要取一致快照先 "
                                  "pyocd_control(action=\"halt\") 再读")
                return out
            prev = nxt
        out["reread_consistent"] = False
        out["read_confidence"] = "low"
        out["warning"] = ("复读未能确认（%s）：当前读数不可信；先 pyocd_status 确认目标"
                          "状态再读" % (out.get("reread_error") or "读数一直在变"))
        return out

    # ---- 寄存器 ----
    def reg_names(self) -> list:
        t = self.target()
        idx = getattr(t, "core_registers", None)
        names = list(getattr(idx, "by_name", {}) or {})
        if names:
            return names
        return ["r%d" % i for i in range(13)] + ["sp", "lr", "pc", "xpsr"]

    def read_regs(self, names=None) -> dict:
        t = self.target()
        want = list(names or ["r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7",
                              "r8", "r9", "r10", "r11", "r12", "sp", "lr", "pc", "xpsr"])
        try:
            vals = t.read_core_registers_raw(want)
        except Exception as e:  # noqa: BLE001
            raise PyOCDError("读核心寄存器失败（%s）：%s"
                             % (",".join(map(str, want)), e), "pyocd-reg-failed")
        out = {}
        for n, v in zip(want, vals):
            try:
                out[str(n)] = "0x%08X" % (int(v) & 0xFFFFFFFF)
            except Exception:  # noqa: BLE001
                out[str(n)] = str(v)
        return out

    def write_reg(self, name: str, value: int) -> dict:
        t = self.target()
        try:
            t.write_core_registers_raw([str(name)], [int(value) & 0xFFFFFFFF])
        except Exception as e:  # noqa: BLE001
            raise PyOCDError("写核心寄存器 %s 失败：%s" % (name, e), "pyocd-reg-write-failed")
        back = None
        try:
            back = int(t.read_core_registers_raw([str(name)])[0]) & 0xFFFFFFFF
        except Exception:  # noqa: BLE001
            pass
        out = {"ok": True, "name": str(name), "value": "0x%08X" % (int(value) & 0xFFFFFFFF)}
        if back is not None:
            out["readback"] = "0x%08X" % back
            out["verified"] = (back == (int(value) & 0xFFFFFFFF))
            if not out["verified"]:
                out["warning"] = "回读值与写入值不同：该寄存器可能有只读位/被硬件改写"
        return out

    # ---- 断点 / 观察点 ----
    def set_bp(self, addr: int, kind: str = "auto") -> dict:
        from pyocd.core.target import Target
        t = self.target()
        k = _BP_KINDS.get(str(kind or "auto").strip().lower())
        if not k:
            raise PyOCDError("kind 只支持 auto/hw/sw，收到 %r" % kind, "pyocd-bad-bp-kind")
        try:
            ok = t.set_breakpoint(int(addr), Target.BreakpointType[k])
        except Exception as e:  # noqa: BLE001
            raise PyOCDError("下断点失败 @0x%08X：%s" % (addr, e), "pyocd-bp-failed")
        self.bps[int(addr)] = k
        return {"ok": bool(ok), "action": "set", "addr": "0x%08X" % int(addr),
                "kind": k, "note": "" if ok else "底层返回 False：可能硬件断点槽已满"}

    def clear_bp(self, addr: int) -> dict:
        from pyocd.core.target import Target
        t = self.target()
        found = self.bps.get(int(addr), "AUTO")
        try:
            t.remove_breakpoint(int(addr), Target.BreakpointType[found])
        except Exception as e:  # noqa: BLE001
            # 类型对不上时按 AUTO 再来一次：调用方给的是地址，不想让它猜类型
            try:
                t.remove_breakpoint(int(addr), Target.BreakpointType.AUTO)
            except Exception as e2:  # noqa: BLE001
                raise PyOCDError("清断点失败 @0x%08X：%s / %s"
                                 % (addr, e, e2), "pyocd-bp-clear-failed")
        self.bps.pop(int(addr), None)
        return {"ok": True, "action": "clear", "addr": "0x%08X" % int(addr)}

    def list_bps(self) -> dict:
        t = self.target()
        items = []
        for a, k in sorted(self.bps.items()):
            present = _safe(lambda a=a: t.find_breakpoint(a) is not None, None)
            items.append({"addr": "0x%08X" % a, "kind": k, "present": present})
        return {"ok": True, "action": "list", "count": len(items), "breakpoints": items,
                "note": "只列本模块登记过的断点（pyOCD 没有全局断点列表 API）；"
                        "present 由 find_breakpoint 复核，None 表示复核不可用"}

    def set_wp(self, addr: int, size: int = 4, kind: str = "w") -> dict:
        from pyocd.core.target import Target
        t = self.target()
        k = _WP_KINDS.get(str(kind or "w").strip().lower())
        if not k:
            raise PyOCDError("kind 只支持 read/write/read_write，收到 %r" % kind,
                             "pyocd-bad-wp-kind")
        if int(size) <= 0:
            raise PyOCDError("size 必须是正数", "pyocd-bad-wp-size")
        try:
            ok = t.set_watchpoint(int(addr), int(size), Target.WatchpointType[k])
        except Exception as e:  # noqa: BLE001
            raise PyOCDError("下观察点失败 @0x%08X：%s" % (addr, e), "pyocd-wp-failed")
        self.wps[(int(addr), int(size))] = k
        return {"ok": bool(ok), "action": "set", "addr": "0x%08X" % int(addr),
                "size": int(size), "kind": k,
                "note": "" if ok else "底层返回 False：可能观察点槽已满或该区域不支持"}

    def clear_wp(self, addr: int, size: int = 4) -> dict:
        from pyocd.core.target import Target
        t = self.target()
        key = (int(addr), int(size))
        k = self.wps.get(key, "WRITE")
        try:
            t.remove_watchpoint(int(addr), int(size), Target.WatchpointType[k])
        except Exception as e:  # noqa: BLE001
            raise PyOCDError("清观察点失败 @0x%08X：%s" % (addr, e), "pyocd-wp-clear-failed")
        self.wps.pop(key, None)
        return {"ok": True, "action": "clear", "addr": "0x%08X" % int(addr),
                "size": int(size)}

    def list_wps(self) -> dict:
        items = [{"addr": "0x%08X" % a, "size": s, "kind": k}
                 for (a, s), k in sorted(self.wps.items())]
        return {"ok": True, "action": "list", "count": len(items), "watchpoints": items,
                "note": "只列本模块登记过的观察点（pyOCD 没有全局观察点列表 API）"}

    # ---- 控制 ----
    def control(self, action: str, reset_type: str = "") -> dict:
        from pyocd.core.target import Target
        t = self.target()
        a = str(action or "").strip().lower()
        rt = None
        if reset_type:
            name = _RESET_ALIAS.get(str(reset_type).strip().lower())
            if not name:
                raise PyOCDError("reset_type 不认识：%r" % reset_type,
                                 "pyocd-bad-reset-type")
            rt = Target.ResetType[name.upper()]
        try:
            if a == "halt":
                t.halt()
            elif a in ("resume", "run", "go"):
                t.resume()
            elif a == "reset":
                t.reset(rt)
            elif a in ("reset_halt", "reset-halt", "resethalt"):
                if rt is not None:
                    t.reset(rt)
                else:
                    t.reset_and_halt()
            elif a in ("step", "step_into"):
                t.step()
            elif a == "init":
                t.init()
            else:
                raise PyOCDError("action 只支持 halt/resume/reset/reset_halt/step/init，"
                                 "收到 %r" % action, "pyocd-bad-action")
        except PyOCDError:
            raise
        except Exception as e:  # noqa: BLE001
            raise PyOCDError("%s 失败：%s" % (a, e), "pyocd-control-failed")
        out = {"ok": True, "action": a, "state": _state_name(t),
               "halt_reason": _halt_reason(t)}
        if out["state"] == "halted":
            out["regs"] = {"pc": self.read_regs(["pc"]).get("pc"),
                           "sp": self.read_regs(["sp"]).get("sp")}
        return out

    # ---- 烧录 ----
    def flash(self, path: str, file_format: str = "", base_address: int = 0,
              chip_erase: str = "", smart_flash: bool = True,
              trust_crc: bool = True, reset: bool = True,
              extra: dict | None = None) -> dict:
        from pyocd.flash.file_programmer import FileProgrammer
        if not path:
            raise PyOCDError("file 不能为空", "pyocd-no-file")
        if not os.path.exists(path):
            raise PyOCDError("文件不存在：%s" % path, "pyocd-file-not-found")
        ce = str(chip_erase or "").strip().lower()
        if ce in ("", "auto"):
            ce = None
        elif ce in ("chip", "mass"):
            ce = "chip"
        elif ce in ("sector", "page"):
            ce = "sector"
        else:
            raise PyOCDError("chip_erase 只支持 auto/chip/sector，收到 %r" % chip_erase,
                             "pyocd-bad-chip-erase")
        kw = dict(chip_erase=ce, smart_flash=bool(smart_flash),
                  trust_crc=bool(trust_crc), no_reset=not bool(reset))
        if extra:
            kw.update(extra)
        t0 = time.time()
        try:
            fp = FileProgrammer(self.sess, **kw)
            opts = {}
            if base_address:
                opts["base_address"] = int(base_address)
            fp.program(path, file_format=(file_format or None), **opts)
        except PyOCDError:
            raise
        except Exception as e:  # noqa: BLE001
            raise PyOCDError("烧录失败：%s" % e, "pyocd-flash-failed")
        out = {"ok": True, "file": path, "format": file_format or "auto",
               "elapsed_s": round(time.time() - t0, 2),
               "chip_erase": ce or "auto", "smart_flash": bool(smart_flash),
               "trust_crc": bool(trust_crc), "reset": bool(reset)}
        if base_address:
            out["base_address"] = "0x%08X" % int(base_address)
        try:
            out["state"] = _state_name(self.target())
        except Exception:  # noqa: BLE001
            pass
        return out

    def erase(self, mode: str = "chip", addresses=None) -> dict:
        from pyocd.flash.eraser import FlashEraser
        m = str(mode or "chip").strip().lower()
        if m in ("mass",):
            mode_enum = FlashEraser.Mode.MASS
        elif m in ("chip", "all"):
            mode_enum = FlashEraser.Mode.CHIP
        elif m in ("sector", "page"):
            mode_enum = FlashEraser.Mode.SECTOR
        else:
            raise PyOCDError("mode 只支持 chip/mass/sector，收到 %r" % mode,
                             "pyocd-bad-erase-mode")
        if mode_enum is FlashEraser.Mode.SECTOR and not addresses:
            raise PyOCDError("sector 模式必须给 addresses（如 \"0x08000000\" 或 "
                             "\"0x08000000-0x08004000\"）", "pyocd-no-erase-address")
        t0 = time.time()
        try:
            er = FlashEraser(self.sess, mode_enum)
            er.erase(addresses)
        except PyOCDError:
            raise
        except Exception as e:  # noqa: BLE001
            raise PyOCDError("擦除失败：%s" % e, "pyocd-erase-failed")
        return {"ok": True, "mode": m, "elapsed_s": round(time.time() - t0, 2)}

    # ---- gdbserver（外部 IDE / GDB 用） ----
    def gdb_info(self) -> dict:
        p = self.gdb
        if p is None:
            return {"running": False}
        out = {"running": p.poll() is None, "pid": getattr(p, "pid", None),
               "port": getattr(self, "gdb_port", DEF_GDB_PORT),
               "log": self.gdb_log}
        if out["running"]:
            out["log_tail"] = _tail(self.gdb_log, 20)
        else:
            out["exit_code"] = p.returncode
            out["log_tail"] = _tail(self.gdb_log, 20)
        return out


def _tail(path: str, n: int = 20) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
        return "".join(lines[-n:]).strip()
    except Exception:  # noqa: BLE001
        return ""


def _port_open(port: int, host: str = "127.0.0.1") -> bool:
    s = socket.socket()
    s.settimeout(0.3)
    try:
        s.connect((host, int(port)))
        return True
    except Exception:  # noqa: BLE001
        return False
    finally:
        try:
            s.close()
        except Exception:  # noqa: BLE001
            pass


def _degenerate_kind(data: bytes) -> str:
    """整帧退化识别：与 client.UVClient._degenerate_kind 同一套规则。

    单独实现而不是 import client，是为了让这一层在「没有 Keil 客户端」的机器上
    也能独立工作（client 会拉起 UVSOCK 相关模块）。
    """
    if not data:
        return ""
    if all(b == 0x00 for b in data):
        return "all_zero"
    if all(b == 0xFF for b in data):
        return "all_ff"
    if len(data) >= 8 and len(data) % 4 == 0:
        w = data[:4]
        step = 4
        if all(data[i:i + step] == w for i in range(0, len(data), step)):
            return "repeated_word"
    return ""


# ---------------------------------------------------------------------------
# 单例
# ---------------------------------------------------------------------------
def get_session() -> PyOCDSession:
    if _CACHE.get("sess") is None:
        _CACHE["sess"] = PyOCDSession()
    return _CACHE["sess"]


def session_if_open():
    """给「没有 Keil 时的读数源」用：会话开着才返回适配器，否则 None。"""
    s = get_session()
    if not s.running():
        return None
    return PyOCDMemoryClient(s)


class PyOCDMemoryClient:
    """把 pyOCD 会话伪装成 triggers 需要的「内存客户端」。

    只实现条件触发真正会用到的那几个方法（read_mem_verified / read_mem /
    write_mem / get_status）。多出来的方法一律抛错——**宁可报错也不给错答案**：
    让调用方一眼看出「这条链路不提供这个能力」，而不是拿到一个空字典。
    """

    def __init__(self, session: PyOCDSession):
        self.session = session

    def get_status(self) -> dict:
        out = self.session.info()
        out["debugging"] = bool(self.session.running())
        out["backend"] = "pyocd"
        return out

    def read_mem(self, addr: int, n_bytes: int) -> dict:
        try:
            data = self.session.read_bytes(int(addr), int(n_bytes))
        except PyOCDError as e:
            return {"ok": False, "error": str(e), "error_code": e.code,
                    "status_text": str(e), "addr": int(addr), "n_bytes": int(n_bytes)}
        return {"ok": True, "addr": int(addr), "n_bytes": int(n_bytes),
                "data_hex": data.hex(), "ascii": _ascii(data),
                "backend": "pyocd"}

    def read_mem_verified(self, addr: int, n_bytes: int, verify: str = "auto") -> dict:
        try:
            out = self.session.read_verified(int(addr), int(n_bytes), verify=verify)
        except PyOCDError as e:
            return {"ok": False, "error": str(e), "error_code": e.code,
                    "status_text": str(e), "read_confidence": "low"}
        out["ascii"] = _ascii(bytes.fromhex(out.get("data_hex") or ""))
        out["backend"] = "pyocd"
        return out

    def write_mem(self, addr: int, data: bytes) -> dict:
        try:
            n = self.session.write_bytes(int(addr), bytes(data))
        except PyOCDError as e:
            return {"ok": False, "error": str(e), "error_code": e.code,
                    "status_text": str(e), "written": 0}
        return {"ok": True, "addr": int(addr), "written": n, "backend": "pyocd"}

    def __getattr__(self, name):
        raise PyOCDError(
            "pyOCD 链路不提供 %s（它是给 Keil 客户端用的）；这条链路只支持读内存/"
            "写内存/状态查询，其余请用 pyocd_* 工具" % name, "pyocd-unsupported")


def _ascii(data: bytes) -> str:
    return "".join(chr(b) if 32 <= b < 127 else "." for b in data)


def _hexdump(data: bytes, base: int, width: int = 16) -> list:
    lines = []
    for off in range(0, len(data), width):
        chunk = data[off:off + width]
        hexs = " ".join("%02X" % b for b in chunk)
        lines.append("%08X  %-*s  |%s|" % (base + off, width * 3 - 1, hexs,
                                           _ascii(chunk)))
    return lines


def _words(data: bytes, width: int) -> list:
    out = []
    for i in range(0, len(data) - width + 1, width):
        out.append(int.from_bytes(data[i:i + width], "little"))
    return out


# ---------------------------------------------------------------------------
# 参数小工具
# ---------------------------------------------------------------------------
def _default_js(obj) -> str:
    return json.dumps(obj, ensure_ascii=False, default=str)


def _addr(s) -> int:
    """地址解析：0x/0b/0o/十进制。**不接受符号名**——pyOCD 不读 ELF 符号表，
    符号先 find_symbol / parse_map 换成地址，别在这里猜。"""
    if isinstance(s, int):
        return s
    t = str(s or "").strip().replace("_", "")
    if not t:
        raise PyOCDError("地址为空：给 '0x20000000' 这样的值", "pyocd-bad-addr")
    try:
        if t.lower().startswith("0x"):
            return int(t, 16)
        if t.lower().startswith("0b"):
            return int(t, 2)
        if t.lower().startswith("0o"):
            return int(t, 8)
        return int(t, 10)
    except ValueError:
        raise PyOCDError(
            "地址解析失败：%r。pyOCD 链路只认数字地址（0x...）；符号名请先用 "
            "find_symbol / parse_map 换成地址" % s, "pyocd-bad-addr")


def _opt_dict(s) -> dict:
    """把 'a=b,c=d' 或 JSON 对象解析成 dict（pyOCD 的 -O 选项）。"""
    if not s:
        return {}
    t = str(s).strip()
    if t.startswith("{"):
        try:
            return dict(json.loads(t))
        except Exception as e:  # noqa: BLE001
            raise PyOCDError("options 不是合法 JSON：%s" % e, "pyocd-bad-options")
    out = {}
    for part in re.split(r"[;,]", t):
        part = part.strip()
        if not part:
            continue
        if "=" not in part:
            raise PyOCDError("options 项缺 '='：%r（形如 a=b,c=d）" % part,
                             "pyocd-bad-options")
        k, v = part.split("=", 1)
        out[k.strip()] = v.strip()
    return out


def _hex_bytes(s) -> bytes:
    t = str(s or "").strip()
    for ch in (" ", ",", "\n", "\r", "\t", "-", ":"):
        t = t.replace(ch, "")
    if t.lower().startswith("0x"):
        t = t[2:]
    if len(t) % 2:
        raise PyOCDError("data_hex 的十六进制字符数必须是偶数（收到 %d 个）" % len(t),
                         "pyocd-bad-data")
    try:
        return bytes.fromhex(t)
    except ValueError as e:
        raise PyOCDError("data_hex 不是合法十六进制：%s" % e, "pyocd-bad-data")


def _ints(s) -> list:
    t = str(s or "").strip()
    if not t:
        return []
    parts = [p for p in re.split(r"[,\s;]+", t) if p]
    return [_addr(p) for p in parts]


def _err(e: Exception) -> dict:
    out = {"ok": False, "error": str(e)}
    code = getattr(e, "code", "")
    if code:
        out["error_code"] = code
    return out


# ---------------------------------------------------------------------------
# 工具注册
# ---------------------------------------------------------------------------
def register(server, js=None) -> int:
    _js = js or _default_js
    n = 0

    @server.tool(
        name="pyocd_list",
        title="列探针 / 查目标名（pyOCD 链路的入口）",
        description=(
            "不打开会话，只做三件事：看当前连着哪些调试探针（CMSIS-DAP / J-Link / "
            "ST-Link 都行）、按关键字过滤 pyOCD 认识的目标名、确认 pyocd 有没有装。\n"
            "**targets 给关键字**（如 'stm32f4'、'nrf52'）会返回匹配的目标名列表，"
            "这些名字正是 pyocd_start(target=...) 要的值。\n"
            "探针列表为空通常不是没插——而是被 Keil / OpenOCD / 另一个 pyOCD 占着，"
            "同一根探针同一时刻只能有一个调试宿主。"
        ),
    )
    async def pyocd_list(probes: bool = True, targets: str = "", limit: int = 50) -> str:
        try:
            av = available()
            out = {"ok": True, "available": av}
            if not av.get("installed"):
                out["ok"] = False
                out["error"] = av.get("error")
                out["error_code"] = av.get("error_code", "pyocd-not-installed")
                out["hint"] = av.get("hint")
                return _js(out)
            _, CH = _pyocd()
            if probes:
                try:
                    ps = CH.get_all_connected_probes(blocking=False,
                                                     print_wait_message=False)
                except Exception as e:  # noqa: BLE001
                    ps = []
                    out["probe_error"] = str(e)
                items = []
                for p in ps:
                    items.append({
                        "unique_id": str(_safe(lambda p=p: p.unique_id, "") or ""),
                        "description": str(_safe(lambda p=p: p.description, "") or ""),
                        "vendor": str(_safe(lambda p=p: p.vendor_name, "") or ""),
                        "product": str(_safe(lambda p=p: p.product_name, "") or ""),
                        "board_name": str(_safe(lambda p=p: p.board_name, "") or ""),
                        "protocol": str(_safe(lambda p=p: p.protocol, "") or ""),
                    })
                out["probes"] = items
                out["probe_count"] = len(items)
            if targets:
                try:
                    from pyocd.target import TARGET
                    kw = str(targets).strip().lower()
                    names = sorted(x for x in TARGET if kw in str(x).lower())
                    out["target_keyword"] = targets
                    out["targets_matched"] = names[:max(1, int(limit or 50))]
                    out["targets_total"] = len(names)
                    if not names:
                        out["hint"] = ("没有匹配的目标名：换个短关键字（'f4'/'stm32'），"
                                       "或在 pyocd_start(pack=...) 里给 CMSIS-Pack，"
                                       "让它在包里找这个器件")
                except Exception as e:  # noqa: BLE001
                    out["targets_error"] = str(e)
            if not (probes or targets):
                out["session"] = get_session().info()
            out["next"] = ["pyocd_start(target=..., unique_id=...)",
                           "pyocd_status → pyocd_info → pyocd_control"]
            return _js(out)
        except Exception as e:  # noqa: BLE001
            return _js(_err(e))
    n += 1

    @server.tool(
        name="pyocd_start",
        title="打开 pyOCD 会话（不开 Keil 也能调试/烧录的总入口）",
        description=(
            "在进程内打开一个 pyOCD 会话，之后所有 pyocd_* 工具都作用于它。"
            "**一根探针同一时刻只能被一个调试宿主占着**（Keil / OpenOCD / pyOCD），"
            "已开会话时再 start 会明确报错；要换配置给 restart=true。\n"
            "target 用 pyocd_list(targets='stm32f4') 查名字；不写 target 时按探针"
            "读到的器件自动选，选不出来会在错误里说清楚。pack 可以给 CMSIS-Pack "
            "路径（器件不在内置表里时用它）。connect_mode=halt 会在连上时停住内核"
            "（默认）；要观察正在跑的目标用 attach——**attach 不改目标状态**。"
        ),
    )
    async def pyocd_start(unique_id: str = "", target: str = "", pack: str = "",
                          frequency: float = 0, connect_mode: str = "halt",
                          reset_type: str = "", options: str = "",
                          auto_unlock: bool = False, resume_on_disconnect: bool = False,
                          restart: bool = False) -> str:
        try:
            s = get_session()
            if s.running() and not restart:
                return _js({"ok": False, "error": "已有 pyOCD 会话在跑",
                            "error_code": "pyocd-already-open",
                            "session": s.info(),
                            "hint": "pyocd_stop 停掉，或 pyocd_start(restart=true) 重启"})
            if s.running() and restart:
                s.close()
            r = s.open(unique_id=unique_id, target=target, pack=pack,
                       frequency=frequency, connect_mode=connect_mode,
                       reset_type=reset_type, options=_opt_dict(options),
                       auto_unlock=auto_unlock,
                       resume_on_disconnect=resume_on_disconnect)
            r["next"] = ["pyocd_info（确认连的是谁）",
                         "pyocd_control(action=\"reset_halt\") 或 pyocd_flash(...)"]
            return _js(r)
        except Exception as e:  # noqa: BLE001
            return _js(_err(e))
    n += 1

    @server.tool(
        name="pyocd_stop",
        title="关闭 pyOCD 会话（释放探针）",
        description=(
            "关闭会话并让 pyOCD 放开探针。**调试结束后应当显式调它**——探针被占着会"
            "挡住 Keil / OpenOCD / 另一个 pyOCD。resume=true 会在关闭前把目标放开运行"
            "（默认不碰目标状态：不留一个被无意停住的内核）。"
        ),
    )
    async def pyocd_stop(resume: bool = False) -> str:
        try:
            return _js(get_session().close(resume=bool(resume)))
        except Exception as e:  # noqa: BLE001
            return _js(_err(e))
    n += 1

    @server.tool(
        name="pyocd_status",
        title="pyOCD 会话状态（探针 / 目标状态 / 断点数）",
        description=(
            "看一眼会话还在不在、连的哪个探针、目标的实时状态（halted/running/"
            "sleeping/lockup）与停机原因，以及本模块登记过的断点/观察点数量。"
            "排查「怎么读不到内存」时先看这里的 state——running 意味着读到的可能是"
            "半改写的值。"
        ),
    )
    async def pyocd_status() -> str:
        try:
            s = get_session()
            out = s.info()
            if s.running():
                out["breakpoints"] = len(s.bps)
                out["watchpoints"] = len(s.wps)
            out["last_error"] = s.last_error or None
            return _js(out)
        except Exception as e:  # noqa: BLE001
            return _js(_err(e))
    n += 1

    @server.tool(
        name="pyocd_info",
        title="目标身份与内存映射（part number / 内核 / 区域）",
        description=(
            "连上之后先问「这是谁」：part_number、vendor、核列表、当前状态与停机原因；"
            "memory_map=true（默认）再给内存区域表（Flash/RAM/外设的起止与类型），"
            "读地址之前用它确认范围，比猜 0x20000000 靠谱。"
        ),
    )
    async def pyocd_info(memory_map: bool = True) -> str:
        try:
            s = get_session()
            out = {"ok": True, "session": s.info()}
            out["target"] = s.target_info(memory_map=bool(memory_map))
            return _js(out)
        except Exception as e:  # noqa: BLE001
            return _js(_err(e))
    n += 1

    @server.tool(
        name="pyocd_control",
        title="运行控制（halt / resume / reset / step）",
        description=(
            "action：halt（停下）、resume（放开跑）、reset（复位后继续跑）、"
            "reset_halt（复位后停在复位向量，最常用的「从头开始」）、step（单步）、"
            "init（重新走一遍目标初始化，探针状态乱了时用）。\n"
            "reset_type 可选 default/hardware/software/systick/core/vectreset/"
            "sysresetreq；不给就用目标默认。停在 halted 时返回 pc/sp 便于立刻定位。"
        ),
    )
    async def pyocd_control(action: str = "halt", reset_type: str = "") -> str:
        try:
            return _js(get_session().control(action, reset_type=reset_type))
        except Exception as e:  # noqa: BLE001
            return _js(_err(e))
    n += 1

    @server.tool(
        name="pyocd_read_mem",
        title="读内存（带可信度与退化识别）",
        description=(
            "按地址读字节：返回 data_hex（原始字节）、words（按 width 解的无符号整数）、"
            "hexdump 行。**读数自带可信度**：read_confidence=high/medium/low，"
            "degenerate 标整帧全 0/全 FF/同一个 4 字节字重复——最后一种是「目标全速运行时"
            "经 SWD 读 SRAM」的伪值签名，不是真实内容。\n"
            "目标不在 halted 时两读不一致会标 medium 并说明两种解释分不开（变量在变 / "
            "读被打断）；要一致快照先 pyocd_control(action=\"halt\")。"
        ),
    )
    async def pyocd_read_mem(addr: str = "0x20000000", n_bytes: int = 64,
                             width: int = 4, verify: str = "auto",
                             ascii_col: bool = True) -> str:
        try:
            a = _addr(addr)
            nb = int(n_bytes)
            w = int(width)
            if w not in (1, 2, 4, 8):
                return _js({"ok": False, "error": "width 只支持 1/2/4/8",
                            "error_code": "pyocd-bad-width"})
            if nb <= 0:
                return _js({"ok": False, "error": "n_bytes 必须为正",
                            "error_code": "pyocd-bad-length"})
            s = get_session()
            r = s.read_verified(a, nb, verify=verify)
            r["addr"] = "0x%08X" % a
            r["width"] = w
            data = bytes.fromhex(r.get("data_hex") or "")
            r["words"] = ["0x%0*X" % (w * 2, x) for x in _words(data, w)]
            r["hexdump"] = _hexdump(data, a)
            if not ascii_col:
                for i, line in enumerate(r["hexdump"]):
                    r["hexdump"][i] = line.split("  |")[0].rstrip()
            r["ascii"] = _ascii(data)
            return _js(r)
        except Exception as e:  # noqa: BLE001
            return _js(_err(e))
    n += 1

    @server.tool(
        name="pyocd_write_mem",
        title="写内存（写完回读校验）",
        description=(
            "两种给值方式：data_hex（'01 02 03' 或 '0x010203' 都行，按字节原样写），"
            "或 words + width（按小端把整数写成 width 字节，'1,2,3'）。\n"
            "写完默认回读比对（verify=true），返回 verified 与 mismatch_at——"
            "**写成功不等于写对了**：写 Flash 未擦除区域、写只读外设、目标正在跑都可能"
            "让写入静默失效。verify=false 只用于大块搬运。"
        ),
    )
    async def pyocd_write_mem(addr: str = "0x20000000", data_hex: str = "",
                              words: str = "", width: int = 4,
                              verify: bool = True) -> str:
        try:
            a = _addr(addr)
            w = int(width)
            if w not in (1, 2, 4, 8):
                return _js({"ok": False, "error": "width 只支持 1/2/4/8",
                            "error_code": "pyocd-bad-width"})
            if data_hex:
                data = _hex_bytes(data_hex)
            elif words:
                vals = _ints(words)
                data = b"".join((int(v) & ((1 << (8 * w)) - 1)).to_bytes(w, "little")
                                for v in vals)
            else:
                return _js({"ok": False, "error": "data_hex 与 words 至少给一个",
                            "error_code": "pyocd-no-data"})
            s = get_session()
            n = s.write_bytes(a, data)
            out = {"ok": True, "addr": "0x%08X" % a, "written": n,
                   "data_hex": data.hex()}
            if verify:
                try:
                    back = s.read_bytes(a, len(data))
                except Exception as e:  # noqa: BLE001
                    out["verified"] = None
                    out["verify_error"] = str(e)
                    return _js(out)
                if back == data:
                    out["verified"] = True
                else:
                    out["verified"] = False
                    out["readback_hex"] = back.hex()
                    for i, (x, y) in enumerate(zip(data, back)):
                        if x != y:
                            out["mismatch_at"] = "0x%08X" % (a + i)
                            out["mismatch"] = {"wrote": "%02X" % x, "read": "%02X" % y}
                            break
                    out["warning"] = (
                        "回读与写入不一致：目标在跑、写到了只读/受保护区域（Flash 未擦除、"
                        "外设只读位）、或该地址被硬件改写。先 pyocd_control(action=\"halt\") "
                        "并确认内存映射再重试")
            return _js(out)
        except Exception as e:  # noqa: BLE001
            return _js(_err(e))
    n += 1

    @server.tool(
        name="pyocd_reg",
        title="核心寄存器（读 / 写 / 列出可用名）",
        description=(
            "action=read（默认）：不带 names 时返回 r0-r12/sp/lr/pc/xpsr；"
            "names='r0,r1,pc' 只读这几个。action=write 必须给 name 与 value，"
            "写完回读。action=list 返回该目标实际暴露的寄存器名（不同内核不一样，"
            "FPU 目标还有 s0-s31/d0-d15）。"
        ),
    )
    async def pyocd_reg(action: str = "read", name: str = "", value: str = "",
                        names: str = "") -> str:
        try:
            a = str(action or "read").strip().lower()
            s = get_session()
            if a == "list":
                nm = s.reg_names()
                return _js({"ok": True, "count": len(nm), "names": nm})
            if a == "read":
                want = [x.strip() for x in re.split(r"[,\s]+", names or "") if x.strip()]
                regs = s.read_regs(want or None)
                return _js({"ok": True, "action": "read", "state": _state_name(s.target()),
                            "registers": regs})
            if a in ("write", "set"):
                if not name:
                    return _js({"ok": False, "error": "action=write 必须给 name",
                                "error_code": "pyocd-reg-name-required"})
                if value in ("", None):
                    return _js({"ok": False, "error": "action=write 必须给 value",
                                "error_code": "pyocd-reg-value-required"})
                return _js(s.write_reg(name, _addr(value)))
            return _js({"ok": False, "error": "action 只支持 read/write/list，收到 %r" % action,
                        "error_code": "pyocd-bad-action"})
        except Exception as e:  # noqa: BLE001
            return _js(_err(e))
    n += 1

    @server.tool(
        name="pyocd_bp",
        title="断点（set / clear / list）",
        description=(
            "action=set 下断点，kind=auto（默认，让 pyOCD 选）/hw/sw；"
            "action=clear 按地址清；action=list 列**本模块登记过的**断点并用 "
            "find_breakpoint 复核它是否还在（pyOCD 没有全局断点列表 API，这一点"
            "如实写在这里，不假装列全）。硬件断点槽只有 4-8 个，槽满时 set 会返回 "
            "ok=false 而不是假装成功。"
        ),
    )
    async def pyocd_bp(action: str = "set", addr: str = "0x00000000",
                       kind: str = "auto") -> str:
        try:
            a = str(action or "set").strip().lower()
            s = get_session()
            if a == "list":
                return _js(s.list_bps())
            if a == "set":
                return _js(s.set_bp(_addr(addr), kind))
            if a in ("clear", "remove", "delete"):
                return _js(s.clear_bp(_addr(addr)))
            return _js({"ok": False, "error": "action 只支持 set/clear/list",
                        "error_code": "pyocd-bad-action"})
        except Exception as e:  # noqa: BLE001
            return _js(_err(e))
    n += 1

    @server.tool(
        name="pyocd_wp",
        title="观察点（set / clear / list）",
        description=(
            "action=set 下观察点：addr + size + kind（read/write/read_write，默认 write）。"
            "命中后目标会停在 halted 且 halt_reason=watchpoint（pyocd_status 可见）。"
            "action=clear 按 addr+size 清；action=list 列本模块登记过的观察点。"
            "观察点同样吃硬件槽位，且必须 2 的幂大小、地址按 size 对齐。"
        ),
    )
    async def pyocd_wp(action: str = "set", addr: str = "0x20000000", size: int = 4,
                       kind: str = "w") -> str:
        try:
            a = str(action or "set").strip().lower()
            s = get_session()
            if a == "list":
                return _js(s.list_wps())
            if a == "set":
                return _js(s.set_wp(_addr(addr), int(size), kind))
            if a in ("clear", "remove", "delete"):
                return _js(s.clear_wp(_addr(addr), int(size)))
            return _js({"ok": False, "error": "action 只支持 set/clear/list",
                        "error_code": "pyocd-bad-action"})
        except Exception as e:  # noqa: BLE001
            return _js(_err(e))
    n += 1

    @server.tool(
        name="pyocd_flash",
        title="烧录固件（elf / hex / bin，走 CMSIS-Pack 算法）",
        description=(
            "用 pyOCD 的 FileProgrammer 把文件烧进目标 Flash：elf/hex 自带地址，"
            "bin 必须给 base_address。chip_erase：auto（默认，按需擦）/ chip（整片擦）"
            "/ sector（扇区擦）。smart_flash+trust_crc 让重复烧同一份镜像时跳过未变扇区"
            "（省时间，但**它靠 CRC 判等**——镜像里若有随机/时间戳，就不会命中）。\n"
            "**烧完默认复位**（reset=true）；要烧完停在复位向量就 reset=false 再自己 "
            "pyocd_control(action=\"reset_halt\")。"
        ),
    )
    async def pyocd_flash(file: str = "", format: str = "", base_address: str = "0",
                          chip_erase: str = "auto", smart_flash: bool = True,
                          trust_crc: bool = True, reset: bool = True) -> str:
        try:
            if not file:
                return _js({"ok": False, "error": "file 不能为空",
                            "error_code": "pyocd-no-file"})
            ba = _addr(base_address) if str(base_address).strip() not in ("", "0") else 0
            fmt = str(format or "").strip().lower()
            if fmt and fmt not in ("elf", "axf", "hex", "bin"):
                return _js({"ok": False, "error": "format 只支持 elf/axf/hex/bin",
                            "error_code": "pyocd-bad-format"})
            if fmt == "bin" and not ba:
                return _js({"ok": False,
                            "error": "烧 bin 必须给 base_address（bin 里没有地址信息）",
                            "error_code": "pyocd-bin-needs-address"})
            return _js(get_session().flash(file, file_format=fmt, base_address=ba,
                                           chip_erase=chip_erase,
                                           smart_flash=smart_flash,
                                           trust_crc=trust_crc, reset=reset))
        except Exception as e:  # noqa: BLE001
            return _js(_err(e))
    n += 1

    @server.tool(
        name="pyocd_erase",
        title="擦除 Flash（chip / mass / sector）",
        description=(
            "mode=chip 擦整片、mass 走 mass erase（有些目标会顺带解保护/擦配置区）、"
            "sector 按地址擦（必须给 addresses，支持 '0x08000000' 与 "
            "'0x08000000-0x08004000'）。**擦除不可撤销**——只想换固件请直接用 "
            "pyocd_flash（它会按需擦）。"
        ),
    )
    async def pyocd_erase(mode: str = "chip", addresses: str = "") -> str:
        try:
            addrs = None
            if str(addresses or "").strip():
                addrs = [p.strip() for p in re.split(r"[,;\s]+", str(addresses)) if p.strip()]
            return _js(get_session().erase(mode, addrs))
        except Exception as e:  # noqa: BLE001
            return _js(_err(e))
    n += 1

    @server.tool(
        name="pyocd_gdb",
        title="起 pyOCD 的 GDB Server（给外部 IDE / arm-gdb 连）",
        description=(
            "action=start 起一个独立的 ``pyocd gdbserver`` 进程并等端口起来；"
            "action=stop 停它；action=status 看 pid/端口/日志尾部。\n"
            "**gdbserver 要独占探针**：进程内会话开着时 start 会直接报错，先 "
            "pyocd_stop。这条路的用途是「pyOCD 拿探针、VSCode/CLion/GDB 做题」——"
            "本 MCP 自己的读写不要让两边同时做。"
        ),
    )
    async def pyocd_gdb(action: str = "start", port: int = DEF_GDB_PORT,
                        target: str = "", unique_id: str = "", frequency: float = 0,
                        options: str = "", wait: float = 12.0) -> str:
        try:
            s = get_session()
            a = str(action or "start").strip().lower()
            if a == "status":
                return _js({"ok": True, "gdb": s.gdb_info()})
            if a in ("stop", "kill"):
                if s.gdb is None:
                    return _js({"ok": True, "was_running": False})
                p = s.gdb
                running = p.poll() is None
                if running:
                    try:
                        p.terminate()
                        p.wait(timeout=6)
                    except Exception:  # noqa: BLE001
                        try:
                            p.kill()
                        except Exception:  # noqa: BLE001
                            pass
                s.gdb = None
                return _js({"ok": True, "was_running": running,
                            "exit_code": p.returncode,
                            "log_tail": _tail(s.gdb_log, 20)})
            if a != "start":
                return _js({"ok": False, "error": "action 只支持 start/stop/status",
                            "error_code": "pyocd-bad-action"})
            if s.running():
                return _js({"ok": False,
                            "error": "进程内 pyOCD 会话开着，gdbserver 拿不到探针",
                            "error_code": "pyocd-probe-busy",
                            "hint": "先 pyocd_stop，再 pyocd_gdb(action=\"start\")"})
            if s.gdb is not None and s.gdb.poll() is None:
                return _js({"ok": False, "error": "gdbserver 已经在跑",
                            "error_code": "pyocd-gdb-already-running",
                            "gdb": s.gdb_info()})
            av = available()
            if not av.get("installed"):
                return _js({"ok": False, "error": av.get("error"),
                            "error_code": av.get("error_code"), "hint": av.get("hint")})
            port = int(port or DEF_GDB_PORT)
            if _port_open(port):
                return _js({"ok": False,
                            "error": "端口 %d 已被占用（可能是另一个 gdbserver）" % port,
                            "error_code": "pyocd-port-busy"})
            fd, log_path = tempfile.mkstemp(prefix="mdkdebug_pyocd_gdb_", suffix=".log")
            os.close(fd)
            cmd = [sys.executable, "-m", "pyocd", "gdbserver", "-p", str(port)]
            if unique_id:
                cmd += ["-u", str(unique_id)]
            if target:
                cmd += ["-t", str(target)]
            if frequency:
                cmd += ["-f", str(frequency)]
            for k, v in _opt_dict(options).items():
                cmd += ["-O", "%s=%s" % (k, v)]
            logf = open(log_path, "w", encoding="utf-8", errors="replace")
            try:
                p = subprocess.Popen(cmd, stdout=logf, stderr=subprocess.STDOUT,
                                     cwd=os.getcwd())
            except Exception as e:  # noqa: BLE001
                logf.close()
                raise PyOCDError("启动 gdbserver 失败：%s" % e, "pyocd-gdb-start-failed")
            s.gdb = p
            s.gdb_log = log_path
            s.gdb_port = port
            t0 = time.time()
            while time.time() - t0 < float(wait or 12.0):
                if p.poll() is not None:
                    s.gdb = None
                    return _js({"ok": False,
                                "error": "gdbserver 启动后退出了（exit=%s）" % p.returncode,
                                "error_code": "pyocd-gdb-exited",
                                "cmd": cmd, "log": _tail(log_path, 30)})
                if _port_open(port):
                    return _js({"ok": True, "action": "start", "pid": p.pid,
                                "port": port, "wait_s": round(time.time() - t0, 2),
                                "cmd": cmd, "log": log_path,
                                "log_tail": _tail(log_path, 12),
                                "next": "GDB 里 target remote 127.0.0.1:%d" % port})
                time.sleep(0.15)
            return _js({"ok": True, "action": "start", "pid": p.pid, "port": port,
                        "listening": False,
                        "warning": "等了 %.1fs 端口还没起来，进程没退出："
                                   "用 pyocd_gdb(action=\"status\") 看日志尾部"
                                   % float(wait or 12.0),
                        "log_tail": _tail(log_path, 25)})
        except Exception as e:  # noqa: BLE001
            return _js(_err(e))
    n += 1

    @server.tool(
        name="pyocd_log",
        title="pyOCD 链路诊断（版本 / 会话 / gdbserver 日志 / 最近事件）",
        description=(
            "一次看全：pyocd 装没装、什么版本、会话参数、目标状态、gdbserver 的日志"
            "尾部。**连不上或行为怪异时先看这里**——pyOCD 把真正的原因写在日志里"
            "（探针被占、目标不给 ID、pack 里找不到器件），比任何猜测都准。"
        ),
    )
    async def pyocd_log(lines: int = 60, clear: bool = False) -> str:
        try:
            s = get_session()
            out = {"ok": True, "available": available(), "session": s.info(),
                   "events": list(_LOG_RING)[-max(1, int(lines or 60)):]}
            if s.gdb is not None:
                out["gdb"] = s.gdb_info()
            if clear:
                _LOG_RING.clear()
            return _js(out)
        except Exception as e:  # noqa: BLE001
            return _js(_err(e))
    n += 1

    return n
