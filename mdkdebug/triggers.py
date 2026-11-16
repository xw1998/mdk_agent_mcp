# -*- coding: utf-8 -*-
"""条件触发：把「一直等」换成「到点叫我」。

为什么需要
----------
串口与 Modbus 的既有工具都是**阻塞式**的：``serial_expect`` 等到命中或超时、
``modbus_read`` 发一帧收一帧。AI 想让「目标复位后打出某行日志」「某个保持寄存器
超过阈值」这类条件成立，只能自己反复调 ``serial_read`` / ``modbus_read`` 做轮询——
每一次调用都要占用一轮上下文，等到的东西又常常以「还没变」告终。

这里补的是**注册式**等待：``trigger_add`` 只登记条件（可选顺手发一帧/一条命令），
后台线程自己盯着；AI 可以继续编译、烧录、看别的信号，最后调一次 ``trigger_wait``
拿结论（或 ``trigger_wait(block=false)`` 立即取快照，完全不阻塞）。

设计要点
--------
1. **只认注册之后的新事件**：串口基线取注册瞬间的 ``next_seq``，缓冲区里的老日志
   不会被当成命中（与 ``serial_expect`` 同一口径）；Modbus 第一次采样只建立基线，
   ``op="change"`` 不会因为「第一次读到值」就误触发。
2. **不猜**：条件参数不全、op 不认识、value 不是数、要读的位置超出返回块，
   一律报错并说清改哪个参数；轮询出错（超时/CRC 错）不静默吞掉，计入
   ``errors``/``last_error`` 并继续等，连续失败到上限才转 ``error`` 状态。
3. **端口只借不抢**：串口触发只用 ``serialmon`` 已持有的监听，不自己开端口；
   Modbus 触发走 ``modbus.ensure`` 复用会话（同口同参数不重开口，避免 DTR 抖动
   复位目标板）。串口监听被停掉时状态转 ``error`` 并给出重新监听的指路，
   而不是假装还在等。
4. **一定有终点**：每个触发都有 ``duration_s``（默认 900 秒，与串口的空闲释放同量级），
   到点转 ``expired``；进程退出、全部取消都会停线程。默认 ``once``——命中一次就停，
   不会在后台无限重发 ``on_fire`` 动作。
"""
from __future__ import annotations

import atexit
import logging
import re
import threading
import time

from . import modbus, serialmon

logger = logging.getLogger("mdkdebug.triggers")

MAX_TRIGGERS = 8
MAX_HISTORY = 20
MAX_FIRES = 200
DEFAULT_DURATION_S = 900.0
MIN_POLL_MS = 20
DEFAULT_SERIAL_POLL_MS = 50
DEFAULT_MODBUS_POLL_MS = 200
# 批次113：内存通路。UVSOCK 每次读是真实链路往返（运行态还要多复读一轮），
# 比串口行匹配贵一个数量级，所以下限单独抬高、并发数单独限死。
MIN_MEM_POLL_MS = 200
DEFAULT_MEM_POLL_MS = 500
MAX_MEM_TRIGGERS = 4
MEM_WIDTHS = (1, 2, 4, 8)
MEM_MAX_CONSECUTIVE_AMBIGUOUS = 20
OPS = ("eq", "ne", "gt", "ge", "lt", "le", "change", "mask_set", "mask_clear")
ON_FIRE = ("none", "serial_send", "modbus_write")


class TriggerError(ValueError):
    """参数/状态问题：调用方要把它当成「这次没登记成」而不是「等到了」。

    ``code`` 是可选的错误码（批次113）：内存通路的七类参数/前提问题要各自可辨，
    而串口/Modbus 既有的 ``raise TriggerError(...)`` 不带码、由工具层统一落到
    ``invalid-argument``，行为与批次112 完全一致。
    """

    def __init__(self, msg, code: str = ""):
        super().__init__(msg)
        self.code = str(code or "")


# ----------------------------------------------------------------------
# 比较
# ----------------------------------------------------------------------
def compare(op: str, cur, prev, target, mask=None) -> bool:
    """按 op 比较当前值与目标值。参数不合法抛 TriggerError（不返回 False 糊过去）。"""
    o = str(op or "").strip().lower()
    o = {"==": "eq", "=": "eq", "!=": "ne", ">": "gt", ">=": "ge",
         "<": "lt", "<=": "le", "changed": "change", "delta": "change",
         "masked": "mask_set", "cleared": "mask_clear"}.get(o, o)
    if o not in OPS:
        raise TriggerError("op 只支持 %s，收到: %s" % (" / ".join(OPS), op))
    if o == "change":
        if prev is None:
            return False
        return cur != prev
    if o in ("mask_set", "mask_clear"):
        if mask is None:
            raise TriggerError("op=%s 时必须给 mask（如 0x0100）" % o)
        hit = bool(int(cur) & int(mask))
        return hit if o == "mask_set" else (not hit)
    if target is None:
        raise TriggerError("op=%s 时必须给 value" % o)
    try:
        t = int(target)
    except (TypeError, ValueError):
        raise TriggerError("value 必须是整数（十进制或 0x 十六进制），收到: %r" % (target,))
    c = int(cur)
    return {"eq": c == t, "ne": c != t, "gt": c > t, "ge": c >= t,
            "lt": c < t, "le": c <= t}[o]


# ----------------------------------------------------------------------
# 触发器
# ----------------------------------------------------------------------
class Trigger:
    def __init__(self, tid: str, kind: str, label: str, params: dict):
        self.id = tid
        self.kind = kind                    # serial / modbus
        self.label = label
        self.params = params
        self.state = "waiting"              # waiting / fired / stopped / expired / error
        self.created = time.time()
        self.started = 0.0
        self.deadline = 0.0
        self.polls = 0
        self.errors = 0
        self.consecutive_errors = 0
        self.fires = []
        self.last_error = ""
        self.last_error_code = ""
        self.last_match = ""
        self.last_value = None
        self.last_hex = ""
        self.last_sample_at = 0.0
        self.error_code = ""
        self.hint = ""
        # 批次113（kind=memory）：只有高置信样本才算样本，其余记 ambiguous。
        self.ambiguous = 0
        self.ambiguous_consecutive = 0
        self.last_ambiguous_hex = ""
        self.last_confidence = ""
        self.last_while_running = None
        self.baseline_ready = False
        self.sample_ts = []
        self.cursor = None
        self.prev_value = None
        self.event = threading.Event()
        self.stop_ev = threading.Event()
        self.thread = None
        self._lock = threading.RLock()

    # ---- 生命周期 ----
    def start(self, target, duration_s: float):
        self.started = time.time()
        self.deadline = self.started + max(1.0, float(duration_s or DEFAULT_DURATION_S))
        self.thread = threading.Thread(target=target, args=(self,), name="mdk-trigger-%s" % self.id)
        self.thread.daemon = True
        self.thread.start()
        return self

    def stop(self, state: str = "stopped", reason: str = ""):
        with self._lock:
            if self.state in ("stopped", "expired"):
                return
            self.state = state
            if reason:
                self.last_error = reason
        self.stop_ev.set()
        self.event.set()

    def set_error(self, code: str, msg: str, hint: str = ""):
        with self._lock:
            self.state = "error"
            self.error_code = code
            self.last_error_code = code
            self.last_error = msg
            if hint:
                self.hint = hint
        self.stop_ev.set()
        self.event.set()
        logger.info("trigger %s error %s: %s", self.id, code, msg)

    def fire(self, hit: dict):
        with self._lock:
            hit = dict(hit)
            hit.setdefault("t", round(time.time(), 3))
            hit["seq"] = len(self.fires) + 1
            self.fires.append(hit)
            if len(self.fires) > MAX_HISTORY:
                self.fires = self.fires[-MAX_HISTORY:]
            self.last_value = hit.get("value", self.last_value)
            if hit.get("matched_text") is not None:
                self.last_match = hit["matched_text"]
            if hit.get("max_fires") and len(self.fires) >= int(hit["max_fires"]):
                self.state = "fired"
                self.stop_ev.set()
        self.event.set()

    def snapshot(self, with_history: bool = True) -> dict:
        with self._lock:
            now = time.time()
            out = {
                "ok": True,
                "id": self.id,
                "kind": self.kind,
                "label": self.label,
                "state": self.state,
                "pending": self.state == "waiting",
                "fired": self.state == "fired" or bool(self.fires),
                "fire_count": len(self.fires),
                "polls": self.polls,
                "errors": self.errors,
                "consecutive_errors": self.consecutive_errors,
                "last_error": self.last_error,
                "error_code": self.error_code,
                "last_error_code": self.last_error_code,
                "last_match": self.last_match,
                "last_value": self.last_value,
                "last_value_hex": self.last_hex,
                "last_sample_at": round(self.last_sample_at, 3),
                "elapsed_s": round(now - self.created, 1) if self.created else 0,
                "remaining_s": max(0.0, round(self.deadline - now, 1)) if self.deadline else None,
                "params": {k: v for k, v in self.params.items() if not k.startswith("_")},
            }
            if getattr(self, "hint", ""):
                out["hint"] = self.hint
            if self.kind == "memory":
                out.update(_mem_view(self))
            if with_history:
                out["hits"] = list(self.fires[-5:])
                out["hits_truncated"] = len(self.fires) > 5
            return out


_TRIGGERS = {}
_COUNTER = [0]
_LOCK = threading.RLock()


def _next_id() -> str:
    _COUNTER[0] += 1
    return "trg%d" % _COUNTER[0]


def _register(tr: Trigger) -> Trigger:
    with _LOCK:
        if len(_TRIGGERS) >= MAX_TRIGGERS:
            raise TriggerError(
                "同时在跑的触发已有 %d 个（上限 %d）：先 trigger_cancel 掉不用的，"
                "或等它们命中/到期" % (len(_TRIGGERS), MAX_TRIGGERS))
        _TRIGGERS[tr.id] = tr
    return tr


def _pop_finished():
    """把已结束且线程已退出的触发移出表（还在收尾的留着，免得线程往孤儿对象写）。"""
    with _LOCK:
        dead = [k for k, v in _TRIGGERS.items()
                if v.state in ("stopped", "expired", "error")
                and (v.thread is None or not v.thread.is_alive())]
        for k in dead:
            _TRIGGERS.pop(k, None)


def get(tid: str) -> Trigger:
    with _LOCK:
        t = _TRIGGERS.get(str(tid or "").strip())
    if t is None:
        raise TriggerError("没有这个触发：%s（trigger_list 看还有哪些在跑）" % tid)
    return t


# ----------------------------------------------------------------------
# 串口触发
# ----------------------------------------------------------------------
def add_serial(pattern: str, regex: bool = True, case_sensitive: bool = True,
               include_partial: bool = True, poll_ms: int = DEFAULT_SERIAL_POLL_MS,
               send: str = "", hex: str = "", eol: str = "crlf",
               encoding: str = "utf-8", label: str = "",
               duration_s: float = DEFAULT_DURATION_S, repeat: bool = False,
               cooldown_s: float = 0.0, max_fires: int = 0,
               on_fire: str = "none") -> dict:
    """登记一条串口条件。依赖 serialmon 已持有端口（监听在跑）。"""
    pat = str(pattern or "")
    if not pat.strip():
        raise TriggerError("pattern 不能为空：要等的内容是什么？（regex=false 时按字面文本）")
    mon = serialmon.current()
    if mon is None:
        raise TriggerError(
            "当前没有串口监听在运行：串口触发靠监听持有端口。"
            "先 serial_monitor_start(port=\"COM9\", baud=115200) 再登记；"
            "不确定口用 serial_list_ports")
    flags = 0 if case_sensitive else re.IGNORECASE
    try:
        rx = re.compile(pat, flags) if regex else re.compile(re.escape(pat), flags)
    except re.error as e:
        raise TriggerError("正则编译失败（pattern=%s）：%s；要按字面文本匹配请传 regex=false"
                           % (pat, e))
    of = _norm_on_fire(on_fire)
    if of == "modbus_write":
        raise TriggerError("串口触发的 on_fire 只能 none / serial_send；"
                           "要写 Modbus 寄存器请用 kind=modbus 的触发")
    baseline = mon.rb.stats()["next_seq"]
    params = {
        "pattern": pat, "regex": bool(regex), "case_sensitive": bool(case_sensitive),
        "include_partial": bool(include_partial), "poll_ms": _poll(poll_ms, DEFAULT_SERIAL_POLL_MS),
        "baseline_seq": baseline, "repeat": bool(repeat),
        "cooldown_s": max(0.0, float(cooldown_s or 0)),
        "max_fires": int(max_fires or (MAX_FIRES if repeat else 1)),
        "on_fire": of, "send": str(send or ""), "hex": str(hex or ""),
        "eol": "" if eol is None else str(eol), "encoding": str(encoding or "utf-8"),
        "_rx": rx, "_mon": mon,
    }
    tr = Trigger(_next_id(), "serial", str(label or ""), params)
    tr.cursor = baseline
    if repeat:
        tr.params["_cooldown_until"] = 0.0
    _register(tr)
    # 可选：登记后顺手下发（把「先发命令再等」也做成一次调用，且不阻塞）
    sent = None
    raw, eol_note = _build_payload(params, send, hex, eol, encoding)
    if raw:
        w = serialmon.write_bytes(raw, wait_ms=0, max_items=1, read_after=False)
        if not w.get("ok"):
            tr.set_error("serial-send-failed", "登记成功但下发失败：%s" % w.get("error"),
                         "确认监听仍持有端口（serial_monitor_status），或改 options=只等不发")
            return tr.snapshot()
        sent = {"sent_hex": raw.hex(), "sent_bytes": len(raw)}
        if eol_note:
            sent["eol_note"] = eol_note
    out = tr.snapshot()
    tr.start(_serial_loop, duration_s)
    out = tr.snapshot()
    out["sent"] = bool(sent)
    if sent:
        out.update(sent)
    out["note"] = ("已登记：只认注册之后新出现的日志（baseline_seq=%d）；"
                   "命中一次就停（repeat=true 才连续盯）" % baseline)
    return out


def _serial_loop(tr: Trigger):
    p = tr.params
    rx = p["_rx"]
    mon = p["_mon"]
    poll = p["poll_ms"] / 1000.0
    include_partial = p["include_partial"]
    cooldown = p["cooldown_s"]
    max_fires = p["max_fires"]
    while not tr.stop_ev.is_set() and time.time() < tr.deadline:
        cur = serialmon.current()
        if cur is None or not cur.port_held:
            tr.set_error("serial-monitor-gone",
                         "串口监听已停止/释放，条件再也不会被检查（已等 %.0f 秒）"
                         % (time.time() - tr.created),
                         "重新 serial_monitor_start(port=...)，再 trigger_add 一次")
            return
        if cur is not mon:
            tr.set_error("serial-monitor-replaced",
                         "串口监听被换成了另一个实例（%s → %s），本触发盯的是旧监听"
                         % (getattr(mon, "port", "?"), getattr(cur, "port", "?")),
                         "对当前监听重新 trigger_add")
            return
        try:
            r = mon.read(max_items=500, since=tr.cursor)
        except Exception as e:  # noqa: BLE001
            tr.errors += 1
            tr.consecutive_errors += 1
            tr.last_error = "读监听缓冲失败：%s" % e
            tr.last_error_code = "serial-read-failed"
            tr.last_sample_at = time.time()
            if tr.consecutive_errors >= 20:
                tr.set_error("serial-read-failed", tr.last_error)
                return
            tr.stop_ev.wait(poll)
            continue
        tr.polls += 1
        tr.last_sample_at = time.time()
        tr.cursor = r.get("next_seq", tr.cursor) or tr.cursor
        lines = [str(x.get("text", "")) for x in (r.get("items") or [])]
        partial = str(r.get("partial") or "")
        text = "\n".join(lines)
        mo = rx.search(text)
        where = "line"
        if mo is None and include_partial and partial:
            mo = rx.search(partial)
            where = "partial"
        if mo is not None:
            hit = {"matched_text": mo.group(0),
                   "matched_group": (mo.group(1) if mo.groups() else None),
                   "matched_source": where,
                   "matched_line": (partial if where == "partial"
                                    else _line_at(text, lines, mo.start())),
                   "new_lines": len(lines),
                   "cooldown_s": cooldown,
                   "max_fires": max_fires,
                   "t": round(time.time(), 3)}
            if p["on_fire"] == "serial_send":
                try:
                    raw, _note = _build_payload(p, p["send"], p["hex"], p["eol"], p["encoding"])
                    w = serialmon.write_bytes(raw, wait_ms=0, max_items=1, read_after=False)
                    hit["fired_action"] = {"sent_hex": raw.hex(),
                                           "sent_bytes": len(raw),
                                           "ok": bool(w.get("ok")),
                                           "error": w.get("error") if not w.get("ok") else None}
                except Exception as e:  # noqa: BLE001
                    hit["fired_action"] = {"ok": False, "error": str(e)}
            tr.consecutive_errors = 0
            tr.fire(hit)
            if tr.state != "fired" and len(tr.fires) < max_fires:
                if cooldown > 0:
                    tr.stop_ev.wait(cooldown)
                continue
            tr.stop("fired")
            return
        tr.consecutive_errors = 0
        tr.stop_ev.wait(poll)
    if tr.state == "waiting":
        tr.stop("expired", "到 duration_s 仍未命中（不是「条件不成立」，是这段时间内没出现）")


def _line_at(text: str, lines: list, pos: int) -> str:
    idx = text[:pos].count("\n")
    return lines[idx] if 0 <= idx < len(lines) else ""


# ----------------------------------------------------------------------
# Modbus 触发
# ----------------------------------------------------------------------
def add_modbus(port: str = "", baud: int = 9600, databits: int = 8,
               parity: str = "none", stopbits: float = 1, mode: str = "rtu",
               serial_format: str = "", slave: int = 1, func: int = 3,
               addr: int = 0, count: int = 1, index: int = 0,
               op: str = "eq", value: int | None = None, mask: int | None = None,
               signed: bool = False, poll_ms: int = DEFAULT_MODBUS_POLL_MS,
               timeout_ms: int = 1000, label: str = "",
               duration_s: float = DEFAULT_DURATION_S, repeat: bool = False,
               cooldown_s: float = 0.0, max_fires: int = 0,
               on_fire: str = "none", write_addr: int | None = None,
               write_value: int | None = None, write_func: int = 6,
               max_consecutive_errors: int = 20) -> dict:
    op_n = _norm_op(op)
    f = int(func)
    if f not in (1, 2, 3, 4):
        raise TriggerError("轮询式触发只支持读功能码 1/2/3/4（读线圈/离散输入/保持寄存器/"
                           "输入寄存器），收到 func=%s；写请求不适合当条件" % func)
    if mask is not None:
        try:
            mask = modbus._int_literal(mask)  # noqa: SLF001 —— 复用同一套 0x/十进制解析
        except ValueError as e:
            raise TriggerError("mask 不是整数：%s" % e)
    if value is not None:
        try:
            value = modbus._int_literal(value)  # noqa: SLF001
        except ValueError as e:
            raise TriggerError("value 不是整数：%s" % e)
    if op_n in ("mask_set", "mask_clear") and mask is None:
        raise TriggerError("op=%s 时必须给 mask（如 mask=\"0x0100\"）" % op_n)
    if op_n not in ("change", "mask_set", "mask_clear") and value is None:
        raise TriggerError("op=%s 时必须给 value（要和什么比）" % op_n)
    try:
        req = modbus.make_request(mode or "rtu", slave, f, addr=addr, count=count)
    except ValueError as e:
        raise TriggerError("请求参数不合法：%s" % e)
    of = _norm_on_fire(on_fire)
    if of == "serial_send":
        raise TriggerError("on_fire=serial_send 只用于串口触发；Modbus 触发请用 modbus_write")
    if of == "modbus_write":
        if write_addr is None or write_value is None:
            raise TriggerError("on_fire=modbus_write 需要同时给 write_addr 与 write_value")
        try:
            wreq = modbus.make_request(mode or "rtu", slave, int(write_func),
                                       addr=write_addr, value=write_value)
        except ValueError as e:
            raise TriggerError("on_fire 的写请求参数不合法：%s" % e)
    else:
        wreq = None
    ix = int(index or 0)
    if ix < 0:
        raise TriggerError("index 不能为负（收到 %d）" % ix)
    params = {
        "port": str(port or ""), "slave": int(slave), "func": f,
        "addr": int(addr), "count": int(count), "index": ix,
        "op": op_n, "value": value, "mask": mask, "signed": bool(signed),
        "poll_ms": _poll(poll_ms, DEFAULT_MODBUS_POLL_MS),
        "timeout_ms": max(50, int(timeout_ms or 1000)),
        "baud": int(baud or 9600), "databits": int(databits or 8),
        "parity": str(parity or "none"), "stopbits": float(stopbits or 1),
        "mode": modbus.norm_mode(mode or "rtu"), "serial_format": str(serial_format or ""),
        "repeat": bool(repeat), "cooldown_s": max(0.0, float(cooldown_s or 0)),
        "max_fires": int(max_fires or (MAX_FIRES if repeat else 1)),
        "on_fire": of, "write_addr": write_addr, "write_value": write_value,
        "write_func": int(write_func), "max_consecutive_errors": max(1, int(max_consecutive_errors or 20)),
        "_req": req["request"], "request_hex": req["request_hex"],
        "_wreq": (wreq["request"] if wreq else b""),
    }
    tr = Trigger(_next_id(), "modbus", str(label or ""), params)
    _register(tr)
    tr.start(_modbus_loop, duration_s)
    out = tr.snapshot(with_history=False)
    out["note"] = ("已登记并在后台轮询（每 %dms 一次）。"
                   "op=change 第一次采样只建立基线、不触发。"
                   % params["poll_ms"])
    return out


def _modbus_loop(tr: Trigger):
    p = tr.params
    req = p["_req"]
    poll = p["poll_ms"] / 1000.0
    timeout_s = p["timeout_ms"] / 1000.0
    max_err = p["max_consecutive_errors"]
    while not tr.stop_ev.is_set() and time.time() < tr.deadline:
        sess = modbus.current()
        if sess is None or not sess.port_held:
            got = modbus.ensure(port=p["port"], baud=p["baud"], databits=p["databits"],
                                parity=p["parity"], stopbits=p["stopbits"],
                                mode=p["mode"], timeout_s=timeout_s,
                                serial_format=p["serial_format"])
            if not got.get("ok"):
                tr.errors += 1
                tr.consecutive_errors += 1
                tr.last_error = "打开/复用 Modbus 会话失败：%s" % got.get("error")
                tr.last_error_code = got.get("error_code") or "modbus-no-session"
                tr.last_sample_at = time.time()
                if tr.consecutive_errors >= max_err:
                    tr.set_error(tr.last_error_code, tr.last_error, got.get("hint"))
                    return
                tr.stop_ev.wait(poll)
                continue
            sess = got["session"]
        try:
            resp = sess.transact(req, timeout_s=timeout_s)
        except Exception as e:  # noqa: BLE001
            tr.errors += 1
            tr.consecutive_errors += 1
            tr.last_error = "发送/接收异常：%s" % e
            tr.last_error_code = "serial-port-busy"
            tr.last_sample_at = time.time()
            if tr.consecutive_errors >= max_err:
                tr.set_error("serial-port-busy", tr.last_error,
                             "串口可能被拔出或被别的程序抢占；serial_list_ports 确认口还在")
                return
            tr.stop_ev.wait(poll)
            continue
        tr.polls += 1
        tr.last_sample_at = time.time()
        if not resp.get("ok"):
            tr.errors += 1
            tr.consecutive_errors += 1
            tr.last_error = resp.get("error") or "本次请求没有拿到应答"
            tr.last_error_code = resp.get("error_code") or "modbus-no-response"
            if tr.consecutive_errors >= max_err:
                tr.set_error(tr.last_error_code, tr.last_error,
                             resp.get("hint") or "从站没有应答：确认从站号/波特率/接线；"
                             "只想等「总线安静」时不要用本工具")
                return
            tr.stop_ev.wait(poll)
            continue
        dec = resp.get("response") or {}
        kind = dec.get("kind")
        if kind == "registers":
            vals = list(dec.get("signed") if p["signed"] else dec.get("registers") or [])
        elif kind == "bits":
            vals = [1 if b else 0 for b in (dec.get("bits") or [])]
        else:
            tr.set_error("modbus-response-unsupported",
                         "应答解析成 kind=%r，不是寄存器/位块，无法按数值比较" % kind,
                         "确认从站真的按功能码 %d 应答；私有协议先用 modbus_raw 看原始帧" % p["func"])
            return
        ix = p["index"]
        if ix >= len(vals):
            tr.set_error("modbus-index-out-of-range",
                         "index=%d 超出返回块（本次只读到 %d 项：addr=%d count=%d）"
                         % (ix, len(vals), p["addr"], p["count"]),
                         "把 count 加大或把 index 收进 0..%d" % (len(vals) - 1))
            return
        cur = vals[ix]
        tr.last_value = cur
        tr.last_hex = ("0x%04X" % cur) if cur >= 0 else ("-0x%04X" % -cur)
        tr.consecutive_errors = 0
        try:
            hit_now = compare(p["op"], cur, tr.prev_value, p["value"], p["mask"])
        except TriggerError as e:
            tr.set_error("trigger-bad-condition", str(e))
            return
        prev = tr.prev_value
        tr.prev_value = cur
        if hit_now:
            hit = {"value": cur, "value_hex": tr.last_hex, "prev_value": prev,
                   "response_hex": resp.get("response_hex"),
                   "cooldown_s": p["cooldown_s"], "max_fires": p["max_fires"],
                   "t": round(time.time(), 3),
                   "condition": "%s %s" % (p["op"], p["value"] if p["value"] is not None
                                           else ("mask=%s" % p["mask"]))}
            if p["on_fire"] == "modbus_write" and p["_wreq"]:
                try:
                    w = sess.transact(p["_wreq"], timeout_s=timeout_s)
                    hit["fired_action"] = {"ok": bool(w.get("ok")),
                                           "request_hex": p["_wreq"].hex(),
                                           "error": w.get("error") if not w.get("ok") else None}
                except Exception as e:  # noqa: BLE001
                    hit["fired_action"] = {"ok": False, "error": str(e)}
            tr.fire(hit)
            if tr.state != "fired" and len(tr.fires) < p["max_fires"]:
                if p["cooldown_s"] > 0:
                    tr.stop_ev.wait(p["cooldown_s"])
                continue
            tr.stop("fired")
            return
        tr.stop_ev.wait(poll)
    if tr.state == "waiting":
        tr.stop("expired", "到 duration_s 仍未满足条件（这段时间内条件没有成立）")


# ----------------------------------------------------------------------
# 内存触发（批次113）
# ----------------------------------------------------------------------
# 不反向依赖 server：由 create_server() 注入取客户端的函数
# （与 builder.set_reset_connection_hook 同一套手法）。
_CLIENT_PROVIDER = [None]


def set_client_provider(fn) -> None:
    _CLIENT_PROVIDER[0] = fn


def _client_or_raise():
    fn = _CLIENT_PROVIDER[0]
    if fn is None:
        raise TriggerError("调试客户端未初始化：memory 触发需要一条已建好的 UVSOCK 连接",
                           code="memory-no-client")
    try:
        return fn()
    except TriggerError:
        raise
    except Exception as e:  # noqa: BLE001
        raise TriggerError("取调试客户端失败：%s" % e, code="memory-no-client")


def _mem_count() -> int:
    with _LOCK:
        return sum(1 for t in _TRIGGERS.values()
                   if t.kind == "memory" and t.state in ("waiting", "fired"))


def _mem_view(tr: Trigger) -> dict:
    """内存通路专有的现场（只在高置信样本上更新 last_value）。"""
    gaps = []
    ts = list(tr.sample_ts)
    for a, b in zip(ts, ts[1:]):
        gaps.append((b - a) * 1000.0)
    total = tr.polls + tr.ambiguous
    return {
        "read_confidence": tr.last_confidence,
        "while_running": tr.last_while_running,
        "ambiguous_count": tr.ambiguous,
        "ambiguous_rate": (round(tr.ambiguous / total, 4) if total else 0.0),
        "last_ambiguous_hex": tr.last_ambiguous_hex,
        "baseline_ready": tr.baseline_ready,
        "sample_gap_ms": (round(sorted(gaps)[int(len(gaps) * 0.95) - 1 if len(gaps) > 1 else 0], 1)
                          if gaps else None),
        "sampled": tr.polls,
    }


def _decode(raw: bytes, width: int, signed: bool):
    if len(raw) != width:
        return None
    return int.from_bytes(raw, "little", signed=bool(signed))


def add_memory(addr: int, op: str, value=None, mask=None, width: int = 4,
               index: int = 0, signed: bool = False, poll_ms: int = DEFAULT_MEM_POLL_MS,
               label: str = "", duration_s: float = DEFAULT_DURATION_S,
               repeat: bool = False, cooldown_s: float = 0.0, max_fires: int = 0,
               max_consecutive_errors: int = 20,
               addr_arg: str = "", addr_note: str = "",
               on_fire: str = "none", running: str = "live") -> dict:
    """登记一条内存条件（采样型：只看目标此刻的值）。

    与串口/Modbus 的两条差别（预注册 docs/trigger-memory-prereg.md）：
    1. **只认高置信样本**：read_confidence 非 high、或整帧退化、或复读不一致的读数一律记
       ``ambiguous``——不建基线、不算命中、不覆盖 ``last_value``（脏读会伪装成命中）；
    2. **链路只借不抢**：借 create_server() 那条 UVSOCK（UVClient 自带锁），没连上就报错。
    """
    of = _norm_on_fire(on_fire)
    if of != "none":
        raise TriggerError(
            "memory 触发不支持 on_fire=%s：命中后自动写内存会静默失败（写下去可能被 CPU 立即覆盖，"
            "连 write_mem 自己都要靠回读 verified 才敢说落地）。改成 on_fire=none，"
            "等 trigger_wait 命中后显式调 write_mem（记得看 verified）" % of,
            code="memory-on-fire-unsupported")
    run_mode = str(running or "live").strip().lower()
    if run_mode != "live":
        raise TriggerError(
            "memory 触发只支持 running=\"live\"，收到 %r：轮询式「停-读-走」会**改变被观察对象**"
            "（每次暂停 paused_ms 累积，超时/看门狗/握手这类条件会被自己的观测改掉）。"
            "要某一瞬间的一致快照：先 stop 目标再登记，或单次 read_mem(running=\"halt\")"
            % running, code="memory-halt-not-supported")
    op_n = str(op or "").strip().lower()
    if not op_n:
        raise TriggerError(
            "memory 触发必须显式给 op（eq/ne/gt/ge/lt/le/change/mask_set/mask_clear）："
            "不给默认值是有意的——默认 change 会把「我只想看现在是多少」静默变成跳变订阅",
            code="memory-op-required")
    op_n = _norm_op(op_n)
    w = int(width if width is not None else 4)
    if w not in MEM_WIDTHS:
        raise TriggerError("width 只支持 %s（字节），收到: %r"
                           % (" / ".join(str(x) for x in MEM_WIDTHS), width),
                           code="memory-bad-width")
    ix = int(index or 0)
    if ix < 0:
        raise TriggerError("index 不能为负（收到 %d）" % ix, code="memory-bad-index")
    try:
        pm = int(poll_ms if poll_ms is not None else DEFAULT_MEM_POLL_MS)
    except (TypeError, ValueError):
        raise TriggerError("poll_ms 必须是毫秒整数，收到: %r" % (poll_ms,),
                           code="memory-bad-poll")
    if pm < MIN_MEM_POLL_MS:
        raise TriggerError(
            "memory 通路的 poll_ms 下限是 %dms（收到 %d）：每次采样是一次真实 UVSOCK 往返，"
            "目标运行态还会多复读一轮。要更细的分辨率请用 set_watchpoint（数据观察点）或 trace"
            % (MIN_MEM_POLL_MS, pm), code="memory-poll-too-fast")
    bits = 8 * w
    if mask is not None:
        try:
            mask = int(mask)
        except (TypeError, ValueError):
            raise TriggerError("mask 必须是整数（十进制或 0x），收到: %r" % (mask,),
                               code="memory-bad-mask")
        if mask < 0 or mask >= (1 << bits):
            raise TriggerError("mask=0x%X 超出 width=%d 的取值范围（0..0x%X）"
                               % (mask, w, (1 << bits) - 1), code="memory-bad-mask")
    if value is not None:
        try:
            value = int(value)
        except (TypeError, ValueError):
            raise TriggerError("value 必须是整数（十进制或 0x），收到: %r" % (value,),
                               code="memory-bad-value")
        lo = -(1 << (bits - 1)) if signed else 0
        hi = (1 << (bits - (1 if signed else 0))) - 1
        if not (lo <= value <= hi):
            raise TriggerError(
                "value=%d 超出 width=%d signed=%s 的取值范围 %d..%d（不截断、不猜）"
                % (value, w, bool(signed), lo, hi), code="memory-value-out-of-range")
    if op_n in ("mask_set", "mask_clear") and mask is None:
        raise TriggerError("op=%s 时必须给 mask（如 mask=\"0x0100\"）" % op_n,
                           code="memory-bad-mask")
    if op_n not in ("change", "mask_set", "mask_clear") and value is None:
        raise TriggerError("op=%s 时必须给 value（要和什么比）" % op_n,
                           code="memory-bad-value")
    if _mem_count() >= MAX_MEM_TRIGGERS:
        raise TriggerError(
            "同时在跑的内存触发已有 %d 个（上限 %d）：内存采样要走真实调试链路，"
            "再多会把链路拖慢。先 trigger_cancel 掉不用的，或改成在 AI 这边少等一会儿"
            % (MAX_MEM_TRIGGERS, MAX_MEM_TRIGGERS), code="memory-too-many")
    a = int(addr)
    # 登记时先确认链路在（不挂空等），并解析符号（解析只做一次）
    client = _client_or_raise()
    if not hasattr(client, "read_mem_verified"):
        raise TriggerError("当前客户端不支持 read_mem_verified，无法做内存条件触发",
                           code="memory-no-client")
    params = {
        "addr": a, "addr_expr": (str(addr_arg) if str(addr_arg or "") else hex(a)),
        "addr_note": str(addr_note or ""), "width": w, "index": ix,
        "op": op_n, "value": value, "mask": mask, "signed": bool(signed),
        "poll_ms": pm,
        "repeat": bool(repeat), "cooldown_s": max(0.0, float(cooldown_s or 0)),
        "max_fires": int(max_fires or (MAX_FIRES if repeat else 1)),
        "on_fire": "none",
        "max_consecutive_errors": max(1, int(max_consecutive_errors or 20)),
    }
    tr = Trigger(_next_id(), "memory", str(label or ""), params)
    _register(tr)
    tr.start(_memory_loop, duration_s)
    out = tr.snapshot(with_history=False)
    out["note"] = ("已登记并在后台采样（每 %dms 一次）。只认高置信样本："
                   "read_confidence≠high / 整帧退化 / 复读不一致的读数记作 ambiguous，"
                   "不建基线也不判命中。采样会漏——poll_ms 内「变过去又变回来」看不到"
                   % pm)
    return out


def _memory_loop(tr: Trigger):
    p = tr.params
    poll = p["poll_ms"] / 1000.0
    max_err = p["max_consecutive_errors"]
    width = p["width"]
    base_addr = p["addr"] + p["index"] * width
    while not tr.stop_ev.is_set() and time.time() < tr.deadline:
        try:
            client = _client_or_raise()
            r = client.read_mem_verified(base_addr, width)
        except Exception as e:  # noqa: BLE001
            tr.errors += 1
            tr.consecutive_errors += 1
            tr.last_error = "读内存失败：%s" % e
            tr.last_error_code = "memory-read-failed"
            tr.last_sample_at = time.time()
            if tr.consecutive_errors >= max_err:
                tr.set_error("memory-read-failed", tr.last_error,
                             "确认 Keil 还连着（keil_health）；链接被编译/烧录打断后用 "
                             "restart_keil 或重新 create_server")
                return
            tr.stop_ev.wait(poll)
            continue
        tr.polls += 1
        tr.last_sample_at = time.time()
        if not r.get("ok"):
            tr.errors += 1
            tr.consecutive_errors += 1
            tr.last_error = "读内存没成功：%s" % (r.get("status_text") or r.get("error") or "未知原因")
            tr.last_error_code = "memory-read-failed"
            if tr.consecutive_errors >= max_err:
                tr.set_error("memory-read-failed", tr.last_error,
                             "地址是否越界（query_memory_map）？目标是否还在调试态？")
                return
            tr.stop_ev.wait(poll)
            continue
        conf = str(r.get("read_confidence") or "")
        deg = str(r.get("degenerate") or "")
        cons = r.get("reread_consistent")
        tr.last_confidence = conf
        tr.last_while_running = r.get("while_running")
        # 【核心】只有「高置信 + 无退化 + 未判不一致」才算一个样本。
        if conf != "high" or deg or cons is False:
            tr.ambiguous += 1
            tr.ambiguous_consecutive += 1
            tr.last_ambiguous_hex = (r.get("first_read_hex") or r.get("data_hex") or "")
            tr.last_error = ("本次读数不可信（read_confidence=%s%s%s）：不参与判定"
                            % (conf or "?", ("，degenerate=%s" % deg) if deg else "",
                               "，两读不一致" if cons is False else ""))
            tr.last_error_code = "memory-ambiguous"
            tr.sample_ts.append(time.time())
            if len(tr.sample_ts) > 200:
                tr.sample_ts = tr.sample_ts[-200:]
            if tr.ambiguous_consecutive >= MEM_MAX_CONSECUTIVE_AMBIGUOUS:
                tr.set_error(
                    "memory-unstable",
                    "连续 %d 次采样都不是高置信读数（最近一次 read_confidence=%s"
                    "%s）：这不是「条件不成立」，是**读不可信**"
                    % (tr.ambiguous_consecutive, conf or "?",
                       ("，degenerate=%s" % deg) if deg else ""),
                    "先 get_status 确认目标状态；运行态抖动大就 stop 目标再登记，"
                    "或单次 read_mem 看 read_confidence（M7 可问 cache_info / dcache_maintain）")
                return
            tr.stop_ev.wait(poll)
            continue
        tr.consecutive_errors = 0
        tr.ambiguous_consecutive = 0
        raw = bytes.fromhex(r.get("data_hex") or "")
        cur = _decode(raw, width, p["signed"])
        if cur is None:
            tr.errors += 1
            tr.consecutive_errors += 1
            tr.last_error = "读数长度不符（要 %d 字节，拿到 %d 字节）" % (width, len(raw))
            tr.last_error_code = "memory-bad-width"
            if tr.consecutive_errors >= max_err:
                tr.set_error("memory-bad-width", tr.last_error)
                return
            tr.stop_ev.wait(poll)
            continue
        tr.last_value = cur
        tr.last_hex = ("0x%0*X" % (width * 2, cur)) if cur >= 0 else ("-0x%0*X" % (width * 2, -cur))
        tr.sample_ts.append(time.time())
        if len(tr.sample_ts) > 200:
            tr.sample_ts = tr.sample_ts[-200:]
        try:
            hit_now = compare(p["op"], cur, tr.prev_value, p["value"], p["mask"])
        except TriggerError as e:
            tr.set_error("trigger-bad-condition", str(e))
            return
        prev = tr.prev_value
        if p["op"] == "change" and not tr.baseline_ready:
            # 首个高置信样本只建基线：否则「登记的一瞬间」会被当成一次变化
            tr.prev_value = cur
            tr.baseline_ready = True
            tr.stop_ev.wait(poll)
            continue
        tr.baseline_ready = True
        tr.prev_value = cur
        if hit_now:
            hit = {"value": cur, "value_hex": tr.last_hex, "prev_value": prev,
                   "addr": hex(base_addr), "width": width,
                   "read_confidence": conf, "while_running": r.get("while_running"),
                   "raw_hex": raw.hex(),
                   "sample_gap_ms": _mem_view(tr).get("sample_gap_ms"),
                   "cooldown_s": p["cooldown_s"], "max_fires": p["max_fires"],
                   "t": round(time.time(), 3),
                   "condition": "%s %s" % (p["op"], p["value"] if p["value"] is not None
                                           else ("mask=%s" % p["mask"]))}
            tr.fire(hit)
            if tr.state != "fired" and len(tr.fires) < p["max_fires"]:
                if p["cooldown_s"] > 0:
                    tr.stop_ev.wait(p["cooldown_s"])
                continue
            tr.stop("fired")
            return
        tr.stop_ev.wait(poll)
    if tr.state == "waiting":
        tr.stop("expired",
                "到 duration_s 仍未满足条件（这段时间内没有采样到满足条件的高置信读数；"
                "采样会漏，不等于从未发生过）")


# ----------------------------------------------------------------------
# 查询 / 等待 / 取消
# ----------------------------------------------------------------------
def list_all(with_finished: bool = True) -> dict:
    _pop_finished()
    with _LOCK:
        items = [t.snapshot(with_history=False) for t in _TRIGGERS.values()]
    if not with_finished:
        items = [x for x in items if x["state"] == "waiting"]
    items.sort(key=lambda x: x["id"])
    return {"ok": True, "count": len(items), "limit": MAX_TRIGGERS,
            "waiting": sum(1 for x in items if x["state"] == "waiting"),
            "triggers": items,
            "hint": "trigger_wait(id=\"\", timeout_s=0) 可立刻取全部快照，不阻塞"}


def status(tid: str = "") -> dict:
    if not str(tid or "").strip():
        return list_all()
    return get(tid).snapshot()


def wait(tid: str = "", timeout_s: float = 30.0, block: bool = True,
         with_history: bool = True) -> dict:
    """等待某个触发命中（tid 为空 = 任意一个）。

    - ``timeout_s=0`` 或 ``block=false``：立即返回快照（pending=true 表示还在等）。
    - 到时仍未命中：``ok=true, fired=false, timeout=true``——**超时不等于条件不成立**，
      只说明这段时间里没等到；现场（polls / last_value / last_error）一起返回。
    """
    t0 = time.time()
    target = get(tid) if str(tid or "").strip() else None
    limit = max(0.0, float(timeout_s or 0)) if block else 0.0
    deadline = t0 + limit
    # 调用瞬间已经命中过的条数：repeat 触发要等到「再多一次」才算这次等到，
    # 否则第二次 wait 会把上一次的旧命中当成新结果（那是在骗调用方）。
    with _LOCK:
        base = {g.id: len(g.fires) for g in _TRIGGERS.values()}
    while True:
        if target is not None:
            groups = [target]
        else:
            _pop_finished()
            with _LOCK:
                groups = list(_TRIGGERS.values())
        fired = [g for g in groups
                 if (g.state == "fired" and g.fires)
                 or len(g.fires) > base.get(g.id, 0)]
        if fired:
            g = fired[0]
            out = g.snapshot(with_history=with_history)
            out.update({"waited_ms": int((time.time() - t0) * 1000),
                        "wait_timeout_s": limit, "fired": True,
                        "trigger_id": g.id})
            return out
        stopped = [g for g in groups if g.state in ("error", "expired")]
        if target is not None and target.state in ("error", "expired"):
            out = target.snapshot(with_history=with_history)
            out.update({"waited_ms": int((time.time() - t0) * 1000),
                        "wait_timeout_s": limit, "fired": False,
                        "trigger_id": target.id, "ended": target.state,
                        "note": "触发以 %s 结束，不会再有命中" % target.state})
            return out
        if not groups and target is None:
            return {"ok": False, "fired": False, "error": "当前没有任何触发在跑",
                    "error_code": "trigger-none", "waited_ms": 0,
                    "hint": "先 trigger_add 登记条件"}
        if time.time() >= deadline:
            if target is not None:
                out = target.snapshot(with_history=with_history)
                out.update({"waited_ms": int((time.time() - t0) * 1000),
                            "wait_timeout_s": limit, "fired": False,
                            "trigger_id": target.id, "timeout": True,
                            "timeout_kind": ("blocked-off" if not block else "not-yet")})
                if not block:
                    out["note"] = "block=false：只取了快照，没有等待"
                else:
                    out["note"] = ("%dms 内没有命中——**这不等于条件不成立**，只说明这段时间没等到；"
                                   "polls/last_value/last_error 是现场" % int(limit * 1000))
                return out
            # 任意一个：返回等待中的快照集合
            with _LOCK:
                pend = [t.snapshot(with_history=False) for t in _TRIGGERS.values()]
            return {"ok": True, "fired": False, "timeout": True,
                    "waited_ms": int((time.time() - t0) * 1000),
                    "wait_timeout_s": limit, "pending": pend,
                    "timeout_kind": ("blocked-off" if not block else "not-yet"),
                    "note": "没有任何触发命中；pending 里是各自的现场"}
        if stopped and target is None:
            # 全都没了命中的机会：直接回，别白等到超时
            return {"ok": True, "fired": False, "ended": True,
                    "waited_ms": int((time.time() - t0) * 1000),
                    "triggers": [g.snapshot(with_history=False) for g in stopped],
                    "note": "剩下的触发都以 error/expired 结束，不会再有命中"}
        time.sleep(min(0.05, max(0.0, deadline - time.time())))


def cancel(tid: str = "", reason: str = "调用方取消") -> dict:
    key = str(tid or "").strip()
    if not key:
        with _LOCK:
            items = list(_TRIGGERS.values())
        for t in items:
            t.stop("stopped", reason)
            if t.thread is not None:
                t.thread.join(timeout=0.5)
        with _LOCK:
            _TRIGGERS.clear()
        return {"ok": True, "cancelled": len(items), "note": "已取消全部触发"}
    t = get(key)
    t.stop("stopped", reason)
    if t.thread is not None:
        t.thread.join(timeout=1.0)
    _pop_finished()
    return {"ok": True, "cancelled": 1, "trigger_id": t.id, "state": t.state}


def clear_finished() -> dict:
    with _LOCK:
        dead = [k for k, v in _TRIGGERS.items()
                if v.state in ("stopped", "expired", "error", "fired")]
        for k in dead:
            _TRIGGERS.pop(k, None)
    return {"ok": True, "removed": len(dead),
            "note": "只清掉已结束的触发；还在等的用 trigger_cancel"}


def _shutdown():
    with _LOCK:
        items = list(_TRIGGERS.values())
    for t in items:
        try:
            t.stop("stopped", "进程退出")
        except Exception:  # noqa: BLE001
            pass


atexit.register(_shutdown)


# ----------------------------------------------------------------------
# 小工具
# ----------------------------------------------------------------------
def _poll(ms, default_ms) -> int:
    try:
        v = int(ms if ms is not None else default_ms)
    except (TypeError, ValueError):
        raise TriggerError("poll_ms 必须是毫秒整数，收到: %r" % (ms,))
    return max(MIN_POLL_MS, v)


def _norm_op(op) -> str:
    o = str(op or "eq").strip().lower()
    alias = {"==": "eq", "=": "eq", "!=": "ne", ">": "gt", ">=": "ge",
             "<": "lt", "<=": "le", "delta": "change", "changed": "change",
             "masked": "mask_set", "mask": "mask_set", "cleared": "mask_clear"}
    o = alias.get(o, o)
    if o not in OPS:
        raise TriggerError("op 只支持 %s，收到: %s" % (" / ".join(OPS), op))
    return o


def _norm_on_fire(v) -> str:
    o = str(v or "none").strip().lower()
    if o not in ON_FIRE:
        raise TriggerError("on_fire 只支持 %s，收到: %s" % (" / ".join(ON_FIRE), v))
    return o


def _build_payload(p: dict, send: str, hex_s: str, eol, encoding: str):
    """把 send/hex 变成字节；eol 语义与 serial_write 保持一致（复用它的表）。"""
    raw = b""
    note = ""
    toks = [t for t in re.split(r"[\s,]+", str(hex_s or "").replace("0x", "").replace("0X", "")) if t]
    if toks:
        try:
            raw += bytes.fromhex("".join(toks))
        except ValueError as e:
            raise TriggerError("hex 解析失败（应为偶数长度的十六进制字节串）：%s" % e)
    if send:
        try:
            raw += str(send).encode(encoding or "utf-8")
        except Exception as e:  # noqa: BLE001
            raise TriggerError("send 编码失败（encoding=%s）：%s" % (encoding, e))
        eol_name, eol_bytes = _eol_bytes(eol)
        raw += eol_bytes
        if not eol_bytes:
            note = "eol 未生效（eol=none）"
    return raw, note


def _eol_bytes(eol):
    name = str(eol if eol is not None else "crlf").strip().lower()
    table = {"crlf": ("crlf", b"\r\n"), "cr": ("cr", b"\r"), "lf": ("lf", b"\n"),
             "none": ("none", b""), "": ("none", b"")}
    if name in ("auto",):
        return "crlf", b"\r\n"
    return table.get(name, ("crlf", b"\r\n"))


def summary() -> dict:
    with _LOCK:
        items = list(_TRIGGERS.values())
    return {"active": len(items),
            "waiting": sum(1 for t in items if t.state == "waiting"),
            "kinds": sorted({t.kind for t in items}),
            "limit": MAX_TRIGGERS}
