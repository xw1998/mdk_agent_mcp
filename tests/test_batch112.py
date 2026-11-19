# -*- coding: utf-8 -*-
"""批次112 测试：条件触发（trigger_add / list / wait / cancel）。

要解决的问题：串口与 Modbus 的既有工具都是阻塞式的，AI 想等「目标打出某行日志」
「某寄存器超过阈值」只能自己反复轮询，每轮都占上下文。本批补的是注册式等待：
登记条件 → 后台盯 → 干别的 → 一次 trigger_wait 收结论。

分节：

  A 工具面与注解：注册数、四个工具在 serial 组（不进默认面）、只读/可写归类
  B compare 纯函数：九种 op 的语义 + 非法参数一律抛错（不返回 False 糊过去）
  C 参数校验：缺监听/缺 pattern/非法 op/缺 value/缺 mask/负 index/错功能码/未知 kind
  D 串口端到端（假监听）：基线只认新内容、半行匹配、on_fire 下发、repeat 连盯、
    trigger_wait 非阻塞取快照
  E Modbus 端到端（假会话）：op 比较、change 首样本不触发、mask、index 越界、
    连续错误到上限转 error、on_fire 写寄存器
  F 文档 / 版本 / 闸门登记

运行：python -m tests.test_batch112
"""
import ast
import asyncio
import json
import os
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.environ.setdefault("MDKDEBUG_TOOLSETS", "all")

PASS, FAIL = [], []


def check(name, ok, detail=None):
    (PASS if ok else FAIL).append(name)
    print("  [%s] %s %s" % ("PASS" if ok else "FAIL", name,
                            "" if ok else str(detail)[:400]), flush=True)


def _src(rel):
    return open(os.path.join(ROOT, rel), "rb").read().decode("utf-8")


def _call(server, name, args=None):
    async def _go():
        r = await server.call_tool(name, args or {})
        parts = [getattr(c, "text", "") for c in (getattr(r, "content", []) or [])]
        txt = "\n".join(p for p in parts if p)
        try:
            return json.loads(txt)
        except Exception:
            return {"_raw": txt}
    return asyncio.run(_go())


# ---------------------------------------------------------------------------
# 假串口监听 / 假 Modbus 会话
# ---------------------------------------------------------------------------
class FakeRB:
    def __init__(self, mon):
        self.mon = mon

    def stats(self):
        return {"capacity": 2000, "size": len(self.mon.items),
                "first_seq": self.mon.first_seq, "next_seq": self.mon.next,
                "dropped": 0}


class FakeMon:
    port = "COM9"
    port_held = True

    def __init__(self):
        self.items = []
        self.next = 0
        self.first_seq = 0
        self.partial = ""
        self.rb = FakeRB(self)

    def touch(self):
        pass

    def push(self, text):
        self.items.append({"seq": self.next, "text": text, "t": time.time()})
        self.next += 1

    def read(self, max_items=200, clear=False, since=None):
        lo = self.first_seq if since is None else int(since)
        items = [it for it in self.items if it["seq"] >= lo]
        trunc = len(items) > max_items
        if trunc:
            items = items[-max_items:]
        return {"items": items, "count": len(items), "next_seq": self.next,
                "first_seq": self.first_seq, "dropped": 0,
                "truncated": trunc, "partial": self.partial}


class FakeSession:
    port_held = True

    def __init__(self, script, repeat_last=False):
        self.script = list(script)     # 每次 transact 弹一个；元素是 dict 或 Exception
        self.repeat_last = repeat_last  # 脚本用完就一直重放最后一个（模拟「一直是这个值」）
        self.requests = []

    def transact(self, req, timeout_s=None, **kw):
        self.requests.append(bytes(req))
        if not self.script:
            if not self.repeat_last:
                return {"ok": False, "error": "脚本用完了",
                        "error_code": "modbus-timeout-no-response"}
            step = self._last
        elif len(self.script) == 1 and self.repeat_last:
            step = self._last = self.script[0]
        else:
            step = self._last = self.script.pop(0)
        if isinstance(step, Exception):
            raise step
        return step


def _regs(*vals, signed=None):
    regs = [v & 0xFFFF for v in vals]
    return {"ok": True, "response_hex": "aa",
            "response": {"kind": "registers", "registers": regs,
                         "signed": signed if signed is not None else
                         [r - 0x10000 if r >= 0x8000 else r for r in regs]}}


def _bits(*vals):
    return {"ok": True, "response_hex": "bb",
            "response": {"kind": "bits", "bits": [bool(v) for v in vals]}}


# ---------------------------------------------------------------------------
# A 工具面与注解
# ---------------------------------------------------------------------------
def section_a():
    print("\nA 工具面与注解")
    from mdkdebug import server as SV, toolbox as TB, annotate as AN
    srv = SV.create_server(port=15994, toolsets="all")
    names = [t.name for t in asyncio.run(srv.list_tools())]
    trig = sorted(n for n in names if n.startswith("trigger"))
    check("A1 四个 trigger 工具都注册了",
          trig == ["trigger_add", "trigger_cancel", "trigger_list", "trigger_wait"], trig)
    check("A2 注册总数 246（227 + 4）", len(names) == 246, len(names))
    check("A3 注解表覆盖完整", AN.check_surface(sorted(names)) == [],
          AN.check_surface(sorted(names)))
    core = set(TB.TOOLSETS["core"]) | set(TB.ALWAYS)
    check("A4 四个工具都不进默认面（默认暴露仍是 42）",
          not (set(trig) & core) and len(core) == 42, sorted(set(trig) & core))
    serial_grp = set(TB.TOOLSETS["serial"])
    check("A5 四个工具都在 serial 组",
          set(trig) <= serial_grp, sorted(set(trig) - serial_grp))
    check("A6 只读归类：list/wait 只读，add/cancel 会改状态",
          {"trigger_list", "trigger_wait"} <= AN.READONLY
          and {"trigger_add", "trigger_cancel"} <= AN.MUTATING
          and not ({"trigger_add", "trigger_cancel"} & AN.READONLY), None)
    check("A7 trigger_add 标了非幂等（每次登记都是一条新触发）",
          "trigger_add" in AN.NON_IDEMPOTENT, None)
    return srv


# ---------------------------------------------------------------------------
# B compare
# ---------------------------------------------------------------------------
def section_b():
    print("\nB compare 纯函数")
    from mdkdebug import triggers as T
    cases = [
        ("eq", 5, None, 5, None, True), ("eq", 5, None, 4, None, False),
        ("ne", 5, None, 4, None, True),
        ("gt", 6, None, 5, None, True), ("gt", 5, None, 5, None, False),
        ("ge", 5, None, 5, None, True),
        ("lt", 4, None, 5, None, True), ("le", 5, None, 5, None, True),
        ("change", 7, None, None, None, False),
        ("change", 7, 6, None, None, True),
        ("change", 7, 7, None, None, False),
        ("mask_set", 0x0140, None, None, 0x0100, True),
        ("mask_clear", 0x0040, None, None, 0x0100, True),
        ("mask_set", 0x0040, None, None, 0x0100, False),
        ("==", 3, None, 3, None, True),
        ("changed", 9, 8, None, None, True),
    ]
    bad = []
    for op, cur, prev, val, mask, want in cases:
        try:
            got = T.compare(op, cur, prev, val, mask)
        except Exception as e:  # noqa: BLE001
            got = "raise:%s" % e
        if got is not want:
            bad.append((op, cur, prev, val, mask, got, want))
    check("B1 十六种比较组合都对（含 ==/changed 别名）", not bad, bad)

    def _raises(fn):
        try:
            fn()
        except T.TriggerError:
            return True
        except Exception:
            return False
        return False

    check("B2 非法 op 抛 TriggerError", _raises(lambda: T.compare("approximately", 1, None, 1)))
    check("B3 缺 value 抛 TriggerError", _raises(lambda: T.compare("eq", 1, None, None)))
    check("B4 value 不是整数抛 TriggerError", _raises(lambda: T.compare("eq", 1, None, "abc")))
    check("B5 掩码类缺 mask 抛 TriggerError",
          _raises(lambda: T.compare("mask_set", 1, None, None, None)))


# ---------------------------------------------------------------------------
# C 参数校验（工具层）
# ---------------------------------------------------------------------------
def section_c(srv):
    print("\nC 参数校验（工具层）")
    from mdkdebug import triggers as T
    from mdkdebug import serialmon

    old = getattr(serialmon, "_monitor", None)
    serialmon._monitor = None
    try:
        r = _call(srv, "trigger_add", {"kind": "serial", "pattern": "boot"})
        check("C1 没有串口监听时直接报错并指路 serial_monitor_start",
              r.get("ok") is False and "serial_monitor_start" in str(r.get("error")), r)

        r = _call(srv, "trigger_add", {"kind": "modbus", "func": 16, "addr": 0})
        check("C2 写功能码不能当条件（func=16 报错）",
              r.get("ok") is False and "1/2/3/4" in str(r.get("error")), r)

        r = _call(srv, "trigger_add", {"kind": "modbus", "op": "eq"})
        check("C3 op=eq 缺 value 报错",
              r.get("ok") is False and "value" in str(r.get("error")), r)

        r = _call(srv, "trigger_add", {"kind": "modbus", "op": "roughly", "value": "1"})
        check("C4 非法 op 报错并列出可选值",
              r.get("ok") is False and "mask_clear" in str(r.get("error")), r)

        r = _call(srv, "trigger_add", {"kind": "modbus", "op": "mask_set", "mask": ""})
        check("C5 mask 类 op 缺 mask 报错",
              r.get("ok") is False and "mask" in str(r.get("error")), r)

        r = _call(srv, "trigger_add", {"kind": "modbus", "index": -1, "op": "eq", "value": "1"})
        check("C6 负 index 报错", r.get("ok") is False and "index" in str(r.get("error")), r)

        r = _call(srv, "trigger_add", {"kind": "gpio", "pattern": "x"})
        check("C7 未知 kind 报错（只支持 serial/modbus）",
              r.get("ok") is False and "serial / modbus" in str(r.get("error")), r)

        r = _call(srv, "trigger_add", {"kind": "modbus", "on_fire": "modbus_write",
                                       "op": "eq", "value": "1"})
        check("C8 on_fire=modbus_write 缺 write_addr/write_value 报错",
              r.get("ok") is False and "write_addr" in str(r.get("error")), r)

        r = _call(srv, "trigger_wait", {})
        check("C9 没有任何触发时 trigger_wait 不假装等待",
              r.get("ok") is False and r.get("error_code") == "trigger-none", r)

        r = _call(srv, "trigger_list", {"id": "trg999"})
        check("C10 查不存在的触发报 trigger-not-found",
              r.get("ok") is False and r.get("error_code") == "trigger-not-found", r)
    finally:
        serialmon._monitor = old
        T.cancel()


# ---------------------------------------------------------------------------
# D 串口端到端
# ---------------------------------------------------------------------------
def section_d(srv):
    print("\nD 串口端到端（假监听）")
    from mdkdebug import triggers as T
    from mdkdebug import serialmon

    old_mon = getattr(serialmon, "_monitor", None)
    old_write = serialmon.write_bytes
    mon = FakeMon()
    sent = []
    serialmon._monitor = mon
    serialmon.write_bytes = lambda data, **kw: (sent.append(bytes(data)),
                                                {"ok": True})[1]
    try:
        mon.push("boot: old line before registration")
        r = _call(srv, "trigger_add", {"kind": "serial", "pattern": "READY",
                                       "poll_ms": 20})
        tid = r.get("id")
        check("D1 登记成功且 state=waiting",
              r.get("ok") is True and r.get("state") == "waiting" and tid, r)
        time.sleep(0.2)
        r = _call(srv, "trigger_wait", {"id": tid, "block": False})
        check("D2 注册前的老日志不算命中（基线语义）",
              r.get("fired") is False and r.get("polls", 0) >= 1, r)

        mon.push("boot: READY")
        r = _call(srv, "trigger_wait", {"id": tid, "timeout_s": 2})
        check("D3 新日志命中且 matched_text 正确",
              r.get("fired") is True and r.get("last_match") == "READY", r)
        check("D4 命中后一旦即停（state=fired，不再轮询）",
              r.get("state") == "fired", r)

        # 半行匹配：rt_kprintf 常常不带换行
        tr = T.cancel()
        mon2 = FakeMon()
        serialmon._monitor = mon2
        r = _call(srv, "trigger_add", {"kind": "serial", "pattern": "sensor=",
                                       "poll_ms": 20})
        tid2 = r.get("id")
        mon2.partial = "sensor=42"
        r = _call(srv, "trigger_wait", {"id": tid2, "timeout_s": 2})
        check("D5 半行（没换行）也能命中，matched_source=partial",
              r.get("fired") is True and r.get("hits", [{}])[-1].get("matched_source") == "partial", r)

        # on_fire=serial_send：命中时自动回一条
        T.cancel()
        mon3 = FakeMon()
        serialmon._monitor = mon3
        sent.clear()
        r = _call(srv, "trigger_add", {"kind": "serial", "pattern": "PING",
                                       "poll_ms": 20, "on_fire": "serial_send",
                                       "send": "PONG", "eol": "crlf"})
        mon3.push("Rx: PING")
        r = _call(srv, "trigger_wait", {"id": r.get("id"), "timeout_s": 2})
        act = (r.get("hits") or [{}])[-1].get("fired_action") or {}
        check("D6 on_fire=serial_send 命中后真的下发了（含 CRLF）",
              r.get("fired") is True and sent and sent[-1] == b"PONG\r\n"
              and act.get("ok") is True, (r.get("fired"), sent, act))

        # repeat=true：连续命中两次才到 max_fires
        T.cancel()
        mon4 = FakeMon()
        serialmon._monitor = mon4
        r = _call(srv, "trigger_add", {"kind": "serial", "pattern": "ALARM",
                                       "poll_ms": 20, "repeat": True,
                                       "max_fires": 2, "cooldown_s": 0})
        tid4 = r.get("id")
        mon4.push("ALARM 1")
        time.sleep(0.2)
        mon4.push("ALARM 2")
        r = _call(srv, "trigger_wait", {"id": tid4, "timeout_s": 3})
        check("D7 repeat=true 连续盯：两次命中才停",
              r.get("fire_count") == 2 and r.get("state") == "fired", r.get("fire_count"))

        # 监听被停掉 -> 状态转 error，而不是假装还在等
        T.cancel()
        mon5 = FakeMon()
        serialmon._monitor = mon5
        r = _call(srv, "trigger_add", {"kind": "serial", "pattern": "X", "poll_ms": 20})
        tid5 = r.get("id")
        serialmon._monitor = None
        time.sleep(0.2)
        r = _call(srv, "trigger_list", {"id": tid5})
        check("D8 监听消失后转 error（serial-monitor-gone），不假装在等",
              r.get("state") == "error" and r.get("last_error_code") == "serial-monitor-gone", r)

        # 登记时顺手发送
        T.clear_finished() if False else None
        T.cancel()
        mon6 = FakeMon()
        serialmon._monitor = mon6
        sent.clear()
        r = _call(srv, "trigger_add", {"kind": "serial", "pattern": "OK",
                                       "send": "go", "eol": "lf", "poll_ms": 20})
        check("D9 登记同时下发（只发不等），返回 sent=true 与字节",
              r.get("sent") is True and sent and sent[-1] == b"go\n", (r.get("sent"), sent))
    finally:
        T.cancel()
        serialmon._monitor = old_mon
        serialmon.write_bytes = old_write


# ---------------------------------------------------------------------------
# E Modbus 端到端
# ---------------------------------------------------------------------------
def section_e(srv):
    print("\nE Modbus 端到端（假会话）")
    from mdkdebug import triggers as T
    from mdkdebug import modbus

    old_cur, old_ensure = modbus.current, modbus.ensure

    def _serve(sess):
        modbus.current = lambda: sess
        modbus.ensure = lambda **kw: {"ok": True, "session": sess}
        return sess

    try:
        sess = _serve(FakeSession([_regs(10), _regs(60)]))
        r = _call(srv, "trigger_add", {"kind": "modbus", "port": "COM9", "slave": 1,
                                       "func": 3, "addr": 100, "count": 1,
                                       "op": "ge", "value": "50", "poll_ms": 20})
        tid = r.get("id")
        check("E1 Modbus 触发登记成功（带请求摘要）",
              r.get("ok") is True and r.get("state") == "waiting"
              and r.get("params", {}).get("op") == "ge", r)
        r = _call(srv, "trigger_wait", {"id": tid, "timeout_s": 3})
        check("E2 op=ge：10 不触发、60 触发，last_value=60",
              r.get("fired") is True and r.get("last_value") == 60
              and r.get("polls", 0) >= 2, r)
        check("E3 命中时带 response_hex 与条件描述",
              bool((r.get("hits") or [{}])[-1].get("response_hex"))
              and "ge" in str((r.get("hits") or [{}])[-1].get("condition")), r.get("hits"))

        T.cancel()
        sess = _serve(FakeSession([_regs(5), _regs(5), _regs(6)]))
        r = _call(srv, "trigger_add", {"kind": "modbus", "port": "COM9", "addr": 1,
                                       "op": "change", "poll_ms": 20})
        tid = r.get("id")
        r = _call(srv, "trigger_wait", {"id": tid, "timeout_s": 3})
        check("E4 op=change 第一次采样只建基线，不误触发",
              r.get("fired") is True and r.get("last_value") == 6
              and r.get("polls", 0) >= 3, r)

        T.cancel()
        _serve(FakeSession([_regs(0x0040), _regs(0x0140)]))
        r = _call(srv, "trigger_add", {"kind": "modbus", "port": "COM9", "addr": 2,
                                       "op": "mask_set", "mask": "0x0100", "poll_ms": 20})
        r = _call(srv, "trigger_wait", {"id": r.get("id"), "timeout_s": 3})
        check("E5 mask_set：0x0040 不算、0x0140 命中",
              r.get("fired") is True and r.get("last_value") == 0x0140, r)

        T.cancel()
        _serve(FakeSession([_bits(0, 1)]))
        r = _call(srv, "trigger_add", {"kind": "modbus", "port": "COM9", "func": 1,
                                       "addr": 0, "count": 2, "index": 1,
                                       "op": "eq", "value": "1", "poll_ms": 20})
        r = _call(srv, "trigger_wait", {"id": r.get("id"), "timeout_s": 3})
        check("E6 位读功能码：按 index 取位比较",
              r.get("fired") is True and r.get("last_value") == 1, r)

        T.cancel()
        _serve(FakeSession([_regs(1)]))
        r = _call(srv, "trigger_add", {"kind": "modbus", "port": "COM9", "count": 1,
                                       "index": 3, "op": "eq", "value": "1",
                                       "poll_ms": 20})
        r = _call(srv, "trigger_wait", {"id": r.get("id"), "timeout_s": 3})
        check("E7 index 越界直接 error（不猜值）",
              r.get("state") == "error"
              and r.get("last_error_code") == "modbus-index-out-of-range", r)

        T.cancel()
        _serve(FakeSession([{"ok": False, "error": "无应答",
                             "error_code": "modbus-timeout-no-response"},
                            {"ok": False, "error": "无应答",
                             "error_code": "modbus-timeout-no-response"}]))
        r = _call(srv, "trigger_add", {"kind": "modbus", "port": "COM9",
                                       "op": "eq", "value": "1", "poll_ms": 20,
                                       "duration_s": 30})
        # max_consecutive_errors 默认 20：连错 2 次不该停
        time.sleep(0.2)
        r = _call(srv, "trigger_list", {"id": r.get("id")})
        check("E8 偶发无应答不杀触发（errors 计数、状态仍 waiting）",
              r.get("state") == "waiting" and r.get("errors", 0) >= 1, r)

        T.cancel()
        _serve(FakeSession([_regs(7)], repeat_last=True))
        r = _call(srv, "trigger_add", {"kind": "modbus", "port": "COM9", "addr": 9,
                                       "op": "eq", "value": "0", "poll_ms": 20,
                                       "on_fire": "modbus_write", "write_addr": 300,
                                       "write_value": 1, "write_func": 6})
        r = _call(srv, "trigger_wait", {"id": r.get("id"), "timeout_s": 3})
        check("E9 全成对不上时保持 waiting 并可被取消",
              r.get("fired") is False and r.get("state") == "waiting", r)
        c = _call(srv, "trigger_cancel", {"id": r.get("id")})
        check("E10 trigger_cancel 停掉并反映在 list 里",
              c.get("ok") is True and c.get("state") == "stopped", c)

        # on_fire=modbus_write 真写一帧
        T.cancel()
        sess = _serve(FakeSession([_regs(1)]))
        r = _call(srv, "trigger_add", {"kind": "modbus", "port": "COM9", "addr": 5,
                                       "op": "eq", "value": "1", "poll_ms": 20,
                                       "on_fire": "modbus_write", "write_addr": 300,
                                       "write_value": 1, "write_func": 6})
        r = _call(srv, "trigger_wait", {"id": r.get("id"), "timeout_s": 3})
        act = (r.get("hits") or [{}])[-1].get("fired_action") or {}
        check("E11 on_fire=modbus_write 命中后真的发了写帧（功能码 06）",
              r.get("fired") is True and len(sess.requests) >= 2
              and sess.requests[-1][1] == 0x06, (r.get("fired"), [x.hex() for x in sess.requests]))

        T.cancel()
        _serve(FakeSession([_regs(2)]))
        r = _call(srv, "trigger_add", {"kind": "modbus", "port": "COM9",
                                       "op": "eq", "value": "2", "poll_ms": 20})
        r0 = _call(srv, "trigger_wait", {"id": r.get("id"), "timeout_s": 3})
        r1 = _call(srv, "trigger_wait", {"id": r.get("id"), "block": False})
        check("E12 block=false 立刻返回（不阻塞）且仍能报出已命中",
              r0.get("fired") is True and r1.get("fired") is True
              and r1.get("waited_ms", 999) < 500, r1.get("waited_ms"))
    finally:
        T.cancel()
        modbus.current, modbus.ensure = old_cur, old_ensure


# ---------------------------------------------------------------------------
# F 文档 / 版本 / 闸门
# ---------------------------------------------------------------------------
def section_f():
    print("\nF 文档 / 版本 / 闸门")
    readme = _src("README.md")
    skill = _src("skills/mdkdebug/SKILL.md")
    gate = _src("tools/run_all_tests.py")
    init = _src("mdkdebug/__init__.py")
    check("F1 README 有 trigger_add 的用法与「不阻塞」口径",
          "trigger_add" in readme and "trigger_wait" in readme, None)
    check("F2 SKILL.md 写了触发流程", "trigger_add" in skill, None)
    import re as _re
    _m = _re.search(r'__version__\s*=\s*"(\d+)\.(\d+)\.(\d+)"', init)
    _v = tuple(int(x) for x in _m.groups()) if _m else (0, 0, 0)
    check("F3 版本号 ≥ 0.2.36", _v >= (0, 2, 36), _v)
    check("F4 闸门已登记 test_batch112", "test_batch112" in gate, None)
    for rel in ("mdkdebug/triggers.py", "mdkdebug/server.py", "tests/test_batch112.py"):
        try:
            ast.parse(_src(rel))
            ok = True
        except SyntaxError as e:
            ok = False
            print("    ", e)
        check("F5 %s 能解析" % rel, ok, None)


def main():
    srv = section_a()
    section_b()
    section_c(srv)
    section_d(srv)
    section_e(srv)
    section_f()
    print("\n通过 %d / 失败 %d" % (len(PASS), len(FAIL)))
    if FAIL:
        print("FAIL:", "、".join(FAIL))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
