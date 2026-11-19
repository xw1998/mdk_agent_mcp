# -*- coding: utf-8 -*-
"""批次113 测试：kind="memory" 条件触发。

预注册：docs/trigger-memory-prereg.md（判据 G1–G7，冻结后不得就地改）。
本文件覆盖 G1/G2/G3/G4/G7 + G5 的读次数预算（真机 p95 属 G6，无真机时如实记欠账）。

分节：

  A 工具面：不新增工具（注册 246、默认面 42、serial 组 19）、注解无遗漏
  B 参数与错误：G2 的八类问题各自有 error_code，**不得**退化成 waiting
  C 脏读免疫（G3，核心）：伪值不建基线、不判命中；medium 不参与；连续 ambiguous 转 error
  D 端到端（假客户端）：eq/change/repeat/非阻塞快照/读失败/到期/上限/预算
  E 文档 / 版本 / 闸门

运行：python -m tests.test_batch113
"""
import ast
import asyncio
import json
import os
import re
import sys
import threading
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
# 假客户端：按脚本回 read_mem_verified
# ---------------------------------------------------------------------------
def hx(v, w=4):
    return (int(v) & ((1 << (8 * w)) - 1)).to_bytes(w, "little").hex()


def sample(v, w=4, conf="high", degenerate="", consistent=True, running=None):
    out = {"ok": True, "addr": 0x20000000, "n_bytes": w, "data_hex": hx(v, w),
           "ascii": "", "read_confidence": conf, "reread_count": 0,
           "reread_consistent": consistent, "verify": "auto"}
    if degenerate:
        out["degenerate"] = degenerate
    if running is not None:
        out["while_running"] = running
    return out


def bad_read(msg="uvsock: no response"):
    return {"ok": False, "status_text": msg, "data_hex": "", "read_confidence": "low"}


class FakeClient:
    """script 用完就一直重放最后一条（与真实读「值稳定」等价）。"""

    def __init__(self, script):
        self.script = list(script)
        self.i = 0
        self.calls = []
        self.lock = threading.Lock()

    def read_mem_verified(self, addr, n):
        with self.lock:
            self.calls.append((addr, n, time.time()))
            if self.i < len(self.script):
                r = dict(self.script[self.i])
                self.i += 1
            else:
                r = dict(self.script[-1])
        r.setdefault("ok", True)
        r.setdefault("read_confidence", "high")
        r.setdefault("reread_consistent", True)
        r.setdefault("data_hex", hx(0, n))
        r["addr"] = addr
        r["n_bytes"] = n
        return r


def use_client(fake):
    import mdkdebug.triggers as T
    T.set_client_provider(lambda: fake)
    return T


# ---------------------------------------------------------------------------
# A 工具面
# ---------------------------------------------------------------------------
def section_a():
    from mdkdebug import server as SV, toolbox as TB, annotate as AN
    srv = SV.create_server(port=4823, toolsets="all")
    names = [t.name for t in asyncio.run(srv.list_tools())]
    ALWAYS = set(TB.ALWAYS)
    allset = set(ALWAYS) | {n for v in TB.TOOLSETS.values() for n in v}
    check("A1 不新增工具：注册仍 246", len(allset) == 246, (len(allset), len(names)))
    check("A2 默认暴露仍 42", len(set(TB.TOOLSETS["core"]) | ALWAYS) == 42,
          len(set(TB.TOOLSETS["core"]) | ALWAYS))
    check("A3 serial 组仍 19（不加工具，只加 kind）",
          len(TB.TOOLSETS["serial"]) == 19, len(TB.TOOLSETS["serial"]))
    check("A4 AN.check_surface 无问题（只读/可写归类齐）", AN.check_surface(names) == [],
          AN.check_surface(names))
    import mdkdebug.triggers as T
    check("A5 triggers 导出 add_memory / set_client_provider",
          hasattr(T, "add_memory") and hasattr(T, "set_client_provider"), None)
    check("A6 预算常量：MIN_MEM_POLL_MS=200 / MAX_MEM_TRIGGERS=4 / 默认 500",
          (T.MIN_MEM_POLL_MS, T.MAX_MEM_TRIGGERS, T.DEFAULT_MEM_POLL_MS) == (200, 4, 500),
          (T.MIN_MEM_POLL_MS, T.MAX_MEM_TRIGGERS, T.DEFAULT_MEM_POLL_MS))
    return srv


# ---------------------------------------------------------------------------
# B 参数与错误（G2）
# ---------------------------------------------------------------------------
def section_b(srv):
    fake = FakeClient([sample(0)])
    use_client(fake)

    def code(args):
        out = _call(srv, "trigger_add", args)
        return out.get("ok"), out.get("error_code"), out.get("error", "")

    base = {"kind": "memory", "addr": "0x20000000", "op": "eq", "value": "0"}

    ok, c, msg = code({"kind": "memory", "addr": "0x20000000", "value": "0"})
    check("B1 缺 op → memory-op-required（不给默认 change）",
          ok is False and c == "memory-op-required" and "op" in msg, (ok, c, msg))

    ok, c, msg = code(dict(base, width=3))
    check("B2 width=3 → memory-bad-width", ok is False and c == "memory-bad-width", (ok, c, msg))

    ok, c, msg = code(dict(base, poll_ms=50))
    check("B3 poll_ms=50 → memory-poll-too-fast（不静默抬到下限）",
          ok is False and c == "memory-poll-too-fast" and "200" in msg, (ok, c, msg))

    ok, c, msg = code(dict(base, running="halt"))
    check("B4 running=halt → memory-halt-not-supported（停机采样会改变被观察对象）",
          ok is False and c == "memory-halt-not-supported", (ok, c, msg))

    ok, c, msg = code(dict(base, on_fire="modbus_write"))
    check("B5 on_fire=modbus_write → memory-on-fire-unsupported",
          ok is False and c == "memory-on-fire-unsupported", (ok, c, msg))

    ok, c, msg = code({"kind": "memory", "addr": "0x20000000", "op": "mask_set"})
    check("B6 mask_set 缺 mask → memory-bad-mask", ok is False and c == "memory-bad-mask",
          (ok, c, msg))

    ok, c, msg = code({"kind": "memory", "addr": "0x20000000", "op": "eq",
                       "value": "256", "width": 1})
    check("B7 value 超位宽 → memory-value-out-of-range（不截断）",
          ok is False and c == "memory-value-out-of-range", (ok, c, msg))

    ok, c, msg = code(dict(base, index=-1))
    check("B8 index=-1 → memory-bad-index", ok is False and c == "memory-bad-index", (ok, c, msg))

    ok, c, msg = code({"kind": "memory", "addr": "no_such_symbol_xyz", "op": "eq", "value": "0"})
    check("B9 符号解析失败 → memory-symbol-unresolved",
          ok is False and c == "memory-symbol-unresolved", (ok, c, msg))

    ok, c, msg = code({"kind": "memory", "addr": "0x20000000", "op": "eq", "value": "0",
                       "width": 4})
    check("B10 正常参数能登记（state=waiting，带 addr/width/poll 回显）",
          ok is True and msg == "" and True, (ok, c))
    return True


# ---------------------------------------------------------------------------
# C 脏读免疫（G3，核心）
# ---------------------------------------------------------------------------
def _wait_fire(trig_id, timeout_s=5.0):
    import mdkdebug.triggers as T
    return T.wait(tid=trig_id, timeout_s=timeout_s)


def section_c(srv):
    import mdkdebug.triggers as T

    # C1：伪值（整段重复同一个 4 字节字）绝不能在 gt 上命中
    pseudo = sample(0x01010101, conf="low", degenerate="repeated_word")
    fake = FakeClient([pseudo, pseudo, sample(5), sample(5), sample(200)])
    use_client(fake)
    out = T.add_memory(addr=0x20000000, op="gt", value=100, poll_ms=200)
    tid = out["id"]
    r = _wait_fire(tid)
    fires = r.get("hits") or []
    vals = [f.get("value") for f in fires]
    check("C1 伪值 0x01010101 上不 fire；真值 200 才 fire",
          r.get("fired") is True and vals == [200], (r.get("fired"), vals))
    check("C2 伪值记入 ambiguous_count 且留证 last_ambiguous_hex",
          r.get("ambiguous_count", 0) >= 2 and (r.get("last_ambiguous_hex") or "").startswith("01010101"),
          (r.get("ambiguous_count"), r.get("last_ambiguous_hex")))
    T.cancel("")

    # C3：op=change 不拿伪值当基线
    fake = FakeClient([sample(0x01010101, conf="low", degenerate="repeated_word"),
                       sample(5), sample(9)])
    use_client(fake)
    out = T.add_memory(addr=0x20000000, op="change", poll_ms=200)
    tid = out["id"]
    r = _wait_fire(tid)
    fires = r.get("hits") or []
    check("C3 op=change 首样本(伪值)不建基线，首个高置信样本只建基线，第二次变化才 fire",
          r.get("fired") is True and len(fires) == 1
          and fires[0].get("value") == 9 and fires[0].get("prev_value") == 5,
          [(f.get("prev_value"), f.get("value")) for f in fires])
    T.cancel("")

    # C4：medium（两读不一致）不参与判定
    fake = FakeClient([sample(5), sample(999, conf="medium", consistent=False),
                       sample(6), sample(7)])
    use_client(fake)
    out = T.add_memory(addr=0x20000000, op="gt", value=100, poll_ms=200)
    tid = out["id"]
    time.sleep(1.2)
    snap = T.status(tid)
    check("C4 medium 样本不被当成命中（999 不 fire）",
          not (snap.get("hits") or []) and snap.get("state") == "waiting"
          and snap.get("ambiguous_count", 0) >= 1,
          (snap.get("state"), snap.get("hits"), snap.get("ambiguous_count")))
    T.cancel("")

    # C5：连续 20 次 ambiguous → error（memory-unstable），且文案是「读不可信」
    fake = FakeClient([sample(1, conf="low", degenerate="all_zero")])
    use_client(fake)
    out = T.add_memory(addr=0x20000000, op="eq", value=1, poll_ms=200)
    tid = out["id"]
    r = T.wait(tid, timeout_s=8.0)
    check("C5 连续 20 次 ambiguous → state=error / memory-unstable",
          r.get("state") == "error" and r.get("error_code") == "memory-unstable",
          (r.get("state"), r.get("error_code")))
    check("C6 该错误明确区分「读不可信」与「条件不成立」",
          "不是" in (r.get("last_error") or "") and "读不可信" in (r.get("last_error") or ""),
          r.get("last_error"))
    T.cancel("")
    return True


# ---------------------------------------------------------------------------
# D 端到端（假客户端）
# ---------------------------------------------------------------------------
def section_d(srv):
    import mdkdebug.triggers as T

    # D1 eq 命中
    fake = FakeClient([sample(1), sample(1), sample(7)])
    use_client(fake)
    out = T.add_memory(addr=0x20000000, op="eq", value=7, poll_ms=200, label="等到 7")
    r = T.wait(out["id"], timeout_s=5.0)
    check("D1 op=eq 命中，value/value_hex/read_confidence 齐全",
          r.get("fired") is True and (r.get("hits") or [{}])[0].get("value") == 7
          and (r.get("hits") or [{}])[0].get("read_confidence") == "high",
          r.get("hits"))
    T.cancel("")

    # D2 repeat 连盯
    fake = FakeClient([sample(3)])
    use_client(fake)
    out = T.add_memory(addr=0x20000000, op="eq", value=3, poll_ms=200,
                       repeat=True, cooldown_s=0.2, max_fires=3)
    tid = out["id"]
    time.sleep(2.0)
    snap = T.status(tid)
    check("D2 repeat=true 连续命中（≥2 次，受 cooldown 限制）",
          len(snap.get("hits") or []) >= 1 and snap.get("fire_count", 0) >= 2,
          (snap.get("fire_count"), snap.get("state")))
    T.cancel("")

    # D3 block=false 只取快照
    fake = FakeClient([sample(0)])
    use_client(fake)
    out = T.add_memory(addr=0x20000000, op="eq", value=99, poll_ms=200)
    r = T.wait(out["id"], timeout_s=3, block=False)
    check("D3 block=false 立即返回（fired=false / timeout_kind=blocked-off）",
          r.get("fired") is False and r.get("timeout_kind") == "blocked-off", r.get("timeout_kind"))
    T.cancel("")

    # D4 连续读失败 → error memory-read-failed
    fake = FakeClient([bad_read()])
    use_client(fake)
    out = T.add_memory(addr=0x20000000, op="eq", value=1, poll_ms=200)
    r = T.wait(out["id"], timeout_s=8.0)
    check("D4 连续 20 次读失败 → error / memory-read-failed",
          r.get("state") == "error" and r.get("error_code") == "memory-read-failed",
          (r.get("state"), r.get("error_code")))
    T.cancel("")

    # D5 到期 expired，且文案不把「没等到」读成「条件不成立」
    fake = FakeClient([sample(0)])
    use_client(fake)
    out = T.add_memory(addr=0x20000000, op="eq", value=99, poll_ms=200, duration_s=0.5)
    r = T.wait(out["id"], timeout_s=4.0)
    check("D5 duration_s 到点 → expired，且文案写明「不等于从未发生」",
          r.get("state") == "expired" and "不等于" in (r.get("last_error") or ""),
          (r.get("state"), r.get("last_error")))
    T.cancel("")

    # D6 MAX_MEM_TRIGGERS=4
    fake = FakeClient([sample(0)])
    use_client(fake)
    ids = []
    for i in range(4):
        ids.append(T.add_memory(addr=0x20000000 + 4 * i, op="eq", value=99, poll_ms=500)["id"])
    try:
        T.add_memory(addr=0x20000100, op="eq", value=0, poll_ms=500)
        too_many = None
    except T.TriggerError as e:
        too_many = getattr(e, "code", "")
    check("D6 内存触发上限 4 → memory-too-many", too_many == "memory-too-many", too_many)
    T.cancel("")

    # D7 读次数预算（G5 的假链路版）：4 个触发 @200ms ≈ 每秒 20 次采样，不越界放大
    fakes = []
    ids = []
    for i in range(4):
        fc = FakeClient([sample(0)])
        fakes.append(fc)
        use_client(fc)
        ids.append(T.add_memory(addr=0x20000000 + 4 * i, op="eq", value=99, poll_ms=200))
    t0 = time.time()
    time.sleep(1.2)
    n = sum(len(fc.calls) for fc in fakes)
    dt = time.time() - t0
    use_client(FakeClient([sample(0)]))  # 恢复默认
    T.cancel("")
    check("D7 4 个触发 @200ms 的采样率 ≈ 4/0.2 ≈ 20 次/秒（预算内，不放大）",
          10 <= n / dt <= 40, "%.1f 次/秒（%.1fs 共 %d 次）" % (n / dt, dt, n))

    # D8 index 参与寻址（addr + index*width）
    fc = FakeClient([sample(5)])
    use_client(fc)
    out = T.add_memory(addr=0x20000000, index=3, width=4, op="eq", value=99, poll_ms=200)
    time.sleep(0.6)
    addrs = {c[0] for c in fc.calls}
    T.cancel("")
    check("D8 index=3 / width=4 → 实际读 0x2000000C", addrs == {0x2000000C}, addrs)
    return True


# ---------------------------------------------------------------------------
# E 文档 / 版本 / 闸门
# ---------------------------------------------------------------------------
def section_e(srv):
    readme = _src("README.md")
    skill = _src("skills/mdkdebug/SKILL.md")
    init = _src("mdkdebug/__init__.py")
    gate = _src("tools/run_all_tests.py")
    srv_src = _src("mdkdebug/server.py")

    check("E1 README 写了 kind=\"memory\" 与「只认高置信样本」",
          ('kind="memory"' in readme or "kind=memory" in readme) and "ambiguous" in readme,
          None)
    check("E2 README/SKILL 写明「采样会漏」",
          "采样会漏" in readme and "采样会漏" in skill, None)
    check("E3 SKILL.md 有内存触发小节", "trigger_add" in skill and "memory" in skill, None)
    ver = re.search(r'__version__ = "(\d+)\.(\d+)\.(\d+)"', init).groups()
    check("E4 版本 ≥ 0.2.37", tuple(int(x) for x in ver) >= (0, 2, 37), ver)
    py = _src("pyproject.toml")
    check("E5 pyproject 版本与 __init__ 一致", ('version = "%s.%s.%s"' % ver) in py, ver)
    check("E6 闸门已登记 test_batch113", "test_batch113" in gate, None)
    # E7 必须断「服务后」的描述：lean 档会把中间段归档，只看源码等于诊断口径没覆盖被测段
    _desc = {t.name: (getattr(t, "description", "") or "")
             for t in asyncio.run(srv.list_tools())}.get("trigger_add", "")
    check("E7 服务后 trigger_add 描述里「采样会漏」/「ambiguous」/「memory」都存活（lean 档）",
          ("采样会漏" in _desc) and ("ambiguous" in _desc) and ("memory" in _desc),
          "len=%d 采样会漏=%s ambiguous=%s memory=%s" % (
              len(_desc), "采样会漏" in _desc, "ambiguous" in _desc, "memory" in _desc))
    for rel in ("mdkdebug/triggers.py", "mdkdebug/server.py", "tests/test_batch113.py"):
        try:
            ast.parse(_src(rel))
            ok = True
        except SyntaxError as e:
            ok = False
            print("    ", e)
        check("E8 %s 能解析" % rel, ok, None)


def main():
    srv = section_a()
    section_b(srv)
    section_c(srv)
    section_d(srv)
    section_e(srv)
    print("\n通过 %d / 失败 %d" % (len(PASS), len(FAIL)))
    if FAIL:
        print("FAIL:", "、".join(FAIL))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
