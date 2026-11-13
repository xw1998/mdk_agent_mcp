# -*- coding: utf-8 -*-
"""批次111 测试：trace 六条通路互指路 + 状态工具分工收敛。

问题：六条观测通路（变量 scope / 热点采样 / 函数录制 / Event Recorder / RTT /
插桩事件流三个后端）此前各讲各的，选错通路的成本是「接线白接、插桩白插、还以为
测不到」；四类状态工具（trace_status / trace_swd_status / trace_buff_status /
trace_eventrec）也没写明谁看哪一层。

分节：

  A routes 主题本身：六条通路齐全、每条给出「详见哪个 topic」、howto 指过来
  B 指针不断链：全 GUIDE 扫描 topic=xxx 必须都在 GUIDE 里；routes 真能被取到
  C 状态工具分工：四个状态工具的描述互相点名（不是各说各话）
  D 采集工具的出口指针：十个工具的描述里都有 topic=routes，且 lean 档下仍可见
  E 文档 / 版本 / 闸门登记

运行：python -m tests.test_batch111
"""
import ast
import asyncio
import json
import os
import re
import sys

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
        txt = "\n".join(p for p in parts if p) or str(r)
        try:
            return json.loads(txt)
        except Exception:
            return {"_raw": txt}
    return asyncio.run(_go())


# ---------------------------------------------------------------------------
# A routes 主题
# ---------------------------------------------------------------------------
def section_a():
    print("\nA routes 主题：六条通路 + 每条给出去处")
    from mdkdebug import trace as T

    g = T.GUIDE
    r = g.get("routes") or ""
    check("A1 新增 topic=routes", bool(r), sorted(g))
    paths = {
        "①变量时间线": ("trace_scope_start", "trace_scope_read"),
        "②热点占比": ("trace_pcsample", "trace_profile"),
        "③函数进入/退出": ("trace_record", "FPB"),
        "④Event Recorder": ("trace_eventrec", "SCVD"),
        "⑤RTT": ("trace_rtt_attach", "trace_rtt_read"),
        "⑥插桩事件流": ("trace_swo_start", "trace_buff_status", "trace_swd_status"),
    }
    missing = []
    for label, keys in paths.items():
        for k in keys:
            if k not in r:
                missing.append("%s/%s" % (label, k))
    check("A2 六条通路的工具名都在（含各自的前提词）", missing == [], missing)
    check("A3 每条都写明「详见 topic=…」（不是只列名字）",
          r.count("详见 topic=") >= 6, r.count("详见 topic="))
    check("A4 讲清三问（要不要改代码 / 会不会停机 / 能不能不丢）",
          all(k in r for k in ("改目标代码", "停机", "一条不丢")), r[:200])
    check("A5 硬边界写死：ETM 才能「每跳都记」，SWD 两线做不到",
          "ETM" in r and "做不到" in r, r[-400:])
    check("A6 howto 顶部指到 routes（新读者先看全表再看细节）",
          "topic=routes" in (g.get("howto") or ""), (g.get("howto") or "")[:120])


# ---------------------------------------------------------------------------
# B 指针不断链
# ---------------------------------------------------------------------------
def section_b():
    print("\nB 指针不断链：topic=xxx 必须都存在")
    from mdkdebug import server as SV
    from mdkdebug import trace as T

    bad = []
    for k, v in T.GUIDE.items():
        for m in re.findall(r"topic=([a-z_0-9]+)", v or ""):
            if m not in T.GUIDE:
                bad.append("%s→%s" % (k, m))
    check("B1 全 GUIDE 里没有悬空的 topic 指针", bad == [], bad)
    refs = set(re.findall(r"topic=([a-z_0-9]+)", T.GUIDE.get("routes") or ""))
    check("B2 routes 指向的主题足够多（≥5 个，且不指回自己）",
          len(refs) >= 5 and "routes" not in refs, sorted(refs))

    srv = SV.create_server(port=15992, toolsets="all")
    r = _call(srv, "trace_guide", {"topic": "routes"})
    check("B3 trace_guide(topic=routes) 真能取到且内容非空",
          r.get("ok") is True and "六条通路" in (r.get("text") or ""), r)
    r0 = _call(srv, "trace_guide", {})
    check("B5 无参 trace_guide 的 topics 列表里有 routes",
          "routes" in (r0.get("topics") or []), r0.get("topics"))


# ---------------------------------------------------------------------------
# C 状态工具分工
# ---------------------------------------------------------------------------
def section_c():
    print("\nC 状态工具分工：各看一层，互相点名")
    from mdkdebug import server as SV

    srv = SV.create_server(port=15993, toolsets="all")
    ts = asyncio.run(srv.list_tools())
    d = {t.name: (t.description or "") for t in ts}
    check("C1 trace_status 声明是「跨后端总览」并点名三个后端状态工具",
          "跨后端" in d.get("trace_status", "")
          and all(k in d.get("trace_status", "") for k in
                  ("trace_swd_status", "trace_buff_status", "trace_eventrec")),
          d.get("trace_status", "")[-300:])
    check("C2 trace_swd_status 反过来点名 trace_status（不各说各话）",
          "trace_status" in d.get("trace_swd_status", ""), None)
    check("C3 trace_buff_status 也点名 trace_status 与 trace_swd_status",
          "trace_status" in d.get("trace_buff_status", "")
          and "trace_swd_status" in d.get("trace_buff_status", ""), None)
    check("C4 swd / buff 都自称「控制块」快照（不冒充采集工具）",
          "控制块" in d.get("trace_swd_status", "")
          and "控制块" in d.get("trace_buff_status", ""), None)


# ---------------------------------------------------------------------------
# D 采集工具的出口指针（含 lean 档可见性）
# ---------------------------------------------------------------------------
def section_d():
    print("\nD 采集工具的出口指针（lean 档必须仍可见）")
    from mdkdebug import server as SV

    srv = SV.create_server(port=15994, toolsets="all")
    ts = asyncio.run(srv.list_tools())
    d = {t.name: (t.description or "") for t in ts}
    want = ["trace_status", "trace_swd_status", "trace_buff_status", "trace_eventrec",
            "trace_scope_start", "trace_pcsample", "trace_profile", "trace_record",
            "trace_rtt_attach", "trace_swo_start"]
    miss = [w for w in want if "topic=routes" not in d.get(w, "")]
    check("D1 十个工具都在描述里给出 topic=routes 出口（lean 档没被截掉）",
          miss == [], miss)
    total = sum(len(d.get(w, "")) for w in want)
    check("D2 lean 档仍生效（十个描述合计 < 12000 字符，没把全文塞回上下文）",
          total < 12000, total)


# ---------------------------------------------------------------------------
# E 文档 / 版本 / 闸门
# ---------------------------------------------------------------------------
def section_e():
    print("\nE 文档 / 版本 / 闸门")
    rd = _src("README.md")
    check("E1 README 里有 trace_guide(topic=routes) 入口", "topic=routes" in rd, None)
    init = _src("mdkdebug/__init__.py")
    check("E2 版本号到 0.2.35", "0.2.35" in init, init[-160:])
    check("E3 本批登记进全量闸门", '"test_batch111"' in _src("tools/run_all_tests.py"),
          None)
    ok = True
    try:
        for rel in ("mdkdebug/trace.py", "mdkdebug/server.py"):
            ast.parse(_src(rel))
    except SyntaxError as e:  # noqa: BLE001
        ok = False
        check("E4 两个改动文件都能 parse", False, e)
    if ok:
        check("E4 两个改动文件都能 parse", True, None)


def main():
    print("=" * 70)
    print("批次111：trace 六条通路互指路 + 状态工具分工")
    print("=" * 70)
    section_a()
    section_b()
    section_c()
    section_d()
    section_e()
    print("\n通过 %d 失败 %d" % (len(PASS), len(FAIL)))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
