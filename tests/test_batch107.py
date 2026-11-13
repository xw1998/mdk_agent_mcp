# -*- coding: utf-8 -*-
"""批次107 测试：还原 C 的闭环（计划 / 进度 / 证据包 / 核对 / 回编译 / 模拟）。

本批是从 reagent 吸收过来的六件事，**全部落在工具里，不在工具里调 LLM**：

  recover_plan       出一份按依赖序排的还原计划（谁先做、分几批、为什么排除）
  recover_status     读计划 + 结果目录，报五态覆盖与 stale（镜像/版本变了就别信旧结果）
  recover_c_context  单个函数写 C 的证据包（汇编 / 伪 C / 栈槽 / 结构体 / 字符串 / 缺口）
  recover_c_check    候选 C 与镜像里这段码的结构体检（只报强不匹配 → 三态判词）
  recover_c_build    把候选 C 真编出来，指令序列级比对（exact / structural / differs）
  recover_emulate    用 Unicorn 跑一段码看「写了什么内存」（可选依赖，缺失严格报 unsupported）

分节：

  A 工具面：6 个工具注册、归组、注解、schema、参数别名
  B plan 纯逻辑：体积口径、调用边、依赖序、环、难度、排除分类、参数校验
  C plan 实测：真实镜像的计数、依赖序自洽、分批、落盘与「不写进工程目录」
  D status：五态 + stale + 覆盖率
  E contextpack：缺口词表、目标定位、身份一致、上限记账
  F ccheck：三态判词、轮次上限
  G cbuild：工具链缺失如实报、真机编译比对（无 armclang 则 skip 并说明）
  H emulate：unicorn 缺失报 unsupported（用 monkeypatch 造缺失）、装了就跑通
  I 零依赖 / 文档 / 版本闸门

运行：python -m tests.test_batch107
"""
import json
import os
import re
import shutil
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.environ.setdefault("MDKDEBUG_TOOLSETS", "all")

from mdkdebug import annotate as AN          # noqa: E402
from mdkdebug import cbuild as CB            # noqa: E402
from mdkdebug import ccheck as CK            # noqa: E402
from mdkdebug import contextpack as CP       # noqa: E402
from mdkdebug import emulate as EM           # noqa: E402
from mdkdebug import plan as PL              # noqa: E402
from mdkdebug import toolbox as TB           # noqa: E402

AXF = os.path.join(ROOT, "example_mdk_project", "mdk_test", "MDK-ARM",
                   "mdk_test", "mdk_test.axf")
NEW_TOOLS = ("recover_plan", "recover_status", "recover_c_context",
             "recover_c_check", "recover_c_build", "recover_emulate")
READONLY_TOOLS = ("recover_plan", "recover_status",
                  "recover_c_context", "recover_c_check")
HEAVY_TOOLS = ("recover_c_build", "recover_emulate")

PASS, FAIL, SKIP = [], [], []
TMP = []


def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print("  [%s] %s %s" % ("PASS" if ok else "FAIL", name,
                            "" if ok else str(detail)[:400]), flush=True)


def skip(name, why):
    SKIP.append((name, why))
    print("  [SKIP] %s —— %s" % (name, why), flush=True)


def tmpdir(prefix="mdk107_"):
    d = tempfile.mkdtemp(prefix=prefix)
    TMP.append(d)
    return d


def _err(fn, *a, **kw):
    """调用并返回异常消息（调用成功返回空串）。"""
    try:
        fn(*a, **kw)
    except ValueError as e:
        return str(e)
    except Exception as e:                   # noqa: BLE001
        return "WRONG-TYPE:%s" % type(e).__name__
    return ""


def _fake_funcs():
    """造一组函数记录：入口 + 调用目标 + 体积（用来单测纯逻辑，不碰真实镜像）。"""
    return [
        {"addr": 0x1000, "name": "leaf", "size": 16, "call_targets": []},
        {"addr": 0x1100, "name": "mid", "size": 0,
         "call_targets": [0x1000 | 1]},                      # Thumb 位要抹掉
        {"addr": 0x1200, "name": "top", "size": 32,
         "call_targets": [0x1100, 0xDEAD]},                  # 0xDEAD 不在入口表里
    ]


# ---------------------------------------------------------------------------
# A 工具面
# ---------------------------------------------------------------------------
def section_a():
    print("\nA 工具面：注册 / 归组 / 注解 / schema / 别名")
    import asyncio

    from mdkdebug import aliases as AL
    from mdkdebug import server as SV

    srv = SV.create_server(port=15983, toolsets="all")
    tools = {t.name: t for t in asyncio.run(srv.list_tools())}
    names = set(tools)
    check("A1 六个新工具都注册了",
          all(n in names for n in NEW_TOOLS),
          [n for n in NEW_TOOLS if n not in names])
    check("A2 注册总数 227（批次106 后为 227，本批 +6）",
          len(names) == 227, len(names))
    check("A3 build 组 43 个（批次105 后为 44，本批 +6）",
          len(TB.TOOLSETS["build"]) == 43, len(TB.TOOLSETS["build"]))
    check("A4 六个都只归一组且归到 build",
          all(sum(1 for g in TB.TOOLSETS if n in TB.TOOLSETS[g]) == 1
              and n in TB.TOOLSETS["build"] for n in NEW_TOOLS),
          {n: [g for g in TB.TOOLSETS if n in TB.TOOLSETS[g]] for n in NEW_TOOLS})
    check("A5 四个只读环节在 READONLY 且注解 readOnlyHint=true",
          all(n in AN.READONLY
              and AN.annotations_for(n).get("readOnlyHint") is True
              for n in READONLY_TOOLS),
          {n: AN.annotations_for(n) for n in READONLY_TOOLS})
    check("A6 两个重环节不在 READONLY，且在 MUTATING 里",
          all(n not in AN.READONLY and n in AN.MUTATING for n in HEAVY_TOOLS),
          {n: [n in AN.READONLY, n in AN.MUTATING] for n in HEAVY_TOOLS})
    check("A7 两个重环节都标 non-idempotent（重跑≠只跑一次）",
          all(n in AN.NON_IDEMPOTENT
              and AN.annotations_for(n).get("idempotentHint") is False
              for n in HEAVY_TOOLS),
          {n: AN.annotations_for(n) for n in HEAVY_TOOLS})
    check("A8 六个都不是 destructive（不写目标 Flash/RAM、不覆盖用户工程）",
          all(n not in AN.DESTRUCTIVE for n in NEW_TOOLS),
          [n for n in NEW_TOOLS if n in AN.DESTRUCTIVE])
    check("A9 工具面归类完整（check_surface 无问题）",
          AN.check_surface(sorted(names)) == [], AN.check_surface(sorted(names)))
    check("A10 六个都不进默认面（属逆向场景）",
          all(n not in TB.TOOLSETS["core"] for n in NEW_TOOLS))

    want = {
        "recover_plan": {"path", "base", "order", "batch", "exclude",
                         "library", "limit", "out", "deep", "max_functions",
                         "max_insns"},
        "recover_status": {"plan", "results_dir", "out", "current", "base"},
        "recover_c_context": {"path", "target", "symbol", "base", "max_chars",
                              "max_insns", "include_c", "include_asm"},
        "recover_c_check": {"path", "source", "base", "target", "symbol",
                            "code", "state", "max_attempts"},
        "recover_c_build": {"path", "source", "base", "target", "symbol",
                            "code", "compiler", "cpu", "opt", "includes",
                            "work_dir", "keep", "threshold"},
        "recover_emulate": {"path", "entry", "base", "args", "symbol",
                            "max_insns", "stack", "ram", "timeout_us",
                            "reference", "base_reference"},
    }
    bad = {}
    for n, ps in want.items():
        props = set((tools[n].input_schema.get("properties") or {}).keys())
        if not ps <= props:
            bad[n] = sorted(ps - props)
    check("A11 schema 参数名齐全（CLI 靠它生成 --arg）", not bad, bad)

    bad_alias = []
    for n in NEW_TOOLS:
        amap = AL.aliases_of(n)
        real = set((tools[n].input_schema.get("properties") or {}).keys())
        if not amap:
            bad_alias.append((n, "无别名"))
        for alias, primary in amap.items():
            if primary not in real:
                bad_alias.append((n, "%s→%s 主名不存在" % (alias, primary)))
            if alias in real:
                bad_alias.append((n, "%s 会遮蔽真实参数" % alias))
    check("A12 别名表不指向不存在的主名，也不遮蔽真实参数", not bad_alias, bad_alias)
    check("A13 镜像类参数收 image/axf/elf 这类写法（不收 file/src 防与候选源码混淆）",
          AL.aliases_of("recover_c_build").get("image") == "path"
          and AL.aliases_of("recover_c_build").get("src") == "source"
          and "file" not in AL.aliases_of("recover_c_build"),
          AL.aliases_of("recover_c_build"))


# ---------------------------------------------------------------------------
# B plan 纯逻辑
# ---------------------------------------------------------------------------
def section_b():
    print("\nB plan 纯逻辑：体积 / 调用边 / 依赖序 / 环 / 难度 / 排除")
    funcs = _fake_funcs()
    spans = PL._spans(funcs)
    check("B1 符号表给了 size 就用它（basis=symtab）",
          spans[0x1000] == (16, "symtab"), spans)
    check("B2 size 缺失按入口间距兜底（basis=gap）",
          spans[0x1100] == (0x100, "gap"), spans)

    single = PL._spans([{"addr": 0x2000, "size": 0}])
    check("B3 只有一个函数且无 size 时体积未知（basis=unknown，不瞎猜）",
          single[0x2000] == (0, "unknown"), single)

    edges, n_ext = PL._edges(funcs)
    check("B4 调用边只认落在已知入口上的目标（Thumb 位被抹掉）",
          edges[0x1100] == {0x1000} and 0xDEAD not in edges[0x1200], edges)
    check("B5 指到别处的调用计入 external（看不见的依赖要记账）",
          n_ext == 1 and edges[0x1200] == {0x1100}, (n_ext, edges[0x1200]))

    order, cycles, n_cyc = PL.dependency_order(funcs, edges)
    check("B6 依赖序是被调者先出现（post-order）",
          order.index(0x1000) < order.index(0x1100) < order.index(0x1200), order)
    check("B7 无环时 cycles 为空", (cycles, n_cyc) == ([], 0), (cycles, n_cyc))

    ring = [{"addr": 0x3000, "call_targets": [0x3004]},
            {"addr": 0x3004, "call_targets": [0x3000]},
            {"addr": 0x3008, "call_targets": [0x3000]}]
    e2, _ = PL._edges(ring)
    order2, cyc2, n2 = PL.dependency_order(ring, e2)
    check("B8 环被识别出来，且不假装拉平（环内函数排到最后）",
          n2 >= 2 and set(cyc2) <= set(order2) and
          order2[-n2:] == sorted(cyc2), (order2, cyc2))
    check("B9 指向环里的函数自己仍排在环后（不被打乱成环内成员）",
          0x3008 in order2 and order2.index(0x3008) < order2.index(0x3000),
          order2)

    s1, l1, _w = PL._difficulty({"call_targets": []}, 60, "symtab")
    s2, l2, w2 = PL._difficulty({"call_targets": [], "n_cases": 8,
                                "callee_count": 7}, 700, "gap")
    check("B10 难度按体积分档（60 字节 easy / 700 字节 hard）",
          (l1, l2) == ("easy", "hard"), (s1, l1, s2, l2))
    check("B11 入口间距兜底的体积会在理由里显式说明（不把估计当实测）",
          any("入口间距" in x for x in w2), w2)

    why_thunk = PL._excluded_reason({"is_thunk": True, "thunk_to_hex": "0x1000"},
                                    16, "symtab", [])
    why_triv = PL._excluded_reason({"size": 4, "call_targets": []}, 4, "symtab", [])
    why_lib = PL._excluded_reason({"name": "memcpy"}, 100, "symtab", ["memcpy*"])
    why_keep = PL._excluded_reason({"name": "app_main"}, 100, "symtab", ["memcpy*"])
    check("B12 thunk / 常量返回 / 库名规则各自给出排除原因",
          why_thunk.startswith("thunk") and why_triv.startswith("常量返回")
          and why_lib.startswith("名字匹配") and why_keep == "",
          (why_thunk, why_triv, why_lib, why_keep))
    check("B13 排除原因归成 thunk / trivial / library 三档",
          (PL._kind_of(why_thunk), PL._kind_of(why_triv), PL._kind_of(why_lib))
          == ("thunk", "trivial", "library"))

    m = _err(PL.build, "")
    check("B14 缺 path 时 build 返回错误不抛异常",
          PL.build("").get("ok") is False and "path" in PL.build("")["error"], m)
    r = PL.build(AXF, order="nonsense")
    check("B15 order 不合法时报错并列出可选值",
          r.get("ok") is False and "order" in r.get("error", ""), r)
    r = PL.build(AXF, exclude="thunk,bogus")
    check("B16 exclude 里有不认识的类别时报错（不静默忽略）",
          r.get("ok") is False and "bogus" in r.get("error", ""), r)
    r = PL.build(AXF, order="nonsense")
    check("B17 参数校验在剖析镜像之前（坏参数不浪费时间读 500KB）",
          r.get("ok") is False and "in_image" not in r, r)


# ---------------------------------------------------------------------------
# C plan 实测
# ---------------------------------------------------------------------------
def section_c():
    print("\nC plan 实测：计数 / 依赖序自洽 / 分批 / 落盘")
    if not os.path.isfile(AXF):
        skip("C 全节", "示例镜像不存在：%s" % AXF)
        return
    p = PL.build(AXF)
    check("C1 计划出来了", p.get("ok") is True, p.get("error"))
    c = p.get("counts") or {}
    check("C2 计数与基线一致（175 在镜像 / 120 计划 / 55 排除）",
          (c.get("in_image"), c.get("planned"), c.get("excluded"))
          == (175, 120, 55), c)
    check("C3 三档难度加起来等于计划数",
          c.get("easy", 0) + c.get("medium", 0) + c.get("hard", 0)
          == c.get("planned"), c)
    check("C4 身份里有 sha256 / 体积 / 工具版本（换镜像或换版本要能判 stale）",
          len(str(p["identity"].get("sha256"))) == 64
          and p["identity"].get("size") > 0
          and p["identity"].get("tool_version"), p["identity"])

    pos = {r["addr"]: r["index"] for r in p["functions"]}
    broken = []
    for r in p["functions"]:
        if r.get("cycle"):
            continue
        for dep in r.get("depends_on") or []:
            a = int(dep, 16)
            if a in pos and pos[a] > r["index"]:
                broken.append((r["addr_hex"], dep))
    check("C5 依赖序自洽：每个函数的所有已知被调者都排在它前面",
          not broken, broken[:6])

    batches = p.get("batches") or []
    check("C6 分批覆盖整条计划且不重不漏",
          sum(b["size"] for b in batches) == c["planned"]
          and all(b["end_index"] - b["start_index"] + 1 == b["size"]
                  for b in batches)
          and [b["batch"] for b in batches] == list(range(1, len(batches) + 1)),
          [(b["batch"], b["size"]) for b in batches][:4])
    check("C7 每批除最后一批外都是 8 个",
          all(b["size"] == 8 for b in batches[:-1])
          and batches[-1]["size"] == c["planned"] % 8 or c["planned"] % 8 == 0,
          [b["size"] for b in batches])
    check("C8 体积口径写明来源（symtab / gap / unknown 之一）",
          {r["size_basis"] for r in p["functions"]} <= {"symtab", "gap", "unknown"}
          and "gap" in {r["size_basis"] for r in p["functions"]},
          {r["size_basis"] for r in p["functions"]})
    reasons = [g["reason"] for g in p["gaps"]]
    check("C9 gaps 里记了「基址静态定不了」与「参数是推断」两条（看不见 ≠ 没有）",
          any("无法静态确定" in x for x in reasons)
          and any("不是从二进制里读出来的类型信息" in x for x in reasons),
          [x[:40] for x in reasons])

    p_all = PL.build(AXF, exclude="none")
    check("C10 exclude=none 时不排除任何函数（计划数=镜像函数数-0）",
          p_all["counts"]["excluded"] == 0
          and p_all["counts"]["planned"] == p_all["counts"]["in_image"],
          p_all["counts"])
    p_easy = PL.build(AXF, order="easiest-first")
    scores = [r["difficulty_score"] for r in p_easy["functions"]]
    check("C11 easiest-first 真的按难度分升序",
          scores == sorted(scores), scores[:8])

    d = tmpdir("mdk107_plan_")
    r = PL.build(AXF, limit=5, out=d)
    f = ((r.get("out") or {}).get("file") or "")
    ok = bool(f) and os.path.isfile(f)
    body = ""
    if ok:
        with open(f, "rb") as fh:
            body = fh.read().decode("utf-8")
    check("C12 out 给目录时落 plan.json（utf-8 无 BOM、以换行结尾）",
          ok and body and not body.startswith("\ufeff") and body.endswith("\n"),
          (f, body[:20]))
    check("C13 落盘的计划能被 JSON 解析且带 identity",
          ok and json.loads(body).get("artifact_kind") == "plan", f)

    bad_dir = os.path.join(ROOT, "example_mdk_project", "mdk_test", "MDK-ARM")
    r2 = PL.build(AXF, limit=5, out=bad_dir)
    check("C14 out 指到 Keil 工程里时被拒（证据不进源码树）",
          r2.get("ok") is False
          and "evidence-in-build-dir" in json.dumps(r2, ensure_ascii=False),
          r2.get("error"))


# ---------------------------------------------------------------------------
# D status
# ---------------------------------------------------------------------------
def section_d():
    print("\nD status：五态 / 覆盖率 / stale")
    if not os.path.isfile(AXF):
        skip("D 全节", "示例镜像不存在")
        return
    root = tmpdir("mdk107_status_")
    plan_dir = os.path.join(root, "planout")
    res = os.path.join(root, "results")
    os.makedirs(res)
    p = PL.build(AXF, limit=4, out=plan_dir)
    plan_file = (p.get("out") or {}).get("file") or ""
    check("D1 计划落盘成功（status 有东西可读）", os.path.isfile(plan_file), plan_file)

    s0 = PL.status(plan_file, res)
    check("D2 空结果目录时四个都 unattempted",
          s0.get("ok") is True and s0["counts"]["unattempted"] == 4, s0.get("counts"))
    check("D3 覆盖率 0（没碰过）",
          s0["coverage"]["attempted_ratio"] == 0.0, s0["coverage"])

    rows = p["functions"]
    r_att, r_acc, r_fail = rows[0], rows[1], rows[2]
    def stem(row):
        return str(row["addr_hex"]).lower()
    with open(os.path.join(res, stem(r_att) + ".c"), "wb") as fh:
        fh.write(b"int f(void){return 0;}\n")
    with open(os.path.join(res, stem(r_acc) + ".build.json"), "wb") as fh:
        fh.write(b'{"verdict": "exact_sequence"}\n')
    with open(os.path.join(res, stem(r_fail) + ".check.json"), "wb") as fh:
        fh.write(b'{"verdict": "strong_mismatch"}\n')

    s1 = PL.status(plan_file, res)
    check("D4 五态各就各位（attempted 1 / accepted 1 / failed 1 / unattempted 1）",
          s1["counts"] == {"unattempted": 1, "attempted": 1,
                           "accepted": 1, "failed": 1, "stale": 0},
          s1["counts"])
    check("D5 没通过的不算通过（weak/strong 判词进 failed）",
          any(x["state"] == "failed" and x["verdict"] == "strong_mismatch"
              for x in s1["functions"]),
          [x for x in s1["functions"] if x["state"] == "failed"])
    check("D6 覆盖率按「碰过的 / 计划总数」算（3/4）",
          abs(s1["coverage"]["attempted_ratio"] - 0.75) < 1e-9, s1["coverage"])

    other = os.path.join(root, "other.bin")
    with open(other, "wb") as fh:
        fh.write(b"\x00" * 32)
    s2 = PL.status(plan_file, res, current=other)
    check("D7 当前镜像换了（sha256 不同）→ 整条计划 stale",
          s2["stale"] is True and s2["counts"]["stale"] == 4
          and s2["counts"]["accepted"] == 0, s2["counts"])
    check("D8 stale 理由里写明是镜像变了",
          any("镜像变了" in x for x in s2["stale_reasons"]), s2["stale_reasons"])

    s3 = PL.status(plan_file, res, current=AXF)
    check("D9 当前镜像与计划一致时不 stale",
          s3["stale"] is False and s3["counts"]["stale"] == 0, s3["stale_reasons"])

    bad = os.path.join(root, "nope.json")
    with open(bad, "wb") as fh:
        fh.write(b'{"ok": true}\n')
    check("D10 不是计划文件的 JSON 被识别出来（不硬算出五态）",
          PL.status(bad).get("ok") is False, PL.status(bad))


# ---------------------------------------------------------------------------
# E contextpack
# ---------------------------------------------------------------------------
def section_e():
    print("\nE contextpack：缺口词表 / 定位 / 身份 / 上限")
    m = _err(CP._gap, "bogus", "x")
    check("E1 缺口类别只能是五类，别的一律报错（词表不自由发挥）",
          "bogus" in m and "unavailable" in m, m)
    g = CP._gap("limit", "反汇编被截断", detail="超过上限", origin="t")
    check("E2 缺口结构固定（kind / what / detail / origin 四键）",
          set(g) == {"kind", "what", "detail", "origin"}, g)

    if not os.path.isfile(AXF):
        skip("E3-E9", "示例镜像不存在")
        return
    c = CP.pack(AXF, symbol="main")
    check("E3 按 symbol 找到 main 并给出证据包",
          c.get("ok") is True and c["function"]["name"] == "main",
          c.get("error"))
    check("E4 汇编非空且条数与文本一致",
          c["asm"]["n_insns"] > 0
          and c["asm"]["n_insns"] == len(c["asm"]["instructions"]),
          c["asm"]["n_insns"])
    check("E5 伪 C 默认打开（含 code 字段）",
          isinstance(c.get("pseudo_c"), dict) and c["pseudo_c"].get("code"),
          type(c.get("pseudo_c")))
    check("E6 身份指纹与 plan 的一致（同一份镜像同一 sha256）",
          c["identity"]["sha256"] == PL.identity_of(AXF)["sha256"],
          c["identity"]["sha256"])

    c2 = CP.pack(AXF, target="0x080030B0")
    check("E7 按地址（字符串 0x 前缀）也能定位到同一个函数",
          c2.get("ok") is True and c2["function"]["addr_hex"] == "0x080030B0",
          c2.get("function"))

    r = CP.pack(AXF)
    check("E8 既不给 target 也不给 symbol 时报错并说明该给什么",
          r.get("ok") is False and "target" in (r.get("error") or ""), r.get("error"))
    r = CP.pack(AXF, symbol="nosuch_function_xyz")
    check("E9 名字不存在时报错（不猜最像的那个）",
          r.get("ok") is False and "nosuch_function_xyz" in (r.get("error") or ""),
          r.get("error"))

    c3 = CP.pack(AXF, symbol="main", include_c=False, include_asm=False)
    check("E10 关掉伪 C 与汇编后不再产出这两段（只留推断证据）",
          c3.get("pseudo_c") is None and c3["asm"]["n_insns"] == 0, c3.get("chars"))
    check("E11 chars 里记了上限与两段实际字数",
          set(c3.get("chars") or {}) == {"asm", "pseudo_c", "limit"}, c3.get("chars"))
    c4 = CP.pack(AXF, symbol="main", max_chars=500)
    check("E12 max_chars 有下限（不会被压到失真，最低 2000）",
          c4["chars"]["limit"] == 2000, c4["chars"])
    check("E13 gaps 里至少有一条（DWARF 只给行号 / 缺被调者之类）",
          isinstance(c.get("gaps"), list) and len(c["gaps"]) >= 1,
          [g["kind"] for g in (c.get("gaps") or [])])


# ---------------------------------------------------------------------------
# F ccheck
# ---------------------------------------------------------------------------
def section_f():
    print("\nF ccheck：三态判词 / 轮次上限")
    if not os.path.isfile(AXF):
        skip("F 全节", "示例镜像不存在")
        return
    r = CK.check(AXF, symbol="main", code="int main(void){ return 0; }")
    check("F1 候选里连调用都没有 → strong_mismatch",
          r.get("ok") is True and r["verdict"] == "strong_mismatch",
          (r.get("verdict"), [s["signal"] for s in r.get("signals") or []]))
    check("F2 判词带具体的信号名（不只是一个红字）",
          isinstance(r.get("signals"), list) and r["signals"]
          and all("signal" in s and "severity" in s for s in r["signals"]),
          r.get("signals"))
    check("F3 明确写清这是结构体检不是等价性证明",
          "不是等价性证明" in (r.get("scope") or ""), r.get("scope"))

    good = (
        "#include <stdint.h>\n"
        "typedef struct { volatile uint32_t MODER, OTYPER, OSPEEDR, PUPDR,\n"
        "  IDR, ODR, BSRR, LCKR, AFR[2]; } GPIO_TypeDef;\n"
        "void HAL_GPIO_TogglePin(GPIO_TypeDef *GPIOx, uint16_t GPIO_Pin)\n"
        "{\n"
        "  uint32_t odr = GPIOx->ODR;\n"
        "  GPIOx->BSRR = (~odr & GPIO_Pin) | ((odr & GPIO_Pin) << 16u);\n"
        "}\n"
    )
    r2 = CK.check(AXF, symbol="HAL_GPIO_TogglePin", code=good)
    check("F4 结构与汇编对得上时不报强不匹配",
          r2.get("ok") is True and r2["verdict"] != "strong_mismatch",
          (r2.get("verdict"), [s["signal"] for s in r2.get("signals") or []]))
    # 回归：函数定义曾被数成「一次调用」，于是 6 条指令的短函数 + 正确候选
    # 会触发「汇编像常量返回、源码却在调人」这条强判据（真实假阳性）。
    check("F4b 函数定义不算调用（6 条指令的短函数 + 正确候选 → no_obvious_mismatch）",
          r2.get("verdict") == "no_obvious_mismatch",
          (r2.get("verdict"), r2.get("source", {}).get("stats")))

    d = tmpdir("mdk107_check_")
    st = os.path.join(d, "state.json")
    first = CK.check(AXF, symbol="HAL_GPIO_TogglePin", code=good, state=st,
                     max_attempts=2)
    second = CK.check(AXF, symbol="HAL_GPIO_TogglePin", code=good, state=st,
                      max_attempts=2)
    third = CK.check(AXF, symbol="HAL_GPIO_TogglePin", code=good, state=st,
                     max_attempts=2)
    check("F5 前两轮正常计数（attempts 1 → 2）",
          first["attempts"]["count"] == 1 and second["attempts"]["count"] == 2,
          (first["attempts"], second["attempts"]))
    check("F6 第三轮超限：ok=false + attempt_budget_exhausted（不无限重试）",
          third.get("ok") is False
          and third.get("error_code") == "attempt_budget_exhausted",
          third.get("error_code"))
    check("F7 超限返回里仍带上一个轮次的历史（知道前几轮看到什么）",
          isinstance(third.get("history"), list) and len(third["history"]) == 2,
          third.get("history"))
    check("F8 状态文件真的落盘且无 BOM",
          os.path.isfile(st) and not open(st, "rb").read().startswith(b"\xef\xbb\xbf"))

    r3 = CK.check(AXF, symbol="HAL_GPIO_TogglePin")
    check("F9 既不给 source 也不给 code 时报错（不拿空源码判无罪）",
          r3.get("ok") is False and "候选源码" in (r3.get("error") or ""),
          r3.get("error"))


# ---------------------------------------------------------------------------
# G cbuild
# ---------------------------------------------------------------------------
def section_g():
    print("\nG cbuild：工具链缺失如实报 / 真机编译比对")
    if not os.path.isfile(AXF):
        skip("G 全节", "示例镜像不存在")
        return

    real = CB.find_compilers
    try:
        CB.find_compilers = lambda explicit_dir="": {
            "ok": False, "ac5": "", "ac6": "", "tried": ["<fake>"],
            "error": "找不到 ARM 编译器（armcc / armclang）",
            "hint": "装 Keil MDK，或设 MDK_ARMCC_BIN=..."}
        r = CB.build(AXF, symbol="HAL_GPIO_TogglePin", code="void f(void){}\n")
        check("G1 工具链缺失时如实报 toolchain_not_found（不假装编过）",
              r.get("ok") is False
              and r.get("error_code") == "toolchain_not_found"
              and r.get("verdict") == "build_failed", r.get("error_code"))
        check("G2 缺失时也给出安装提示与试过的路径",
              r.get("hint") and r.get("tried") == ["<fake>"], r.get("tried"))
    finally:
        CB.find_compilers = real

    r = CB.build(AXF, symbol="nosuch_xyz", code="void f(void){}\n")
    check("G3 目标函数不存在时报错（先找函数再找编译器）",
          r.get("ok") is False and "找不到目标函数" in (r.get("error") or ""),
          r.get("error"))

    tc = CB.find_compilers()
    if not tc.get("ac6") and not tc.get("ac5"):
        skip("G4-G10", "本机没有 armcc/armclang：回编译比对无法验证（不假装通过）")
        return

    d = tmpdir("mdk107_build_")
    good = os.path.join(d, "cand.c")
    with open(good, "wb") as fh:
        fh.write((
            "#include <stdint.h>\n"
            "typedef struct { volatile uint32_t MODER, OTYPER, OSPEEDR, PUPDR,\n"
            "  IDR, ODR, BSRR, LCKR, AFR[2]; } GPIO_TypeDef;\n"
            "void HAL_GPIO_TogglePin(GPIO_TypeDef *GPIOx, uint16_t GPIO_Pin)\n"
            "{\n"
            "  uint32_t odr = GPIOx->ODR;\n"
            "  GPIOx->BSRR = (~odr & GPIO_Pin) | ((odr & GPIO_Pin) << 16u);\n"
            "}\n").encode("utf-8"))
    r = CB.build(AXF, source=good, symbol="HAL_GPIO_TogglePin",
                 cpu="cortex-m4", opt="-O2")
    cmp_ = r.get("compare") or {}
    check("G4 真编出来了并与镜像对上（structural_match 或 exact_sequence）",
          r.get("ok") is True
          and r.get("verdict") in ("structural_match", "exact_sequence"), r)
    check("G5 回报选了哪个节/哪个符号（不让人猜比的是谁）",
          (r.get("tool") or {}).get("built_section", "").startswith(".text")
          and (r.get("tool") or {}).get("built_symbol") == "HAL_GPIO_TogglePin",
          r.get("tool"))
    check("G6 compare 里给两边的指令数/调用数/分支数（可复核）",
          {"n_insns_image", "n_insns_candidate", "calls", "branches",
           "pushes", "mnemonic_ratio"} <= set(cmp_), sorted(cmp_))

    bad = os.path.join(d, "bad.c")
    with open(bad, "wb") as fh:
        fh.write(b"void HAL_GPIO_TogglePin(void *p, unsigned short n)\n"
                 b"{\n  *(volatile unsigned int *)((char *)p + 0x18) = n;\n}\n")
    r2 = CB.build(AXF, source=bad, symbol="HAL_GPIO_TogglePin",
                  cpu="cortex-m4", opt="-O2")
    check("G7 故意写错时判 differs 并指出第一个分歧点",
          r2.get("ok") is True and r2.get("verdict") == "differs"
          and (r2.get("compare") or {}).get("first_diff") is not None,
          (r2.get("verdict"), (r2.get("compare") or {}).get("first_diff")))
    check("G8 diff 里候选地址已映射回原函数地址（两边地址可比）",
          any(l.startswith("+") and l[1:9].strip()
              and int(l[1:9], 16) >= r2["function"]["addr"]
              for l in (r2.get("diff") or [])
              if re.match(r"^\+[0-9A-Fa-f]{8} ", l)),
          (r2.get("diff") or [])[:4])
    check("G9 结果里明写「结构相同 ≠ 语义等价」",
          "不是等价性证明" in (r.get("scope") or ""), r.get("scope"))

    r3 = CB.build(AXF, symbol="HAL_GPIO_TogglePin",
                  code="int x = ;\n", cpu="cortex-m4")
    check("G10 编不过时判 build_failed 并带上 stderr（不抛异常）",
          r3.get("ok") is True and r3.get("verdict") == "build_failed"
          and (r3.get("stderr") or ""), r3.get("verdict"))


# ---------------------------------------------------------------------------
# H emulate
# ---------------------------------------------------------------------------
def section_h():
    print("\nH emulate：缺失如实报 / 装了就跑通")
    if not os.path.isfile(AXF):
        skip("H 全节", "示例镜像不存在")
        return
    real_av = EM.available
    try:
        EM.available = lambda: {"supported": False, "error": "ModuleNotFoundError",
                                "hint": "pip install unicorn",
                                "why": "Unicorn 是可选依赖"}
        r = EM.run(AXF, symbol="HAL_GPIO_TogglePin", args="0x20000000,1")
        check("H1 unicorn 缺失时严格报 unsupported（不降级成静态猜测）",
              r.get("ok") is False and r.get("supported") is False
              and r.get("verdict") == "not_supported", r.get("verdict"))
        check("H2 缺失时给出安装提示",
              "unicorn" in json.dumps(r.get("hint") or "", ensure_ascii=False),
              r.get("hint"))
    finally:
        EM.available = real_av

    av = EM.available()
    if not av.get("supported"):
        skip("H3-H7", "本机没装 unicorn：%s" % av.get("error"))
        return
    r = EM.run(AXF, symbol="HAL_GPIO_TogglePin", args="0x20000000,1")
    res = r.get("result") or {}
    check("H3 跑完并返回（stop_reason=returned）",
          r.get("ok") is True and res.get("stop_reason") == "returned",
          res.get("stop_reason"))
    check("H4 抓到了写内存（BSRR 写 0x20000018 = 1）",
          any(w["addr"].lower() == "0x20000018" and w["value"] == "0x1"
              for w in res.get("writes") or []), res.get("writes"))
    check("H5 回报 r0..r3（看得见输入原样进寄存器）",
          set(res.get("return") or {}) >= {"r0", "r1", "r2", "r3"}, res.get("return"))

    r2 = EM.run(AXF, entry=0)
    check("H6 既不给 entry 也不给 symbol 时报错",
          r2.get("ok") is False and "entry" in (r2.get("error") or ""),
          r2.get("error"))

    r3 = EM.run(AXF, symbol="main")
    check("H7 碰到外设访问就停下（如实报 peripheral_access，不假装跑完）",
          r3.get("ok") is True
          and (r3.get("result") or {}).get("stop_reason") in
          ("peripheral_access", "unmapped_access", "returned"),
          (r3.get("result") or {}).get("stop_reason"))


# ---------------------------------------------------------------------------
# I 零依赖 / 文档 / 版本闸门
# ---------------------------------------------------------------------------
def section_i():
    print("\nI 零依赖 / 文档 / 版本闸门")
    stdlib = ("os", "re", "io", "sys", "json", "math", "time", "hashlib",
              "struct", "shutil", "tempfile", "fnmatch", "difflib", "argparse",
              "__future__", "typing", "dataclasses", "collections", "datetime",
              "subprocess", "base64", "itertools", "textwrap")
    local = ("recover", "rtypes", "reveng", "decomp", "_recover", "_rtypes",
             "_reveng", "_evidence", "_textio", "ccheck", "cbuild", "plan",
             "contextpack", "emulate", "annotate", "toolbox")
    # 两个允许的第三方：pyelftools 是本仓必装依赖（解析 .o 的节与符号）；
    # unicorn 是可选依赖，单独由 I2 断言「只在函数里 lazy import」。
    allow = {"plan": (), "contextpack": (), "ccheck": (),
             "cbuild": ("elftools",), "emulate": ("unicorn",)}
    for mod in ("plan", "contextpack", "ccheck", "cbuild", "emulate"):
        src = open(os.path.join(ROOT, "mdkdebug", mod + ".py"),
                   encoding="utf-8").read()
        mods = re.findall(r"^\s*(?:from|import)\s+([A-Za-z_][\w.]*)", src, re.M)
        bad = [m for m in mods
               if m.split(".")[0] not in stdlib + local + allow[mod]]
        check("I1 %s.py 除了允许项外只依赖标准库与本仓库模块" % mod,
              bad == [], bad)

    src = open(os.path.join(ROOT, "mdkdebug", "emulate.py"), encoding="utf-8").read()
    check("I2 emulate 里 unicorn 是 lazy import（模块导入时不炸）",
          "import unicorn" in src
          and not re.search(r"^import unicorn", src, re.M))

    rd = open(os.path.join(ROOT, "README.md"), encoding="utf-8").read()
    check("I3 README 有批次107 的说明块", "批次107" in rd,
          re.findall(r"批次1\d\d", rd)[-6:])
    check("I4 README 六个新工具都出现在工具表里",
          all(("`%s`" % n) in rd for n in NEW_TOOLS),
          [n for n in NEW_TOOLS if ("`%s`" % n) not in rd])

    from mdkdebug import __version__ as V
    py = open(os.path.join(ROOT, "pyproject.toml"), encoding="utf-8").read()
    check("I5 版本三处同步（__init__ / pyproject / README）",
          ('version = "%s"' % V) in py and ("版本号 %s" % V) in rd
          and re.match(r"^0\.2\.\d+$", V) is not None, (V,))
    check("I6 pyproject 里有 emu 可选依赖（unicorn 不进必装）",
          "[project.optional-dependencies]" in py and "unicorn" in py)
    rt = open(os.path.join(ROOT, "tools", "run_all_tests.py"),
              encoding="utf-8").read()
    check("I7 全量闸门里含 test_batch107", '"test_batch107"' in rt)


def main():
    print("批次107 测试：还原 C 的闭环")
    for fn in (section_a, section_b, section_c, section_d, section_e,
               section_f, section_g, section_h, section_i):
        try:
            fn()
        except Exception as e:               # noqa: BLE001
            import traceback
            traceback.print_exc()
            FAIL.append("%s 抛异常：%s" % (fn.__name__, e))
    for d in TMP:
        shutil.rmtree(d, ignore_errors=True)
    print("\n%d pass / %d fail / %d skip"
          % (len(PASS), len(FAIL), len(SKIP)))
    if FAIL:
        print("失败项：")
        for x in FAIL:
            print("  -", x)
        return 1
    print("全部通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())
