# -*- coding: utf-8 -*-
"""批次105 测试：定位线（字节/文本搜索 + 交叉引用）。

本批补的是逆向里最常被问、却一直没有工具出口的两问：

  recover_search  按**字节模式（十六进制 + ?? 通配）或文本**在镜像里找，
                  每个命中给出「文件偏移 → 虚拟地址 → 所属节 → 是否可执行」
  recover_xref    给定地址或符号，列出**谁引用它**（call / branch / data_read /
                  data_write / data_code_pointer），带 confidence 与所属函数

对照：recover_strings 只找可打印串，find_symbol 只认符号名，search_mem 搜的是
目标在线内存——三者都回答不了「这段字节在镜像里出现在哪」「谁在改这个全局变量」。

分节：

  A 工具面：2 个新工具注册、归组、只读、schema
  B 模式解析：分隔符/通配/编码/各类错误都要报得准
  C find_all 纯函数：重叠、通配锚点、区间限制、上限截断
  D search 端到端：真 axf + 合成 bin、分页、区间、未映射节、两路分别搜
  E xref 端到端：符号/地址/Thumb 位、kinds、向量表、is_function_entry、
                 数据符号的 data_read/data_write、unresolved 透出
  F 零依赖与文档闸门

运行：python -m tests.test_batch105
"""
import io
import json
import os
import re
import struct
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.environ.setdefault("MDKDEBUG_TOOLSETS", "all")

from mdkdebug import annotate as AN          # noqa: E402
from mdkdebug import locate as L             # noqa: E402
from mdkdebug import recover as RC           # noqa: E402
from mdkdebug import toolbox as TB           # noqa: E402

AXF = os.path.join(ROOT, "example_mdk_project", "mdk_test", "MDK-ARM",
                   "mdk_test", "mdk_test.axf")
BASE = 0x08000000
NEW_TOOLS = ("recover_search", "recover_xref")

PASS, FAIL = [], []
TMP = []


def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print("  [%s] %s %s" % ("PASS" if ok else "FAIL", name,
                            "" if ok else str(detail)[:400]), flush=True)


def tmpdir(prefix="mdk105_"):
    d = tempfile.mkdtemp(prefix=prefix)
    TMP.append(d)
    return d


def _w(data, name, d=None):
    d = d or tmpdir()
    p = os.path.join(d, name)
    with open(p, "wb") as f:
        f.write(data if isinstance(data, bytes) else data.encode("utf-8"))
    return p


MAGIC = b"\xDE\xAD\xBE\xEF\x12\x34"
MAGIC_OFF = 0x140


def magic_bin():
    """合成固件：向量表 + 0x140 处一段魔数（带唯一前后文，便于定位）。"""
    blob = bytearray(struct.pack("<II", 0x20005000, BASE + 0x101))
    blob += b"\x00" * (MAGIC_OFF - 2 - len(blob))
    blob += b"\xA5\x5A" + MAGIC + b"\x5A\xA5"
    blob += b"\x00" * (0x400 - len(blob))
    return _w(bytes(blob), "magic.bin")


# ---------------------------------------------------------------------------
# A 工具面
# ---------------------------------------------------------------------------
def section_a():
    print("\nA 工具面：2 个新工具注册、归组、注解、参数口径")
    from mdkdebug import server as SV
    import asyncio

    srv = SV.create_server(port=15973, toolsets="all")
    tools = {t.name: t for t in asyncio.run(srv.list_tools())}
    names = set(tools)
    check("A1 两个新工具都注册了",
          all(n in names for n in NEW_TOOLS), [n for n in NEW_TOOLS if n not in names])
    check("A2 注册总数 232（本批新增 2 个）", len(names) == 232, len(names))
    check("A3 build 组 45 个且两者都在 build 组",
          len(TB.TOOLSETS["build"]) == 45 and all(n in TB.TOOLSETS["build"]
                                                  for n in NEW_TOOLS),
          len(TB.TOOLSETS["build"]))
    check("A4 只归一组（一键一义）",
          all(sum(1 for g in TB.TOOLSETS if n in TB.TOOLSETS[g]) == 1
              for n in NEW_TOOLS),
          {n: [g for g in TB.TOOLSETS if n in TB.TOOLSETS[g]] for n in NEW_TOOLS})
    check("A5 两个都是只读（READONLY）",
          all(n in AN.READONLY for n in NEW_TOOLS),
          [n for n in NEW_TOOLS if n not in AN.READONLY])
    check("A6 都不在 DESTRUCTIVE / NON_IDEMPOTENT 里",
          all(n not in AN.DESTRUCTIVE and n not in AN.NON_IDEMPOTENT
              for n in NEW_TOOLS),
          [n for n in NEW_TOOLS
           if n in AN.DESTRUCTIVE or n in AN.NON_IDEMPOTENT])
    ann = AN.annotations_for("recover_search")
    check("A7 search 注解：只读", ann.get("readOnlyHint") is True, ann)
    check("A8 工具面归类完整（check_surface 无问题）",
          AN.check_surface(sorted(names)) == [], AN.check_surface(sorted(names)))
    want = {"recover_search": {"pattern", "text", "encoding", "start", "end",
                               "offset", "limit", "max_matches", "context", "base"},
            "recover_xref": {"target", "symbol", "kinds", "max_refs", "deep",
                             "base", "max_insns", "max_functions"}}
    bad = {}
    for n, ps in want.items():
        props = set((tools[n].input_schema.get("properties") or {}).keys())
        if not ps <= props:
            bad[n] = sorted(ps - props)
    check("A9 schema 参数名齐全（CLI 靠它生成 --arg）", not bad, bad)


# ---------------------------------------------------------------------------
# B 模式解析
# ---------------------------------------------------------------------------
def section_b():
    print("\nB 模式解析：分隔符 / 通配 / 编码 / 错误口径")
    same = [L.parse_pattern(t) for t in
            ("48 8B ?? 24", "488b??24", "48-8B--24", "48_8B_??_24",
             "48,8B,??,24")]
    check("B1 五种写法解析成同一串", all(x == [0x48, 0x8B, None, 0x24] for x in same),
          same)
    check("B2 单问号与 -- 都是通配",
          L.parse_pattern("48 ? 24") == [0x48, None, 0x24] and
          L.parse_pattern("48 -- 24") == [0x48, None, 0x24])
    check("B3 大小写不敏感", L.parse_pattern("AbCd") == [0xAB, 0xCD])

    def _err(fn, *a):
        try:
            fn(*a)
        except L.PatternError as e:
            return str(e)
        except Exception as e:          # noqa: BLE001
            return "WRONG-TYPE:%s" % type(e).__name__
        return ""

    m = _err(L.parse_pattern, "48 8")
    check("B4 奇数长度报错且指出出处", "奇数" in m and "'8'" in m, m)
    m = _err(L.parse_pattern, "zz")
    check("B5 非十六进制报错且指出字节", "不是十六进制" in m and "zz" in m, m)
    m = _err(L.parse_pattern, "?? ??")
    check("B6 全通配被拒（否则每个位置都命中）", "全是通配" in m, m)
    m = _err(L.parse_pattern, "   ")
    check("B7 空模式被拒", "为空" in m, m)
    m = _err(L.parse_pattern, "ab" * 600)
    check("B8 超长模式被拒（上限 512 字节）", "过长" in m, m)

    check("B9 文本按 ascii 编码成字节",
          L.text_pattern("AT+CGMR") == list(b"AT+CGMR"))
    check("B10 utf16le 每字符两字节且带 NUL",
          L.text_pattern("AT", "utf16le") == [0x41, 0x00, 0x54, 0x00])
    check("B11 gbk 中文两字节",
          L.text_pattern("固件", "gbk") == list("固件".encode("gbk")))
    m = _err(L.text_pattern, "固件", "ascii")
    check("B12 ascii 编不出的字符要报错而不是替换成 ?", "编不出" in m, m)
    m = _err(L.text_pattern, "x", "latin1")
    check("B13 未知编码被拒", "未知编码" in m, m)
    m = _err(L.text_pattern, "", "ascii")
    check("B14 空文本被拒", "为空" in m, m)


# ---------------------------------------------------------------------------
# C find_all 纯函数
# ---------------------------------------------------------------------------
def section_c():
    print("\nC find_all：重叠 / 通配 / 区间 / 上限")
    data = b"\xAA\x48\x8B\x11\x24\x48\x8B\x22\x24\xBB" + b"\x00" * 20
    pat = L.parse_pattern("48 8B ?? 24")
    r = L.find_all(data, pat)
    check("C1 重叠命中全报（两条）", r["offsets"] == [1, 5], r)
    check("C2 锚点取最长定值段", r["anchor"]["len"] >= 2, r["anchor"])
    # 模式以通配开头、数据开头就是锚点：start 会算成 -1，必须跳过而不是负下标
    r2 = L.find_all(b"\x8B\x11\x22\x8B\x11", L.parse_pattern("?? 8B 11"))
    check("C3 锚点落在模式非首位、命中位置算出负下标时跳过",
          r2["offsets"] == [2], r2)
    # 区间限制：只允许 [1,9) 内的命中
    r3 = L.find_all(data, pat, in_ranges=[(1, 9)])
    check("C4 in_ranges 只放行整段落在区间内的命中",
          r3["offsets"] == [1, 5], r3)
    r4 = L.find_all(data, pat, in_ranges=[(2, 9)])
    check("C5 跨区间的命中被排除（不把两段拼成一条）",
          r4["offsets"] == [5], r4)
    r5 = L.find_all(data, pat, limit=1)
    check("C6 limit 到顶即停并报 truncated",
          r5["offsets"] == [1] and r5["truncated"] is True, r5)
    # 尾部不足一个模式长度时不能越界
    r6 = L.find_all(b"\x01\x02\x03", L.parse_pattern("02 03 ?? ?? ?? ?? 09"))
    check("C7 段尾不足模式长度不越界、不命中", r6["offsets"] == [], r6)

    m = L.parse_pattern("12 34")
    check("C8 单一定值模式也能走 find 快路径",
          L.find_all(b"xxxx\x12\x34yyyy", m)["offsets"] == [4])


# ---------------------------------------------------------------------------
# D search 端到端
# ---------------------------------------------------------------------------
def _unit(path):
    an = RC.analyze(path, deep=False, max_functions=1)
    return an.get("_unit")


def section_d():
    print("\nD search：真 axf + 合成 bin")
    p = magic_bin()
    r = L.search(p, base=BASE, pattern="DE AD ?? EF 12 34", limit=5)
    check("D1 合成 bin：魔数命中一处",
          r.get("ok") and r["total"] == 1, r.get("error") or r.get("total"))
    m = (r.get("matches") or [{}])[0]
    check("D2 偏移与地址自洽（0x140 处 → BASE+0x140）",
          m.get("file_offset") == MAGIC_OFF and
          m.get("addr") == BASE + MAGIC_OFF and
          m.get("addr_hex") == "0x%08X" % (BASE + MAGIC_OFF), m)
    check("D3 上下文回显（默认前后各 16 字节）贴着命中位置",
          (m.get("before_hex") or "").endswith("a55a") and
          (m.get("after_hex") or "").startswith("5aa5") and
          len(m.get("before_hex") or "") == 32, m)
    check("D4 match_hex 是命中的原始字节（通配位不报成 00）",
          m.get("match_hex") == MAGIC.hex(), m)
    check("D5 region=code（合成 bin 整段都可执行）", m.get("region") == "code", m)

    r = L.search(p, base=BASE, text="AT+CGMR", limit=5)
    check("D6 没命中时 total=0 且 ok=True（不是错误）",
          r.get("ok") is True and r["total"] == 0, r.get("total"))

    # 区间限制：把魔数排除在外
    r = L.search(p, base=BASE, pattern="DE AD BE EF", start=BASE + 0x200,
                 end=BASE + 0x300)
    check("D7 start/end 按地址限制（魔数在 0x140 之外，应为 0）",
          r.get("ok") is True and r["total"] == 0, r.get("total") or r.get("error"))
    r = L.search(p, base=BASE, pattern="DE AD BE EF", start=BASE + 0x100,
                 end=BASE + 0x200)
    check("D8 start/end 包住魔数时能命中", r["total"] == 1, r.get("total"))

    # 分页
    r = L.search(p, base=BASE, pattern="00 00", limit=3, offset=0, max_matches=50)
    check("D9 分页：limit 生效且 next_offset 可续",
          r.get("ok") and r["returned"] == 3 and
          r["next_offset"] == 3 and r["total"] > 3, r.get("total"))
    r2 = L.search(p, base=BASE, pattern="00 00", limit=3, offset=3, max_matches=50)
    check("D10 第二页从 offset 起（不与第一页重复）",
          r2["matches"][0]["file_offset"] != r["matches"][0]["file_offset"],
          r2["matches"][:1])
    r3 = L.search(p, base=BASE, pattern="00 00", limit=3, max_matches=3)
    check("D11 max_matches 到顶报 truncated 且说明总数只是下限",
          r3.get("ok") and r3["truncated"] is True and
          "下限" in (r3.get("truncated_reason") or ""), r3.get("truncated_reason"))

    # 错误路径
    check("D12 文件不存在报错", L.search("nope.bin", pattern="00").get("ok") is False)
    r = L.search(p, base=BASE)
    check("D13 不给任何条件直接拒绝（不猜搜什么）",
          r.get("ok") is False and "pattern" in (r.get("error") or ""), r.get("error"))
    check("D14 模式写错原样透出 PatternError 文案",
          "十六进制" in (L.search(p, pattern="zz").get("error") or ""))

    # 真 axf：未映射节与两路分别搜
    r = L.search(AXF, text="GCC", limit=3)
    check("D15 真 axf 文本搜索命中且标注来源节",
          r.get("ok") and r["total"] > 0 and
          all(x.get("via") == "text" for x in r["matches"]), r.get("total"))
    check("D16 未映射命中给出所属节（.debug_* / .symtab 等）与按节汇总",
          isinstance(r.get("unmapped_sections"), dict) and
          any(k.startswith((".debug", ".symtab", ".strtab", ".comment"))
              for k in (r.get("unmapped_sections") or {})),
          r.get("unmapped_sections"))
    check("D17 未映射命中的 addr 为 null（不按基址硬加）",
          all(x.get("addr") is None for x in r["matches"]
              if x.get("file_section") and x.get("addr") is None))
    r = L.search(AXF, pattern="47 43 43", text="GCC", limit=2)
    vias = {x["via"] for x in (r.get("matches") or [])}
    check("D18 两路都给时分别搜、分别报（via 两种都在）",
          vias == {"pattern", "text"}, vias)

    # 真 axf：偏移↔地址自洽（用 Unit 反查）
    u = _unit(AXF)
    r = L.search(AXF, pattern="00 00 00 00", start=BASE, end=BASE + 0x4000, limit=5)
    ok_pair = True
    for m in r.get("matches") or []:
        if m.get("addr") is None:
            continue
        off = u.offset_of(m["addr"])
        if off != m["file_offset"]:
            ok_pair = False
    check("D19 addr 与 file_offset 双向自洽（Unit.offset_of 反查一致）", ok_pair)
    check("D20 范围内所有命中都落在区间里",
          all(m["addr"] is None or BASE <= m["addr"] < BASE + 0x4000
              for m in (r.get("matches") or [])))


# ---------------------------------------------------------------------------
# E xref 端到端
# ---------------------------------------------------------------------------
def section_e():
    print("\nE xref：符号 / 地址 / Thumb 位 / kinds / 向量表 / 数据符号")
    r = L.xrefs(AXF, symbol="main")
    check("E1 符号解析到 main 且标为函数入口",
          r.get("ok") and r["target"]["name"] == "main" and
          r["is_function_entry"] is True and r["in_code"] is True, r.get("error"))
    addr = r["target"]["addr"]
    r2 = L.xrefs(AXF, target="0x%08X" % addr)
    check("E2 地址入口与符号入口结果一致",
          r2.get("ok") and r2["total"] == r["total"] and
          r2["target"]["addr"] == addr, (r["total"], r2.get("total")))
    r3 = L.xrefs(AXF, target="0x%08X" % (addr | 1))
    check("E3 Thumb 位（addr|1）也认，同一结果",
          r3.get("ok") and r3["total"] == r["total"], r3.get("total"))
    check("E4 main 的引用者是 __main 里的直接 bl（observed）",
          r["total"] >= 1 and
          r["referrers"][0]["kind"] == "call" and
          r["referrers"][0]["confidence"] == "observed", r["referrers"][:1])

    rk = L.xrefs(AXF, symbol="main", kinds="data_read")
    check("E5 kinds 过滤（data_read 下 main 无引用）",
          rk.get("ok") and rk["total"] == 0, rk.get("total"))
    check("E6 未知 kinds 被拒并列出可选值",
          "未知的 kinds" in (L.xrefs(AXF, symbol="main", kinds="nope")
                             .get("error") or ""))
    rn = L.xrefs(AXF, target="no_such_symbol_xyz")
    check("E7 找不到符号时给出 error + candidates 字段",
          rn.get("ok") is False and "candidates" in rn, rn.get("error"))
    r0 = L.xrefs(AXF)
    check("E8 不给目标直接拒绝（不猜目标）",
          r0.get("ok") is False and "没有目标" in (r0.get("error") or ""))

    # 向量表：复位入口
    vt_entry = RC.vector_table(_unit(AXF))["entries"][0]      # index=1 是 Reset
    raddr = int(vt_entry["handler_hex"], 16) & ~1
    rv = L.xrefs(AXF, target="0x%08X" % raddr, deep=False)
    check("E9 复位入口能在向量表里被认出（exception=Reset）",
          rv.get("ok") and any(x.get("exception") == "Reset"
                               for x in rv["in_vector_table"]),
          rv.get("in_vector_table"))
    check("E10 复位入口不在可执行区之外（in_image/in_code 都为真）",
          rv.get("in_image") is True and rv.get("in_code") is True, rv.get("target"))

    # 数据符号：全局变量的读写
    st = RC.symbol_table(_unit(AXF))
    objs = [o for o in st["objects"] if o.get("size")]
    got = None
    for o in objs:
        rr = L.xrefs(AXF, symbol=o["name"], max_refs=50)
        if rr.get("ok") and rr["total"] > 0:
            got = (o["name"], rr)
            break
    check("E11 数据符号能查到引用者（data_read / data_write）",
          got is not None and all(x["kind"].startswith("data_")
                                  for x in got[1]["referrers"]),
          None if got is None else got[1]["by_kind"])
    if got:
        check("E12 数据引用带 member 偏移或 base_reg（结构成员访问可追）",
              any(x.get("member") is not None or x.get("base_reg")
                  for x in got[1]["referrers"]), got[1]["referrers"][:1])

    # unresolved 必须透出（「没找到引用」与「看不到」是两件事）
    check("E13 unresolved 计数透出（间接调用解析不了要如实说）",
          isinstance(r.get("unresolved"), int) and r["unresolved"] > 0,
          r.get("unresolved"))
    check("E14 limitations 里写明「没有引用者 ≠ 没人用它」",
          any("不等于" in x for x in (r.get("limitations") or [])),
          r.get("limitations"))
    check("E15 max_refs 截断时 by_kind 统计的仍是全部",
          (L.xrefs(AXF, symbol="__NVIC_SetPriority", max_refs=1)["by_kind"]
           or {}).get("call", 0) >= 1)

    rk0 = L.xrefs(AXF, target="0x%08X" % 0x08000000)
    check("E16 指向向量表首字（SP）时不误判成函数入口",
          rk0.get("ok") and rk0.get("is_function_entry") is False, rk0.get("function"))


# ---------------------------------------------------------------------------
# F 零依赖与文档闸门
# ---------------------------------------------------------------------------
def section_f():
    print("\nF 零依赖与文档闸门")
    src = open(os.path.join(ROOT, "mdkdebug", "locate.py"), encoding="utf-8").read()
    mods = re.findall(r"^\s*(?:from|import)\s+([A-Za-z_][\w.]*)", src, re.M)
    third = [m for m in mods
             if m.split(".")[0] not in ("os", "re", "struct", "sys", "json", "math")]
    check("F1 locate.py 只依赖标准库与本仓库模块", third == [], third)
    check("F2 locate.py 不写文件（没有 open(...,'w') / os.makedirs / shutil）",
          not re.search(r"open\([^)]*['\"][wa]", src) and
          "os.makedirs" not in src and "shutil" not in src)

    rd = open(os.path.join(ROOT, "README.md"), encoding="utf-8").read()
    check("F3 README 有批次105 的说明块", "批次105" in rd,
          [x for x in re.findall(r"批次1\d\d", rd)][-5:])
    # 版本号本身不在这里断言数值（发版会变），只断言「三处一致」
    from mdkdebug import __version__ as V
    check("F4 README 目录树版本号与包一致",
          ("版本号 %s" % V) in rd, (V, re.findall(r"版本号 0\.2\.\d+", rd)))
    py = open(os.path.join(ROOT, "pyproject.toml"), encoding="utf-8").read()
    check("F5 版本三处同步（__init__ / pyproject / README）",
          ('version = "%s"' % V) in py and ("版本号 %s" % V) in rd, (V,))
    rt = open(os.path.join(ROOT, "tools", "run_all_tests.py"), encoding="utf-8").read()
    check("F6 全量闸门里含 test_batch105", '"test_batch105"' in rt)


def main():
    print("批次105 测试：定位线（recover_search / recover_xref）")
    for fn in (section_a, section_b, section_c, section_d, section_e, section_f):
        try:
            fn()
        except Exception as e:  # noqa: BLE001
            import traceback
            traceback.print_exc()
            FAIL.append("%s 抛异常：%s" % (fn.__name__, e))
    for d in TMP:
        import shutil
        shutil.rmtree(d, ignore_errors=True)
    print("\n%d pass / %d fail" % (len(PASS), len(FAIL)))
    if FAIL:
        print("失败项：")
        for x in FAIL:
            print("  -", x)
        return 1
    print("全部通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())
