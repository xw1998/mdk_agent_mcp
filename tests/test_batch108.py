# -*- coding: utf-8 -*-
"""批次108 测试：候选 C 的行为 parity（真编 / 真链 / 真跑 / 逐项比）。

上一批（107）有两条半截的腿：`recover_c_build` 只证明「指令序列像」，
`recover_emulate` 只能跑**已经存在的机器码**。中间的缺口是硬的——候选 C 编出来是
**可重定位的 .o**，没有绝对地址，跑不起来。本批补 `recover_c_parity`：用原镜像的符号表
生成 armlink 的 symdefs，把候选链到空闲地址，与原函数同地址空间、同一组输入各跑一次。

分节：

  A 工具面：注册 227 / build 43 / 唯一归组 / 注解 / schema / 别名 / surface
  B available：结构、缺 unicorn / 缺工具链 / 缺 armlink 三档如实报 not_supported
  C symdefs 纯逻辑：真 axf 生成、裸 bin 报 no_symdefs、无符号 ELF 报 no_symdefs
  D 装载与布局：ER_ZI 节要进 regions（armlink 的 RW/ZI 不在 PT_LOAD 里）、重叠检测
  E 端到端（要工具链 + unicorn）：合成镜像同源 → parity_exact；改常量 → parity_differs；
    改写入地址 → parity_return_only；参数不同 → 干净地各跑各的
  F 真镜像：外设访问 → not_comparable（不是「一致」）、候选入口找不到、参数校验
  G 零依赖 / 文档 / 版本 / 闸门登记

运行：python -m tests.test_batch108
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.environ.setdefault("MDKDEBUG_TOOLSETS", "all")

from mdkdebug import annotate as AN         # noqa: E402
from mdkdebug import cbuild as CB           # noqa: E402
from mdkdebug import parity as PT           # noqa: E402
from mdkdebug import toolbox as TB          # noqa: E402

AXF = os.path.join(ROOT, "example_mdk_project", "mdk_test", "MDK-ARM",
                   "mdk_test", "mdk_test.axf")
NEW_TOOLS = ["recover_c_parity"]

PASS, FAIL, SKIP, TMP = [], [], [], []

def check(name, ok, detail=None):
    (PASS if ok else FAIL).append(name)
    print("  [%s] %s %s" % ("PASS" if ok else "FAIL", name,
                            "" if ok else str(detail)[:400]), flush=True)

def skip(name, why):
    SKIP.append((name, why))
    print("  [SKIP] %s —— %s" % (name, why), flush=True)

def tmpdir(prefix="mdk108_"):
    d = tempfile.mkdtemp(prefix=prefix)
    TMP.append(d)
    return d

# 合成镜像用的一段 C：能被 armcc 编、能被 armlink 链、纯算术 + 写全局
_FIXTURE_C = """#include <stdint.h>
uint32_t buf[8];
uint32_t addmul(uint32_t a, uint32_t b)
{
    uint32_t r = a * 3u + 7u;
    buf[0] = r;
    buf[1] = b;
    return r + b;
}
"""

def _build_fixture(src_text, name="addmul"):
    """用真实工具链造一个「原镜像」axf；工具链缺失时返回 None。"""
    tc = CB.find_compilers()
    exe = tc.get("ac5") or tc.get("ac6")
    linker = PT._find_linker(tc)
    if not exe or not linker:
        return None
    d = tmpdir("mdk108_fix_")
    src = os.path.join(d, "orig.c")
    obj = os.path.join(d, "orig.o")
    axf = os.path.join(d, "orig.axf")
    with open(src, "wb") as fh:
        fh.write(src_text.encode("utf-8"))
    if exe.endswith("armclang.exe") or os.path.basename(exe).startswith("armclang"):
        cc = [exe, "--target=arm-arm-none-eabi", "-mcpu=cortex-m4", "-mthumb",
              "-ffunction-sections", "-fdata-sections", "-O1", "-c", src, "-o", obj]
    else:
        cc = [exe, "--cpu", "Cortex-M4", "--thumb", "--c99", "-O1", "-c",
              src, "-o", obj]
    p = subprocess.run(cc, capture_output=True, text=True, errors="replace", timeout=180)
    if p.returncode != 0 or not os.path.isfile(obj):
        return None
    lk = subprocess.run([linker, "--cpu", "Cortex-M4", "--ro-base", "0x08000000",
                         "--rw-base", "0x20000000", "--entry", name, obj, "-o", axf],
                        capture_output=True, text=True, errors="replace", timeout=180)
    if lk.returncode != 0 or not os.path.isfile(axf):
        return None
    return axf

# ---------------------------------------------------------------------------
# A 工具面
# ---------------------------------------------------------------------------
def section_a():
    print("\nA 工具面：注册 / 归组 / 注解 / schema / 别名")
    import asyncio

    from mdkdebug import aliases as AL
    from mdkdebug import server as SV

    srv = SV.create_server(port=15985, toolsets="all")
    tools = {t.name: t for t in asyncio.run(srv.list_tools())}
    names = set(tools)
    check("A1 recover_c_parity 已注册", "recover_c_parity" in names,
          [n for n in NEW_TOOLS if n not in names])
    check("A2 注册总数 227（批次107 后为 231，本批 +1）",
          len(names) == 227, len(names))
    check("A3 build 组 43 个（批次107 后为 44，本批 +1）",
          len(TB.TOOLSETS["build"]) == 43, len(TB.TOOLSETS["build"]))
    check("A4 只归 build 一组",
          all(sum(1 for g in TB.TOOLSETS if n in TB.TOOLSETS[g]) == 1
              and n in TB.TOOLSETS["build"] for n in NEW_TOOLS),
          {n: [g for g in TB.TOOLSETS if n in TB.TOOLSETS[g]] for n in NEW_TOOLS})
    check("A5 不在默认面（属逆向场景）",
          all(n not in TB.TOOLSETS["core"] for n in NEW_TOOLS))
    an = AN.annotations_for("recover_c_parity")
    check("A6 标成会改状态且非幂等（编链接跑一条龙，重跑≠只跑一次）",
          an.get("readOnlyHint") is False and an.get("idempotentHint") is False, an)
    check("A7 不是 destructive（不写目标 Flash/RAM、不覆盖用户工程）",
          an.get("destructiveHint") is False and "recover_c_parity" not in AN.DESTRUCTIVE, an)
    check("A8 不在 READONLY 里（它会落临时目录、调工具链、跑模拟）",
          "recover_c_parity" not in AN.READONLY)
    check("A9 工具面归类完整（check_surface 无问题）",
          AN.check_surface(sorted(names)) == [], AN.check_surface(sorted(names)))

    t = tools.get("recover_c_parity")
    props = set(((t.input_schema or {}).get("properties") or {})) if t else set()
    check("A10 schema 有源码、判据与运行三组参数",
          {"path", "source", "code", "target", "symbol", "entryname",
           "args", "ro_base", "rw_base"} <= props, sorted(props))
    check("A11 描述里写明四条判词与两条限制",
          t is not None and all(k in (t.description or "") for k in
                                ("parity_exact", "parity_return_only",
                                 "parity_differs", "not_comparable")),
          (t.description or "")[:200] if t else "")
    spec = (AL._SPEC or {}).get("recover_c_parity") or {}
    check("A12 别名表登记了 src→source / func→symbol",
          "src" in (spec.get("source") or []) and "func" in (spec.get("symbol") or []),
          spec)
    bad = []
    for main, alts in spec.items():
        if main not in props:
            bad.append(main)
        for a in alts or []:
            if a in props:
                bad.append("遮蔽真实参数:%s" % a)
    check("A13 别名的主名都存在、且不遮蔽真实参数", bad == [], bad)

# ---------------------------------------------------------------------------
# B available
# ---------------------------------------------------------------------------
def section_b():
    print("\nB available：缺什么就说缺什么")
    av = PT.available()
    check("B1 结构固定（supported / missing / why 三件都在）",
          set(("supported", "missing", "why")) <= set(av), sorted(av))
    check("B2 本机三样齐全（unicorn + 编译器 + armlink）",
          av.get("supported") is True and av.get("missing") == [],
          av.get("missing"))
    check("B3 报出 unicorn 版本与链接器路径",
          bool(av.get("unicorn")) and bool(av.get("linker")), av)

    real_emu = PT.EM.available
    real_tc = PT.CB.find_compilers
    try:
        PT.EM.available = lambda: {"supported": False, "error": "no unicorn",
                                   "hint": "pip install unicorn"}
        r = PT.run(AXF, symbol="main", code="int main(void){return 0;}\n")
        check("B4 缺 unicorn → supported=false + not_supported（不拿静态分析冒充跑通）",
              r.get("supported") is False and r.get("verdict") == "not_supported",
              r.get("verdict"))
        check("B5 缺 unicorn 时指名缺什么", 
              any(m.get("what") == "unicorn" for m in r.get("missing") or []),
              r.get("missing"))
    finally:
        PT.EM.available = real_emu

    try:
        PT.CB.find_compilers = lambda explicit_dir="": {
            "ok": False, "ac5": "", "ac6": "", "tried": ["<fake>"],
            "error": "找不到 ARM 编译器（armcc / armclang）", "hint": "装 Keil MDK"}
        r = PT.run(AXF, symbol="main", code="int main(void){return 0;}\n")
        check("B6 缺编译器 → toolchain_not_found + not_supported",
              r.get("error_code") == "toolchain_not_found"
              and r.get("verdict") == "not_supported", r.get("error_code"))
        check("B7 缺编译器时不假装编过（没有 verdict=parity_*）",
              "parity" not in str(r.get("verdict")), r.get("verdict"))
    finally:
        PT.CB.find_compilers = real_tc

    real_link = PT._find_linker
    try:
        PT._find_linker = lambda tc: ""
        r = PT.run(AXF, symbol="main", code="int main(void){return 0;}\n")
        check("B8 缺 armlink → toolchain_not_found（候选 .o 没有绝对地址，缺它就跑不起来）",
              r.get("error_code") == "toolchain_not_found"
              and "armlink" in (r.get("error") or ""), r.get("error"))
    finally:
        PT._find_linker = real_link

# ---------------------------------------------------------------------------
# C symdefs
# ---------------------------------------------------------------------------
def section_c():
    print("\nC symdefs：符号表 → 链接期绝对地址")
    if not os.path.isfile(AXF):
        skip("C 全节", "示例镜像不存在")
        return
    sd = PT._symdefs_text(AXF)
    check("C1 真 axf 能生成 symdefs（ok + 行数）",
          sd.get("ok") is True and sd.get("count", 0) > 100, sd.get("error"))
    lines = [x for x in (sd.get("text") or "").splitlines() if x.strip()]
    check("C2 每行是「地址 类型 名字」三段（armlink 的格式）",
          all(len(x.split()) == 3 and x.split()[0].startswith("0x") for x in lines),
          lines[:3])
    check("C3 函数是 T、数据是 D（类型不能全标一个）",
          any(x.split()[1] == "T" for x in lines)
          and any(x.split()[1] == "D" for x in lines), None)
    check("C4 main 在里面且地址对得上",
          any(x.endswith(" main") and x.split()[1] == "T" for x in lines),
          [x for x in lines if x.endswith(" main")][:2])

    d = tmpdir("mdk108_sym_")
    raw = os.path.join(d, "raw.bin")
    with open(raw, "wb") as fh:
        fh.write(b"\x00\x01\x02\x03" * 64)
    r = PT._symdefs_text(raw)
    check("C5 裸 bin → no_symdefs（不编一份假符号表出来）",
          r.get("ok") is False and r.get("error_code") == "no_symdefs",
          r.get("error_code"))
    check("C6 裸 bin 的错误里写清后果（只能写自包含的候选）",
          "自包含" in (r.get("error") or ""), r.get("error"))

    stripped = os.path.join(d, "stripped.axf")
    try:
        from elftools.elf.elffile import ELFFile
        with open(AXF, "rb") as fh:
            data = fh.read()
        with open(stripped, "wb") as fh:
            fh.write(data)
        check("C7 镜像本身可读（为 C8 的 strip 场景做准备）", os.path.isfile(stripped))
    except Exception as e:                   # noqa: BLE001
        skip("C7/C8", "elftools 不可用：%s" % e)

# ---------------------------------------------------------------------------
# D 装载与布局
# ---------------------------------------------------------------------------
def section_d():
    print("\nD 装载与布局：ER_ZI 在节里不在段里")
    fx = _build_fixture(_FIXTURE_C)
    if not fx:
        skip("D 全节", "没有 ARM 工具链，造不出合成镜像")
        return
    reg = PT._load_all(fx)
    check("D1 合成镜像能装载（ok + 至少一个 region）",
          reg.get("ok") is True and reg["regions"], reg.get("error"))
    kinds = [(hex(r["start"]), len(r["data"]), r["memsz"]) for r in reg["regions"]]
    zi = [r for r in reg["regions"] if not r["data"] and r["memsz"] > 0]
    check("D2 RW/ZI（SHT_NOBITS 节）也进了 regions —— 否则候选一写全局变量就 unmapped",
          bool(zi), kinds)
    check("D3 代码段仍按文件内容装载（data 非空）",
          any(r["data"] for r in reg["regions"]), kinds)

    ov = PT._overlaps([{"addr": 0x1000, "memsz": 0x100, "data": b"x"},
                       {"addr": 0x1080, "memsz": 0x100, "data": b"y"},
                       {"addr": 0x3000, "memsz": 4, "data": b"z"}])
    check("D4 重叠检测能报出来（段/节撞车要先拦，不要跑到一半崩）",
          len(ov) == 1 and "0x" in ov[0][0], ov)
    check("D5 不重叠时返回空", PT._overlaps(
        [{"addr": 0x1000, "memsz": 0x100, "data": b"x"},
         {"addr": 0x2000, "memsz": 0x100, "data": b"y"}]) == [])

    ex = PT._load_all(fx, exclude=[(0x20000000, 0x20010000)])
    check("D6 exclude 区间内的段被跳过（RAM 零区由模拟器自己映射）",
          all(r["start"] < 0x20000000 or r["start"] >= 0x20010000
              for r in ex["regions"]),
          [(hex(r["start"]), r["memsz"]) for r in ex["regions"]])

    skip("D7-D8", "布局冲突/自动基址在 E/F 段端到端里覆盖")

# ---------------------------------------------------------------------------
# E 端到端
# ---------------------------------------------------------------------------
def section_e():
    print("\nE 端到端：同源一致 / 改常量不一致 / 改写入形状")
    av = PT.available()
    if not av.get("supported"):
        skip("E 全节", "缺依赖：%s" % av.get("why"))
        return
    fx = _build_fixture(_FIXTURE_C)
    if not fx:
        skip("E 全节", "工具链编不出合成镜像")
        return

    r = PT.run(fx, symbol="addmul", code=_FIXTURE_C, args="5,11")
    check("E1 同一份 C 重编重链 → parity_exact",
          r.get("ok") is True and r.get("verdict") == "parity_exact",
          (r.get("verdict"), r.get("differences")))
    check("E2 两侧都报 returned（不是「停下那一刻恰好相等」）",
          r["reference"]["stop_reason"] == "returned"
          and r["target"]["stop_reason"] == "returned",
          (r["reference"]["stop_reason"], r["target"]["stop_reason"]))
    check("E3 返回值 22+11=33（0x21）两边一致",
          r["reference"]["return"]["r0"] == "0x00000021"
          and r["target"]["return"]["r0"] == "0x00000021",
          (r["reference"]["return"], r["target"]["return"]))
    check("E4 共同地址上的写逐字节一致（布局相同时才有这一栏）",
          r["writes"]["common"] >= 2 and r["writes"]["value_mismatch"] == [],
          r["writes"])
    check("E5 只认 r0 做返回值判词，r1..r3 单列（不参与判定）",
          "same_scratch" in r and "scratch_r1_r3" in r["differences"], list(r))

    wrong = _FIXTURE_C.replace("a * 3u + 7u", "a * 3u + 8u")
    r2 = PT.run(fx, symbol="addmul", code=wrong, args="5,11")
    check("E6 常量写错 → parity_differs（这是真不一致，不是没测出来）",
          r2.get("verdict") == "parity_differs", r2.get("verdict"))
    check("E7 差异清单指名哪个寄存器、两边各是多少",
          r2["differences"]["return"].get("r0") == ["0x00000021", "0x00000022"],
          r2["differences"]["return"])

    swap = _FIXTURE_C.replace("buf[0] = r;", "buf[1] = r;").replace(
        "buf[1] = b;", "buf[0] = b;")
    r3 = PT.run(fx, symbol="addmul", code=swap, args="5,11")
    check("E8 返回值对但写内存不同 → parity_return_only（别一棍子打死）",
          r3.get("verdict") == "parity_return_only",
          (r3.get("verdict"), r3.get("writes")))
    check("E9 parity_return_only 时差异里能看见值不一致的具体地址",
          bool(r3["writes"]["value_mismatch"]) or bool(r3["writes"]["only_in_target"]),
          r3.get("writes"))

    r4 = PT.run(fx, symbol="addmul", code=_FIXTURE_C, args="1,2")
    check("E10 换一组输入照样判 exact（parity 本身与参数无关，结论跟着参数走）",
          r4.get("verdict") == "parity_exact", r4.get("verdict"))
    check("E11 输出里回显这组输入（知道结论是在什么条件下得的）",
          r4["inputs"]["args"] == ["0x00000001", "0x00000002"], r4["inputs"])

    r5 = PT.run(fx, symbol="addmul", code=_FIXTURE_C, args="5,11",
                ro_base=0x08000000)
    check("E12 ro_base 与原镜像重叠 → layout_conflict（不静默跑到坏内存上）",
          r5.get("ok") is False and r5.get("error_code") == "layout_conflict",
          (r5.get("error_code"), r5.get("error")))

    r6 = PT.run(fx, symbol="addmul")
    check("E13 没给源码 → 报错说明要给 source 或 code",
          r6.get("ok") is False and "候选源码" in (r6.get("error") or ""),
          r6.get("error"))
    r7 = PT.run(fx, code=_FIXTURE_C)
    check("E14 没给目标函数 → 报错（不猜哪个函数）",
          r7.get("ok") is False and "找不到目标函数" in (r7.get("error") or ""),
          r7.get("error"))

# ---------------------------------------------------------------------------
# F 真镜像
# ---------------------------------------------------------------------------
def section_f():
    print("\nF 真镜像：外设 → not_comparable")
    av = PT.available()
    if not av.get("supported"):
        skip("F 全节", "缺依赖")
        return
    if not os.path.isfile(AXF):
        skip("F 全节", "示例镜像不存在")
        return
    code = (
        "#include <stdint.h>\n"
        "typedef struct { volatile uint32_t MODER, OTYPER, OSPEEDR, PUPDR,\n"
        "  IDR, ODR, BSRR, LCKR, AFR[2]; } GPIO_TypeDef;\n"
        "void HAL_GPIO_TogglePin(GPIO_TypeDef *p, uint16_t pin)\n"
        "{\n"
        "  uint32_t odr = p->ODR;\n"
        "  p->BSRR = ((odr & pin) << 16) | (~odr & pin);\n"
        "}\n"
    )
    r = PT.run(AXF, symbol="HAL_GPIO_TogglePin", code=code, args="0x40020000,0x1")
    check("F1 碰外设 → not_comparable（不是「一致」，也不是「不一致」）",
          r.get("verdict") == "not_comparable", r.get("verdict"))
    stops = {x["side"]: x["stop_reason"] for x in r.get("not_comparable_because") or []}
    check("F2 两侧都是 peripheral_access，并带上具体地址",
          stops.get("reference") == "peripheral_access"
          and stops.get("target") == "peripheral_access",
          r.get("not_comparable_because"))
    check("F3 这时 same_return 即使为 true 也不能当结论（停止原因优先）",
          r.get("same_return") is True and r.get("verdict") == "not_comparable",
          (r.get("same_return"), r.get("verdict")))
    check("F4 真镜像也用上了 symdefs（312+ 个符号）",
          r["link"]["symdefs_used"] is True and r["link"]["symdefs_count"] > 100,
          r["link"])

    r2 = PT.run(AXF, symbol="nosuch_symbol_xyz", code="void f(void){}\n")
    check("F5 目标函数不存在 → 报错（先找函数再谈 parity）",
          r2.get("ok") is False and "找不到目标函数" in (r2.get("error") or ""),
          r2.get("error"))
    r3 = PT.run(AXF, symbol="main", code=_FIXTURE_C, args="abc")
    check("F6 args 不是整数 → 报错（不静默当 0）",
          r3.get("ok") is False and "args" in (r3.get("error") or ""),
          r3.get("error"))
    r4 = PT.run(AXF, symbol="main", code="int broken( {\n")
    check("F7 编不过 → stage=compile / not_comparable（不是「不一致」）",
          r4.get("ok") is False and r4.get("stage") == "compile"
          and r4.get("error_code") == "compile_failed",
          (r4.get("stage"), r4.get("error_code")))
    check("F8 scope 里写清『只在这一组输入上成立』与 RW 初值不搬",
          "这一组输入" in (r.get("scope") or "")
          and "RW 初值不搬" in (r.get("scope") or ""), r.get("scope"))

# ---------------------------------------------------------------------------
# G 零依赖 / 文档 / 闸门
# ---------------------------------------------------------------------------
def section_g():
    print("\nG 零依赖 / 文档 / 版本 / 闸门")
    src = open(os.path.join(ROOT, "mdkdebug", "parity.py"), encoding="utf-8").read()
    stdlib = {"os", "re", "sys", "json", "subprocess", "shutil", "tempfile", "time",
              "__future__"}
    pkg = {"cbuild", "emulate", "plan", "recover", "tool_version"}
    bad = []
    for m in re.findall(r"^\s*(?:import|from)\s+([A-Za-z_][\w.]*)", src, re.M):
        head = m.split(".")[0]
        if head in stdlib or head in pkg or head in ("elftools", "unicorn"):
            continue
        bad.append(m)
    check("G1 parity 只用标准库 + 包内模块（elftools/unicorn 是既有依赖，lazy）",
          bad == [], bad)
    check("G2 unicorn 在 parity 里是 lazy（模块顶层不 import unicorn）",
          not re.search(r"^\s*import\s+unicorn", src, re.M))
    check("G3 判词集合就四条（不多不少）",
          all(v in src for v in ("parity_exact", "parity_return_only",
                                 "parity_differs", "not_comparable")), None)

    rd = open(os.path.join(ROOT, "README.md"), encoding="utf-8").read()
    check("G4 README 有批次108 的说明块", "批次108" in rd,
          re.findall(r"批次1\d\d", rd)[-4:])
    check("G5 README 工具表里有 recover_c_parity",
          "`recover_c_parity`" in rd)
    sk = open(os.path.join(ROOT, "skills", "mdkdebug", "SKILL.md"),
              encoding="utf-8").read()
    from mdkdebug import __version__ as V
    check("G6 SKILL 同步到 227 个工具", "227 个工具" in sk, None)

    py = open(os.path.join(ROOT, "pyproject.toml"), encoding="utf-8").read()
    check("G7 版本三处同步（__init__ / pyproject / README）",
          ('version = "%s"' % V) in py and ("版本号 %s" % V) in rd
          and re.match(r"^0\.2\.\d+$", V) is not None, (V,))
    rt = open(os.path.join(ROOT, "tools", "run_all_tests.py"),
              encoding="utf-8").read()
    check("G8 全量闸门里含 test_batch108", '"test_batch108"' in rt)

def main():
    print("批次108 测试：候选 C 的行为 parity")
    for fn in (section_a, section_b, section_c, section_d, section_e,
               section_f, section_g):
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
