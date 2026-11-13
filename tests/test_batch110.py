# -*- coding: utf-8 -*-
"""批次110 测试：recover_c_parity 的多组输入（args_sets）。

批次108 的 parity 只跑一组输入，结论押在一个采样点上；本批让一次调用跑多组。
分节：

  A 工具面：注册仍 227、schema 有 args_sets、别名表登记且不遮蔽
  B 参数校验：args 与 args_sets 同时给报错、非法 args_sets 报错带参数名
  C 端到端（要工具链 + unicorn）：全一致 → parity_exact + all_exact；
    一组反例 → 聚合 parity_differs（另一组仍 exact）；逐组细节在 cases[]；
    单组向后兼容（顶层 reference/target/writes 仍在）
  D 聚合口径：not_comparable 只在没有更硬结论时顶到顶层
  E 文档 / 版本 / 闸门登记

运行：python -m tests.test_batch110
"""
import json
import os
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.environ.setdefault("MDKDEBUG_TOOLSETS", "all")

from mdkdebug import parity as PT           # noqa: E402

PASS, FAIL, SKIP, TMP = [], [], [], []


def check(name, ok, detail=None):
    (PASS if ok else FAIL).append(name)
    print("  [%s] %s %s" % ("PASS" if ok else "FAIL", name,
                            "" if ok else str(detail)[:400]), flush=True)


def skip(name, why):
    SKIP.append((name, why))
    print("  [SKIP] %s —— %s" % (name, why), flush=True)


def tmpdir(prefix="mdk110_"):
    d = tempfile.mkdtemp(prefix=prefix)
    TMP.append(d)
    return d


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

# 只在 a==0 时走岔路：args_sets 里 "0,2" 判 differs，"5,11" 仍 exact
_ONLY_ZERO_DIFF = _FIXTURE_C.replace(
    "    uint32_t r = a * 3u + 7u;",
    "    if (a == 0u) { return 1u; }\n    uint32_t r = a * 3u + 7u;")

# 只在 a==0 时碰外设：那一组 not_comparable，其它组仍 exact
_ONLY_ZERO_PERI = _FIXTURE_C.replace(
    "    uint32_t r = a * 3u + 7u;",
    "    if (a == 0u) { *(volatile uint32_t *)0x40000000u = 1u; }\n"
    "    uint32_t r = a * 3u + 7u;")


def _build_fixture(src_text, name="addmul"):
    from mdkdebug import cbuild as CB
    tc = CB.find_compilers()
    exe = tc.get("ac5") or tc.get("ac6")
    linker = PT._find_linker(tc)
    if not exe or not linker:
        return None
    d = tmpdir("mdk110_fix_")
    src = os.path.join(d, "orig.c")
    obj = os.path.join(d, "orig.o")
    axf = os.path.join(d, "orig.axf")
    with open(src, "wb") as fh:
        fh.write(src_text.encode("utf-8"))
    if os.path.basename(exe).startswith("armclang"):
        cc = [exe, "--target=arm-arm-none-eabi", "-mcpu=cortex-m4", "-mthumb",
              "-ffunction-sections", "-fdata-sections", "-O1", "-c", src, "-o", obj]
    else:
        cc = [exe, "--cpu", "Cortex-M4", "--thumb", "--c99", "-O1", "-c",
              src, "-o", obj]
    p = subprocess.run(cc, capture_output=True, text=True, errors="replace",
                       timeout=180)
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
    print("\nA 工具面：注册 / schema / 别名")
    import asyncio

    from mdkdebug import aliases as AL
    from mdkdebug import annotate as AN
    from mdkdebug import server as SV

    srv = SV.create_server(port=15987, toolsets="all")

    async def _list():
        return await srv.list_tools()

    tools = {t.name: t for t in asyncio.run(_list())}
    names = sorted(tools)
    check("A1 注册总数仍是 227（本批只加参数，不加工具）", len(names) == 227,
          len(names))
    check("A2 recover_c_parity 仍在", "recover_c_parity" in tools)
    t = tools.get("recover_c_parity")
    props = set(((t.input_schema or {}).get("properties") or {})) if t else set()
    check("A3 schema 里有 args_sets，且 args 还在", {"args", "args_sets"} <= props,
          sorted(props))
    # 档位=lean 时长描述被挪进 mdk_guide(topic="tool")，所以两处都查：
    # lean 面必须露出 args_sets 这个参数名，完整说明必须讲清多组口径。
    src = open(os.path.join(ROOT, "mdkdebug", "server.py"), "rb").read().decode("utf-8")
    check("A4 lean 面露出 args_sets、完整说明写明多组口径",
          t is not None and "args_sets" in (t.description or "")
          and all(k in src for k in (r'args_sets=\"1,2;3,4;0,0\"',
                                    "逐组结果在 cases[]", "summary.counts")),
          (t.description or "")[:300] if t else "")
    spec = (AL._SPEC or {}).get("recover_c_parity") or {}
    check("A5 别名表登记了 args_sets 的别名", "args_sets" in spec, sorted(spec))
    bad = []
    for main, alts in spec.items():
        if main not in props:
            bad.append(main)
        for a in alts or []:
            if a in props:
                bad.append("遮蔽真实参数:%s" % a)
    check("A6 别名主名都在 schema 里、且不遮蔽真实参数", bad == [], bad)
    check("A7 工具面归类完整", AN.check_surface(names) == [],
          AN.check_surface(names))


# ---------------------------------------------------------------------------
# B 参数校验
# ---------------------------------------------------------------------------
AXF = os.path.join(ROOT, "example_mdk_project", "mdk_test", "MDK-ARM",
                   "mdk_test", "mdk_test.axf")


def section_b():
    print("\nB 参数校验：一个参数一个含义")
    r = PT.run(AXF, symbol="no_such_fn", code=_FIXTURE_C,
               args="1,2", args_sets="3,4")
    check("B1 args 与 args_sets 同时给 → 报错（不猜谁覆盖谁）",
          r.get("ok") is False and "不能同时给" in (r.get("error") or ""),
          r.get("error"))
    r2 = PT.run(AXF, symbol="no_such_fn", code=_FIXTURE_C, args_sets="1,2;zz")
    check("B2 非法 args_sets → 报错里带参数名（不静默当全 0）",
          r2.get("ok") is False and "args_sets" in (r2.get("error") or ""),
          r2.get("error"))
    r3 = PT.run(AXF, symbol="no_such_fn", code=_FIXTURE_C, args_sets="  ;  ")
    check("B3 空的 args_sets（只有分隔符）→ 按单组全 0 走，不报错",
          r3.get("ok") is False and "候选源码" not in (r3.get("error") or "")
          and "args_sets" not in (r3.get("error") or ""),
          r3.get("error"))


# ---------------------------------------------------------------------------
# C/D 端到端
# ---------------------------------------------------------------------------
def section_c():
    print("\nC 端到端：多组一致 / 一组反例 / 单组向后兼容")
    av = PT.available()
    if not av.get("supported"):
        skip("C 全节", "缺依赖：%s" % av.get("why"))
        return
    fx = _build_fixture(_FIXTURE_C)
    if not fx:
        skip("C 全节", "工具链编不出合成镜像")
        return

    r = PT.run(fx, symbol="addmul", code=_FIXTURE_C,
               args_sets="5,11; 1,2; 0,0")
    check("C1 三组都一致 → 顶层 parity_exact", r.get("verdict") == "parity_exact",
          (r.get("verdict"), r.get("summary")))
    check("C2 summary 记了三组、全 exact、all_exact=True",
          r["summary"]["cases"] == 3 and r["summary"]["all_exact"] is True
          and r["summary"]["counts"]["parity_exact"] == 3, r.get("summary"))
    check("C3 cases[] 三组、每组带自己的 args 与 verdict",
          len(r.get("cases") or []) == 3
          and [c["args"][1] for c in r["cases"]] == ["0x0000000B", "0x00000002",
                                                     "0x00000000"],
          [c.get("args") for c in (r.get("cases") or [])])
    check("C4 多组时不把某一组冒充整体（顶层没有 reference/target）",
          "reference" not in r and "target" not in r, sorted(r))
    check("C5 inputs 里回显每组（知道结论在什么条件下得的）",
          r["inputs"].get("cases") == 3 and len(r["inputs"].get("arg_sets") or []) == 3,
          r.get("inputs"))

    # 一组反例：0,2 判 differs，其余 exact
    r2 = PT.run(fx, symbol="addmul", code=_ONLY_ZERO_DIFF,
                args_sets="5,11; 0,2")
    check("C6 一组反例 → 顶层 parity_differs（一组就足以否证等价）",
          r2.get("verdict") == "parity_differs",
          (r2.get("verdict"), r2.get("summary")))
    check("C7 另一组仍然 exact，且分布如实记 1 exact + 1 differs",
          r2["summary"]["counts"]["parity_exact"] == 1
          and r2["summary"]["counts"]["parity_differs"] == 1
          and r2["summary"]["all_exact"] is False, r2.get("summary"))
    check("C8 逐组判词各自正确（不是整批一个词）",
          [c["verdict"] for c in r2["cases"]] == ["parity_exact", "parity_differs"],
          [c["verdict"] for c in r2["cases"]])
    check("C9 反例那组指名 r0 两侧各是多少",
          r2["cases"][1]["differences"]["return"].get("r0") == ["0x00000009",
                                                                "0x00000001"],
          r2["cases"][1]["differences"]["return"])

    # 单组向后兼容
    r3 = PT.run(fx, symbol="addmul", code=_FIXTURE_C, args_sets="5,11")
    check("C10 单组走旧形状：顶层有 reference/target/writes/differences",
          all(k in r3 for k in ("reference", "target", "writes", "differences")),
          sorted(r3))
    check("C11 单组 inputs 仍是 args（不是 arg_sets）",
          r3["inputs"].get("args") == ["0x00000005", "0x0000000B"], r3.get("inputs"))
    check("C12 单组 summary 也给出（1 组、all_exact）",
          r3["summary"]["cases"] == 1 and r3["summary"]["all_exact"] is True,
          r3.get("summary"))


def section_d():
    print("\nD 聚合口径：not_comparable 不被别的组淹没")
    av = PT.available()
    if not av.get("supported"):
        skip("D 全节", "缺依赖：%s" % av.get("why"))
        return
    fx = _build_fixture(_FIXTURE_C)
    if not fx:
        skip("D 全节", "工具链编不出合成镜像")
        return
    r = PT.run(fx, symbol="addmul", code=_ONLY_ZERO_PERI,
               args_sets="5,11; 0,2")
    check("D1 一组碰外设 → 那组 not_comparable（不是「一致」）",
          [c["verdict"] for c in (r.get("cases") or [])]
          == ["parity_exact", "not_comparable"],
          [(c["verdict"], c.get("stop_reason")) for c in (r.get("cases") or [])])
    check("D2 没有更硬结论时顶层取 not_comparable",
          r.get("verdict") == "not_comparable", r.get("verdict"))
    check("D3 not_comparable 那组写明是哪一侧、什么原因停下",
          r["cases"][1].get("differences", {}).get("stopped")
          and r["cases"][1]["differences"]["stopped"][0].get("stop_reason"),
          r["cases"][1].get("differences", {}).get("stopped"))


# ---------------------------------------------------------------------------
# E 文档 / 版本 / 闸门
# ---------------------------------------------------------------------------
def section_e():
    print("\nE 文档 / 版本 / 闸门")
    rd = open(os.path.join(ROOT, "README.md"), "rb").read().decode("utf-8")
    check("E1 README 写明 args_sets 的分号写法",
          'args_sets="1,2;3,4' in rd or 'args_sets": "5,11; 1,2; 0,0' in rd, None)
    check("E2 README 写明聚合取最硬与「一组反例足以否证」",
          "一组反例就足以否证" in rd and "parity_differs` > " in rd, None)
    pf = open(os.path.join(ROOT, "mdkdebug", "parity.py"), "rb").read().decode("utf-8")
    check("E3 工具自己的 scope 已改读法（不再是「这一组输入」）",
          "跑过的那几组输入" in pf and "这一组输入" not in pf, None)
    init = open(os.path.join(ROOT, "mdkdebug", "__init__.py"), "rb").read().decode("utf-8")
    check("E4 版本号已到 0.2.34", '0.2.34' in init, init[-200:])
    gate = open(os.path.join(ROOT, "tools", "run_all_tests.py"), "rb").read().decode("utf-8")
    check("E5 本批已登记进全量闸门", '"test_batch110"' in gate, None)
    check("E6 零新增依赖（parity 仍只用已有模块）",
          "import unicorn" not in open(os.path.join(ROOT, "mdkdebug", "parity.py"),
                                       "rb").read().decode("utf-8"), None)


def main():
    print("=" * 70)
    print("批次110：recover_c_parity 多组输入（args_sets）")
    print("=" * 70)
    section_a()
    section_b()
    section_c()
    section_d()
    section_e()
    for d in TMP:
        import shutil
        shutil.rmtree(d, ignore_errors=True)
    print("\n通过 %d 失败 %d 跳过 %d" % (len(PASS), len(FAIL), len(SKIP)))
    if SKIP:
        for n, why in SKIP:
            print("  SKIP %s —— %s" % (n, why))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
