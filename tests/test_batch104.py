# -*- coding: utf-8 -*-
"""批次104 测试：工具即 CLI 子命令（不进 MCP 客户端也能调每个工具）。

设计目标（这批要证明的）：

  A 纯函数：路由判据 / 值还原 / --arg 解析 / --args 文件 / 一句话摘要 / 组与风险映射
  B 端到端：tools / groups / describe / call 四条子命令真跑起来，退出码符合约定
  C 默认零变化：无参启动、--version、--host 值、MDKDEBUG_CLI=0 全部回到原解析器
  D 一致性：子命令清单与分发表、parser 注册三者不许漂移

运行：python -m tests.test_batch104
"""
import io
import json
import os
import re
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.environ.setdefault("MDKDEBUG_TOOLSETS", "all")

from mdkdebug import toolcli as TC          # noqa: E402
from mdkdebug import toolbox as TB          # noqa: E402

PASS, FAIL = [], []
TMP = []
PY = sys.executable


def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print("  [%s] %s %s" % ("PASS" if ok else "FAIL", name,
                            "" if ok else str(detail)[:400]), flush=True)


def tmpfile(name, text, enc="utf-8"):
    d = tempfile.mkdtemp(prefix="mdk104_")
    TMP.append(d)
    path = os.path.join(d, name)
    with io.open(path, "w", encoding=enc, newline="\n") as fp:
        fp.write(text)
    return path


def cli(args, env_extra=None):
    """跑一次真实 CLI，返回 (exit_code, stdout, stderr)。"""
    env = dict(os.environ)
    env["MDKDEBUG_TOOLSETS"] = "all"
    env.pop("MDKDEBUG_CLI", None)
    env["PYTHONPATH"] = ROOT
    for k, v in (env_extra or {}).items():
        if v is None:
            env.pop(k, None)
        else:
            env[k] = v
    p = subprocess.run([PY, "-m", "mdkdebug.cli"] + list(args), cwd=ROOT,
                       env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return (p.returncode, p.stdout.decode("utf-8", "replace"),
            p.stderr.decode("utf-8", "replace"))


# ----------------------------------------------------------------------
# A 纯函数
# ----------------------------------------------------------------------
def section_a():
    print("\nA 纯函数")

    # 路由判据：只认第一个位置参数
    saved = os.environ.pop("MDKDEBUG_CLI", None)
    try:
        check("A1 handles([]) 为假（无参＝服务端）", TC.handles([]) is False)
        check("A2 handles(--version) 为假（选项留给原解析器）",
              TC.handles(["--version"]) is False)
        check("A3 handles(--host 127.0.0.1) 为假（值在第二位，不被误吃）",
              TC.handles(["--host", "127.0.0.1"]) is False)
        check("A4 handles(tools) 为真", TC.handles(["tools"]) is True)
        check("A5 handles(read_mem ...) 为真", TC.handles(["read_mem", "--arg", "a=1"]) is True)
        check("A6 enabled() 默认开", TC.enabled() is True)

        os.environ["MDKDEBUG_CLI"] = "0"
        check("A7 MDKDEBUG_CLI=0 时 handles 一律为假（整体关掉）",
              TC.handles(["tools"]) is False and TC.enabled() is False)
        os.environ["MDKDEBUG_CLI"] = "off"
        check("A8 MDKDEBUG_CLI=off 同样关掉", TC.enabled() is False)
        os.environ["MDKDEBUG_CLI"] = "1"
        check("A9 MDKDEBUG_CLI=1 照常开", TC.enabled() is True)
    finally:
        os.environ.pop("MDKDEBUG_CLI", None)
        if saved is not None:
            os.environ["MDKDEBUG_CLI"] = saved

    # 值还原：能认的认成 JSON 类型，认不出的**原样交回**
    check("A10 coerce(16) → int", TC.coerce("16") == 16 and isinstance(TC.coerce("16"), int))
    check("A11 coerce(1.5) → float", TC.coerce("1.5") == 1.5)
    check("A12 coerce(true) → bool", TC.coerce("true") is True)
    check("A13 coerce(null) → None", TC.coerce("null") is None)
    check("A14 coerce([1,2]) → list", TC.coerce("[1,2]") == [1, 2])
    check("A15 coerce(\"x\") → str（引号被 JSON 消掉）", TC.coerce('"x"') == "x")
    check("A16 coerce(0x20000000) 原样当字符串（十六进制不硬转）",
          TC.coerce("0x20000000") == "0x20000000")
    check("A17 coerce(abc) → 字符串", TC.coerce("abc") == "abc")
    check("A18 coerce(空串) → 空串（不变成 None）", TC.coerce("") == "")

    d = TC.parse_assignments(["addr=0x20000000", "n=16", "verify=true"])
    check("A19 parse_assignments 混合类型",
          d == {"addr": "0x20000000", "n": 16, "verify": True}, d)

    try:
        TC.parse_assignments(["addr"])
        check("A20 --arg 缺 = 时报用法错", False, "没有抛")
    except SystemExit as e:
        check("A20 --arg 缺 = 时报用法错且退出码 2", e.code == 2, e.code)

    try:
        TC.parse_assignments(["=1"])
        check("A21 --arg 空键报用法错", False, "没有抛")
    except SystemExit as e:
        check("A21 --arg 空键报用法错且退出码 2", e.code == 2, e.code)

    # --args
    check("A22 load_args 空值 → 空 dict", TC.load_args(None) == {} and TC.load_args("") == {})
    check("A23 load_args 内联 JSON", TC.load_args('{"addr":"0x20000000"}') == {"addr": "0x20000000"})
    path = tmpfile("args.json", '{"n": 32}\n', enc="utf-8-sig")
    check("A24 load_args @文件（容忍 BOM）", TC.load_args("@" + path) == {"n": 32})
    try:
        TC.load_args("[1,2]")
        check("A25 --args 非对象报用法错", False, "没有抛")
    except SystemExit as e:
        check("A25 --args 非对象报用法错且退出码 2", e.code == 2, e.code)
    try:
        TC.load_args("@/definitely/not/here.json")
        check("A26 --args 文件不存在报用法错", False, "没有抛")
    except SystemExit as e:
        check("A26 --args 文件不存在报用法错且退出码 2", e.code == 2, e.code)

    # 一句话摘要 / 组 / 风险 / 示例
    desc = "第一句是用途。\n第二行补充。\n【参数】必填: addr\n【调用示例】{}\n【风险】高"
    one = TC._one_line(desc)
    check("A27 _one_line 截掉【参数】之后的块", "【参数】" not in one and "第一句是用途" in one, one)
    check("A28 _one_line 压成一行的空白", "\n" not in one)
    long_one = TC._one_line("字" * 300)
    check("A29 超长摘要加省略号且不超上限", long_one.endswith("…")
          and len(long_one) <= TC._SUMMARY_MAX + 1, len(long_one))
    check("A30 read_mem 归 core 组", TC._group_of("read_mem") == "core", TC._group_of("read_mem"))
    check("A31 不存在的名字归空串（视为常驻）", TC._group_of("no_such_tool_xyz") == "")
    check("A32 recover_verify 有风险标注", TC._risk_of("recover_verify") in ("medium", "high"),
          TC._risk_of("recover_verify"))
    check("A33 只读工具无风险标注", TC._risk_of("get_version") == "", TC._risk_of("get_version"))
    ex = TC._example_value({"name": "addr", "type": "string|integer"})
    check("A34 地址类参数示例给 0x 字面量", ex == "0x20000000", ex)


# ----------------------------------------------------------------------
# B 端到端
# ----------------------------------------------------------------------
def section_b():
    print("\nB 端到端（真跑子进程）")

    code, out, err = cli(["tools", "--group", "build", "--json"])
    body = None
    try:
        body = json.loads(out)
    except Exception:  # noqa: BLE001
        pass
    ok_json = isinstance(body, dict) and body.get("count", 0) > 0
    check("B1 tools --json 退出码 0 且是合法 JSON", code == 0 and ok_json, (code, out[:200], err[:200]))
    got = body.get("tools") if ok_json else []
    check("B2 tools --group build 只出 build 组",
          bool(got) and all(t["group"] == "build" for t in got),
          sorted({t["group"] for t in got}))
    check("B3 每条都带 name/summary/required",
          bool(got) and all({"name", "summary", "required"} <= set(t) for t in got))
    check("B4 必填参数被标出来（build 组有必填）",
          any(t["required"] for t in got), [t["required"] for t in got][:5])

    code, out, err = cli(["groups", "--json"])
    try:
        gb = json.loads(out)
    except Exception:  # noqa: BLE001
        gb = {}
    check("B5 groups --json 退出码 0", code == 0, err[:200])
    check("B6 组数与 TOOLSETS 一致（不多组不漏组）",
          len(gb.get("groups") or []) == len(TB.TOOLSETS),
          (len(gb.get("groups") or []), len(TB.TOOLSETS)))
    check("B7 每组都带 note 与可见计数",
          all(g.get("note") and isinstance(g.get("visible"), int)
              for g in (gb.get("groups") or [])))
    check("B8 可见工具数 > 0（工具面真装上）", (gb.get("visible_tools") or 0) > 0,
          gb.get("visible_tools"))

    code, out, err = cli(["describe", "read_mem", "--json"])
    try:
        db = json.loads(out)
    except Exception:  # noqa: BLE001
        db = {}
    check("B9 describe --json 退出码 0", code == 0, err[:200])
    names = [p["name"] for p in (db.get("params") or [])]
    check("B10 describe 报出参数名", "addr" in names and "n_bytes" in names, names[:8])
    check("B11 describe 给出可照抄的调用示例",
          "--arg addr" in (db.get("example") or ""), db.get("example"))
    check("B12 describe 带组与摘要", db.get("group") == "core" and bool(db.get("summary")), db.get("group"))

    code, out, err = cli(["describe", "read_me"])
    check("B13 名字不存在时退出码 2 并给出相近名字",
          code == 2 and "read_mem" in err, (code, err[-200:]))

    # 简写：不带 call 直接给工具名
    code, out, err = cli(["mdk_guide", "--arg", "topic=capabilities", "--compact"])
    try:
        cb = json.loads(out)
    except Exception:  # noqa: BLE001
        cb = {}
    check("B14 简写 get_version 式调用能跑（mdk_guide(topic=capabilities) 不需 Keil）",
          code == 0 and cb.get("ok") is True, (code, out[:200], err[:200]))

    # 需要 Keil 的工具：退出码必须与返回体自洽（不依赖本机是否开着 Keil）
    code, out, err = cli(["get_version", "--json"])
    try:
        vb = json.loads(out)
    except Exception:  # noqa: BLE001
        vb = {}
    failed = (vb.get("ok") is False) or (str(vb.get("status", "")).lower() == "error")
    check("B15 工具失败时退出码非 0、成功时 0（与返回体自洽）",
          bool(vb) and code == (1 if failed else 0), (code, out[:200]))
    check("B16 失败体带统一信封字段（status/error 或 next_actions）",
          (not failed) or ("status" in vb and ("error" in vb or "error_code" in vb)), sorted(vb))

    code, out, err = cli(["read_mem", "--arg", "addr"])
    check("B17 --arg 写法错时退出码 2", code == 2 and "k=v" in err, (code, err[-200:]))

    code, out, err = cli(["tools", "--grep", "mem", "--limit", "5", "--json"])
    try:
        tb = json.loads(out)
    except Exception:  # noqa: BLE001
        tb = {}
    check("B18 tools --grep/--limit 生效",
          code == 0 and 0 < (tb.get("count") or 0) <= 5, (code, tb.get("count")))

    code, out, err = cli(["tools", "--group", "build"])
    check("B19 tools 文本输出带组头与合计行",
          code == 0 and "== build ==" in out and "共 " in out, out[-200:])


# ----------------------------------------------------------------------
# C 默认零变化
# ----------------------------------------------------------------------
def section_c():
    print("\nC 默认路径零变化")

    code, out, err = cli(["--version"])
    check("C1 --version 仍由原解析器处理（退出码 0、打印版本）",
          code == 0 and "mdkdebug " in out, (code, out, err[-200:]))

    code, out, err = cli(["--host", "127.0.0.1", "--version"])
    check("C2 --host 的值不被当成工具名（仍打印版本）",
          code == 0 and "mdkdebug " in out and "没有这个工具" not in err, (code, out, err[-200:]))

    code, out, err = cli(["tools"], env_extra={"MDKDEBUG_CLI": "0"})
    check("C3 MDKDEBUG_CLI=0 时 tools 回到原解析器（argparse 用法错，退出码 2）",
          code == 2 and ("unrecognized" in err or "invalid" in err), (code, err[-300:]))

    src = io.open(os.path.join(ROOT, "mdkdebug", "cli.py"), encoding="utf-8").read()
    check("C4 cli.py 里确有 toolcli.handles 闸门", "toolcli.handles(" in src and "_toolcli.main(" in src)
    check("C5 cli.py 仍把 argv 交给原解析器（parse_args(_argv)）", "parse_args(_argv)" in src)
    check("C6 服务端两条运行路径未被改动",
          "asyncio.run(run_stdio(" in src and "run_http(" in src)

    # run_server.py 薄壳仍等价
    env = dict(os.environ)
    env["PYTHONPATH"] = ROOT
    p = subprocess.run([PY, "run_server.py", "--version"], cwd=ROOT, env=env,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    check("C7 run_server.py --version 仍等价（薄壳没被 CLI 层破坏）",
          p.returncode == 0 and b"mdkdebug " in p.stdout, p.stderr[-200:])

    # 无参启动：handler 注册表与 parser 一致（不真起 stdio，避免挂住）
    check("C8 无参不进入 CLI 层（handles([]) False，服务端分支保留）",
          TC.handles([]) is False and "run_stdio" in src)


# ----------------------------------------------------------------------
# D 一致性（防「加了子命令忘了接线」）
# ----------------------------------------------------------------------
def section_d():
    print("\nD 一致性")

    src = io.open(os.path.join(ROOT, "mdkdebug", "toolcli.py"), encoding="utf-8").read()
    registered = set(re.findall(r'sub\.add_parser\(\s*"([a-z_]+)"', src))
    check("D1 parser 注册的子命令 == SUBCOMMANDS",
          registered == set(TC.SUBCOMMANDS), (sorted(registered), list(TC.SUBCOMMANDS)))
    dispatch = set(re.findall(r'"(tools|groups|describe|call)":\s*cmd_', src))
    check("D2 分发表覆盖全部子命令", dispatch == set(TC.SUBCOMMANDS),
          (sorted(dispatch), list(TC.SUBCOMMANDS)))
    check("D3 子命令名不与真实工具重名（否则简写会歧义）",
          not (set(TC.SUBCOMMANDS) & TB.assigned_names()),
          sorted(set(TC.SUBCOMMANDS) & TB.assigned_names()))

    readme = io.open(os.path.join(ROOT, "README.md"), encoding="utf-8").read()
    check("D4 README 写明 CLI 子命令与开关", "mdkdebug tools" in readme and "MDKDEBUG_CLI" in readme)
    check("D5 README 写明简写形态", "mdkdebug read_mem --arg" in readme)
    check("D6 零新增依赖（toolcli 只 import 标准库 + 本包）",
          not re.search(r"^\s*(import|from)\s+(click|typer|rich|requests)\b", src, re.M))


def main():
    print("=" * 70)
    print("批次104：工具即 CLI 子命令")
    print("=" * 70)
    try:
        section_a()
        section_b()
        section_c()
        section_d()
    finally:
        for d in TMP:
            for root, _dirs, names in os.walk(d, topdown=False):
                for nm in names:
                    try:
                        os.remove(os.path.join(root, nm))
                    except OSError:
                        pass
                try:
                    os.rmdir(root)
                except OSError:
                    pass
    print("\n%d pass / %d fail" % (len(PASS), len(FAIL)))
    if FAIL:
        print("失败：%s" % "、".join(FAIL))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
